from fastapi import FastAPI, Depends, HTTPException, UploadFile, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from typing import List
from jose import jwt
from app.authentication import verify_password
from jose.exceptions import JWTError
import magic 
import os
import secrets
from datetime import datetime, timedelta

from app.models import User, File, SecureDownloadLink, UserType
from fastapi import FastAPI

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Hello, welcome to EZASSG!"}

from app.schemas import UserCreate, UserInDB, Token, FileInDB, SecureDownloadLink
from app.authentication import (
    get_current_user,
    get_current_ops_user,
    get_current_client_user,
    create_access_token,
    get_password_hash
)
from app.database import get_db, Base, engine
from app.email_service import send_verification_email

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
Base.metadata.create_all(bind=engine)
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_TYPES = {
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx"
}

# file verify krne kelie
def verify_file_type(file: UploadFile):
    file_content = file.file.read(1024)
    file.file.seek(0)
    
    mime = magic.from_buffer(file_content, mime=True)
    file_ext = ALLOWED_TYPES.get(mime)
    
    if not file_ext:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Only {', '.join(ALLOWED_TYPES.values())} are allowed"
        )
    return file_ext

# API  ke Endpoints
@app.post("/signup", response_model=UserInDB)
async def signup(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    hashed_password = get_password_hash(user.password)
    db_user = User(
        email=user.email,
        password_hash=hashed_password,
        user_type=user.user_type
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    if user.user_type == UserType.CLIENT:
        verification_token = create_access_token({"sub": user.email})
        verification_url = f"{os.getenv('FRONTEND_URL')}/verify?token={verification_token}"
        await send_verification_email(user.email, verification_url)
    
    return db_user

@app.get("/verify")
async def verify_email(token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=[os.getenv("ALGORITHM")])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=400, detail="Invalid token")
        
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        if user.user_type != UserType.CLIENT:
            raise HTTPException(status_code=400, detail="Only client users need verification")
        
        user.is_verified = True
        db.commit()
        
        return {"message": "Email verified successfully"}
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

@app.post("/login", response_model=Token)
async def login(email: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password (password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user.user_type == UserType.CLIENT and not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email not verified"
        )
    
    access_token = create_access_token({"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/upload")
async def upload_file(
    file: UploadFile,
    current_user: User = Depends(get_current_ops_user),
    db: Session = Depends(get_db)
):
    file_ext = verify_file_type(file)
    file_path = os.path.join(UPLOAD_DIR, f"{secrets.token_hex(8)}.{file_ext}")
    with open(file_path, "wb") as buffer:
        buffer.write(await file.read())
    
    # Save to database
    db_file = File(
        file_name=file.filename,
        file_path=file_path,
        file_type=file_ext,
        uploaded_by=current_user.id
    )
    db.add(db_file)
    db.commit()
    db.refresh(db_file)
    
    return {"message": "File uploaded successfully", "file_id": db_file.id}

@app.get("/files", response_model=List[FileInDB])
async def list_files(
    current_user: User = Depends(get_current_client_user),
    db: Session = Depends(get_db)
):
    files = db.query(File).all()
    return files

@app.post("/files/{file_id}/generate_download", response_model=SecureDownloadLink)
async def generate_download_link(
    file_id: int,
    current_user: User = Depends(get_current_client_user),
    db: Session = Depends(get_db)
):
    file = db.query(File).filter(File.id == file_id).first()
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=1)
    download_link = SecureDownloadLink(
        file_id=file_id,
        client_id=current_user.id,
        token=token,
        expires_at=expires_at
    )
    db.add(download_link)
    db.commit()
    
    return {
        "download_url": f"/download?token={token}",
        "expires_at": expires_at
    }

@app.get("/download")
async def download_file(
    token: str,
    db: Session = Depends(get_db)
):

    download_link = db.query(SecureDownloadLink).filter(
        SecureDownloadLink.token == token,
        SecureDownloadLink.expires_at > datetime.utcnow(),
        SecureDownloadLink.is_used == False
    ).first()
    
    if not download_link:
        raise HTTPException(status_code=404, detail="Invalid or expired download link")

    file = db.query(File).filter(File.id == download_link.file_id).first()
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    download_link.is_used = True
    db.commit()
    return FileResponse(
        file.file_path,
        filename=file.file_name,
        media_type="application/octet-stream"
    )