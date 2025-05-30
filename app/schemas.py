from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional
from enum import Enum

class UserType(str, Enum):
    OPS = "ops"
    CLIENT = "client"

class UserBase(BaseModel):
    email: EmailStr
    user_type: UserType = UserType.CLIENT

class UserCreate(UserBase):
    password: str

class UserInDB(UserBase):
    id: int
    is_verified: bool
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class FileBase(BaseModel):
    file_name: str
    file_type: str

class FileCreate(FileBase):
    pass

class FileInDB(FileBase):
    id: int
    uploaded_by: int
    created_at: datetime

    class Config:
        from_attributes = True

class SecureDownloadLinkCreate(BaseModel):
    file_id: int

class SecureDownloadLink(BaseModel):
    download_url: str
    expires_at: datetime