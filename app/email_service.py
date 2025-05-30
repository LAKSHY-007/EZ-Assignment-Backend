import aiosmtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
import os

load_dotenv()

async def send_verification_email(email: str, verification_url: str):
    message = MIMEText(f"Please verify your email by clicking this link: {verification_url}")
    message["From"] = os.getenv("SMTP_USERNAME")
    message["To"] = email
    message["Subject"] = "Verify Your Email"
    
    await aiosmtplib.send(
        message,
        hostname=os.getenv("SMTP_SERVER"),
        port=os.getenv("SMTP_PORT"),
        username=os.getenv("SMTP_USERNAME"),
        password=os.getenv("SMTP_PASSWORD"),
        use_tls=True
    )