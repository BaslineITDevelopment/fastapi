

# auth.py
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from . import database, models, schemas
from sqlalchemy.future import select
import os
from dotenv import load_dotenv
from .models import User, Admin  
from .database import get_db
import smtplib
from email.mime.text import MIMEText
from .models import User, Admin 
load_dotenv()

ROLE_MODEL_MAP = {
    "customer": User,
    "admin": Admin,

}

ROLE_UPDATE_MAP = {
    "staff": User,
    "contractor": User,
    "customer": User
}

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
EMAIL_SECRET = os.getenv("EMAIL_VERIFICATION_SECRET")
EMAIL_EXPIRE_MINUTES = int(os.getenv("EMAIL_VERIFICATION_EXPIRE_MINUTES", 30))
EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_APP_PASSWORD = os.getenv("EMAIL_APP_PASSWORD")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

async def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

async def get_password_hash(password):
    return pwd_context.hash(password)



async def get_user_by_email(db: AsyncSession, email: str):
    
    result = await db.execute(select(Admin).where(Admin.email == email))
    admin_user = result.scalar_one_or_none()
    if admin_user:
        return admin_user
    
    
    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


async def get_user_by_email_from_users_table(db: AsyncSession, email: str):
    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()



async def authenticate_user(db: AsyncSession, username_input: str, password: str):
    if "@" in username_input:
        
        result = await db.execute(select(models.User).filter(models.User.email == username_input))
    else:
        
        result = await db.execute(select(models.User).filter(models.User.username == username_input))

    user = result.scalars().first()

    if not user or not await verify_password(password, user.hashed_password):
        return False
    return user


async def authenticate_user_by_model(db: AsyncSession, model, username_or_email: str, password: str):
    result = await db.execute(select(model).where(model.email == username_or_email))
    user = result.scalar_one_or_none()
    if user and await verify_password(password, user.hashed_password):
        return user
    return None

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(data: dict, expires_delta: timedelta = None):
    expire = datetime.utcnow() + (expires_delta or timedelta(days=7))
    to_encode = data.copy()
    to_encode.update({"exp": expire, "scope": "refresh_token"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(database.get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        role = payload.get("role")

        if not email or not role or role not in ROLE_MODEL_MAP:
            raise credentials_exception

        model = ROLE_MODEL_MAP[role]
        result = await db.execute(select(model).filter(model.email == email))
        user = result.scalars().first()
        if not user:
            raise credentials_exception

        return user
    except JWTError:
        raise credentials_exception


async def get_current_admin(
    current_user = Depends(get_current_user)
):
    if not isinstance(current_user, Admin):
        raise HTTPException(status_code=403, detail="Not authorized as admin")
    return current_user



def create_email_verification_token(email: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=EMAIL_EXPIRE_MINUTES)
    payload = {"sub": email, "exp": expire}
    return jwt.encode(payload, EMAIL_SECRET, algorithm="HS256")


def verify_email_token(token: str) -> str:
    try:
        payload = jwt.decode(token, EMAIL_SECRET, algorithms=["HS256"])
        return payload.get("sub")
    except JWTError:
        raise ValueError("Invalid or expired token")


async def send_verification_email(email: str, token: str):
    msg = MIMEText(f"Click the link to verify your email:\n\nhttp://localhost:8000/verify-email?token={token}")
    msg["Subject"] = "Email Verification"
    msg["From"] = EMAIL_SENDER
    msg["To"] = email

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(EMAIL_SENDER, EMAIL_APP_PASSWORD)
        server.sendmail(EMAIL_SENDER, [email], msg.as_string())