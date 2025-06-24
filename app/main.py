


from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Request
from . import database, models, schemas, crud, auth
from .schemas import UserOut
from .auth import get_current_user
from .models import User, Admin
from .database import get_db

from .auth import get_current_admin
from fastapi import Body

from app.schemas import LoginRequest, UnifiedLoginResponse
from app.auth import create_access_token, verify_password, get_password_hash
from sqlalchemy import select

from app import schemas
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from app.auth import oauth2_scheme, SECRET_KEY, ALGORITHM 

from fastapi import Form
from fastapi import Query
from typing import List
from app.auth import get_password_hash
from fastapi.responses import JSONResponse
from app.auth import create_refresh_token
from app.auth import get_current_admin 
from fastapi.middleware.cors import CORSMiddleware
import logging
from fastapi import Request
import json
from fastapi.responses import RedirectResponse
from datetime import datetime
from app.logging_model import RequestLog

app = FastAPI()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = datetime.now()
    
    # Skip logging for documentation endpoints
    if request.url.path in ["/docs", "/openapi.json", "/redoc"]:
        return await call_next(request)
    
    try:
        response = await call_next(request)
    except HTTPException as http_exc:
        process_time = (datetime.now() - start_time).total_seconds() * 1000
        log_data = {
            "timestamp": start_time,
            "method": request.method,
            "path": request.url.path,
            "ip": request.client.host if request.client else None,
            "status_code": http_exc.status_code,
            "process_time_ms": process_time,
            "user_agent": request.headers.get("user-agent"),
            "error": http_exc.detail
        }
        logger.error(json.dumps({**log_data, "timestamp": log_data["timestamp"].isoformat()}))
        raise http_exc
    except Exception as e:
        process_time = (datetime.now() - start_time).total_seconds() * 1000
        logger.error(f"Request failed: {str(e)}")
        raise
    
    process_time = (datetime.now() - start_time).total_seconds() * 1000
    
    log_data = {
        "timestamp": start_time,
        "method": request.method,
        "path": request.url.path,
        "ip": request.client.host if request.client else None,
        "status_code": response.status_code,
        "process_time_ms": process_time,
        "user_agent": request.headers.get("user-agent"),
    }
    
    # Special handling for login attempts
    if request.url.path == "/login":
        try:
            body = await request.json()
            log_data["additional_data"] = {
                "login_attempt": {
                    "email": body.get("email"),
                    "success": response.status_code == 200
                }
            }
        except Exception as e:
            logger.warning(f"Failed to parse login data: {str(e)}")
    
    # Special handling for file uploads
    if request.url.path == "/upload":
        try:
            log_data["additional_data"] = {
                "file_upload": True,
                "content_type": request.headers.get("content-type")
            }
        except Exception as e:
            logger.warning(f"Failed to log upload details: {str(e)}")
    
    # Log to console
    console_log = {**log_data, "timestamp": log_data["timestamp"].isoformat()}
    logger.info(json.dumps(console_log, default=str))
    
    # Store in database
    try:
        db = database.async_session()
        await crud.create_request_log(db, log_data)
    except Exception as e:
        logger.error(f"Database log failed: {str(e)}")
    finally:
        await db.close()
 
    
    return response

@app.on_event("startup")
async def on_startup():
    async with database.engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)
        from .logging_model import RequestLog
        await conn.run_sync(RequestLog.metadata.create_all)



@app.post("/register", response_model=schemas.UserOut)
async def register(user: schemas.UserCreate, db: AsyncSession = Depends(database.get_db)):
    existing_user = await auth.get_user_by_email(db, user.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return await crud.create_user(db, user, role="customer")



@app.post("/login", response_model=schemas.UnifiedLoginResponse)
async def unified_login(
    data: schemas.LoginRequest = Body(...),
    db: AsyncSession = Depends(get_db)
):
    #  check Admin table
    result = await db.execute(select(Admin).where(Admin.email == data.email))
    admin_user = result.scalar_one_or_none()
    if admin_user and await verify_password(data.password, admin_user.hashed_password):
        #  Generate both access and refresh tokens
        access_token = create_access_token(data={"sub": admin_user.email, "role": "admin"})
        refresh_token = create_refresh_token(data={"sub": admin_user.email, "role": "admin"})  

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,  
            "token_type": "bearer",
            "status": "true",
            "role": "admin",
            "message": "Login successful as admin",
            "user": schemas.AdminOut.model_validate(admin_user, from_attributes=True)
        }

    # check in Users table
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()
    if not user or not await verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Generate both access and refresh tokens
    access_token = create_access_token(data={"sub": user.email, "role": user.role})
    refresh_token = create_refresh_token(data={"sub": user.email, "role": user.role})  

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,  
        "token_type": "bearer",
        "status": "true",
        "role": user.role,
        "message": f"Login successful as {user.role}",
        "user": schemas.UserOut.model_validate(user, from_attributes=True)
    }


@app.post("/refresh-token")
async def refresh_token(request: Request):
    data = await request.json()
    token = data.get("refresh_token")
    if not token:
        raise HTTPException(status_code=400, detail="Missing refresh token")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("scope") != "refresh_token":
            raise HTTPException(status_code=401, detail="Invalid scope for token")

        email = payload.get("sub")
        role = payload.get("role")
        if not email or not role:
            raise HTTPException(status_code=401, detail="Invalid token payload")

        new_access_token = create_access_token(data={"sub": email, "role": role})
        return {
            "access_token": new_access_token,
            "token_type": "bearer"
        }

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")



@app.get("/users/me/read", response_model=schemas.UserOut)
async def read_customer(current_user: User = Depends(get_current_user)):
    return current_user

@app.post("/logout", status_code=status.HTTP_200_OK)
async def logout(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        role = payload.get("role")
        if not email or not role:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    return {
        "message": f"Logout successful for role '{role}' and user '{email}'. Thankyou!"
    }


@app.post("/admin/create-user", response_model=schemas.UserOut)
async def create_user_by_admin(
    user_data: schemas.CreateUserByAdmin,
    db: AsyncSession = Depends(get_db),
    current_admin: Admin = Depends(get_current_admin)
):
    
    if user_data.role not in ["staff", "contractor"]:
        raise HTTPException(status_code=400, detail="Admins can only create staff or contractor accounts")

    existing_user = await auth.get_user_by_email_from_users_table(db, user_data.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    return await crud.create_user(db, user=user_data, role=user_data.role)

@app.get("/admin/users", response_model=List[schemas.UserOut])
async def get_all_users(
    db: AsyncSession = Depends(database.get_db),
    current_admin: models.Admin = Depends(auth.get_current_admin)  # admin authentication
):
    result = await db.execute(select(models.User))
    users = result.scalars().all()
    return users


# @app.get("/admin/users", response_model=List[schemas.UserOut])
# async def get_all_users(
#     db: AsyncSession = Depends(database.get_db),
#     current_admin: models.Admin = Depends(auth.get_current_admin)
# ):
#     if not current_admin:
#         return RedirectResponse(url="/login")
#     result = await db.execute(select(models.User))
#     return result.scalars().all()

@app.put("/user/update/{user_id}", response_model=schemas.UserOut)
async def update_any_user(
    user_id: int,  # Required path parameter (no default)
    user_update: schemas.UnifiedUserUpdate,  # Required request body (no default)
    db: AsyncSession = Depends(database.get_db),  # Dependency with default
    current_user: models.Admin = Depends(get_current_admin)  # Dependency with default
):
    result = await db.execute(select(models.User).filter(models.User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    update_data = user_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(user, field, value)

    await db.commit()
    await db.refresh(user)
    return user
