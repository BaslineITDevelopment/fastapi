



from sqlalchemy.ext.asyncio import AsyncSession
from . import models, schemas
from .auth import get_password_hash
from typing import Union

# async def create_user(db: AsyncSession, user: schemas.UserCreate, role: str = "customer"):
#     hashed_password = await get_password_hash(user.password)
#     db_user = models.User(
#         first_name=user.first_name,
#         last_name=user.last_name,
#         username=user.username,
#         email=user.email,
#         hashed_password=hashed_password,
#         company_name=user.company_name,
#         phone_number=user.phone_number,                  
#         country=user.country,                            
#         timezone=user.timezone,                          
#         subscription_plan=user.subscription_plan or "free",
#         role=role  
#     )
#     db.add(db_user)
#     await db.commit()
#     await db.refresh(db_user)
#     return db_user

# async def update_user(db: AsyncSession, user: models.User, user_update: schemas.UserUpdate):
#     for field, value in user_update.dict(exclude_unset=True).items():
#         setattr(user, field, value)
#     db.add(user)
#     await db.commit()
#     await db.refresh(user)
#     return user
async def create_user(db: AsyncSession, user: Union[schemas.UserCreate, schemas.CreateUserByAdmin], role: str = "customer"):
    hashed_password = await get_password_hash(user.password)
    db_user = models.User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        first_name=user.first_name,
        last_name=user.last_name,
        company_name=user.company_name,
        phone_number=user.phone_number,
        country=user.country,
        timezone=user.timezone,
        subscription_plan=user.subscription_plan,
        role=role,
    )
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user

# In crud.py add this function
async def create_request_log(db: AsyncSession, log_data: dict):
    from .logging_model import RequestLog
    try:
        db_log = RequestLog(
            timestamp=log_data["timestamp"],
            method=log_data["method"],
            path=log_data["path"],
            ip=log_data["ip"],
            status_code=log_data["status_code"],
            process_time_ms=log_data["process_time_ms"],
            user_agent=log_data["user_agent"],
            additional_data=log_data.get("additional_data")
        )
        db.add(db_log)
        await db.commit()
        await db.refresh(db_log)
        return db_log
    except Exception as e:
        await db.rollback()
        raise e