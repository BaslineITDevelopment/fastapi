

from sqlalchemy import Column, Integer, String, Boolean, DateTime, TIMESTAMP, text, ARRAY, JSON 

from sqlalchemy.sql import func
from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    company_name = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())  
    phone_number = Column(String, nullable=False)            
    country = Column(String, nullable=False)                 
    timezone = Column(String, nullable=False)               
    subscription_plan = Column(String, nullable=False, default="free")     
    is_verified = Column(Boolean, default=False)
    role = Column(String, default="customer")
    permissions = Column(ARRAY(String), default=["read"])

class Admin(Base):
    __tablename__ = "admins"

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String)
    last_name = Column(String)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    company_name = Column(String)
    role = Column(String)
    phone_number = Column(String)
    country = Column(String)
    timezone = Column(String)
    subscription_plan = Column(String, server_default="free")
    created_at = Column(TIMESTAMP, server_default=text("CURRENT_TIMESTAMP"))
    permissions = Column(ARRAY(String), default=["read", "write", "delete"])

# class RequestLog(Base):
#     __tablename__ = "request_logs"
    
#     id = Column(Integer, primary_key=True, index=True)
#     timestamp = Column(DateTime)
#     method = Column(String)
#     path = Column(String)
#     ip = Column(String)
#     status_code = Column(Integer)
#     process_time_ms = Column(Integer)
#     user_agent = Column(String)
#     additional_data = Column(JSON)  # For storing login attempts, API usage etc.
# class Staff(Base):
#     __tablename__ = "staffs"

#     id = Column(Integer, primary_key=True, index=True)
#     first_name = Column(String)
#     last_name = Column(String)
#     username = Column(String, unique=True, nullable=False)
#     email = Column(String, unique=True, nullable=False)
#     hashed_password = Column(String, nullable=False)
#     created_at = Column(TIMESTAMP, server_default=text("CURRENT_TIMESTAMP"))
#     company_name = Column(String)
#     role = Column(String)
#     phone_number = Column(String)
#     country = Column(String)
#     timezone = Column(String)
#     subscription_plan = Column(String, server_default="free")

# class Contractor(Base):
#     __tablename__ = "contractors"

#     id = Column(Integer, primary_key=True, index=True)
#     first_name = Column(String)
#     last_name = Column(String)
#     username = Column(String, unique=True, nullable=False)
#     email = Column(String, unique=True, nullable=False)
#     hashed_password = Column(String, nullable=False)
#     created_at = Column(TIMESTAMP, server_default=text("CURRENT_TIMESTAMP"))
#     company_name = Column(String)
#     role = Column(String)
#     phone_number = Column(String)
#     country = Column(String)
#     timezone = Column(String)
#     subscription_plan = Column(String, server_default="free")



