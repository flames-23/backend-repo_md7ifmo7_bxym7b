from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, Literal
from datetime import datetime

# Users
class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: str = Field(..., description="Email address")
    password_hash: str = Field(..., description="SHA256 hash of password")
    role: Literal["admin", "user"] = Field("user", description="User role")
    is_active: bool = Field(True, description="Whether user is active")

# Sessions (simple token auth)
class Session(BaseModel):
    user_id: str
    token: str
    expires_at: datetime

# PDF resources
class Pdf(BaseModel):
    title: str
    description: Optional[str] = None
    url: HttpUrl
    tags: Optional[list[str]] = None

# Patient check-up entries
class Checkup(BaseModel):
    patient_name: Optional[str] = Field(None, description="Optional patient display name")
    department: Optional[str] = None
    notes: Optional[str] = None
    date: Optional[datetime] = Field(None, description="Explicit date of check-up; defaults to now")
