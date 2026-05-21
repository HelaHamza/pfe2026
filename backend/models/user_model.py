from pydantic import BaseModel, EmailStr, Field
from typing import Literal, Optional


# ── Stored in MongoDB ──────────────────────────────────────────────
class UserInDB(BaseModel):
    email: EmailStr
    password: str
    first_name: str = ""
    last_name:  str = ""
    phone:      str = ""
    sex:        str = ""
    address:    str = ""
    specialty: Literal["ia_user", "soc_user"] = "ia_user"
    role: Literal["admin", "user"] = "user"
    status: Literal["pending", "approved", "rejected"] = "pending"
    avatar: Optional[str] = None

    class Config:
        arbitrary_types_allowed = True


# ── Auth ───────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class SignUpRequest(BaseModel):
    first_name: str  = Field(min_length=1)
    last_name:  str  = Field(min_length=1)
    email:      EmailStr
    password:   str  = Field(min_length=6)
    phone:      str  = ""
    sex:        str  = ""
    specialty: Literal["ia_user", "soc_user"] = "ia_user"


# ── Profile ────────────────────────────────────────────────────────
class ProfileUpdateRequest(BaseModel):
    first_name: Optional[str] = None
    last_name:  Optional[str] = None
    phone:      Optional[str] = None
    sex:        Optional[str] = None
    address:    Optional[str] = None
    avatar:     Optional[str] = None


# ── Admin ──────────────────────────────────────────────────────────
class ApproveUserRequest(BaseModel):
    email:  EmailStr
    action: Literal["approve", "reject"]


# ── Responses ──────────────────────────────────────────────────────
class UserResponse(BaseModel):
    email:      EmailStr
    role:       str       = ""
    first_name: str       = ""
    last_name:  str       = ""
    phone:      str       = ""
    sex:        str       = ""
    address:    str       = ""
    specialty:  str       = ""
    status:     str       = ""
    avatar:     Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    user:         UserResponse