from pydantic import BaseModel, EmailStr
from typing import Literal, Optional


class FeedbackCreateRequest(BaseModel):
    message: str
    rating: Optional[int] = None   # 1-5 stars, optional


class FeedbackResponse(BaseModel):
    id: str
    user_email: str
    user_name:  str
    message:    str
    rating:     Optional[int] = None
    status:     Literal["pending", "approved", "rejected"] = "pending"
    created_at: str


class FeedbackActionRequest(BaseModel):
    feedback_id: str
    action: Literal["approve", "reject"]