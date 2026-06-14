# models/feedback_model.py
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

    @classmethod
    def from_mongo(cls, f: dict) -> "FeedbackResponse":
        """Convertit un document Mongo brut en schéma de réponse.
        Le str(_id) est l'inverse du ObjectId(...) côté repository."""
        return cls(
            id=str(f["_id"]),
            user_email=f.get("user_email", ""),
            user_name=f.get("user_name", ""),
            message=f.get("message", ""),
            rating=f.get("rating"),
            status=f.get("status", "pending"),
            created_at=f.get("created_at", ""),
        )


class FeedbackActionRequest(BaseModel):
    feedback_id: str
    action: Literal["approve", "reject"]