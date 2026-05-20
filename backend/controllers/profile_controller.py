from fastapi import HTTPException, status
from core.database import users_collection
from models.user_model import ProfileUpdateRequest, UserResponse


def _to_user_response(u: dict) -> UserResponse:
    return UserResponse(
        email=u["email"],
        role=u.get("role", "user"),
        first_name=u.get("first_name", ""),
        last_name=u.get("last_name", ""),
        phone=u.get("phone", ""),
        sex=u.get("sex", ""),
        address=u.get("address", ""),
        specialty=u.get("specialty", ""),
        status=u.get("status", ""),
        avatar=u.get("avatar"),
    )


def get_profile(current_user: dict) -> UserResponse:
    return _to_user_response(current_user)


def update_profile(body: ProfileUpdateRequest, current_user: dict) -> UserResponse:
    updates = {k: v for k, v in body.model_dump().items() if v is not None}

    if not updates:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No fields to update")

    users_collection.update_one(
        {"email": current_user["email"]},
        {"$set": updates}
    )

    updated = users_collection.find_one({"email": current_user["email"]})
    return _to_user_response(updated)