# controllers/profile_controller.py
from fastapi import HTTPException, status
from models.user_model import ProfileUpdateRequest, UserResponse
from repositories import user_repository as users


def get_profile(current_user: dict) -> UserResponse:
    return UserResponse.from_mongo(current_user)


def update_profile(body: ProfileUpdateRequest, current_user: dict) -> UserResponse:
    updates = {k: v for k, v in body.model_dump().items() if v is not None}

    if not updates:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No fields to update")

    users.update_fields(current_user["email"], updates)

    updated = users.find_by_email(current_user["email"])
    return UserResponse.from_mongo(updated)