from fastapi import HTTPException, status
from core.database import users_collection
from core.email import send_approval_notification, send_rejection_notification
from models.user_model import ApproveUserRequest, UserResponse
from typing import List


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
        status=u.get("status", "pending"),
        avatar=u.get("avatar"),
    )


def list_pending_users() -> List[UserResponse]:
    users = users_collection.find({"status": "pending"})
    return [_to_user_response(u) for u in users]


def list_all_users() -> List[UserResponse]:
    users = users_collection.find({"role": {"$ne": "admin"}})
    return [_to_user_response(u) for u in users]


def approve_or_reject_user(body: ApproveUserRequest) -> dict:
    user = users_collection.find_one({"email": body.email})
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if user.get("status") == ("approved" if body.action == "approve" else "rejected"):
        return {"message": f"User is already {body.action}d"}

    new_status = "approved" if body.action == "approve" else "rejected"
    users_collection.update_one({"email": body.email}, {"$set": {"status": new_status}})

    full_name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip() or user["email"]

    try:
        if body.action == "approve":
            send_approval_notification(user["email"], full_name)
        else:
            send_rejection_notification(user["email"], full_name)
    except Exception as e:
        print(f"[EMAIL WARNING] Could not send notification: {e}")

    return {"message": f"User {body.action}d successfully"}