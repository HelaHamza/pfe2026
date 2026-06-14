from fastapi import HTTPException, status
from core.email import send_approval_notification, send_rejection_notification
from models.user_model import ApproveUserRequest, UserResponse
from repositories import user_repository as users
from typing import List


def list_pending_users() -> List[UserResponse]:
    return [UserResponse.from_mongo(u) for u in users.list_by_status("pending")]


def list_all_users() -> List[UserResponse]:
    return [UserResponse.from_mongo(u) for u in users.list_non_admin()]


def approve_or_reject_user(body: ApproveUserRequest) -> dict:
    user = users.find_by_email(body.email)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    new_status = "approved" if body.action == "approve" else "rejected"
    if user.get("status") == new_status:
        return {"message": f"User is already {body.action}d"}

    users.update_fields(body.email, {"status": new_status})

    full_name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip() or user["email"]
    try:
        if body.action == "approve":
            send_approval_notification(user["email"], full_name)
        else:
            send_rejection_notification(user["email"], full_name)
    except Exception as e:
        print(f"[EMAIL WARNING] Could not send notification: {e}")

    return {"message": f"User {body.action}d successfully"}