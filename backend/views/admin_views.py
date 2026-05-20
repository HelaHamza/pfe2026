from fastapi import APIRouter, Depends
from typing import List
from models.user_model import ApproveUserRequest, UserResponse
from controllers.admin_controller import list_pending_users, list_all_users, approve_or_reject_user
from core.deps import get_admin_user

router = APIRouter(prefix="/admin", tags=["Admin"])


@router.get("/users/pending", response_model=List[UserResponse])
def pending_users(admin: dict = Depends(get_admin_user)):
    """List all users awaiting approval."""
    return list_pending_users()


@router.get("/users", response_model=List[UserResponse])
def all_users(admin: dict = Depends(get_admin_user)):
    """List all non-admin users."""
    return list_all_users()


@router.post("/users/approve")
def approve_user(body: ApproveUserRequest, admin: dict = Depends(get_admin_user)):
    """Approve or reject a user registration."""
    return approve_or_reject_user(body)