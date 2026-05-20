from fastapi import APIRouter, Depends
from models.user_model import ProfileUpdateRequest, UserResponse
from controllers.profile_controller import get_profile, update_profile
from core.deps import get_current_user

router = APIRouter(prefix="/profile", tags=["Profile"])


@router.get("/me", response_model=UserResponse)
def read_profile(current_user: dict = Depends(get_current_user)):
    return get_profile(current_user)


@router.patch("/me", response_model=UserResponse)
def edit_profile(body: ProfileUpdateRequest, current_user: dict = Depends(get_current_user)):
    return update_profile(body, current_user)