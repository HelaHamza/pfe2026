from fastapi import APIRouter, Depends
from typing import List
from models.feedback_model import FeedbackCreateRequest, FeedbackResponse, FeedbackActionRequest
from controllers.feedback_controller import submit_feedback, get_approved_feedbacks, get_all_feedbacks, action_feedback
from core.deps import get_current_user, get_admin_user

router = APIRouter(prefix="/feedback", tags=["Feedback"])


@router.post("/", status_code=201)
def create_feedback(body: FeedbackCreateRequest, current_user: dict = Depends(get_current_user)):
    """Submit feedback (authenticated users only)."""
    return submit_feedback(body, current_user)


@router.get("/approved", response_model=List[FeedbackResponse])
def approved_feedbacks():
    """Public — returns only approved feedbacks for the testimonials section."""
    return get_approved_feedbacks()


@router.get("/all", response_model=List[FeedbackResponse])
def all_feedbacks(admin: dict = Depends(get_admin_user)):
    """Admin only — returns all feedbacks with their status."""
    return get_all_feedbacks()


@router.post("/action")
def feedback_action(body: FeedbackActionRequest, admin: dict = Depends(get_admin_user)):
    """Admin only — approve or reject a feedback."""
    return action_feedback(body)