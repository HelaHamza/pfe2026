# controllers/feedback_controller.py
from fastapi import HTTPException, status
from core.email import (
    send_feedback_notification, send_feedback_approved,
    send_feedback_rejected, ADMIN_EMAIL,
)
from models.feedback_model import (
    FeedbackCreateRequest, FeedbackResponse, FeedbackActionRequest,
)
from repositories import feedback_repository as feedbacks
from datetime import datetime, timezone
from typing import List


def submit_feedback(body: FeedbackCreateRequest, current_user: dict) -> dict:
    if not body.message.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Message cannot be empty")

    full_name = f"{current_user.get('first_name', '')} {current_user.get('last_name', '')}".strip() or current_user["email"]

    feedbacks.insert({
        "user_email": current_user["email"],
        "user_name":  full_name,
        "message":    body.message.strip(),
        "rating":     body.rating,
        "status":     "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
    })

    try:
        send_feedback_notification(ADMIN_EMAIL, full_name, current_user["email"], body.message)
    except Exception as e:
        print(f"[EMAIL WARNING] feedback notification failed: {e}")

    return {"message": "Feedback submitted. Thank you!"}


def get_approved_feedbacks() -> List[FeedbackResponse]:
    return [FeedbackResponse.from_mongo(f) for f in feedbacks.find_by_status("approved")]


def get_all_feedbacks() -> List[FeedbackResponse]:
    return [FeedbackResponse.from_mongo(f) for f in feedbacks.find_all()]


def action_feedback(body: FeedbackActionRequest) -> dict:
    fb = feedbacks.find_by_id(body.feedback_id)
    if not fb:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Feedback not found")

    new_status = "approved" if body.action == "approve" else "rejected"
    feedbacks.update_status(body.feedback_id, new_status)

    try:
        if body.action == "approve":
            send_feedback_approved(fb["user_email"], fb["user_name"])
        else:
            send_feedback_rejected(fb["user_email"], fb["user_name"])
    except Exception as e:
        print(f"[EMAIL WARNING] feedback action email failed: {e}")

    return {"message": f"Feedback {new_status}"}