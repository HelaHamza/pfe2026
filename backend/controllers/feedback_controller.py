from fastapi import HTTPException, status
from core.database import db
from core.email import send_feedback_notification, send_feedback_approved, send_feedback_rejected, ADMIN_EMAIL
from models.feedback_model import FeedbackCreateRequest, FeedbackResponse, FeedbackActionRequest
from bson import ObjectId
from datetime import datetime, timezone
from typing import List

feedback_collection = db["feedbacks"]


def _serialize(f: dict) -> FeedbackResponse:
    return FeedbackResponse(
        id=str(f["_id"]),
        user_email=f.get("user_email", ""),
        user_name=f.get("user_name", ""),
        message=f.get("message", ""),
        rating=f.get("rating"),
        status=f.get("status", "pending"),
        created_at=f.get("created_at", ""),
    )


def submit_feedback(body: FeedbackCreateRequest, current_user: dict) -> dict:
    if not body.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    full_name = f"{current_user.get('first_name', '')} {current_user.get('last_name', '')}".strip() or current_user["email"]

    doc = {
        "user_email": current_user["email"],
        "user_name":  full_name,
        "message":    body.message.strip(),
        "rating":     body.rating,
        "status":     "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    feedback_collection.insert_one(doc)

    try:
        send_feedback_notification(ADMIN_EMAIL, full_name, current_user["email"], body.message)
    except Exception as e:
        print(f"[EMAIL WARNING] feedback notification failed: {e}")

    return {"message": "Feedback submitted. Thank you!"}


def get_approved_feedbacks() -> List[FeedbackResponse]:
    feedbacks = feedback_collection.find({"status": "approved"}).sort("created_at", -1)
    return [_serialize(f) for f in feedbacks]


def get_all_feedbacks() -> List[FeedbackResponse]:
    feedbacks = feedback_collection.find().sort("created_at", -1)
    return [_serialize(f) for f in feedbacks]


def action_feedback(body: FeedbackActionRequest) -> dict:
    try:
        oid = ObjectId(body.feedback_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid feedback ID")

    fb = feedback_collection.find_one({"_id": oid})
    if not fb:
        raise HTTPException(status_code=404, detail="Feedback not found")

    new_status = "approved" if body.action == "approve" else "rejected"
    feedback_collection.update_one({"_id": oid}, {"$set": {"status": new_status}})

    try:
        if body.action == "approve":
            send_feedback_approved(fb["user_email"], fb["user_name"])
        else:
            send_feedback_rejected(fb["user_email"], fb["user_name"])
    except Exception as e:
        print(f"[EMAIL WARNING] feedback action email failed: {e}")

    return {"message": f"Feedback {new_status}"}