from datetime import datetime, timezone
from core.database import db  # ton client MongoDB

COLLECTION = "otp_codes"

def create(email: str, code_hash: str, expires_at: datetime):
    db[COLLECTION].delete_many({"email": email})  # un seul OTP actif par user
    db[COLLECTION].insert_one({
        "email": email,
        "code_hash": code_hash,
        "expires_at": expires_at,
        "used": False,
    })

def find_valid(email: str, code_hash: str):
    return db[COLLECTION].find_one({
        "email": email,
        "code_hash": code_hash,
        "used": False,
        "expires_at": {"$gt": datetime.now(timezone.utc)},
    })

def consume(email: str, code_hash: str):
    db[COLLECTION].update_one(
        {"email": email, "code_hash": code_hash},
        {"$set": {"used": True}},
    )