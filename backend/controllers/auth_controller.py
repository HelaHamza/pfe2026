from fastapi import HTTPException, status
from core.database import users_collection
from core.security import hash_password, verify_password, create_access_token
from core.email import send_new_user_notification, send_admin_welcome
from models.user_model import LoginRequest, SignUpRequest, TokenResponse, UserResponse


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


def login_user(body: LoginRequest) -> TokenResponse:
    user = users_collection.find_one({"email": body.email})

    if not user or not verify_password(body.password, user["password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid email or password")

    if user.get("role") != "admin" and user.get("status") != "approved":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Your account is pending admin approval")

    token = create_access_token({"sub": user["email"], "role": user["role"]})
    return TokenResponse(access_token=token, user=_to_user_response(user))


def signup_user(body: SignUpRequest) -> dict:
    if users_collection.find_one({"email": body.email}):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Email already registered")

    new_user = {
        "email":      body.email,
        "password":   hash_password(body.password),
        "first_name": body.first_name,
        "last_name":  body.last_name,
        "phone":      body.phone,
        "sex":        body.sex,
        "specialty":  body.specialty,
        "role":       "user",
        "status":     "pending",
        "address":    "",
        "avatar":     None,
    }
    users_collection.insert_one(new_user)

    try:
        send_new_user_notification(body.email, f"{body.first_name} {body.last_name}")
    except Exception as e:
        print(f"[EMAIL WARNING] Admin notification failed: {e}")

    return {"message": "Registration successful. Awaiting admin approval."}


def seed_admin() -> dict:
    email = "helahamza2020@gmail.com"

    if users_collection.find_one({"email": email}):
        return {"message": "Admin already exists"}

    users_collection.insert_one({
        "email":      email,
        "password":   hash_password("admin123"),
        "first_name": "Admin",
        "last_name":  "User",
        "role":       "admin",
        "status":     "approved",
        "specialty":  "admin",
        "phone": "", "sex": "", "address": "", "avatar": None,
    })

    # Send welcome email to admin
    try:
        send_admin_welcome(email)
    except Exception as e:
        print(f"[EMAIL WARNING] Admin welcome email failed: {e}")

    return {"message": "Admin created successfully"}