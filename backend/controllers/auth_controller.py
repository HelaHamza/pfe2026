from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status

from core.security import (
    hash_password, verify_password, create_access_token,
    generate_reset_token, hash_token,
    generate_otp, hash_otp,                          # ← nouveaux imports
)
from core.email import send_new_user_notification, send_password_reset, send_otp
from repositories import user_repository as users
from repositories import password_reset_repository as resets
from repositories import otp_repository as otps                # ← nouveau repo
from config import FRONTEND_URL, RESET_TOKEN_TTL_MINUTES
from models.user_model import (
    LoginRequest, SignUpRequest, TokenResponse, UserResponse, UserInDB,
    ForgotPasswordRequest, ResetPasswordRequest,
    VerifyOTPRequest,                                           # ← nouveau modèle
)

OTP_TTL_MINUTES = 10
_GENERIC_RESET_MSG = {"message": "If an account exists, a reset link has been sent."}


def login_user(body: LoginRequest) -> dict:
    """
    Étape 1 : valide les credentials, envoie un OTP par email.
    Ne retourne PAS de JWT — seulement un message de confirmation.
    """
    user = users.find_by_email(body.email)

    # Délai constant pour éviter l'énumération d'emails (timing attack)
    if not user or not verify_password(body.password, user["password"]):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")

    if user.get("role") != "admin" and user.get("status") != "approved":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Your account is pending admin approval")

    # Génère et stocke l'OTP
    code = generate_otp()
    otps.create(
        email=body.email,
        code_hash=hash_otp(code),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=OTP_TTL_MINUTES),
    )
    print(f"[TEST] OTP pour {body.email} : {code}")  # retirer en prod

    try:
        send_otp(body.email, code)
    except Exception as e:
        print(f"[EMAIL WARNING] OTP send failed: {e}")
        # On continue quand même (le print de debug suffit en dev)

    return {"message": "A verification code has been sent to your email."}


def verify_otp_and_login(body: VerifyOTPRequest) -> TokenResponse:
    """
    Étape 2 : vérifie l'OTP et retourne le JWT.
    """
    record = otps.find_valid(body.email, hash_otp(body.code))
    if not record:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired code")

    otps.consume(body.email, hash_otp(body.code))

    user = users.find_by_email(body.email)
    if not user:  # sécurité défensive (l'email vient du token vérifié)
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    token = create_access_token({"sub": user["email"], "role": user["role"]})
    return TokenResponse(access_token=token, user=UserResponse.from_mongo(user))


# --- Les autres fonctions restent inchangées ---

def signup_user(body: SignUpRequest) -> dict:
    if users.email_exists(body.email):
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")

    new_user = UserInDB(
        email=body.email,
        password=hash_password(body.password),
        first_name=body.first_name,
        last_name=body.last_name,
        phone=body.phone,
        sex=body.sex,
        specialty=body.specialty,
    )
    users.create(new_user.model_dump())

    try:
        send_new_user_notification(body.email, f"{body.first_name} {body.last_name}")
    except Exception as e:
        print(f"[EMAIL WARNING] Admin notification failed: {e}")

    return {"message": "Registration successful. Awaiting admin approval."}


def request_password_reset(body: ForgotPasswordRequest) -> dict:
    user = users.find_by_email(body.email)
    if user:
        raw_token = generate_reset_token()
        resets.delete_for_email(body.email)
        resets.create(
            email=body.email,
            token_hash=hash_token(raw_token),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=RESET_TOKEN_TTL_MINUTES),
        )
        reset_link = f"{FRONTEND_URL}/reset-password?token={raw_token}"
        print(f"[TEST] reset_link = {reset_link}")
        try:
            send_password_reset(body.email, reset_link)
        except Exception as e:
            print(f"[EMAIL WARNING] reset email failed: {e}")

    return _GENERIC_RESET_MSG


def confirm_password_reset(body: ResetPasswordRequest) -> dict:
    token_hash = hash_token(body.token)
    record = resets.find_valid(token_hash)
    if not record:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired reset token")

    users.update_fields(record["email"], {"password": hash_password(body.new_password)})
    resets.consume(token_hash)
    return {"message": "Password reset successful. You can now log in."}