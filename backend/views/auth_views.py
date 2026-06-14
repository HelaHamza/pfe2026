from fastapi import APIRouter

from models.user_model import (
    LoginRequest, SignUpRequest, TokenResponse,
    ForgotPasswordRequest, ResetPasswordRequest,
    VerifyOTPRequest,                               # ← import depuis models, pas controllers
)
from controllers.auth_controller import (
    login_user, signup_user,
    request_password_reset, confirm_password_reset,
    verify_otp_and_login,                           # ← import direct de la fonction
)

router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post("/login")                              # ← supprime response_model=TokenResponse
def login(body: LoginRequest):
    """Step 1 : validate credentials and send OTP."""
    return login_user(body)


@router.post("/verify-otp", response_model=TokenResponse)   # ← response_model ici
def verify_otp(body: VerifyOTPRequest):
    """Step 2 : verify OTP and receive JWT."""
    return verify_otp_and_login(body)               # ← appel direct, pas auth_service.


@router.post("/signup", status_code=201)
def signup(body: SignUpRequest):
    """Register a new user account (pending admin approval)."""
    return signup_user(body)


@router.post("/forgot-password")
def forgot_password(body: ForgotPasswordRequest):
    """Demande un lien de réinitialisation. Réponse générique (anti-énumération)."""
    return request_password_reset(body)


@router.post("/reset-password")
def reset_password(body: ResetPasswordRequest):
    """Réinitialise le mot de passe à partir d'un token valide."""
    return confirm_password_reset(body)