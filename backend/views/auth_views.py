from fastapi import APIRouter
from models.user_model import LoginRequest, SignUpRequest, TokenResponse
from controllers.auth_controller import login_user, signup_user, seed_admin

router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest):
    """Authenticate and receive a JWT token."""
    return login_user(body)


@router.post("/signup", status_code=201)
def signup(body: SignUpRequest):
    """Register a new user account (pending admin approval)."""
    return signup_user(body)


@router.post("/create-admin")
def create_admin():
    """Seed the default admin account (run once)."""
    return seed_admin()