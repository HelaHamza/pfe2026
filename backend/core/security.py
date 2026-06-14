from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os



import secrets
import hashlib


load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict) -> str:
    payload = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload.update({"exp": expire})
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None




def generate_reset_token() -> str:
    """Token aléatoire haute entropie (256 bits) — celui qui part dans l'email."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Hash stocké en base. SHA-256 suffit : le token est déjà inviolable par entropie."""
    return hashlib.sha256(token.encode()).hexdigest()




OTP_TTL_MINUTES = 10  # ou dans config.py

def generate_otp(length: int = 6) -> str:
    """Génère un code numérique à 6 chiffres."""
    return str(secrets.randbelow(10**length)).zfill(length)

def hash_otp(code: str) -> str:
    """Hash SHA-256 simple pour stocker l'OTP."""
    return hashlib.sha256(code.encode()).hexdigest()