# repositories/password_reset_repository.py
"""Accès aux tokens de réinitialisation — collection dédiée, jamais le token en clair."""
from datetime import datetime, timezone
from typing import Optional
from core.database import db

_collection = db["password_resets"]


def create(email: str, token_hash: str, expires_at: datetime) -> None:
    _collection.insert_one({
        "email":      email,
        "token_hash": token_hash,
        "expires_at": expires_at,
    })


def find_valid(token_hash: str) -> Optional[dict]:
    """Renvoie le token s'il existe ET n'est pas expiré. La comparaison de date
    se fait côté Mongo ($gt) pour éviter les pièges naive/aware de pymongo."""
    return _collection.find_one({
        "token_hash": token_hash,
        "expires_at": {"$gt": datetime.now(timezone.utc)},
    })


def delete_for_email(email: str) -> None:
    """Invalide les anciens tokens avant d'en créer un nouveau (un seul actif)."""
    _collection.delete_many({"email": email})


def consume(token_hash: str) -> None:
    """Usage unique : on supprime le token après réinitialisation réussie."""
    _collection.delete_one({"token_hash": token_hash})