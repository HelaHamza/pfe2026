# repositories/user_repository.py
"""Accès aux données utilisateur. Seule couche qui connaît la collection Mongo."""
from typing import Optional
from core.database import db

_collection = db["users"]


def find_by_email(email: str) -> Optional[dict]:
    return _collection.find_one({"email": email})


def email_exists(email: str) -> bool:
    return _collection.find_one({"email": email}, {"_id": 1}) is not None


def create(user: dict) -> None:
    _collection.insert_one(user)


def update_fields(email: str, fields: dict) -> None:
    _collection.update_one({"email": email}, {"$set": fields})


def list_by_status(status: str) -> list[dict]:
    return list(_collection.find({"status": status}))


def list_non_admin() -> list[dict]:
    return list(_collection.find({"role": {"$ne": "admin"}}))