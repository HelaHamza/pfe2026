#Repository = le comment accéder aux données. Sa seule responsabilité est de lire/écrire dans la base. Il connaît Mongo, les noms de collections, la syntaxe des filtres. Il ne prend aucune décision : on lui demande un user par email, il le renvoie (ou None), point.


# repositories/feedback_repository.py
"""Accès aux données feedback — seule couche qui connaît la collection et ObjectId."""
from typing import Optional
from bson import ObjectId
from bson.errors import InvalidId
from core.database import db

_collection = db["feedbacks"]


def insert(doc: dict) -> None:
    _collection.insert_one(doc)


def find_by_status(status: str) -> list[dict]:
    return list(_collection.find({"status": status}).sort("created_at", -1))


def find_all() -> list[dict]:
    return list(_collection.find().sort("created_at", -1))


def find_by_id(feedback_id: str) -> Optional[dict]:
    """Renvoie None si l'id est mal formé OU si le document n'existe pas.
    Le controller n'a pas à connaître ObjectId."""
    try:
        oid = ObjectId(feedback_id)
    except (InvalidId, TypeError):
        return None
    return _collection.find_one({"_id": oid})


def update_status(feedback_id: str, status: str) -> None:
    _collection.update_one({"_id": ObjectId(feedback_id)}, {"$set": {"status": status}})