# scripts/init_indexes.py
"""Crée les index Mongo. À lancer une fois au déploiement : python -m scripts.init_indexes"""
from core.database import db


def init_indexes() -> None:
    resets = db["password_resets"]
    resets.create_index("token_hash")
    resets.create_index("expires_at", expireAfterSeconds=0)  # TTL : Mongo purge les tokens expirés
    print("Indexes created.")


if __name__ == "__main__":
    init_indexes()