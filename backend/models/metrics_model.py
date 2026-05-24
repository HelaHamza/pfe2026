"""
=============================================================================
models/metrics_model.py
Accès aux métriques de modèle stockées dans MongoDB (version pymongo / sync).
=============================================================================
"""
from datetime import datetime, timezone
from typing import Optional

from core.database import db  # ⚠ adapte au nom réel de ton handle Mongo


class MetricsRepository:
    COLLECTION = "model_metrics"

    def __init__(self):
        self.col = db[self.COLLECTION]

    def insert_metrics(self, metrics: dict) -> str:
        version = metrics.get("version")
        if not version:
            raise ValueError("Le JSON de métriques doit contenir un champ 'version'.")
        metrics.setdefault("ingested_at", datetime.now(timezone.utc).isoformat())
        self.col.replace_one({"version": version}, metrics, upsert=True)
        return version

    def count_versions(self) -> int:
        return self.col.count_documents({})

    def list_versions(self) -> list[dict]:
        cursor = self.col.find(
            {},
            {
                "_id": 0,
                "version": 1,
                "ingested_at": 1,
                "epochs_trained": 1,
                "best_val_loss": 1,
                "train_duration_s": 1,
                "global_metrics.f1_score": 1,
            },
        ).sort("ingested_at", 1)
        return list(cursor)

    def get_version(self, version: str) -> Optional[dict]:
        return self.col.find_one({"version": version}, {"_id": 0})

    def get_many(self, versions: list[str]) -> list[dict]:
        cursor = self.col.find({"version": {"$in": versions}}, {"_id": 0})
        return list(cursor)

    def get_latest(self) -> Optional[dict]:
        cursor = self.col.find({}, {"_id": 0}).sort("ingested_at", -1).limit(1)
        docs = list(cursor)
        return docs[0] if docs else None

    def get_all_ordered(self) -> list[dict]:
        cursor = self.col.find({}, {"_id": 0}).sort("ingested_at", 1)
        return list(cursor)