from __future__ import annotations

import logging

import pymongo
from pymongo.errors import PyMongoError

from config import MONGO_COLL_RETRAIN
from core.database import get_db
from core.exceptions import PersistenceError
from models.retrain_run_model import AcceptanceStats, RetrainRunDocument

log = logging.getLogger(__name__)


class MongoRetrainRepository:

    def __init__(self, db=None):
        self._db_override = db

    @property
    def _db(self):
        return self._db_override if self._db_override is not None else get_db()

    @property
    def _coll(self):
        return self._db[MONGO_COLL_RETRAIN]

    def insert_gate(self, doc: RetrainRunDocument) -> str:
        """Upsert idempotent sur created_at : ré-ingérer le même gate_*.json
        remplace, ne duplique pas."""
        payload = doc.model_dump()
        try:
            self._coll.replace_one({"created_at": doc.created_at},
                                   payload, upsert=True)
        except PyMongoError as e:
            raise PersistenceError(f"Gate {doc.created_at} non écrit : {e}") from e
        log.info("Gate %s (%s) → %s", doc.created_at, doc.verdict,
                 MONGO_COLL_RETRAIN)
        return str(doc.created_at)

    def get_last(self) -> dict | None:
        doc = self._coll.find_one(sort=[("created_at", pymongo.DESCENDING)])
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    def last_accepted(self) -> dict | None:
        """Dernier gate ACCEPTé = modèle actuellement en production (le
        candidat promu devient le courant). Fournit la version déployée et la
        date de promotion à la carte « Modèle en production »."""
        doc = self._coll.find_one({"accepted": True},
                                  sort=[("created_at", pymongo.DESCENDING)])
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    def list_recent(self, limit: int = 20) -> list[dict]:
        cur = self._coll.find().sort("created_at", pymongo.DESCENDING).limit(limit)
        out = []
        for d in cur:
            d["_id"] = str(d["_id"])
            out.append(d)
        return out

    def acceptance_stats(self) -> AcceptanceStats:
        """Taux d'acceptation compté DANS Mongo sur tous les gates."""
        n_acc = n_rej = 0
        for r in self._coll.aggregate(
                [{"$group": {"_id": "$accepted", "n": {"$sum": 1}}}]):
            if r["_id"]:
                n_acc = r["n"]
            else:
                n_rej = r["n"]
        total = n_acc + n_rej
        return AcceptanceStats(
            n_total=total, n_accepted=n_acc, n_rejected=n_rej,
            acceptance_rate=round(100 * n_acc / total, 1) if total else 0.0)


RetrainRepository = MongoRetrainRepository()