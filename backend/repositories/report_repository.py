"""
repositories/report_repository.py
=================================
Accès Mongo aux détections (CNN + Sigma), aux curseurs incrémentaux et aux
rapports de run.

CORRECTIFS PAR RAPPORT À LA VERSION PRÉCÉDENTE
----------------------------------------------
1. `_id = "{run_id}::{clé}"`. Avant, `_id = episode_id` / `dedup_key` seul :
   une re-détection au run N+1 écrasait le document et son `run_id` passait
   à N+1 → le rapport du run N devenait incomplet RÉTROACTIVEMENT.
   La déduplication inter-runs se fait maintenant par le champ indexé
   `dedup_key`, pas par la clé primaire.

2. `event_time` = heure de l'ÉVÉNEMENT, en BSON date. Avant, Sigma stockait
   `@timestamp = now()` : toutes les alertes d'un run recevaient l'heure du
   run et remontaient systématiquement au-dessus des épisodes CNN, plus
   anciens en apparence. Sur un dashboard chronologique, c'était faux.
   `indexed_at` conserve l'heure d'écriture pour l'audit.

3. Clé Sigma DÉTERMINISTE. Avant : `dedup_key or uuid4()` → idempotence
   aléatoire, et deux commentaires contradictoires dans le code.
   Secours = sha1(title|log_source|rule_kind|event_time).

4. Les échecs d'écriture LÈVENT (`PersistenceError`) au lieu d'être avalés
   par un `print`. Sans ça, l'orchestrateur recevait « 40 » sur 47 épisodes
   et avançait le curseur : 7 épisodes perdus définitivement.

5. `severity` unifiée (minuscules) sur les DEUX collections : le mapping
   caché `severity`/`level` disparaît.

6. `logging` au lieu de `print`, et politique d'erreur homogène :
   ÉCRITURE → lève ; LECTURE → laisse remonter (500 explicite).

7. La classe est instanciable (`db` injectable) donc testable ; le nom
   exporté `ReportRepository` reste une instance module-level, ce qui
   préserve tous les appels existants `ReportRepository.methode(...)`.
"""
from __future__ import annotations

import hashlib
import logging

import pymongo
from pymongo import ReplaceOne
from pymongo.errors import BulkWriteError, PyMongoError

from config import (MONGO_COLL_CNN, MONGO_COLL_SIGMA, MONGO_COLL_REPORTS,
                    MONGO_COLL_STATE, ATLAS_QUOTA_MB, ATLAS_WARN_RATIO)
from core.database import close_client, get_db, ping as _ping
from core.exceptions import PersistenceError
from core.timeutils import now_utc, to_utc
from models.enums import norm_severity
from models.report_model import Report

log = logging.getLogger(__name__)



def _is_quota_error(e: Exception) -> bool:
    msg = str(e).lower()
    return ("space quota" in msg or "over your space" in msg
            or "you are over" in msg or "atlaserror" in msg)


def _sigma_dedup_key(alert: dict, event_time) -> str:
    """Clé déterministe : deux détections du même fait produisent la même
    clé, donc un upsert et non un doublon."""
    if alert.get("dedup_key"):
        return str(alert["dedup_key"])
    raw = "|".join([
        str(alert.get("title") or ""),
        str(alert.get("log_source") or ""),
        str(alert.get("rule_kind") or "simple"),
        event_time.isoformat() if event_time else "",
    ])
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:20]


def _extract_event_time(alert: dict):
    """Heure de l'ÉVÉNEMENT source. Retourne (datetime, estimated: bool).

    Trois niveaux, du plus fiable au plus dégradé :
      1. champ `event_time` explicite (chemin normal — sigma_engine le pose) ;
      2. détail structuré (dict) portant un @timestamp ;
      3. détail FORMATÉ EN CHAÎNE : `format_sample` produit
         "2026-07-20T10:00:00 | user=… | ip=…" — le timestamp est en tête,
         on le récupère avant le premier séparateur. Secours uniquement.
    Si tout échoue, heure du run + drapeau `event_time_estimated`, jamais
    un timestamp faux présenté comme vrai."""
    for key in ("event_time", "@timestamp", "timestamp"):
        dt = to_utc(alert.get(key))
        if dt:
            return dt, False

    for detail in (alert.get("details") or []):
        if isinstance(detail, dict):
            for key in ("@timestamp", "timestamp", "time", "event_time"):
                dt = to_utc(detail.get(key))
                if dt:
                    return dt, False
        elif isinstance(detail, str):
            head = detail.strip().split("|", 1)[0].strip()
            dt = to_utc(head)
            if dt:
                return dt, False

    return now_utc(), True


class MongoReportRepository:

    def __init__(self, db=None):
        # `db` injectable : les tests passent un double, sans réseau.
        # Résolution PARESSEUSE : l'instance module-level ci-dessous est
        # créée à l'import, mais aucune connexion n'est ouverte tant
        # qu'aucune requête n'est émise.
        self._db_override = db

    @property
    def _db(self):
        return self._db_override if self._db_override is not None else get_db()

    @property
    def _cnn(self):
        return self._db[MONGO_COLL_CNN]

    @property
    def _sigma(self):
        return self._db[MONGO_COLL_SIGMA]

    @property
    def _reports(self):
        return self._db[MONGO_COLL_REPORTS]

    @property
    def _state(self):
        return self._db[MONGO_COLL_STATE]

    # ── Santé / cycle de vie ───────────────────────────────────────────
    @staticmethod
    def ping() -> None:
        _ping()

    @staticmethod
    def close() -> None:
        close_client()

    # ── CNN ────────────────────────────────────────────────────────────
    def save_cnn_episodes(self, episodes: list[dict], run_id: str) -> int:
        """Upsert idempotent PAR RUN. Lève PersistenceError si une seule
        écriture manque : l'appelant ne doit alors pas avancer le curseur."""
        if not episodes:
            return 0

        ops, skipped = [], 0
        for ep in episodes:
            eid = ep.get("episode_id")
            if not eid:
                skipped += 1
                log.warning("Épisode sans episode_id ignoré : %s",
                            str(ep)[:120])
                continue
            event_time = to_utc(ep.get("event_time") or ep.get("start"))
            doc = {
                **ep,
                "_id": f"{run_id}::{eid}",
                "episode_id": eid,
                "dedup_key": eid,
                "run_id": run_id,
                "detection_source": "cnn",
                "event_time": event_time or now_utc(),
                "event_time_estimated": event_time is None,
                # Vocabulaire FERMÉ : une sévérité exotique deviendrait
                # infiltrable côté API. norm_severity ramène tout dans
                # {critical, high, medium, low}.
                "severity": norm_severity(ep.get("severity")).value,
                "start": to_utc(ep.get("start")),
                "end": to_utc(ep.get("end")),
                "indexed_at": now_utc(),
            }
            ops.append(ReplaceOne({"_id": doc["_id"]}, doc, upsert=True))

        written = 0
        try:
            res = self._cnn.bulk_write(ops, ordered=False)
            written = res.upserted_count + res.matched_count
        except BulkWriteError as e:
            written = e.details.get("nInserted", 0) + e.details.get("nMatched", 0)
            log.error("bulk_write CNN partiel : %s", e.details.get("writeErrors"))
        except PyMongoError as e:
            if _is_quota_error(e):
                log.critical("QUOTA ATLAS SATURÉ — écriture CNN refusée")
            raise PersistenceError(f"Écriture des épisodes CNN échouée : {e}") from e

        if written < len(ops) or skipped:
            raise PersistenceError(
                f"Persistance CNN incomplète : {written}/{len(episodes)} "
                f"épisodes écrits ({skipped} sans episode_id). "
                f"Curseur NON avancé.")

        log.info("%d épisodes CNN → %s", written, MONGO_COLL_CNN)
        return written

    # ── Sigma ──────────────────────────────────────────────────────────
    @staticmethod
    def _sigma_doc(alert: dict, run_id: str) -> dict:
        event_time, estimated = _extract_event_time(alert)
        key = _sigma_dedup_key(alert, event_time)
        return {
            "_id": f"{run_id}::{key}",
            "dedup_key": key,
            "run_id": run_id,
            "event_time": event_time,
            "event_time_estimated": estimated,
            "indexed_at": now_utc(),
            "title": alert.get("title"),
            "level": alert.get("level"),          # brut, pour l'audit
            # `get_rule_meta` peut renvoyer "UNKNOWN" : sans normalisation
            # l'alerte devient invisible dès qu'un filtre de sévérité est posé.
            "severity": norm_severity(alert.get("level")).value,
            "tactic": alert.get("tactic"),
            "hits": alert.get("hits", 0),
            "details": (alert.get("details") or [])[:5],
            "log_source": alert.get("log_source"),
            "host": alert.get("host"),
            "rule_kind": alert.get("rule_kind", "simple"),
            "detection_source": "sigma",
            # Explications posées par le moteur AVANT persistance : plus
            # d'écriture en deux temps, donc plus d'alerte publiée sans
            # son explication en cas d'interruption.
            "llm_explanation": alert.get("llm_explanation"),
            "llm_model": alert.get("llm_model"),
        }

    def save_sigma_alerts(self, alerts: list[dict], run_id: str) -> int:
        """Écriture en LOT de toutes les alertes d'un run. Lève
        PersistenceError si une seule manque — le curseur ne doit pas
        avancer sur une persistance partielle."""
        if not alerts:
            return 0

        ops = []
        for alert in alerts:
            doc = self._sigma_doc(alert, run_id)
            alert["_persisted_id"] = doc["_id"]
            ops.append(ReplaceOne({"_id": doc["_id"]}, doc, upsert=True))

        try:
            res = self._sigma.bulk_write(ops, ordered=False)
            written = res.upserted_count + res.matched_count
        except BulkWriteError as e:
            written = e.details.get("nInserted", 0) + e.details.get("nMatched", 0)
            log.error("bulk_write Sigma partiel : %s", e.details.get("writeErrors"))
        except PyMongoError as e:
            if _is_quota_error(e):
                log.critical("QUOTA ATLAS SATURÉ — écriture Sigma refusée")
            raise PersistenceError(f"Écriture des alertes Sigma échouée : {e}") from e

        if written < len(ops):
            raise PersistenceError(
                f"Persistance Sigma incomplète : {written}/{len(alerts)} "
                f"alertes écrites. Curseur NON avancé.")

        log.info("%d alertes Sigma → %s", written, MONGO_COLL_SIGMA)
        return written

    def save_sigma_alert(self, alert: dict, run_id: str) -> str | None:
        """Écriture unitaire — conservée pour compatibilité. Le chemin normal
        est `save_sigma_alerts` (lot)."""
        doc = self._sigma_doc(alert, run_id)
        try:
            self._sigma.replace_one({"_id": doc["_id"]}, doc, upsert=True)
        except PyMongoError as e:
            if _is_quota_error(e):
                log.critical("QUOTA ATLAS SATURÉ — écriture Sigma refusée")
            raise PersistenceError(f"Écriture alerte Sigma échouée : {e}") from e
        alert["_persisted_id"] = doc["_id"]
        return doc["_id"]

    def update_sigma_explanation(self, alert_id: str, explanation: str,
                                 model: str) -> None:
        try:
            self._sigma.update_one(
                {"_id": alert_id},
                {"$set": {"llm_explanation": explanation, "llm_model": model}})
        except PyMongoError as e:
            # Non bloquant : l'alerte existe, seule l'explication manque.
            log.error("update explication Sigma %s : %s", alert_id, e)

    # ── Curseurs incrémentaux ──────────────────────────────────────────
    def _get_cursor(self, key: str) -> str | None:
        doc = self._state.find_one({"_id": key})
        return doc.get("cursor") if doc else None

    def _set_cursor(self, key: str, cursor: str) -> None:
        try:
            self._state.replace_one(
                {"_id": key},
                {"_id": key, "cursor": cursor, "updated_at": now_utc()},
                upsert=True)
        except PyMongoError as e:
            raise PersistenceError(f"Curseur {key} non enregistré : {e}") from e

    def get_sigma_cursor(self) -> str | None:
        return self._get_cursor("sigma_cursor")

    def set_sigma_cursor(self, cursor: str) -> None:
        self._set_cursor("sigma_cursor", cursor)

    def get_cnn_cursor(self) -> str | None:
        return self._get_cursor("cnn_cursor")

    def set_cnn_cursor(self, cursor: str) -> None:
        self._set_cursor("cnn_cursor", cursor)

    # ── Rapports ───────────────────────────────────────────────────────
    def save_report(self, report: Report) -> str | None:
        """Upsert sur analysis_id (avant : insert_one → un re-run du même
        run_id créait un second rapport)."""
        doc = report.model_dump()
        try:
            self._reports.replace_one({"analysis_id": report.analysis_id},
                                      doc, upsert=True)
        except PyMongoError as e:
            if _is_quota_error(e):
                log.critical("QUOTA ATLAS SATURÉ — rapport non écrit")
            raise PersistenceError(f"Rapport {report.analysis_id} non écrit : {e}") from e

        self._check_storage_saturation()
        return report.analysis_id

    def get_last_report(self) -> dict | None:
        """Dernier run PUBLIABLE. `partial` est inclus : une branche en échec
        ne doit pas rendre invisibles les détections de l'autre."""
        r = self._reports.find_one(
            {"status": {"$in": ["completed", "partial"]}},
            sort=[("finished_at", pymongo.DESCENDING)])
        if r:
            r["_id"] = str(r["_id"])
        return r

    # ── Table de résultats ─────────────────────────────────────────────
    def _build_query(self, run_id: str, level: str | None,
                     cnn_verdicts) -> tuple[dict, dict]:
        base = {"run_id": run_id}
        q_cnn = {**base, "verdict": {"$in": list(cnn_verdicts)}}
        q_sigma = dict(base)
        if level:
            sev = level.lower()
            q_cnn["severity"] = sev
            q_sigma["severity"] = sev          # champ unifié, plus de MAJUSCULES
        return q_cnn, q_sigma

    def get_results(self, run_id: str, level: str = None, source: str = None,
                    limit: int = 500,
                    cnn_verdicts=("true_positive",)) -> list[dict]:
        """Top-N de chaque source, trié DANS Mongo sur `event_time`.
        La fusion et la coupe finale reviennent au contrôleur."""
        q_cnn, q_sigma = self._build_query(run_id, level, cnn_verdicts)
        out: list[dict] = []

        if source in (None, "cnn"):
            for d in (self._cnn.find(q_cnn)
                      .sort("event_time", pymongo.DESCENDING).limit(limit)):
                d["_id"] = str(d["_id"])
                d["type"] = "cnn"
                out.append(d)

        if source in (None, "sigma"):
            for d in (self._sigma.find(q_sigma)
                      .sort("event_time", pymongo.DESCENDING).limit(limit)):
                d["_id"] = str(d["_id"])
                d["type"] = "sigma"
                out.append(d)

        return out

    def count_results(self, run_id: str, level: str = None,
                      source: str = None,
                      cnn_verdicts=("true_positive",)) -> int:
        """Total réel en base pour ce filtre — permet une vraie pagination."""
        q_cnn, q_sigma = self._build_query(run_id, level, cnn_verdicts)
        total = 0
        if source in (None, "cnn"):
            total += self._cnn.count_documents(q_cnn)
        if source in (None, "sigma"):
            total += self._sigma.count_documents(q_sigma)
        return total

    # ── Garde-fou stockage (Atlas M0 = 512 Mo on-disk) ─────────────────
    def _check_storage_saturation(self) -> None:
        """Appelé UNE FOIS par run, jamais sur le chemin de chaque écriture."""
        try:
            s = self._db.command("dbStats", scale=1024 * 1024)
            used = float(s.get("storageSize", 0)) + float(s.get("indexSize", 0))
        except PyMongoError as e:
            log.warning("dbStats indisponible : %s", e)
            return
        ratio = used / max(ATLAS_QUOTA_MB, 1)
        if ratio >= ATLAS_WARN_RATIO:
            log.critical("STOCKAGE ATLAS SATURÉ : %.0f/%d Mo (%.0f %%) — "
                         "purger les anciens runs", used, ATLAS_QUOTA_MB,
                         ratio * 100)
        else:
            log.info("Stockage Atlas : %.0f/%d Mo (%.0f %%)",
                     used, ATLAS_QUOTA_MB, ratio * 100)


# Instance module-level : tous les appels existants `ReportRepository.x(...)`
# continuent de fonctionner, et les tests peuvent instancier
# MongoReportRepository(db_mock) sans toucher au réseau.
ReportRepository = MongoReportRepository()