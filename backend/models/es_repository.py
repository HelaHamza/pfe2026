"""
backend/models/es_repository.py
=================================
Repository principal — Elasticsearch + MongoDB Atlas.

FIXES :
  - get_stats_window : retourne `lo` réel (pas "" si None)
  - get_timeline_window : borne basse calculée proprement
  - claim_cursor : plus de fallback save_cursor en cas d'erreur réseau
    (sinon contourne le verrou atomique)
  - save_report enrichi : stocke timeline aussi
  - Toutes les méthodes *_window utilisent _build_range cohérent
"""

import base64
import json
import os
import ssl
import uuid
import urllib.request
import urllib.error
from datetime import datetime, timezone

import pymongo

from backend.config import MONGO_URI, MONGO_DB, MONGO_COLL

ES_HOST = os.getenv("ES_HOST",     "https://localhost:9200")
ES_USER = os.getenv("ES_USER",     "elastic")
ES_PASS = os.getenv("ELASTIC_PWD", "pfe2026")

ES_INDEX_AE        = "ml-autoencoder-scores"
ES_INDEX_SIGMA     = "sigma-alerts"
ES_INDEX_CURSOR    = "ids-pipeline-cursor"
ES_INDEX_CURSOR_ID = "last_run"
ES_INDEX_SOURCES   = "filebeat-logs-*,auditbeat-*"

SOURCE_KEYWORDS = {
    "auth": [
        "ssh", "sshd", "credential", "brute", "auth", "password",
        "login", "failed", "root", "country", "suspicious",
    ],
    "auditd": [
        "auditd", "audit", "privilege", "ptrace", "suid",
        "reverse shell", "reverse_shell", "shell", "cryptominer",
        "crypto", "miner", "process injection", "obfuscat",
        "execution", "escalat",
    ],
    "syslog": [
        "syslog", "kernel", "module", "systemd", "network scan",
        "scan", "firewall", "network", "oom",
    ],
}

TACTIC_PLACEHOLDER = {"voir règle", "voir regle", ""}


def _derive_source(title: str, tactic: str, log_source_field: str = "") -> str:
    if log_source_field and log_source_field.lower() in SOURCE_KEYWORDS:
        return log_source_field.lower()
    combined = (title + " " + tactic).lower()
    for src, kws in SOURCE_KEYWORDS.items():
        if any(k in combined for k in kws):
            return src
    return "unknown"


def _get_mongo_collection():
    client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    return client[MONGO_DB][MONGO_COLL]


def _build_range(lo: str | None, hi: str | None) -> dict:
    """Construit le filtre @timestamp : (gt lo, lte hi]."""
    r = {}
    if lo:
        r["gt"] = lo
    if hi:
        r["lte"] = hi
    if not r:
        r["gte"] = "now-7d"
    return {"range": {"@timestamp": r}}


class ESRepository:

    # ── HTTP ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _client():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        token = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
        return ctx, {
            "Content-Type":  "application/json",
            "Authorization": f"Basic {token}",
        }

    @staticmethod
    def _request(path: str, body: dict = None, method: str = None) -> dict:
        ctx, headers = ESRepository._client()
        data = json.dumps(body).encode() if body else None
        m    = method or ("POST" if body else "GET")
        req  = urllib.request.Request(
            f"{ES_HOST}{path}", data=data, headers=headers, method=m
        )
        return json.loads(urllib.request.urlopen(req, context=ctx).read())

    @staticmethod
    def _count(index: str, query: dict) -> int:
        try:
            return ESRepository._request(
                f"/{index}/_count", {"query": query}
            ).get("count", 0)
        except Exception:
            return 0

    # ── Curseur ───────────────────────────────────────────────────────────────

    @staticmethod
    def get_cursor() -> str:
        try:
            doc = ESRepository._request(
                f"/{ES_INDEX_CURSOR}/_doc/{ES_INDEX_CURSOR_ID}"
            )
            return doc["_source"].get("last_timestamp", "now-7d")
        except Exception:
            return "now-7d"

    @staticmethod
    def save_cursor(timestamp: str):
        try:
            ESRepository._request(
                f"/{ES_INDEX_CURSOR}/_doc/{ES_INDEX_CURSOR_ID}",
                body={
                    "last_timestamp": timestamp,
                    "updated_at":     datetime.now(timezone.utc).isoformat(),
                },
                method="PUT",
            )
        except Exception as e:
            print(f"[ESRepository] save_cursor error: {e}")

    @staticmethod
    def claim_cursor(expected_cursor: str, new_cursor: str) -> bool:
        """
        Verrou ES atomique avec optimistic concurrency control (seq_no/primary_term).
        Retourne True UNIQUEMENT si :
          - le curseur courant en ES == expected_cursor
          - le PUT conditionnel a réussi (pas de 409)
        Plus de fallback save_cursor : on n'avance JAMAIS le curseur en cas d'erreur.
        """
        try:
            doc = ESRepository._request(
                f"/{ES_INDEX_CURSOR}/_doc/{ES_INDEX_CURSOR_ID}"
            )
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # Document curseur n'existe pas encore → premier run.
                # On le crée avec op_type=create (échoue si un autre run l'a créé entretemps)
                try:
                    ESRepository._request(
                        f"/{ES_INDEX_CURSOR}/_create/{ES_INDEX_CURSOR_ID}",
                        body={
                            "last_timestamp": new_cursor,
                            "updated_at":     datetime.now(timezone.utc).isoformat(),
                        },
                        method="PUT",
                    )
                    print(f"[claim_cursor] ✓ Curseur initial créé : {new_cursor}")
                    return True
                except Exception as e2:
                    print(f"[claim_cursor] Création initiale échouée : {e2}")
                    return False
            print(f"[claim_cursor] HTTP error lecture : {e}")
            return False
        except Exception as e:
            print(f"[claim_cursor] Erreur lecture curseur : {e}")
            return False

        current = doc["_source"].get("last_timestamp")
        if current != expected_cursor:
            print(f"[claim_cursor] Curseur déjà avancé : {current} ≠ {expected_cursor}")
            return False

        seq_no  = doc["_seq_no"]
        primary = doc["_primary_term"]

        try:
            ESRepository._request(
                f"/{ES_INDEX_CURSOR}/_doc/{ES_INDEX_CURSOR_ID}"
                f"?if_seq_no={seq_no}&if_primary_term={primary}",
                body={
                    "last_timestamp": new_cursor,
                    "updated_at":     datetime.now(timezone.utc).isoformat(),
                },
                method="PUT",
            )
            return True
        except urllib.error.HTTPError as e:
            if e.code == 409:
                print(f"[claim_cursor] Conflict 409 — un autre run a gagné la course")
            else:
                print(f"[claim_cursor] HTTP error PUT : {e}")
            return False
        except Exception as e:
            print(f"[claim_cursor] Erreur PUT : {e}")
            return False

    # ── Logs sources ──────────────────────────────────────────────────────────

    @staticmethod
    def get_new_logs_count(cursor: str) -> dict:
        """
        Compte tous les nouveaux logs (>cursor) ET récupère max(@timestamp).
        new_cursor = max_timestamp → on lira tout jusque-là dans la fenêtre.
        """
        body = {
            "size": 0,
            "query": {"bool": {"must": [
                {"exists": {"field": "ml.log_source"}},
                {"range":  {"@timestamp": {"gt": cursor}}},
            ]}},
            "aggs": {
                "by_source":     {"terms": {"field": "ml.log_source.keyword", "size": 10}},
                "max_timestamp": {"max":   {"field": "@timestamp"}},
            },
        }
        try:
            r    = ESRepository._request(f"/{ES_INDEX_SOURCES}/_search", body)
            aggs = r.get("aggregations", {})
            return {
                "total":         r["hits"]["total"]["value"],
                "by_source":     {b["key"]: b["doc_count"]
                                  for b in aggs.get("by_source", {}).get("buckets", [])},
                "max_timestamp": aggs.get("max_timestamp", {}).get("value_as_string"),
            }
        except Exception as e:
            return {"total": 0, "by_source": {}, "max_timestamp": None, "error": str(e)}

    @staticmethod
    def get_logs_by_source(cursor: str = "now-7d") -> dict:
        return ESRepository.get_logs_by_source_window(cursor, None)

    @staticmethod
    def get_logs_by_source_window(lo: str | None, hi: str | None) -> dict:
        body = {
            "size": 0,
            "query": {"bool": {"must": [
                {"exists": {"field": "ml.log_source"}},
                _build_range(lo, hi),
            ]}},
            "aggs": {
                "by_source": {"terms": {"field": "ml.log_source.keyword", "size": 10}}
            },
        }
        try:
            r = ESRepository._request(f"/{ES_INDEX_SOURCES}/_search", body)
            return {
                b["key"]: b["doc_count"]
                for b in r.get("aggregations", {}).get("by_source", {}).get("buckets", [])
            }
        except Exception:
            return {}

    # ── AE stats ──────────────────────────────────────────────────────────────

    @staticmethod
    def get_anomalies(cursor: str, limit: int = 100) -> list[dict]:
        body = {
            "size": limit,
            "query": {"bool": {"must": [
                {"term":  {"ae_is_anomaly": 1}},
                {"range": {"@timestamp": {"gt": cursor}}},
            ]}},
            "sort":    [{"@timestamp": {"order": "desc"}}],
            "_source": [
                "@timestamp", "log_source", "ae_mse_error",
                "ae_anomaly_score", "composite_score", "ae_threshold",
                "kb_severity", "llm_explanation", "detection_source",
            ],
        }
        try:
            r = ESRepository._request(f"/{ES_INDEX_AE}/_search", body)
            return [{"id": h["_id"], "type": "anomaly", **h["_source"]}
                    for h in r["hits"]["hits"]]
        except Exception as e:
            print(f"[ESRepository] get_anomalies error: {e}")
            return []

    @staticmethod
    def get_anomaly_detail(doc_id: str) -> dict:
        ctx, headers = ESRepository._client()
        req = urllib.request.Request(
            f"{ES_HOST}/{ES_INDEX_AE}/_doc/{doc_id}",
            headers=headers, method="GET",
        )
        try:
            doc = json.loads(urllib.request.urlopen(req, context=ctx).read())
            return {"id": doc["_id"], "type": "anomaly", **doc["_source"]}
        except Exception as e:
            raise ValueError(f"Anomalie {doc_id} introuvable : {e}")

    @staticmethod
    def get_anomalies_by_source_since(cursor: str = "now-7d") -> list[dict]:
        return ESRepository.get_anomalies_by_source_window(cursor, None)

    @staticmethod
    def get_anomalies_by_source_window(lo: str | None, hi: str | None) -> list[dict]:
        body = {
            "size": 0,
            "query": {"bool": {"must": [
                {"term": {"ae_is_anomaly": 1}},
                _build_range(lo, hi),
            ]}},
            "aggs": {"by_source": {"terms": {"field": "log_source", "size": 10}}},
        }
        try:
            res = ESRepository._request(f"/{ES_INDEX_AE}/_search", body)
            return [
                {"source": b["key"], "count": b["doc_count"]}
                for b in res["aggregations"]["by_source"]["buckets"]
            ]
        except Exception:
            return []

    @staticmethod
    def get_anomalies_by_source_dict(cursor: str = "now-7d") -> dict:
        rows = ESRepository.get_anomalies_by_source_since(cursor)
        return {r["source"]: r["count"] for r in rows}

    @staticmethod
    def get_anomalies_by_source_dict_window(lo: str | None, hi: str | None) -> dict:
        rows = ESRepository.get_anomalies_by_source_window(lo, hi)
        return {r["source"]: r["count"] for r in rows}

    @staticmethod
    def get_ae_stats_by_source(cursor: str) -> dict:
        return ESRepository.get_ae_stats_by_source_window(cursor, None)

    @staticmethod
    def get_ae_stats_by_source_window(lo: str | None, hi: str | None) -> dict:
        raw_body = {
            "size": 0,
            "query": {"bool": {"must": [
                {"exists": {"field": "ml.log_source"}},
                _build_range(lo, hi),
            ]}},
            "aggs": {
                "by_source": {"terms": {"field": "ml.log_source.keyword", "size": 10}}
            },
        }
        ae_body = {
            "size": 0,
            "query": _build_range(lo, hi),
            "aggs": {
                "by_source": {
                    "terms": {"field": "log_source", "size": 10},
                    "aggs": {
                        "anomalies":    {"filter": {"term": {"ae_is_anomaly": 1}}},
                        "sev_critical": {"filter": {"bool": {"must": [
                            {"term": {"ae_is_anomaly": 1}},
                            {"term": {"kb_severity": "critical"}},
                        ]}}},
                        "sev_high": {"filter": {"bool": {"must": [
                            {"term": {"ae_is_anomaly": 1}},
                            {"term": {"kb_severity": "high"}},
                        ]}}},
                        "sev_medium": {"filter": {"bool": {"must": [
                            {"term": {"ae_is_anomaly": 1}},
                            {"term": {"kb_severity": "medium"}},
                        ]}}},
                    },
                }
            },
        }

        result = {}

        try:
            r = ESRepository._request(f"/{ES_INDEX_SOURCES}/_search", raw_body)
            for b in r.get("aggregations", {}).get("by_source", {}).get("buckets", []):
                result[b["key"]] = {
                    "logs": b["doc_count"], "windows": 0,
                    "anomalies": 0, "severity": None,
                }
        except Exception as e:
            print(f"[ESRepository] get_ae_stats_by_source (raw) error: {e}")

        try:
            r = ESRepository._request(f"/{ES_INDEX_AE}/_search", ae_body)
            for b in r.get("aggregations", {}).get("by_source", {}).get("buckets", []):
                src = b["key"]
                if src not in result:
                    result[src] = {"logs": 0, "windows": 0, "anomalies": 0, "severity": None}
                result[src]["windows"]   = b["doc_count"]
                result[src]["anomalies"] = b.get("anomalies", {}).get("doc_count", 0)
                if b.get("sev_critical", {}).get("doc_count", 0) > 0:
                    result[src]["severity"] = "critical"
                elif b.get("sev_high", {}).get("doc_count", 0) > 0:
                    result[src]["severity"] = "high"
                elif b.get("sev_medium", {}).get("doc_count", 0) > 0:
                    result[src]["severity"] = "medium"
                elif result[src]["anomalies"] > 0:
                    result[src]["severity"] = "low"
        except Exception as e:
            print(f"[ESRepository] get_ae_stats_by_source (ae) error: {e}")

        return result

    # ── Sigma stats ───────────────────────────────────────────────────────────

    @staticmethod
    def get_alerts(cursor: str, limit: int = 100) -> list[dict]:
        body = {
            "size": limit,
            "query": {"range": {"@timestamp": {"gt": cursor}}},
            "sort":  [{"@timestamp": {"order": "desc"}}],
            "_source": [
                "@timestamp", "alert.title", "alert.level",
                "alert.tactic", "alert.hits", "alert.details",
                "detection_source", "ae_correlated", "llm_explanation",
            ],
        }
        try:
            r      = ESRepository._request(f"/{ES_INDEX_SIGMA}/_search", body)
            alerts = []
            for h in r["hits"]["hits"]:
                src    = h["_source"]
                tactic = src.get("alert.tactic", "")
                alerts.append({
                    "id":               h["_id"],
                    "type":             "alert",
                    "@timestamp":       src.get("@timestamp"),
                    "title":            src.get("alert.title", "?"),
                    "level":            src.get("alert.level", "?"),
                    "tactic":           "" if tactic in TACTIC_PLACEHOLDER else tactic,
                    "hits":             src.get("alert.hits", 0),
                    "details":          src.get("alert.details", []),
                    "detection_source": src.get("detection_source", "sigma_only"),
                    "ae_correlated":    src.get("ae_correlated", False),
                    "llm_explanation":  src.get("llm_explanation"),
                })
            return alerts
        except Exception as e:
            print(f"[ESRepository] get_alerts error: {e}")
            return []

    @staticmethod
    def get_alert_detail(doc_id: str) -> dict:
        ctx, headers = ESRepository._client()
        req = urllib.request.Request(
            f"{ES_HOST}/{ES_INDEX_SIGMA}/_doc/{doc_id}",
            headers=headers, method="GET",
        )
        try:
            doc = json.loads(urllib.request.urlopen(req, context=ctx).read())
            return {"id": doc["_id"], "type": "alert", **doc["_source"]}
        except Exception as e:
            raise ValueError(f"Alerte {doc_id} introuvable : {e}")

    @staticmethod
    def get_alerts_by_level(cursor: str = "now-7d") -> list[dict]:
        return ESRepository.get_alerts_by_level_window(cursor, None)

    @staticmethod
    def get_alerts_by_level_window(lo: str | None, hi: str | None) -> list[dict]:
        body = {
            "size": 0,
            "query": _build_range(lo, hi),
            "aggs": {"by_level": {"terms": {"field": "alert.level", "size": 10}}},
        }
        try:
            res = ESRepository._request(f"/{ES_INDEX_SIGMA}/_search", body)
            return [
                {"level": b["key"], "count": b["doc_count"]}
                for b in res["aggregations"]["by_level"]["buckets"]
            ]
        except Exception:
            return []

    @staticmethod
    def get_alerts_by_level_dict(cursor: str = "now-7d") -> dict:
        rows = ESRepository.get_alerts_by_level(cursor)
        return {r["level"].lower(): r["count"] for r in rows}

    @staticmethod
    def get_alerts_by_level_dict_window(lo: str | None, hi: str | None) -> dict:
        rows = ESRepository.get_alerts_by_level_window(lo, hi)
        return {r["level"].lower(): r["count"] for r in rows}

    @staticmethod
    def get_alerts_by_tactic_since(cursor: str = "now-7d") -> list[dict]:
        return ESRepository.get_alerts_by_tactic_window(cursor, None)

    @staticmethod
    def get_alerts_by_tactic_window(lo: str | None, hi: str | None) -> list[dict]:
        body = {
            "size": 0,
            "query": _build_range(lo, hi),
            "aggs": {"by_title": {"terms": {"field": "alert.title", "size": 8}}},
        }
        try:
            res = ESRepository._request(f"/{ES_INDEX_SIGMA}/_search", body)
            return [{"tactic": b["key"], "count": b["doc_count"]}
                    for b in res["aggregations"]["by_title"]["buckets"]]
        except Exception:
            return []

    @staticmethod
    def get_sigma_by_source(cursor: str) -> dict:
        return ESRepository.get_sigma_by_source_window(cursor, None)

    @staticmethod
    def get_sigma_by_source_window(lo: str | None, hi: str | None) -> dict:
        body = {
            "size": 2000,
            "query": _build_range(lo, hi),
            "_source": ["alert.title", "alert.level", "alert.tactic", "log_source"],
            "sort":    [{"@timestamp": {"order": "desc"}}],
        }
        result = {
            "syslog":  {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "auth":    {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "auditd":  {"critical": 0, "high": 0, "medium": 0, "low": 0},
        }
        try:
            res = ESRepository._request(f"/{ES_INDEX_SIGMA}/_search", body)
            for hit in res["hits"]["hits"]:
                s         = hit.get("_source", {})
                title     = s.get("alert.title",  "")
                tactic    = s.get("alert.tactic", "")
                level     = s.get("alert.level",  "low").lower()
                ls_field  = s.get("log_source",   "")
                source    = _derive_source(title, tactic, ls_field)
                if source == "unknown":
                    continue
                if source not in result:
                    result[source] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                lvl = level if level in ("critical", "high", "medium", "low") else "low"
                result[source][lvl] += 1
        except Exception as e:
            print(f"[ESRepository] get_sigma_by_source error: {e}")
        return result

    @staticmethod
    def get_detection_source_stats(cursor: str = "now-7d") -> dict:
        return ESRepository.get_detection_source_stats_window(cursor, None)

    @staticmethod
    def get_detection_source_stats_window(lo: str | None, hi: str | None) -> dict:
        rng = _build_range(lo, hi)
        ae_only = ESRepository._count(ES_INDEX_AE, {"bool": {"must": [
            {"term": {"ae_is_anomaly":    1}},
            {"term": {"detection_source": "ae_only"}},
            rng,
        ]}})
        sigma_only = ESRepository._count(ES_INDEX_SIGMA, {"bool": {"must": [
            {"term": {"detection_source": "sigma_only"}},
            rng,
        ]}})
        both_ae = ESRepository._count(ES_INDEX_AE, {"bool": {"must": [
            {"term": {"ae_is_anomaly":    1}},
            {"term": {"detection_source": "both"}},
            rng,
        ]}})
        both_sigma = ESRepository._count(ES_INDEX_SIGMA, {"bool": {"must": [
            {"term": {"ae_correlated": True}},
            rng,
        ]}})
        both  = max(both_ae, both_sigma)
        total = ae_only + sigma_only + both
        return {
            "ae_only":    ae_only,
            "sigma_only": sigma_only,
            "both":       both,
            "total":      total,
        }

    @staticmethod
    def get_attacks_by_source(cursor: str = "now-7d") -> dict:
        return ESRepository.get_attacks_by_source_window(cursor, None)

    @staticmethod
    def get_attacks_by_source_window(lo: str | None, hi: str | None) -> dict:
        rng = _build_range(lo, hi)
        ae_body = {
            "size": 0,
            "query": {"bool": {"must": [{"term": {"ae_is_anomaly": 1}}, rng]}},
            "aggs": {"by_source": {"terms": {"field": "log_source", "size": 10}}},
        }
        ae_by_source = {}
        try:
            r = ESRepository._request(f"/{ES_INDEX_AE}/_search", ae_body)
            for b in r.get("aggregations", {}).get("by_source", {}).get("buckets", []):
                ae_by_source[b["key"]] = b["doc_count"]
        except Exception:
            pass

        sigma_total = ESRepository._count(ES_INDEX_SIGMA, rng)
        sigma_body = {
            "size": 0,
            "query": rng,
            "aggs": {"by_level": {"terms": {"field": "alert.level", "size": 10}}},
        }
        sigma_by_level = {}
        try:
            r = ESRepository._request(f"/{ES_INDEX_SIGMA}/_search", sigma_body)
            for b in r.get("aggregations", {}).get("by_level", {}).get("buckets", []):
                sigma_by_level[b["key"]] = b["doc_count"]
        except Exception:
            pass

        return {
            "ae":    ae_by_source,
            "sigma": {"total": sigma_total, "by_level": sigma_by_level},
        }

    # ── Stats globales ────────────────────────────────────────────────────────

    @staticmethod
    def get_stats(cursor: str) -> dict:
        return ESRepository.get_stats_window(cursor, None)

    @staticmethod
    def get_stats_window(lo: str | None, hi: str | None) -> dict:
        rng = _build_range(lo, hi)
        return {
            "cursor":          lo or "",     # info uniquement (champ d'affichage)
            "ae_anomalies":    ESRepository._count(ES_INDEX_AE, {"bool": {"must": [
                                   {"term": {"ae_is_anomaly": 1}}, rng,
                               ]}}),
            "sigma_alerts":    ESRepository._count(ES_INDEX_SIGMA, rng),
            "critical":        ESRepository._count(ES_INDEX_SIGMA, {"bool": {"must": [
                                   {"term": {"alert.level": "CRITICAL"}}, rng,
                               ]}}),
            "correlated_both": ESRepository._count(ES_INDEX_SIGMA, {"bool": {"must": [
                                   {"term": {"ae_correlated": True}}, rng,
                               ]}}),
        }

    # ── Timeline ──────────────────────────────────────────────────────────────

    @staticmethod
    def get_timeline(days: int = 7, cursor: str = None) -> list[dict]:
        return ESRepository.get_timeline_window(days, cursor, None)

    @staticmethod
    def get_timeline_window(days: int, lo: str | None, hi: str | None) -> list[dict]:
        """
        Timeline `days` jours.
        - Si `lo` est un ISO timestamp réel → utilise-le comme borne basse.
        - Sinon (None ou 'now-7d') → utilise `now-{days}d`.
        - `hi` est utilisé tel quel si fourni.
        """
        # Détection d'un timestamp ISO valide
        is_iso = bool(lo) and lo not in ("now-7d", "") and "T" in lo

        def agg_by_day(index, extra_filter=None):
            rng_inner = {"gte": lo if is_iso else f"now-{days}d"}
            if hi:
                rng_inner["lte"] = hi
            must = [{"range": {"@timestamp": rng_inner}}]
            if extra_filter:
                must.append(extra_filter)
            body = {
                "size": 0,
                "query": {"bool": {"must": must}},
                "aggs": {"by_day": {"date_histogram": {
                    "field":             "@timestamp",
                    "calendar_interval": "day",
                    "format":            "yyyy-MM-dd",
                }}},
            }
            try:
                res = ESRepository._request(f"/{index}/_search", body)
                return {b["key_as_string"]: b["doc_count"]
                        for b in res["aggregations"]["by_day"]["buckets"]}
            except Exception:
                return {}

        ae_days       = agg_by_day(ES_INDEX_AE,    {"term": {"ae_is_anomaly": 1}})
        sigma_days    = agg_by_day(ES_INDEX_SIGMA)
        critical_days = agg_by_day(ES_INDEX_SIGMA, {"term": {"alert.level": "CRITICAL"}})

        return [
            {
                "date":         d,
                "ae_anomalies": ae_days.get(d, 0),
                "sigma_alerts": sigma_days.get(d, 0),
                "critical":     critical_days.get(d, 0),
            }
            for d in sorted(set(list(ae_days) + list(sigma_days)))
        ]

    # ── MongoDB Atlas — Reports ───────────────────────────────────────────────
    @staticmethod
    def save_report(
        stats,
        cursor,
        started_at,
        new_cursor=None,
        ae_by_source=None,
        ae_by_source_dict=None,
        sigma_by_source=None,
        sigma_by_level=None,
        by_tactic=None,
        detection_src=None,
        logs_by_source=None,
        timeline=None,
        results=None,  # 🆕
    ) -> str | None:

        doc = {
        "analysis_id": str(uuid.uuid4()),
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "status": "completed",
        "generated_by": "pipeline_v3",
        "cursor": cursor,
        "new_cursor": new_cursor,
        "timeline": timeline or [],
        "results": results or [],  # 🆕
        "stats": {
            "total_ae": stats.get("ae_anomalies", 0),
            "total_sigma": stats.get("sigma_alerts", 0),
            "correlated": stats.get("correlated_both", 0),
            "critical": stats.get("critical", 0),
            "sigma_by_source": sigma_by_source or {},
            "sigma_by_level": sigma_by_level or {},
            "ae_by_source": ae_by_source or {},
            "ae_by_source_dict": ae_by_source_dict or {},
            "by_tactic": by_tactic or [],
            "detection_source": detection_src or {},
            "logs_by_source": logs_by_source or {},
        },
        }

        try:
            coll = _get_mongo_collection()
            result = coll.insert_one(doc)
            print(f"[MongoDB] Report sauvegardé : {result.inserted_id}")
            return str(result.inserted_id)

        except Exception as e:
            print(f"[MongoDB] save_report error: {e}")
            return None


    @staticmethod
    def get_last_report() -> dict | None:
        try:
            coll   = _get_mongo_collection()
            report = coll.with_options(
                read_preference=pymongo.ReadPreference.SECONDARY_PREFERRED
            ).find_one(
                {"status": "completed"},
                sort=[("finished_at", pymongo.DESCENDING)],
            )
            if report:
                report["_id"] = str(report["_id"])
            return report
        except Exception as e:
            print(f"[MongoDB] get_last_report error: {e}")
            return None
    
    # ── À AJOUTER dans ESRepository, après get_last_report ──────────────────

    @staticmethod
    def get_last_window() -> tuple[str | None, str | None]:
        """
        Bornes ]lo, hi] de la dernière analyse, lues depuis le snapshot Mongo.
        Source unique de vérité partagée par StatsController et ResultsController.

        - lo = cursor      (fallback started_at pour vieux snapshots)
        - hi = new_cursor  (fallback finished_at pour vieux snapshots)
        - Si aucun report : (get_cursor(), None)
        """
        report = ESRepository.get_last_report()
        if report:
            lo = report.get("cursor")     or report.get("started_at")
            hi = report.get("new_cursor") or report.get("finished_at")
            return lo, hi
        return ESRepository.get_cursor(), None

    # ── À AJOUTER dans la classe ESRepository ───────────────────────────────
    # Variantes fenêtrées ]lo, hi] de get_anomalies / get_alerts.
    # Utilisées par ResultsController pour que le tableau lise la MÊME
    # fenêtre que le snapshot du dashboard.

    @staticmethod
    def get_anomalies_window(lo: str | None, hi: str | None,
                             limit: int = 500) -> list[dict]:
        body = {
            "size": limit,
            "query": {"bool": {"must": [
                {"term": {"ae_is_anomaly": 1}},
                _build_range(lo, hi),
            ]}},
            "sort":    [{"@timestamp": {"order": "desc"}}],
            "_source": [
                "@timestamp", "log_source", "ae_mse_error",
                "ae_anomaly_score", "composite_score", "ae_threshold",
                "kb_severity", "llm_explanation", "detection_source",
            ],
        }
        try:
            r = ESRepository._request(f"/{ES_INDEX_AE}/_search", body)
            return [{"id": h["_id"], "type": "anomaly", **h["_source"]}
                    for h in r["hits"]["hits"]]
        except Exception as e:
            print(f"[ESRepository] get_anomalies_window error: {e}")
            return []

    @staticmethod
    def get_alerts_window(lo: str | None, hi: str | None,
                          limit: int = 500) -> list[dict]:
        body = {
            "size": limit,
            "query": _build_range(lo, hi),
            "sort":  [{"@timestamp": {"order": "desc"}}],
            "_source": [
                "@timestamp", "alert.title", "alert.level",
                "alert.tactic", "alert.hits", "alert.details",
                "detection_source", "ae_correlated", "llm_explanation",
            ],
        }
        try:
            r      = ESRepository._request(f"/{ES_INDEX_SIGMA}/_search", body)
            alerts = []
            for h in r["hits"]["hits"]:
                src    = h["_source"]
                tactic = src.get("alert.tactic", "")
                alerts.append({
                    "id":               h["_id"],
                    "type":             "alert",
                    "@timestamp":       src.get("@timestamp"),
                    "title":            src.get("alert.title", "?"),
                    "level":            src.get("alert.level", "?"),
                    "tactic":           "" if tactic in TACTIC_PLACEHOLDER else tactic,
                    "hits":             src.get("alert.hits", 0),
                    "details":          src.get("alert.details", []),
                    "detection_source": src.get("detection_source", "sigma_only"),
                    "ae_correlated":    src.get("ae_correlated", False),
                    "llm_explanation":  src.get("llm_explanation"),
                })
            return alerts
        except Exception as e:
            print(f"[ESRepository] get_alerts_window error: {e}")
            return []