"""
backend/models/es_repository.py
================================
MODEL — accès Elasticsearch.
Toutes les requêtes ES passent par ici.
Aucune autre couche ne fait de requête ES directement.
"""

import base64
import json
import ssl
import os
import urllib.request
from datetime import datetime, timezone

# ── Config ────────────────────────────────────────────────────────────────────
ES_HOST = os.getenv("ES_HOST",     "https://localhost:9200")
ES_USER = os.getenv("ES_USER",     "elastic")
ES_PASS = os.getenv("ELASTIC_PWD", "pfe2026")

AE_INDEX     = "ml-autoencoder-scores"
SIGMA_INDEX  = "sigma-alerts"
CURSOR_INDEX = "ids-pipeline-cursor"
CURSOR_ID    = "last_run"


class ESRepository:
    """Accès Elasticsearch — singleton implicite (méthodes statiques)."""

    # ── Client ────────────────────────────────────────────────────────────────

    @staticmethod
    def _client():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        token = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
        headers = {
            "Content-Type":  "application/json",
            "Authorization": f"Basic {token}",
        }
        return ctx, headers

    @staticmethod
    def _request(path: str, body: dict = None, method: str = None) -> dict:
        ctx, headers = ESRepository._client()
        data = json.dumps(body).encode() if body else None
        m    = method or ("POST" if body else "GET")
        req  = urllib.request.Request(
            f"{ES_HOST}{path}", data=data, headers=headers, method=m
        )
        resp = urllib.request.urlopen(req, context=ctx)
        return json.loads(resp.read())

    # ── CURSEUR ───────────────────────────────────────────────────────────────

    @staticmethod
    def get_cursor() -> str:
        """
        Retourne le dernier @timestamp traité.
        'now-1d' si premier lancement.
        """
        try:
            doc = ESRepository._request(f"/{CURSOR_INDEX}/_doc/{CURSOR_ID}")
            return doc["_source"].get("last_timestamp", "now-1d")
        except Exception:
            return "now-1d"

    @staticmethod
    def save_cursor(timestamp: str):
        """Sauvegarde le timestamp du dernier log traité."""
        try:
            ESRepository._request(
                f"/{CURSOR_INDEX}/_doc/{CURSOR_ID}",
                body={
                    "last_timestamp": timestamp,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                },
                method="PUT",
            )
        except Exception as e:
            print(f"[ESRepository] Erreur save_cursor : {e}")

    # ── LOGS SOURCES ──────────────────────────────────────────────────────────

    @staticmethod
    def get_new_logs_count(cursor: str) -> dict:
        """
        Compte les nouveaux logs depuis le curseur.
        Retourne {'total', 'by_source', 'max_timestamp'}.
        """
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"exists": {"field": "ml.log_source"}},
                        {"range": {"@timestamp": {"gt": cursor}}}
                    ]
                }
            },
            "aggs": {
                "by_source":     {"terms": {"field": "ml.log_source.keyword", "size": 10}},
                "max_timestamp": {"max":   {"field": "@timestamp"}},
            }
        }
        try:
            result = ESRepository._request(
                "/filebeat-logs-*,auditbeat-*/_search", body
            )
            aggs   = result.get("aggregations", {})
            return {
                "total": result["hits"]["total"]["value"],
                "by_source": {
                    b["key"]: b["doc_count"]
                    for b in aggs.get("by_source", {}).get("buckets", [])
                },
                "max_timestamp": aggs.get("max_timestamp", {}).get("value_as_string"),
            }
        except Exception as e:
            return {"total": 0, "by_source": {}, "max_timestamp": None, "error": str(e)}

    # ── ANOMALIES AE ──────────────────────────────────────────────────────────

    @staticmethod
    def get_anomalies(cursor: str, limit: int = 100) -> list[dict]:
        """Retourne les anomalies AE depuis le curseur."""
        body = {
            "size":  limit,
            "query": {
                "bool": {
                    "must": [
                        {"term":  {"ae_is_anomaly": 1}},
                        {"range": {"@timestamp": {"gt": cursor}}}
                    ]
                }
            },
            "sort":    [{"@timestamp": {"order": "desc"}}],
            "_source": [
                "@timestamp", "log_source", "ae_mse_error",
                "ae_anomaly_score", "composite_score", "ae_threshold",
                "kb_severity", "llm_explanation", "detection_source",
            ],
        }
        try:
            result = ESRepository._request(f"/{AE_INDEX}/_search", body)
            return [
                {"id": h["_id"], "type": "anomaly", **h["_source"]}
                for h in result["hits"]["hits"]
            ]
        except Exception as e:
            print(f"[ESRepository] get_anomalies error : {e}")
            return []

    @staticmethod
    def get_anomaly_detail(doc_id: str) -> dict:
        """Retourne le détail complet d'une anomalie (avec llm_explanation)."""
        ctx, headers = ESRepository._client()
        req = urllib.request.Request(
            f"{ES_HOST}/{AE_INDEX}/_doc/{doc_id}",
            headers=headers, method="GET"
        )
        try:
            resp = urllib.request.urlopen(req, context=ctx)
            doc  = json.loads(resp.read())
            return {"id": doc["_id"], "type": "anomaly", **doc["_source"]}
        except Exception as e:
            raise ValueError(f"Anomalie {doc_id} introuvable : {e}")

    # ── ALERTES SIGMA ─────────────────────────────────────────────────────────

    @staticmethod
    def get_alerts(cursor: str, limit: int = 100) -> list[dict]:
        """Retourne les alertes Sigma depuis le curseur."""
        body = {
            "size":  limit,
            "query": {"range": {"@timestamp": {"gt": cursor}}},
            "sort":  [{"@timestamp": {"order": "desc"}}],
            "_source": [
                "@timestamp", "alert.title", "alert.level", "alert.tactic",
                "alert.hits", "alert.details", "detection_source",
                "ae_correlated", "llm_explanation",
            ],
        }
        try:
            result = ESRepository._request(f"/{SIGMA_INDEX}/_search", body)
            alerts = []
            for h in result["hits"]["hits"]:
                src = h["_source"]
                alerts.append({
                    "id":               h["_id"],
                    "type":             "alert",
                    "@timestamp":       src.get("@timestamp"),
                    "title":            src.get("alert.title", "?"),
                    "level":            src.get("alert.level", "?"),
                    "tactic":           src.get("alert.tactic", ""),
                    "hits":             src.get("alert.hits", 0),
                    "details":          src.get("alert.details", []),
                    "detection_source": src.get("detection_source", "sigma_only"),
                    "ae_correlated":    src.get("ae_correlated", False),
                    "llm_explanation":  src.get("llm_explanation"),
                })
            return alerts
        except Exception as e:
            print(f"[ESRepository] get_alerts error : {e}")
            return []

    @staticmethod
    def get_alert_detail(doc_id: str) -> dict:
        """Retourne le détail complet d'une alerte Sigma."""
        ctx, headers = ESRepository._client()
        req = urllib.request.Request(
            f"{ES_HOST}/{SIGMA_INDEX}/_doc/{doc_id}",
            headers=headers, method="GET"
        )
        try:
            resp = urllib.request.urlopen(req, context=ctx)
            doc  = json.loads(resp.read())
            return {"id": doc["_id"], "type": "alert", **doc["_source"]}
        except Exception as e:
            raise ValueError(f"Alerte {doc_id} introuvable : {e}")

    # ── STATS ─────────────────────────────────────────────────────────────────

    @staticmethod
    def get_stats(cursor: str) -> dict:
        """Stats globales pour le dashboard."""
        def count(index, query):
            try:
                return ESRepository._request(
                    f"/{index}/_count", {"query": query}
                ).get("count", 0)
            except Exception:
                return 0

        ae_total  = count(AE_INDEX, {"bool": {"must": [
            {"term":  {"ae_is_anomaly": 1}},
            {"range": {"@timestamp": {"gt": cursor}}}
        ]}})
        sig_total = count(SIGMA_INDEX, {"range": {"@timestamp": {"gt": cursor}}})
        critical  = count(SIGMA_INDEX, {"bool": {"must": [
            {"term":  {"alert.level": "CRITICAL"}},
            {"range": {"@timestamp": {"gt": cursor}}}
        ]}})
        both      = count(SIGMA_INDEX, {"bool": {"must": [
            {"term":  {"ae_correlated": True}},
            {"range": {"@timestamp": {"gt": cursor}}}
        ]}})

        return {
            "cursor":          cursor,
            "ae_anomalies":    ae_total,
            "sigma_alerts":    sig_total,
            "critical":        critical,
            "correlated_both": both,
        }

 
    @staticmethod
    def get_timeline(days: int = 7) -> list[dict]:
        """
        Agrège anomalies AE et alertes Sigma par jour sur les N derniers jours.
        Retourne : [{ date, ae_anomalies, sigma_alerts, critical }]
        """
        cursor = f"now-{days}d"
 
        def agg_by_day(index, extra_filter=None):
            must = [{"range": {"@timestamp": {"gte": cursor}}}]
            if extra_filter:
                must.append(extra_filter)
            body = {
                "size": 0,
                "query": {"bool": {"must": must}},
                "aggs": {
                    "by_day": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "calendar_interval": "day",
                            "format": "yyyy-MM-dd",
                        }
                    }
                },
            }
            try:
                res = ESRepository._request(f"/{index}/_search", body)
                return {
                    b["key_as_string"]: b["doc_count"]
                    for b in res["aggregations"]["by_day"]["buckets"]
                }
            except Exception:
                return {}
 
        ae_days       = agg_by_day(AE_INDEX,    {"term": {"ae_is_anomaly": 1}})
        sigma_days    = agg_by_day(SIGMA_INDEX)
        critical_days = agg_by_day(SIGMA_INDEX, {"term": {"alert.level": "CRITICAL"}})
 
        all_dates = sorted(set(list(ae_days) + list(sigma_days)))
        return [
            {
                "date":         d,
                "ae_anomalies": ae_days.get(d, 0),
                "sigma_alerts": sigma_days.get(d, 0),
                "critical":     critical_days.get(d, 0),
            }
            for d in all_dates
        ]
 
    # ── PAR NIVEAU ────────────────────────────────────────────────────────────
 
    @staticmethod
    def get_alerts_by_level() -> list[dict]:
        """
        Pie chart — nombre d'alertes Sigma par niveau de sévérité.
        Retourne : [{ level, count }]
        """
        body = {
            "size": 0,
            "aggs": {
                "by_level": {
                    "terms": {"field": "alert.level", "size": 10}
                }
            },
        }
        try:
            res = ESRepository._request(f"/{SIGMA_INDEX}/_search", body)
            return [
                {"level": b["key"], "count": b["doc_count"]}
                for b in res["aggregations"]["by_level"]["buckets"]
            ]
        except Exception:
            return []
 
    # ── PAR SOURCE ────────────────────────────────────────────────────────────
 
    @staticmethod
    def get_anomalies_by_source() -> list[dict]:
        """
        Pie chart — anomalies AE par source de log (auth/syslog/auditd).
        Retourne : [{ source, count }]
        """
        body = {
            "size": 0,
            "query": {"term": {"ae_is_anomaly": 1}},
            "aggs": {
                "by_source": {
                    "terms": {"field": "log_source.keyword", "size": 10}
                }
            },
        }
        try:
            res = ESRepository._request(f"/{AE_INDEX}/_search", body)
            return [
                {"source": b["key"], "count": b["doc_count"]}
                for b in res["aggregations"]["by_source"]["buckets"]
            ]
        except Exception:
            return []
         