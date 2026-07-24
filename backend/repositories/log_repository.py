"""
repositories/log_repository.py
==============================
PLAN D'INGESTION — Elasticsearch en LECTURE SEULE.
Uniquement les logs bruts (filebeat/auditbeat). Aucune écriture,
aucune donnée applicative.

NB : la branche CNN lit le dataset local (data_loader), pas ES.
Ce repository sert donc surtout à Sigma et aux comptages de logs bruts.
"""
import base64
import json
import ssl
import urllib.request

from config import ES_HOST, ES_USER, ES_PASS

ES_INDEX_SOURCES = "filebeat-logs-*,auditbeat-*"


class LogRepository:

    @staticmethod
    def _client():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        token = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
        return ctx, {"Content-Type": "application/json",
                     "Authorization": f"Basic {token}"}

    @staticmethod
    def _search(body: dict) -> dict:
        ctx, headers = LogRepository._client()
        req = urllib.request.Request(
            f"{ES_HOST}/{ES_INDEX_SOURCES}/_search",
            data=json.dumps(body).encode(), headers=headers, method="POST")
        return json.loads(urllib.request.urlopen(req, context=ctx).read())

    @staticmethod
    def count_logs_by_source() -> dict:
        """Comptage des logs bruts par source (pour le bloc 'logs analysés')."""
        body = {
            "size": 0,
            "query": {"exists": {"field": "ml.log_source"}},
            "aggs": {"by_source": {"terms": {
                "field": "ml.log_source.keyword", "size": 10}}},
        }
        try:
            r = LogRepository._search(body)
            return {b["key"]: b["doc_count"]
                    for b in r["aggregations"]["by_source"]["buckets"]}
        except Exception as e:
            print(f"[LogRepo] count_logs_by_source: {e}")
            return {}