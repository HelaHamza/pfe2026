"""
repositories/log_repository.py
==============================
PLAN D'INGESTION — Elasticsearch en LECTURE SEULE.
Uniquement les logs bruts (filebeat/auditbeat). Aucune écriture,
aucune donnée applicative.

NB : la branche CNN lit le dataset local (data_loader), pas ES.
Ce repository sert donc surtout à Sigma et aux comptages de logs bruts.

CHANGEMENT : `count_logs_by_source` accepte désormais une fenêtre
]since, until]. Sans fenêtre, elle comptait TOUT l'index ES (cumul),
d'où un dénominateur géant et un taux d'anomalie faussement nul sur le
dashboard. Le dashboard doit refléter le DERNIER run, pas tout l'historique.
"""

import base64
import json
import logging
import ssl
import urllib.request

from config import ES_HOST, ES_USER, ES_PASS

log = logging.getLogger(__name__)

ES_INDEX_SOURCES = "filebeat-logs-*,auditbeat-*"

# Sans timeout, urlopen bloque indéfiniment si ES est injoignable : un seul
# endpoint qui pend fige le worker. Borne dure.
ES_TIMEOUT_S = 10


class LogRepository:

    @staticmethod
    def _client():
        # TLS désactivé : ELK auto-hébergé, certificat auto-signé, réseau de dev.
        # Choix assumé — à réactiver via CA interne si passage en prod.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        token = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
        return ctx, {"Content-Type": "application/json",
                     "Authorization": f"Basic {token}"}

    @staticmethod
    def _search(body: dict) -> dict:
        ctx, headers = LogRepository._client()
        req = urllib.request.Request(
            f"{ES_HOST}/{ES_INDEX_SOURCES}/_search",
            data=json.dumps(body).encode(), headers=headers, method="POST")
        with urllib.request.urlopen(req, context=ctx, timeout=ES_TIMEOUT_S) as resp:
            return json.loads(resp.read())

    @staticmethod
    def count_logs_by_source(since=None, until=None) -> dict:
        """Comptage des logs bruts par source, RESTREINT à la fenêtre du run.

        `since` / `until` : bornes ISO-8601 (UTC). Convention ]since, until]
        identique au reste du pipeline (gt / lte). Sans bornes → comptage
        global (rétro-compatible, mais à éviter sur le dashboard).

        Dégradation gracieuse : ES injoignable → dict vide, le domaine reste
        affichable sans ce bloc. L'échec est journalisé, pas masqué."""
        filters = [{"exists": {"field": "ml.log_source"}}]
        if since or until:
            rng = {}
            if since:
                rng["gt"] = since       # ] since
            if until:
                rng["lte"] = until      # until ]
            filters.append({"range": {"@timestamp": rng}})

        body = {
            "size": 0,
            "query": {"bool": {"filter": filters}},
            "aggs": {"by_source": {"terms": {
                "field": "ml.log_source.keyword", "size": 10}}},
        }
        try:
            r = LogRepository._search(body)
            return {b["key"]: b["doc_count"]
                    for b in r["aggregations"]["by_source"]["buckets"]}
        except Exception as e:
            log.error("count_logs_by_source: ES injoignable ou réponse inattendue (%s)", e)
            return {}