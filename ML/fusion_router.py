# fusion_router.py
# core/fusion_router.py
#
# RÔLE ACTUEL : génération des explications LLM
#   - process_dataframe()    → explications AE   (appelé par ML/autoencodeur.py)
#   - process_sigma_alerts() → explications Sigma (appelé par sigma_engine.py main())
#
# NOTE : la corrélation AE↔Sigma du DASHBOARD n'est PAS faite ici — elle est
#        calculée par intersection d'IDs dans analyse_controller._run_fusion.
#        Les méthodes _check_ae_correlation / _cross_check_sigma ci-dessous
#        ne servent qu'aux pipelines standalone (entraînement / Sigma CLI).

import os, sys, ssl, json, base64, urllib.request
from datetime import datetime, timezone
import pandas as pd
import numpy as np

# Chemin vers ML/ — fait une seule fois au démarrage
_ML_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'ML')
if _ML_DIR not in sys.path:
    sys.path.insert(0, _ML_DIR)

from rag_explainer import (explain_anomaly, generate_auto_explanation,
                            make_grok_client, build_ml_dict)
from knowledge_base import (get_matched_entries, get_max_severity,
                             retrieve_knowledge_context)

ES_HOST       = os.getenv("ES_HOST", "https://localhost:9200")
ES_USER       = os.getenv("ES_USER", "elastic")
ES_PASS       = os.getenv("ELASTIC_PWD", "pfe2026")
ALERT_INDEX   = "sigma-alerts"
AE_INDEX      = "ml-autoencoder-scores"

MIN_SCORE_LLM  = 6
MIN_SCORE_AUTO = 1


class FusionRouter:
    """
    Génère les explications LLM pour les anomalies AE et les alertes Sigma.
    Conserve une corrélation heuristique (source + fenêtre) utilisée
    uniquement par les pipelines standalone.
    """

    def __init__(self, ae_threshold: float = 0.75):
        self.ae_threshold = ae_threshold
        self._sigma_alerts_cache: list = []

    # ── Pipeline AE : appelé depuis ML/autoencodeur.py ─────────────
    def process_dataframe(self, df_result: pd.DataFrame, thresholds: dict):
        """
        Génère les explications LLM (haute priorité) ou template auto
        (priorité moyenne) pour les anomalies AE, puis met à jour ES.
        Cross-check chaque anomalie AE avec le cache Sigma.
        """
        try:
            grok = make_grok_client()
        except ValueError as e:
            print(f"  [FUSION] LLM Skipped — {e}")
            return

        scores    = pd.to_numeric(
            df_result.get("composite_score", 0), errors="coerce").fillna(0)
        anomalies = df_result.get("ae_is_anomaly", 0)
        has_es_id = df_result.get(
            "_es_write_id",
            pd.Series([None] * len(df_result), index=df_result.index)
        ).notna()

        mask_llm  = (anomalies == 1) & (scores >= MIN_SCORE_LLM) & has_es_id
        mask_auto = (anomalies == 1) & (scores >= MIN_SCORE_AUTO) \
                  & (scores < MIN_SCORE_LLM) & has_es_id

        print(f"\n  [FUSION] {mask_llm.sum()} anomalies AE → LLM | "
              f"{mask_auto.sum()} → template auto")

        ctx_ssl, headers = self._make_es_client()

        for idx, row in df_result[mask_llm].head(20).iterrows():
            anomaly_doc      = row.to_dict()
            detection_source = self._cross_check_sigma(anomaly_doc)
            result = explain_anomaly(
                anomaly_doc, es=None, grok_client=grok,
                detection_source=detection_source
            )
            self._update_es(AE_INDEX, str(row.get("_es_write_id", "")),
                            result, ctx_ssl, headers)
            print(f"  [FUSION-LLM] ✓ {row.get('log_source','?'):8s} | "
                  f"source={detection_source} | "
                  f"sev={result.get('kb_severity','?')}")

        for idx, row in df_result[mask_auto].iterrows():
            result = generate_auto_explanation(row.to_dict())
            self._update_es(AE_INDEX, str(row.get("_es_write_id", "")),
                            result, ctx_ssl, headers)

    # ── Pipeline Sigma : appelé depuis sigma_engine.py main() ──────
    def process_sigma_alerts(self, alerts: list):
        """
        Enrichit chaque alerte Sigma avec ae_correlated + detection_source,
        met à jour ES, puis génère les explications LLM via explain_sigma_alerts.
        """
        import sys as _sys, os as _os
        _sigma = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                               '..', 'sigma', 'detect')
        if _sigma not in _sys.path:
            _sys.path.insert(0, _sigma)
        from sigma_engine import explain_sigma_alerts   # ← corrigé (était: main)

        self._sigma_alerts_cache = alerts

        enriched = []
        for alert in alerts:
            ae_corr = self._check_ae_correlation(alert)
            alert_enriched = dict(alert)
            alert_enriched["ae_correlated"]    = ae_corr
            alert_enriched["detection_source"] = "both" if ae_corr else "sigma_only"
            enriched.append(alert_enriched)
            if ae_corr:
                print(f"  [FUSION] BOTH confirmé : {alert['title']}")

        ctx_ssl, headers = self._make_es_client()
        for a in enriched:
            if a.get("es_id"):
                self._update_es(ALERT_INDEX, a["es_id"],
                                {"ae_correlated": a["ae_correlated"],
                                 "detection_source": a["detection_source"]},
                                ctx_ssl, headers)

        explain_sigma_alerts(enriched)

    # ── Helpers corrélation (standalone uniquement) ────────────────
    def _cross_check_sigma(self, anomaly_doc: dict) -> str:
        """Retourne 'both' | 'ae_only' selon présence d'une alerte Sigma même source."""
        src = anomaly_doc.get("log_source", "")
        SOURCE_MAP = {
            "auth":   ["auth", "sshd", "SSH"],
            "auditd": ["auditd", "audit"],
            "syslog": ["syslog", "kernel", "systemd"],
        }
        keywords = SOURCE_MAP.get(src, [src])
        for alert in self._sigma_alerts_cache:
            title = alert.get("title", "")
            if any(k.lower() in title.lower() for k in keywords):
                return "both"
        return "ae_only"

    def _check_ae_correlation(self, sigma_alert: dict) -> bool:
        """Vérifie si une anomalie AE récente (même source) existe dans ES."""
        tactic = sigma_alert.get("tactic", "")
        SOURCE_MAP = {"SSH": "auth", "Credential": "auth",
                      "auditd": "auditd", "syslog": "syslog"}
        src = next((v for k, v in SOURCE_MAP.items()
                    if k.lower() in tactic.lower()), None)
        if not src:
            return False
        try:
            ctx_ssl, headers = self._make_es_client()
            body = json.dumps({
                "size": 1,
                "query": {
                    "bool": {
                        "must": [
                            {"term":  {"log_source":    src}},
                            {"term":  {"ae_is_anomaly": 1}},
                            {"range": {"@timestamp": {"gte": "now-30m"}}}
                        ]
                    }
                }
            }).encode()
            req  = urllib.request.Request(
                f"{ES_HOST}/{AE_INDEX}/_search",
                data=body, headers=headers, method="POST")
            resp = json.loads(
                urllib.request.urlopen(req, context=ctx_ssl).read())
            return resp["hits"]["total"]["value"] > 0
        except Exception:
            return False

    def _make_es_client(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        token   = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
        headers = {"Content-Type":  "application/json",
                   "Authorization": f"Basic {token}"}
        return ctx, headers

    def _update_es(self, index, doc_id, payload, ctx_ssl, headers):
        if not doc_id or doc_id in ("", "None", "nan"):
            return
        try:
            body = json.dumps({"doc": payload}).encode()
            req  = urllib.request.Request(
                f"{ES_HOST}/{index}/_update/{doc_id}",
                data=body, headers=headers, method="POST")
            urllib.request.urlopen(req, context=ctx_ssl)
        except Exception as e:
            print(f"  [FUSION] Update error {doc_id}: {e}")