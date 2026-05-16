# fusion_router.py
# core/fusion_router.py
import os, sys, ssl, json, base64, urllib.request
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timezone
import pandas as pd
import numpy as np

# Chemin vers ML/ — fait une seule fois au démarrage
_ML_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'ML')
if _ML_DIR not in sys.path:
    sys.path.insert(0, _ML_DIR)

# Imports ML — disponibles dans tout le fichier
from rag_explainer import (explain_anomaly, generate_auto_explanation,
                            make_grok_client, build_ml_dict)
from knowledge_base import (get_matched_entries, get_max_severity,
                             retrieve_knowledge_context)
ES_HOST       = os.getenv("ES_HOST", "https://localhost:9200")
ES_USER       = os.getenv("ES_USER", "elastic")
ES_PASS       = os.getenv("ELASTIC_PWD", "pfe2026")
ALERT_INDEX   = "sigma-alerts"
AE_INDEX      = "ml-autoencoder-scores"

MIN_SCORE_LLM  = 6   # seuil unique — retiré de rag_explainer.py
MIN_SCORE_AUTO = 1

class DetectionSource(Enum):
    NONE        = "none"
    AE_ONLY     = "ae_only"
    SIGMA_ONLY  = "sigma_only"
    BOTH        = "both"

@dataclass
class DetectionResult:
    log_entry:     dict
    sigma_matches: list
    ae_score:      float
    source:        DetectionSource
    severity:      str
    es_id:         str = None   # _id dans sigma-alerts ou ml-autoencoder-scores

class FusionRouter:
    def __init__(self, ae_threshold: float = 0.75):
        self.ae_threshold = ae_threshold
        # Cache des alertes Sigma en mémoire pour le cross-check AE
        self._sigma_alerts_cache: list = []

    # ── Routing d'un log unique (utilisé par log_reader.py) ────────
    def route(self, log_entry: dict,
              sigma_matches: list,
              ae_score: float) -> DetectionResult:
        sigma_hit = bool(sigma_matches)
        ae_hit    = ae_score > self.ae_threshold

        if sigma_hit and ae_hit:
            source   = DetectionSource.BOTH
            severity = "critical"
        elif sigma_hit:
            source   = DetectionSource.SIGMA_ONLY
            severity = self._sigma_severity(sigma_matches)
        elif ae_hit:
            source   = DetectionSource.AE_ONLY
            severity = "high" if ae_score > 0.90 else "medium"
        else:
            source   = DetectionSource.NONE
            severity = "none"

        return DetectionResult(log_entry, sigma_matches,
                               ae_score, source, severity)

    def _sigma_severity(self, rules: list) -> str:
        for r in rules:
            if "CRITICAL" in r.upper(): return "critical"
            if "HIGH"     in r.upper(): return "high"
        return "medium"

    # ── Pipeline AE : appelé depuis ids_pipeline.py ────────────────
    def process_dataframe(self, df_result: pd.DataFrame, thresholds: dict):
        """
        Point d'entrée depuis ids_pipeline.py (section [9/9]).
        Remplace run_llm_explanation_pipeline + run_auto_explanation_pipeline.
        Cross-check chaque anomalie AE avec le cache Sigma.
        """
        from rag_explainer import (explain_anomaly, generate_auto_explanation,
                                   make_grok_client)
        try:
            grok = make_grok_client()
        except ValueError as e:
            print(f"  [FUSION] LLM Skipped — {e}"); return

        scores    = pd.to_numeric(
            df_result.get("composite_score", 0), errors="coerce").fillna(0)
        anomalies = df_result.get("ae_is_anomaly", 0)
        has_es_id = df_result.get(
            "_es_write_id",
            pd.Series([None]*len(df_result), index=df_result.index)
        ).notna()

        # Haute priorité → LLM
        mask_llm  = (anomalies == 1) & (scores >= MIN_SCORE_LLM) & has_es_id
        # Moyenne priorité → template auto
        mask_auto = (anomalies == 1) & (scores >= MIN_SCORE_AUTO) \
                  & (scores < MIN_SCORE_LLM) & has_es_id

        print(f"\n  [FUSION] {mask_llm.sum()} anomalies AE → LLM | "
              f"{mask_auto.sum()} → template auto")

        ctx_ssl, headers = self._make_es_client()

        # ── LLM haute priorité ────────────────────────────────────
        for idx, row in df_result[mask_llm].head(20).iterrows():
            anomaly_doc = row.to_dict()
            # Cross-check : est-ce que Sigma a aussi détecté qqchose ?
            detection_source = self._cross_check_sigma(anomaly_doc)
            result = explain_anomaly(
                anomaly_doc, es=None, grok_client=grok,
                detection_source=detection_source   # ← nouveau paramètre
            )
            self._update_es(AE_INDEX, str(row.get("_es_write_id","")),
                            result, ctx_ssl, headers)
            print(f"  [FUSION-LLM] ✓ {row.get('log_source','?'):8s} | "
                  f"source={detection_source} | "
                  f"sev={result.get('kb_severity','?')}")

        # ── Template auto priorité moyenne ───────────────────────
        for idx, row in df_result[mask_auto].iterrows():
            result = generate_auto_explanation(row.to_dict())
            self._update_es(AE_INDEX, str(row.get("_es_write_id","")),
                            result, ctx_ssl, headers)

    # ── Pipeline Sigma : appelé depuis sigma_detection.py ──────────
    def process_sigma_alerts(self, alerts: list):
        """
        Point d'entrée depuis sigma_detection.py main().
        Remplace explain_sigma_alerts().
        Pour chaque alerte Sigma, vérifie si l'AE a aussi détecté.
        """
        import sys as _sys, os as _os
        _sigma = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                               '..', 'sigma', 'detect')
        if _sigma not in _sys.path:
            _sys.path.insert(0, _sigma)
        from main import explain_sigma_alerts

        # Mettre à jour le cache pour le cross-check AE
        self._sigma_alerts_cache = alerts

        # Enrichir chaque alerte avec le flag ae_correlated
        enriched = []
        for alert in alerts:
            ae_corr = self._check_ae_correlation(alert)
            alert_enriched = dict(alert)
            alert_enriched["ae_correlated"]  = ae_corr
            alert_enriched["detection_source"] = \
                "both" if ae_corr else "sigma_only"
            enriched.append(alert_enriched)
            if ae_corr:
                print(f"  [FUSION] BOTH confirmé : {alert['title']}")

        # Mettre à jour sigma-alerts avec ae_correlated
        ctx_ssl, headers = self._make_es_client()
        for a in enriched:
            if a.get("es_id"):
                self._update_es(ALERT_INDEX, a["es_id"],
                                {"ae_correlated": a["ae_correlated"],
                                 "detection_source": a["detection_source"]},
                                ctx_ssl, headers)

        # Appel LLM enrichi (passe detection_source)
        explain_sigma_alerts(enriched)

    # ── Helpers ────────────────────────────────────────────────────
    def _cross_check_sigma(self, anomaly_doc: dict) -> str:
        """
        Vérifie si une anomalie AE correspond à une alerte Sigma
        via la source de log et la fenêtre temporelle.
        Retourne 'both' | 'ae_only'.
        """
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
        """
        Vérifie si des anomalies AE récentes sont indexées dans ES
        pour la même source que l'alerte Sigma.
        """
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