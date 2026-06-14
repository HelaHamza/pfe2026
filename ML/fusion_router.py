# =============================================================================
# FUSION ROUTER — v9 (adapté au modèle AE V9, signaux comportementaux)
# =============================================================================
# RÔLE : génération des explications LLM.
#   - process_dataframe()    → explications AE   (appelé par ML/autoencodeur.py)
#   - process_sigma_alerts() → explications Sigma (appelé par sigma_engine.py)
#
# CHANGEMENTS v9 (flux AE uniquement) :
#   1. Le tri LLM vs template ne se base PLUS sur composite_score / MIN_SCORE_LLM
#      (ces scores dépendaient des flags-verdict supprimés en V9).
#      → On trie sur le PERCENTILE du MSE PAR SOURCE : les LLM_TOP_PCT % de MSE
#        les plus élevés (dans leur propre source) partent au LLM, le reste au
#        template auto. Le MSE est le signal d'anomalie en V9.
#   2. detection_source forcé à "ae_only" dans le flux AE : il n'y a plus de
#      corrélation Sigma↔flags dans ce pipeline (la corrélation dashboard est
#      faite ailleurs, par intersection d'IDs).
#   3. Plus aucun appel à knowledge_base dans le flux AE : l'explication
#      repose sur ae_behavioral_signals (géré côté rag_explainer).
#
# CONSERVÉ tel quel :
#   - process_sigma_alerts() et ses helpers (_check_ae_correlation,
#     _cross_check_sigma) : utilisés par le pipeline Sigma standalone.
#   - _make_es_client / _update_es.

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

# --- Tri du flux AE (V9) ---
# Fraction (par source) des anomalies envoyées au LLM, triées par MSE décroissant.
# Le reste reçoit l'explication template (sans token Groq).
LLM_TOP_PCT   = 0.10        # top 10% MSE par source -> LLM
LLM_MAX_CALLS = 20          # plafond dur d'appels LLM (garde-fou tokens/rate-limit)


class FusionRouter:
    """
    Génère les explications LLM pour les anomalies AE et les alertes Sigma.
    Flux AE (V9) : tri par percentile MSE par source.
    Flux Sigma : inchangé (corrélation heuristique standalone).
    """

    def __init__(self, ae_threshold: float = 0.75):
        self.ae_threshold = ae_threshold
        self._sigma_alerts_cache: list = []

    # ── Pipeline AE : appelé depuis ML/autoencodeur.py ─────────────
    def process_dataframe(self, df_result: pd.DataFrame, thresholds: dict):
        """
        Génère les explications pour les anomalies AE :
          - top LLM_TOP_PCT % de MSE PAR SOURCE → explication LLM,
          - le reste → explication template auto (comportementale).
        Puis met à jour ES. detection_source = "ae_only" (pas de Sigma ici).
        """
        if df_result is None or len(df_result) == 0:
            print("  [FUSION] Rien à expliquer (df vide).")
            return

        try:
            grok = make_grok_client()
        except ValueError as e:
            print(f"  [FUSION] LLM Skipped — {e}")
            return

        df = df_result.copy()

        # On ne traite que les vraies anomalies adressables dans ES.
        anomalies = pd.to_numeric(
            df.get("ae_is_anomaly", 0), errors="coerce").fillna(0).astype(int)
        has_es_id = df.get(
            "_es_write_id",
            pd.Series([None] * len(df), index=df.index)
        ).notna()

        mse = pd.to_numeric(df.get("ae_mse_error", 0), errors="coerce").fillna(0.0)

        eligible = (anomalies == 1) & has_es_id
        if eligible.sum() == 0:
            print("  [FUSION] Aucune anomalie adressable (ae_is_anomaly==1 "
                  "& _es_write_id présent).")
            return

        # --- Tri par percentile de MSE PAR SOURCE ---
        # rank(pct=True) donne le rang relatif dans [0,1] au sein du groupe.
        # On garde au LLM les MSE dont le rang >= (1 - LLM_TOP_PCT).
        df["_mse_for_rank"] = mse.where(eligible, other=np.nan)
        src_series = df.get("log_source",
                            pd.Series(["?"] * len(df), index=df.index)).astype(str)

        pct_rank = (df.groupby(src_series)["_mse_for_rank"]
                      .rank(pct=True, method="average"))
        df["_mse_pct_in_source"] = pct_rank

        mask_llm  = eligible & (pct_rank >= (1.0 - LLM_TOP_PCT))
        mask_auto = eligible & ~mask_llm

        n_llm_total = int(mask_llm.sum())
        print(f"\n  [FUSION] V9 tri par MSE/source (top {LLM_TOP_PCT*100:.0f}%) : "
              f"{n_llm_total} → LLM (plafond {LLM_MAX_CALLS}) | "
              f"{int(mask_auto.sum())} → template auto")

        ctx_ssl, headers = self._make_es_client()

        # --- LLM : les plus hauts MSE d'abord, plafonnés ---
        df_llm = (df[mask_llm]
                  .sort_values("_mse_for_rank", ascending=False)
                  .head(LLM_MAX_CALLS))

        for idx, row in df_llm.iterrows():
            anomaly_doc = row.to_dict()
            result = explain_anomaly(
                anomaly_doc, es=None, grok_client=grok,
                detection_source="ae_only"          # V9 : pas de Sigma ici
            )
            self._update_es(AE_INDEX, str(row.get("_es_write_id", "")),
                            result, ctx_ssl, headers)
            pct = row.get("_mse_pct_in_source", float("nan"))
            print(f"  [FUSION-LLM] ✓ {str(row.get('log_source','?')):8s} | "
                  f"MSE={row.get('ae_mse_error','?')} | "
                  f"pct_source={pct:.3f} | sev={result.get('kb_severity','?')}")

        # --- Les anomalies LLM au-delà du plafond retombent en template ---
        overflow_idx = df[mask_llm].index.difference(df_llm.index)
        if len(overflow_idx) > 0:
            print(f"  [FUSION] {len(overflow_idx)} anomalies LLM au-delà du "
                  f"plafond → template auto")

        # --- Template auto : reste + overflow ---
        auto_idx = df[mask_auto].index.union(overflow_idx)
        for idx in auto_idx:
            row = df.loc[idx]
            result = generate_auto_explanation(row.to_dict())
            self._update_es(AE_INDEX, str(row.get("_es_write_id", "")),
                            result, ctx_ssl, headers)

        print(f"  [FUSION] Terminé — {len(df_llm)} LLM | "
              f"{len(auto_idx)} template.")

    # ── Pipeline Sigma : appelé depuis sigma_engine.py main() ──────
    # (INCHANGÉ — utilisé par le pipeline Sigma standalone)
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
        from sigma_engine import explain_sigma_alerts

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
    # (INCHANGÉS — utilisés par process_sigma_alerts)
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