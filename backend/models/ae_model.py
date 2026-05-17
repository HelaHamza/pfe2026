"""
backend/models/ae_model.py
===========================
MODEL — Autoencoder MoE-AE.
Charge model_moe_ae.pt une seule fois au démarrage (singleton).
Expose infer(cursor) qui lit ES, calcule MSE, écrit les résultats.
"""

import os
import sys
import warnings
import numpy as np
import pandas as pd
import torch
import joblib

warnings.filterwarnings("ignore")

# ── Paths ─────────────────────────────────────────────────────────────────────
_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ROOT    = os.path.dirname(_BACKEND)
_ML      = os.path.join(_ROOT, "ML")

for _p in [_ML, _ROOT]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ── Imports depuis ML/autoencodeur.py ─────────────────────────────────────────
from autoencodeur import (
    MoEAutoencoder,
    SHARED_FEATURES, EXPERT_FEATURES, EXPERT_DIMS,
    SHARED_DIM, LATENT_DIM, SOURCES, DEVICE,
    ES_INDEX_WRITE,
    preprocess_source,
    get_threshold,
    write_to_elasticsearch,
)

MODEL_PATH   = os.path.join(_ROOT, "model_moe_ae.pt")
SCALERS_PATH = os.path.join(_ROOT, "moe_scalers.pkl")
THRESH_PATH  = os.path.join(_ROOT, "moe_thresholds.pkl")
ES_SOURCE    = "filebeat-logs-*,auditbeat-*"


class AEModel:
    """
    Singleton — le modèle est chargé une seule fois au premier appel.
    Toutes les méthodes sont des classmethods.
    """

    _model      = None
    _scalers    = None
    _thresholds = None

    @classmethod
    def load(cls):
        """Charge le modèle, les scalers et les seuils depuis le disque."""
        if cls._model is not None:
            return  # déjà chargé

        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"Modèle introuvable : {MODEL_PATH}\n"
                "Lance ML/autoencodeur.py d'abord pour l'entraîner."
            )

        print("[AEModel] Chargement du modèle...")
        cls._model = MoEAutoencoder(SHARED_DIM, EXPERT_DIMS, LATENT_DIM)
        cls._model.load_state_dict(
            torch.load(MODEL_PATH, map_location=DEVICE)
        )
        cls._model.to(DEVICE).eval()

        cls._scalers    = joblib.load(SCALERS_PATH)
        cls._thresholds = joblib.load(THRESH_PATH)
        print(f"[AEModel] ✓ Modèle chargé sur {DEVICE}")

    @classmethod
    def infer(cls, cursor: str) -> dict:
        """
        1. Charge les nouveaux logs depuis ES (depuis cursor)
        2. Calcule les MSE par source
        3. Détecte les anomalies
        4. Écrit dans ml-autoencoder-scores
        Retourne {'n_logs', 'n_anomalies', 'last_timestamp'}
        """
        cls.load()  # no-op si déjà chargé

        # ── Chargement logs ───────────────────────────────────────────────────
        df_raw, last_ts = cls._load_new_logs(cursor)

        if df_raw.empty:
            print("[AEModel] Aucun nouveau log.")
            return {"n_logs": 0, "n_anomalies": 0, "last_timestamp": None}

        # ── Inférence par source ──────────────────────────────────────────────
        results = []
        for src in SOURCES:
            if src not in cls._scalers:
                continue
            if "log_source" not in df_raw.columns:
                continue

            df_src = df_raw[df_raw["log_source"] == src].reset_index(drop=True)
            if len(df_src) == 0:
                continue

            sc_sh, sc_ex = cls._scalers[src]
            X_sh, X_ex, _, _ = preprocess_source(
                df_src, src, sc_sh, sc_ex, fit=False
            )

            mse = cls._model.reconstruction_error(
                torch.FloatTensor(X_sh).to(DEVICE),
                torch.FloatTensor(X_ex).to(DEVICE),
                src,
            )

            hours = pd.to_numeric(
                df_src.get("hour_of_day", 12), errors="coerce"
            ).fillna(12).astype(int).values
            dows  = pd.to_numeric(
                df_src.get("day_of_week", 3), errors="coerce"
            ).fillna(3).astype(int).values

            thr_arr = np.array([
                get_threshold(cls._thresholds, src, hours[i], dows[i])
                for i in range(len(mse))
            ])

            p99  = np.percentile(mse, 99) + 1e-9
            norm = np.clip(np.log1p(mse) / np.log1p(p99), 0, 1)

            df_src = df_src.copy()
            df_src["ae_mse_error"]     = np.round(mse,  6)
            df_src["ae_anomaly_score"] = np.round(norm,  4)
            df_src["ae_threshold"]     = np.round(thr_arr, 6)

            if src == "auditd":
                composite = pd.to_numeric(
                    df_src.get("composite_score", 0), errors="coerce"
                ).fillna(0).values
                df_src["ae_is_anomaly"] = (
                    (mse > thr_arr) & (composite >= 1)
                ).astype(int)
            else:
                df_src["ae_is_anomaly"] = (mse > thr_arr).astype(int)

            n = int(df_src["ae_is_anomaly"].sum())
            print(f"[AEModel] {src:8s}: {n}/{len(df_src)} anomalies")
            results.append(df_src)

        if not results:
            return {"n_logs": len(df_raw), "n_anomalies": 0, "last_timestamp": last_ts}

        df_result  = pd.concat(results, ignore_index=True)
        n_anomalies = int(df_result["ae_is_anomaly"].sum())

        # ── Écriture ES ───────────────────────────────────────────────────────
        df_result = write_to_elasticsearch(df_result, cls._thresholds)
        print(f"[AEModel] ✓ {n_anomalies} anomalies écrites dans ES")

        return {
            "n_logs":          len(df_raw),
            "n_anomalies":     n_anomalies,
            "last_timestamp":  last_ts,
            "df_result":       df_result,  # utilisé par analyse_controller pour fusion
        }

    @classmethod
    def _load_new_logs(cls, cursor: str, max_docs: int = 50_000):
        """Charge les nouveaux logs depuis ES depuis le curseur."""
        import base64, ssl, urllib.request
        from autoencodeur import es_request

        all_fields = list(dict.fromkeys(
            SHARED_FEATURES
            + [f for fl in EXPERT_FEATURES.values() for f in fl]
            + ["log_source", "composite_score", "hour_of_day", "day_of_week"]
        ))

        query = {
            "size": 5000,
            "query": {
                "bool": {
                    "must": [
                        {"exists": {"field": "ml.log_source"}},
                        {"range": {"@timestamp": {"gt": cursor}}}
                    ]
                }
            },
            "_source": ["@timestamp"] + ["ml." + f for f in all_fields],
            "sort":    [{"@timestamp": {"order": "asc"}}],
        }

        data      = es_request(f"/{ES_SOURCE}/_search?scroll=2m", query)
        scroll_id = data["_scroll_id"]
        rows      = []
        last_ts   = None

        def extract(d):
            nonlocal last_ts
            out = []
            for hit in d["hits"]["hits"]:
                ml = hit.get("_source", {}).get("ml", {})
                if ml:
                    ml["_id"]        = hit["_id"]
                    ml["@timestamp"] = hit["_source"].get("@timestamp", "")
                    if ml["@timestamp"]:
                        last_ts = ml["@timestamp"]
                    out.append(ml)
            return out

        rows += extract(data)
        while len(rows) < max_docs:
            data = es_request(
                "/_search/scroll",
                {"scroll": "2m", "scroll_id": scroll_id}
            )
            new = extract(data)
            if not new:
                break
            scroll_id = data["_scroll_id"]
            rows     += new

        print(f"[AEModel] {len(rows)} nouveaux logs chargés")
        if not rows:
            return pd.DataFrame(), None

        return pd.DataFrame(rows), last_ts