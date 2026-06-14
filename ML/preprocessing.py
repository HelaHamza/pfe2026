"""
preprocessing.py
================
Construction des matrices X par source.

Points cles :
  * log1p sur les comptages (COUNT_FEATURES) -> ecrase les queues lourdes.
  * StandardScaler fit UNIQUEMENT sur le train (pas de fuite calib/test).
  * Filtre de variance calcule UNIQUEMENT sur le train (corrige la fuite
    mineure de l'ancienne version qui voyait la validation).
  * Clip a +/- SCALE_CLIP (assoupli) apres scaling.
"""
from __future__ import annotations
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

import config as C


def _raw_matrix(df_src, feats):
    """Matrice brute (avant scaling), log1p applique aux comptages."""
    n = len(df_src)
    cols = []
    for c in feats:
        if c not in df_src.columns:
            vals = np.zeros(n, dtype=np.float32)
        else:
            vals = pd.to_numeric(df_src[c], errors="coerce").fillna(0.0).values
            if c in C.COUNT_FEATURES:
                vals = np.log1p(np.clip(vals, 0, None))
        cols.append(vals.astype(np.float32))
    return np.stack(cols, axis=1) if cols else np.zeros((n, 0), dtype=np.float32)


def fit_feature_filter(X_train, feats):
    """Retire les features constantes SUR LE TRAIN (sauf whitelist rare-event).
    Retourne (keep_mask, feats_gardees)."""
    keep = np.array([
        (np.nanvar(X_train[:, i]) > C.VARIANCE_THRESHOLD)
        or feats[i] in C.WHITELIST_FEATURES
        for i in range(X_train.shape[1])
    ])
    dropped = [f for f, k in zip(feats, keep) if not k]
    if dropped:
        print(f"      constantes retirees : {dropped}")
    return keep, [f for f, k in zip(feats, keep) if k]


def fit_scaler(df_train_src, feats, keep_mask):
    """Fit le StandardScaler sur le TRAIN uniquement."""
    X = np.nan_to_num(_raw_matrix(df_train_src, feats))[:, keep_mask]
    scaler = StandardScaler().fit(X)
    return scaler


def transform(df_src, feats, scaler, keep_mask):
    """Applique log1p + keep_mask + scaler + clip. Aucune fuite (scaler deja fit)."""
    X = np.nan_to_num(_raw_matrix(df_src, feats))[:, keep_mask]
    Xs = np.clip(scaler.transform(X), -C.SCALE_CLIP, C.SCALE_CLIP)
    return Xs.astype(np.float32)