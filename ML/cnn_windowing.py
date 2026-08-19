"""
cnn_windowing.py
================
Construction des fenetres glissantes CAUSALES consommees par le CNN.

ROLE
----
A partir d'un sous-DataFrame d'UNE source (auth / syslog / auditd), ce module
produit les deux tenseurs d'entree du reseau :

    Xs [N, Fs, W]   fenetres des features SCALAIRES (branche convolutive)
    Xt [N, W]       fenetres des identifiants d'event_type (branche sequentielle)

ou W = CC.WINDOW_SIZE et N = nombre d'evenements. La fenetre de l'evenement i
couvre [i-W+1 .. i] : elle ne regarde QUE le passe (pad a gauche). Aucune
information future ne fuite dans le score -- condition indispensable a une
detection en ligne honnete, et au fait que les scores hors ligne (gate,
evaluation) soient comparables a ceux de la production.

CLE DE FENETRAGE
----------------
Les fenetres sont construites PAR CLE (_window_key), et non sur le flux global :
selon la source, la cle est l'IP source (auth) ou l'hote (syslog / auditd).
Deux evenements de cles differentes ne partagent jamais une fenetre -- la
rafale d'une IP ne contamine pas la sequence d'une autre. Le decoupage par cle
est realise en un seul balayage sur le df trie par (cle, temps).

COHERENCE ENTRAINEMENT / INFERENCE / GATE
-----------------------------------------
fit_vocab et fit_scaler sont ajustes sur le TRAIN seul ; _token_ids et
_scaled_matrix rejouent EXACTEMENT la meme transformation en inference et dans
le gate. Un token inconnu -> UNK_ID (doctrine "inconnu = nouveau"), une valeur
hors echelle -> clip a +/- SCALE_CLIP. C'est ce qui permet a scoring.py de
faire tourner candidat et courant sur des donnees figees sans aucune divergence
de semantique.
"""
from __future__ import annotations
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

import config_cnn as CC
import cnn_features as FE


# --- 1. vocabulaire de tokens (event_type) ----------------------------------
def fit_vocab(d_train_src):
    """Mappe chaque event_type vu au TRAIN vers un id >= FIRST_TOKEN_ID.
    Reserve PAD/MASK/UNK. Les tokens inconnus en test -> UNK_ID (comportement
    coherent avec la doctrine 'inconnu = nouveau')."""
    toks = (d_train_src[CC.TOKEN_FIELD].fillna("other").astype(str)
            .value_counts().index.tolist())
    vocab = {t: i + CC.FIRST_TOKEN_ID for i, t in enumerate(toks)}
    return vocab


def _token_ids(d_src, vocab):
    t = d_src[CC.TOKEN_FIELD].fillna("other").astype(str)
    return t.map(lambda x: vocab.get(x, CC.UNK_ID)).to_numpy(dtype=np.int64)


# --- 2. scaler scalaire (fit TRAIN seul) ------------------------------------
def fit_scaler(d_train_src, feats):
    X = np.nan_to_num(FE.raw_matrix(d_train_src, feats))
    return StandardScaler().fit(X)


def _scaled_matrix(d_src, feats, scaler):
    X = np.nan_to_num(FE.raw_matrix(d_src, feats))
    return np.clip(scaler.transform(X), -CC.SCALE_CLIP, CC.SCALE_CLIP).astype(np.float32)


# --- 3. cle de fenetrage ----------------------------------------------------
def _window_key(d_src, src):
    host = d_src.get("host_name", pd.Series("", index=d_src.index)).fillna("").astype(str)
    if CC.WINDOW_KEY.get(src) == "ip":
        ip = d_src.get("source_ip", pd.Series("", index=d_src.index)).fillna("").astype(str)
        proc = d_src.get("process_name", pd.Series("", index=d_src.index)).fillna("").astype(str)
        ok = ~ip.isin(["", "nan", "None"])
        return np.where(ok, "ip_" + ip, "host_" + host + "_" + proc)
    return ("host_" + host.replace("", "unknown")).to_numpy()


# --- 4. fenetres glissantes causales ----------------------------------------
def _slide_float(Xk, W):
    """[n, F] -> [n, F, W], fenetre i = [i-W+1 .. i], pad 0 a gauche."""
    n, F = Xk.shape
    if n == 0:
        return np.zeros((0, F, W), np.float32)
    Xp = np.vstack([np.zeros((W - 1, F), Xk.dtype), Xk])
    idx = np.arange(W)[None, :] + np.arange(n)[:, None]
    return Xp[idx].transpose(0, 2, 1).astype(np.float32)


def _slide_ids(ids_k, W):
    """[n] -> [n, W], pad PAD_ID a gauche."""
    n = len(ids_k)
    if n == 0:
        return np.zeros((0, W), np.int64)
    idp = np.concatenate([np.full(W - 1, CC.PAD_ID, np.int64), ids_k])
    idx = np.arange(W)[None, :] + np.arange(n)[:, None]
    return idp[idx].astype(np.int64)


def build_windows(d_src, feats, scaler, vocab, src, W=None):
    """Retourne (Xs [N,Fs,W], Xt [N,W], d_sorted). d_sorted est le sous-df
    reordonne par (cle, temps), aligne ligne-a-ligne sur Xs/Xt."""
    W = W or CC.WINDOW_SIZE
    d = d_src.copy()
    d["_key"] = _window_key(d, src)
    d["_ts"] = pd.to_datetime(d["@timestamp"], utc=True, errors="coerce")
    d = d.sort_values(["_key", "_ts"], kind="stable").reset_index(drop=True)

    Xmat = _scaled_matrix(d, feats, scaler)          # [N, Fs]
    ids  = _token_ids(d, vocab)                      # [N]
    keys = d["_key"].to_numpy()

    Xs = np.zeros((len(d), Xmat.shape[1], W), np.float32)
    Xt = np.zeros((len(d), W), np.int64)
    start = 0
    for k in range(1, len(keys) + 1):
        if k == len(keys) or keys[k] != keys[start]:
            Xs[start:k] = _slide_float(Xmat[start:k], W)
            Xt[start:k] = _slide_ids(ids[start:k], W)
            start = k
    d = d.drop(columns=["_key", "_ts"])
    return Xs, Xt, d