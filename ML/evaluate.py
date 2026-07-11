"""
evaluation.py
=============
Evaluation A POSTERIORI du pipeline Sentinel (AE per-source, NON SUPERVISE).

Repond a la question : "le modele distingue-t-il les logs normaux des logs
anormaux et detecte-t-il correctement les attaques ?"

--------------------------------------------------------------------------
CHOIX METHODOLOGIQUE (justifie par l'architecture, pas un defaut generique)
--------------------------------------------------------------------------
1. L'AE ne fait QUE de la rarete statistique. La discrimination
   rare-benin / rare-malveillant appartient au layer Sigma/LLM en aval.
   => Un "faux positif" AE n'est PAS forcement une erreur : c'est un evenement
      rare legitime, route vers le triage. On rapporte donc la precision brute
      HONNETEMENT, mais la mesure JUSTE du travail de l'AE est le couple
      (recall sur attaques injectees + qualite de SEPARATION du score).

2. La verite terrain est definie par des FENETRES D'INJECTION (protocole
   red-team), jamais par un etiquetage ligne-a-ligne. Un evenement/episode est
   "attaque" s'il tombe dans une fenetre d'injection (hote + source apparies,
   +/- tolerance). C'est non circulaire : les fenetres viennent de signatures
   OBSERVABLES sur champs bruts, pas du score.

3. DEUX granularites :
   - EVENEMENT (ligne) : qualite de RANKING sans seuil via ROC-AUC et surtout
     PR-AUC (les attaques sont <1% -> forte imbalance -> ROC-AUC optimiste,
     PR-AUC prioritaire). + point de fonctionnement (Precision/Recall/F1/
     matrice de confusion) au seuil GPD-POT calibre.
   - EPISODE (sortie analyste reelle) : recall de detection PAR FENETRE
     (chaque attaque a-t-elle produit >= 1 episode ?) + precision episode.
     C'est la metrique operationnelle.

4. Scores comparables entre sources : par-source on utilise le score brut
   (echelles differentes : auth~3.6, syslog~10.4, auditd~5.7). Pour la vue
   GLOBALE on normalise par confidence = score / seuil (1.0 = pile au seuil).

5. Diagnostic specifique : INVERSION DE SCORE par saturation (FEATURE_Z_CAP).
   Des evenements benins (installs de paquets : dracut/hplip/dpkg) saturent a
   ~46 et surclassent l'attaque base64 reelle (~18-31). On quantifie
   explicitement cet effet (AUC episode + fraction de benins au-dessus des
   attaques), car il explique un eventuel PR-AUC mediocre malgre un bon recall.

--------------------------------------------------------------------------
INTEGRATION
--------------------------------------------------------------------------
Reutilise SANS modification : data_loader, feature_engineering, splitting,
inference (load_artifacts / score_features / aggregate_alerts), config.
Aucune metrique supervisee n'est injectee dans l'entrainement ou la calibration.

Usage :
    python evaluation.py                          # re-score le TEST + evalue
    python evaluation.py --groundtruth gt.jsonl   # verite terrain autoritative
    python evaluation.py --from-csv scored.csv    # evalue un CSV deja score
    python evaluation.py --tolerance 120 --results-dir results
"""
from __future__ import annotations

import os
import re
import json
import argparse

import numpy as np
import pandas as pd

import matplotlib
matplotlib.use("Agg")                                   # rendu fichier, sans display
import matplotlib.pyplot as plt

from sklearn.metrics import (
    roc_curve, precision_recall_curve, roc_auc_score,
    average_precision_score, confusion_matrix,
    precision_recall_fscore_support,
)

import config as C


# ===========================================================================
# 0. Petits utilitaires
# ===========================================================================
def _norm_host(h) -> str:
    """Normalise la casse d'hote : auth/syslog='ASUS-X415JA', auditd='asus-x415ja'
    referencent le MEME hote. Sans ca l'appariement de fenetres echoue."""
    return str(h).strip().casefold()


def _to_utc(series) -> pd.Series:
    return pd.to_datetime(series, utc=True, errors="coerce")


def _ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def _cluster_times(ts_sorted: np.ndarray, gap_s: int):
    """Regroupe des timestamps tries en fenetres : nouvelle fenetre des que
    l'ecart au precedent depasse gap_s. Retourne [(start, end), ...]."""
    if len(ts_sorted) == 0:
        return []
    gap = np.timedelta64(int(gap_s), "s")
    windows = []
    start = prev = ts_sorted[0]
    for t in ts_sorted[1:]:
        if t - prev > gap:
            windows.append((start, prev))
            start = t
        prev = t
    windows.append((start, prev))
    return windows


# ===========================================================================
# 1. Verite terrain (fenetres d'injection)
# ===========================================================================
_GT_START_KEYS = ("start", "window_start", "t_start", "begin", "@timestamp")
_GT_END_KEYS   = ("end", "window_end", "t_end", "finish", "stop")
_GT_SRC_KEYS   = ("source", "log_source", "src")
_GT_HOST_KEYS  = ("host", "host_name", "hostname")
_GT_LABEL_KEYS = ("technique", "attack_type", "label", "name", "mitre", "scenario")


def _first_key(d: dict, keys):
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None


def load_groundtruth_windows(path: str):
    """Charge des fenetres d'injection depuis un JSONL a schema FLEXIBLE.
    Champs acceptes : start/end (ou window_start/window_end...), source (opt.),
    host (opt.), technique/label (opt.). Une entree sans 'end' mais avec
    'duration_s' est acceptee (end = start + duration)."""
    windows = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            start = _first_key(d, _GT_START_KEYS)
            end = _first_key(d, _GT_END_KEYS)
            if start is None:
                continue
            start = pd.Timestamp(start, tz="UTC") if pd.Timestamp(start).tzinfo is None \
                else pd.Timestamp(start).tz_convert("UTC")
            if end is None:
                dur = d.get("duration_s")
                end = start + pd.Timedelta(seconds=float(dur)) if dur else start
            else:
                end = pd.Timestamp(end, tz="UTC") if pd.Timestamp(end).tzinfo is None \
                    else pd.Timestamp(end).tz_convert("UTC")
            src = _first_key(d, _GT_SRC_KEYS)
            host = _first_key(d, _GT_HOST_KEYS)
            label = _first_key(d, _GT_LABEL_KEYS) or "attack"
            windows.append({
                "start": start, "end": end,
                "source": str(src) if src else None,
                "host": _norm_host(host) if host else None,
                "label": str(label),
            })
    return windows


# Signatures OBSERVABLES du protocole red-team (champs BRUTS, non circulaire).
_SIG_USER_BRUTE = re.compile(r"^invaliduser\d+$", re.IGNORECASE)   # T1110.001
_SIG_USER_CREATE = {"testintrus"}                                  # T1136.001
_SIG_EXEC_PROC = {"base64", "echo", "python3"}                     # T1059.004 (contexte)


def derive_groundtruth_windows(df, gap_s=None):
    """FALLBACK non circulaire : reconstruit les fenetres de campagne a partir
    de signatures d'injection sur champs BRUTS (user_name / process_name),
    JAMAIS a partir du score. Utilise si aucun groundtruth.jsonl fourni.

    On agrege toutes les signatures (brute-force + creation user + exec) par
    TEMPS (source=None) : une campagne multi-stage (sshd -> useradd -> base64)
    devient UNE fenetre couvrant auth ET auditd, ce qui est correct."""
    gap = gap_s or C.EPISODE_GAP_SECONDS
    user = df.get("user_name", pd.Series("", index=df.index)).fillna("").astype(str)
    proc = df.get("process_name", pd.Series("", index=df.index)).fillna("").astype(str).str.lower()
    is_root = df.get("user_name", pd.Series("", index=df.index)).fillna("").astype(str).str.lower().eq("root")

    m_brute = user.map(lambda u: bool(_SIG_USER_BRUTE.match(u)))
    m_create = user.str.lower().isin(_SIG_USER_CREATE)
    m_exec = proc.isin(_SIG_EXEC_PROC) & is_root
    sig = m_brute | m_create | m_exec
    if not sig.any():
        return [], {"n_sig_events": 0}

    ts = _to_utc(df["@timestamp"])
    host_mode = _norm_host(df.get("host_name", pd.Series([""])).mode().iloc[0]) \
        if "host_name" in df.columns and len(df) else None

    sig_ts = np.sort(ts[sig].dropna().values)
    spans = _cluster_times(sig_ts, gap)

    windows = []
    for (a, b) in spans:
        w_mask = sig & (ts >= a) & (ts <= b)
        labels = []
        if m_brute[w_mask].any():
            labels.append("T1110.001_ssh_bruteforce")
        if m_create[w_mask].any():
            labels.append("T1136.001_user_creation")
        if m_exec[w_mask].any():
            labels.append("T1059.004_exec")
        windows.append({
            "start": pd.Timestamp(a), "end": pd.Timestamp(b),
            "source": None, "host": host_mode,
            "label": "+".join(labels) if labels else "attack",
        })
    return windows, {"n_sig_events": int(sig.sum()), "n_windows": len(windows)}


# ===========================================================================
# 2. Etiquetage evenement / episode par recouvrement de fenetres
# ===========================================================================
def label_events(df, windows, tol_s):
    """y=1 si l'evenement tombe dans une fenetre (+/- tolerance), source/hote
    apparies si la fenetre les specifie."""
    if len(df) == 0 or not windows:
        return np.zeros(len(df), dtype=int)
    ts = _to_utc(df["@timestamp"]).values
    src = df.get("log_source", pd.Series("", index=df.index)).astype(str).values
    host = df.get("host_name", pd.Series("", index=df.index)).map(_norm_host).values
    tol = np.timedelta64(int(tol_s), "s")
    y = np.zeros(len(df), dtype=int)
    for w in windows:
        m = (ts >= np.datetime64(w["start"]) - tol) & (ts <= np.datetime64(w["end"]) + tol)
        if w.get("source"):
            m &= (src == w["source"])
        if w.get("host"):
            m &= (host == w["host"])
        y[m] = 1
    return y


def _episode_overlaps(ep_start, ep_end, ep_src, ep_host, windows, tol):
    """True si l'episode recouvre une fenetre (avec tolerance)."""
    for w in windows:
        if w.get("source") and ep_src != w["source"]:
            continue
        if w.get("host") and ep_host != w["host"]:
            continue
        if (ep_start <= np.datetime64(w["end"]) + tol) and \
           (ep_end >= np.datetime64(w["start"]) - tol):
            return True
    return False


def label_episodes(episodes, windows, tol_s):
    """Marque chaque episode attaque/benin par recouvrement de fenetre."""
    if len(episodes) == 0:
        episodes = episodes.copy()
        episodes["is_attack"] = pd.Series(dtype=int)
        return episodes
    tol = np.timedelta64(int(tol_s), "s")
    st = _to_utc(episodes["start"]).values
    en = _to_utc(episodes["end"]).values
    src = episodes["log_source"].astype(str).values
    host = episodes["host_name"].map(_norm_host).values
    flags = [
        int(_episode_overlaps(st[i], en[i], src[i], host[i], windows, tol))
        for i in range(len(episodes))
    ]
    episodes = episodes.copy()
    episodes["is_attack"] = flags
    return episodes


def window_detection_table(episodes, windows, tol_s):
    """Pour CHAQUE fenetre : est-elle detectee (>=1 episode recouvrant) ?
    C'est le recall de detection d'attaque au niveau operationnel."""
    tol = np.timedelta64(int(tol_s), "s")
    if len(episodes):
        st = _to_utc(episodes["start"]).values
        en = _to_utc(episodes["end"]).values
        src = episodes["log_source"].astype(str).values
        host = episodes["host_name"].map(_norm_host).values
    rows = []
    for wi, w in enumerate(windows):
        n_ep = 0
        if len(episodes):
            for i in range(len(episodes)):
                if w.get("source") and src[i] != w["source"]:
                    continue
                if w.get("host") and host[i] != w["host"]:
                    continue
                if (st[i] <= np.datetime64(w["end"]) + tol) and \
                   (en[i] >= np.datetime64(w["start"]) - tol):
                    n_ep += 1
        rows.append({
            "window_id": wi,
            "label": w["label"],
            "source": w.get("source") or "any",
            "start": str(w["start"]), "end": str(w["end"]),
            "n_episodes": n_ep,
            "detected": int(n_ep > 0),
        })
    return pd.DataFrame(rows)


# ===========================================================================
# 3. Obtention du TEST score (re-scoring ou CSV)
# ===========================================================================
def get_scored_test_set(from_csv=None):
    """Renvoie le split TEST integralement score (TOUS les evenements, pas
    seulement les alertes) : @timestamp, log_source, host_name, user_name,
    process_name, mse (=score anomalie), threshold, is_alert, confidence.

    Reutilise inference.score_features (aucune duplication de logique)."""
    if from_csv and os.path.exists(from_csv):
        df = pd.read_csv(from_csv)
        need = {"@timestamp", "log_source", "host_name", "mse", "threshold", "is_alert"}
        missing = need - set(df.columns)
        if missing:
            raise ValueError(f"CSV incomplet, colonnes manquantes : {missing}")
        if "confidence" not in df.columns:
            df["confidence"] = (df["mse"] / df["threshold"]).clip(lower=0)
        print(f"  [SCORE] chargement CSV pre-score : {len(df):,} evenements")
        return df

    # Re-scoring depuis les artifacts geles (meme chemin qu'inference.main).
    import data_loader as DL
    import feature_engineering as FE
    from splitting import temporal_split
    import inference as INF

    print("  [SCORE] rechargement des artifacts + features...")
    model, scalers, keep, feats, _, thresholds, novelty = INF.load_artifacts()
    df_raw = DL.load_dataset()
    df_feat = FE.build_features(df_raw, novelty_state=None)
    _, _, df_test = temporal_split(df_feat)
    print(f"  [SCORE] snapshot={len(df_feat):,} -> TEST={len(df_test):,}")

    scored = INF.score_features(model, df_test, feats, scalers, keep, thresholds)
    if "confidence" not in scored.columns:
        scored["confidence"] = (scored["mse"] / scored["threshold"]).clip(lower=0)
    return scored


def build_episodes(scored):
    """Reproduit le filtrage analyste d'inference.main puis aggregate_alerts :
    episodes = alertes PRIMAIRES (is_alert=1, role='alert')."""
    import inference as INF
    s = scored.copy()
    if "role" not in s.columns:
        s["role"] = s["log_source"].map(C.SOURCE_ROLE).fillna("alert")
    fired = s[s["is_alert"] == 1]
    primary = fired[fired["role"] == "alert"].copy()
    return INF.aggregate_alerts(primary)


# ===========================================================================
# 4. Metriques
# ===========================================================================
def _safe_auc(y, score, kind):
    """ROC/PR-AUC robuste a une classe unique."""
    y = np.asarray(y)
    if y.sum() == 0 or y.sum() == len(y):
        return None
    if kind == "roc":
        return float(roc_auc_score(y, score))
    return float(average_precision_score(y, score))


def _point_metrics(y_true, y_pred):
    p, r, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0, labels=[0, 1])
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    return {
        "precision": round(float(p), 4), "recall": round(float(r), 4),
        "f1": round(float(f1), 4),
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
    }


def event_level_metrics(scored, y_true):
    """Metriques evenement PAR SOURCE (score brut) + GLOBAL (score=confidence)."""
    out = {"per_source": {}, "global": {}}
    scored = scored.reset_index(drop=True)
    y_true = np.asarray(y_true)

    for s in C.SOURCES:
        m = (scored["log_source"] == s).values
        if m.sum() == 0:
            continue
        yt = y_true[m]
        sc = scored.loc[m, "mse"].values
        yp = scored.loc[m, "is_alert"].astype(int).values
        d = _point_metrics(yt, yp)
        d.update({
            "n": int(m.sum()), "n_attack": int(yt.sum()),
            "roc_auc": _safe_auc(yt, sc, "roc"),
            "pr_auc": _safe_auc(yt, sc, "pr"),
        })
        out["per_source"][s] = d

    # Global : score normalise (mse/seuil) pour comparabilite inter-sources.
    conf = scored["confidence"].values if "confidence" in scored.columns \
        else (scored["mse"] / scored["threshold"]).values
    dg = _point_metrics(y_true, scored["is_alert"].astype(int).values)
    dg.update({
        "n": int(len(scored)), "n_attack": int(y_true.sum()),
        "roc_auc": _safe_auc(y_true, conf, "roc"),
        "pr_auc": _safe_auc(y_true, conf, "pr"),
    })
    out["global"] = dg
    return out


def episode_level_metrics(episodes_lab, windows, tol_s):
    """Metriques episode : precision, recall de detection PAR FENETRE, et
    separation episode (AUC sur mse_max)."""
    wtab = window_detection_table(episodes_lab, windows, tol_s)
    n_win = len(wtab)
    n_det = int(wtab["detected"].sum()) if n_win else 0

    n_ep = len(episodes_lab)
    n_att_ep = int(episodes_lab["is_attack"].sum()) if n_ep else 0
    ep_precision = round(n_att_ep / n_ep, 4) if n_ep else None

    ep_roc = ep_pr = None
    if n_ep and "mse_max" in episodes_lab.columns:
        ep_roc = _safe_auc(episodes_lab["is_attack"].values,
                           episodes_lab["mse_max"].values, "roc")
        ep_pr = _safe_auc(episodes_lab["is_attack"].values,
                          episodes_lab["mse_max"].values, "pr")

    return {
        "n_episodes": int(n_ep),
        "n_attack_episodes": n_att_ep,
        "episode_precision": ep_precision,
        "n_windows": n_win,
        "n_windows_detected": n_det,
        "window_detection_recall": round(n_det / n_win, 4) if n_win else None,
        "episode_roc_auc": ep_roc,
        "episode_pr_auc": ep_pr,
    }, wtab


def score_inversion_diagnostic(episodes_lab):
    """Quantifie l'inversion de score par saturation (FEATURE_Z_CAP).
    - rank moyen des episodes attaque parmi tous (1 = plus haut score) ;
    - fraction de benins qui surclassent l'attaque mediane ;
    - saturation : fraction d'episodes au plafond (mse_max >= cap*top-k proxy)."""
    if len(episodes_lab) == 0 or "mse_max" not in episodes_lab.columns:
        return {}
    e = episodes_lab.copy()
    e = e.sort_values("mse_max", ascending=False).reset_index(drop=True)
    e["rank"] = np.arange(1, len(e) + 1)
    att = e[e["is_attack"] == 1]
    ben = e[e["is_attack"] == 0]
    diag = {
        "n_episodes": int(len(e)),
        "score_max_observed": round(float(e["mse_max"].max()), 3),
        "score_ceiling_hint": round(float(getattr(C, "FEATURE_Z_CAP", 50.0)), 1),
    }
    if len(att):
        med_att = float(att["mse_max"].median())
        diag.update({
            "attack_mean_rank": round(float(att["rank"].mean()), 1),
            "attack_top_rank": int(att["rank"].min()),
            "attack_worst_rank": int(att["rank"].max()),
            "attack_score_median": round(med_att, 3),
            "benign_above_attack_median": int((ben["mse_max"] >= med_att).sum()),
            "benign_above_attack_median_frac": round(
                float((ben["mse_max"] >= med_att).mean()), 4) if len(ben) else None,
        })
    return diag


# ===========================================================================
# 5. Figures
# ===========================================================================
def _save(fig, path):
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)


def plot_roc(scored, y_true, results_dir):
    y_true = np.asarray(y_true)
    fig, ax = plt.subplots(figsize=(6.5, 5.5))
    ax.plot([0, 1], [0, 1], "--", color="grey", lw=1, label="hasard")
    for s in C.SOURCES:
        m = (scored["log_source"] == s).values
        yt = y_true[m]
        if m.sum() == 0 or yt.sum() == 0 or yt.sum() == len(yt):
            continue
        fpr, tpr, _ = roc_curve(yt, scored.loc[m, "mse"].values)
        auc = roc_auc_score(yt, scored.loc[m, "mse"].values)
        ax.plot(fpr, tpr, lw=2, label=f"{s} (AUC={auc:.3f})")
    conf = scored["confidence"].values
    if 0 < y_true.sum() < len(y_true):
        fpr, tpr, _ = roc_curve(y_true, conf)
        ax.plot(fpr, tpr, lw=2.5, color="black",
                label=f"global (AUC={roc_auc_score(y_true, conf):.3f})")
    ax.set_xlabel("Taux de faux positifs"); ax.set_ylabel("Taux de vrais positifs")
    ax.set_title("Courbe ROC (score brut par source, confidence en global)")
    ax.legend(loc="lower right", fontsize=8); ax.grid(alpha=.3)
    _save(fig, os.path.join(results_dir, "roc_curve.png"))


def plot_pr(scored, y_true, results_dir):
    y_true = np.asarray(y_true)
    fig, ax = plt.subplots(figsize=(6.5, 5.5))
    base = y_true.mean()
    ax.axhline(base, ls="--", color="grey", lw=1, label=f"base ({base:.3f})")
    for s in C.SOURCES:
        m = (scored["log_source"] == s).values
        yt = y_true[m]
        if m.sum() == 0 or yt.sum() == 0:
            continue
        prec, rec, _ = precision_recall_curve(yt, scored.loc[m, "mse"].values)
        ap = average_precision_score(yt, scored.loc[m, "mse"].values)
        ax.plot(rec, prec, lw=2, label=f"{s} (PR-AUC={ap:.3f})")
    conf = scored["confidence"].values
    if y_true.sum() > 0:
        prec, rec, _ = precision_recall_curve(y_true, conf)
        ax.plot(rec, prec, lw=2.5, color="black",
                label=f"global (PR-AUC={average_precision_score(y_true, conf):.3f})")
    ax.set_xlabel("Recall"); ax.set_ylabel("Precision")
    ax.set_title("Courbe Precision-Recall (prioritaire : classe desequilibree)")
    ax.legend(loc="upper right", fontsize=8); ax.grid(alpha=.3)
    _save(fig, os.path.join(results_dir, "pr_curve.png"))


def plot_confusion(scored, y_true, results_dir):
    y_true = np.asarray(y_true)
    srcs = [s for s in C.SOURCES if (scored["log_source"] == s).any()]
    fig, axes = plt.subplots(1, len(srcs) + 1, figsize=(4 * (len(srcs) + 1), 3.6))
    if len(srcs) + 1 == 1:
        axes = [axes]
    panels = [("GLOBAL", np.ones(len(scored), dtype=bool))] + \
             [(s, (scored["log_source"] == s).values) for s in srcs]
    for ax, (title, m) in zip(axes, panels):
        cm = confusion_matrix(y_true[m], scored.loc[m, "is_alert"].astype(int).values,
                              labels=[0, 1])
        ax.imshow(cm, cmap="Blues")
        for (i, j), v in np.ndenumerate(cm):
            ax.text(j, i, f"{v:,}", ha="center", va="center",
                    color="white" if v > cm.max() / 2 else "black", fontsize=10)
        ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
        ax.set_xticklabels(["normal", "alerte"]); ax.set_yticklabels(["normal", "attaque"])
        ax.set_xlabel("predit"); ax.set_ylabel("reel"); ax.set_title(title, fontsize=10)
    fig.suptitle("Matrices de confusion (seuil GPD-POT)", y=1.03)
    _save(fig, os.path.join(results_dir, "confusion_matrix.png"))


def plot_score_distributions(scored, y_true, results_dir):
    """Distributions score attaque vs benin par source + ligne de seuil.
    Rend visible l'inversion/saturation."""
    y_true = np.asarray(y_true)
    srcs = [s for s in C.SOURCES if (scored["log_source"] == s).any()]
    fig, axes = plt.subplots(1, len(srcs), figsize=(5 * len(srcs), 4), squeeze=False)
    for ax, s in zip(axes[0], srcs):
        m = (scored["log_source"] == s).values
        sc = scored.loc[m, "mse"].values
        yt = y_true[m]
        thr = float(scored.loc[m, "threshold"].iloc[0])
        bins = np.linspace(0, max(sc.max(), thr) * 1.02, 40)
        ax.hist(sc[yt == 0], bins=bins, alpha=.6, label="normal", color="#4c72b0")
        if yt.sum():
            ax.hist(sc[yt == 1], bins=bins, alpha=.7, label="attaque", color="#c44e52")
        ax.axvline(thr, color="black", ls="--", lw=1.5, label=f"seuil={thr:.2f}")
        ax.set_yscale("log"); ax.set_title(s); ax.set_xlabel("score anomalie")
        ax.set_ylabel("comptes (log)"); ax.legend(fontsize=8)
    fig.suptitle("Distribution du score : normal vs attaque", y=1.03)
    _save(fig, os.path.join(results_dir, "score_distributions.png"))


def plot_window_detection(wtab, results_dir):
    if len(wtab) == 0:
        return
    fig, ax = plt.subplots(figsize=(8, max(2.5, 0.5 * len(wtab))))
    colors = ["#55a868" if d else "#c44e52" for d in wtab["detected"]]
    y = np.arange(len(wtab))
    ax.barh(y, wtab["n_episodes"].clip(lower=0.3), color=colors)
    ax.set_yticks(y)
    ax.set_yticklabels([f"[{r.source}] {r.label[:34]}" for r in wtab.itertuples()],
                       fontsize=8)
    for i, r in enumerate(wtab.itertuples()):
        ax.text(max(r.n_episodes, 0.3) + 0.05, i,
                "detectee" if r.detected else "MANQUEE", va="center", fontsize=8,
                color="#55a868" if r.detected else "#c44e52")
    ax.set_xlabel("nb d'episodes recouvrant la fenetre")
    ax.set_title("Detection par fenetre d'injection (recall operationnel)")
    ax.invert_yaxis()
    _save(fig, os.path.join(results_dir, "window_detection.png"))


def plot_score_inversion(episodes_lab, results_dir):
    """Episodes ranges par mse_max ; attaques en rouge. Si des benins saturent
    au-dessus des attaques -> inversion visible."""
    if len(episodes_lab) == 0 or "mse_max" not in episodes_lab.columns:
        return
    e = episodes_lab.sort_values("mse_max", ascending=False).reset_index(drop=True)
    fig, ax = plt.subplots(figsize=(9, 4.2))
    x = np.arange(len(e))
    ben = e["is_attack"] == 0
    att = e["is_attack"] == 1
    ax.scatter(x[ben.values], e.loc[ben, "mse_max"], s=14, color="#bbbbbb",
               label="benin (rare-benin -> Sigma)")
    if att.any():
        ax.scatter(x[att.values], e.loc[att, "mse_max"], s=42, color="#c44e52",
                   edgecolor="black", zorder=3, label="attaque injectee")
    cap = float(getattr(C, "FEATURE_Z_CAP", 50.0))
    ax.axhline(cap, color="orange", ls=":", lw=1.5, label=f"plafond z={cap:.0f}")
    ax.set_xlabel("rang de l'episode (score decroissant)")
    ax.set_ylabel("mse_max de l'episode")
    ax.set_title("Diagnostic d'inversion de score (saturation)")
    ax.legend(fontsize=8); ax.grid(alpha=.3)
    _save(fig, os.path.join(results_dir, "score_inversion.png"))


def plot_confidence_breakdown(scored, y_true, results_dir):
    if "confidence_level" not in scored.columns:
        return
    y_true = np.asarray(y_true)
    order = ["low", "medium", "high"]
    fig, ax = plt.subplots(figsize=(6, 4))
    lv = scored["confidence_level"].astype(str)
    width = 0.38
    xs = np.arange(len(order))
    ben = [int(((lv == o) & (y_true == 0)).sum()) for o in order]
    att = [int(((lv == o) & (y_true == 1)).sum()) for o in order]
    ax.bar(xs - width / 2, ben, width, label="normal", color="#4c72b0")
    ax.bar(xs + width / 2, att, width, label="attaque", color="#c44e52")
    ax.set_yscale("symlog"); ax.set_xticks(xs); ax.set_xticklabels(order)
    ax.set_ylabel("comptes (symlog)")
    ax.set_title("Repartition par niveau de confiance")
    ax.legend()
    _save(fig, os.path.join(results_dir, "confidence_breakdown.png"))


# ===========================================================================
# 6. Orchestration
# ===========================================================================
def evaluate(from_csv=None, groundtruth=None, tolerance_s=120,
             results_dir="results"):
    """Point d'entree reutilisable. Retourne le dict de metriques."""
    results_dir = _ensure_dir(results_dir)
    print("=" * 64)
    print("  EVALUATION SENTINEL (fenetres d'injection, episode-first)")
    print("=" * 64)

    # (1) Test score
    print("\n[1] Obtention du TEST score...")
    scored = get_scored_test_set(from_csv=from_csv)
    if "confidence_level" not in scored.columns and "confidence" in scored.columns:
        scored["confidence_level"] = pd.cut(
            scored["confidence"], bins=[0, 1.5, 3.0, np.inf],
            labels=["low", "medium", "high"]).astype(str)

    # (2) Verite terrain
    print("\n[2] Verite terrain (fenetres d'injection)...")
    gt_source = None
    if groundtruth and os.path.exists(groundtruth):
        windows = load_groundtruth_windows(groundtruth)
        gt_source = f"file:{groundtruth}"
        print(f"  {len(windows)} fenetres chargees depuis {groundtruth}")
    else:
        windows, info = derive_groundtruth_windows(scored)
        gt_source = "derived_from_signatures"
        print(f"  [FALLBACK] {info.get('n_windows', 0)} fenetres derivees de "
              f"{info.get('n_sig_events', 0)} evenements-signature "
              f"(fournir groundtruth.jsonl pour la version autoritative)")
    for w in windows:
        print(f"    - [{w.get('source') or 'any'}] {w['label']:36s} "
              f"{w['start']} -> {w['end']}")

    # (3) Etiquetage
    print("\n[3] Etiquetage (+/- {}s de tolerance)...".format(tolerance_s))
    y_true = label_events(scored, windows, tolerance_s)
    scored = scored.reset_index(drop=True)
    scored["y_true"] = y_true
    print(f"  evenements test = {len(scored):,} | attaques = {int(y_true.sum()):,} "
          f"({100 * y_true.mean():.3f}%)")

    # (4) Episodes
    print("\n[4] Episodes (sortie analyste)...")
    episodes = build_episodes(scored) if not from_csv else \
        (build_episodes(scored) if "role" in scored or True else pd.DataFrame())
    episodes_lab = label_episodes(episodes, windows, tolerance_s)
    print(f"  episodes = {len(episodes_lab):,} | "
          f"attaque = {int(episodes_lab['is_attack'].sum()) if len(episodes_lab) else 0}")

    has_labels = int(y_true.sum()) > 0

    # (5) Metriques
    print("\n[5] Metriques...")
    ev = event_level_metrics(scored, y_true) if has_labels else None
    ep, wtab = episode_level_metrics(episodes_lab, windows, tolerance_s)
    inv = score_inversion_diagnostic(episodes_lab)

    metrics = {
        "config": {
            "groundtruth_source": gt_source,
            "tolerance_s": tolerance_s,
            "n_windows": len(windows),
            "n_test_events": int(len(scored)),
            "n_attack_events": int(y_true.sum()),
            "attack_prevalence": round(float(y_true.mean()), 6),
            "has_labels": has_labels,
        },
        "event_level": ev,
        "episode_level": ep,
        "score_inversion": inv,
    }

    # (6) Figures
    print("\n[6] Figures -> {}/ ...".format(results_dir))
    if has_labels:
        plot_roc(scored, y_true, results_dir)
        plot_pr(scored, y_true, results_dir)
        plot_confusion(scored, y_true, results_dir)
        plot_score_distributions(scored, y_true, results_dir)
        plot_confidence_breakdown(scored, y_true, results_dir)
    plot_window_detection(wtab, results_dir)
    plot_score_inversion(episodes_lab, results_dir)

    # (7) Sauvegardes
    with open(os.path.join(results_dir, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2, default=str)
    scored.to_csv(os.path.join(results_dir, "scored_test_set.csv"), index=False)
    if len(episodes_lab):
        episodes_lab.to_csv(os.path.join(results_dir, "episodes_labeled.csv"),
                            index=False)
    if len(wtab):
        wtab.to_csv(os.path.join(results_dir, "window_detection.csv"), index=False)
    if ev:
        pd.DataFrame(ev["per_source"]).T.to_csv(
            os.path.join(results_dir, "event_metrics_per_source.csv"))

    _write_summary(metrics, results_dir)
    _print_summary(metrics)
    print(f"\n  Tout est ecrit dans '{results_dir}/'.")
    print("=" * 64)
    return metrics


def _write_summary(metrics, results_dir):
    lines = ["RESUME EVALUATION SENTINEL", "=" * 40]
    c = metrics["config"]
    lines += [
        f"Verite terrain    : {c['groundtruth_source']}",
        f"Tolerance         : {c['tolerance_s']} s",
        f"Fenetres injectees: {c['n_windows']}",
        f"Evenements test   : {c['n_test_events']:,}",
        f"Attaques (events) : {c['n_attack_events']:,} "
        f"({100 * c['attack_prevalence']:.3f}%)",
        "",
    ]
    ep = metrics["episode_level"]
    lines += ["-- NIVEAU EPISODE (operationnel) --",
              f"Recall detection par fenetre : {ep['window_detection_recall']} "
              f"({ep['n_windows_detected']}/{ep['n_windows']})",
              f"Precision episode            : {ep['episode_precision']} "
              f"({ep['n_attack_episodes']}/{ep['n_episodes']})",
              f"AUC episode (mse_max)        : ROC={ep['episode_roc_auc']} "
              f"PR={ep['episode_pr_auc']}", ""]
    if metrics["event_level"]:
        g = metrics["event_level"]["global"]
        lines += ["-- NIVEAU EVENEMENT (global) --",
                  f"Precision={g['precision']} Recall={g['recall']} F1={g['f1']}",
                  f"ROC-AUC={g['roc_auc']} PR-AUC={g['pr_auc']}",
                  f"TP={g['tp']} FP={g['fp']} TN={g['tn']} FN={g['fn']}", ""]
        lines += ["-- PAR SOURCE (PR-AUC prioritaire) --"]
        for s, d in metrics["event_level"]["per_source"].items():
            lines.append(f"{s:8s}: PR-AUC={d['pr_auc']} ROC-AUC={d['roc_auc']} "
                         f"P={d['precision']} R={d['recall']} F1={d['f1']} "
                         f"(n_att={d['n_attack']})")
        lines.append("")
    inv = metrics.get("score_inversion") or {}
    if inv:
        lines += ["-- INVERSION DE SCORE (saturation) --",
                  f"rang moyen des attaques : {inv.get('attack_mean_rank')} "
                  f"/ {inv.get('n_episodes')}",
                  f"benins au-dessus de l'attaque mediane : "
                  f"{inv.get('benign_above_attack_median')} "
                  f"({inv.get('benign_above_attack_median_frac')})"]
    with open(os.path.join(results_dir, "SUMMARY.txt"), "w") as f:
        f.write("\n".join(lines))


def _print_summary(metrics):
    ep = metrics["episode_level"]
    print("\n  --- SYNTHESE ---")
    print(f"  Recall detection/fenetre : {ep['window_detection_recall']} "
          f"({ep['n_windows_detected']}/{ep['n_windows']})   [reponse a "
          f"'detecte-t-il les attaques ?']")
    if metrics["event_level"]:
        g = metrics["event_level"]["global"]
        print(f"  Separation (global)      : PR-AUC={g['pr_auc']} "
              f"ROC-AUC={g['roc_auc']}   [reponse a 'distingue-t-il ?']")
    inv = metrics.get("score_inversion") or {}
    if inv.get("benign_above_attack_median_frac") is not None:
        print(f"  Inversion saturation     : "
              f"{inv['benign_above_attack_median_frac']} des benins surclassent "
              f"l'attaque mediane (a disambiguer par Sigma)")


# ===========================================================================
# 7. CLI
# ===========================================================================
def main():
    ap = argparse.ArgumentParser(description="Evaluation Sentinel HIDS")
    ap.add_argument("--from-csv", default=None,
                    help="CSV TEST deja score (sinon re-score depuis artifacts)")
    ap.add_argument("--groundtruth", default="groundtruth.jsonl",
                    help="JSONL de fenetres d'injection (sinon derive par signatures)")
    ap.add_argument("--tolerance", type=int, default=120,
                    help="tolerance d'appariement en secondes (defaut 120)")
    ap.add_argument("--results-dir", default="results")
    args = ap.parse_args()
    gt = args.groundtruth if args.groundtruth and os.path.exists(args.groundtruth) else None
    evaluate(from_csv=args.from_csv, groundtruth=gt,
             tolerance_s=args.tolerance, results_dir=args.results_dir)


if __name__ == "__main__":
    main()