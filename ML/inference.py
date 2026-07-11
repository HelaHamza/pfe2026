"""
inference.py
============
Scoring NON SUPERVISE du SPLIT TEST uniquement, avec les artifacts entraines,
et diagnostics de sante du modele (Phase 5 : AUCUNE metrique supervisee).

Ce module est EXCLUSIVEMENT dedie a l'EVALUATION : il ne score que le TEST
(dernier bloc chronologique = futur non vu), jamais le train ni la calib, et
n'expose PLUS de chemin "live" / production. Toutes les alertes produites
portent donc la provenance split="test".

Usage :
  python inference.py                 # score le TEST du snapshot (futur du split)
  -> ecrit evaluation_report.json + alerts.csv

NOTE : le "test" n'est pas recalcule localement. On importe
splitting.temporal_split -> le TEST evalue ici est LITTERALEMENT celui defini a
l'entrainement (source unique de verite, aucune formule dupliquee).


"""
from __future__ import annotations
import os
import json
import numpy as np
import pandas as pd
from scipy.stats import skew, kurtosis
import torch
import joblib

import config as C
import data_loader as DL
import feature_engineering as FE
import preprocessing as PP
from autoencoder import PerSourceAutoencoder
import thresholding as TH
from splitting import temporal_split          # <-- meme split que training.py

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


# ---------------------------------------------------------------------------
def load_artifacts():
    """Recharge modele + scalers + seuils + etat de nouveaute (tout gele)."""
    bundle = joblib.load(C.SCALERS_PATH)
    scalers, keep = bundle["scalers"], bundle["keep"]
    feats, input_dims = bundle["feats"], bundle["input_dims"]
    model = PerSourceAutoencoder(input_dims, C.LATENT_DIM_BY_SOURCE).to(DEVICE)
    model.load_state_dict(torch.load(C.MODEL_PATH, map_location=DEVICE))
    model.eval()
    thresholds = joblib.load(C.THRESH_PATH)
    novelty = joblib.load(C.NOVELTY_PATH) if os.path.exists(C.NOVELTY_PATH) else None
    return model, scalers, keep, feats, input_dims, thresholds, novelty


# ---------------------------------------------------------------------------
def _attribution(Z, feat_names, topn=3):
    """A partir de la matrice de z par feature (N, F), renvoie :
      * top_features : chaine 'feat=z' des `topn` features dominantes (z desc),
      * top_feat     : nom de la feature #1 (pour l'agregation episode).

    Les 2 premieres features SONT les composantes du score (SCORE_TOPK=2) ; la
    3e est fournie en contexte. On n'affiche que les z > 0 (une feature au z=0
    est mieux reconstruite que d'habitude, donc pas une raison d'alerte).
    """
    n, f = Z.shape
    if f == 0:
        empty = np.array([""] * n, dtype=object)
        return empty, empty.copy()
    k = min(topn, f)
    names = np.asarray(feat_names, dtype=object)
    idx = np.argsort(-Z, axis=1)[:, :k]              # k plus grands z par ligne

    # feature #1 : nom seulement si son z > 0 (sinon "" -> ignoree a l'agregation).
    z1 = Z[np.arange(n), idx[:, 0]]
    top_feat = np.where(z1 > 0, names[idx[:, 0]], "")

    top_features = np.empty(n, dtype=object)
    for i in range(n):
        top_features[i] = ", ".join(
            f"{names[j]}={Z[i, j]:.1f}" for j in idx[i] if Z[i, j] > 0)
    return top_features, top_feat


# ---------------------------------------------------------------------------
def score_features(model, df_feat, feats, scalers, keep, thresholds, topn=3):
    """Score un df DEJA enrichi (sortie de build_features). Renvoie un df
    par-evenement : log_source, mse, threshold, is_alert + contexte + ATTRIBUTION.

    Provenance figee a split="test" : ce module ne score que l'evaluation.
    """
    parts = []
    for s in C.SOURCES:
        if s not in scalers:
            continue
        d = df_feat[df_feat["log_source"] == s].reset_index(drop=True)
        if len(d) == 0:
            continue
        X = PP.transform(d, feats[s], scalers[s], keep[s])
        xt = torch.FloatTensor(X).to(DEVICE)
        mse = model.reconstruction_error(xt, s)
        Z = model.per_feature_zscore(xt, s)          # (N, F) z |residu| par feature

        # Noms des features GARDEES : ordre = colonnes de Z (apres keep-mask).
        feats_kept = [f for f, k in zip(feats[s], keep[s]) if k]
        top_features, top_feat = _attribution(Z, feats_kept, topn)

        thr = TH.get_threshold(thresholds, s)
        confidence = np.clip(mse / thr, 0.0, None)   # 1.0 = pile au seuil
        d_out = pd.DataFrame({
            "@timestamp": d.get("@timestamp"),
            "log_source": s,
            "host_name": d.get("host_name"),
            "user_name": d.get("user_name"),
            "source_ip": d.get("source_ip"),
            "process_name": d.get("process_name"),
            "event_type": d.get("event_type"),
            "mse": mse,
            "threshold": thr,
            "is_alert": (mse > thr).astype(int),
            "confidence": confidence.round(3),        # niveau de confiance = mse/seuil
            "confidence_level": pd.cut(
                confidence, bins=[0, 1.5, 3.0, np.inf],
                labels=["low", "medium", "high"]).astype(str),
            "top_features": top_features,             # attribution lisible (analyste + LLM)
            "top_feat": top_feat,                     # feature #1 (agregation episode)
        })
        parts.append(d_out)
        print(f"  {s:8s}: {int((mse > thr).sum()):5d} alertes / {len(d):,} "
              f"({(mse > thr).mean() * 100:.2f}%) | seuil={thr:.6f}")
    if not parts:
        return pd.DataFrame()
    scored = pd.concat(parts, ignore_index=True)
    scored["split"] = "test"          # module d'evaluation : toujours le TEST
    return scored


# ---------------------------------------------------------------------------
# Diagnostics NON SUPERVISES (Phase 5)
# ---------------------------------------------------------------------------
def unsupervised_diagnostics(model, df_feat, feats, scalers, keep, thresholds):
    """Sante du modele SANS labels : forme de la distribution des scores
    (skew/kurtosis = queue lourde ?) et vie de l'espace latent (dims mortes)."""
    diag = {}
    print("\n  [DIAGNOSTICS NON SUPERVISES]")
    for s in C.SOURCES:
        if s not in scalers:
            continue
        d = df_feat[df_feat["log_source"] == s].reset_index(drop=True)
        if len(d) == 0:
            continue
        X = PP.transform(d, feats[s], scalers[s], keep[s])
        xt = torch.FloatTensor(X).to(DEVICE)
        mse = model.reconstruction_error(xt, s)
        Z = model.latent(xt, s)
        thr = TH.get_threshold(thresholds, s)
        latent_var = Z.var(axis=0)
        diag[s] = {
            "n": int(len(d)),
            "alert_rate_pct": round(float((mse > thr).mean() * 100), 3),
            "mse_median": round(float(np.median(mse)), 6),
            "mse_p99": round(float(np.quantile(mse, 0.99)), 6),
            "mse_skewness": round(float(skew(mse)), 3),
            "mse_kurtosis": round(float(kurtosis(mse)), 3),     # queue lourde si grand
            "latent_var_min": round(float(latent_var.min()), 6),  # ~0 => dim morte
            "latent_var_mean": round(float(latent_var.mean()), 6),
            "latent_dead_dims": int((latent_var < 1e-4).sum()),
        }
        print(f"  {s:8s}: alertes={diag[s]['alert_rate_pct']:.2f}% | "
              f"skew={diag[s]['mse_skewness']} kurt={diag[s]['mse_kurtosis']} | "
              f"dims_latentes_mortes={diag[s]['latent_dead_dims']}")
    return diag


# ---------------------------------------------------------------------------
def aggregate_alerts(alerts, gap_seconds=None):
    """Regroupe les alertes en EPISODES : au sein d'une meme (source, hote),
    des alertes separees de moins de gap_seconds forment un seul episode.
    Un reboot (des centaines de lignes en rafale) devient ainsi 1 episode,
    pas 300 -> charge analyste realiste."""
    import pandas as pd
    gap = gap_seconds or C.EPISODE_GAP_SECONDS
    if len(alerts) == 0:
        return pd.DataFrame()
    a = alerts.copy()
    a["_ts"] = pd.to_datetime(a["@timestamp"], utc=True, errors="coerce")
    a = a.sort_values(["log_source", "host_name", "_ts"]).reset_index(drop=True)
    grp = a.groupby(["log_source", "host_name"], sort=False)
    # Nouvel episode quand l'ecart au precedent (meme cle) depasse gap.
    dt_prev = grp["_ts"].diff().dt.total_seconds()
    new_ep = (dt_prev.isna()) | (dt_prev > gap)
    a["_episode"] = new_ep.groupby([a["log_source"], a["host_name"]]).cumsum()

    rows = []
    for (src, host, ep), g in a.groupby(["log_source", "host_name", "_episode"],
                                        sort=False):
        procs = g["process_name"].fillna("").astype(str)
        top = procs[procs != ""].value_counts().head(3).index.tolist()

        # Features dominantes de l'episode : driver #1 le plus frequent.
        # C'est le "pourquoi" statistique agrege -> tri Sigma/LLM et debug FP.
        if "top_feat" in g.columns:
            tf = g["top_feat"].fillna("").astype(str)
            tf = tf[tf != ""]
            dom = ", ".join(f"{name} ({cnt})"
                            for name, cnt in tf.value_counts().head(3).items())
        else:
            dom = ""

        rows.append({
            "log_source": src, "host_name": host,
            "start": g["_ts"].min(), "end": g["_ts"].max(),
            "duration_s": round((g["_ts"].max() - g["_ts"].min()).total_seconds(), 1),
            "n_alerts": len(g),
            "n_distinct_proc": int(procs[procs != ""].nunique()),
            "top_processes": ", ".join(top),
            "dominant_features": dom,           # <-- attribution au niveau episode
            "mse_max": round(float(g["mse"].max()), 4),
            "mse_mean": round(float(g["mse"].mean()), 4),
        })
    episodes = pd.DataFrame(rows).sort_values("mse_max", ascending=False)
    return episodes.reset_index(drop=True)


# ---------------------------------------------------------------------------
def main():
    print("=" * 64)
    print("  INFERENCE + DIAGNOSTICS NON SUPERVISES (TEST ONLY)")
    print("=" * 64)
    if not os.path.exists(C.MODEL_PATH):
        print("ERREUR : modele introuvable. Lancer training.py d'abord.")
        return
    model, scalers, keep, feats, _, thresholds, novelty = load_artifacts()

    print("\n[1] Chargement + features...")
    df_raw = DL.load_dataset()
    df_feat = FE.build_features(df_raw, novelty_state=None)

    # EVALUATION HONNETE : on ne score QUE le TEST (futur), pas le snapshot
    # entier (qui contient le train + les contaminants retires -> sur-alerte
    # mecanique). temporal_split renvoie (pool, calib, test) : on jette
    # explicitement pool et calib.
    _, _, df_eval = temporal_split(df_feat)
    print(f"  snapshot={len(df_feat):,} -> evaluation sur le TEST={len(df_eval):,}")

    # Borne temporelle du TEST par source (preuve d'audit : rien avant n'est
    # score -> les alertes ne portent QUE sur le futur non vu).
    test_bounds = {}
    for s in df_eval["log_source"].unique():
        ts = pd.to_datetime(df_eval[df_eval["log_source"] == s]["@timestamp"],
                            utc=True, errors="coerce")
        test_bounds[s] = {"start": str(ts.min()), "end": str(ts.max()),
                          "n": int(len(ts))}
        print(f"    {s:8s}: test depuis {test_bounds[s]['start']}  "
              f"({test_bounds[s]['n']:,} logs)")

    print("\n[2] Scoring (split test)...")
    scored = score_features(model, df_eval, feats, scalers, keep, thresholds)

    # --- Separation alertes PRIMAIRES (analyste) / CONTEXTE (correlation Sigma)
    # Une source demote en "correlation" (SOURCE_ROLE) reste scoree et dispo
    # pour Sigma, mais ne pollue pas la file analyste.
    if len(scored):
        scored["role"] = scored["log_source"].map(C.SOURCE_ROLE).fillna("alert")
        fired   = scored[scored["is_alert"] == 1]
        primary = fired[fired["role"] == "alert"].copy()        # -> analyste
        context = fired[fired["role"] == "correlation"].copy()  # -> feed Sigma
    else:
        primary = context = scored.iloc[:0].copy() if len(scored.columns) else scored

    episodes = aggregate_alerts(primary)   # episodes = alertes PRIMAIRES seulement

    print("\n[3] Diagnostics (split test)...")
    diag = unsupervised_diagnostics(model, df_eval, feats, scalers, keep, thresholds)

    report = {
        "thresholds": {s: thresholds[s] for s in thresholds},
        "test_window_by_source": test_bounds,     # preuve : evaluation test-only
        "unsupervised_diagnostics": diag,
        "n_scored": int(len(scored)),
        "n_alerts_primary": int(len(primary)),
        "n_alerts_context": int(len(context)),
        "n_alert_episodes": int(len(episodes)),
        "source_roles": C.SOURCE_ROLE,
    }

    if len(scored):
        print(f"\n  Alertes primaires : {len(primary):,} -> episodes : {len(episodes):,}"
              f"  | contexte (Sigma) : {len(context):,}")

    with open(C.REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2, default=str)
    if len(primary):
        primary.to_csv("alerts.csv", index=False)
    if len(context):
        context.to_csv("alerts_context.csv", index=False)
    if len(episodes):
        episodes.to_csv("alerts_episodes.csv", index=False)

    print(f"\n  Rapport -> {C.REPORT_PATH} | alertes primaires -> alerts.csv | "
          f"contexte -> alerts_context.csv | episodes -> alerts_episodes.csv")
    print("=" * 64)


if __name__ == "__main__":
    main()