"""
inference_cnn.py
================
Equivalent CNN de inference.py : INFERENCE SEULE sur le split TEST, avec le
modele CNN hybride DEJA entraine (aucun re-entrainement).

Comme inference.py, il n'y a PAS de fichier de test statique : le TEST est le
dernier bloc chronologique par source, recalcule par splitting.temporal_split
(meme decoupage qu'a l'entrainement -> source unique de verite).

Sorties (prefixe cnn_) :
  * cnn_scored_test.csv     tous les evenements du test, scores (pour A/B eval)
  * cnn_alerts.csv          alertes PRIMAIRES (is_alert==1, role='alert')
  * cnn_alerts_context.csv  alertes de sources en role 'correlation' (feed Sigma)
  * cnn_alerts_episodes.csv episodes (alertes primaires regroupees)
  * cnn_evaluation_report.json  bornes du test + diagnostics legers

Usage :
  python train_eval_cnn.py     # 1) entraine + calibre + sauve les artifacts
  python inference_cnn.py      # 2) infere sur le test -> alertes / episodes
  python evaluation.py --from-csv cnn_scored_test.csv   # 3) A/B chiffre
"""
from __future__ import annotations
import os, json
import numpy as np
import pandas as pd
from scipy.stats import skew, kurtosis
import torch
import joblib

import config_cnn as CC
import data_loader as DL
import cnn_features as FE          # [FIX] etait feature_engineering (module MLP).
                                   # Les scalers/vocabs geles dans cnn_bundle.pkl
                                   # ont ete fittes sur la sortie de cnn_features :
                                   # l'inference DOIT reconstruire les features avec
                                   # le MEME module, sinon skew train/inference.
import cnn_windowing as W
from autoencoder_cnn import PerSourceHybridConvAE
from splitting import temporal_split
from train_eval_cnn import _score_df, DEVICE  # reutilise le scoring par source


def load_artifacts_cnn():
    """Recharge modele CNN + scalers + vocabs + feats + seuils (tout gele)."""
    b = joblib.load(CC.BUNDLE_PATH)
    model = PerSourceHybridConvAE(
        b["scalar_dims"], b["vocab_sizes"], win=b["win"]).to(DEVICE)
    model.load_state_dict(torch.load(CC.MODEL_PATH, map_location=DEVICE))
    model.eval()
    thresholds = joblib.load(CC.THRESH_PATH)
    return model, b["scalers"], b["vocabs"], b["feats"], thresholds


# ---------------------------------------------------------------------------
def aggregate_alerts(alerts, gap_seconds=None):
    """Regroupe les alertes en EPISODES : au sein d'une meme (source, hote),
    des alertes separees de moins de gap_seconds forment un seul episode.
    Un reboot (des centaines de lignes en rafale) devient ainsi 1 episode,
    pas 300 -> charge analyste realiste."""
    import pandas as pd
    gap = gap_seconds or CC.EPISODE_GAP_SECONDS
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

def main():
    print("=" * 64)
    print("  INFERENCE CNN HYBRIDE (TEST ONLY, sans re-entrainement)")
    print("=" * 64)
    for p in (CC.MODEL_PATH, CC.BUNDLE_PATH, CC.THRESH_PATH):
        if not os.path.exists(p):
            print(f"ERREUR : artifact introuvable ({p}). Lancer train_eval_cnn.py d'abord.")
            return

    model, scalers, vocabs, feats_by, thresholds = load_artifacts_cnn()

    print("\n[1] Chargement + features + is_fail...")
    # FE.build_features (cnn_features) ajoute deja is_fail ; W.add_atomic_channels
    # est idempotent (no-op si is_fail present) -> aucun effet de bord.
    df = FE.build_features(DL.load_dataset())

    # TEST = dernier bloc chronologique par source (on jette pool + calib).
    _, _, df_test = temporal_split(df)
    print(f"  snapshot={len(df):,} -> TEST={len(df_test):,}")

    # Bornes du TEST par source (preuve d'audit : rien avant n'est score).
    bounds = {}
    for s in df_test["log_source"].unique():
        ts = pd.to_datetime(df_test[df_test["log_source"] == s]["@timestamp"],
                            utc=True, errors="coerce")
        bounds[s] = {"start": str(ts.min()), "end": str(ts.max()), "n": int(len(ts))}
        print(f"    {s:8s}: test depuis {bounds[s]['start']} ({bounds[s]['n']:,} logs)")

    print("\n[2] Scoring du TEST par source...")
    parts = []
    for s in scalers:                       # sources reellement entrainees
        d = df_test[df_test["log_source"] == s].reset_index(drop=True)
        if len(d) == 0:
            continue
        thr = float(thresholds[s]["threshold"])
        out = _score_df(model, d, feats_by[s], scalers[s], vocabs[s], s, thr)
        if len(out):
            parts.append(out)
            print(f"    {s:8s}: {int(out['is_alert'].sum()):5d} alertes / {len(out):,} "
                  f"({100 * out['is_alert'].mean():.2f}%) | seuil={thr:.6f}")
    scored = pd.concat(parts, ignore_index=True) if parts else pd.DataFrame()

    # --- separation primaires / contexte (meme logique qu'inference.py) -----
    if len(scored):
        # [FIX] etait C.SOURCE_ROLE (config MLP). _score_df pose deja le role
        # depuis config_cnn.SOURCE_ROLE : on unifie sur CC pour eviter que la
        # separation primaire/contexte diverge entre train et inference.
        scored["role"] = scored["log_source"].map(CC.SOURCE_ROLE).fillna("alert")
        fired = scored[scored["is_alert"] == 1]
        primary = fired[fired["role"] == "alert"].copy()
        context = fired[fired["role"] == "correlation"].copy()
    else:
        primary = context = scored

    episodes = aggregate_alerts(primary)   # reutilise l'agregation en episodes

    # --- diagnostics legers (forme de la distribution des scores) -----------
    print("\n[3] Diagnostics (test)...")
    diag = {}
    for s in scored["log_source"].unique() if len(scored) else []:
        m = scored["log_source"] == s
        sc = scored.loc[m, "mse"].to_numpy()
        thr = float(thresholds[s]["threshold"])
        diag[s] = {
            "n": int(m.sum()),
            "alert_rate_pct": round(float((sc > thr).mean() * 100), 3),
            "score_median": round(float(np.median(sc)), 4),
            "score_p99": round(float(np.quantile(sc, 0.99)), 4),
            "score_skew": round(float(skew(sc)), 3),
            "score_kurtosis": round(float(kurtosis(sc)), 3),
        }
        print(f"    {s:8s}: alertes={diag[s]['alert_rate_pct']:.2f}% "
              f"skew={diag[s]['score_skew']} kurt={diag[s]['score_kurtosis']}")

    # --- ecritures ----------------------------------------------------------
    scored.to_csv(CC.SCORED_TEST_CSV, index=False)
    if len(primary):
        primary.to_csv("cnn_alerts.csv", index=False)
    if len(context):
        context.to_csv("cnn_alerts_context.csv", index=False)
    if len(episodes):
        episodes.to_csv("cnn_alerts_episodes.csv", index=False)

    report = {
        "test_window_by_source": bounds,
        "thresholds": {s: thresholds[s]["threshold"] for s in thresholds},
        "diagnostics": diag,
        "n_scored": int(len(scored)),
        "n_alerts_primary": int(len(primary)),
        "n_alerts_context": int(len(context)),
        "n_alert_episodes": int(len(episodes)),
    }
    with open("cnn_evaluation_report.json", "w") as f:
        json.dump(report, f, indent=2, default=str)

    if len(scored):
        print(f"\n  Alertes primaires : {len(primary):,} -> episodes : {len(episodes):,}"
              f"  | contexte : {len(context):,}")
    print(f"  -> {CC.SCORED_TEST_CSV} | cnn_alerts.csv | cnn_alerts_episodes.csv")
    print(f"  A/B : python evaluation.py --from-csv {CC.SCORED_TEST_CSV}")
    print("=" * 64)


if __name__ == "__main__":
    main()