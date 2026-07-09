"""
evaluate_axe4.py
================
AXE 4 (etape 2/2) -- Mesure de la capacite de detection, sur le SPLIT TEST.

Principe : le modele GELE score le test (futur non vu) SANS voir les labels.
On confronte ensuite ses alertes aux fenetres d'attaque de groundtruth.json
(etiquetees independamment par signature brute -> non circulaire).

Metriques produites :
  * rappel PAR SCENARIO   -- l'AE tire-t-il >=1 alerte dans la fenetre (+/-tol) ?
                             (le resultat phare : "recall intact sur les 4")
  * precision / rappel / F1 au niveau EPISODE (grain honnete)
  * ROC-AUC et PR-AUC PAR SOURCE (+ courbes) -- seuil-independant
  * couverture TEST : combien d'episodes GT tombent dans le test (denominateur
    honnete du rappel ; les episodes hors-test sont non evaluables et signales)

Prerequis : avoir lance training.py (artefacts geles) puis groundtruth.py.
Sortie : evaluation_axe4.json + axe4_curves.png
"""
from __future__ import annotations
import json
import os

import numpy as np
import pandas as pd
from sklearn.metrics import (roc_auc_score, average_precision_score,
                             roc_curve, precision_recall_curve)

import config as C
import data_loader as DL
import feature_engineering as FE
import thresholding as TH
import inference as INF
from splitting import temporal_split

TOL = pd.Timedelta(seconds=120)          # tolerance temporelle (+/- 2 min)
MED_CONF = 1.5                            # seuil "confiance medium+" (mse/thr)
SCENARIOS = ["ssh_bruteforce", "user_creation", "b64_exec", "syslog_burst"]


# ---------------------------------------------------------------------------
def _load_gt(path="groundtruth.json"):
    if not os.path.exists(path):
        raise FileNotFoundError("groundtruth.json absent -> lance groundtruth.py d'abord.")
    eps = json.load(open(path))["scenarios"]
    for e in eps:
        e["_start"] = pd.to_datetime(e["start"], utc=True)
        e["_end"] = pd.to_datetime(e["end"], utc=True)
        e["host_name"] = str(e.get("host_name", ""))
    return eps


def _score_test():
    """Recharge les artefacts geles et score le TEST (meme pipeline qu'inference)."""
    model, scalers, keep, feats, _, thresholds, _ = INF.load_artifacts()
    df = FE.build_features(DL.load_dataset(), novelty_state=None)
    _, _, df_eval = temporal_split(df)
    scored = INF.score_features(model, df_eval, feats, scalers, keep, thresholds)
    scored["@ts"] = pd.to_datetime(scored["@timestamp"], utc=True, errors="coerce")
    scored["host_name"] = scored["host_name"].fillna("").astype(str)
    return scored, thresholds


def _in_window(df, host, start, end):
    """Masque : lignes de `df` sur `host` dont @ts est dans [start-tol, end+tol]."""
    return (df["host_name"] == host) & df["@ts"].between(start - TOL, end + TOL)


# ---------------------------------------------------------------------------
def main():
    print("=" * 64)
    print("  AXE 4 -- capacite de detection (TEST only, modele gele)")
    print("=" * 64)
    gt = _load_gt()
    scored, thresholds = _score_test()
    fired = scored[scored["is_alert"] == 1]
    print(f"  test={len(scored):,} logs scores | {len(fired):,} alertes | "
          f"{len(gt)} episodes GT")

    # --- (A) couverture test + detection par episode GT --------------------
    for e in gt:
        cover = _in_window(scored, e["host_name"], e["_start"], e["_end"])
        hit = _in_window(fired, e["host_name"], e["_start"], e["_end"])
        e["_n_test_lines"] = int(cover.sum())      # 0 => episode HORS test
        e["_in_test"] = e["_n_test_lines"] > 0
        e["_detected"] = bool(hit.any())
        e["_n_alerts"] = int(hit.sum())

    gt_test = [e for e in gt if e["_in_test"]]
    gt_out = [e for e in gt if not e["_in_test"]]

    # --- (B) rappel PAR SCENARIO (sur episodes in-test) --------------------
    per_scenario = {}
    print("\n  Rappel par scenario (episodes in-test) :")
    for sc in SCENARIOS:
        es = [e for e in gt_test if e["scenario"] == sc]
        det = sum(e["_detected"] for e in es)
        rec = det / len(es) if es else None
        per_scenario[sc] = {"n_in_test": len(es), "detected": det,
                            "recall": None if rec is None else round(rec, 3)}
        r = "n/a" if rec is None else f"{rec*100:.0f}%"
        print(f"    {sc:16s}: {det}/{len(es)} detecte(s)  (rappel={r})")

    n_det = sum(e["_detected"] for e in gt_test)
    recall_ep = n_det / len(gt_test) if gt_test else None

    # --- (C) precision episode (cote predictions) --------------------------
    scored["role"] = scored["log_source"].map(C.SOURCE_ROLE).fillna("alert")
    primary = scored[(scored["is_alert"] == 1) & (scored["role"] == "alert")].copy()
    pred = INF.aggregate_alerts(primary)           # episodes predits

    def _matches_gt(row):
        for e in gt_test:                          # TP si chevauche une fenetre GT
            if (row["host_name"] == e["host_name"]
                    and row["start"] <= e["_end"] + TOL
                    and row["end"] >= e["_start"] - TOL):
                return True
        return False

    if len(pred):
        pred["start"] = pd.to_datetime(pred["start"], utc=True)
        pred["end"] = pd.to_datetime(pred["end"], utc=True)
        pred["host_name"] = pred["host_name"].astype(str)
        pred["_thr"] = pred["log_source"].map(lambda s: TH.get_threshold(thresholds, s))
        pred["_conf_max"] = pred["mse_max"] / pred["_thr"].replace(0, np.nan)
        pred["_tp"] = pred.apply(_matches_gt, axis=1)
        tp = int(pred["_tp"].sum())
        prec_ep = tp / len(pred)
        med = pred[pred["_conf_max"] >= MED_CONF]
        prec_med = (int(med["_tp"].sum()) / len(med)) if len(med) else None
    else:
        tp = 0; prec_ep = None; prec_med = None; med = pred

    f1 = (2 * prec_ep * recall_ep / (prec_ep + recall_ep)
          if (prec_ep and recall_ep) else None)

    print(f"\n  Episode-level : rappel={_pct(recall_ep)} | "
          f"precision={_pct(prec_ep)} | F1={_pct(f1)}")
    print(f"    precision (confiance medium+, mse/thr>={MED_CONF}) = {_pct(prec_med)}"
          f"  [{len(med) if len(pred) else 0} episodes retenus]")
    print(f"    (precision brute basse = rare-benins legitimement flagues, attendu)")

    # --- (D) ROC-AUC / PR-AUC PAR SOURCE (ligne, mse comme score) ----------
    pos = pd.Series(False, index=scored.index)
    for e in gt_test:
        pos |= _in_window(scored, e["host_name"], e["_start"], e["_end"])
    scored["_y"] = pos.astype(int)

    aucs, curves = {}, {}
    print("\n  AUC par source (ligne) :")
    for s, g in scored.groupby("log_source"):
        y = g["_y"].to_numpy(); sc = g["mse"].to_numpy()
        if y.sum() == 0 or y.sum() == len(y):
            print(f"    {s:8s}: pas de positif dans le test -> AUC non definie")
            aucs[s] = None
            continue
        roc = float(roc_auc_score(y, sc)); pr = float(average_precision_score(y, sc))
        aucs[s] = {"roc_auc": round(roc, 4), "pr_auc": round(pr, 4),
                   "n_pos": int(y.sum()), "n": int(len(y))}
        fpr, tpr, _ = roc_curve(y, sc)
        p, r, _ = precision_recall_curve(y, sc)
        curves[s] = (fpr, tpr, roc, r, p, pr)
        print(f"    {s:8s}: ROC-AUC={roc:.3f} | PR-AUC={pr:.3f} "
              f"({int(y.sum())} pos / {len(y):,})")

    # combine sur la confiance (comparable inter-source)
    conf = (scored["mse"] / scored["threshold"].replace(0, np.nan)).fillna(0).to_numpy()
    y_all = scored["_y"].to_numpy()
    roc_all = (round(float(roc_auc_score(y_all, conf)), 4)
               if 0 < y_all.sum() < len(y_all) else None)

    # --- (E) courbes -------------------------------------------------------
    _plot(curves)

    # --- (F) rapport -------------------------------------------------------
    report = {
        "tolerance_s": int(TOL.total_seconds()),
        "n_gt_total": len(gt), "n_gt_in_test": len(gt_test),
        "gt_hors_test": [f'{e["id"]} ({e["start"]})' for e in gt_out],
        "recall_par_scenario": per_scenario,
        "episode_recall": _round(recall_ep), "episode_precision": _round(prec_ep),
        "episode_precision_medium_plus": _round(prec_med),
        "episode_f1": _round(f1), "n_pred_episodes": int(len(pred)),
        "auc_par_source": aucs, "roc_auc_global_confiance": roc_all,
    }
    json.dump(report, open("evaluation_axe4.json", "w"), indent=2, default=str)

    if gt_out:
        print(f"\n  /!\\ {len(gt_out)} episode(s) GT HORS test (non evaluables) :")
        for e in gt_out:
            print(f"      {e['id']} @ {e['start']} -> verifie qu'il devrait etre "
                  f"dans les 20% finaux, sinon rappel sur denominateur partiel")
    print("\n  -> evaluation_axe4.json | axe4_curves.png")
    print("=" * 64)
    return report


# ---------------------------------------------------------------------------
def _pct(x):
    return "n/a" if x is None else f"{x*100:.1f}%"


def _round(x):
    return None if x is None else round(float(x), 4)


def _plot(curves):
    if not curves:
        return
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
        for s, (fpr, tpr, roc, r, p, pr) in curves.items():
            ax1.plot(fpr, tpr, label=f"{s} (AUC={roc:.3f})")
            ax2.plot(r, p, label=f"{s} (AP={pr:.3f})")
        ax1.plot([0, 1], [0, 1], "k--", lw=0.8)
        ax1.set_xlabel("FPR"); ax1.set_ylabel("TPR"); ax1.set_title("ROC par source")
        ax2.set_xlabel("Rappel"); ax2.set_ylabel("Precision")
        ax2.set_title("Precision-Rappel par source")
        ax1.legend(); ax2.legend()
        fig.tight_layout(); fig.savefig("axe4_curves.png", dpi=140)
        print("  figure -> axe4_curves.png")
    except Exception as e:
        print(f"  [figure ignoree] {e}")


if __name__ == "__main__":
    main()