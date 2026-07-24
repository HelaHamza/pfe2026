"""
evaluation.py
=============
Evaluateur UNIFIE pour Sentinel (branche CNN ou MLP), mode --from-csv :
prend un dump DEJA score (cnn_scored_test.csv / test_scored.csv) et sort,
en une commande, les trois niveaux d'evaluation.

Ne re-score RIEN en mode --from-csv : il lit le CSV, LABELLISE les lignes de
facon INDEPENDANTE du score, puis mesure.

Labels (non circulaires : signatures OBSERVABLES, jamais le score) :
  * MARQUEUR d'injection (pose au moment de l'attaque) :
      auth  user_name = invaliduserN  -> brute-force    (TOUS les rejeux)
      auth  user_name = testintrus    -> creation compte (TOUS les rejeux)
  * FENETRE GT (groundtruth.jsonl, +/-tol, meme source, hote casefold) :
      couvre les scenarios exec (base64/echo) et le reste.
  y = 1 si marqueur OU fenetre GT, sinon 0.

Trois granularites :
  1. LIGNE  : qualite de RANKING sans seuil -> ROC-AUC et surtout PR-AUC
     (attaques < 1% -> forte imbalance -> PR-AUC prioritaire) + precision@k,
     PAR SOURCE. + point de fonctionnement (P/R/F1/confusion) au seuil GPD-POT.
  2. EPISODE: sortie analyste reelle -> recall de detection PAR FENETRE
     (chaque attaque a-t-elle produit >=1 episode ?) + precision episode.
     METRIQUE OPERATIONNELLE.
  3. INVERSION de score (saturation FEATURE_Z_CAP) : fraction de benins qui
     surclassent l'attaque mediane -> explique un PR-AUC mediocre malgre un
     bon recall.

Bornes de test : derivees DIRECTEMENT du CSV (min/max @timestamp par source).
Une fenetre GT hors du range test de SA source = NON SCORABLE (trou de
couverture d'eval, PAS un rate modele) -> exclue du recall.

Reutilise sans modification : config, inference.aggregate_alerts.

Usage :
    python evaluation.py --from-csv cnn_scored_test.csv
    python evaluation.py --from-csv cnn_scored_test.csv --episodes cnn_alerts_episodes.csv
    python evaluation.py --from-csv cnn_scored_test.csv --tolerance 120 --results-dir eval_cnn
"""
from __future__ import annotations
import os
import re
import json
import argparse

import numpy as np
import pandas as pd

from sklearn.metrics import (
    roc_auc_score, average_precision_score,
    precision_recall_fscore_support,
)

import config_cnn as C

try:
    import inference as INF
    _HAS_INF = True
except Exception:
    _HAS_INF = False


ATT_USER_RE = re.compile(r"invaliduser\d+", re.IGNORECASE)


# ===========================================================================
# 0. Utilitaires
# ===========================================================================
def _norm_host(h) -> str:
    """auth/syslog='ASUS-X415JA', auditd='asus-x415ja' -> MEME hote."""
    return "" if h is None else str(h).casefold()


def load_gt(path):
    """groundtruth.jsonl -> DataFrame (start/end UTC). None si absent."""
    if not os.path.exists(path):
        print(f"  /!\\ {path} absent : labelling par MARQUEUR seul "
              f"(auth complet, exec auditd non etiquete -> conservateur).")
        return None
    rows = []
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue                       # ignore lignes corrompues anciennes
    if not rows:
        return None
    gt = pd.DataFrame(rows)
    gt["start"] = pd.to_datetime(gt["start"], utc=True, errors="coerce")
    gt["end"]   = pd.to_datetime(gt["end"],   utc=True, errors="coerce")
    gt = gt.dropna(subset=["start", "end"]).reset_index(drop=True)
    n_dropped = n_avant - len(gt)
    if n_dropped:
        print(f"  /!\\ {n_dropped} ligne(s) GT rejetée(s) (date illisible)")
    return gt


# ===========================================================================
# 1. Labelling (independant du score)
# ===========================================================================
def label_events(scored, gt, tol=pd.Timedelta(0)):   # <-- APRÈS : tol ligne = 0
    ts   = pd.to_datetime(scored["@timestamp"], utc=True, errors="coerce")
    user = scored.get("user_name", pd.Series("", index=scored.index)).fillna("").astype(str)
    host = scored["host_name"].map(_norm_host)
    src  = scored["log_source"].astype(str)

    marker = user.str.match(ATT_USER_RE) | user.eq("testintrus")

    gtmask = pd.Series(False, index=scored.index)
    if gt is not None and len(gt):
        for _, g in gt.iterrows():
            m = (src == g["source"]) & (ts >= g["start"] - tol) & (ts <= g["end"] + tol)
            if "host" in g and pd.notna(g.get("host")):
                m &= (host == _norm_host(g["host"]))
            gtmask |= m.fillna(False)

    y = (marker | gtmask).astype(int).to_numpy()
    return y, ts


# ===========================================================================
# 2. Niveau LIGNE (ranking sans seuil)
# ===========================================================================
def line_level(scored, y):
    per_source = {}
    for s in scored["log_source"].unique():
        m = (scored["log_source"] == s).to_numpy()
        ys = y[m]
        score = scored.loc[m, "mse"].to_numpy()
        n_att = int(ys.sum())
        if n_att == 0 or n_att == len(ys):
            per_source[s] = {"n": int(m.sum()), "n_attack": n_att,
                             "note": "pas de contraste (labels homogenes)"}
            continue
        order = np.argsort(-score)
        p_at_k = float(ys[order[:n_att]].mean())      # precision@k, k=n_att
        per_source[s] = {
            "n": int(m.sum()), "n_attack": n_att,
            "roc_auc": round(float(roc_auc_score(ys, score)), 4),
            "pr_auc":  round(float(average_precision_score(ys, score)), 4),
            "precision_at_k": round(p_at_k, 4), "k": n_att,
        }
    return per_source


def global_confidence(scored, y):
    """Vue GLOBALE : echelles differentes par source -> normalise par
    confidence = mse / seuil (1.0 = pile au seuil)."""
    if y.sum() == 0 or y.sum() == len(y):
        return {}
    conf = (scored["mse"] / scored["threshold"]).to_numpy()
    return {
        "roc_auc": round(float(roc_auc_score(y, conf)), 4),
        "pr_auc":  round(float(average_precision_score(y, conf)), 4),
        "n": int(len(y)), "n_attack": int(y.sum()),
        "attack_prevalence": round(float(y.mean()), 5),
    }


def operating_point(scored, y):
    """Point de fonctionnement au seuil GPD-POT (is_alert=1)."""
    pred = scored["is_alert"].to_numpy().astype(int)
    p, r, f1, _ = precision_recall_fscore_support(
        y, pred, average="binary", zero_division=0)
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    out = {"precision": round(float(p), 4), "recall": round(float(r), 4),
           "f1": round(float(f1), 4), "tp": tp, "fp": fp, "tn": tn, "fn": fn}

    # Bonus : precision parmi les alertes de confiance medium+ (filtre l'epaule
    # benin-low sans toucher au code). Metrique operationnelle etablie.
    if "confidence_level" in scored.columns:
        medplus = scored["confidence_level"].isin(["medium", "high"]).to_numpy()
        fired_mp = (pred == 1) & medplus
        if fired_mp.sum():
            out["precision_medium_plus"] = round(float(y[fired_mp].mean()), 4)
            out["n_fired_medium_plus"] = int(fired_mp.sum())
    return out


# ===========================================================================
# 3. Niveau EPISODE (operationnel)
# ===========================================================================
def get_episodes(scored, episodes_path):
    """Priorite au CSV d'episodes deja ecrit ; sinon re-agrege via inference."""
    if episodes_path and os.path.exists(episodes_path):
        return pd.read_csv(episodes_path), f"lu ({episodes_path})"
    if _HAS_INF:
        sc = scored.copy()
        sc["role"] = sc["log_source"].map(C.SOURCE_ROLE).fillna("alert")
        primary = sc[(sc["is_alert"] == 1) & (sc["role"] == "alert")].copy()
        try:
            return INF.aggregate_alerts(primary), "re-agrege (inference.aggregate_alerts)"
        except Exception as e:
            print(f"  [!] re-agregation echouee ({e}) -> eval episode ignoree.")
    return None, "indisponible"


def episode_level(scored, gt, tol, episodes, ts):
    if episodes is None or len(episodes) == 0 or gt is None:
        return {}
    ep = episodes.copy()
    ep["start"] = pd.to_datetime(ep["start"], utc=True, errors="coerce")
    ep["end"]   = pd.to_datetime(ep["end"],   utc=True, errors="coerce")
    ep = ep.dropna(subset=["start", "end"]).reset_index(drop=True)
    ep["host_k"] = ep["host_name"].map(_norm_host)

    # Bornes test par source, derivees du CSV score.
    bounds = {}
    for s in scored["log_source"].unique():
        m = (scored["log_source"] == s).to_numpy()
        bounds[s] = (ts[m].min(), ts[m].max())

    detail, det, scorable = [], 0, 0
    for _, g in gt.iterrows():
        s = g["source"]
        tb = bounds.get(s)
        is_scorable = not (tb is not None and
                           (g["end"] < tb[0] or g["start"] > tb[1]))
        cand = ep[ep["log_source"] == s]
        if "host" in g and pd.notna(g.get("host")):
            cand = cand[cand["host_k"] == _norm_host(g["host"])]
        hit = cand[(cand["start"] <= g["end"] + tol) &
                   (cand["end"] >= g["start"] - tol)]
        ok = len(hit) > 0
        if is_scorable:
            scorable += 1
            det += int(ok)
        detail.append({"name": g.get("name"), "source": s,
                       "scorable": bool(is_scorable), "detected": bool(ok),
                       "mse_max": round(float(hit["mse_max"].max()), 2) if ok else None})

    # Precision episode (borne basse : les 'FP' incluent des benins-rares reels).
    def _ep_tp(e):
        c = gt[gt["source"] == e["log_source"]]
        if not len(c):
            return False
        return bool(((c["start"] <= e["end"] + tol) &
                     (c["end"] >= e["start"] - tol)).any())

    ep["tp"] = ep.apply(_ep_tp, axis=1)
    n_tp = int(ep["tp"].sum())
    return {
        "window_detection_recall": round(det / scorable, 4) if scorable else None,
        "n_windows_detected": det, "n_windows_scorable": scorable, "n_windows_gt": len(gt),
        "episode_precision": round(n_tp / len(ep), 4) if len(ep) else None,
        "n_attack_episodes": n_tp, "n_episodes": len(ep),
        "detail": detail,
    }


# ===========================================================================
# 4. Diagnostic INVERSION de score (saturation)
# ===========================================================================
def score_inversion(scored, y):
    att = scored.loc[y == 1, "mse"].to_numpy()
    ben = scored.loc[y == 0, "mse"].to_numpy()
    if len(att) == 0:
        return {}
    med = float(np.median(att))
    return {
        "attack_median_score": round(med, 4),
        "attack_max_score": round(float(att.max()), 4),
        "benign_max_score": round(float(ben.max()), 4) if len(ben) else None,
        "benign_above_attack_median": int((ben > med).sum()) if len(ben) else 0,
        "benign_above_attack_median_frac":
            round(float((ben > med).mean()), 4) if len(ben) else None,
    }


# ===========================================================================
# 5. Restitution
# ===========================================================================
def _print_summary(M):
    print("\n" + "=" * 68)
    print("  SYNTHESE EVALUATION")
    print("=" * 68)
    c = M["config"]
    print(f"  Verite terrain    : {c['groundtruth']}  | tol=+/-{c['tolerance_s']}s")
    print(f"  Evenements        : {c['n_events']:,}  | attaques="
          f"{c['n_attack']:,} ({100 * c['attack_prevalence']:.3f}%)")

    ep = M.get("episode_level") or {}
    if ep:
        print("\n  -- EPISODE (operationnel) --")
        print(f"  Recall detection/fenetre : {ep['window_detection_recall']} "
              f"({ep['n_windows_detected']}/{ep['n_windows_scorable']} scorables"
              f", {ep['n_windows_gt']} GT)")
        print(f"  Precision episode        : {ep['episode_precision']} "
              f"({ep['n_attack_episodes']}/{ep['n_episodes']}) [borne basse]")

    g = M.get("global") or {}
    if g:
        print("\n  -- LIGNE global (confidence normalisee) --")
        print(f"  ROC-AUC={g['roc_auc']}  PR-AUC={g['pr_auc']}")

    ls = M.get("line_per_source") or {}
    if ls:
        print("\n  -- LIGNE par source (PR-AUC prioritaire) --")
        for s, d in ls.items():
            if "pr_auc" in d:
                print(f"  {s:8s}: PR-AUC={d['pr_auc']} ROC-AUC={d['roc_auc']} "
                      f"P@{d['k']}={d['precision_at_k']} (n_att={d['n_attack']})")
            else:
                print(f"  {s:8s}: {d.get('note', '')} (n_att={d['n_attack']})")

    op = M.get("operating_point") or {}
    if op:
        print("\n  -- POINT DE FONCTIONNEMENT (seuil GPD-POT) --")
        line = (f"  P={op['precision']} R={op['recall']} F1={op['f1']} | "
                f"TP={op['tp']} FP={op['fp']} TN={op['tn']} FN={op['fn']}")
        if "precision_medium_plus" in op:
            line += f" | P(medium+)={op['precision_medium_plus']}"
        print(line)

    inv = M.get("score_inversion") or {}
    if inv:
        print("\n  -- INVERSION DE SCORE (saturation) --")
        print(f"  attaque mediane={inv['attack_median_score']} | "
              f"benins au-dessus={inv['benign_above_attack_median']} "
              f"({inv['benign_above_attack_median_frac']})")
        print(f"  max benin={inv['benign_max_score']}  vs  "
              f"max attaque={inv['attack_max_score']}")
    print("=" * 68)


# ===========================================================================
# 6. main
# ===========================================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-csv", dest="from_csv", required=True,
                    help="dump deja score (cnn_scored_test.csv)")
    ap.add_argument("--groundtruth", default="groundtruth.jsonl")
    ap.add_argument("--episodes", default="cnn_alerts_episodes.csv",
                    help="CSV d'episodes ; sinon re-agrege depuis le dump")
    ap.add_argument("--tolerance", type=int, default=120, help="tolerance (s)")
    ap.add_argument("--results-dir", default="eval_results")
    args = ap.parse_args()

    if not os.path.exists(args.from_csv):
        print(f"ERREUR : {args.from_csv} introuvable.")
        return
    os.makedirs(args.results_dir, exist_ok=True)
    tol = pd.Timedelta(seconds=args.tolerance)

    print("=" * 68)
    print(f"  EVALUATION --from-csv {args.from_csv}")
    print("=" * 68)

    scored = pd.read_csv(args.from_csv)
    gt = load_gt(args.groundtruth)
    y, ts = label_events(scored, gt, pd.Timedelta(0))   # labelling ligne : STRICT

    episodes, ep_src = get_episodes(scored, args.episodes)
    print(f"  Episodes : {ep_src}")

    M = {
        "config": {
            "from_csv": args.from_csv,
            "groundtruth": args.groundtruth if gt is not None else "MARQUEUR seul",
            "tolerance_s": args.tolerance,
            "n_events": int(len(scored)),
            "n_attack": int(y.sum()),
            "attack_prevalence": float(y.mean()) if len(y) else 0.0,
        },
        "episode_level":   episode_level(scored, gt, tol, episodes, ts),
        "line_per_source": line_level(scored, y),
        "global":          global_confidence(scored, y),
        "operating_point": operating_point(scored, y),
        "score_inversion": score_inversion(scored, y),
    }

    _print_summary(M)

    out = os.path.join(args.results_dir, "evaluation_metrics.json")
    with open(out, "w") as f:
        json.dump(M, f, indent=2, default=str)
    print(f"\n  -> {out}")


if __name__ == "__main__":
    main()