from __future__ import annotations

"""Évaluation CNN seul vs cascade CNN+LLM contre un ground-truth injecté.

Principe : le système est une CASCADE.
  - Le CNN score la RARETÉ (mse continu)  -> bon rappel, précision faible.
  - Le LLM FILTRE le bruit bénin           -> précision monte, rappel préservé.

--------------------------------------------------------------------------
CE DONT CHAQUE MÉTRIQUE A BESOIN  (à lire avant de choisir --scored)
--------------------------------------------------------------------------
  précision (niveau alerte)  = TP_alertes / toutes_alertes
        -> alertes + GT SUFFISENT. Ne regarde que les prédits positifs,
           donc identique que --scored soit complet ou tronqué.

  rappel (niveau attaque)    = attaques détectées / attaques injectées
        -> alertes + GT SUFFISENT. Une attaque manquée n'a AUCUNE alerte
           qui la chevauche -> comptée comme ratée. Robuste à la troncature.
        -> C'EST L'ENTÊTE DÉFENDABLE devant un jury.

  ROC / AUC (CNN)            = balayage du seuil sur le score continu
        -> EXIGE tous les épisodes de la fenêtre (alertes ET non alertes).

  confusion épisode + rappel-épisode + TN
        -> EXIGE aussi tous les épisodes. Un épisode d'attaque scoré SOUS le
           seuil doit être présent pour être compté en FN. S'il est absent
           (cas cnn_alerts.csv), le rappel-épisode est SURÉVALUÉ -> désactivé.

--------------------------------------------------------------------------
DEUX MODES pour --scored (détectés automatiquement)
--------------------------------------------------------------------------
  COMPLET  : tous les épisodes (episode_id,host_name,start,end,mse_max).
             -> ROC/AUC + confusion-épisode + rappel-épisode ACTIVÉS.
  ALERTES  : uniquement cnn_alerts.csv (épisodes >= seuil).
             -> précision-alerte + rappel-attaque restent VALIDES ;
                ROC/AUC + rappel-épisode DÉSACTIVÉS et signalés.

Le mode est détecté (présence d'épisodes sous le seuil) ; forçable via
--mode {auto,complet,alertes}.

Entrées :
  --groundtruth  groundtruth.jsonl   (sortie de inject.py : t_start/t_end/host/technique)
  --scored       scored_episodes.csv  (COMPLET) ou cnn_alerts.csv (ALERTES)
  --triage       cnn_triage.jsonl    (verdicts LLM : episode_id, verdict)
  --threshold    seuil POT du CNN (float). Sinon lu dans --scored (colonne
                 'threshold') si présente.
"""

import argparse
import json
import math

import pandas as pd


# --------------------------------------------------------------------------- #
#  Alias de colonnes : on tolère les schémas de sortie différents             #
# --------------------------------------------------------------------------- #
_ALIASES = {
    "episode_id": ["episode_id", "ep_id", "id", "episode"],
    "host_name":  ["host_name", "host.name", "host", "agent_name", "hostname"],
    "start":      ["start", "t_start", "window_start", "ep_start", "first_seen"],
    "end":        ["end", "t_end", "window_end", "ep_end", "last_seen"],
    "mse_max":    ["mse_max", "score", "score_max", "anomaly_score", "mse"],
}


# --------------------------------------------------------------------------- #
#  Utilitaires                                                                 #
# --------------------------------------------------------------------------- #
def _norm_id(v) -> str:
    """Normalise un episode_id : 123.0 -> '123', sinon str strippée.
    Évite l'échec silencieux de jointure quand pandas lit l'id en float."""
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    s = str(v).strip()
    if s.endswith(".0") and s[:-2].isdigit():
        return s[:-2]
    return s


def _remap_columns(df: pd.DataFrame) -> pd.DataFrame:
    lower = {c.lower(): c for c in df.columns}
    ren = {}
    for canon, aliases in _ALIASES.items():
        for a in aliases:
            if a.lower() in lower and lower[a.lower()] != canon:
                ren[lower[a.lower()]] = canon
                break
    return df.rename(columns=ren)


def _overlaps(a_start, a_end, b_start, b_end) -> bool:
    return max(a_start, b_start) <= min(a_end, b_end)


def _fmt(x) -> str:
    return "n/a" if x is None or (isinstance(x, float) and x != x) else f"{x:.3f}"


def _pct(x) -> str:
    return "n/a" if x is None or (isinstance(x, float) and x != x) else f"{100*x:.1f}%"


# --------------------------------------------------------------------------- #
#  Chargement                                                                  #
# --------------------------------------------------------------------------- #
def load_groundtruth(path: str) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            rows.append({
                "attack_id": str(r.get("attack_id", "")),
                "technique": r.get("technique", ""),
                "host_name": str(r.get("host_name", "")),
                "t_start": pd.to_datetime(r["t_start"], utc=True, format="mixed"),
                "t_end":   pd.to_datetime(r["t_end"], utc=True, format="mixed"),
            })
    return rows


def load_scored(path: str) -> pd.DataFrame:
    df = _remap_columns(pd.read_csv(path))
    missing = [c for c in ("episode_id", "host_name", "start", "end", "mse_max")
               if c not in df.columns]
    if missing:
        raise SystemExit(
            f"Colonnes manquantes dans {path}: {missing}. "
            f"Colonnes trouvées: {list(df.columns)}. "
            f"Renomme-les ou complète _ALIASES en tête de script.")
    df["start"] = pd.to_datetime(df["start"], utc=True, errors="coerce", format="mixed")
    df["end"]   = pd.to_datetime(df["end"],   utc=True, errors="coerce", format="mixed")
    df["host_name"] = df["host_name"].astype(str)
    df["mse_max"]   = pd.to_numeric(df["mse_max"], errors="coerce")
    df["ep"] = df["episode_id"].map(_norm_id)
    return df


def load_triage(path: str) -> dict[str, str]:
    verdicts: dict[str, str] = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            verdicts[_norm_id(r["episode_id"])] = str(r.get("verdict", "")).lower()
    return verdicts


def load_run_window(path: str):
    """Lit run_window.json (écrit par inject.py) -> (since, until, run_id)."""
    try:
        with open(path, encoding="utf-8") as f:
            w = json.load(f)
        return (pd.to_datetime(w["since"], utc=True, format="mixed"),
                pd.to_datetime(w["until"], utc=True, format="mixed"),
                w.get("run_id"))
    except Exception:
        return None


def filter_gt(gt: list[dict], run_id: str | None, window) -> tuple[list[dict], int]:
    """Ne garde que les attaques du run courant. C'est le garde-fou contre un
    groundtruth.jsonl qui s'accumule sur plusieurs runs (footgun classique).
    Priorité : run_id explicite > fenêtre temporelle > aucun filtre."""
    if run_id:
        kept = [g for g in gt if run_id in g.get("attack_id", "")]
        return kept, len(gt) - len(kept)
    if window:
        since, until = window
        kept = [g for g in gt if _overlaps(g["t_start"], g["t_end"], since, until)]
        return kept, len(gt) - len(kept)
    return gt, 0


# --------------------------------------------------------------------------- #
#  Étiquetage : un épisode est POSITIF s'il chevauche une fenêtre GT           #
# --------------------------------------------------------------------------- #
def label_episodes(scored: pd.DataFrame, gt: list[dict]) -> pd.DataFrame:
    # host_name comparé en CASSE-INSENSIBLE : ES normalise host.name
    # différemment selon la source (auth garde la casse, auditd minuscule).
    labels, techs = [], []
    for _, ep in scored.iterrows():
        hit = []
        if not (pd.isna(ep["start"]) or pd.isna(ep["end"])):
            for g in gt:
                if str(ep["host_name"]).lower() != g["host_name"].lower():
                    continue
                if _overlaps(ep["start"], ep["end"], g["t_start"], g["t_end"]):
                    if g["technique"] not in hit:
                        hit.append(g["technique"])
        labels.append(1 if hit else 0)
        techs.append(",".join(hit))
    out = scored.copy()
    out["label"] = labels                # 1 = attaque injectée, 0 = bénin
    out["gt_technique"] = techs
    return out


# --------------------------------------------------------------------------- #
#  Détection au NIVEAU ATTAQUE (robuste à la troncature)                       #
# --------------------------------------------------------------------------- #
def detect_per_attack(scored: pd.DataFrame, gt: list[dict],
                      thr: float, kept_ids: set[str]) -> pd.DataFrame:
    """Pour chaque attaque injectée : a-t-elle >=1 alerte CNN qui la chevauche ?
    Et parmi elles, >=1 conservée par le LLM (cascade) ?"""
    rows = []
    for g in gt:
        same_host = scored[scored["host_name"].str.lower() == g["host_name"].lower()]
        mask = same_host.apply(
            lambda e: (not pd.isna(e["start"]) and not pd.isna(e["end"])
                       and _overlaps(e["start"], e["end"], g["t_start"], g["t_end"])),
            axis=1)
        overlap = same_host[mask] if len(same_host) else same_host
        alerts = overlap[overlap["mse_max"] >= thr]
        cnn_det = len(alerts) > 0
        casc_det = any(ep in kept_ids for ep in alerts["ep"])
        rows.append({
            "attack_id": g["attack_id"], "technique": g["technique"],
            "n_overlap": len(overlap), "n_alerts": len(alerts),
            "cnn": cnn_det, "cascade": casc_det,
        })
    return pd.DataFrame(rows)


# --------------------------------------------------------------------------- #
#  Métriques épisode (mode COMPLET seulement)                                  #
# --------------------------------------------------------------------------- #
def auc_rank(scores: list[float], labels: list[int]) -> float:
    """AUC = P(score(positif) > score(négatif)), formule de Mann-Whitney U.
    Transparente et exacte, sans sklearn -> vérifiable par un jury."""
    pairs = sorted(zip(scores, labels), key=lambda x: x[0])
    ranks = [0.0] * len(pairs)
    i = 0
    while i < len(pairs):
        j = i
        while j + 1 < len(pairs) and pairs[j + 1][0] == pairs[i][0]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[k] = avg
        i = j + 1
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        return float("nan")
    sum_ranks_pos = sum(r for r, (_, y) in zip(ranks, pairs) if y == 1)
    return (sum_ranks_pos - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def roc_points(scores: list[float], labels: list[int]) -> list[tuple[float, float]]:
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        return []
    pts = [(0.0, 0.0)]
    for thr in sorted(set(scores), reverse=True):
        tp = sum(1 for s, y in zip(scores, labels) if s >= thr and y == 1)
        fp = sum(1 for s, y in zip(scores, labels) if s >= thr and y == 0)
        pts.append((fp / n_neg, tp / n_pos))
    pts.append((1.0, 1.0))
    return pts


def confusion(pred_pos: list[bool], labels: list[int]) -> dict:
    tp = sum(1 for p, y in zip(pred_pos, labels) if p and y == 1)
    fp = sum(1 for p, y in zip(pred_pos, labels) if p and y == 0)
    fn = sum(1 for p, y in zip(pred_pos, labels) if not p and y == 1)
    tn = sum(1 for p, y in zip(pred_pos, labels) if not p and y == 0)
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    rec = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = (2 * prec * rec / (prec + rec)
          if prec == prec and rec == rec and (prec + rec) else float("nan"))
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": prec, "recall": rec, "f1": f1}


# --------------------------------------------------------------------------- #
#  Main                                                                        #
# --------------------------------------------------------------------------- #
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--groundtruth", default="groundtruth.jsonl")
    ap.add_argument("--scored", default="scored_episodes.csv")
    ap.add_argument("--triage", default="cnn_triage.jsonl")
    ap.add_argument("--threshold", type=float, default=None)
    ap.add_argument("--window", default="run_window.json",
                    help="run_window.json d'inject.py (filtre le GT sur la fenêtre)")
    ap.add_argument("--run-id", default=None,
                    help="ne garder que les attaques de ce run (prioritaire sur --window)")
    ap.add_argument("--mode", choices=("auto", "complet", "alertes"), default="auto",
                    help="force le mode d'entrée (défaut: auto-détecté)")
    ap.add_argument("--kept-verdicts", default="true_positive,uncertain",
                    help="verdicts considérés comme CONSERVÉS (positifs LLM)")
    ap.add_argument("--out-prefix", default="eval")
    a = ap.parse_args()

    gt_all = load_groundtruth(a.groundtruth)
    scored = load_scored(a.scored)
    verdicts = load_triage(a.triage)
    kept = {v.strip().lower() for v in a.kept_verdicts.split(",")}
    kept_ids = {ep for ep, v in verdicts.items() if v in kept}

    # ---- FILTRAGE DU GROUND-TRUTH sur le run courant -----------------------
    win = load_run_window(a.window) if a.window else None
    window = (win[0], win[1]) if win else None
    run_id = a.run_id or (win[2] if win else None)
    gt, dropped = filter_gt(gt_all, run_id, window)
    if dropped:
        via = f"run_id={run_id}" if a.run_id or (win and not a.run_id) else "fenêtre"
        print(f"  [GT] {dropped} attaque(s) hors run courant ignorée(s) "
              f"(via {via}). {len(gt)} conservée(s) sur {len(gt_all)}.")
    if not gt:
        raise SystemExit(
            f"Aucune attaque retenue. Vérifie --run-id / --window, ou que "
            f"groundtruth.jsonl correspond bien à ce run ({len(gt_all)} au total).")

    # ---- seuil POT ----------------------------------------------------------
    thr = a.threshold
    if thr is None and "threshold" in scored.columns:
        thr = float(pd.to_numeric(scored["threshold"], errors="coerce").iloc[0])
    alerts_only_auto = False
    if thr is None:
        # Pas de seuil : on suppose --scored = alertes seules (seuillage
        # per-source déjà appliqué en amont par predict_cnn). Toute ligne
        # fournie est alors une alerte. Évite d'avoir à passer --threshold 0.
        thr = float("-inf")
        alerts_only_auto = True

    labelled = label_episodes(scored, gt)

    # ---- détection du mode --------------------------------------------------
    has_sub = bool((labelled["mse_max"] < thr).any())
    if a.mode == "auto":
        mode = "complet" if has_sub else "alertes"
    else:
        mode = a.mode
    complet = (mode == "complet")

    n_attacks = len(gt)
    n_ep = len(labelled)

    print("=" * 70)
    print("  ÉVALUATION  CNN seul  vs  cascade CNN+LLM")
    print("=" * 70)
    print(f"  mode d'entrée        : {mode.upper()}"
          + ("" if complet else "  (ROC/AUC + rappel-épisode désactivés)"))
    print(f"  épisodes fournis     : {n_ep}"
          f"   (>= seuil: {int((labelled['mse_max'] >= thr).sum())},"
          f"  < seuil: {int((labelled['mse_max'] < thr).sum())})")
    print(f"  attaques injectées   : {n_attacks}")
    thr_str = "n/a (alertes en amont)" if thr == float("-inf") else f"{thr:.2f}"
    print(f"  seuil POT (CNN)      : {thr_str}")
    if not complet:
        print("  /!\\ Entrée ALERTES seules : rappel-par-attaque et précision "
              "restent valides,\n      mais fournis TOUS les épisodes pour une "
              "ROC/AUC.")

    # ---- diagnostic couverture triage --------------------------------------
    alerts = labelled[labelled["mse_max"] >= thr].copy()
    n_alerts = len(alerts)
    cov = alerts["ep"].isin(set(verdicts)).mean() if n_alerts else float("nan")
    if n_alerts and cov < 1.0:
        manquants = int(round((1 - cov) * n_alerts))
        print(f"  /!\\ COUVERTURE TRIAGE {_pct(cov)} : {manquants} alerte(s) sans "
              "verdict LLM.\n      Sans verdict -> traitée comme FILTRÉE : "
              "vérifie l'appariement des episode_id.")

    # ---- Précision (niveau alerte) : valide dans les deux modes ------------
    tp_alerts = int((alerts["label"] == 1).sum())
    fp_alerts = n_alerts - tp_alerts
    cnn_prec = tp_alerts / n_alerts if n_alerts else float("nan")

    casc = alerts[alerts["ep"].isin(kept_ids)]
    n_casc = len(casc)
    tp_casc = int((casc["label"] == 1).sum())
    fp_casc = n_casc - tp_casc
    casc_prec = tp_casc / n_casc if n_casc else float("nan")

    # ---- Rappel (niveau attaque) : valide dans les deux modes --------------
    per_attack = detect_per_attack(labelled, gt, thr, kept_ids)
    cnn_rec_atk = per_attack["cnn"].mean() if n_attacks else float("nan")
    casc_rec_atk = per_attack["cascade"].mean() if n_attacks else float("nan")

    print("\n  [CNN seul]  (entête = niveau attaque)")
    print(f"    précision (alerte) : {_fmt(cnn_prec)}   "
          f"(TP={tp_alerts}  FP={fp_alerts}  alertes={n_alerts})")
    print(f"    rappel   (attaque) : {_fmt(cnn_rec_atk)}   "
          f"({int(per_attack['cnn'].sum())}/{n_attacks} attaques détectées)")

    print("\n  [Cascade CNN+LLM]")
    print(f"    précision (alerte) : {_fmt(casc_prec)}   "
          f"(TP={tp_casc}  FP={fp_casc}  alertes conservées={n_casc})")
    print(f"    rappel   (attaque) : {_fmt(casc_rec_atk)}   "
          f"({int(per_attack['cascade'].sum())}/{n_attacks} attaques détectées)")

    # ---- Le message ---------------------------------------------------------
    fp_removed = fp_alerts - fp_casc
    print("\n  [Effet du LLM]")
    print(f"    FP retirés par le LLM : {fp_removed}"
          + (f"  ({round(100*fp_removed/fp_alerts)}% du bruit CNN)"
             if fp_alerts else "  (aucun FP CNN au départ)"))
    print(f"    précision : {_fmt(cnn_prec)} -> {_fmt(casc_prec)}  "
          f"(delta {casc_prec - cnn_prec:+.3f})")
    print(f"    rappel    : {_fmt(cnn_rec_atk)} -> {_fmt(casc_rec_atk)}  "
          f"(delta {casc_rec_atk - cnn_rec_atk:+.3f})")
    lost = int(per_attack["cnn"].sum() - per_attack["cascade"].sum())
    if lost == 0:
        print("    -> RAPPEL PRÉSERVÉ : le LLM n'a fermé AUCUNE attaque détectée.")
    else:
        fermees = per_attack[per_attack["cnn"] & ~per_attack["cascade"]]
        print(f"    -> /!\\ le LLM a fermé {lost} attaque(s) : "
              f"{list(fermees['attack_id'])}")

    # ---- ROC / AUC + confusion épisode : mode COMPLET seulement ------------
    auc = float("nan")
    ep_cnn = ep_pipe = None
    if complet:
        scores = labelled["mse_max"].astype(float).tolist()
        labels = labelled["label"].astype(int).tolist()
        auc = auc_rank(scores, labels)
        cnn_pred = [s >= thr for s in scores]
        pipe_pred = [bool(f) and (ep in kept_ids)
                     for f, ep in zip(cnn_pred, labelled["ep"])]
        ep_cnn = confusion(cnn_pred, labels)
        ep_pipe = confusion(pipe_pred, labels)
        print("\n  [Niveau ÉPISODE — mode COMPLET]")
        print(f"    ROC AUC (mse)      : {_fmt(auc)}")
        print(f"    CNN     épisode    : précision={_fmt(ep_cnn['precision'])}  "
              f"rappel={_fmt(ep_cnn['recall'])}  "
              f"TP={ep_cnn['tp']} FP={ep_cnn['fp']} FN={ep_cnn['fn']} TN={ep_cnn['tn']}")
        print(f"    Cascade épisode    : précision={_fmt(ep_pipe['precision'])}  "
              f"rappel={_fmt(ep_pipe['recall'])}  "
              f"TP={ep_pipe['tp']} FP={ep_pipe['fp']} FN={ep_pipe['fn']} TN={ep_pipe['tn']}")
        pts = roc_points(scores, labels)
        pd.DataFrame(pts, columns=["fpr", "tpr"]).to_csv(
            f"{a.out_prefix}_roc_points.csv", index=False)
    else:
        print("\n  [Niveau ÉPISODE] désactivé (entrée ALERTES) : "
              "pas de ROC/AUC ni de rappel-épisode fiables.")

    # ---- Rappel par technique ----------------------------------------------
    print("\n  [Détection par technique]  (CNN alerte ? / LLM conserve ?)")
    if per_attack.empty:
        print("    (aucune attaque dans le ground-truth)")
    else:
        for tech in sorted(per_attack["technique"].unique()):
            sub = per_attack[per_attack["technique"] == tech]
            print(f"    {tech:14s} : CNN={sub['cnn'].sum()}/{len(sub)}   "
                  f"cascade={sub['cascade'].sum()}/{len(sub)}")

    # ---- Sorties ------------------------------------------------------------
    per_attack.to_csv(f"{a.out_prefix}_per_attack.csv", index=False)
    summary = {
        "mode": mode,
        "n_episodes": n_ep, "n_attacks": n_attacks,
        "threshold": None if thr == float("-inf") else thr,
        "triage_coverage": None if cov != cov else round(cov, 4),
        "alert_level": {
            "cnn":     {"precision": cnn_prec,  "n_alerts": n_alerts,
                        "tp": tp_alerts, "fp": fp_alerts},
            "cascade": {"precision": casc_prec, "n_alerts": n_casc,
                        "tp": tp_casc, "fp": fp_casc, "fp_removed": fp_removed},
        },
        "attack_level": {
            "cnn_recall": cnn_rec_atk, "cascade_recall": casc_rec_atk,
            "attacks_detected_cnn": int(per_attack["cnn"].sum()) if not per_attack.empty else 0,
            "attacks_detected_cascade": int(per_attack["cascade"].sum()) if not per_attack.empty else 0,
        },
        "episode_level": None if not complet else {
            "auc": auc,
            "cnn": ep_cnn, "cascade": ep_pipe,
        },
    }
    def _clean(o):
        if isinstance(o, dict):
            return {k: _clean(v) for k, v in o.items()}
        if isinstance(o, float) and math.isnan(o):
            return None
        return o
    with open(f"{a.out_prefix}_summary.json", "w", encoding="utf-8") as f:
        json.dump(_clean(summary), f, indent=2, ensure_ascii=False)

    outs = [f"{a.out_prefix}_summary.json", f"{a.out_prefix}_per_attack.csv"]
    if complet:
        outs.append(f"{a.out_prefix}_roc_points.csv")
    print(f"\n  -> {'  |  '.join(outs)}")
    print("=" * 70)


if __name__ == "__main__":
    main()