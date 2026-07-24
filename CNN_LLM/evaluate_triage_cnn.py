"""
evaluate_triage_cnn.py
======================
Mesure ce que la couche LLM apporte REELLEMENT. C'est la slide du jury.

Une couche de triage se juge sur DEUX chiffres, jamais un seul :
  * REDUCTION DU BRUIT : % d'episodes benins ecartes.
  * RETENTION DU RAPPEL : les episodes d'attaque (verite terrain) sont-ils
    TOUJOURS remontes apres triage ?
Une couche qui reduit 90 % du bruit en perdant 1 attaque sur 4 est INUTILE.
Le seul resultat publiable est : bruit fortement reduit ET rappel intact.

La verite terrain sert UNIQUEMENT ici, a l'evaluation. Elle n'est jamais
injectee dans le prompt : le LLM ne la voit pas.

Usage :
    python evaluate_triage_cnn.py --gt /home/hala-hamza/pfe-backend-2026/ML/groundtruth.jsonl
"""
from __future__ import annotations

import argparse
import json

import pandas as pd


def load_gt(path: str) -> pd.DataFrame:
    """groundtruth.jsonl : un objet par scenario, avec au minimum un debut et
    une fin. Les noms de champs sont tolerants (start/start_time/ts_start...)."""
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            g = lambda *ks: next((d[k] for k in ks if k in d and d[k]), None)  # noqa: E731
            start, end = g("start", "start_time", "ts_start", "@timestamp"), \
                         g("end", "end_time", "ts_end")
            if start is None:
                continue
            rows.append({
                "scenario": g("scenario", "name", "label", "attack") or "?",
                "technique": g("technique", "mitre", "technique_id") or "",
                "log_source": (g("log_source", "source") or "").lower(),
                "start": pd.to_datetime(start, utc=True),
                "end": pd.to_datetime(end or start, utc=True),
            })
    return pd.DataFrame(rows)


def overlaps(ep_start, ep_end, gt_start, gt_end, tol_s: float = 60.0) -> bool:
    tol = pd.Timedelta(seconds=tol_s)
    return (ep_start - tol) <= gt_end and (ep_end + tol) >= gt_start


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--triage", default="cnn_triage.jsonl")
    ap.add_argument("--gt", default="groundtruth.jsonl")
    ap.add_argument("--tolerance", type=float, default=60.0)
    a = ap.parse_args()

    tri = pd.DataFrame([json.loads(l) for l in open(a.triage, encoding="utf-8")
                        if l.strip()])
    tri["start"] = pd.to_datetime(tri["start"], utc=True, format="ISO8601")
    tri["end"] = pd.to_datetime(tri["end"], utc=True, format="ISO8601")
    gt = load_gt(a.gt)

    # --- appariement episode <-> scenario ----------------------------------
    tri["gt_scenario"] = ""
    for i, ep in tri.iterrows():
        for _, g in gt.iterrows():
            if g["log_source"] and g["log_source"] != ep["log_source"].lower():
                continue
            if overlaps(ep["start"], ep["end"], g["start"], g["end"], a.tolerance):
                tri.at[i, "gt_scenario"] = g["scenario"]
                break

    is_attack = tri["gt_scenario"] != ""
    kept = tri["verdict"] != "false_positive"

    # --- COUVERTURE : partir des SCENARIOS, pas des episodes ---------------
    # Une boucle qui part des episodes ne peut pas voir un scenario que AUCUN
    # episode ne recouvre : il disparait de la mesure au lieu d'etre compte
    # comme manque. C'est l'inverse qu'il faut interroger -- pour chaque
    # scenario connu, arrive-t-il jusqu'a l'analyste ? -- et cela separe deux
    # responsabilites que "2/2" confondait :
    #   * jamais detecte    -> le CNN (couche 1) n'a pas alerte : hors sujet
    #                          pour evaluer le triage.
    #   * detecte puis clos -> la couche 3 a perdu l'attaque : REGRESSION.
    couverture = []
    for _, g in gt.iterrows():
        m = tri.apply(
            lambda ep: (not g["log_source"]
                        or g["log_source"] == ep["log_source"].lower())
            and overlaps(ep["start"], ep["end"], g["start"], g["end"],
                         a.tolerance), axis=1)
        eps = tri[m] if len(tri) else tri
        survivants = eps[eps["verdict"] != "false_positive"] if len(eps) else eps
        couverture.append({
            "scenario": g["scenario"], "technique": g["technique"],
            "log_source": g["log_source"], "start": g["start"],
            "n_episodes": len(eps), "n_conserves": len(survivants),
            "verdicts": ", ".join(sorted(set(eps["verdict"]))) if len(eps) else "",
            "etat": ("jamais_detecte" if len(eps) == 0 else
                     "PERDU_PAR_TRIAGE" if len(survivants) == 0 else
                     "conserve"),
        })
    cov = pd.DataFrame(couverture)

    n = len(tri)
    n_atk = int(is_attack.sum())
    n_benign = n - n_atk

    print("=" * 66)
    print("  EVALUATION DE LA COUCHE LLM + RAG (niveau episode)")
    print("=" * 66)
    print(f"\nAVANT triage : {n} episodes remontes a l'analyste "
          f"({n_atk} d'attaque, {n_benign} benins)")
    print(f"APRES triage : {int(kept.sum())} episodes remontes")

    print("\n--- Reduction du bruit ---")
    if n_benign:
        fp_removed = int((~kept & ~is_attack).sum())
        print(f"  episodes benins ecartes : {fp_removed}/{n_benign} "
              f"({100 * fp_removed / n_benign:.1f}%)")
    print(f"  charge analyste : {n} -> {int(kept.sum())} "
          f"(-{100 * (1 - kept.sum() / max(n, 1)):.1f}%)")

    print("\n--- Retention du rappel (LE chiffre critique) ---")

    n_gt = len(cov)
    n_det = int((cov["etat"] != "jamais_detecte").sum())
    n_ok = int((cov["etat"] == "conserve").sum())
    n_perdu = int((cov["etat"] == "PERDU_PAR_TRIAGE").sum())
    n_jamais = int((cov["etat"] == "jamais_detecte").sum())

    print(f"  scenarios de la verite terrain    : {n_gt}")
    print(f"  detectes par le CNN (couche 1)    : {n_det}/{n_gt}")
    if n_det:
        print(f"  CONSERVES par le triage (couche 3): {n_ok}/{n_det} "
              f"({100 * n_ok / n_det:.1f}%)   <-- performance de CETTE couche")
    print(f"  perdus par le triage              : {n_perdu}")
    print(f"  jamais detectes (hors sujet ici)  : {n_jamais}")

    print("\n  Detail par scenario :")
    for _, r in cov.sort_values("start").iterrows():
        mark = {"conserve": "[OK ]", "PERDU_PAR_TRIAGE": "[!! ]",
                "jamais_detecte": "[ - ]"}[r["etat"]]
        print(f"     {mark} {r['scenario']:26s} {str(r['technique'] or ''):12s} "
              f"{r['n_episodes']} ep. -> {r['verdicts'] or 'aucun episode CNN'}")

    if n_perdu:
        print("\n  !! REGRESSION BLOQUANTE : la couche 3 a clos une attaque que")
        print("     le CNN avait detectee. A corriger avant toute publication.")
        for _, r in cov[cov["etat"] == "PERDU_PAR_TRIAGE"].iterrows():
            print(f"       - {r['scenario']} ({r['log_source']}, {r['start']})")
    elif n_ok:
        print("\n  Aucune attaque perdue par le triage.")

    if n_jamais:
        print("\n  Note : les scenarios non detectes le sont par la COUCHE 1")
        print("  (CNN/POT). Le triage ne peut ni les retrouver ni les perdre ;")
        print("  ils ne comptent pas dans l'evaluation de cette couche, mais")
        print("  le denominateur doit etre annonce tel quel.")

    print("\n--- Repartition des verdicts ---")
    print(tri["verdict"].value_counts().to_string())
    print("\n--- Garde-fous declenches ---")
    g = pd.Series([x for r in tri["guardrails"] for x in (r or [])])
    print(g.value_counts().to_string() if len(g) else "  aucun")

    out = tri[["episode_id", "log_source", "start", "verdict", "confidence",
               "severity", "gt_scenario", "title"]]
    out.to_csv("cnn_triage_eval.csv", index=False)
    cov.to_csv("cnn_gt_coverage.csv", index=False)
    print("\n-> cnn_triage_eval.csv | cnn_gt_coverage.csv")
    print("=" * 66)


if __name__ == "__main__":
    main()