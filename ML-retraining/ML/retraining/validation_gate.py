"""
validation_gate.py
==================
Les cinq tests qui decident si un modele candidat remplace la production.

PRINCIPE
--------
Un reentrainement automatique SANS gate n'est pas de l'automatisation, c'est
un mecanisme de degradation automatique : chaque mois, le systeme remplace un
modele valide par un modele dont personne n'a rien verifie. Le gate est la
seule chose qui distingue les deux.

En cas d'echec : le candidat est archive dans artifacts/_rejected/, un rapport
est ecrit, `current` NE BOUGE PAS. Le systeme continue de tourner sur l'ancien
modele -- FAIL-SAFE, pas fail-open. Un modele perime detecte encore ; un modele
casse ne detecte plus rien.

LES CINQ TESTS
--------------
(1) INTEGRITE      les 5 artefacts existent, leurs hashes concordent, le
                   bundle et le .pt decrivent le meme modele.
(2) GOLDEN SET     les scenarios d'attaque connus restent detectes.
                   Recall episodique >= GATE_GOLDEN_MIN_RECALL (1.0 par
                   defaut). C'est le test le plus fort.
(3) TAUX D'ALERTE  sur la fenetre de reference figee, le nombre d'episodes
                   candidat / courant reste dans [0.5x, 2x].
                   Explosion = bug ou derive massive.
                   Effondrement a 0 = COLLAPSE de l'auto-encodeur : il
                   reconstruit tout parfaitement, attaques comprises. C'est la
                   panne la plus dangereuse car totalement silencieuse.
(4) DISTRIBUTION   statistique de Kolmogorov-Smirnov entre les scores candidat
                   et courant sur les memes donnees benignes.
(5) SEUILS         les seuils GPD-POT par source restent du meme ordre de
                   grandeur que ceux de la production.

NOTE METHODOLOGIQUE SUR LE TEST (4)
------------------------------------
On seuille sur la STATISTIQUE D, pas sur la p-value. A N ~ 1e5 la p-value du
test KS est quasi toujours < 1e-10, meme pour un ecart de distribution
totalement negligeable : le test devient un refus systematique et perd tout
pouvoir informatif. D mesure l'ecart maximal entre les deux CDF empiriques,
est born entre 0 et 1, et ne depend pas de N. La p-value reste calculee sur un
sous-echantillon, a titre indicatif uniquement.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import ks_2samp

from retraining import artifact_store as AS
from retraining import build_golden as BG
from retraining import retrain_config as RC
from retraining.scoring import ArtifactSet, score_raw, to_episodes


@dataclass
class TestResult:
    name: str
    passed: bool
    blocking: bool = True
    detail: str = ""
    metrics: dict = field(default_factory=dict)

    @property
    def status(self) -> str:
        if self.passed:
            return "PASS"
        return "FAIL" if self.blocking else "WARN"


# ===========================================================================
# Test 1 : integrite
# ===========================================================================
def test_integrity(cand_dir) -> TestResult:
    problems = AS.check_artifact_set(cand_dir)
    man = AS.read_manifest(cand_dir)
    if man is not None:
        problems += AS.verify_hashes(cand_dir)
    return TestResult(
        "integrite_artefacts", not problems,
        detail=("jeu d'artefacts coherent" if not problems
                else "; ".join(problems)),
        metrics={"n_problemes": len(problems), "problemes": problems})


# ===========================================================================
# Test 2 : golden set
# ===========================================================================
def _overlaps(ep, inc, tol_seconds: int = 300) -> bool:
    tol = pd.Timedelta(seconds=tol_seconds)
    if inc.log_source and ep["log_source"] != inc.log_source:
        return False
    if inc.host_name and ep["host_name"] not in (inc.host_name, "(none)"):
        return False
    return (ep["start"] <= inc.end + tol) and (ep["end"] >= inc.start - tol)


def test_golden(cand: ArtifactSet, cur: ArtifactSet | None) -> TestResult:
    from retraining.decontaminate import _load_json_incidents

    problems = BG.verify()
    if problems:
        return TestResult("golden_set", False,
                          detail="golden set indisponible ou altere : "
                                 + "; ".join(problems))

    incidents = _load_json_incidents(BG.INCIDENTS_JSON, "golden")
    df_raw = pd.read_parquet(BG.GOLDEN_PARQUET)

    cand_eps = to_episodes(score_raw(cand, df_raw))
    detected = []
    for inc in incidents:
        hit = any(_overlaps(ep, inc) for _, ep in cand_eps.iterrows())
        detected.append((inc.id, hit))
    n_hit = sum(1 for _, h in detected if h)
    recall = n_hit / len(incidents) if incidents else 0.0

    # Comparaison au courant : distinguer une regression d'un scenario qui
    # n'etait deja plus detecte avant. On ne refuse pas un candidat pour un
    # defaut herite.
    baseline = {}
    if cur is not None:
        cur_eps = to_episodes(score_raw(cur, df_raw))
        for inc in incidents:
            baseline[inc.id] = any(_overlaps(ep, inc)
                                   for _, ep in cur_eps.iterrows())

    regressions = [i for i, h in detected if not h and baseline.get(i, True)]
    passed = recall >= RC.GATE_GOLDEN_MIN_RECALL and not regressions
    missed = [i for i, h in detected if not h]

    return TestResult(
        "golden_set", passed,
        detail=(f"recall episodique {n_hit}/{len(incidents)} "
                f"({recall:.0%})"
                + (f" | REGRESSIONS : {regressions}" if regressions else "")
                + (f" | non detectes : {missed}" if missed and not regressions
                   else "")),
        metrics={"recall": recall, "n_incidents": len(incidents),
                 "detecte": dict(detected), "baseline_courant": baseline,
                 "regressions": regressions})


# ===========================================================================
# Tests 3 et 4 : taux d'alerte et distribution
# ===========================================================================
def test_reference(cand: ArtifactSet,
                   cur: ArtifactSet | None) -> tuple[TestResult, TestResult]:
    if not BG.REFERENCE_PARQUET.exists():
        r = TestResult("taux_alerte", False,
                       detail="golden/reference_events.parquet absent")
        return r, TestResult("distribution_scores", False, RC.GATE_KS_BLOCKING,
                             detail="fenetre de reference absente")

    df_raw = pd.read_parquet(BG.REFERENCE_PARQUET)
    cand_scored = score_raw(cand, df_raw)
    cand_eps = len(to_episodes(cand_scored))

    if cur is None:
        rate = TestResult(
            "taux_alerte", cand_eps >= RC.GATE_MIN_REFERENCE_EPISODES,
            detail=f"{cand_eps} episode(s) sur la reference "
                   f"(aucun modele courant : pas de comparaison possible)",
            metrics={"episodes_candidat": cand_eps})
        dist = TestResult("distribution_scores", True, RC.GATE_KS_BLOCKING,
                          detail="aucun modele courant : test non applicable")
        return rate, dist

    cur_scored = score_raw(cur, df_raw)
    cur_eps = len(to_episodes(cur_scored))

    lo, hi = RC.GATE_ALERT_RATE_BAND
    if cur_eps == 0:
        ratio = float("nan")
        ok_rate = cand_eps <= 5     # le courant n'alertait pas : le candidat non plus
        why = "modele courant a 0 episode sur la reference"
    else:
        ratio = cand_eps / cur_eps
        ok_rate = (lo <= ratio <= hi)
        why = f"ratio {ratio:.2f} (bande [{lo}, {hi}])"
    if cand_eps < RC.GATE_MIN_REFERENCE_EPISODES:
        ok_rate = False
        why += " | 0 episode : COLLAPSE probable de l'auto-encodeur"

    rate = TestResult(
        "taux_alerte", ok_rate,
        detail=f"candidat={cand_eps} ep. vs courant={cur_eps} ep. | {why}",
        metrics={"episodes_candidat": cand_eps, "episodes_courant": cur_eps,
                 "ratio": None if np.isnan(ratio) else round(ratio, 4)})

    # --- KS par source, sur les memes evenements benins -------------------
    ks_by_src, worst_d, worst_src = {}, 0.0, None
    for src in sorted(set(cand_scored["log_source"]) & set(cur_scored["log_source"])):
        a = cand_scored.loc[cand_scored["log_source"] == src, "score"].to_numpy()
        b = cur_scored.loc[cur_scored["log_source"] == src, "score"].to_numpy()
        if len(a) < 50 or len(b) < 50:
            continue
        d = float(ks_2samp(a, b).statistic)
        # p-value indicative sur sous-echantillon (cf. note methodologique).
        rng = np.random.default_rng(42)
        sub = min(len(a), len(b), 2000)
        p = float(ks_2samp(rng.choice(a, sub, replace=False),
                           rng.choice(b, sub, replace=False)).pvalue)
        ks_by_src[src] = {"D": round(d, 4), "p_sous_echantillon": p,
                          "n_candidat": len(a), "n_courant": len(b)}
        if d > worst_d:
            worst_d, worst_src = d, src

    ok_dist = worst_d <= RC.GATE_KS_D_MAX
    dist = TestResult(
        "distribution_scores", ok_dist, RC.GATE_KS_BLOCKING,
        detail=(f"D_max={worst_d:.3f} sur '{worst_src}' "
                f"(seuil {RC.GATE_KS_D_MAX})" if worst_src
                else "donnees insuffisantes pour le test KS"),
        metrics={"D_max": round(worst_d, 4), "source_pire_cas": worst_src,
                 "par_source": ks_by_src})
    return rate, dist


# ===========================================================================
# Test 5 : seuils
# ===========================================================================
def test_thresholds(cand: ArtifactSet, cur: ArtifactSet | None) -> TestResult:
    lo, hi = RC.GATE_THRESHOLD_RATIO_BAND
    rows, bad = {}, []
    for src in cand.sources:
        tc = cand.threshold(src)
        rec = {"candidat": round(float(tc), 6)}
        if not np.isfinite(tc) or tc <= 0:
            bad.append(f"{src}: seuil non exploitable ({tc})")
        if cur is not None and src in cur.sources:
            tp = cur.threshold(src)
            rec["courant"] = round(float(tp), 6)
            if np.isfinite(tp) and tp > 0:
                r = tc / tp
                rec["ratio"] = round(r, 3)
                if not (lo <= r <= hi):
                    bad.append(f"{src}: ratio {r:.2f} hors bande [{lo}, {hi}]")
        rows[src] = rec
    return TestResult(
        "seuils_pot", not bad,
        detail=("; ".join(bad) if bad else
                " | ".join(f"{s}: {v['candidat']:.3f}"
                           + (f" (x{v['ratio']:.2f})" if "ratio" in v else "")
                           for s, v in rows.items())),
        metrics={"seuils": rows})


# ===========================================================================
# Orchestration
# ===========================================================================
def run_gate(cand_dir, cur_dir=None, verbose: bool = True) -> dict:
    cand_dir = Path(cand_dir)
    results: list[TestResult] = []

    if verbose:
        print("\n  [GATE] (1/5) integrite des artefacts...")
    integ = test_integrity(cand_dir)
    results.append(integ)

    if not integ.passed:
        # Inutile de charger un modele incoherent : les tests suivants
        # planteraient avec une trace illisible au lieu d'un verdict clair.
        return _report(cand_dir, cur_dir, results, verbose,
                       note="tests 2-5 non executes : artefacts incoherents")

    cand = ArtifactSet(cand_dir)
    cur = ArtifactSet(cur_dir) if cur_dir and Path(cur_dir).exists() else None

    if verbose:
        print("  [GATE] (2/5) golden set (non-regression fonctionnelle)...")
    results.append(test_golden(cand, cur))
    if verbose:
        print("  [GATE] (3-4/5) fenetre de reference (taux + distribution)...")
    rate, dist = test_reference(cand, cur)
    results += [rate, dist]
    if verbose:
        print("  [GATE] (5/5) coherence des seuils GPD-POT...")
    results.append(test_thresholds(cand, cur))

    return _report(cand_dir, cur_dir, results, verbose)


def _report(cand_dir, cur_dir, results, verbose, note: str = "") -> dict:
    blocking_failures = [r.name for r in results if not r.passed and r.blocking]
    warnings = [r.name for r in results if not r.passed and not r.blocking]
    verdict = "PROMOTE" if not blocking_failures else "REJECT"

    report = {
        "verdict": verdict,
        "created_at": pd.Timestamp.utcnow().isoformat(),
        "candidat": str(cand_dir),
        "courant": str(cur_dir) if cur_dir else None,
        "echecs_bloquants": blocking_failures,
        "avertissements": warnings,
        "note": note,
        "tests": [{"nom": r.name, "statut": r.status, "bloquant": r.blocking,
                   "detail": r.detail, "metriques": r.metrics}
                  for r in results],
    }
    if verbose:
        print("\n  " + "-" * 62)
        for r in results:
            flag = "" if r.blocking else " (non bloquant)"
            print(f"  {r.status:4s}  {r.name:22s} {r.detail}{flag}")
        print("  " + "-" * 62)
        print(f"  VERDICT : {verdict}"
              + (f"  -> {blocking_failures}" if blocking_failures else ""))
        if note:
            print(f"  {note}")
    return report


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Gate de validation Sentinel CNN")
    ap.add_argument("--candidate", default=str(AS.candidate_dir()))
    ap.add_argument("--current", default=None)
    ap.add_argument("--out", default=None, help="chemin du rapport JSON")
    a = ap.parse_args(argv)

    cur = a.current or (str(AS.current_dir()) if AS.current_dir() else None)
    report = run_gate(a.candidate, cur)
    out = Path(a.out) if a.out else \
        AS.reports_dir() / f"gate_{pd.Timestamp.utcnow():%Y%m%dT%H%M%S}.json"
    with open(out, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"  rapport -> {out}")
    return 0 if report["verdict"] == "PROMOTE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
