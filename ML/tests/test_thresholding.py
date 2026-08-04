"""
test_thresholding.py
====================
Regression sur _pot_threshold : chaque garde-fou est verifie.

Le calibrage du seuil est le composant le plus fragile de la chaine parce
qu'il est le seul dont une defaillance ne provoque AUCUNE erreur : un seuil
trop bas noie l'analyste, un seuil trop haut supprime toute detection. Dans
les deux cas le pipeline s'execute normalement de bout en bout.

Le cas reel rejoue ici : auth avait produit xi=-2.45, ce qui pretendait
"score <= ~3.01" alors que le test montrait p99=19. Le garde-fou bilateral sur
xi a ete ajoute pour cela ; ce test verifie qu'il ne disparaitra pas au
detour d'une refactorisation.
"""
from __future__ import annotations

import numpy as np
import pytest

import config_cnn as C
import thresholding as TH


def test_empty_scores_returns_inf():
    """Pas de donnees de calibration = aucune alerte, jamais toutes."""
    thr, info = TH._pot_threshold(np.array([]))
    assert thr == float("inf")
    assert info["method"] == "empty"


def test_few_excess_falls_back_to_empirical():
    scores = np.concatenate([np.zeros(500), np.ones(3)])
    thr, info = TH._pot_threshold(scores, target_rate=0.005, min_excess=30)
    assert info["method"] == "quantile_fallback"
    assert info["reason"] == "few_excess"


def test_threshold_never_below_empirical_quantile():
    """PLANCHER : la GPD ne peut rendre le seuil que PLUS conservateur.

    Sans ce plancher, auditd s'etait retrouve avec un seuil sous son propre
    p99 -- soit un taux d'alerte superieur a 1 %.
    """
    rng = np.random.default_rng(0)
    for dist in (rng.exponential(1.0, 20000),
                 rng.lognormal(0, 1, 20000),
                 rng.pareto(3.0, 20000)):
        rate = 0.005
        thr, info = TH._pot_threshold(dist, target_rate=rate)
        emp = float(np.quantile(dist, 1 - rate))
        assert thr >= emp - 1e-9, (
            f"seuil {thr} sous le quantile empirique {emp} "
            f"(methode={info['method']})")


def test_xi_too_low_is_rejected():
    """xi tres negatif = support borne artificiel -> hors regime MLE."""
    rng = np.random.default_rng(1)
    # Distribution a support strictement borne : pousse le MLE vers xi << 0.
    scores = rng.uniform(0, 1, 30000)
    thr, info = TH._pot_threshold(scores, target_rate=0.005)
    if info["method"] == "gpd_pot":
        assert info["xi"] >= C.POT_XI_MIN
    else:
        assert info["reason"] in ("xi_too_low", "xi_too_high", "few_excess",
                                 "non_finite", "xi_non_finite")


def test_xi_bounds_enforced_whenever_gpd_is_used():
    rng = np.random.default_rng(2)
    for a in (1.2, 2.0, 3.0, 5.0):
        scores = rng.pareto(a, 30000)
        _, info = TH._pot_threshold(scores, target_rate=0.002)
        if info["method"] == "gpd_pot":
            assert C.POT_XI_MIN <= info["xi"] <= C.POT_XI_MAX


def test_threshold_is_finite_and_positive_on_realistic_scores():
    rng = np.random.default_rng(3)
    scores = np.abs(rng.normal(2.0, 1.0, 50000))
    thr, info = TH._pot_threshold(scores, target_rate=0.0025)
    assert np.isfinite(thr) and thr > 0
    assert info["method"] in ("gpd_pot", "quantile_fallback")


@pytest.mark.parametrize("rate", [0.01, 0.005, 0.002, 0.001])
def test_lower_target_rate_gives_higher_threshold(rate):
    """Monotonie : viser moins d'alertes doit remonter le seuil."""
    rng = np.random.default_rng(4)
    scores = rng.exponential(1.0, 50000)
    thr, _ = TH._pot_threshold(scores, target_rate=rate)
    thr_loose, _ = TH._pot_threshold(scores, target_rate=0.02)
    assert thr >= thr_loose - 1e-9


def test_get_threshold_accepts_both_shapes():
    """thresholds[src] est un dict en sortie de training, parfois un float
    dans des artefacts plus anciens. get_threshold doit absorber les deux."""
    assert TH.get_threshold({"auth": {"threshold": 4.2}}, "auth") == 4.2
    assert TH.get_threshold({"auth": 4.2}, "auth") == 4.2
    assert TH.get_threshold({}, "auth") == float("inf")
