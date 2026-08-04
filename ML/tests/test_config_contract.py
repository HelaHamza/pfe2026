"""
test_config_contract.py
=======================
Tests de CONTRAT sur config_cnn.py.

Ces tests ne verifient pas des proprietes theoriques : ils rejouent des bugs
REELLEMENT rencontres sur ce projet. C'est ce qui les rend rentables -- une
suite de tests generique attrape des erreurs qui ne se produisent pas, une
suite construite sur son propre historique de pannes attrape celles qui se
reproduisent.

Correspondance test <-> bug d'origine :

  test_atomic_channels_not_coerced   is_fail neutralise a 0.0 par la coercion
                                     de build_features_shared -> signal SSH
                                     brute-force integralement perdu, sans la
                                     moindre exception.
  test_artifact_paths_absolute       chemins relatifs : les artefacts
                                     atterrissaient dans le cwd du processus,
                                     variable selon le mode de lancement.
  test_dataset_cache_absolute        meme cause, et en plus le cache perime
                                     court-circuite tout reentrainement.
  test_every_source_fully_configured un dictionnaire par source oublie ->
                                     KeyError en plein entrainement, apres des
                                     minutes de calcul.
"""
from __future__ import annotations

import os

import pytest

import config_cnn as C


def test_atomic_channels_excluded_from_known_features():
    """is_fail ne doit JAMAIS etre coerce avant son calcul reel.

    Le bug : build_features_shared force a 0.0 toute colonne de
    KNOWN_FEATURES absente. Si is_fail y figure, la colonne est creee a 0.0
    AVANT le calcul -> le canal est neutralise partout. Aucune erreur, aucun
    avertissement : les echecs d'authentification deviennent invisibles.
    """
    assert C.ATOMIC_CHANNELS, "ATOMIC_CHANNELS ne doit pas etre vide"
    assert not (C.KNOWN_FEATURES & C.ATOMIC_CHANNELS), (
        f"Canaux atomiques presents dans KNOWN_FEATURES : "
        f"{C.KNOWN_FEATURES & C.ATOMIC_CHANNELS}")


def test_atomic_channels_are_declared_features():
    """Un canal atomique doit rester utilise par au moins une source."""
    all_feats = set().union(*(set(v) for v in C.CNN_FEATURES.values()))
    orphans = C.ATOMIC_CHANNELS - all_feats
    assert not orphans, f"Canaux atomiques inutilises : {orphans}"


def test_known_features_is_exact_complement():
    all_feats = set().union(*(set(v) for v in C.CNN_FEATURES.values()))
    assert C.KNOWN_FEATURES == all_feats - C.ATOMIC_CHANNELS


@pytest.mark.parametrize("name", [
    "MODEL_PATH", "BUNDLE_PATH", "THRESH_PATH", "NOVELTY_STATE_PATH"])
def test_artifact_paths_absolute(name):
    """Un chemin relatif depend du cwd. Le timer systemd n'a pas le meme cwd
    qu'un shell interactif : les artefacts partiraient ailleurs."""
    assert os.path.isabs(getattr(C, name)), f"{name} doit etre absolu"


def test_dataset_cache_absolute():
    """DATASET_CACHE doit etre absolu ET suivre ARTIFACT_DIR.

    Sans cela, le cycle mensuel relit le snapshot du mois precedent et
    reentraine sur des donnees perimees en produisant un modele "neuf"
    strictement identique a l'ancien. Panne totalement silencieuse.
    """
    assert os.path.isabs(C.DATASET_CACHE), "DATASET_CACHE doit etre absolu"
    assert hasattr(C, "ARTIFACT_DIR"), (
        "config_cnn.ARTIFACT_DIR absent : le patch d'isolation du candidat "
        "n'a pas ete applique (cf. PATCH_config_cnn.md).")
    assert C.DATASET_CACHE.startswith(C.ARTIFACT_DIR)


def test_artifacts_follow_artifact_dir():
    for name in ("MODEL_PATH", "BUNDLE_PATH", "THRESH_PATH",
                 "NOVELTY_STATE_PATH"):
        assert getattr(C, name).startswith(C.ARTIFACT_DIR), (
            f"{name} ne suit pas ARTIFACT_DIR : l'isolation du candidat est "
            f"incomplete, le training ecraserait la production.")


@pytest.mark.parametrize("mapping", [
    "CNN_FEATURES", "WINDOW_KEY", "LATENT_DIM_BY_SOURCE",
    "EPOCHS_BY_SOURCE", "PATIENCE_BY_SOURCE", "LR_BY_SOURCE",
    "SCORE_LSE_TAU_BY_SOURCE", "SOURCE_ROLE"])
def test_every_source_fully_configured(mapping):
    d = getattr(C, mapping)
    missing = set(C.SOURCES) - set(d)
    assert not missing, f"{mapping} : sources manquantes {missing}"


def test_pot_rates_are_valid_probabilities():
    for src, rate in C.POT_TARGET_RATE_BY_SOURCE.items():
        assert 0 < rate < 1, f"{src}: taux POT invalide {rate}"
        assert rate < 1 - C.POT_INIT_Q + 0.05, (
            f"{src}: taux cible {rate} incoherent avec POT_INIT_Q="
            f"{C.POT_INIT_Q} (le seuil de depart doit etre plus bas que le "
            f"niveau vise, sinon l'extrapolation GPD n'a plus de sens)")


def test_pot_xi_bounds_are_ordered():
    assert C.POT_XI_MIN < 0 < C.POT_XI_MAX
    assert C.POT_XI_MAX < 1.0, (
        "xi >= 1 implique une esperance infinie : la borne haute doit rester "
        "strictement inferieure a 1.")


def test_window_and_stride():
    assert C.WINDOW_SIZE >= 2
    assert C.WINDOW_STRIDE >= 1
    assert C.WINDOW_STRIDE <= C.WINDOW_SIZE


def test_split_ratios_sum_to_one():
    assert abs(sum(C.SPLIT_RATIOS) - 1.0) < 1e-9
    assert 0 < C.VAL_RATIO < 1


def test_seed_is_fixed():
    """La reproductibilite est une exigence de l'architecture (LLM a
    temperature=0/seed=42) : elle doit valoir aussi pour la branche CNN."""
    assert C.SEED == 42
