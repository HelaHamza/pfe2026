"""
test_artifact_store.py
======================
Le store est le socle : si la promotion n'est pas atomique ou si une alteration
passe inapercue, tout le reste du gate ne sert a rien.

Ces tests n'ont besoin ni de donnees ni de modele entraine : ils travaillent
sur une arborescence temporaire. Ils tournent donc en CI en quelques secondes.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from retraining import artifact_store as AS
from retraining import retrain_config as RC


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(RC, "ARTIFACTS_ROOT", str(tmp_path / "artifacts"))
    return tmp_path / "artifacts"


def _fake_version(root: Path, name: str) -> Path:
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    for f in AS.REQUIRED_FILES:
        (d / f).write_bytes(f"contenu-{name}-{f}".encode())
    return d


# ===========================================================================
# Manifest et empreintes
# ===========================================================================
def test_manifest_records_all_files(store, monkeypatch):
    monkeypatch.setattr(AS, "_config_fingerprint", lambda: {"hash": "test"})
    d = _fake_version(AS.artifacts_root(), "2026-08-01")
    man = AS.write_manifest(d)
    assert set(man["files"]) == set(AS.REQUIRED_FILES)
    assert (d / "manifest.json").exists()
    assert AS.verify_hashes(d) == []


def test_tampering_is_detected(store, monkeypatch):
    """Le coeur du test d'integrite : un octet change doit etre vu."""
    monkeypatch.setattr(AS, "_config_fingerprint", lambda: {"hash": "test"})
    d = _fake_version(AS.artifacts_root(), "2026-08-01")
    AS.write_manifest(d)
    (d / "cnn_thresholds.pkl").write_bytes(b"altere")
    problems = AS.verify_hashes(d)
    assert len(problems) == 1
    assert "cnn_thresholds.pkl" in problems[0]


def test_missing_file_is_detected(store, monkeypatch):
    monkeypatch.setattr(AS, "_config_fingerprint", lambda: {"hash": "test"})
    d = _fake_version(AS.artifacts_root(), "2026-08-01")
    AS.write_manifest(d)
    (d / "cnn_novelty_state.pkl").unlink()
    assert any("cnn_novelty_state" in p for p in AS.verify_hashes(d))


def test_manifest_absent_is_reported(store):
    d = _fake_version(AS.artifacts_root(), "2026-08-01")
    assert AS.verify_hashes(d) == [f"{d.name}: manifest.json absent"]


# ===========================================================================
# Symlink atomique
# ===========================================================================
def test_atomic_symlink_switch(store):
    root = AS.artifacts_root()
    _fake_version(root, "2026-07-01")
    _fake_version(root, "2026-08-01")
    link = AS.current_link()

    AS._atomic_symlink("2026-07-01", link)
    assert link.is_symlink() and AS.current_version() == "2026-07-01"

    AS._atomic_symlink("2026-08-01", link)
    assert AS.current_version() == "2026-08-01"


def test_symlink_target_is_relative(store):
    """Cible relative = arborescence deplacable (sauvegarde, changement de
    machine) sans casser `current`."""
    root = AS.artifacts_root()
    _fake_version(root, "2026-08-01")
    AS._atomic_symlink("2026-08-01", AS.current_link())
    assert not os.path.isabs(os.readlink(AS.current_link()))


def test_refuses_to_replace_a_real_directory(store):
    """Garde-fou : si `current` est un vrai repertoire (bascule manuelle mal
    faite), on refuse plutot que d'ecraser des artefacts."""
    root = AS.artifacts_root()
    _fake_version(root, "2026-08-01")
    (root / RC.CURRENT_LINKNAME).mkdir(parents=True)
    with pytest.raises(RuntimeError, match="PAS un symlink"):
        AS._atomic_symlink("2026-08-01", AS.current_link())


# ===========================================================================
# Rejet et versions
# ===========================================================================
def test_reject_moves_never_deletes(store, monkeypatch):
    """Doctrine du projet : `mv`, jamais `rm`, sur ce qui porte un resultat."""
    monkeypatch.setattr(AS, "_config_fingerprint", lambda: {"hash": "test"})
    root = AS.artifacts_root()
    cand = _fake_version(root, RC.CANDIDATE_DIRNAME)
    dest = AS.reject(cand, "2026-08-01", "golden_set")
    assert not cand.exists()
    assert dest.exists() and dest.parent.name == RC.REJECTED_DIRNAME
    man = json.loads((dest / "manifest.json").read_text())
    assert man["status"] == "rejected"
    assert man["rejection"] == "golden_set"


def test_reject_twice_does_not_overwrite(store, monkeypatch):
    monkeypatch.setattr(AS, "_config_fingerprint", lambda: {"hash": "test"})
    root = AS.artifacts_root()
    d1 = AS.reject(_fake_version(root, RC.CANDIDATE_DIRNAME), "2026-08-01", "a")
    d2 = AS.reject(_fake_version(root, RC.CANDIDATE_DIRNAME), "2026-08-01", "b")
    assert d1 != d2 and d1.exists() and d2.exists()


def test_new_version_id_avoids_collision(store):
    root = AS.artifacts_root()
    from datetime import datetime, timezone
    now = datetime(2026, 8, 1, tzinfo=timezone.utc)
    v1 = AS.new_version_id(now)
    assert v1 == "2026-08-01"
    _fake_version(root, v1)
    assert AS.new_version_id(now) == "2026-08-01_2"


def test_list_versions_excludes_private_dirs(store):
    root = AS.artifacts_root()
    _fake_version(root, "2026-07-01")
    _fake_version(root, "2026-08-01")
    _fake_version(root, RC.CANDIDATE_DIRNAME)
    (root / RC.REJECTED_DIRNAME).mkdir(exist_ok=True)
    assert AS.list_versions() == ["2026-07-01", "2026-08-01"]


def test_rollback_without_argument_targets_previous(store, monkeypatch):
    monkeypatch.setattr(AS, "check_artifact_set", lambda d, **k: [])
    root = AS.artifacts_root()
    _fake_version(root, "2026-07-01")
    _fake_version(root, "2026-08-01")
    AS._atomic_symlink("2026-08-01", AS.current_link())
    AS.rollback()
    assert AS.current_version() == "2026-07-01"


def test_rollback_refuses_incoherent_version(store, monkeypatch):
    monkeypatch.setattr(AS, "check_artifact_set",
                        lambda d, **k: ["artefact manquant"])
    root = AS.artifacts_root()
    _fake_version(root, "2026-07-01")
    with pytest.raises(RuntimeError, match="incoherente"):
        AS.rollback("2026-07-01")


def test_promote_refuses_existing_version(store, monkeypatch):
    monkeypatch.setattr(AS, "check_artifact_set", lambda d, **k: [])
    monkeypatch.setattr(AS, "_config_fingerprint", lambda: {"hash": "test"})
    root = AS.artifacts_root()
    _fake_version(root, "2026-08-01")
    cand = _fake_version(root, RC.CANDIDATE_DIRNAME)
    with pytest.raises(RuntimeError, match="existe deja"):
        AS.promote(cand, "2026-08-01")


def test_promote_then_current_points_to_new_version(store, monkeypatch):
    monkeypatch.setattr(AS, "check_artifact_set", lambda d, **k: [])
    monkeypatch.setattr(AS, "_config_fingerprint", lambda: {"hash": "test"})
    root = AS.artifacts_root()
    cand = _fake_version(root, RC.CANDIDATE_DIRNAME)
    AS.promote(cand, "2026-08-01")
    assert AS.current_version() == "2026-08-01"
    assert not cand.exists()
    man = AS.read_manifest(root / "2026-08-01")
    assert man["status"] == "promoted"
