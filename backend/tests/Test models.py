"""
Tests de la couche Modèle — chacun est lié à un bug réellement rencontré.
"""
from datetime import timezone

import pytest

from core.timeutils import to_utc
from models.detection_models import ResultRow
from models.enums import Severity


# ── Bug : tri lexicographique cassé par le format pandas ──────────────
@pytest.mark.parametrize("raw", [
    "2026-07-20T10:00:00+00:00",
    "2026-07-20T10:00:00Z",
    "2026-07-20 10:00:00",          # sérialisation pandas (espace, pas de 'T')
    "2026-07-20T10:00:00",          # naïf → présumé UTC
])
def test_formats_temporels_convergent(raw):
    dt = to_utc(raw)
    assert dt is not None
    assert dt.tzinfo is not None
    assert dt.astimezone(timezone.utc).hour == 10


def test_timestamp_illisible_ne_leve_pas():
    """Un timestamp corrompu ne doit jamais faire tomber une écriture."""
    assert to_utc("pas une date") is None
    assert to_utc(None) is None


# ── Bug : level "UNKNOWN" rendait l'alerte infiltrable ────────────────
def test_severite_inconnue_retombe_sur_low():
    row = ResultRow.from_sigma({
        "dedup_key": "k1", "level": "UNKNOWN", "title": "Règle sans level",
        "event_time": "2026-07-20T10:00:00+00:00",
    })
    assert row.severity == Severity.low.value


def test_severite_sigma_majuscule_normalisee():
    row = ResultRow.from_sigma({
        "dedup_key": "k2", "level": "CRITICAL", "title": "Brute force",
        "event_time": "2026-07-20T10:00:00+00:00",
    })
    assert row.severity == Severity.critical.value


# ── Bug : fuite de champs internes vers le client ─────────────────────
def test_champs_internes_non_exposes():
    row = ResultRow.from_cnn({
        "episode_id": "ep-1", "verdict": "true_positive", "severity": "high",
        "start": "2026-07-20T10:00:00+00:00",
        "run_id": "SECRET", "indexed_at": "2026-07-20T11:00:00+00:00",
        "llm_model": "gpt-oss-120b", "dedup_key": "ep-1",
    })
    payload = row.model_dump()
    for interne in ("run_id", "indexed_at", "llm_model", "dedup_key"):
        assert interne not in payload