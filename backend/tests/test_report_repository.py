"""
Test de la garantie centrale : une persistance partielle DOIT lever, sinon
l'orchestrateur avance un curseur sur des détections jamais écrites.
"""
import pytest

from core.exceptions import PersistenceError
from repositories.report_repository import MongoReportRepository


class _FakeResult:
    def __init__(self, upserted, matched):
        self.upserted_count = upserted
        self.matched_count = matched


class _FakeCollection:
    """Simule une écriture partielle : n_ok opérations aboutissent."""
    def __init__(self, n_ok=None):
        self.n_ok = n_ok
        self.ops = []

    def bulk_write(self, ops, ordered=True):
        self.ops = ops
        n = len(ops) if self.n_ok is None else self.n_ok
        return _FakeResult(upserted=n, matched=0)


class _FakeDB:
    def __init__(self, coll):
        self._coll = coll

    def __getitem__(self, _name):
        return self._coll


def _repo(coll):
    return MongoReportRepository(db=_FakeDB(coll))


EPISODES = [
    {"episode_id": f"ep-{i}", "verdict": "true_positive", "severity": "high",
     "start": "2026-07-20T10:00:00+00:00"}
    for i in range(3)
]


def test_ecriture_complete_retourne_le_compte():
    assert _repo(_FakeCollection()).save_cnn_episodes(EPISODES, "run-1") == 3


def test_ecriture_partielle_leve():
    """40 épisodes écrits sur 47 renvoyaient « 40 » sans erreur : le curseur
    avançait et 7 épisodes étaient perdus définitivement."""
    with pytest.raises(PersistenceError):
        _repo(_FakeCollection(n_ok=2)).save_cnn_episodes(EPISODES, "run-1")


def test_episode_sans_identifiant_leve():
    episodes = EPISODES + [{"verdict": "true_positive"}]
    with pytest.raises(PersistenceError):
        _repo(_FakeCollection()).save_cnn_episodes(episodes, "run-1")


def test_id_prefixe_par_le_run():
    """Sans le préfixe, une re-détection écrasait le document et son run_id :
    le rapport du run précédent devenait incomplet rétroactivement."""
    coll = _FakeCollection()
    _repo(coll).save_cnn_episodes(EPISODES, "run-1")
    ids = [op._filter["_id"] for op in coll.ops]
    assert ids == ["run-1::ep-0", "run-1::ep-1", "run-1::ep-2"]


def test_alertes_sigma_partielles_levent():
    alerts = [{"title": f"R{i}", "level": "HIGH",
               "event_time": "2026-07-20T10:00:00+00:00"} for i in range(4)]
    with pytest.raises(PersistenceError):
        _repo(_FakeCollection(n_ok=1)).save_sigma_alerts(alerts, "run-1")