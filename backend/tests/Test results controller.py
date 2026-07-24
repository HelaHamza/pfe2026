"""
Test de la fusion CNN + Sigma : les alertes Sigma remontaient
systématiquement en tête parce qu'elles portaient l'heure du run et non
celle de l'événement.
"""
import controllers.results_controller as rc


class _StubRepo:
    def __init__(self, docs, total=None):
        self._docs = docs
        self._total = total if total is not None else len(docs)

    def get_last_report(self):
        return {"analysis_id": "run-1"}

    def count_results(self, run_id, level=None, source=None, **kw):
        return self._total

    def get_results(self, run_id, level=None, source=None, limit=500, **kw):
        """Reproduit fidèlement le vrai repository : la limite s'applique
        PAR COLLECTION, pas à la liste fusionnée. C'est ce qui rend correct
        le fait de demander skip+limit à chaque source — la page finale peut
        provenir intégralement de l'une ou de l'autre."""
        out = []
        for kind in ("cnn", "sigma"):
            if source in (None, kind):
                subset = sorted(
                    (d for d in self._docs if d["type"] == kind),
                    key=lambda d: d["event_time"], reverse=True)
                out += subset[:limit]
        return out


DOCS = [
    {"type": "sigma", "dedup_key": "s1", "level": "HIGH", "title": "Sigma ancien",
     "event_time": "2026-07-20T08:00:00+00:00"},
    {"type": "cnn", "episode_id": "c1", "severity": "high", "verdict": "true_positive",
     "title": "CNN récent", "start": "2026-07-20T12:00:00+00:00",
     "event_time": "2026-07-20T12:00:00+00:00"},
    {"type": "sigma", "dedup_key": "s2", "level": "CRITICAL", "title": "Sigma récent",
     "event_time": "2026-07-20T10:00:00+00:00"},
]


def test_tri_chronologique_toutes_sources_confondues(monkeypatch):
    monkeypatch.setattr(rc, "ReportRepository", _StubRepo(DOCS))
    resp = rc.ResultsController.get_results()
    titres = [r.title for r in resp.results]
    assert titres == ["CNN récent", "Sigma récent", "Sigma ancien"]


def test_total_reflete_la_base_pas_la_page(monkeypatch):
    """`total` valait len(rows) APRÈS troncature : l'API annonçait 500 sur
    900 résultats et la pagination était impossible."""
    monkeypatch.setattr(rc, "ReportRepository", _StubRepo(DOCS, total=900))
    resp = rc.ResultsController.get_results(limit=2)
    assert resp.total == 900
    assert resp.count == 2


def test_pagination(monkeypatch):
    monkeypatch.setattr(rc, "ReportRepository", _StubRepo(DOCS))
    resp = rc.ResultsController.get_results(limit=1, skip=1)
    assert [r.title for r in resp.results] == ["Sigma récent"]


def test_absence_de_rapport_renvoie_une_reponse_vide(monkeypatch):
    class _Empty(_StubRepo):
        def get_last_report(self):
            return None
    monkeypatch.setattr(rc, "ReportRepository", _Empty([]))
    resp = rc.ResultsController.get_results()
    assert resp.total == 0 and resp.results == []