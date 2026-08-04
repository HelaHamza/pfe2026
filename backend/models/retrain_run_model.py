"""
models/retrain_run_model.py
===========================
Domaine C : santé du ré-entraînement. Un document par TENTATIVE de gate
(validation_gate.py → gate_*.json), acceptée ou rejetée. La collection
`retrain_runs` rend durable et interrogeable ce que le gate ne gardait que
sur disque : pourquoi un candidat passe ou non, et l'évolution dans le temps.
Le gate reste seul juge — on expose ses verdicts, on ne les réinterprète pas.
extra="allow" : un nouveau test du gate est stocké et affiché sans modif ici.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

_LOOSE = ConfigDict(extra="allow")


class GateTest(BaseModel):
    """Un test du gate, tel quel. `metriques` reste libre : sa forme dépend
    du test (golden_set ≠ seuils_pot ≠ distribution_scores)."""
    model_config = _LOOSE
    nom: str
    statut: str                        # PASS | FAIL
    bloquant: bool = False
    detail: str | None = None
    metriques: dict = Field(default_factory=dict)


class RetrainRunDocument(BaseModel):
    """Document stocké dans `retrain_runs`. Dédup sur created_at."""
    model_config = _LOOSE
    created_at: datetime
    ingested_at: datetime
    verdict: str                       # ACCEPT | REJECT (brut du gate)
    accepted: bool                     # dérivé : verdict commence par ACCEPT
    candidate_version: str | None = None
    current_version: str | None = None
    echecs_bloquants: list[str] = Field(default_factory=list)
    avertissements: list[str] = Field(default_factory=list)
    note: str | None = None
    tests: list[GateTest] = Field(default_factory=list)
    quarantine_count: int = 0


# ── Sous-blocs de sortie ────────────────────────────────────────────────────
class GoldenResult(BaseModel):
    """golden_set : recall épisodique candidat vs baseline déployée, par
    attaque. Alimente le recall par attaque + régressions en carte ②."""
    recall: float | None = None
    n_incidents: int = 0
    detected: dict[str, bool] = Field(default_factory=dict)   # candidat
    baseline: dict[str, bool] = Field(default_factory=dict)   # courant déployé
    regressions: list[str] = Field(default_factory=list)


class AcceptanceStats(BaseModel):
    n_total: int = 0
    n_accepted: int = 0
    n_rejected: int = 0
    acceptance_rate: float = 0.0       # % ACCEPT


class GateHistoryPoint(BaseModel):
    created_at: datetime | None = None
    verdict: str | None = None
    accepted: bool = False
    failed_tests: list[str] = Field(default_factory=list)


class RetrainLast(BaseModel):
    created_at: datetime | None = None
    verdict: str | None = None
    accepted: bool = False
    candidate_version: str | None = None
    current_version: str | None = None
    echecs_bloquants: list[str] = Field(default_factory=list)
    avertissements: list[str] = Field(default_factory=list)
    note: str | None = None
    reason: str | None = None          # phrase POURQUOI, prête pour le jury


def _gate_reason(run: RetrainRunDocument) -> str:
    """Phrase d'affichage : POURQUOI ce verdict, en clair."""
    if run.echecs_bloquants:
        return ("Rejeté — tests bloquants échoués : "
                + ", ".join(run.echecs_bloquants))
    if run.accepted:
        base = "Accepté — tous les tests bloquants passés"
        if run.avertissements:
            return f"{base} (avertissements : {'; '.join(run.avertissements)})."
        return base + "."
    return run.note or "Verdict sans détail."


class RetrainingResponse(BaseModel):
    has_data: bool
    reason: str | None = None          # état vide (« aucun gate exécuté »)
    last: RetrainLast | None = None
    golden: GoldenResult | None = None
    gate_tests: list[GateTest] = Field(default_factory=list)
    history: list[GateHistoryPoint] = Field(default_factory=list)
    acceptance: AcceptanceStats = Field(default_factory=AcceptanceStats)
    quarantine_count: int = 0

    @classmethod
    def from_document(cls, doc: dict, history: list[dict],
                      acceptance: AcceptanceStats) -> "RetrainingResponse":
        run = RetrainRunDocument.model_validate(doc)

        golden = None
        for t in run.tests:
            if t.nom == "golden_set":
                m = t.metriques or {}
                golden = GoldenResult(
                    recall=m.get("recall"),
                    n_incidents=m.get("n_incidents", 0),
                    detected=m.get("detecte", {}) or {},
                    baseline=m.get("baseline_courant", {}) or {},
                    regressions=m.get("regressions", []) or [],
                )
                break

        hist = []
        for h in history:
            hr = RetrainRunDocument.model_validate(h)
            hist.append(GateHistoryPoint(
                created_at=hr.created_at, verdict=hr.verdict,
                accepted=hr.accepted, failed_tests=hr.echecs_bloquants))

        return cls(
            has_data=True,
            last=RetrainLast(
                created_at=run.created_at, verdict=run.verdict,
                accepted=run.accepted,
                candidate_version=run.candidate_version,
                current_version=run.current_version,
                echecs_bloquants=run.echecs_bloquants,
                avertissements=run.avertissements, note=run.note,
                reason=_gate_reason(run)),
            golden=golden,
            gate_tests=run.tests,
            history=hist,
            acceptance=acceptance,
            quarantine_count=run.quarantine_count,
        )