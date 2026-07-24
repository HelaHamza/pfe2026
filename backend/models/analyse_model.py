"""
models/analyse_model.py
=======================
Contrats de l'API d'orchestration.

Le journal d'exécution (`logs`) est typé lui aussi : c'est ce que le
frontend affiche en direct pendant un run, et une clé manquante y produit
un écran vide sans message d'erreur.
"""
from datetime import datetime

from pydantic import BaseModel, Field


class LogEntry(BaseModel):
    ts: datetime
    msg: str


class AnalyseTrigger(BaseModel):
    started: bool = Field(description="False si un run était déjà en cours.")
    run_id: str | None = None
    message: str


class AnalyseStatus(BaseModel):
    running: bool
    done: bool
    run_id: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = Field(
        default=None,
        description="Erreurs concaténées des branches. Non nul avec "
                    "done=True ⇒ run partiel : une branche a échoué, "
                    "le dashboard doit l'indiquer.")
    logs: list[LogEntry] = Field(default_factory=list)