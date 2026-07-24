"""
models/dashboard_model.py
=========================
Contrat de sortie du dashboard SOC.

Deux garanties apportées :
  1. FORME STABLE JUSQU'AU DERNIER NIVEAU. `stats` est toujours un
     ReportStats complet (zéros si aucun run) et non un dict vide : le
     front n'a plus à distinguer « pas de données » de « données à zéro »
     dans son rendu.
  2. STATUT VISIBLE. Depuis qu'un run peut être `partial`, un « 0 alerte
     Sigma » peut signifier « rien détecté » OU « branche jamais exécutée ».
     Sur un outil de sécurité, ces deux zéros ne peuvent pas s'afficher de
     la même façon : `status` + `errors` permettent au front de poser un
     bandeau d'avertissement.
"""
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from models.enums import ReportStatus
from models.report_model import ReportStats, TacticCount


class DashboardResponse(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    has_data: bool
    status: ReportStatus | None = Field(
        default=None,
        description="completed | partial | failed. `partial` ⇒ afficher un "
                    "avertissement : une branche de détection a échoué.")
    errors: list[str] = Field(default_factory=list)

    last_started_at: datetime | None = None
    last_finished_at: datetime | None = None

    stats: ReportStats = Field(default_factory=ReportStats)
    cnn_by_severity: dict[str, int] = Field(default_factory=dict)
    cnn_by_verdict: dict[str, int] = Field(default_factory=dict)
    sigma_by_level: dict[str, int] = Field(default_factory=dict)
    logs_by_source: dict[str, int] = Field(default_factory=dict)
    by_tactic: list[TacticCount] = Field(default_factory=list)