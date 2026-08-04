"""
models/dashboard_model.py
=========================
Contrat de sortie de GET /dashboard : snapshot du dernier run publié.
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
    # Anomalies AE (true_positive) par source → taux d'anomalie par type de log.
    anomalies_by_source: dict[str, int] = Field(default_factory=dict)
    by_tactic: list[TacticCount] = Field(default_factory=list)