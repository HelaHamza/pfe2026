"""
models/report_model.py
======================
Snapshot d'un run du pipeline.

Avant : `save_report(run_id, started_at, **blocks)` — la structure du rapport
n'était écrite NULLE PART, elle vivait implicitement dans l'appelant. Toute
faute de frappe dans un nom de bloc produisait un rapport silencieusement
amputé, et le dashboard affichait 0.
"""
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from models.enums import ReportStatus


class TacticCount(BaseModel):
    tactic: str
    count: int


class ReportStats(BaseModel):
    """Compteurs affichés en tête du dashboard SOC."""
    cnn_episodes: int = 0
    cnn_kept: int = Field(default=0, description="Épisodes true_positive → SOC.")
    cnn_to_review: int = Field(
        default=0,
        description="Épisodes uncertain / fail-open → dashboard Expert AI. "
                    "JAMAIS écartés silencieusement.")
    sigma_alerts: int = 0
    cnn_critical: int = 0
    sigma_critical: int = 0
    logs_total: int = 0
    noise_reduction_pct: float = Field(
        default=0.0,
        description="100 × false_positive / total_épisodes. "
                    "DÉNOMINATEUR = TOUS les épisodes. Les `uncertain` ne "
                    "comptent PAS comme réduction : ils restent du travail "
                    "analyste, simplement déporté vers l'Expert AI.")


class Report(BaseModel):
    """Document de la collection `reports`."""
    model_config = ConfigDict(use_enum_values=True)

    analysis_id: str
    started_at: datetime
    finished_at: datetime
    status: ReportStatus
    generated_by: str = "pipeline_cnn_v1"
    errors: list[str] = Field(
        default_factory=list,
        description="Messages d'erreur par branche en cas de statut partial/failed.")

    stats: ReportStats = Field(default_factory=ReportStats)
    cnn_by_severity: dict[str, int] = Field(default_factory=dict)
    cnn_by_verdict: dict[str, int] = Field(default_factory=dict)
    sigma_by_level: dict[str, int] = Field(default_factory=dict)
    logs_by_source: dict[str, int] = Field(default_factory=dict)
    by_tactic: list[TacticCount] = Field(default_factory=list)