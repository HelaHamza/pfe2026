"""
models/report_model.py
======================
Snapshot d'un run du pipeline.

Avant : `save_report(run_id, started_at, **blocks)` — la structure du rapport
n'était écrite NULLE PART, elle vivait implicitement dans l'appelant. Toute
faute de frappe dans un nom de bloc produisait un rapport silencieusement
amputé, et le dashboard affichait 0.

MODE EXPLICATION SEULE : le LLM ne filtre plus, il explique et priorise. Le
verdict est constant (true_positive). Les compteurs de filtrage (`cnn_to_review`,
`noise_reduction_pct`) sont CONSERVÉS à 0 pour ne pas casser le contrat du
dashboard, mais ils n'ont plus de dynamique.
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
    cnn_kept: int = Field(
        default=0,
        description="Épisodes conservés → SOC. Le LLM ne filtrant plus, "
                    "cnn_kept == cnn_episodes.")
    cnn_to_review: int = Field(
        default=0,
        description="Hérité de l'ancienne cascade (file de revue Expert AI). "
                    "Toujours 0 en mode explication seule — conservé pour la "
                    "compatibilité du contrat dashboard.")
    sigma_alerts: int = 0
    cnn_critical: int = 0
    sigma_critical: int = 0
    logs_total: int = 0
    noise_reduction_pct: float = Field(
        default=0.0,
        description="Hérité de l'ancienne cascade filtrante. Toujours 0.0 : le "
                    "LLM n'écarte plus aucune alerte. Conservé pour la "
                    "compatibilité du contrat dashboard.")


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
    # Verdict constant en mode explication seule → {"true_positive": N}.
    cnn_by_verdict: dict[str, int] = Field(default_factory=dict)
    sigma_by_level: dict[str, int] = Field(default_factory=dict)
    logs_by_source: dict[str, int] = Field(default_factory=dict)
    # Anomalies AE ventilées par source de log. Somme = cnn_episodes.
    anomalies_by_source: dict[str, int] = Field(default_factory=dict)
    by_tactic: list[TacticCount] = Field(default_factory=list)