"""
controllers/stats_controller.py
===============================
Lecteur du dernier snapshot Mongo. Le dashboard ne lit QUE le snapshot
(déterminisme : deux affichages du même run donnent le même écran, aucun
recalcul à la volée).
"""
import logging

from models.dashboard_model import DashboardResponse
from models.report_model import ReportStats, TacticCount
from repositories.report_repository import ReportRepository

log = logging.getLogger(__name__)


class StatsController:

    @staticmethod
    def dashboard() -> DashboardResponse:
        r = ReportRepository.get_last_report()
        if not r:
            # Forme identique à la branche pleine, JUSQU'AUX SOUS-OBJETS :
            # `stats` est un ReportStats à zéro, pas un dict vide.
            return DashboardResponse(has_data=False)

        tactics = []
        for t in (r.get("by_tactic") or []):
            try:
                tactics.append(TacticCount(**t))
            except Exception as e:
                log.warning("by_tactic malformé ignoré (%s) : %s", t, e)

        return DashboardResponse(
            has_data=True,
            status=r.get("status"),
            errors=r.get("errors") or [],
            last_started_at=r.get("started_at"),
            last_finished_at=r.get("finished_at"),
            stats=ReportStats(**(r.get("stats") or {})),
            cnn_by_severity=r.get("cnn_by_severity") or {},
            cnn_by_verdict=r.get("cnn_by_verdict") or {},
            sigma_by_level=r.get("sigma_by_level") or {},
            logs_by_source=r.get("logs_by_source") or {},
            by_tactic=tactics,
        )