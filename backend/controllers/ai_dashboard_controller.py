import logging

from adapters.cnn_report_adapter import CnnReportAdapter
from adapters.cnn_eval_adapter import CnnEvalAdapter
from models.ai_dashboard_model import (AIOverviewResponse, EvalComparisonResponse,
                                        FrozenModelResponse, PrioritizationSummary,
                                        RunTrendPoint, TriageQuality, TriageResponse)
from models.retrain_run_model import RetrainingResponse
from repositories.report_repository import ReportRepository
from repositories.retrain_repository import RetrainRepository

log = logging.getLogger(__name__)


class StatsControllerAI:

    # ══ ① Modèle en production (identité + calibration) ════════════════
    @staticmethod
    def frozen_model() -> FrozenModelResponse:
        """cnn_evaluation_report.json (seuils POT, fenêtres, forme) + dernier
        gate ACCEPTé (version, promotion) + dernier report (triage). Recall/
        precision NE SONT PAS ici : voir ④ (seule source à vérité terrain)."""
        return FrozenModelResponse.assemble(
            cnn_report=CnnReportAdapter.load(),
            accepted_gate=RetrainRepository.last_accepted(),
            report=ReportRepository.get_last_report())

    # ══ ③ Priorisation live (mode explication seule) ═══════════════════
    @staticmethod
    def _prioritization(sev: dict[str, int], n_fail_open: int) -> PrioritizationSummary:
        """Le LLM ne filtre plus : le signal utile est la répartition de
        sévérité (priorisation) et le fail-open (fiabilité), pas un entonnoir."""
        total = sum(sev.values())
        n_ch = sev.get("critical", 0) + sev.get("high", 0)
        return PrioritizationSummary(
            total_episodes=total,
            by_severity=sev,
            n_critical_high=n_ch,
            n_fail_open=n_fail_open,
            fail_open_pct=round(100 * n_fail_open / total, 1) if total else 0.0,
        )

    @staticmethod
    def overview(trend_limit: int = 10) -> AIOverviewResponse:
        report = ReportRepository.get_last_report()
        if not report:
            return AIOverviewResponse(
                has_data=False,
                errors=["Aucun run publié — lance une analyse pour alimenter "
                        "le dashboard."])

        run_id = report["analysis_id"]
        sev = ReportRepository.cnn_severity_breakdown(run_id)
        # n_fail_open vient du résumé de triage attaché au report (D). Absent
        # si le triage n'a pas été ingéré → 0, la priorisation reste affichable.
        n_fail_open = int((report.get("triage") or {}).get("n_fail_open") or 0)
        prio = StatsControllerAI._prioritization(sev, n_fail_open)

        # Tendance : on LIT le breakdown figé dans chaque report (cnn_by_severity
        # + triage.n_fail_open) au lieu de ré-agréger par run (N+1 requêtes,
        # divergence possible sur un run partiel). Le report est la vérité publiée.
        trend = []
        for r in ReportRepository.list_recent_reports(limit=trend_limit):
            r_sev = r.get("cnn_by_severity", {}) or {}
            r_total = sum(r_sev.values())
            r_fo = int((r.get("triage") or {}).get("n_fail_open") or 0)
            trend.append(RunTrendPoint(
                run_id=r["analysis_id"], finished_at=r.get("finished_at"),
                total_episodes=r_total,
                n_critical_high=r_sev.get("critical", 0) + r_sev.get("high", 0),
                fail_open_pct=round(100 * r_fo / r_total, 1) if r_total else 0.0))
        trend.reverse()   # chronologique : tracé gauche → droite

        return AIOverviewResponse(
            has_data=True, status=report.get("status"), run_id=run_id,
            last_finished_at=report.get("finished_at"),
            model_version=report.get("model_version"),
            prioritization=prio, cnn_by_severity=sev, trend=trend)

    # ══ ② Ré-entraînement ══════════════════════════════════════════════
    @staticmethod
    def retraining(history_limit: int = 20) -> RetrainingResponse:
        last = RetrainRepository.get_last()
        if not last:
            return RetrainingResponse(
                has_data=False,
                reason="Aucun gate exécuté — lance un cycle de ré-entraînement.")
        history = RetrainRepository.list_recent(limit=history_limit)
        acceptance = RetrainRepository.acceptance_stats()
        return RetrainingResponse.from_document(last, history, acceptance)

    # ══ ⑤ Qualité triage ═══════════════════════════════════════════════
    @staticmethod
    def triage() -> TriageResponse:
        report = ReportRepository.get_last_report()
        if not report:
            return TriageResponse(has_data=False, reason="Aucun run publié.")
        run_id = report["analysis_id"]
        t = report.get("triage")
        if not t:
            return TriageResponse(has_data=False, run_id=run_id,
                                  reason="Triage non ingéré pour ce run.")
        return TriageResponse(has_data=True, run_id=run_id,
                              triage=TriageQuality.model_validate(t))

    # ══ ④ Capacité de détection du modèle en production (CNN seul) ═════
    # Lecture DIRECTE de eval_summary.json sur disque (via CnnEvalAdapter) :
    # l'éval est une propriété du MODÈLE, pas d'un run. Aucune ingestion Mongo,
    # aucun run_id. La carte se remplit dès que le fichier existe. En mode
    # explication seule, on n'affiche QUE les métriques du CNN (le LLM n'écarte
    # plus rien) : la comparaison avec la cascade n'a plus lieu d'être.
    @staticmethod
    def eval_comparison() -> EvalComparisonResponse:
        raw = CnnEvalAdapter.load()
        if not raw:
            return EvalComparisonResponse(
                has_data=False,
                reason="eval_summary.json introuvable — lance le protocole "
                       "d'évaluation (inject.py) ou vérifie CNN_EVAL_SUMMARY.")
        return EvalComparisonResponse.from_raw(raw)