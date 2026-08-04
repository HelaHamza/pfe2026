import logging

from adapters.cnn_report_adapter import CnnReportAdapter
from models.ai_dashboard_model import (AIOverviewResponse, EvalComparisonResponse,
                                        FrozenModelResponse, RunTrendPoint,
                                        TriageFunnel, TriageQuality,
                                        TriageResponse)
from models.detection_models import ResultRow, ResultsResponse
from models.enums import Verdict
from models.retrain_run_model import RetrainingResponse
from repositories.report_repository import ReportRepository
from repositories.retrain_repository import RetrainRepository

log = logging.getLogger(__name__)

# uncertain (+ fail-open) : ni confirmé ni écarté → revue experte.
REVIEW_VERDICTS = (Verdict.uncertain.value,)


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

    # ══ ③ Efficacité live ══════════════════════════════════════════════
    @staticmethod
    def _funnel_from_breakdown(vb: dict[str, int]) -> TriageFunnel:
        tp  = vb.get(Verdict.true_positive.value, 0)
        fp  = vb.get(Verdict.false_positive.value, 0)
        unc = vb.get(Verdict.uncertain.value, 0)
        total = sum(vb.values())
        return TriageFunnel(
            total_episodes=total,
            true_positive=tp, false_positive=fp, uncertain=unc,
            remaining_after_llm=tp + unc,
            noise_reduction_pct=round(100 * fp / total, 1) if total else 0.0,
            fail_open_pct=round(100 * unc / total, 1) if total else 0.0,
        )

    @staticmethod
    def overview(trend_limit: int = 10) -> AIOverviewResponse:
        report = ReportRepository.get_last_report()
        if not report:
            return AIOverviewResponse(
                has_data=False,
                errors=["Aucun run publié — lance une analyse pour alimenter "
                        "l'entonnoir."])

        run_id = report["analysis_id"]
        vb = ReportRepository.cnn_verdict_breakdown(run_id)
        funnel = StatsControllerAI._funnel_from_breakdown(vb)
        sev = ReportRepository.cnn_severity_breakdown(run_id)

        # Tendance : on LIT le breakdown figé dans chaque report (cnn_by_verdict)
        # au lieu de ré-agréger par run (N+1 requêtes, divergence possible sur
        # un run partiel). Le report est la vérité publiée.
        trend = []
        for r in ReportRepository.list_recent_reports(limit=trend_limit):
            rf = StatsControllerAI._funnel_from_breakdown(
                r.get("cnn_by_verdict", {}))
            trend.append(RunTrendPoint(
                run_id=r["analysis_id"], finished_at=r.get("finished_at"),
                total_episodes=rf.total_episodes,
                remaining_after_llm=rf.remaining_after_llm,
                noise_reduction_pct=rf.noise_reduction_pct,
                fail_open_pct=rf.fail_open_pct))
        trend.reverse()   # chronologique : tracé gauche → droite

        return AIOverviewResponse(
            has_data=True, status=report.get("status"), run_id=run_id,
            last_finished_at=report.get("finished_at"),
            model_version=report.get("model_version"),
            funnel=funnel, cnn_by_severity=sev, trend=trend)

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

    # ══ ④ Capacité de détection (CNN vs CNN→LLM) ═══════════════════════
    @staticmethod
    def eval_comparison() -> EvalComparisonResponse:
        report = ReportRepository.get_last_report()
        if not report:
            return EvalComparisonResponse(has_data=False,
                                          reason="Aucun run publié.")
        run_id = report["analysis_id"]
        ec = report.get("eval_comparison")
        if not ec:
            return EvalComparisonResponse(
                has_data=False, run_id=run_id,
                reason="Éval CNN-vs-cascade non ingérée — régénère "
                       "eval_summary.json.")
        return EvalComparisonResponse.from_raw(run_id, ec)

    # ══ Revue experte (épisodes uncertain) ═════════════════════════════
    @staticmethod
    def pending_review(level: str | None = None, limit: int = 500,
                       skip: int = 0) -> ResultsResponse:
        report = ReportRepository.get_last_report()
        if not report:
            return ResultsResponse(total=0, count=0, skip=skip, limit=limit)

        run_id = report["analysis_id"]
        total = ReportRepository.count_results(
            run_id, level=level, source="cnn", cnn_verdicts=REVIEW_VERDICTS)
        docs = ReportRepository.get_results(
            run_id, level=level, source="cnn", limit=skip + limit,
            cnn_verdicts=REVIEW_VERDICTS)

        rows = []
        for d in docs:
            try:
                rows.append(ResultRow.from_cnn(d, full=True))
            except Exception as e:
                log.error("Épisode %s non mappable : %s", d.get("_id"), e)

        page = rows[skip:skip + limit]
        return ResultsResponse(run_id=run_id, total=total, count=len(page),
                               skip=skip, limit=limit, results=page)