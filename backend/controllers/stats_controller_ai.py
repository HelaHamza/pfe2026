"""
controllers/stats_controller_ai.py
==================================
DASHBOARD EXPERT AI — destination des épisodes que le triage LLM n'a pas
tranchés (`uncertain`) et des épisodes en fail-open.

RAISON D'ÊTRE ARCHITECTURALE : le dashboard SOC n'affiche que les épisodes
`true_positive`. Sans cette vue, les `uncertain` seraient persistés en base
et inatteignables par l'API — c'est-à-dire perdus en pratique. La doctrine
du projet est explicite : un épisode n'est JAMAIS silencieusement écarté,
il est soit affiché, soit routé vers une revue experte.

C'est le même repository et les mêmes modèles que le SOC ; seul le filtre
de verdict change. La couche Modèle rend cette vue quasi gratuite.
"""
import logging

from models.detection_models import ResultRow, ResultsResponse
from models.enums import Verdict
from repositories.report_repository import ReportRepository

log = logging.getLogger(__name__)

# Verdicts routés vers la revue experte : tout ce qui n'est ni confirmé
# ni écarté. `uncertain` couvre aussi le fail-open (LLM indisponible →
# l'épisode remonte plutôt que d'être classé à tort).
REVIEW_VERDICTS = (Verdict.uncertain.value,)


class StatsControllerAI:

    @staticmethod
    def pending_review(level: str = None, limit: int = 500,
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
                # full=True : la revue experte reçoit scores,
                # seuil, evidence, kb_refs et garde-fous.
                rows.append(ResultRow.from_cnn(d, full=True))
            except Exception as e:
                log.error("Épisode %s non mappable : %s", d.get("_id"), e)

        rows.sort(key=lambda r: r.event_time, reverse=True)
        page = rows[skip:skip + limit]

        return ResultsResponse(run_id=run_id, total=total, count=len(page),
                               skip=skip, limit=limit, results=page)