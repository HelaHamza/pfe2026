"""
controllers/results_controller.py
=================================
Table de résultats SOC : fusion CNN (true_positive) + Sigma du dernier run.

Le contrôleur ne connaît pas Mongo et ne connaît pas HTTP. Il orchestre
repository → modèles, et applique la seule logique qui ne peut pas vivre
dans Mongo : la fusion inter-collections.
"""
import logging

from models.detection_models import ResultRow, ResultsResponse
from repositories.report_repository import ReportRepository

log = logging.getLogger(__name__)


class ResultsController:

    @staticmethod
    def get_results(level: str = None, source: str = None,
                    limit: int = 500, skip: int = 0) -> ResultsResponse:
        report = ReportRepository.get_last_report()
        if not report:
            return ResultsResponse(total=0, count=0, skip=skip, limit=limit)

        run_id = report["analysis_id"]
        total = ReportRepository.count_results(run_id, level=level, source=source)

        # Pour une page [skip, skip+limit[ correcte après fusion, il faut
        # les (skip+limit) premières lignes de CHAQUE source : la page finale
        # peut provenir intégralement de l'une ou de l'autre.
        need = skip + limit
        docs = ReportRepository.get_results(run_id, level=level,
                                            source=source, limit=need)

        rows: list[ResultRow] = []
        for d in docs:
            try:
                rows.append(ResultRow.from_cnn(d) if d.get("type") == "cnn"
                            else ResultRow.from_sigma(d))
            except Exception as e:
                # Un document malformé ne doit pas vider tout le tableau.
                log.error("Document %s non mappable : %s", d.get("_id"), e)

        # Tri global sur datetime (pas sur chaîne) : plus de dépendance au
        # format de sérialisation de chaque branche.
        rows.sort(key=lambda r: r.event_time, reverse=True)
        page = rows[skip:skip + limit]

        return ResultsResponse(run_id=run_id, total=total, count=len(page),
                               skip=skip, limit=limit, results=page)