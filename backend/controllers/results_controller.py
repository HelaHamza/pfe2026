"""
backend/controllers/results_controller.py
==========================================
CONTROLLER — Tableau et détail des événements.
  get_results() → liste unifiée anomalies + alertes
  get_detail()  → détail complet + LLM
"""

from backend.models.es_repository import ESRepository
from backend.controllers.analyse_controller import get_state


class ResultsController:

    @staticmethod
    def get_results(limit: int = 100, level: str = None, source: str = None) -> dict:
        state  = get_state()
        cursor = state.get("run_cursor") or ESRepository.get_cursor()

        anomalies = ESRepository.get_anomalies(cursor, limit)
        alerts    = ESRepository.get_alerts(cursor, limit)
        results   = anomalies + alerts

        if level:
            results = [r for r in results if (r.get("level") or "").upper() == level.upper()]
        if source:
            results = [r for r in results if (r.get("detection_source") or "").lower() == source.lower()]

        results.sort(key=lambda x: x.get("@timestamp") or "", reverse=True)
        return {"total": len(results), "cursor": cursor, "results": results[:limit]}

    @staticmethod
    def get_detail(doc_type: str, doc_id: str) -> dict:
        if doc_type == "anomaly":
            return ESRepository.get_anomaly_detail(doc_id)
        elif doc_type == "alert":
            return ESRepository.get_alert_detail(doc_id)
        else:
            raise ValueError(f"Type inconnu : {doc_type}")