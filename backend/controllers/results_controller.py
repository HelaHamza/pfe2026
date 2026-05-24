"""
backend/controllers/results_controller.py
==========================================
Le tableau lit la MÊME fenêtre que les cartes du dashboard via
ESRepository.get_last_window() (source unique de vérité, partagée
avec StatsController — plus de duplication de la logique de fenêtre).

TRI : alertes Sigma + anomalies corrélées (both) en premier, puis par
sévérité, puis par date desc. Met en avant les vraies menaces.
"""

from models.es_repository import ESRepository


_SOURCE_RANK = {"both": 0, "sigma_only": 1, "ae_only": 2, "unknown": 3}
_SEV_RANK    = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


class ResultsController:

    @staticmethod
    def _normalize(item: dict) -> dict:
        is_anomaly = item.get("type") == "anomaly"
        return {
            "id":               item.get("id"),
            "type":             item.get("type"),
            "@timestamp":       item.get("@timestamp"),
            "severity":         item.get("kb_severity") or item.get("level", "unknown"),
            "detection_source": item.get("detection_source", "unknown"),
            "title":            item.get("log_source", "Anomalie AE") if is_anomaly
                                else item.get("title", "Alerte Sigma"),
            "tactic":           item.get("tactic", ""),
            "score":            item.get("ae_anomaly_score"),
            "hits":             item.get("hits"),
            "llm_explanation":  item.get("llm_explanation"),
            "ae_correlated":    item.get("ae_correlated", False),
        }

    @staticmethod
    def _sort_key(r: dict):
        src = (r.get("detection_source") or "unknown").lower()
        sev = (r.get("kb_severity") or r.get("level") or "unknown").upper()
        return (_SOURCE_RANK.get(src, 3), _SEV_RANK.get(sev, 4))

    @staticmethod
    def get_results(limit: int = 500, level: str = None, source: str = None) -> dict:
        lo, hi = ESRepository.get_last_window()   # source unique de verite

        if source in ("ae_only", "both"):
            anomalies = ESRepository.get_anomalies_window(lo, hi, limit)
            alerts    = []
        elif source == "sigma_only":
            anomalies = []
            alerts    = ESRepository.get_alerts_window(lo, hi, limit)
        else:
            anomalies = ESRepository.get_anomalies_window(lo, hi, limit)
            alerts    = ESRepository.get_alerts_window(lo, hi, limit)

        results = anomalies + alerts

        if source == "both":
            results = [r for r in results if r.get("ae_correlated") or
                       (r.get("detection_source") or "").lower() == "both"]

        if level:
            results = [
                r for r in results
                if (r.get("kb_severity") or r.get("level") or "").upper() == level.upper()
            ]

        results.sort(key=lambda x: (x.get("@timestamp") or ""), reverse=True)
        results.sort(key=ResultsController._sort_key)

        normalized = [ResultsController._normalize(r) for r in results[:limit]]
        return {"total": len(normalized), "window": {"lo": lo, "hi": hi},
                "results": normalized}

    @staticmethod
    def get_detail(doc_type: str, doc_id: str) -> dict:
        if doc_type == "anomaly":
            return ESRepository.get_anomaly_detail(doc_id)
        elif doc_type == "alert":
            return ESRepository.get_alert_detail(doc_id)
        else:
            raise ValueError(f"Type inconnu : {doc_type}")