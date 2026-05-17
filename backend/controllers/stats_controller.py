"""
backend/controllers/stats_controller.py
========================================
CONTROLLER — Statistiques pour le dashboard.
  get_stats()        → 4 cards
  get_timeline(days) → graphique tendances
  get_by_level()     → pie chart sévérité
  get_by_source()    → bar chart sources log
"""

from backend.models.es_repository import ESRepository
from backend.controllers.analyse_controller import get_state


class StatsController:

    @staticmethod
    def get_stats() -> dict:
        state  = get_state()
        cursor = state.get("run_cursor") or ESRepository.get_cursor()
        return ESRepository.get_stats(cursor)

    @staticmethod
    def get_timeline(days: int = 7) -> list[dict]:
        return ESRepository.get_timeline(days)

    @staticmethod
    def get_by_level() -> list[dict]:
        return ESRepository.get_alerts_by_level()

    @staticmethod
    def get_by_source() -> list[dict]:
        return ESRepository.get_anomalies_by_source()