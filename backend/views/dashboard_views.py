"""
views/dashboard_views.py
========================
Dashboard SOC : compteurs et répartitions du dernier run publié.

⚠️ À COMPARER avec ton fichier existant : si tu exposes d'autres routes ici
(séries temporelles, filtres…), reprends-les — ce fichier ne contient que la
route principale, corrigée d'un `response_model`.
"""
from fastapi import APIRouter, Depends

from controllers.stats_controller import StatsController
from core.deps import get_current_user
from models.dashboard_model import DashboardResponse

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("", response_model=DashboardResponse,
            summary="Snapshot du dernier run")
def dashboard(current_user: dict = Depends(get_current_user)) -> DashboardResponse:
    return StatsController.dashboard()