"""
views/ai_dashboard_views.py
===========================
Dashboard Expert AI : épisodes CNN en attente de revue humaine.

Séparé du dashboard SOC par un préfixe distinct — les deux publics ne
consomment pas la même file. Le SOC voit ce qui est confirmé, l'expert voit
ce qui est douteux.
"""
from fastapi import APIRouter, Depends, Query

from controllers.stats_controller_ai import StatsControllerAI
from core.deps import get_current_user
from models.detection_models import ResultsResponse
from models.enums import Severity

router = APIRouter(prefix="/ai-dashboard", tags=["Expert AI"])


@router.get("/pending", response_model=ResultsResponse,
            summary="Épisodes CNN non tranchés par le triage LLM")
def pending_review(
    limit: int = Query(500, ge=1, le=500),
    skip: int = Query(0, ge=0),
    level: Severity | None = Query(None),
    current_user: dict = Depends(get_current_user),
) -> ResultsResponse:
    return StatsControllerAI.pending_review(
        level=level.value if level else None, limit=limit, skip=skip)