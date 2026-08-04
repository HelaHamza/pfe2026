from fastapi import APIRouter, Depends, Query

from controllers.ai_dashboard_controller import StatsControllerAI
from core.deps import get_current_user
from models.ai_dashboard_model import (AIOverviewResponse, EvalComparisonResponse,
                                        FrozenModelResponse, TriageResponse)
from models.detection_models import ResultsResponse
from models.enums import Severity
from models.retrain_run_model import RetrainingResponse

router = APIRouter(prefix="/ai-dashboard", tags=["Expert AI"])


@router.get("/frozen-model", response_model=FrozenModelResponse,
            summary="① Modèle en production : version, seuils POT par source")
def frozen_model(current_user: dict = Depends(get_current_user)) -> FrozenModelResponse:
    return StatsControllerAI.frozen_model()


@router.get("/retraining", response_model=RetrainingResponse,
            summary="② Santé du ré-entraînement (dernier gate + historique)")
def retraining(current_user: dict = Depends(get_current_user)) -> RetrainingResponse:
    return StatsControllerAI.retraining()


@router.get("/overview", response_model=AIOverviewResponse,
            summary="③ Entonnoir de triage et efficacité du dernier run")
def overview(current_user: dict = Depends(get_current_user)) -> AIOverviewResponse:
    return StatsControllerAI.overview()


@router.get("/eval-comparison", response_model=EvalComparisonResponse,
            summary="④ Capacité de détection : CNN vs CNN→LLM")
def eval_comparison(current_user: dict = Depends(get_current_user)) -> EvalComparisonResponse:
    return StatsControllerAI.eval_comparison()


@router.get("/triage", response_model=TriageResponse,
            summary="⑤ Qualité et coût du triage LLM du dernier run")
def triage(current_user: dict = Depends(get_current_user)) -> TriageResponse:
    return StatsControllerAI.triage()


@router.get("/pending", response_model=ResultsResponse,
            summary="Épisodes CNN non tranchés par le triage (revue experte)")
def pending_review(
    limit: int = Query(500, ge=1, le=500),
    skip: int = Query(0, ge=0),
    level: Severity | None = Query(None),
    current_user: dict = Depends(get_current_user),
) -> ResultsResponse:
    return StatsControllerAI.pending_review(
        level=level.value if level else None, limit=limit, skip=skip)