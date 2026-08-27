"""
views/ai_dashboard_views.py
===========================
Couche VUE du dashboard Expert IA.

MODE EXPLICATION SEULE : la route /pending (revue des épisodes `uncertain`) a
été retirée — le LLM ne produit plus d'épisodes incertains, la file était
structurellement vide. La route ③ /overview expose désormais la PRIORISATION
du run (répartition de sévérité + fail-open), plus l'ancien entonnoir de
filtrage.
"""
from fastapi import APIRouter, Depends

from controllers.ai_dashboard_controller import StatsControllerAI
from core.deps import get_current_user
from models.ai_dashboard_model import (AIOverviewResponse, EvalComparisonResponse,
                                        FrozenModelResponse, TriageResponse)
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
            summary="③ Priorisation du dernier run (sévérité + fail-open)")
def overview(current_user: dict = Depends(get_current_user)) -> AIOverviewResponse:
    return StatsControllerAI.overview()


@router.get("/eval-comparison", response_model=EvalComparisonResponse,
            summary="④ Capacité de détection : CNN vs CNN→LLM (évaluation)")
def eval_comparison(current_user: dict = Depends(get_current_user)) -> EvalComparisonResponse:
    return StatsControllerAI.eval_comparison()


@router.get("/triage", response_model=TriageResponse,
            summary="⑤ Qualité et coût du triage LLM du dernier run")
def triage(current_user: dict = Depends(get_current_user)) -> TriageResponse:
    return StatsControllerAI.triage()