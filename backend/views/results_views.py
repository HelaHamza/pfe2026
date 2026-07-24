"""
views/results_views.py
======================
Couche VUE. Dans une API REST, la vue est la sérialisation JSON exposée :
routage, validation d'entrée, contrat de sortie. Aucune logique métier.

Correctifs :
  - `source` / `level` typés par énumération → 422 explicite au lieu d'un
    200 avec liste vide sur une faute de frappe côté front.
  - `response_model` → contrat de sortie validé + documentation OpenAPI
    réelle (avant : aucun schéma, donc aucune vue au sens strict).
  - `skip` → pagination possible, maintenant que `total` est honnête.
"""
from fastapi import APIRouter, Depends, Query

from controllers.results_controller import ResultsController
from core.deps import get_current_user
from models.detection_models import ResultsResponse
from models.enums import DetectionSource, Severity

router = APIRouter(prefix="/results", tags=["Results"])


@router.get("", response_model=ResultsResponse,
            summary="Tableau des détections du dernier run")
def get_results(
    limit: int = Query(500, ge=1, le=500),
    skip: int = Query(0, ge=0),
    level: Severity | None = Query(None, description="Filtre de sévérité."),
    source: DetectionSource | None = Query(None, description="Branche."),
    current_user: dict = Depends(get_current_user),
) -> ResultsResponse:
    return ResultsController.get_results(
        level=level.value if level else None,
        source=source.value if source else None,
        limit=limit, skip=skip)