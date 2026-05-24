"""
=============================================================================
views/ai_dashboard_views.py
=============================================================================
"""
from fastapi import APIRouter, Query, HTTPException

from controllers import stats_controller_ai as stats_controller

router = APIRouter(prefix="/ai-dashboard", tags=["ai-dashboard"])


@router.get("/versions")
async def get_versions():
    return stats_controller.list_versions()


@router.get("/overview")
async def get_overview(version: str | None = Query(default=None)):
    data = stats_controller.get_overview(version)
    if data is None:
        raise HTTPException(status_code=404, detail="Aucune métrique trouvée.")
    return data


@router.get("/compare")
async def compare(versions: str | None = Query(default=None)):
    version_list = None
    if versions:
        version_list = [v.strip() for v in versions.split(",") if v.strip()]
    return stats_controller.compare_versions(version_list)