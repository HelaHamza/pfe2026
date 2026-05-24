"""

====================================
FIX : 100% des stats viennent du SNAPSHOT MongoDB via StatsController.
      Plus aucune lecture LIVE sur ES → chiffres stables entre reloads.

Premier lancement : si aucun snapshot, on renvoie un payload "empty"
avec last_finished_at=None → le front affiche EmptyDashboardState.
Sinon (snapshot existe, même vieux) → on l'affiche + last_finished_at
pour que le topbar affiche "Dernière analyse il y a X heures".
"""

from fastapi import APIRouter, Depends, Query

from controllers.stats_controller   import StatsController
from controllers.analyse_controller import get_state
from models.es_repository           import ESRepository
from core.deps                      import get_current_user

router = APIRouter(tags=["Dashboard"])


@router.get("/dashboard")
@router.get("/dashboard")
def get_dashboard(current_user: dict = Depends(get_current_user)):
    state  = get_state()
    report = ESRepository.get_last_report()

    if not report:
        return {
            "has_data":          False,
            "running":           state.get("running", False),
            "last_finished_at":  None,
            "last_started_at":   None,
            "stats":             {"ae_anomalies": 0, "sigma_alerts": 0,
                                  "critical": 0, "correlated_both": 0, "cursor": ""},
            "timeline":          [],
            "by_tactic":         [],
            "detection_source":  {"ae_only": 0, "sigma_only": 0, "both": 0, "total": 0},
            "logs_by_source":    {},
            "attacks_by_source": {},
            "sigma_by_source":   {},
            "sigma_by_level":    {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "anomalies_by_source": {},
            "activity_by_source":  {},
            "report":              None,
            "results":             [],    # 🆕
        }

    stats               = StatsController.get_stats()
    timeline            = StatsController.get_timeline(days=7)
    sigma_by_level      = StatsController.get_sigma_by_level()
    anomalies_by_source = StatsController.get_anomalies_by_source()
    logs_by_source      = StatsController.get_logs_by_source()
    detection_source    = StatsController.get_detection_source_stats()
    by_tactic           = StatsController.get_by_tactic()
    sigma_by_source     = StatsController.get_sigma_by_source()
    activity_by_src     = StatsController.get_ae_stats_by_source()

    attacks_by_source = {
        src: data.get("anomalies", 0)
        for src, data in activity_by_src.items()
    }

    # 🆕 Résultats depuis le snapshot — jamais depuis ES live
    snapshot_results = report.get("results", [])

    return {
        "has_data":            True,
        "running":             state.get("running", False),
        "last_finished_at":    report.get("finished_at"),
        "last_started_at":     report.get("started_at"),
        "stats":               stats,
        "timeline":            timeline,
        "by_tactic":           by_tactic,
        "detection_source":    detection_source,
        "logs_by_source":      logs_by_source,
        "attacks_by_source":   attacks_by_source,
        "sigma_by_source":     sigma_by_source,
        "sigma_by_level":      sigma_by_level,
        "anomalies_by_source": anomalies_by_source,
        "activity_by_source":  activity_by_src,
        "report":              report,
        "results":             snapshot_results,    # 🆕
    }


# ── Routes éclatées /stats/* ─────────────────────────────────────────────────

@router.get("/stats")
def get_stats(current_user: dict = Depends(get_current_user)):
    return StatsController.get_stats()


@router.get("/stats/timeline")
def get_timeline(
    days: int = Query(7, ge=1, le=30),
    current_user: dict = Depends(get_current_user),
):
    return StatsController.get_timeline(days)


@router.get("/stats/by-level")
def get_by_level(current_user: dict = Depends(get_current_user)):
    return StatsController.get_by_level()


@router.get("/stats/by-source")
def get_by_source(current_user: dict = Depends(get_current_user)):
    return StatsController.get_by_source()


@router.get("/stats/by-tactic")
def get_by_tactic(current_user: dict = Depends(get_current_user)):
    return StatsController.get_by_tactic()


@router.get("/stats/sigma-by-source")
def get_sigma_by_source(current_user: dict = Depends(get_current_user)):
    return StatsController.get_sigma_by_source()


@router.get("/stats/detection-source")
def get_detection_source(current_user: dict = Depends(get_current_user)):
    return StatsController.get_detection_source_stats()


@router.get("/stats/logs-by-source")
def get_logs_by_source(current_user: dict = Depends(get_current_user)):
    return StatsController.get_logs_by_source()