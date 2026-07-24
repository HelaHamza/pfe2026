"""
controllers/analyse_controller.py
=================================
ORCHESTRATEUR BATCH. Ne connaît ni le pipeline (→ adapters) ni Mongo
(→ repository). Il ne fait qu'ordonner, et cet ordre est la garantie
centrale du système :

        collecter → PERSISTER → publier le rapport → AVANCER les curseurs

Un curseur n'avance jamais avant que les résultats correspondants ne
soient atteignables par l'API. Toute rupture de cette séquence produit une
perte silencieuse de détections.

INDÉPENDANCE DES BRANCHES : chaque branche a son propre try. Une panne du
modèle CNN ne doit pas priver l'analyste de la détection par règles, qui
est précisément le filet de sécurité.

LIMITE ASSUMÉE : `_state` est un état PROCESSUS. Avec plusieurs workers
uvicorn le verrou ne protège rien. Mono-worker en soutenance ; la version
multi-worker exigerait un verrou dans `pipeline_state` (Mongo).
"""
import asyncio
import logging
import threading
import uuid
from collections import Counter, deque

import config as CFG
from adapters.cnn_adapter import CNNAdapter
from adapters.sigma_adapter import SigmaAdapter
from core.timeutils import now_utc, to_utc
from models.enums import ReportStatus
from models.report_model import Report, ReportStats, TacticCount
from repositories.log_repository import LogRepository
from repositories.report_repository import ReportRepository

log = logging.getLogger(__name__)

_MAX_LOGS = 500
_lock = threading.Lock()
_state = {
    "running": False, "done": False, "error": None, "run_id": None,
    "started_at": None, "finished_at": None, "logs": deque(maxlen=_MAX_LOGS),
}


# ══════════════════════════════════════════════════════════════════════
#  État exposé à la vue (polling front)
# ══════════════════════════════════════════════════════════════════════
def get_state() -> dict:
    with _lock:
        s = dict(_state)
        s["logs"] = list(_state["logs"])
        return s


def _log(msg: str, level: int = logging.INFO):
    with _lock:
        _state["logs"].append({"ts": now_utc().isoformat(), "msg": msg})
    log.log(level, "[Analyse] %s", msg)


def _acquire(run_id: str) -> bool:
    with _lock:
        if _state["running"]:
            return False
        _state["logs"].clear()
        _state.update(running=True, done=False, error=None, run_id=run_id,
                      finished_at=None, started_at=now_utc().isoformat())
        return True


async def run_analyse():
    run_id = str(uuid.uuid4())
    if not _acquire(run_id):
        log.warning("[Analyse] run déjà en cours — abandon")
        return
    await asyncio.to_thread(_run_pipeline, run_id)


# ══════════════════════════════════════════════════════════════════════
#  Branches — collecte PUIS persistance, dans la même unité d'échec
# ══════════════════════════════════════════════════════════════════════
def _cnn_branch(run_id: str, until: str) -> tuple[list[dict], str]:
    since = ReportRepository.get_cnn_cursor() or CFG.PROD_START
    episodes, next_cursor = CNNAdapter.collect(since, until)
    ReportRepository.save_cnn_episodes(episodes, run_id)   # lève si incomplet
    _log(f"{len(episodes)} épisodes CNN persistés")
    return episodes, next_cursor


def _sigma_branch(run_id: str, until: str) -> tuple[list[dict], str]:
    since = ReportRepository.get_sigma_cursor() or CFG.PROD_START
    alerts, next_cursor = SigmaAdapter.collect(since, until)
    ReportRepository.save_sigma_alerts(alerts, run_id)     # lève si incomplet
    _log(f"{len(alerts)} alertes Sigma persistées")
    return alerts, next_cursor


# ══════════════════════════════════════════════════════════════════════
#  Pipeline
# ══════════════════════════════════════════════════════════════════════
def _run_pipeline(run_id: str):
    with _lock:
        started = _state["started_at"]      # borne haute FIGÉE, partagée

    cnn_eps, sigma_alerts, errors = [], [], []
    cnn_cursor = sigma_cursor = None

    try:
        cnn_eps, cnn_cursor = _cnn_branch(run_id, started)
    except Exception as e:
        errors.append(f"CNN : {e}")
        _log(f"ÉCHEC branche CNN : {e}", logging.ERROR)

    try:
        sigma_alerts, sigma_cursor = _sigma_branch(run_id, started)
    except Exception as e:
        errors.append(f"Sigma : {e}")
        _log(f"ÉCHEC branche Sigma : {e}", logging.ERROR)

    try:
        logs_by_source = LogRepository.count_logs_by_source()
    except Exception as e:
        logs_by_source = {}
        errors.append(f"Comptage logs : {e}")

    if cnn_cursor and sigma_cursor:
        status = ReportStatus.completed
    elif cnn_cursor or sigma_cursor:
        status = ReportStatus.partial
    else:
        status = ReportStatus.failed

    # ── Rapport AVANT curseurs ────────────────────────────────────────
    report_ok = False
    try:
        _save_snapshot(run_id, started, status, errors,
                       cnn_eps, sigma_alerts, logs_by_source)
        report_ok = True
    except Exception as e:
        errors.append(f"Rapport : {e}")
        _log(f"ÉCHEC écriture du rapport : {e}", logging.ERROR)

    # ── Curseurs UNIQUEMENT si les résultats sont atteignables ────────
    if report_ok:
        for setter, value, name in (
                (ReportRepository.set_cnn_cursor, cnn_cursor, "CNN"),
                (ReportRepository.set_sigma_cursor, sigma_cursor, "Sigma")):
            if not value:
                continue
            try:
                setter(value)
                _log(f"Curseur {name} → {value}")
            except Exception as e:
                errors.append(f"Curseur {name} : {e}")
                _log(f"Curseur {name} NON avancé : {e}", logging.ERROR)
    else:
        _log("Rapport non publié → AUCUN curseur avancé (relance sûre).",
             logging.WARNING)

    with _lock:
        _state.update(running=False, done=True,
                      error="; ".join(errors) if errors else None,
                      finished_at=now_utc().isoformat())
    _log("✓ Analyse terminée" if not errors
         else f"Analyse terminée avec {len(errors)} erreur(s)")


# ══════════════════════════════════════════════════════════════════════
#  Snapshot dashboard
# ══════════════════════════════════════════════════════════════════════
_TACTIC_PLACEHOLDERS = {"", "voir règle", "n/a", "unknown", "none"}


def _save_snapshot(run_id, started, status, errors,
                   cnn_eps, sigma_alerts, logs_by_source):
    shown = [e for e in cnn_eps if e.get("verdict") == "true_positive"]
    fp = [e for e in cnn_eps if e.get("verdict") == "false_positive"]
    to_review = [e for e in cnn_eps
                 if e.get("verdict") not in ("true_positive", "false_positive")]

    cnn_sev = Counter(str(e.get("severity", "low")).lower() for e in shown)
    cnn_verdict = Counter(e.get("verdict", "uncertain") for e in cnn_eps)
    sig_lvl = Counter(str(a.get("level", "LOW")).lower() for a in sigma_alerts)

    tactics = Counter(
        a["tactic"] for a in sigma_alerts
        if a.get("tactic")
        and str(a["tactic"]).strip().lower() not in _TACTIC_PLACEHOLDERS)

    report = Report(
        analysis_id=run_id,
        started_at=to_utc(started) or now_utc(),
        finished_at=now_utc(),
        status=status,
        errors=errors,
        stats=ReportStats(
            cnn_episodes=len(cnn_eps),
            cnn_kept=len(shown),
            cnn_to_review=len(to_review),
            sigma_alerts=len(sigma_alerts),
            cnn_critical=cnn_sev.get("critical", 0),
            sigma_critical=sig_lvl.get("critical", 0),
            logs_total=sum(logs_by_source.values()),
            # Dénominateur = TOUS les épisodes ; les `uncertain` ne comptent
            # pas comme réduction (travail analyste déporté, pas supprimé).
            noise_reduction_pct=round(100 * len(fp) / max(len(cnn_eps), 1), 1),
        ),
        cnn_by_severity=dict(cnn_sev),
        cnn_by_verdict=dict(cnn_verdict),
        sigma_by_level=dict(sig_lvl),
        logs_by_source=logs_by_source,
        by_tactic=[TacticCount(tactic=t, count=c)
                   for t, c in tactics.most_common(8)],
    )
    ReportRepository.save_report(report)