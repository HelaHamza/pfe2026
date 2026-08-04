import asyncio
import logging
import threading
import uuid
from collections import Counter, deque

import config as CFG
from adapters.cnn_adapter import CNNAdapter
from adapters.eval_adapter import EvalAdapter
from adapters.gate_adapter import GateAdapter
from adapters.sigma_adapter import SigmaAdapter
from core.timeutils import now_utc, to_utc
from models.enums import ReportStatus
from models.report_model import Report, ReportStats, TacticCount
from repositories.log_repository import LogRepository
from repositories.report_repository import ReportRepository
from repositories.retrain_repository import RetrainRepository

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
    # Retour IMMÉDIAT au modal : predict_cnn + triage LLM prennent plusieurs
    # minutes sans émettre de log — sans ce message, le front reste à 0 %.
    _log("Inférence CNN + triage LLM en cours… (plusieurs minutes)")
    episodes, next_cursor = CNNAdapter.collect(since, until)
    ReportRepository.save_cnn_episodes(episodes, run_id)   # lève si incomplet
    _log(f"{len(episodes)} épisodes CNN persistés")
    return episodes, next_cursor


def _sigma_branch(run_id: str, until: str) -> tuple[list[dict], str]:
    since = ReportRepository.get_sigma_cursor() or CFG.PROD_START
    _log("Analyse Sigma en cours…")
    alerts, next_cursor = SigmaAdapter.collect(since, until)
    ReportRepository.save_sigma_alerts(alerts, run_id)     # lève si incomplet
    _log(f"{len(alerts)} alertes Sigma persistées")
    return alerts, next_cursor


# ══════════════════════════════════════════════════════════════════════
#  Auto-ingest des artefacts hors-bande (domaines C et E)
#  Non bloquants : un échec ici n'invalide JAMAIS le run de détection.
#  Calqués sur le bloc « Résumé de triage » : try / log / errors.append.
# ══════════════════════════════════════════════════════════════════════
def _ingest_gate(errors: list[str]) -> None:
    """Domaine C : pousse le dernier gate_*.json dans retrain_runs.
    Idempotent (upsert sur created_at) ; on saute l'écriture si ce gate est
    déjà en base pour éviter le bruit de log à chaque run."""
    doc = GateAdapter.load_latest()
    if not doc:
        return                              # aucun gate sur disque → carte C vide
    last = RetrainRepository.get_last()
    if last and to_utc(last.get("created_at")) == doc.created_at:
        _log("Gate déjà en base — ré-ingestion sautée (C à jour)")
        return
    RetrainRepository.insert_gate(doc)
    _log(f"Gate {doc.created_at} ({doc.verdict}) ingéré (domaine C)")


def _ingest_eval(run_id: str, errors: list[str]) -> None:
    """Domaine E : attache eval_summary.json AU RUN COURANT. Absent → no-op,
    la carte E reste has_data=False. mtime journalisée (péremption visible)."""
    loaded = EvalAdapter.load_summary()
    if not loaded:
        return
    raw, mtime = loaded
    ReportRepository.save_eval_comparison(run_id, raw)
    _log(f"Comparaison d'éval attachée au run {run_id} "
         f"(éval générée le {mtime.isoformat()})")


# ══════════════════════════════════════════════════════════════════════
#  Pipeline
# ══════════════════════════════════════════════════════════════════════
def _run_pipeline(run_id: str):
    with _lock:
        started = _state["started_at"]      # borne haute FIGÉE, partagée

    # Borne basse du run pour le comptage des logs ES (AVANT avancement des
    # curseurs). ES = domaine Sigma → on prend le curseur Sigma.
    run_since = ReportRepository.get_sigma_cursor() or CFG.PROD_START

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
        # Fenêtre ]run_since, started] → logs DU RUN, pas tout l'index.
        logs_by_source = LogRepository.count_logs_by_source(
            since=run_since, until=started)
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

    # ── Résumé de triage attaché au report (enchaînement automatique) ──
    if report_ok:
        try:
            summary = CNNAdapter.load_triage_summary()
            if summary:
                ReportRepository.save_triage_summary(run_id, summary)
                _log("Résumé de triage attaché au report")
            else:
                _log("Aucun résumé de triage pour ce run (domaine D vide)",
                     logging.WARNING)
        except Exception as e:
            errors.append(f"Triage : {e}")
            _log(f"Résumé de triage NON attaché : {e}", logging.ERROR)

    # ── Domaine C : auto-ingest du dernier gate de ré-entraînement ─────
    try:
        _ingest_gate(errors)
    except Exception as e:
        errors.append(f"Gate (C) : {e}")
        _log(f"Auto-ingest gate NON effectué : {e}", logging.ERROR)

    # ── Domaine E : auto-ingest de l'éval offline, attachée au run courant ─
    if report_ok:
        try:
            _ingest_eval(run_id, errors)
        except Exception as e:
            errors.append(f"Éval (E) : {e}")
            _log(f"Auto-ingest éval NON effectué : {e}", logging.ERROR)

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

    # Anomalies AE (TP) ventilées par source. INITIALISÉ à 0 pour CHAQUE source
    # présente dans les logs : un run à 0 TP renvoie ainsi {auditd:0, auth:0,
    # syslog:0} et non {}. Le front distingue « 0 anomalie » de « champ absent »
    # et affiche donc toujours le %.
    anomalies_by_source: dict[str, int] = {src: 0 for src in logs_by_source}
    for e in shown:                          # TP uniquement
        src = (e.get("log_source") or "unknown").lower()
        anomalies_by_source[src] = anomalies_by_source.get(src, 0) + 1

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
        anomalies_by_source=anomalies_by_source,
        by_tactic=[TacticCount(tactic=t, count=c)
                   for t, c in tactics.most_common(8)],
    )
    ReportRepository.save_report(report)