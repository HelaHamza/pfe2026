"""
backend/controllers/analyse_controller.py
==========================================
CONTROLLER — Analyse principale.
Lance AE et Sigma en parallèle, puis appelle fusion_router.
Gère l'état de l'analyse (running, logs de progression, curseur).
"""

import asyncio
import os
import sys
from datetime import datetime, timezone

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ROOT    = os.path.dirname(_BACKEND)
_CORE    = os.path.join(_ROOT, "core")

for _p in [_CORE, _ROOT]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from backend.models.ae_model      import AEModel
from backend.models.sigma_model   import SigmaModel
from backend.models.es_repository import ESRepository


# ── État global de l'analyse ──────────────────────────────────────────────────
_state = {
    "running":    False,
    "started_at": None,
    "done":       False,
    "error":      None,
    "logs":       [],       # progression pour SSE
    "run_cursor": None,     # cursor utilisé pour cette analyse
}


def get_state() -> dict:
    return _state


def _log(msg: str):
    """Ajoute un message de progression (affiché dans la console SSE du front)."""
    entry = {"ts": datetime.now(timezone.utc).isoformat(), "msg": msg}
    _state["logs"].append(entry)
    print(f"[AnalyseController] {msg}")


# ── Pipeline principal ────────────────────────────────────────────────────────

async def run_analyse():
    """
    Lance l'analyse complète :
      1. AE + Sigma en parallèle
      2. fusion_router (corrélation + LLM)
      3. Mise à jour curseur

    Appelé depuis api.py via asyncio.create_task().
    """
    if _state["running"]:
        return

    _state.update(
        running=True, done=False, error=None, logs=[],
        started_at=datetime.now(timezone.utc).isoformat()
    )

    try:
        # ── Étape 1 : curseur ─────────────────────────────────────────────────
        cursor = ESRepository.get_cursor()
        _state["run_cursor"] = cursor
        _log(f"Analyse depuis : {cursor}")

        new = ESRepository.get_new_logs_count(cursor)
        _log(f"Nouveaux logs : {new['total']}")
        for src, cnt in new.get("by_source", {}).items():
            _log(f"  {src} : {cnt} logs")

        if new["total"] == 0:
            _log("Aucun nouveau log — analyse ignorée")
            return

        # ── Étape 2 : AE + Sigma en parallèle ────────────────────────────────
        _log("Lancement AE + Sigma en parallèle...")

        loop = asyncio.get_event_loop()

        ae_future    = loop.run_in_executor(None, _run_ae,    cursor)
        sigma_future = loop.run_in_executor(None, _run_sigma)

        ae_result, sigma_alerts = await asyncio.gather(
            ae_future, sigma_future, return_exceptions=True
        )

        # Gestion des exceptions
        if isinstance(ae_result, Exception):
            _log(f"[AE] Erreur : {ae_result}")
            ae_result = None
        if isinstance(sigma_alerts, Exception):
            _log(f"[SIGMA] Erreur : {sigma_alerts}")
            sigma_alerts = []

        ae_ok    = ae_result    is not None
        sigma_ok = sigma_alerts is not None

        _log(f"AE : {'✓' if ae_ok else '✗'}  |  Sigma : {'✓' if sigma_ok else '✗'}")

        # ── Étape 3 : fusion_router ───────────────────────────────────────────
        _log("Corrélation AE ↔ Sigma + génération LLM...")
        try:
            _run_fusion(ae_result, sigma_alerts or [], cursor)
        except Exception as e:
            _log(f"[FUSION] Erreur non bloquante : {e}")

        # ── Étape 4 : mise à jour curseur ─────────────────────────────────────
        if new.get("max_timestamp"):
            ESRepository.save_cursor(new["max_timestamp"])
            _log(f"Curseur mis à jour : {new['max_timestamp']}")

        # Résumé
        stats = ESRepository.get_stats(cursor)
        _log(f"Résultats : {stats['ae_anomalies']} anomalies AE | {stats['sigma_alerts']} alertes Sigma")
        _log("✓ Analyse terminée")

    except Exception as e:
        _state["error"] = str(e)
        _log(f"ERREUR CRITIQUE : {e}")
    finally:
        _state["running"] = False
        _state["done"]    = True


# ── Fonctions bloquantes (appelées dans executor) ────────────────────────────

def _run_ae(cursor: str) -> dict | None:
    """Lance l'inférence AE (bloquant — tourne dans un thread)."""
    try:
        result = AEModel.infer(cursor)
        _log(f"[AE] {result['n_anomalies']} anomalies sur {result['n_logs']} logs")
        return result
    except Exception as e:
        _log(f"[AE] Erreur : {e}")
        return None


def _run_sigma() -> list:
    """Lance les règles Sigma (bloquant — tourne dans un thread)."""
    try:
        alerts = SigmaModel.run_rules()
        _log(f"[SIGMA] {len(alerts)} alertes déclenchées")
        return alerts
    except Exception as e:
        _log(f"[SIGMA] Erreur : {e}")
        return []


def _run_fusion(ae_result: dict | None, sigma_alerts: list, cursor: str):
    """
    Appelle fusion_router pour :
    - Corréler AE et Sigma (detection_source = 'both')
    - Générer les explications LLM
    """
    from fusion_router import FusionRouter
    import pandas as pd

    router = FusionRouter()
    router._sigma_alerts_cache = sigma_alerts

    # Fusion sur les anomalies AE
    if ae_result and "df_result" in ae_result:
        df = ae_result["df_result"]
        if not df.empty:
            router.process_dataframe(df, thresholds={})
            _log(f"[FUSION] {len(df)} anomalies AE traitées")

    # Fusion sur les alertes Sigma
    if sigma_alerts:
        router.process_sigma_alerts(sigma_alerts)
        _log(f"[FUSION] {len(sigma_alerts)} alertes Sigma traitées")