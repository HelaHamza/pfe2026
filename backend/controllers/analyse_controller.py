"""
backend/controllers/analyse_controller.py
==========================================
CONTROLLER — Analyse principale.

GARANTIES :
  1. Verrou IN-PROCESS thread-safe (threading.Lock) — protège double-clic
  2. AUTO-RESET si state bloqué > STALE_LOCK_MINUTES (crash / reload uvicorn)
  3. reset_state() exposé pour /run/reset (déblocage manuel)
  4. Verrou ES atomique (claim_cursor) — protège workers concurrents
  5. Curseur strict : fenêtre fermée ]cursor, new_cursor]
  6. NOUVEAU — Stats du snapshot calculées EN MÉMOIRE (df_result + sigma_alerts),
     plus aucun re-query ES après l'analyse → chiffres 100% déterministes,
     stables entre reloads. Plus de time.sleep(1.5).
  7. NOUVEAU — Corrélation AE↔Sigma EXACTE par intersection d'IDs :
     {source_id des anomalies AE} ∩ {matched_doc_ids des alertes Sigma}.
"""

import asyncio
import os
import sys
import threading
from collections import Counter
from datetime import datetime, timezone

import pandas as pd

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ROOT    = os.path.dirname(_BACKEND)
_CORE    = os.path.join(_ROOT, "core")

for _p in [_CORE, _ROOT]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from ml.ae_model      import AEModel
from ml.sigma_model   import SigmaModel
from models.es_repository import ESRepository, _derive_source

# ── Configuration ─────────────────────────────────────────────────────────────
STALE_LOCK_MINUTES = 10

# ── État global thread-safe ───────────────────────────────────────────────────
_state_lock = threading.Lock()
_state = {
    "running":     False,
    "started_at":  None,
    "finished_at": None,
    "done":        False,
    "error":       None,
    "logs":        [],
    "run_cursor":  None,
    "new_cursor":  None,
}


def _check_stale_locked():
    """À appeler UNIQUEMENT depuis un bloc with _state_lock."""
    if _state["running"] and _state["started_at"]:
        try:
            started = datetime.fromisoformat(
                _state["started_at"].replace("Z", "+00:00")
            )
            age_min = (datetime.now(timezone.utc) - started).total_seconds() / 60
            if age_min > STALE_LOCK_MINUTES:
                print(f"[AnalyseController] ⚠ Lock obsolète ({age_min:.1f} min) — auto-reset")
                _state["running"] = False
                _state["error"]   = f"Auto-reset après {age_min:.1f} min sans réponse"
                _state["done"]    = True
        except Exception:
            pass


def get_state() -> dict:
    with _state_lock:
        _check_stale_locked()
        return dict(_state)


def reset_state():
    with _state_lock:
        print("[AnalyseController] ⚠ Reset manuel du state")
        _state.update(
            running=False, done=False, error=None,
            started_at=None, finished_at=None, logs=[],
            run_cursor=None, new_cursor=None,
        )


def set_running(value: bool):
    """DEPRECATED — conservé pour compatibilité."""
    with _state_lock:
        _state["running"] = value


def _log(msg: str):
    entry = {"ts": datetime.now(timezone.utc).isoformat(), "msg": msg}
    with _state_lock:
        _state["logs"].append(entry)
    print(f"[AnalyseController] {msg}")


def _set_field(**kwargs):
    with _state_lock:
        _state.update(**kwargs)


def _try_acquire_lock() -> bool:
    with _state_lock:
        _check_stale_locked()
        if _state["running"]:
            return False
        _state.update(
            running=True, done=False, error=None, logs=[],
            finished_at=None, run_cursor=None, new_cursor=None,
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        return True


# ── Pipeline principal ────────────────────────────────────────────────────────

async def run_analyse():
    if not _try_acquire_lock():
        print("[AnalyseController] Analyse déjà en cours — abandon")
        return

    try:
        # ── Étape 1 : curseur courant ────────────────────────────────────────
        cursor = ESRepository.get_cursor()
        _set_field(run_cursor=cursor)
        _log(f"Analyse depuis : {cursor}")

        new = ESRepository.get_new_logs_count(cursor)
        _log(f"Nouveaux logs : {new['total']}")
        for src, cnt in new.get("by_source", {}).items():
            _log(f"  {src} : {cnt} logs")

        if new["total"] == 0:
            _log("Aucun nouveau log — analyse ignorée (snapshot précédent conservé)")
            return

        new_cursor = new.get("max_timestamp")
        if not new_cursor:
            _log("Impossible de déterminer max_timestamp — abandon")
            return

        _set_field(new_cursor=new_cursor)

        # ── Étape 1bis : CLAIM atomique ──────────────────────────────────────
        if not ESRepository.claim_cursor(expected_cursor=cursor, new_cursor=new_cursor):
            _log("⚠ Curseur déjà avancé par un autre run — abandon (pas de doublon)")
            return

        _log(f"✓ Curseur claimé : {cursor} → {new_cursor}")

        # ── Étape 2 : AE + Sigma en parallèle ────────────────────────────────
        _log("Lancement AE + Sigma en parallèle...")

        loop = asyncio.get_running_loop()
        ae_future    = loop.run_in_executor(None, _run_ae,    cursor, new_cursor)
        sigma_future = loop.run_in_executor(None, _run_sigma, cursor, new_cursor)

        ae_result, sigma_alerts = await asyncio.gather(
            ae_future, sigma_future, return_exceptions=True
        )

        if isinstance(ae_result, Exception):
            _log(f"[AE] Erreur : {ae_result}")
            ae_result = None
        if isinstance(sigma_alerts, Exception):
            _log(f"[SIGMA] Erreur : {sigma_alerts}")
            sigma_alerts = []

        _log(
            f"AE : {'✓' if ae_result is not None else '✗'}  |  "
            f"Sigma : {'✓' if sigma_alerts is not None else '✗'}"
        )

        # ── Étape 3 : fusion (corrélation + LLM + snapshot mémoire) ──────────
        _log("Corrélation AE ↔ Sigma + génération LLM...")
        try:
            _run_fusion(ae_result, sigma_alerts or [], cursor, new_cursor)
        except Exception as e:
            _log(f"[FUSION] Erreur non bloquante : {e}")

        _log("✓ Analyse terminée")

    except Exception as e:
        _set_field(error=str(e))
        _log(f"ERREUR CRITIQUE : {e}")
    finally:
        _set_field(
            running=False,
            done=True,
            finished_at=datetime.now(timezone.utc).isoformat(),
        )


# ── Fonctions bloquantes (AE / Sigma) ─────────────────────────────────────────

def _run_ae(cursor: str, until: str = None) -> dict | None:
    try:
        try:
            result = AEModel.infer(cursor, until=until)
        except TypeError:
            result = AEModel.infer(cursor)
            if result and "df_result" in result:
                cols = result["df_result"].columns.tolist()
                print("[DEBUG] colonnes df_result:", cols)
                print("[DEBUG] '_id' présent:", "_id" in cols, "| 'source_id' présent:", "source_id" in cols)
        _log(f"[AE] {result['n_anomalies']} anomalies sur {result['n_logs']} logs")
        return result
    except Exception as e:
        _log(f"[AE] Erreur : {e}")
        return None


def _run_sigma(cursor: str = None, until: str = None) -> list:
    try:
        try:
            alerts = SigmaModel.run_rules(cursor=cursor, until=until)
        except TypeError:
            alerts = SigmaModel.run_rules(cursor=cursor)
        _log(f"[SIGMA] {len(alerts)} alertes déclenchées")
        return alerts
    except Exception as e:
        _log(f"[SIGMA] Erreur : {e}")
        return []


# ── Helpers extraction champs Sigma (gèrent clés nues OU préfixées alert.) ────

def _sig_level(a: dict) -> str:
    return str(a.get("level", a.get("alert.level", "low"))).lower()


def _sig_title(a: dict) -> str:
    return a.get("title", a.get("alert.title", ""))


def _sig_tactic(a: dict) -> str:
    t = a.get("tactic", a.get("alert.tactic", ""))
    return "" if t in ("voir règle", "voir regle", "") else t


def _sig_source(a: dict) -> str:
    ls = a.get("log_source", "")
    return _derive_source(_sig_title(a), a.get("tactic", a.get("alert.tactic", "")), ls)


def _sig_matched_ids(a: dict) -> list:
    return a.get("matched_doc_ids", []) or []


# ── Fusion : corrélation exacte + LLM + snapshot déterministe ─────────────────

def _run_fusion(ae_result: dict | None, sigma_alerts: list,
                cursor: str, new_cursor: str):
    """
    SANS FusionRouter (retiré car redondant). Fait :
      1. Corrélation EXACTE par intersection d'IDs
         {source_id des anomalies AE} ∩ {matched_doc_ids des alertes Sigma}
      2. Conserve les explications LLM Sigma via explain_sigma_alerts()
         (les explications AE sont déjà générées par write_to_elasticsearch
          au moment de l'inférence AE)
      3. Snapshot MongoDB calculé EN MÉMOIRE — déterministe.
    """
    # ── 0. IDs des logs détectés en anomalie par l'AE ────────────────────────
    ae_anomaly_log_ids: set[str] = set()
    ae_by_source       = {}
    ae_by_source_dict  = {}
    logs_by_source     = {}

    if ae_result and "df_result" in ae_result:
        df = ae_result["df_result"]
        for src, grp in df.groupby("log_source"):
            src       = str(src)
            anomalies = int((grp.get("ae_is_anomaly", 0) == 1).sum())
            ae_by_source[src]      = {"windows": len(grp), "anomalies": anomalies}
            ae_by_source_dict[src] = anomalies
            logs_by_source[src]    = len(grp)

        anom_mask = df.get("ae_is_anomaly", pd.Series(0, index=df.index)) == 1
        for _, row in df[anom_mask].iterrows():
            sid = row.get("source_id") or row.get("_id")
            if sid:
                ae_anomaly_log_ids.add(str(sid))

    _log(f"[FUSION] {len(ae_anomaly_log_ids)} logs en anomalie AE")

    # ── 1. Corrélation exacte par intersection d'IDs ─────────────────────────
    correlated_alerts = 0
    correlated_log_ids: set[str] = set()

    for a in sigma_alerts:
        sig_ids = set(str(x) for x in (a.get("matched_doc_ids", []) or []))
        inter   = sig_ids & ae_anomaly_log_ids
        is_corr = len(inter) > 0
        a["ae_correlated"]    = is_corr
        a["detection_source"] = "both" if is_corr else "sigma_only"
        if is_corr:
            correlated_alerts += 1
            correlated_log_ids |= inter
            _log(f"[FUSION] BOTH : {_sig_title(a)} ({len(inter)} log(s) commun(s))")

    _log(f"[FUSION] Corrélées — {correlated_alerts} alertes | "
         f"{len(correlated_log_ids)} logs")

    # ── 2. Explications LLM Sigma (conservées, sans FusionRouter) ────────────
    if sigma_alerts:
        try:
            from sigma_engine import explain_sigma_alerts
            explain_sigma_alerts(sigma_alerts)
            _log(f"[FUSION] ✓ Explications LLM générées pour {len(sigma_alerts)} alertes")
        except Exception as e:
            _log(f"[FUSION] explain_sigma_alerts non bloquant : {e}")
    # (les explications AE sont déjà écrites par write_to_elasticsearch)

     # ── 3. Stats en MÉMOIRE — déterministes ──────────────────────────────────
    try:
        total_ae    = sum(ae_by_source_dict.values())
        total_sigma = len(sigma_alerts)
        critical    = sum(1 for a in sigma_alerts if _sig_level(a) == "critical")

        sigma_by_level = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for a in sigma_alerts:
            lvl = _sig_level(a)
            sigma_by_level[lvl if lvl in sigma_by_level else "low"] += 1

        sigma_by_source = {
            "syslog": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "auth":   {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "auditd": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        }
        for a in sigma_alerts:
            src = _sig_source(a)
            if src == "unknown":
                continue
            sigma_by_source.setdefault(
                src, {"critical": 0, "high": 0, "medium": 0, "low": 0}
            )
            lvl = _sig_level(a)
            sigma_by_source[src][lvl if lvl in sigma_by_source[src] else "low"] += 1

        title_counts = Counter(_sig_title(a) for a in sigma_alerts if _sig_title(a))
        by_tactic = [{"tactic": t, "count": c}
                     for t, c in title_counts.most_common(8)]

        both       = correlated_alerts
        sigma_only = max(total_sigma - correlated_alerts, 0)
        ae_only    = max(total_ae - len(correlated_log_ids), 0)
        detection_src = {
            "ae_only":         ae_only,
            "sigma_only":      sigma_only,
            "both":            both,
            "total":           ae_only + sigma_only + both,
            "correlated_logs": len(correlated_log_ids),
        }

        stats = {
            "ae_anomalies":    total_ae,
            "sigma_alerts":    total_sigma,
            "critical":        critical,
            "correlated_both": both,
            "cursor":          cursor or "",
        }

        timeline = ESRepository.get_timeline_window(days=7, lo=None, hi=new_cursor)

        # ── 🆕 NOUVEAU : construire results[] en mémoire ──────────────────────
        snapshot_results = _build_results(ae_result, sigma_alerts)
        _log(f"[FUSION] {len(snapshot_results)} résultats normalisés pour le snapshot")
        # ─────────────────────────────────────────────────────────────────────

        with _state_lock:
            started_at = _state.get("started_at", "")

        ESRepository.save_report(
            stats             = stats,
            cursor            = cursor,
            new_cursor        = new_cursor,
            started_at        = started_at,
            ae_by_source      = ae_by_source,
            ae_by_source_dict = ae_by_source_dict,
            sigma_by_source   = sigma_by_source,
            sigma_by_level    = sigma_by_level,
            by_tactic         = by_tactic,
            detection_src     = detection_src,
            logs_by_source    = logs_by_source,
            timeline          = timeline,
            results           = snapshot_results,   # 🆕
        )
        _log(f"[FUSION] ✓ Snapshot figé — {total_ae} AE | {total_sigma} Sigma "
             f"| {critical} crit | {both} corrélées")

    except Exception as e:
        _log(f"[FUSION] save_report non bloquant : {e}")


# ── 🆕 NOUVELLE FONCTION à ajouter après _run_fusion ─────────────────────────

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
_SRC_RANK = {"both": 0, "sigma_only": 1, "ae_only": 2, "unknown": 3}

def _build_results(ae_result: dict | None, sigma_alerts: list) -> list:
    """
    Construit la liste normalisée des résultats depuis les données EN MÉMOIRE.
    Même structure que ResultsController._normalize() — la table peut lire
    directement depuis le snapshot sans passer par ES.
    """
    results = []

    # ── Anomalies AE ─────────────────────────────────────────────────────────
    if ae_result and "df_result" in ae_result:
        df = ae_result["df_result"]
        anom_mask = df.get("ae_is_anomaly", pd.Series(0, index=df.index)) == 1
        df_anom = df[anom_mask]

        for _, row in df_anom.iterrows():
            # Sévérité : utiliser kb_severity si présent, sinon calculer
            kb_sev = str(row.get("kb_severity", "") or "").upper()
            if not kb_sev or kb_sev in ("", "UNKNOWN", "NAN", "NONE"):
                # Calculer depuis composite_score ou ae_anomaly_score
                score = float(row.get("composite_score", 0) or 0)
                ae_score = float(row.get("ae_anomaly_score", 0) or 0)
                if score >= 7 or ae_score >= 0.85:
                    kb_sev = "CRITICAL"
                elif score >= 5 or ae_score >= 0.70:
                    kb_sev = "HIGH"
                elif score >= 3 or ae_score >= 0.50:
                    kb_sev = "MEDIUM"
                else:
                    kb_sev = "LOW"

            src = str(row.get("log_source", "") or "")
            detection_source = str(row.get("detection_source", "ae_only") or "ae_only")

            results.append({
                "id":               str(row.get("source_id") or row.get("_id") or ""),
                "type":             "anomaly",
                "@timestamp":       str(row.get("@timestamp", "") or ""),
                "severity":         kb_sev,
                "kb_severity":      kb_sev,
                "detection_source": detection_source,
                "title":            src or "Anomalie AE",
                "log_source":       src,
                "tactic":           "",
                "score":            float(row.get("ae_anomaly_score", 0) or 0),
                "ae_anomaly_score": float(row.get("ae_anomaly_score", 0) or 0),
                "ae_correlated":    detection_source == "both",
                "llm_explanation":  str(row.get("llm_explanation", "") or ""),
            })

    # ── Alertes Sigma ─────────────────────────────────────────────────────────
    for a in sigma_alerts:
        lvl = _sig_level(a).upper()
        if lvl not in _SEV_RANK:
            lvl = "LOW"

        detection_source = a.get("detection_source", "sigma_only")

        results.append({
            "id":               str(a.get("id", "") or ""),
            "type":             "alert",
            "@timestamp":       str(a.get("@timestamp", "") or ""),
            "severity":         lvl,
            "kb_severity":      lvl,
            "level":            lvl,
            "detection_source": detection_source,
            "title":            _sig_title(a),
            "log_source":       _sig_source(a),
            "tactic":           _sig_tactic(a),
            "score":            None,
            "ae_anomaly_score": None,
            "hits":             a.get("hits", a.get("alert.hits", 0)),
            "ae_correlated":    a.get("ae_correlated", False),
            "llm_explanation":  str(a.get("llm_explanation", "") or ""),
        })

    # Tri : même logique que ResultsController
    results.sort(key=lambda x: (x.get("@timestamp") or ""), reverse=True)
    results.sort(key=lambda x: (
        _SRC_RANK.get((x.get("detection_source") or "unknown").lower(), 3),
        _SEV_RANK.get((x.get("kb_severity") or "unknown").upper(), 4),
    ))

    return results