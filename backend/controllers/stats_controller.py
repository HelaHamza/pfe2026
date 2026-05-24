"""
backend/controllers/stats_controller.py
=========================================
FIX DÉFINITIF : TOUTES les stats viennent du SNAPSHOT MongoDB
                sauvegardé en fin d'analyse (save_report).

Avant ce fix :
  - get_stats() lisait depuis MongoDB ✓
  - get_by_level(), get_by_tactic(), get_attacks_by_source(), etc.
    recomptaient depuis ES en LIVE → chiffres qui bougent à chaque reload
    car Sigma écrit dans ES en continu (service indépendant).

Maintenant :
  - 100% des endpoints lisent depuis le snapshot MongoDB
  - Le snapshot est figé : stats, by_tactic, by_level, detection_src,
    sigma_by_source, ae_by_source, logs_by_source
  - Fallback ES seulement si le champ manque (vieux snapshot) — utilise
    alors une fenêtre fermée [started_at, finished_at] reproductible
"""

from backend.models.es_repository import ESRepository


# ── Helpers ───────────────────────────────────────────────────────────────────


def _last_report() -> dict | None:
    """Récupère le dernier report MongoDB. None si erreur."""
    try:
        return ESRepository.get_last_report()
    except Exception:
        return None


def _window(report: dict | None = None) -> tuple[str | None, str | None]:
    """
    Bornes ]lo, hi] de la dernière analyse.
    Délègue à ESRepository.get_last_window() (source unique de vérité,
    partagée avec ResultsController). Le paramètre `report` est ignoré
    et conservé uniquement pour compatibilité avec les appels existants.
    """
    return ESRepository.get_last_window()


# ── Controller ────────────────────────────────────────────────────────────────

class StatsController:

    # ── Stats globales ────────────────────────────────────────────────────────

    @staticmethod
    def get_stats() -> dict:
        """Stats globales — depuis le snapshot."""
        report = _last_report()
        if report:
            s = report.get("stats", {})
            return {
                "cursor":          report.get("cursor", ""),
                "ae_anomalies":    s.get("total_ae",    0),
                "sigma_alerts":    s.get("total_sigma", 0),
                "critical":        s.get("critical",    0),
                "correlated_both": s.get("correlated",  0),
            }
        # Fallback
        lo, _ = _window()
        return ESRepository.get_stats(lo)

    @staticmethod
    def get_timeline(days: int = 7) -> list[dict]:
        """Timeline depuis le snapshot si stockée, sinon ES sur fenêtre fermée."""
        report = _last_report()
        if report:
            tl = report.get("timeline")
            if tl:
                return tl
            lo, hi = _window(report)
            return ESRepository.get_timeline_window(days, lo, hi)
        lo, _ = _window()
        return ESRepository.get_timeline(days, cursor=lo)

    # ── Sigma ─────────────────────────────────────────────────────────────────

    @staticmethod
    def get_by_level() -> list[dict]:
        """Liste [{level, count}] — depuis snapshot."""
        report = _last_report()
        if report:
            d = report.get("stats", {}).get("sigma_by_level", {})
            if d:
                return [{"level": k, "count": v} for k, v in d.items()]
            lo, hi = _window(report)
            return ESRepository.get_alerts_by_level_window(lo, hi)
        lo, _ = _window()
        return ESRepository.get_alerts_by_level(lo)

    @staticmethod
    def get_sigma_by_level() -> dict:
        """Dict {critical, high, medium, low} — depuis snapshot."""
        report = _last_report()
        if report:
            d = report.get("stats", {}).get("sigma_by_level", {})
            if d:
                # Normalise les clés en minuscules
                return {k.lower(): v for k, v in d.items()}
            # Fallback : agréger sigma_by_source
            by_src = report.get("stats", {}).get("sigma_by_source", {})
            if by_src:
                result = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                for src_data in by_src.values():
                    for lvl in result:
                        result[lvl] += src_data.get(lvl, 0)
                if any(v > 0 for v in result.values()):
                    return result
            lo, hi = _window(report)
            return ESRepository.get_alerts_by_level_dict_window(lo, hi)
        lo, _ = _window()
        return ESRepository.get_alerts_by_level_dict(lo)

    @staticmethod
    def get_by_tactic() -> list[dict]:
        """Top tactiques/règles — depuis snapshot (figé)."""
        report = _last_report()
        if report:
            t = report.get("stats", {}).get("by_tactic")
            if t:
                return t
            lo, hi = _window(report)
            return ESRepository.get_alerts_by_tactic_window(lo, hi)
        lo, _ = _window()
        return ESRepository.get_alerts_by_tactic_since(lo)

    @staticmethod
    def get_sigma_by_source() -> dict:
        """Dict {src: {critical, high, medium, low}} — depuis snapshot."""
        report = _last_report()
        if report:
            d = report.get("stats", {}).get("sigma_by_source", {})
            if d:
                return d
            lo, hi = _window(report)
            return ESRepository.get_sigma_by_source_window(lo, hi)
        lo, _ = _window()
        return ESRepository.get_sigma_by_source(lo)

    # ── AE ────────────────────────────────────────────────────────────────────

    @staticmethod
    def get_by_source() -> list[dict]:
        """Liste [{source, count}] — depuis snapshot."""
        report = _last_report()
        if report:
            d = report.get("stats", {}).get("ae_by_source_dict", {})
            if d:
                return [{"source": k, "count": v} for k, v in d.items()]
            lo, hi = _window(report)
            return ESRepository.get_anomalies_by_source_window(lo, hi)
        lo, _ = _window()
        return ESRepository.get_anomalies_by_source_since(lo)

    @staticmethod
    def get_anomalies_by_source() -> dict:
        """Dict {src: count} — depuis snapshot."""
        report = _last_report()
        if report:
            d = report.get("stats", {}).get("ae_by_source_dict", {})
            if d:
                return d
            # Fallback : convertir ae_by_source (format {src: {windows, anomalies}})
            ae_src = report.get("stats", {}).get("ae_by_source", {})
            if ae_src:
                result = {}
                for src, data in ae_src.items():
                    if isinstance(data, dict):
                        result[src] = data.get("anomalies", 0)
                    else:
                        result[src] = int(data)
                return result
            lo, hi = _window(report)
            return ESRepository.get_anomalies_by_source_dict_window(lo, hi)
        lo, _ = _window()
        return ESRepository.get_anomalies_by_source_dict(lo)

    @staticmethod
    def get_ae_stats_by_source() -> dict:
        """
        Dict {src: {logs, windows, anomalies, severity}} — depuis snapshot.
        Combine logs_by_source + ae_by_source pour produire le bloc
        "Logs & anomalies AE par type" du dashboard.
        """
        report = _last_report()
        if report:
            stats = report.get("stats", {})
            logs_by  = stats.get("logs_by_source", {})
            ae_by    = stats.get("ae_by_source", {})
            sigma_by = stats.get("sigma_by_source", {})

            if logs_by or ae_by:
                # Sources = union de toutes les clés vues
                all_sources = set(logs_by) | set(ae_by) | set(sigma_by)
                result = {}
                for src in all_sources:
                    ae_data = ae_by.get(src, {})
                    if isinstance(ae_data, dict):
                        windows   = ae_data.get("windows", 0)
                        anomalies = ae_data.get("anomalies", 0)
                    else:
                        windows   = 0
                        anomalies = int(ae_data)

                    # Sévérité max depuis sigma_by_source pour cette src
                    sev_data = sigma_by.get(src, {}) if isinstance(sigma_by, dict) else {}
                    severity = None
                    if sev_data.get("critical", 0) > 0:
                        severity = "critical"
                    elif sev_data.get("high", 0) > 0:
                        severity = "high"
                    elif sev_data.get("medium", 0) > 0:
                        severity = "medium"
                    elif anomalies > 0:
                        severity = "low"

                    result[src] = {
                        "logs":      logs_by.get(src, 0),
                        "windows":   windows,
                        "anomalies": anomalies,
                        "severity":  severity,
                    }
                return result

            lo, hi = _window(report)
            return ESRepository.get_ae_stats_by_source_window(lo, hi)
        lo, _ = _window()
        return ESRepository.get_ae_stats_by_source(lo)

    # ── Logs bruts ────────────────────────────────────────────────────────────

    @staticmethod
    def get_logs_by_source() -> dict:
        """Logs analysés par source — depuis snapshot."""
        report = _last_report()
        if report:
            d = report.get("stats", {}).get("logs_by_source", {})
            if d:
                return d
            lo, hi = _window(report)
            return ESRepository.get_logs_by_source_window(lo, hi)
        lo, _ = _window()
        return ESRepository.get_logs_by_source(lo)

    # ── Mixtes ────────────────────────────────────────────────────────────────

    @staticmethod
    def get_detection_source_stats() -> dict:
        """{ae_only, sigma_only, both, total} — depuis snapshot."""
        report = _last_report()
        if report:
            d = report.get("stats", {}).get("detection_source", {})
            if d:
                return d
            lo, hi = _window(report)
            return ESRepository.get_detection_source_stats_window(lo, hi)
        lo, _ = _window()
        return ESRepository.get_detection_source_stats(lo)

    @staticmethod
    def get_attacks_by_source() -> dict:
        """{ae: {src: cnt}, sigma: {total, by_level}} — depuis snapshot."""
        report = _last_report()
        if report:
            stats = report.get("stats", {})
            ae_dict = stats.get("ae_by_source_dict", {})
            if not ae_dict:
                # Reconstruire depuis ae_by_source format dict
                ae_raw = stats.get("ae_by_source", {})
                ae_dict = {
                    k: (v.get("anomalies", 0) if isinstance(v, dict) else int(v))
                    for k, v in ae_raw.items()
                }
            sigma_lvl = stats.get("sigma_by_level", {})
            if sigma_lvl or ae_dict:
                return {
                    "ae": ae_dict,
                    "sigma": {
                        "total":    stats.get("total_sigma", 0),
                        "by_level": sigma_lvl,
                    },
                }
            lo, hi = _window(report)
            return ESRepository.get_attacks_by_source_window(lo, hi)
        lo, _ = _window()
        return ESRepository.get_attacks_by_source(lo)