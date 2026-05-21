# core/test_fusion_correlation.py
"""
Tests unitaires du FusionRouter.
La corrélation compare _ae_analysis_time (moment où l'AE tourne)
avec @timestamp des alertes Sigma — pas le timestamp des logs sources.
Lance avec : python3 core/test_fusion_correlation.py
"""
import sys, os
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from fusion_router import FusionRouter, CORRELATION_WINDOW_SECONDS

_NOW = datetime.now(timezone.utc)


def ts(offset_seconds=0) -> str:
    return (_NOW + timedelta(seconds=offset_seconds)).isoformat()


def make_router(ae_sources: list, analysis_offset=0) -> FusionRouter:
    """
    Crée un router simulant une analyse AE qui a tourné à
    _NOW + analysis_offset secondes, sur les sources listées.
    """
    router = FusionRouter()
    router._ae_analysis_time = _NOW + timedelta(seconds=analysis_offset)
    router._ae_detections    = {src: 10 for src in ae_sources}
    return router


# ── Tests _check_ae_correlation (Sigma → AE) ─────────────────────────────────

def test_both_auth_same_window():
    """AE sur auth + alerte Sigma auth créée 1min après l'analyse → True."""
    router = make_router(["auth"], analysis_offset=0)
    alert  = {
        "title":      "SSH Rapid Connection Attempts",
        "tactic":     "T1110.001 - Password Guessing",
        "@timestamp": ts(+60),   # alerte Sigma créée 1min après l'analyse AE
    }
    assert router._check_ae_correlation(alert) is True
    print("PASS  test_both_auth_same_window")


def test_both_auth_before_analysis():
    """Alerte Sigma créée 2min AVANT l'analyse AE → True (dans la fenêtre)."""
    router = make_router(["auth"], analysis_offset=0)
    alert  = {
        "title":      "Failed SSH Login as Root",
        "tactic":     "T1078",
        "@timestamp": ts(-120),  # alerte créée 2min avant
    }
    assert router._check_ae_correlation(alert) is True
    print("PASS  test_both_auth_before_analysis")


def test_no_both_outside_window():
    """Alerte Sigma créée 2h avant l'analyse AE → False."""
    router = make_router(["auth"], analysis_offset=0)
    alert  = {
        "title":      "SSH Rapid Connection Attempts",
        "tactic":     "T1110.001",
        "@timestamp": ts(-7200),
    }
    assert router._check_ae_correlation(alert) is False
    print("PASS  test_no_both_outside_window")


def test_no_both_source_mismatch():
    """AE sur syslog + alerte Sigma auth → False (sources différentes)."""
    router = make_router(["syslog"], analysis_offset=0)
    alert  = {
        "title":      "SSH Rapid Connection Attempts",
        "tactic":     "T1110.001 - Password Guessing",
        "@timestamp": ts(-30),
    }
    assert router._check_ae_correlation(alert) is False
    print("PASS  test_no_both_source_mismatch")


def test_no_both_no_ae_analysis():
    """_ae_analysis_time non défini → False."""
    router = FusionRouter()
    router._ae_detections    = {"auth": 5}
    # _ae_analysis_time reste None
    alert  = {
        "title":      "SSH Rapid Connection Attempts",
        "tactic":     "T1110.001",
        "@timestamp": ts(-30),
    }
    assert router._check_ae_correlation(alert) is False
    print("PASS  test_no_both_no_ae_analysis")


def test_both_auditd_cryptominer():
    """AE auditd + Sigma 'Cryptominer Execution' dans fenêtre → True."""
    router = make_router(["auditd"], analysis_offset=0)
    alert  = {
        "title":      "Cryptominer Execution",
        "tactic":     "T1496 - Resource Hijacking",
        "@timestamp": ts(+300),   # 5min après
    }
    assert router._check_ae_correlation(alert) is True
    print("PASS  test_both_auditd_cryptominer")


def test_both_auditd_reverse_shell():
    """AE auditd + Sigma 'Reverse Shell Indicators' → True."""
    router = make_router(["auditd"], analysis_offset=0)
    alert  = {
        "title":      "Reverse Shell Indicators",
        "tactic":     "T1059",
        "@timestamp": ts(-200),
    }
    assert router._check_ae_correlation(alert) is True
    print("PASS  test_both_auditd_reverse_shell")


def test_both_syslog_network_scan():
    """AE syslog + Sigma 'Network Scan Detected via Syslog' → True."""
    router = make_router(["syslog"], analysis_offset=0)
    alert  = {
        "title":      "Network Scan Detected via Syslog",
        "tactic":     "T1046 - Network Service Discovery",
        "@timestamp": ts(-100),
    }
    assert router._check_ae_correlation(alert) is True
    print("PASS  test_both_syslog_network_scan")


def test_no_ae_detections_for_source():
    """AE a tourné mais pas sur la source auth → False."""
    router = make_router(["auditd"], analysis_offset=0)  # seulement auditd
    alert  = {
        "title":      "Failed SSH Login as Root",
        "tactic":     "T1078",
        "@timestamp": ts(-30),
    }
    assert router._check_ae_correlation(alert) is False
    print("PASS  test_no_ae_detections_for_source")


# ── Tests _cross_check_sigma (AE → Sigma) ────────────────────────────────────

def test_cross_check_both_auditd():
    """AE auditd + alerte Sigma auditd dans fenêtre → 'both'."""
    router = make_router(["auditd"])
    router._sigma_alerts_cache = [{
        "title":      "Reverse Shell Indicators",
        "tactic":     "T1059",
        "@timestamp": ts(+60),
    }]
    anomaly = {"log_source": "auditd", "@timestamp": ts(-3600)}  # log ancien
    assert router._cross_check_sigma(anomaly) == "both"
    print("PASS  test_cross_check_both_auditd")


def test_cross_check_ae_only_outside_window():
    """Alerte Sigma créée 2h après l'analyse AE → 'ae_only'."""
    router = make_router(["auditd"])
    router._sigma_alerts_cache = [{
        "title":      "Reverse Shell Indicators",
        "tactic":     "T1059",
        "@timestamp": ts(+7200),  # 2h après l'analyse
    }]
    anomaly = {"log_source": "auditd", "@timestamp": ts(-3600)}
    assert router._cross_check_sigma(anomaly) == "ae_only"
    print("PASS  test_cross_check_ae_only_outside_window")


def test_cross_check_ae_only_different_source():
    """AE syslog + alerte Sigma auth → 'ae_only'."""
    router = make_router(["syslog"])
    router._sigma_alerts_cache = [{
        "title":      "SSH Rapid Connection Attempts",
        "tactic":     "T1110.001",
        "@timestamp": ts(+30),
    }]
    anomaly = {"log_source": "syslog", "@timestamp": ts(-3600)}
    assert router._cross_check_sigma(anomaly) == "ae_only"
    print("PASS  test_cross_check_ae_only_different_source")


def test_cross_check_no_sigma_cache():
    """Cache Sigma vide → 'ae_only'."""
    router = make_router(["auth"])
    router._sigma_alerts_cache = []
    anomaly = {"log_source": "auth", "@timestamp": ts()}
    assert router._cross_check_sigma(anomaly) == "ae_only"
    print("PASS  test_cross_check_no_sigma_cache")


def test_cross_check_no_ae_analysis_time():
    """_ae_analysis_time non défini → 'ae_only'."""
    router = FusionRouter()
    router._ae_detections = {"auth": 5}
    router._sigma_alerts_cache = [{
        "title":      "SSH Rapid Connection Attempts",
        "tactic":     "T1110.001",
        "@timestamp": ts(+30),
    }]
    anomaly = {"log_source": "auth", "@timestamp": ts()}
    assert router._cross_check_sigma(anomaly) == "ae_only"
    print("PASS  test_cross_check_no_ae_analysis_time")


def test_both_exactly_at_boundary():
    """Écart exactement égal à CORRELATION_WINDOW_SECONDS → 'both'."""
    router = make_router(["auth"])
    router._sigma_alerts_cache = [{
        "title":      "Failed SSH Login as Root",
        "tactic":     "T1078",
        "@timestamp": ts(-CORRELATION_WINDOW_SECONDS),
    }]
    anomaly = {"log_source": "auth", "@timestamp": ts(-3600)}
    assert router._cross_check_sigma(anomaly) == "both"
    print("PASS  test_both_exactly_at_boundary")


def test_ae_only_just_outside_boundary():
    """Écart = CORRELATION_WINDOW_SECONDS + 1s → 'ae_only'."""
    router = make_router(["auth"])
    router._sigma_alerts_cache = [{
        "title":      "Failed SSH Login as Root",
        "tactic":     "T1078",
        "@timestamp": ts(-(CORRELATION_WINDOW_SECONDS + 1)),
    }]
    anomaly = {"log_source": "auth", "@timestamp": ts(-3600)}
    assert router._cross_check_sigma(anomaly) == "ae_only"
    print("PASS  test_ae_only_just_outside_boundary")


# ── Scénario réel simulé ──────────────────────────────────────────────────────

def test_real_scenario_8min_gap():
    """
    Scénario réel observé :
    - AE tourne à T0
    - Sigma génère ses alertes à T0 + 8 minutes (480s < 600s)
    → devrait donner 'both' pour les sources communes
    """
    router = make_router(["auditd", "auth", "syslog"], analysis_offset=0)

    # Alertes Sigma créées 8min après l'analyse AE
    sigma_alerts = [
        {"title": "Cryptominer Execution",            "tactic": "T1496",
         "@timestamp": ts(+480)},
        {"title": "Reverse Shell Indicators",         "tactic": "T1059",
         "@timestamp": ts(+475)},
        {"title": "Failed SSH Login as Root",         "tactic": "T1078",
         "@timestamp": ts(+470)},
        {"title": "Network Scan Detected via Syslog", "tactic": "T1046",
         "@timestamp": ts(+465)},
    ]

    results = {a["title"]: router._check_ae_correlation(a)
               for a in sigma_alerts}

    assert results["Cryptominer Execution"]            is True,  "Cryptominer doit être both"
    assert results["Reverse Shell Indicators"]         is True,  "Reverse shell doit être both"
    assert results["Failed SSH Login as Root"]         is True,  "SSH login doit être both"
    assert results["Network Scan Detected via Syslog"] is True,  "Network scan doit être both"
    print("PASS  test_real_scenario_8min_gap — tous both ✓")


def test_real_scenario_outside_window():
    """
    Même scénario mais écart = 15 minutes (900s > 600s)
    → toutes les alertes restent sigma_only
    """
    router = make_router(["auditd", "auth", "syslog"], analysis_offset=0)

    sigma_alerts = [
        {"title": "Cryptominer Execution",    "tactic": "T1496",
         "@timestamp": ts(+900)},
        {"title": "Failed SSH Login as Root", "tactic": "T1078",
         "@timestamp": ts(+910)},
    ]

    results = {a["title"]: router._check_ae_correlation(a)
               for a in sigma_alerts}

    assert results["Cryptominer Execution"]    is False
    assert results["Failed SSH Login as Root"] is False
    print("PASS  test_real_scenario_outside_window — tous sigma_only ✓")


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_both_auth_same_window,
        test_both_auth_before_analysis,
        test_no_both_outside_window,
        test_no_both_source_mismatch,
        test_no_both_no_ae_analysis,
        test_both_auditd_cryptominer,
        test_both_auditd_reverse_shell,
        test_both_syslog_network_scan,
        test_no_ae_detections_for_source,
        test_cross_check_both_auditd,
        test_cross_check_ae_only_outside_window,
        test_cross_check_ae_only_different_source,
        test_cross_check_no_sigma_cache,
        test_cross_check_no_ae_analysis_time,
        test_both_exactly_at_boundary,
        test_ae_only_just_outside_boundary,
        test_real_scenario_8min_gap,
        test_real_scenario_outside_window,
    ]

    passed, failed = 0, 0
    for t in tests:
        try:
            t()
            passed += 1
        except AssertionError as e:
            print(f"FAIL  {t.__name__} — {e}")
            failed += 1
        except Exception as e:
            print(f"ERROR {t.__name__} — {type(e).__name__}: {e}")
            failed += 1

    print(f"\n{'='*45}")
    print(f"{passed}/{passed+failed} tests passés")
    if failed == 0:
        print("Logique de corrélation validée ✓")
    print(f"{'='*45}")