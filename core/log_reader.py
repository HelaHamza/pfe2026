"""
log_reader.py
=============
Rôle : lire les logs Linux en temps réel, les passer UNE SEULE FOIS
       à Sigma et à l'AE en parallèle, router le résultat.

Dépendances : fusion_router, rag_explainer, knowledge_base
Système      : journalctl (systemd)
"""

import asyncio
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor

_BASE = os.path.dirname(os.path.abspath(__file__))
for _p in [os.path.join(_BASE, "ML"), os.path.join(_BASE, "core")]:
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

from fusion_router import FusionRouter
from rag_explainer import make_grok_client, build_ml_dict

CURSOR_FILE    = "/tmp/ids_cursor.txt"
LOG_QUEUE_SIZE = 1000
LLM_QUEUE_SIZE = 50


def _load_cursor() -> int:
    try:
        return int(open(CURSOR_FILE).read().strip())
    except Exception:
        return 0


def _save_cursor(ts: int):
    try:
        with open(CURSOR_FILE, "w") as f:
            f.write(str(ts))
    except Exception:
        pass


class LogReader:

    def __init__(self, sigma_engine, ae_engine, router: FusionRouter):
        self.sigma  = sigma_engine
        self.ae     = ae_engine
        self.router = router

        try:
            self._grok = make_grok_client()
        except ValueError:
            self._grok = None
            print("[LogReader] LLM désactivé (GROK_API_KEY absent)")

        self._log_queue: asyncio.Queue = asyncio.Queue(maxsize=LOG_QUEUE_SIZE)
        self._llm_queue: asyncio.Queue = asyncio.Queue(maxsize=LLM_QUEUE_SIZE)
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ids")

        self.stats = {
            "logs_read":    0,
            "logs_dropped": 0,
            "alerts_total": 0,
            "alerts_ae":    0,
            "alerts_sigma": 0,
            "alerts_both":  0,
            "llm_called":   0,
            "llm_errors":   0,
        }

        self._alert_ring: list[dict] = []
        self._alert_ring_max = 200

    async def run(self):
        await asyncio.gather(
            self._tail_logs(),
            self._dispatch_worker(),
            self._llm_worker(),
        )

    async def _tail_logs(self):
        import subprocess
        cursor = _load_cursor()
        cmd = ["journalctl", "-f", "-o", "json"]
        if cursor:
            cmd += [f"--after-cursor={cursor}"]

        loop = asyncio.get_event_loop()
        proc = await loop.run_in_executor(
            None,
            lambda: subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        )
        print(f"[LogReader] journalctl démarré (cursor={cursor})")

        while True:
            raw = await loop.run_in_executor(None, proc.stdout.readline)
            if not raw:
                await asyncio.sleep(0.05)
                continue
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            self.stats["logs_read"] += 1
            try:
                self._log_queue.put_nowait(line)
            except asyncio.QueueFull:
                try:
                    self._log_queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                self._log_queue.put_nowait(line)
                self.stats["logs_dropped"] += 1

    async def _dispatch_worker(self):
        loop = asyncio.get_event_loop()

        while True:
            raw = await self._log_queue.get()

            try:
                log_entry = json.loads(raw)
            except json.JSONDecodeError:
                continue

            ts_str = log_entry.get("__REALTIME_TIMESTAMP", "0")
            try:
                ts = int(ts_str)
            except (ValueError, TypeError):
                ts = 0

            if ts and ts <= _load_cursor():
                continue

            sigma_fut = loop.run_in_executor(self._executor, self.sigma.match, log_entry)
            ae_fut    = loop.run_in_executor(self._executor, self.ae.reconstruction_error, log_entry)

            sigma_matches, ae_score = await asyncio.gather(
                sigma_fut, ae_fut, return_exceptions=True
            )

            if isinstance(sigma_matches, Exception):
                print(f"[LogReader] sigma error: {sigma_matches}")
                sigma_matches = []
            if isinstance(ae_score, Exception):
                print(f"[LogReader] ae error: {ae_score}")
                ae_score = 0.0

            sigma_matches = sigma_matches or []
            ae_score      = float(ae_score or 0.0)

            result = self.router.route(log_entry, sigma_matches, ae_score)

            if ts:
                _save_cursor(ts)

            if result.source.value == "none":
                continue

            self.stats["alerts_total"] += 1
            src = result.source.value
            if src == "ae_only":    self.stats["alerts_ae"]    += 1
            elif src == "sigma_only": self.stats["alerts_sigma"] += 1
            elif src == "both":       self.stats["alerts_both"]  += 1

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
            self._push_alert(alert_record)

            try:
                self._llm_queue.put_nowait((result, alert_record))
            except asyncio.QueueFull:
                pass

    async def _llm_worker(self):
        if not self._grok:
            while True:
                await self._llm_queue.get()

        loop = asyncio.get_event_loop()

        while True:
            result, alert_record = await self._llm_queue.get()

            anomaly_doc = dict(result.log_entry)
            anomaly_doc["ml"] = build_ml_dict(anomaly_doc)
            sev_map = {"critical": 8, "high": 6, "medium": 3, "low": 1}
            anomaly_doc["composite_score"] = sev_map.get(result.severity, 1)

            try:
                from rag_explainer import explain_anomaly
                expl = await loop.run_in_executor(
                    self._executor,
                    lambda: explain_anomaly(
                        anomaly_doc, es=None,
                        grok_client=self._grok,
                        detection_source=result.source.value,
                    )
                )
                alert_record["llm_explanation"] = expl.get("llm_explanation")
                alert_record["kb_severity"]     = expl.get("kb_severity", "UNKNOWN")
                self.stats["llm_called"] += 1
            except Exception as e:
                self.stats["llm_errors"] += 1
                alert_record["llm_explanation"] = f"Erreur LLM : {e}"
                print(f"[LogReader] LLM error: {e}")

    def _push_alert(self, record: dict):
        self._alert_ring.append(record)
        if len(self._alert_ring) > self._alert_ring_max:
            self._alert_ring.pop(0)

    def get_recent_alerts(self, limit: int = 50) -> list[dict]:
        return list(reversed(self._alert_ring[-limit:]))








# log_reader.py est le point d'entrée temps réel du pipeline — c'est lui qui lit les logs Linux au fur et à mesure qu'ils arrivent et les fait passer par les deux moteurs de détection.

# En une phrase : il lit chaque log une seule fois, lance Sigma et l'AE en parallèle sur ce log, puis envoie le résultat au FusionRouter.

# Concrètement il fait trois choses :

# Lire — il ouvre journalctl -f en continu (comme un tail -f mais en JSON). Chaque nouvelle ligne qui apparaît dans les logs système est récupérée.

# Dispatcher — pour chaque log, il lance sigma.match() et ae.reconstruction_error() en même temps (deux threads parallèles), puis passe les deux résultats à router.route() qui décide si c'est une alerte ou non.

# Transmettre — si c'est une alerte, il l'envoie dans une queue séparée pour que le LLM génère une explication, sans bloquer la lecture des logs suivants.

# Ce qui le distingue des autres fichiers : knowledge_base.py, rag_explainer.py et fusion_router.py traitent des anomalies déjà collectées (en batch, depuis Elasticsearch). log_reader.py lui travaille en temps réel, log par log, dès qu'ils arrivent sur le système.