# log_reader.py
import subprocess, json, threading
from fusion_router import FusionRouter

class LogReader:
    def __init__(self, sigma_engine, ae_engine, router: FusionRouter):
        self.sigma   = sigma_engine
        self.ae      = ae_engine
        self.router  = router

    def tail_logs(self):
        proc = subprocess.Popen(
            ["journalctl", "-f", "-o", "json"],
            stdout=subprocess.PIPE
        )
        for raw_line in proc.stdout:
            try:
                self._process(raw_line.decode("utf-8", errors="replace"))
            except Exception as e:
                print(f"[LogReader] {e}")

    def _process(self, raw: str):
        """Chaque log lu UNE seule fois — deux branches parallèles."""
        log_entry = self._parse(raw)
        if not log_entry:
            return

        # Résultats des deux branches
        sigma_result = [None]
        ae_result    = [None]

        def run_sigma():
            sigma_result[0] = self.sigma.match(log_entry)

        def run_ae():
            ae_result[0] = self.ae.reconstruction_error(log_entry)

        t1 = threading.Thread(target=run_sigma)
        t2 = threading.Thread(target=run_ae)
        t1.start(); t2.start()
        t1.join();  t2.join()

        result = self.router.route(
            log_entry,
            sigma_matches=sigma_result[0] or [],
            ae_score=ae_result[0] or 0.0,
        )
        if result.source.value != "none":
            self._handle_alert(result)

    def _parse(self, raw: str) -> dict | None:
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    def _handle_alert(self, result):
        from rag_explainer import make_grok_client, explain_anomaly
        try:
            grok = make_grok_client()
            explanation = explain_anomaly(
                result.log_entry, es=None, grok_client=grok,
                detection_source=result.source.value
            )
            print(f"[ALERT] {result.source.value.upper()} | "
                  f"sev={result.severity} | "
                  f"{result.log_entry.get('log_source','?')}")
        except Exception as e:
            print(f"[LogReader] LLM error: {e}")