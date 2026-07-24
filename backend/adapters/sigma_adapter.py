"""
adapters/sigma_adapter.py
=========================
FRONTIÈRE avec le moteur de règles Sigma (`sigma/detect/sigma_engine.py`).

Comme CNNAdapter : ne persiste rien, retourne des alertes. Après le patch
de sigma_engine (voir PATCH_sigma_engine.md), le moteur n'importe plus
`ReportRepository` et ne connaît plus de `run_id` — il détecte, point.

Deux fenêtres, volontairement différentes :
  - règles SIMPLES      : incrémentale ]cursor, until], bornée. Une alerte
                          manquée serait perdue → curseur obligatoire.
  - règles d'AGRÉGATION : glissante now−Xm. Un seuil « 5 échecs en 10 min »
                          n'a pas de sens sur une fenêtre historique
                          arbitraire → hors curseur, assumé.
"""
import logging
import sys

import config as CFG
from core.exceptions import PipelineStepError

log = logging.getLogger(__name__)


class SigmaAdapter:

    @staticmethod
    def _engine():
        if CFG.SIGMA_DETECT_DIR not in sys.path:
            sys.path.insert(0, CFG.SIGMA_DETECT_DIR)
        try:
            import sigma_engine
            return sigma_engine
        except ImportError as e:
            raise PipelineStepError(
                f"sigma_engine introuvable dans {CFG.SIGMA_DETECT_DIR} ({e}).")

    @classmethod
    def collect(cls, since: str, until: str) -> tuple[list[dict], str]:
        """Exécute les règles Sigma et enrichit les alertes des explications
        LLM. Retourne (alertes, curseur candidat).

        Le curseur candidat est `until` et non un watermark : une alerte
        Sigma est un match ponctuel, pas un épisode à cheval sur la borne."""
        SE = cls._engine()
        summary: list[dict] = []
        alerts: list[dict] = []

        log.info("Règles Sigma simples — fenêtre ]%s , %s]", since, until)
        alerts += SE.run_simple_rules(summary, cursor=since, until=until)

        log.info("Règles Sigma d'agrégation — fenêtres glissantes")
        alerts += SE.run_aggregation_rules(summary)

        # Explications LLM écrites DANS les dicts (plus aucun accès Mongo
        # depuis le moteur). Non bloquant : une alerte sans explication reste
        # une alerte qui doit remonter au SOC.
        try:
            SE.explain_sigma_alerts(alerts)
        except Exception as e:
            log.error("Explication LLM Sigma indisponible : %s", e)

        log.info("%d alerte(s) Sigma collectée(s)", len(alerts))
        return alerts, until