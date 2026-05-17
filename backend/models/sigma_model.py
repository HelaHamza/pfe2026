"""
backend/models/sigma_model.py
==============================
MODEL — Règles Sigma.
Wrapper autour de sigma/detect/main.py.
Expose run_rules() qui applique toutes les règles sur ES.
"""

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ROOT    = os.path.dirname(_BACKEND)
_SIGMA   = os.path.join(_ROOT, "sigma", "detect")

for _p in [_SIGMA, _ROOT]:
    if _p not in sys.path:
        sys.path.insert(0, _p)


class SigmaModel:
    """
    Wrapper autour de sigma/detect/main.py.
    run_rules() applique les règles simples + agrégation sur ES
    et retourne la liste des alertes déclenchées.
    """

    @staticmethod
    def run_rules() -> list[dict]:
        """
        Lance toutes les règles Sigma sur ES.
        Retourne la liste des alertes avec es_id.
        Chaque alerte est un dict :
            {title, level, tactic, hits, details, es_id}
        """
        from main import run_simple_rules, run_aggregation_rules

        summary    = []
        all_alerts = []

        print("[SigmaModel] Lancement des règles simples...")
        all_alerts += run_simple_rules(summary)

        print("[SigmaModel] Lancement des règles avec agrégation...")
        all_alerts += run_aggregation_rules(summary)

        print(f"[SigmaModel] ✓ {len(all_alerts)} alertes déclenchées")
        for a in summary:
            print(f"  [{a['level']}] {a['rule']} — {a['hits']} hit(s)")

        return all_alerts