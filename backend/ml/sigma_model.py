"""
backend/models/sigma_model.py
==============================
MODEL — Règles Sigma.
Wrapper autour de sigma/detect/main.py.
Expose run_rules(cursor, until) qui applique toutes les règles sur ES.

NOUVEAU :
  - run_rules accepte cursor / until et les propage à run_simple_rules
    (fenêtre fermée ]cursor, until]). Les règles d'agrégation gardent
    leur fenêtre glissante now-Xm (sémantique de détection de rafale).
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
    run_rules() applique les règles simples (fenêtre de session)
    + agrégation (fenêtre glissante) sur ES.
    """

    @staticmethod
    def run_rules(cursor: str = None, until: str = None) -> list[dict]:
        """
        Lance toutes les règles Sigma sur ES.

        Args:
            cursor : borne basse exclusive (>cursor). Si None → pas de borne basse.
            until  : borne haute inclusive (<=until). Si None → pas de borne haute.

        Chaque alerte retournée est un dict :
            {title, level, tactic, hits, details, es_id, matched_doc_ids}
        """
        from sigma_engine import run_simple_rules, run_aggregation_rules

        summary    = []
        all_alerts = []

        print(f"[SigmaModel] Règles simples (fenêtre ]{cursor}, {until}])...")
        all_alerts += run_simple_rules(summary, cursor=cursor, until=until)

        print("[SigmaModel] Règles avec agrégation (fenêtre glissante now-Xm)...")
        all_alerts += run_aggregation_rules(summary)

        print(f"[SigmaModel] ✓ {len(all_alerts)} alertes déclenchées")
        for a in summary:
            print(f"  [{a['level']}] {a['rule']} — {a['hits']} hit(s)")

        return all_alerts