"""
adapters/eval_adapter.py
========================
FRONTIÈRE disque avec l'évaluation offline (evaluation/evaluate_cnn_vs_llm.py).

Lit eval_summary.json et retourne son contenu BRUT + la mtime du fichier. Ne
persiste rien, ne réinterprète rien : le JSON brut est stocké tel quel par le
contrôleur (via save_eval_comparison), les deltas sont dérivés au READ par
EvalComparisonResponse.from_raw — cohérent avec le pattern triage.

MODEL-SCOPED : eval_summary.json mesure la VERSION du modèle, pas un run de
production. La mtime est retournée pour que l'appelant journalise la fraîcheur
et rende visible une éventuelle péremption après promotion de modèle.
"""
import json
import logging
import os
from datetime import datetime, timezone

import config as CFG

log = logging.getLogger(__name__)


class EvalAdapter:
    """Lecture de l'artefact d'évaluation CNN vs cascade."""

    @staticmethod
    def load_summary() -> tuple[dict, datetime] | None:
        """Retourne (contenu_brut, mtime_utc) ou None si le fichier est absent
        ou illisible. Absence = no-op silencieux : la carte E reste
        has_data=False, ce qui est le comportement correct."""
        path = CFG.EVAL_SUMMARY_JSON
        if not os.path.exists(path):
            log.info("eval_summary.json absent (%s) — domaine E non alimenté",
                     path)
            return None

        try:
            with open(path, encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            log.error("eval_summary.json illisible (%s) — ingestion E ignorée", e)
            return None

        mtime = datetime.fromtimestamp(os.path.getmtime(path), tz=timezone.utc)
        return raw, mtime