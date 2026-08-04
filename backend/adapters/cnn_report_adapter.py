"""
adapters/cnn_report_adapter.py
==============================
FRONTIÈRE disque avec le rapport d'entraînement du CNN
(ML/cnn_evaluation_report.json). Porte les seuils GPD-POT PAR SOURCE, les
fenêtres de scoring, les volumes et les diagnostics de distribution.

Retourne le JSON brut + la mtime ; ne réinterprète rien. Les dérivations
vivent au READ, dans FrozenModelResponse.assemble — cohérent avec eval_adapter.
"""
import json
import logging
import os
from datetime import datetime, timezone

import config as CFG

log = logging.getLogger(__name__)


class CnnReportAdapter:
    """Lecture du rapport d'entraînement/évaluation du CNN."""

    @staticmethod
    def load() -> tuple[dict, datetime] | None:
        """(contenu_brut, mtime_utc) ou None si le fichier est absent ou
        illisible. Absence = no-op silencieux : la carte reste has_data=False."""
        path = CFG.CNN_EVAL_REPORT_JSON
        if not os.path.exists(path):
            log.info("cnn_evaluation_report.json absent (%s) — calibration "
                     "modèle non alimentée", path)
            return None
        try:
            with open(path, encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            log.error("cnn_evaluation_report.json illisible (%s) — ignoré", e)
            return None
        mtime = datetime.fromtimestamp(os.path.getmtime(path), tz=timezone.utc)
        return raw, mtime