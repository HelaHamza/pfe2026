"""
adapters/cnn_eval_adapter.py
============================
Frontière DISQUE pour eval_summary.json — le rapport du protocole d'évaluation
par injection (inject.py).

En mode explication seule, la capacité de détection est une propriété du
MODÈLE, pas d'un run : le LLM n'écarte plus rien, le détecteur est le CNN. On
lit donc ce fichier DIRECTEMENT sur disque (comme cnn_report_adapter lit
cnn_evaluation_report.json), sans passer par une ingestion Mongo par run_id.
La carte ④ se remplit dès que le fichier existe.

Dépendance : adapters → (rien), sauf config. Aucun repository, aucun réseau.
"""

import json
import logging
import os

import config as CFG

log = logging.getLogger(__name__)


def _resolve_path() -> str:
    """Chemin de eval_summary.json.

      1. CFG.CNN_EVAL_SUMMARY si tu l'as défini (prioritaire) ;
      2. sinon, à côté de cnn_triage_report.json (même dossier de sortie CNN),
         là où inject.py l'écrit le plus souvent.
    Si ton inject.py l'écrit ailleurs, définis CNN_EVAL_SUMMARY dans config.py.
    """
    explicit = getattr(CFG, "CNN_EVAL_SUMMARY", None)
    if explicit:
        return explicit
    triage_report = getattr(CFG, "CNN_TRIAGE_REPORT", None)
    if triage_report:
        return os.path.join(os.path.dirname(triage_report), "eval_summary.json")
    return "eval_summary.json"


class CnnEvalAdapter:
    """Lecture seule de eval_summary.json. Absence NON bloquante : la carte ④
    affiche « fichier introuvable » au lieu de planter."""

    @staticmethod
    def load() -> dict | None:
        path = _resolve_path()
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            log.info("eval_summary.json chargé depuis %s", path)
            return data
        except FileNotFoundError:
            log.warning("eval_summary.json introuvable (%s) — carte ④ vide. "
                        "Lance le protocole d'évaluation ou définis "
                        "CNN_EVAL_SUMMARY dans config.py.", path)
            return None
        except (OSError, json.JSONDecodeError) as e:
            log.warning("eval_summary.json illisible (%s) : %s", path, e)
            return None