"""
adapters/gate_adapter.py
========================
FRONTIÈRE disque avec la pipeline de ré-entraînement (ML/retraining/).

Lit le gate_*.json le plus récent et quarantine.json, et retourne un
RetrainRunDocument PRÊT à persister. Il ne persiste RIEN : comme cnn_adapter,
la dépendance ne va que vers l'intérieur.
        adapters → models  (jamais repositories)
Le contrôleur relie l'adapter au RetrainRepository.

Logique reprise TELLE QUELLE de l'ancien scripts/ingest_gate.py, désormais
seule source de vérité pour le parsing d'un gate. Le script CLI en devient un
simple wrapper.
"""
import glob
import json
import logging
import os

import config as CFG
from core.timeutils import now_utc, to_utc
from models.retrain_run_model import RetrainRunDocument

log = logging.getLogger(__name__)


class GateAdapter:
    """Lecture des artefacts du gate de ré-entraînement."""

    @staticmethod
    def _latest_gate_path() -> str | None:
        """gate_*.json le plus récent par mtime (robuste au nommage)."""
        files = glob.glob(os.path.join(CFG.GATE_REPORTS_DIR, "gate_*.json"))
        return max(files, key=os.path.getmtime) if files else None

    @staticmethod
    def _quarantine_count() -> int:
        """Incidents en quarantaine, hors entrée d'exemple du schéma.
        Absence de fichier = 0, jamais une erreur."""
        if not os.path.exists(CFG.QUARANTINE_JSON):
            return 0
        try:
            with open(CFG.QUARANTINE_JSON, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            log.warning("quarantine.json illisible (%s) — compté 0", e)
            return 0
        inc = data.get("incidents", []) or []
        return sum(1 for i in inc
                   if not str(i.get("id", "")).lower().startswith("exemple"))

    @staticmethod
    def _version_from_path(p) -> str | None:
        return os.path.basename(str(p).rstrip("/")) if p else None

    @classmethod
    def load_latest(cls) -> RetrainRunDocument | None:
        """Retourne le dernier gate en RetrainRunDocument, ou None si aucun
        gate n'existe sur disque. Ne persiste rien — le contrôleur décide."""
        path = cls._latest_gate_path()
        if not path:
            log.info("Aucun gate_*.json dans %s — domaine C non alimenté",
                     CFG.GATE_REPORTS_DIR)
            return None

        try:
            with open(path, encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            log.error("gate illisible %s (%s) — ingestion C ignorée", path, e)
            return None

        verdict = str(raw.get("verdict", "")).upper()
        return RetrainRunDocument(
            created_at=to_utc(raw.get("created_at")) or now_utc(),
            ingested_at=now_utc(),
            verdict=raw.get("verdict"),
            accepted=verdict.startswith("ACCEPT"),
            candidate_version=cls._version_from_path(raw.get("candidat")),
            current_version=cls._version_from_path(raw.get("courant")),
            echecs_bloquants=raw.get("echecs_bloquants", []) or [],
            avertissements=raw.get("avertissements", []) or [],
            note=raw.get("note"),
            tests=raw.get("tests", []) or [],
            quarantine_count=cls._quarantine_count(),
        )