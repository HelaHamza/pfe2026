"""
adapters/cnn_adapter.py
=======================
FRONTIÈRE avec la branche CNN du pipeline (ML/ + CNN_LLM/).

C'est le SEUL module du backend qui sait qu'un pipeline externe existe :
chemins, subprocess, artefacts JSON/JSONL. Le contrôleur, lui, ne voit
qu'une méthode qui retourne des épisodes et un curseur.

Il ne persiste RIEN. La dépendance ne va que vers l'intérieur :
        adapters → (rien)
        controllers → adapters + repositories
Avant, `CNN_LLM/persist_cnn.py` importait `ReportRepository` avec un
sys.path en dur vers le backend : le pipeline dépendait du backend qui
dépendait du pipeline. Cycle supprimé.
"""
import json
import logging
import os
import subprocess
import sys

import config as CFG
from core.exceptions import PipelineStepError

log = logging.getLogger(__name__)


def _run_step(cmd: list[str], cwd: str, label: str) -> None:
    """Étape externe. Capture stderr et le remonte : sans ça, l'erreur
    affichée à l'analyste se réduit à « returned non-zero exit status 1 »."""
    log.info("→ %s", label)
    try:
        subprocess.run(cmd, cwd=cwd, check=True, text=True,
                       capture_output=True,
                       timeout=CFG.PIPELINE_STEP_TIMEOUT_S)
    except FileNotFoundError as e:
        raise PipelineStepError(f"{label} : exécutable ou dossier introuvable ({e}).")
    except subprocess.TimeoutExpired:
        raise PipelineStepError(
            f"{label} : dépassement du délai ({CFG.PIPELINE_STEP_TIMEOUT_S}s).")
    except subprocess.CalledProcessError as e:
        tail = "\n".join((e.stderr or e.stdout or "").strip().splitlines()[-15:])
        raise PipelineStepError(f"{label} : code {e.returncode}\n{tail}")


class CNNAdapter:
    """Inférence CNN de production + triage LLM/RAG."""

    @staticmethod
    def _read_next_cursor() -> str:
        """Watermark produit par predict_cnn.

        Le curseur N'EST PAS `until` : predict_cnn RETIENT la queue non
        stabilisée (épisodes dont end > until − EPISODE_GAP). Avancer à
        `until` les rendrait invisibles au run suivant."""
        try:
            with open(CFG.CNN_RUN_META, encoding="utf-8") as f:
                return json.load(f)["next_cursor"]
        except (OSError, KeyError, json.JSONDecodeError) as e:
            raise PipelineStepError(
                f"cnn_run_meta.json illisible ou incomplet ({e}). "
                f"Curseur NON avancé — relance sûre.")

    @staticmethod
    def _load_triaged() -> list[dict]:
        """Lecture de cnn_triage.jsonl. Une ligne corrompue est signalée et
        ignorée : elle ne doit pas faire perdre les épisodes valides du run."""
        episodes, bad = [], 0
        try:
            with open(CFG.CNN_TRIAGE_JSONL, encoding="utf-8") as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ep = json.loads(line)
                        ep["detection_source"] = "cnn"
                        episodes.append(ep)
                    except json.JSONDecodeError:
                        bad += 1
                        log.error("cnn_triage.jsonl ligne %d illisible", i)
        except OSError as e:
            raise PipelineStepError(f"cnn_triage.jsonl introuvable ({e}).")
        if bad:
            log.warning("%d ligne(s) de triage ignorée(s)", bad)
        return episodes

    @classmethod
    def collect(cls, since: str, until: str) -> tuple[list[dict], str]:
        """Exécute la branche CNN sur ]since, until].

        Retourne (épisodes triagés, curseur candidat). Lève PipelineStepError
        en cas d'échec — le contrôleur décide alors de ne pas avancer le
        curseur."""
        log.info("Inférence CNN (production) — fenêtre ]%s , %s]", since, until)
        _run_step([sys.executable, "predict_cnn.py",
                   "--until", until, "--since", since],
                  CFG.INFERENCE_DIR, "predict_cnn.py")

        next_cursor = cls._read_next_cursor()

        _run_step([sys.executable, "triage_cnn.py"],
                  CFG.CNN_LLM_DIR, "triage_cnn.py (LLM + RAG)")

        episodes = cls._load_triaged()
        log.info("%d épisodes triagés (curseur candidat : %s)",
                 len(episodes), next_cursor)
        return episodes, next_cursor