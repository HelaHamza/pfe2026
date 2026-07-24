"""
llm_sigma/config_sigma.py
=========================
Configuration AUTONOME de la couche d'explication LLM des alertes Sigma.

Frontière stricte (cahier des charges, point 8 — indépendance des dossiers) :
  * CNN_LLM/config_llm_cnn.py  = triage LLM des épisodes CNN     → NE CHANGE PAS
  * llm_sigma/config_sigma.py  = explication LLM des alertes Sigma → CE FICHIER
Aucun des deux n'importe l'autre : chacun lit SA clé / SON modèle.

La CLÉ reste un SECRET : lue depuis .env (GROQ_API_KEY), jamais écrite en dur.
Le NOM du modèle n'est pas un secret : constante surchargeable par env.
"""
from __future__ import annotations
import os
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _find_dotenv() -> str | None:
    """Cherche le .env en remontant DEPUIS LE MODULE, pas depuis le cwd — même
    doctrine que config_llm_cnn : le pipeline marche lancé depuis backend/,
    depuis le home ou via un subprocess FastAPI."""
    d = BASE_DIR
    for _ in range(4):               # llm_sigma -> projet -> home -> /
        p = os.path.join(d, ".env")
        if os.path.exists(p):
            return p
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return None


_dotenv = _find_dotenv()
if _dotenv:
    load_dotenv(_dotenv)
else:
    load_dotenv()                    # repli : comportement par défaut

# --- Clé Groq (SECRET → .env) ----------------------------------------------
# ATTENTION : la variable s'appelle GROQ_API_KEY (avec un Q), identique à celle
# lue par la branche CNN. L'ancien rag_explainer lisait GROK_API_KEY (SANS Q) :
# la clé valait donc toujours None → make_grok_client levait ValueError → TOUTES
# les alertes Sigma remontaient SANS explication. C'est LE bug corrigé ici.
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# --- Modèle Groq -----------------------------------------------------------
# Groq a déprécié llama-3.3-70b-versatile / llama-3.1-8b-instant le 17/06/2026.
# Défaut aligné sur la migration recommandée : openai/gpt-oss-20b (rapide/éco,
# suffisant pour une explication < 350 mots). Surchargeable sans toucher au code :
#   export SIGMA_LLM_MODEL=openai/gpt-oss-120b   # raisonnement plus poussé
GROK_MODEL   = os.getenv("SIGMA_LLM_MODEL", "openai/gpt-oss-20b")

# --- Endpoint + paramètres d'appel -----------------------------------------
GROQ_BASE_URL   = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
LLM_MAX_TOKENS  = int(os.getenv("SIGMA_LLM_MAX_TOKENS", "500"))
LLM_TEMPERATURE = float(os.getenv("SIGMA_LLM_TEMPERATURE", "0.1"))
LLM_MAX_RETRIES = int(os.getenv("SIGMA_LLM_MAX_RETRIES", "1"))