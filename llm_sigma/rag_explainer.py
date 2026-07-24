"""
llm_sigma/rag_explainer.py
==========================
COUCHE D'EXPLICATION LLM DES ALERTES SIGMA (uniquement).

Réduit à ce que sigma_engine.explain_sigma_alerts importe RÉELLEMENT :
    make_grok_client, call_llm_with_retry
Tout le code hérité (fusion_router, autoencodeur MoE, index ES
ml-autoencoder-scores, knowledge_base, templates V9) a été RETIRÉ : il
appartenait à la branche autoencodeur, remplacée par CNN_LLM/. llm_sigma ne
dépend donc plus que de config_sigma → dossiers indépendants (point 8 du CDC).
"""
from __future__ import annotations
import re
import time

from openai import OpenAI

import config_sigma as CS


def make_grok_client() -> OpenAI:
    """Client Groq (API compatible OpenAI). Le modèle est accroché à l'objet
    (_sentinel_model) pour que explain_sigma_alerts sache quel modèle a produit
    l'explication sans redéclarer la constante de son côté."""
    if not CS.GROQ_API_KEY:
        raise ValueError(
            "GROQ_API_KEY absent du .env — récupère ta clé sur "
            "https://console.groq.com puis ajoute GROQ_API_KEY=... dans .env")
    client = OpenAI(api_key=CS.GROQ_API_KEY, base_url=CS.GROQ_BASE_URL)
    client._sentinel_model = CS.GROK_MODEL      # lu par explain_sigma_alerts
    return client


def parse_retry_seconds(error_message: str) -> float:
    """Délai d'attente d'un message d'erreur Groq 429.
    Format : 'Please try again in 8m23.712s' ou 'in 45.3s'. 60 s par défaut."""
    m = re.search(r'in\s+(?:(\d+)m\s*)?(\d+(?:\.\d+)?)s', error_message)
    if m:
        return float(m.group(1) or 0) * 60 + float(m.group(2))
    return 60.0


def call_llm_with_retry(grok_client, messages, max_tokens=None,
                        temperature=None, max_retries=None):
    """Appel Groq avec retry sur 429. Le modèle vient de config_sigma : plus de
    GROK_MODEL non défini (c'était un NameError GARANTI dès qu'on corrigeait le
    nom de la clé)."""
    model       = CS.GROK_MODEL
    max_tokens  = CS.LLM_MAX_TOKENS  if max_tokens  is None else max_tokens
    temperature = CS.LLM_TEMPERATURE if temperature is None else temperature
    max_retries = CS.LLM_MAX_RETRIES if max_retries is None else max_retries

    for attempt in range(max_retries + 1):
        try:
            return grok_client.chat.completions.create(
                model=model, messages=messages,
                max_tokens=max_tokens, temperature=temperature)
        except Exception as e:
            err = str(e)
            if ("429" in err or "rate_limit_exceeded" in err) and attempt < max_retries:
                wait = parse_retry_seconds(err) + 5.0
                print(f"  [SIGMA-LLM] 429 — attente {wait:.0f}s "
                      f"({attempt + 1}/{max_retries})...")
                time.sleep(wait)
                continue
            raise