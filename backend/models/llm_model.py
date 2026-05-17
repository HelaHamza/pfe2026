"""
backend/models/llm_model.py
=============================
MODEL — LLM (Groq) + RAG (knowledge_base).
Wrapper autour de ML/rag_explainer.py et ML/knowledge_base.py.
Expose explain() pour générer une explication en français.
"""

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ROOT    = os.path.dirname(_BACKEND)
_ML      = os.path.join(_ROOT, "ML")

for _p in [_ML, _ROOT]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from rag_explainer  import explain_anomaly, make_grok_client, generate_auto_explanation
from knowledge_base import retrieve_knowledge_context, get_max_severity, get_matched_entries


class LLMModel:
    """
    Singleton Groq client — instancié une seule fois.
    """

    _grok = None

    @classmethod
    def _get_client(cls):
        if cls._grok is None:
            try:
                cls._grok = make_grok_client()
                print("[LLMModel] ✓ Client Groq initialisé")
            except ValueError as e:
                print(f"[LLMModel] LLM désactivé : {e}")
                cls._grok = False   # False = désactivé, None = pas encore tenté
        return cls._grok if cls._grok else None

    @classmethod
    def explain(cls, anomaly_doc: dict, detection_source: str = "ae_only") -> dict:
        """
        Génère une explication LLM pour une anomalie.

        Args:
            anomaly_doc      : document ES (avec champs ML)
            detection_source : 'ae_only' | 'sigma_only' | 'both'

        Returns:
            dict avec llm_explanation, kb_severity, mitre_flags
        """
        grok = cls._get_client()

        if grok is None:
            # Pas de clé Groq → explication automatique depuis knowledge_base
            return generate_auto_explanation(anomaly_doc)

        return explain_anomaly(
            anomaly_doc,
            es=None,
            grok_client=grok,
            detection_source=detection_source,
        )

    @classmethod
    def get_kb_context(cls, anomaly_doc: dict) -> str:
        """Retourne le contexte RAG de la knowledge base sans appeler le LLM."""
        return retrieve_knowledge_context(anomaly_doc)

    @classmethod
    def get_severity(cls, anomaly_doc: dict) -> str:
        """Retourne la sévérité maximale depuis la knowledge base."""
        return get_max_severity(anomaly_doc)