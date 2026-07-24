"""
models/detection_models.py
==========================
COUCHE MODÈLE de la détection : le document Mongo brut devient un objet
métier typé.

RÔLE — trois problèmes réglés d'un coup :
  1. Fuite de champs internes : `run_id`, `indexed_at`, `dedup_key`,
     `llm_model`… ne partent plus au client. La liste blanche, c'est ce
     modèle.
  2. Couplage front ↔ base : renommer un champ dans le pipeline ne casse
     plus React, seuls les mappers ci-dessous changent.
  3. Contrat d'API : `response_model` rend la documentation OpenAPI réelle
     et valide la sortie.

RÉPARTITION SOC / EXPERT AI
---------------------------
Le dashboard SOC a besoin du strict nécessaire à la décision : quoi, quand,
à quel point c'est grave, pourquoi. Tout le reste — scores de
reconstruction, seuil, références RAG, garde-fous, recommandations — relève
de la revue experte et n'est peuplé que lorsque `full=True`.

Une seule ligne (`ResultRow`) pour les deux branches : le frontend n'a pas à
connaître deux schémas.
"""
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from models.enums import (DetectionSource, Severity, Verdict,
                          norm_severity, norm_verdict)


def _as_float(value) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _as_int(value) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _as_text(value) -> str | None:
    """Aplatit les champs qui peuvent arriver en liste ou en chaîne.
    `mitre`, `evidence` et `recommendation` sont des listes côté pipeline."""
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        parts = [str(v).strip() for v in value if str(v).strip()]
        return ", ".join(parts) if parts else None
    text = str(value).strip()
    return text or None


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if str(v).strip()]
    return [str(value)] if str(value).strip() else []


class ExpertDetail(BaseModel):
    """Contexte de revue experte. Absent des réponses du dashboard SOC.

    Ces champs répondent à « pourquoi le modèle a-t-il réagi » et
    « qu'est-ce que le LLM a mobilisé pour trancher », pas à « que dois-je
    faire maintenant » — d'où leur exclusion de la vue SOC."""
    confidence: float | None = Field(
        default=None, description="Confiance du triage LLM (0–1).")
    score_max: float | None = Field(
        default=None, description="Erreur de reconstruction maximale (mse_max).")
    score_mean: float | None = None
    threshold: float | None = Field(
        default=None, description="Seuil GPD-POT en vigueur pour cette source.")
    n_alerts: int | None = Field(
        default=None, description="Nombre de fenêtres alertantes dans l'épisode.")
    duration_s: float | None = None
    evidence: list[str] = Field(default_factory=list)
    recommendation: list[str] = Field(default_factory=list)
    kb_refs: list[str] = Field(
        default_factory=list, description="Chunks RAG mobilisés par le triage.")
    guardrails: list[str] = Field(
        default_factory=list,
        description="Garde-fous politiques déclenchés (policy-over-LLM).")
    policy_flags: list[str] = Field(default_factory=list)
    missing_context: str | None = None
    actionable: bool | None = None
    llm_model: str | None = None
    details: list[str] = Field(
        default_factory=list, description="Échantillons bruts (Sigma).")


class ResultRow(BaseModel):
    """Ligne unifiée du tableau SOC."""
    model_config = ConfigDict(use_enum_values=True)

    id: str
    type: DetectionSource
    event_time: datetime = Field(
        description="Heure de l'ÉVÉNEMENT (jamais de l'indexation). "
                    "Clé de tri du tableau.")
    severity: Severity
    title: str
    explanation: str | None = Field(
        default=None,
        description="Analyse en langage naturel produite par le LLM.")

    tactic: str | None = None
    log_source: str | None = None
    host: str | None = None
    hits: int | None = Field(
        default=None,
        description="Volume : fenêtres alertantes (CNN) ou événements "
                    "correspondants (Sigma).")

    # Spécifique CNN
    verdict: Verdict | None = None
    started_at: datetime | None = None
    ended_at: datetime | None = None

    # Spécifique Sigma
    rule_kind: str | None = None

    event_time_estimated: bool = Field(
        default=False,
        description="True si l'heure de l'événement n'a pu être extraite du "
                    "log source et a été remplacée par celle du run.")

    expert: ExpertDetail | None = Field(
        default=None,
        description="Peuplé uniquement par le dashboard Expert AI.")

    # ── Mappers ────────────────────────────────────────────────────────
    @classmethod
    def from_cnn(cls, d: dict, full: bool = False) -> "ResultRow":
        expert = None
        if full:
            expert = ExpertDetail(
                confidence=_as_float(d.get("confidence")),
                score_max=_as_float(d.get("mse_max")),
                score_mean=_as_float(d.get("mse_mean")),
                threshold=_as_float(d.get("threshold")),
                n_alerts=_as_int(d.get("n_alerts")),
                duration_s=_as_float(d.get("duration_s")),
                evidence=_as_list(d.get("evidence")),
                recommendation=_as_list(d.get("recommendation")),
                kb_refs=_as_list(d.get("kb_refs")),
                guardrails=_as_list(d.get("guardrails")),
                policy_flags=_as_list(d.get("policy_flags")),
                missing_context=_as_text(d.get("missing_context")),
                actionable=d.get("actionable"),
            )
        return cls(
            id=str(d.get("episode_id") or d.get("_id")),
            type=DetectionSource.cnn,
            event_time=d.get("event_time") or d.get("start"),
            severity=norm_severity(d.get("severity")),
            title=(d.get("title")
                   or f"Épisode CNN — {d.get('log_source') or 'source inconnue'}"),
            # `rationale` : nom du champ produit par triage_cnn.py.
            explanation=_as_text(d.get("rationale")
                                 or d.get("llm_explanation")
                                 or d.get("explanation")),
            # `mitre` arrive en LISTE (souvent vide) : aplatie ici.
            tactic=_as_text(d.get("mitre") or d.get("tactic")),
            log_source=d.get("log_source"),
            host=d.get("host_name") or d.get("host"),
            # n_alerts joue pour le CNN le rôle que `hits` joue pour Sigma :
            # une seule colonne « volume » côté frontend.
            hits=_as_int(d.get("n_alerts")),
            verdict=norm_verdict(d.get("verdict")),
            started_at=d.get("start"),
            ended_at=d.get("end"),
            event_time_estimated=bool(d.get("event_time_estimated", False)),
            expert=expert,
        )

    @classmethod
    def from_sigma(cls, d: dict, full: bool = False) -> "ResultRow":
        expert = None
        if full:
            expert = ExpertDetail(
                details=_as_list(d.get("details")),
                llm_model=d.get("llm_model"),
            )
        return cls(
            id=str(d.get("dedup_key") or d.get("_id")),
            type=DetectionSource.sigma,
            event_time=d.get("event_time"),
            severity=norm_severity(d.get("severity") or d.get("level")),
            title=d.get("title") or "Alerte Sigma",
            explanation=_as_text(d.get("llm_explanation")),
            tactic=_as_text(d.get("tactic")),
            log_source=d.get("log_source"),
            host=d.get("host"),
            hits=_as_int(d.get("hits")),
            rule_kind=d.get("rule_kind"),
            event_time_estimated=bool(d.get("event_time_estimated", False)),
            expert=expert,
        )


class ResultsResponse(BaseModel):
    """Contrat de sortie de GET /results et GET /ai-dashboard/pending.

    `total` = lignes correspondant au filtre EN BASE, avant pagination.
    L'ancienne version renvoyait len(rows) après troncature : le front ne
    pouvait pas paginer et l'API mentait sur son propre contrat."""
    model_config = ConfigDict(use_enum_values=True)

    run_id: str | None = Field(
        default=None, description="Run affiché (dernier run publié).")
    total: int = Field(description="Total en base pour ce filtre.")
    count: int = Field(description="Nombre de lignes dans cette page.")
    skip: int = 0
    limit: int = 500
    results: list[ResultRow] = Field(default_factory=list)