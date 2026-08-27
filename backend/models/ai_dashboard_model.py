"""
models/ai_dashboard_model.py
============================
Contrat de sortie du dashboard Expert IA (distinct du contrat SOC).
Décrit la SANTÉ et l'EFFICACITÉ du système, jamais des menaces à traiter.

MODE EXPLICATION SEULE — ce que le LLM fait désormais :
  * il ne FILTRE plus ; toute alerte du CNN est conservée et expliquée ;
  * son signal utile est la PRIORISATION (répartition de sévérité) et sa
    FIABILITÉ (taux de fail-open = épisodes non explicables, conservés par
    sécurité).

  * A (LIVE)  — dernier run : priorisation du run + tendance inter-runs.
  * D (TRIAGE)— métadonnées run-level du triage LLM, sous-objet `triage`.
  * E (EVAL)  — capacité de détection du MODÈLE EN PRODUCTION (CNN seul).
                En explication seule, le LLM n'écarte plus rien : le détecteur,
                c'est le CNN. On n'expose donc QUE ses métriques (précision au
                niveau alerte, rappel au niveau attaque), issues du protocole
                d'évaluation par injection (eval_summary.json).

Forme stable partout (zéros plutôt que dict vide) et statut visible.
CONTRAT PUR : aucune route, aucun import de contrôleur. Les modèles sont
en bas du flux (vues → contrôleurs → repositories → modèles).
"""
import logging
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from core.timeutils import to_utc
from models.enums import ReportStatus

log = logging.getLogger(__name__)


# ── ③ Priorisation live (remplace l'ancien entonnoir de filtrage) ───────────
class PrioritizationSummary(BaseModel):
    """Priorisation du dernier run.

    Le LLM ne filtre plus : `total_episodes` = toutes les alertes levées par le
    CNN, toutes conservées. Le signal d'action n'est donc plus un taux de
    réduction de bruit mais :
      • by_severity      → ce que l'analyste traite en premier ;
      • n_critical_high  → volume prioritaire (critical + high) ;
      • n_fail_open      → épisodes que le LLM n'a pas pu expliquer (panne
                           d'API), conservés par sécurité. Indicateur de
                           FIABILITÉ de la couche.
    """
    total_episodes: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    n_critical_high: int = 0
    n_fail_open: int = 0
    fail_open_pct: float = 0.0        # 100 · n_fail_open / total_episodes


class RunTrendPoint(BaseModel):
    """Point de tendance inter-runs : volume et priorisation, pas filtrage."""
    run_id: str
    finished_at: datetime | None = None
    total_episodes: int = 0
    n_critical_high: int = 0
    fail_open_pct: float = 0.0


class AIOverviewResponse(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    has_data: bool
    status: ReportStatus | None = None
    errors: list[str] = Field(default_factory=list)

    run_id: str | None = None
    last_finished_at: datetime | None = None
    model_version: str | None = None

    prioritization: PrioritizationSummary = Field(
        default_factory=PrioritizationSummary)
    cnn_by_severity: dict[str, int] = Field(default_factory=dict)
    trend: list[RunTrendPoint] = Field(default_factory=list)


# ── ① Modèle en production (identité + calibration) ─────────────────────────
class SourceCalibration(BaseModel):
    """Calibration d'une source (auth | syslog | auditd), issue de
    l'entraînement. Le seuil GPD-POT est PAR SOURCE : ne jamais moyenner,
    l'asymétrie EST l'info (auth alerte à 1,7 %, syslog à 0,07 %).

    skew/kurtosis décrivent la FORME de la distribution des scores. Fortement
    leptokurtique (kurtosis ≫ 3) + asymétrie droite ⇒ queue lourde ⇒ GPD-POT
    justifié plutôt qu'un seuil gaussien. À afficher en REPLI avec cette
    lecture, jamais en KPI de tête."""
    threshold: float | None = None
    alert_rate_pct: float | None = None

    # Volumes : test = scoré (présent) ; train/eval si un artefact les porte.
    n_test: int | None = None
    n_train: int | None = None
    n_eval: int | None = None

    window_start: datetime | None = None
    window_end: datetime | None = None

    score_median: float | None = None
    score_p99: float | None = None
    score_skew: float | None = None
    score_kurtosis: float | None = None


class FrozenModelResponse(BaseModel):
    """Carte « Modèle en production » : QUEL modèle tourne et comment il est
    CALIBRÉ. Recall/precision N'Y SONT PAS — ils vivent en ④ (seule source à
    vérité terrain, eval_summary.json). Assemblée à la lecture depuis :
      • cnn_evaluation_report.json → seuils POT/source, fenêtres, volumes, forme ;
      • dernier gate ACCEPTé       → version déployée + date de promotion ;
      • dernier report             → moteur de triage (model/provider)."""
    model_config = ConfigDict(extra="allow")

    has_data: bool
    reason: str | None = None

    version: str | None = None
    promoted_at: datetime | None = None
    trained_at: datetime | None = None      # mtime du rapport d'entraînement

    total_events: int | None = None         # n_scored
    n_alert_episodes: int | None = None
    by_source: dict[str, SourceCalibration] = Field(default_factory=dict)

    llm_model: str | None = None
    llm_provider: str | None = None

    @classmethod
    def assemble(cls, *, cnn_report: tuple | None, accepted_gate: dict | None,
                 report: dict | None) -> "FrozenModelResponse":
        cnn_raw, trained_at = cnn_report if cnn_report else (None, None)

        if not cnn_raw and not accepted_gate and not report:
            return cls(has_data=False,
                       reason="Aucune source : ni rapport d'entraînement, ni "
                              "gate ACCEPTé, ni run publié.")

        gate   = accepted_gate or {}
        cnn    = cnn_raw or {}
        report = report or {}

        version     = gate.get("candidate_version") or report.get("model_version")
        promoted_at = to_utc(gate.get("created_at")) if gate else None

        thresholds = cnn.get("thresholds") or {}
        windows    = cnn.get("test_window_by_source") or {}
        diags      = cnn.get("diagnostics") or {}
        splits     = cnn.get("splits_by_source") or {}   # optionnel (train/eval)
        by_source: dict[str, SourceCalibration] = {}
        for src in set(thresholds) | set(windows) | set(diags):
            w, d = windows.get(src) or {}, diags.get(src) or {}
            sp = splits.get(src) or {}
            by_source[src] = SourceCalibration(
                threshold=thresholds.get(src),
                alert_rate_pct=d.get("alert_rate_pct"),
                n_test=w.get("n") or d.get("n") or sp.get("test"),
                n_train=sp.get("train"),
                n_eval=sp.get("eval"),
                window_start=to_utc(w.get("start")),
                window_end=to_utc(w.get("end")),
                score_median=d.get("score_median"),
                score_p99=d.get("score_p99"),
                score_skew=d.get("score_skew"),
                score_kurtosis=d.get("score_kurtosis"),
            )

        triage = report.get("triage") or {}
        reason = None if cnn_raw else ("cnn_evaluation_report.json absent — "
                                       "seuils GPD-POT et fenêtres non renseignés.")

        return cls(
            has_data=True, reason=reason,
            version=version, promoted_at=promoted_at, trained_at=trained_at,
            total_events=cnn.get("n_scored"),
            n_alert_episodes=cnn.get("n_alert_episodes"),
            by_source=by_source,
            llm_model=triage.get("model"), llm_provider=triage.get("provider"),
        )


# ── ⑤ Qualité triage ────────────────────────────────────────────────────────
class TriageQuality(BaseModel):
    """Miroir de cnn_triage_report.json. extra="allow" : un futur champ du
    triage est conservé sans toucher ce contrat.

    En mode explication seule, `noise_reduction_pct` vaut 0 et `verdicts` vaut
    {"true_positive": N} : ces champs restent affichés tels quels (miroir
    honnête du rapport), la valeur informative étant `n_fail_open`, `elapsed_s`,
    `severities` et le bloc `grounding`."""
    model_config = ConfigDict(extra="allow")
    model: str | None = None
    provider: str | None = None
    temperature: float | None = None
    rag_backend: str | None = None
    n_kb_chunks: int | None = None
    n_episodes_in: int | None = None
    n_alerts_in: int | None = None
    verdicts: dict[str, int] = Field(default_factory=dict)
    severities: dict[str, int] = Field(default_factory=dict)
    n_fail_open: int | None = None
    n_episodes_to_analyst: int | None = None
    noise_reduction_pct: float | None = None
    elapsed_s: float | None = None
    mode: str | None = None


class TriageResponse(BaseModel):
    has_data: bool
    run_id: str | None = None
    reason: str | None = None
    triage: TriageQuality | None = None


# ── ④ Capacité de détection du MODÈLE EN PRODUCTION (CNN seul) ───────────────
# Mode explication seule : le LLM n'écarte plus rien, le détecteur est le CNN.
# On n'expose QUE ses métriques. Source : eval_summary.json (protocole
# d'évaluation par injection). Précision au niveau ALERTE, rappel au niveau
# ATTAQUE (robuste à la troncature) — deux granularités présentées séparément,
# jamais fondues dans un F1 qui les mélangerait.
class ModelDetectionMetrics(BaseModel):
    precision: float = 0.0        # niveau alerte : tp / (tp + fp)
    recall: float = 0.0           # niveau attaque : attaques détectées / injectées
    n_alerts: int = 0
    tp: int = 0
    fp: int = 0
    n_attacks: int = 0
    attacks_detected: int = 0
    attacks_missed: int = 0
    mode: str = "?"


class EvalComparisonResponse(BaseModel):
    has_data: bool
    reason: str | None = None
    metrics: ModelDetectionMetrics | None = None

    @classmethod
    def from_raw(cls, raw: dict) -> "EvalComparisonResponse":
        al = (raw or {}).get("alert_level") or {}
        at = (raw or {}).get("attack_level") or {}
        cnn = al.get("cnn")
        if not cnn or not at:
            missing = [n for n, v in (("alert_level.cnn", cnn),
                                      ("attack_level", at)) if not v]
            log.warning("eval_summary mal formé : clés absentes %s — "
                        "vérifier eval_summary.json", missing)
            return cls(has_data=False,
                       reason=f"eval_summary.json mal formé : clés absentes {missing}.")

        precision = float(cnn.get("precision") or 0.0)
        recall = float(at.get("cnn_recall") or 0.0)
        n_attacks = int(raw.get("n_attacks") or 0)
        detected = int(at.get("attacks_detected_cnn") or 0)

        return cls(has_data=True, metrics=ModelDetectionMetrics(
            precision=round(precision, 3),
            recall=round(recall, 3),
            n_alerts=int(cnn.get("n_alerts") or 0),
            tp=int(cnn.get("tp") or 0),
            fp=int(cnn.get("fp") or 0),
            n_attacks=n_attacks,
            attacks_detected=detected,
            attacks_missed=max(n_attacks - detected, 0),
            mode=str(raw.get("mode") or "?"),
        ))