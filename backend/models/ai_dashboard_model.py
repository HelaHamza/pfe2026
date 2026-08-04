"""
models/ai_dashboard_model.py
============================
Contrat de sortie du dashboard Expert IA (distinct du contrat SOC).
Décrit la SANTÉ et l'EFFICACITÉ du système, jamais des menaces à traiter.

  * A (LIVE)  — dernier run, collections reports + cnn. Entonnoir, réduction
                de bruit, fail-open, tendance inter-runs.
  * D (TRIAGE)— métadonnées run-level du triage LLM, sous-objet `triage`.
  * E (EVAL)  — comparaison CNN seul vs cascade CNN→LLM, sous-objet
                `eval_comparison`.

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


# ── ③ Efficacité live ───────────────────────────────────────────────────────
class TriageFunnel(BaseModel):
    """Entonnoir CNN → LLM.
      • total_episodes      = alertes LEVÉES par le CNN (dénominateur) ;
      • remaining_after_llm = ce qui SURVIT au filtrage (tp + uncertain) ;
      • false_positive      = écarté comme bruit."""
    total_episodes: int = 0
    true_positive: int = 0
    false_positive: int = 0
    uncertain: int = 0
    remaining_after_llm: int = 0
    noise_reduction_pct: float = 0.0   # 100 · fp / total
    fail_open_pct: float = 0.0         # 100 · uncertain / total


class RunTrendPoint(BaseModel):
    run_id: str
    finished_at: datetime | None = None
    total_episodes: int = 0
    remaining_after_llm: int = 0
    noise_reduction_pct: float = 0.0
    fail_open_pct: float = 0.0


class AIOverviewResponse(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    has_data: bool
    status: ReportStatus | None = None
    errors: list[str] = Field(default_factory=list)

    run_id: str | None = None
    last_finished_at: datetime | None = None
    model_version: str | None = None

    funnel: TriageFunnel = Field(default_factory=TriageFunnel)
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
    triage est conservé sans toucher ce contrat."""
    model_config = ConfigDict(extra="allow")
    model: str | None = None
    provider: str | None = None
    temperature: float | None = None
    rag_backend: str | None = None
    n_kb_chunks: int | None = None
    n_episodes_reaggregated: int | None = None
    n_episodes_in: int | None = None
    n_alerts_in: int | None = None
    verdicts: dict[str, int] = Field(default_factory=dict)
    n_fail_open: int | None = None
    n_episodes_to_analyst: int | None = None
    noise_reduction_pct: float | None = None
    elapsed_s: float | None = None


class TriageResponse(BaseModel):
    has_data: bool
    run_id: str | None = None
    reason: str | None = None
    triage: TriageQuality | None = None


# ── ④ Capacité de détection : CNN seul vs CNN→LLM ───────────────────────────
class EvalAlertMetrics(BaseModel):
    """Niveau ALERTE. Défauts : un sous-doc partiel ne fait jamais échouer le
    read."""
    precision: float = 0.0
    n_alerts: int = 0
    tp: int = 0
    fp: int = 0
    fp_removed: int | None = None


class EvalAttackMetrics(BaseModel):
    """Niveau ATTAQUE (rappel sur les anomalies injectées)."""
    cnn_recall: float = 0.0
    cascade_recall: float = 0.0
    attacks_detected_cnn: int = 0
    attacks_detected_cascade: int = 0


class EvalComparison(BaseModel):
    mode: str = "?"
    n_episodes: int = 0
    n_attacks: int = 0
    threshold: float | None = None
    triage_coverage: float = 0.0
    cnn: EvalAlertMetrics
    cascade: EvalAlertMetrics
    attack: EvalAttackMetrics

    precision_delta: float   # cascade − cnn (>0 = le LLM gagne en précision)
    recall_delta: float      # cascade − cnn (<0 = le LLM perd du rappel)
    alerts_removed: int
    tp_removed: int          # coût
    fp_removed: int          # bénéfice
    attacks_lost: int        # downgrade en false_positive = vrai FN


class EvalComparisonResponse(BaseModel):
    has_data: bool
    run_id: str | None = None
    reason: str | None = None
    comparison: EvalComparison | None = None

    @classmethod
    def from_raw(cls, run_id: str, raw: dict) -> "EvalComparisonResponse":
        al = (raw or {}).get("alert_level") or {}
        at = (raw or {}).get("attack_level") or {}
        if not al.get("cnn") or not al.get("cascade") or not at:
            missing = [name for name, val in (
                ("alert_level.cnn", al.get("cnn")),
                ("alert_level.cascade", al.get("cascade")),
                ("attack_level", at)) if not val]
            log.warning("eval_comparison run %s ignorée : clés absentes/vides "
                        "%s — vérifier eval_summary.json", run_id, missing)
            return cls(has_data=False, run_id=run_id,
                       reason=f"eval_summary.json ingéré mais mal formé : "
                              f"clés absentes {missing}.")

        cnn = EvalAlertMetrics(**al["cnn"])
        cascade = EvalAlertMetrics(**al["cascade"])
        attack = EvalAttackMetrics(**at)

        comp = EvalComparison(
            mode=raw.get("mode", "?"),
            n_episodes=raw.get("n_episodes", 0),
            n_attacks=raw.get("n_attacks", 0),
            threshold=raw.get("threshold"),
            triage_coverage=raw.get("triage_coverage", 0.0),
            cnn=cnn, cascade=cascade, attack=attack,
            precision_delta=round(cascade.precision - cnn.precision, 3),
            recall_delta=round(attack.cascade_recall - attack.cnn_recall, 3),
            alerts_removed=cnn.n_alerts - cascade.n_alerts,
            tp_removed=cnn.tp - cascade.tp,
            fp_removed=cnn.fp - cascade.fp,
            attacks_lost=(attack.attacks_detected_cnn
                          - attack.attacks_detected_cascade),
        )
        return cls(has_data=True, run_id=run_id, comparison=comp)