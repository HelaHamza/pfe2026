"""
models/enums.py
===============
Vocabulaire fermé du domaine. Utilisé à la fois par la couche Modèle
(validation) et par la couche Vue (paramètres de requête → 422 automatique
au lieu d'un 200 avec liste vide sur une faute de frappe).
"""
from enum import Enum


class DetectionSource(str, Enum):
    """Branche de détection ayant produit la ligne."""
    cnn = "cnn"
    sigma = "sigma"


class Verdict(str, Enum):
    """Verdict du triage LLM (branche CNN uniquement).

    - true_positive  → dashboard SOC
    - false_positive → bruit écarté (compte dans noise_reduction_pct)
    - uncertain      → dashboard Expert AI (JAMAIS silencieusement écarté)
    """
    true_positive = "true_positive"
    false_positive = "false_positive"
    uncertain = "uncertain"


class Severity(str, Enum):
    """Échelle de sévérité UNIFIÉE CNN/Sigma.

    Avant : CNN écrivait `severity` en minuscules, Sigma `level` en
    MAJUSCULES. Le mapping vivait implicitement dans le repository et
    n'apparaissait dans aucun contrat d'API. Désormais les deux branches
    écrivent le même champ `severity` avec ce vocabulaire.
    """
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class ReportStatus(str, Enum):
    """État d'un run.

    - completed → les deux branches ont abouti
    - partial   → une branche a échoué, l'autre a produit des résultats
                  (le rapport est publié quand même : les détections
                  réussies doivent rester atteignables)
    - failed    → aucune branche n'a abouti
    """
    completed = "completed"
    partial = "partial"
    failed = "failed"


# ── Normaliseurs tolérants (entrée pipeline → vocabulaire fermé) ───────────
_SEVERITY_ALIASES = {
    "critical": Severity.critical, "crit": Severity.critical,
    "high": Severity.high, "élevé": Severity.high, "eleve": Severity.high,
    "medium": Severity.medium, "moyen": Severity.medium, "med": Severity.medium,
    "low": Severity.low, "faible": Severity.low,
    "informational": Severity.low, "info": Severity.low,
}


def norm_severity(value, default: Severity = Severity.low) -> Severity:
    """Toute valeur inconnue retombe sur `default` — une sévérité exotique
    ne doit pas faire échouer la sérialisation d'une alerte réelle."""
    if isinstance(value, Severity):
        return value
    return _SEVERITY_ALIASES.get(str(value or "").strip().lower(), default)


def norm_verdict(value) -> Verdict | None:
    try:
        return Verdict(str(value or "").strip().lower())
    except ValueError:
        return None