"""
models/enums.py
===============
Vocabulaire fermé du domaine. Utilisé à la fois par la couche Modèle
(validation) et par la couche Vue (paramètres de requête → 422 automatique
au lieu d'un 200 avec liste vide sur une faute de frappe).

MODE EXPLICATION SEULE : le LLM ne classe plus. Le CNN décide ce qui est une
alerte, le LLM l'explique et la priorise. Le verdict est donc CONSTANT (fixé
à true_positive par la couche de triage). Les anciennes valeurs de verdict
false_positive / uncertain — produites quand le LLM filtrait — n'ont plus de
source et ont été retirées.
"""


from enum import Enum


class DetectionSource(str, Enum):
    """Branche de détection ayant produit la ligne."""
    cnn = "cnn"
    sigma = "sigma"


class Verdict(str, Enum):
    """Verdict de la branche CNN.

    En mode explication seule, il n'existe qu'UNE valeur : true_positive. Toute
    alerte levée par le CNN est conservée et expliquée par le LLM ; aucune n'est
    close ni écartée. Le champ `verdict` reste présent en base (le dashboard SOC
    filtre dessus, `cnn_by_verdict` l'affiche), mais il est invariant.

    Les valeurs false_positive et uncertain de l'ancienne cascade filtrante ont
    été supprimées : plus rien ne les produit. Après cette suppression, penser à
    `grep -rn "Verdict.false_positive\\|Verdict.uncertain" backend/` pour
    éliminer d'éventuelles références résiduelles hors des fichiers déjà revus.
    """
    true_positive = "true_positive"


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
    """Conservé pour compatibilité. En mode explication seule, seule la valeur
    true_positive est reconnue ; toute autre entrée renvoie None."""
    try:
        return Verdict(str(value or "").strip().lower())
    except ValueError:
        return None