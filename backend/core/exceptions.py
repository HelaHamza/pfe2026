"""
core/exceptions.py
==================
Exceptions métier. Objectif : rendre IMPOSSIBLE la perte silencieuse de
détections. Une écriture partielle DOIT être signalée à l'orchestrateur,
sinon celui-ci avance un curseur sur des données jamais persistées.
"""


class SentinelError(Exception):
    """Base de toutes les erreurs applicatives du backend."""


class PersistenceError(SentinelError):
    """Écriture base incomplète ou échouée.

    CONTRAT : l'appelant qui reçoit cette exception NE DOIT PAS avancer
    de curseur incrémental. La fenêtre sera re-scannée au run suivant
    (l'upsert idempotent garantit l'absence de doublons)."""


class PipelineStepError(SentinelError):
    """Étape externe du pipeline (predict_cnn, triage_cnn…) en échec :
    code retour ≠ 0, timeout, ou artefact de sortie illisible."""