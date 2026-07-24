"""
scripts/init_indexes.py
=======================
Création de TOUS les index Mongo du projet, en une seule fois.

    python -m scripts.init_indexes        (depuis backend/)

Idempotent : relançable sans risque, Mongo ignore un index déjà présent à
l'identique.

POURQUOI LES INDEX DE DÉTECTION SONT INDISPENSABLES
---------------------------------------------------
`get_results` filtre sur {run_id, verdict, severity} puis trie sur
`event_time`. Sans index composé couvrant à la fois le filtre et le tri,
Mongo trie EN MÉMOIRE, avec un plafond de 32 Mo : au-delà la requête
n'est pas lente, elle ÉCHOUE. L'ordre des clés suit la règle ESR
(Equality, Sort, Range).
"""
import logging

import pymongo
from pymongo.errors import OperationFailure

from config import MONGO_COLL_CNN, MONGO_COLL_REPORTS, MONGO_COLL_SIGMA
from core.database import get_db

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)

ASC = pymongo.ASCENDING
DESC = pymongo.DESCENDING


def _create(collection, keys, **kwargs) -> None:
    """Crée un index en signalant clairement l'échec sans interrompre les
    suivants."""
    try:
        created = collection.create_index(keys, **kwargs)
        log.info("  ✓ %s.%s", collection.name, created)
    except OperationFailure as e:
        name = kwargs.get("name") or keys
        log.error("  ✗ %s.%s — %s", collection.name, name, e)
        if kwargs.get("unique"):
            log.error("     Index UNIQUE refusé : la collection contient "
                      "déjà des doublons sur ces clés. Purge-les avant de "
                      "relancer.")


# ══════════════════════════════════════════════════════════════════════
#  Authentification (repris de la version initiale)
# ══════════════════════════════════════════════════════════════════════
def init_auth_indexes(db) -> None:
    log.info("Authentification")
    resets = db["password_resets"]
    # Pas de `name=` : ces index existent déjà sous les noms par défaut
    # (token_hash_1, expires_at_1). Les renommer serait refusé par Mongo
    # et rendrait le script non rejouable.
    _create(resets, "token_hash")
    _create(resets, "expires_at", expireAfterSeconds=0)
    # ── À DÉCOMMENTER après vérification des noms de champs ───────────
    # Je n'ai pas vu user_repository.py ni otp_repository.py : ces index
    # sont plausibles mais non vérifiés. Un `unique=True` posé sur un champ
    # contenant déjà des doublons échoue — d'où la prudence.
    #
    # _create(db["users"], "email", unique=True, name="ux_user_email")
    # _create(db["otps"], "expires_at", expireAfterSeconds=0,
    #         name="ttl_otp_expires_at")


# ══════════════════════════════════════════════════════════════════════
#  Détection (CNN + Sigma + rapports)
# ══════════════════════════════════════════════════════════════════════
def init_detection_indexes(db) -> None:
    log.info("Détection")

    # Table SOC : filtre {run_id, verdict, severity} + tri event_time.
    _create(db[MONGO_COLL_CNN],
            [("run_id", ASC), ("verdict", ASC), ("severity", ASC),
             ("event_time", DESC)],
            name="ix_cnn_run_verdict_sev_time")
    # Déduplication INTER-runs : la clé primaire est préfixée par le run_id,
    # c'est donc ce champ qui permet de retrouver les re-détections.
    _create(db[MONGO_COLL_CNN],
            [("dedup_key", ASC), ("event_time", DESC)],
            name="ix_cnn_dedup")

    _create(db[MONGO_COLL_SIGMA],
            [("run_id", ASC), ("severity", ASC), ("event_time", DESC)],
            name="ix_sigma_run_sev_time")
    _create(db[MONGO_COLL_SIGMA],
            [("dedup_key", ASC), ("event_time", DESC)],
            name="ix_sigma_dedup")

    # Un seul rapport par run. ⚠️ Si d'anciens rapports ont été créés avec
    # `insert_one` (avant le passage à l'upsert), des doublons existent et
    # cet index sera REFUSÉ. Voir le message d'erreur affiché.
    _create(db[MONGO_COLL_REPORTS], [("analysis_id", ASC)], unique=True,
            name="ux_report_analysis_id")
    # get_last_report : filtre sur status, tri sur finished_at.
    _create(db[MONGO_COLL_REPORTS],
            [("status", ASC), ("finished_at", DESC)],
            name="ix_report_last")

    # `pipeline_state` : accès uniquement par _id, aucun index à ajouter.


def init_indexes() -> None:
    db = get_db()
    init_auth_indexes(db)
    init_detection_indexes(db)

    log.info("\nIndex présents par collection :")
    for name in ("password_resets", MONGO_COLL_CNN, MONGO_COLL_SIGMA,
                 MONGO_COLL_REPORTS):
        try:
            log.info("  %-16s %s", name, sorted(db[name].index_information()))
        except OperationFailure as e:
            log.warning("  %-16s illisible (%s)", name, e)
    log.info("\nTerminé.")


if __name__ == "__main__":
    init_indexes()