"""
core/database.py
================
Connexion MongoDB PARTAGÉE par tout le backend.

⚠️ RÉCONCILIATION : tu possèdes déjà un `core/database.py`. NE L'ÉCRASE PAS
à l'aveugle. Compare-le à ce module : s'il expose déjà un client, garde le
tien et ajoute simplement les fonctions manquantes (`get_db`, `close_client`,
`ping`). L'objectif est qu'il n'existe qu'UN SEUL MongoClient dans le
processus — `report_repository` en créait un second, soit deux pools de
connexions vers le même cluster.

CONNEXION PARESSEUSE : le client n'est créé qu'au premier appel. Sans ça,
importer un repository suffirait à ouvrir une connexion — impossible à
tester hors ligne.
"""
import logging
import threading

import pymongo

from config import MONGO_DB, MONGO_URI

log = logging.getLogger(__name__)

_client: pymongo.MongoClient | None = None
_lock = threading.Lock()


def get_client() -> pymongo.MongoClient:
    global _client
    if _client is None:
        with _lock:
            if _client is None:
                # tz_aware=True est INDISPENSABLE : par défaut pymongo relit
                # les BSON dates en datetime NAÏFS. Le JSON sortirait sans
                # suffixe "+00:00" et le frontend interpréterait de l'UTC
                # comme de l'heure locale — décalage silencieux partout.
                _client = pymongo.MongoClient(
                    MONGO_URI, serverSelectionTimeoutMS=5000, tz_aware=True)
                log.info("Client MongoDB initialisé.")
    return _client


def get_db(name: str = MONGO_DB):
    return get_client()[name]


def ping() -> None:
    """Lève si le cluster est injoignable. Appelé au démarrage (lifespan)."""
    get_client().admin.command("ping")


def close_client() -> None:
    global _client
    if _client is not None:
        _client.close()
        _client = None
        log.info("Client MongoDB fermé.")


# ══════════════════════════════════════════════════════════════════════
#  Compatibilité : `from core.database import db`
# ══════════════════════════════════════════════════════════════════════
class _LazyDatabase:
    """Proxy vers la base réelle, résolu au premier accès.

    RAISON D'ÊTRE : tes repositories existants importent un objet `db` au
    niveau module (`from core.database import db`). Exposer directement
    `get_client()[MONGO_DB]` ici ouvrirait une connexion au simple import
    d'un repository — donc à l'import de FastAPI, donc pendant les tests,
    donc hors ligne impossible.

    Ce proxy conserve exactement la syntaxe d'appel (`db["users"]`,
    `db.users`, `db.command(...)`) tout en repoussant la connexion au
    premier usage effectif. Aucun repository existant n'a besoin d'être
    modifié.
    """

    def __getitem__(self, name):
        return get_db()[name]

    def __getattr__(self, name):
        return getattr(get_db(), name)

    def __repr__(self):
        return f"<LazyDatabase {MONGO_DB!r}>"


db = _LazyDatabase()