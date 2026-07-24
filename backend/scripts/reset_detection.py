"""
scripts/reset_detection.py
==========================
Prépare la base pour le premier run après migration : diagnostic puis purge
des collections de DÉTECTION uniquement.

    python -m scripts.reset_detection            # diagnostic seul
    python -m scripts.reset_detection --apply    # purge réelle

POURQUOI LA PURGE EST NÉCESSAIRE
--------------------------------
Les documents antérieurs à la migration n'ont pas de champ `event_time` et
portent l'ancien format d'`_id` (sans préfixe run_id). Ils ne seraient ni
triés ni filtrés correctement, et l'index unique sur `analysis_id` sera
refusé si `reports` contient des doublons hérités de l'ancien `insert_one`.

CE QUI EST TOUCHÉ            CE QUI NE L'EST PAS
  cnn_alerts                   users
  sigma_alerts                 feedbacks
  reports                      password_resets
  pipeline_state               otps
                               (toutes les collections d'authentification)

Vider `pipeline_state` fait repartir les curseurs CNN et Sigma de
PROD_START — c'est le comportement voulu pour repartir sur un jeu de
données cohérent.

SÉCURITÉ : diagnostic par défaut. Rien n'est supprimé sans `--apply`,
conformément à la règle « mv, jamais rm » du projet.
"""
import argparse
import logging

import config as CFG
from core.database import get_db

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)

DETECTION_COLLECTIONS = [
    CFG.MONGO_COLL_CNN,
    CFG.MONGO_COLL_SIGMA,
    CFG.MONGO_COLL_REPORTS,
    CFG.MONGO_COLL_STATE,
]


def diagnose(db) -> None:
    log.info("Base : %s\n", db.name)

    log.info("Collections de détection")
    for name in DETECTION_COLLECTIONS:
        try:
            n = db[name].count_documents({})
            log.info("  %-16s %6d document(s)", name, n)
        except Exception as e:
            log.warning("  %-16s illisible (%s)", name, e)

    # ── Doublons de rapports (bloquent l'index unique) ─────────────────
    log.info("\nDoublons sur analysis_id (bloquent ux_report_analysis_id)")
    try:
        dups = list(db[CFG.MONGO_COLL_REPORTS].aggregate([
            {"$group": {"_id": "$analysis_id", "n": {"$sum": 1}}},
            {"$match": {"n": {"$gt": 1}}},
        ]))
        if dups:
            for d in dups[:10]:
                log.info("  %s → %d exemplaires", d["_id"], d["n"])
            log.info("  %d run(s) en doublon au total.", len(dups))
        else:
            log.info("  aucun.")
    except Exception as e:
        log.warning("  vérification impossible (%s)", e)

    # ── Documents hérités, sans event_time ─────────────────────────────
    log.info("\nDocuments sans champ event_time (schéma antérieur)")
    for name in (CFG.MONGO_COLL_CNN, CFG.MONGO_COLL_SIGMA):
        try:
            n = db[name].count_documents({"event_time": {"$exists": False}})
            log.info("  %-16s %6d", name, n)
        except Exception as e:
            log.warning("  %-16s illisible (%s)", name, e)

    # ── Curseurs actuels ───────────────────────────────────────────────
    log.info("\nCurseurs incrémentaux")
    try:
        found = False
        for doc in db[CFG.MONGO_COLL_STATE].find():
            log.info("  %-16s %s", doc.get("_id"), doc.get("cursor"))
            found = True
        if not found:
            log.info("  aucun → le prochain run partira de PROD_START (%s)",
                     CFG.PROD_START)
    except Exception as e:
        log.warning("  illisible (%s)", e)


def purge(db) -> None:
    log.info("\nPurge en cours…")
    for name in DETECTION_COLLECTIONS:
        try:
            db[name].drop()
            log.info("  ✓ %s supprimée", name)
        except Exception as e:
            log.error("  ✗ %s — %s", name, e)
    log.info("\nCollections d'authentification laissées intactes.")
    log.info("Étape suivante : python -m scripts.init_indexes")


def main():
    parser = argparse.ArgumentParser(
        description="Diagnostic et purge des collections de détection.")
    parser.add_argument("--apply", action="store_true",
                        help="Exécute réellement la purge.")
    args = parser.parse_args()

    db = get_db()
    diagnose(db)

    if not args.apply:
        log.info("\n" + "=" * 60)
        log.info("DIAGNOSTIC SEUL — rien n'a été supprimé.")
        log.info("Pour purger : python -m scripts.reset_detection --apply")
        log.info("=" * 60)
        return

    purge(db)


if __name__ == "__main__":
    main()