"""
scripts/purge_runs.py
=====================
Purge des runs anciens. Le garde-fou de `report_repository` AVERTIT quand le
stockage Atlas approche du quota (M0 = 512 Mo) mais ne purge rien : voici
l'outil correspondant.

    python -m scripts.purge_runs --keep 10            # simulation
    python -m scripts.purge_runs --keep 10 --apply    # exécution

SÉCURITÉ : simulation par défaut. Rien n'est supprimé sans `--apply` —
même logique que ta règle « mv, jamais rm » sur les snapshots de résultats.
"""
import argparse
import logging

import pymongo

from config import MONGO_COLL_CNN, MONGO_COLL_REPORTS, MONGO_COLL_SIGMA
from repositories.report_repository import ReportRepository

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="Purge des runs anciens.")
    parser.add_argument("--keep", type=int, default=10,
                        help="Nombre de runs les plus récents à conserver.")
    parser.add_argument("--apply", action="store_true",
                        help="Exécute réellement la suppression.")
    args = parser.parse_args()

    db = ReportRepository._db
    reports = db[MONGO_COLL_REPORTS]

    recent = list(reports.find({}, {"analysis_id": 1})
                  .sort("finished_at", pymongo.DESCENDING)
                  .limit(args.keep))
    keep_ids = [r["analysis_id"] for r in recent]

    if not keep_ids:
        log.info("Aucun rapport en base — rien à purger.")
        return

    old = {"run_id": {"$nin": keep_ids}}
    n_cnn = db[MONGO_COLL_CNN].count_documents(old)
    n_sig = db[MONGO_COLL_SIGMA].count_documents(old)
    n_rep = reports.count_documents({"analysis_id": {"$nin": keep_ids}})

    log.info("Conservation des %d run(s) les plus récents.", len(keep_ids))
    log.info("À supprimer : %d épisodes CNN, %d alertes Sigma, %d rapports.",
             n_cnn, n_sig, n_rep)

    if not args.apply:
        log.info("\nSIMULATION — relance avec --apply pour exécuter.")
        return

    db[MONGO_COLL_CNN].delete_many(old)
    db[MONGO_COLL_SIGMA].delete_many(old)
    reports.delete_many({"analysis_id": {"$nin": keep_ids}})
    log.info("Purge effectuée.")
    ReportRepository._check_storage_saturation()


if __name__ == "__main__":
    main()