"""
scripts/inspect_schema.py
=========================
Affiche les clés RÉELLEMENT présentes dans les documents persistés, et
signale celles que les mappers `ResultRow.from_cnn` / `from_sigma`
cherchent sans les trouver.

    python -m scripts.inspect_schema        (depuis backend/)

RAISON D'ÊTRE : les épisodes CNN proviennent de `cnn_triage.jsonl`, produit
par un pipeline externe. Le backend ne peut pas deviner les noms de champs
— ce script les lit.
"""
import json
import logging

import config as CFG
from core.database import get_db

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)

# Clés recherchées par les mappers, par champ de sortie.
CNN_EXPECTED = {
    "explanation": ["llm_explanation", "explanation"],
    "score":       ["score", "max_score", "episode_score"],
    "tactic":      ["tactic", "mitre_tactic"],
    "title":       ["title", "summary"],
    "host":        ["host"],
}
SIGMA_EXPECTED = {
    "log_source": ["log_source"],
    "host":       ["host"],
}

# Champs posés par le backend lui-même : inutile de les signaler.
BACKEND_FIELDS = {
    "_id", "run_id", "indexed_at", "event_time", "event_time_estimated",
    "dedup_key", "detection_source", "severity",
}


def _all_keys(collection, limit=200) -> set:
    keys = set()
    for doc in collection.find({}, limit=limit):
        keys |= set(doc.keys())
    return keys


def _preview(value, width=70) -> str:
    s = json.dumps(value, ensure_ascii=False, default=str)
    return s[:width] + ("…" if len(s) > width else "")


def inspect(collection, label, expected: dict) -> None:
    log.info("\n%s", "=" * 70)
    log.info("  %s  (%s)", label, collection.name)
    log.info("%s", "=" * 70)

    doc = collection.find_one()
    if not doc:
        log.info("  collection vide.")
        return

    keys = _all_keys(collection)

    log.info("\n  Clés présentes (%d) :", len(keys))
    for k in sorted(keys):
        marker = "   " if k in BACKEND_FIELDS else " · "
        log.info("  %s%-28s %s", marker, k, _preview(doc.get(k)))

    log.info("\n  Correspondance avec les mappers :")
    for field, candidates in expected.items():
        found = [c for c in candidates if c in keys]
        if found:
            log.info("    ✓ %-12s ← %s", field, found[0])
        else:
            orphans = sorted(k for k in keys
                             if k not in BACKEND_FIELDS
                             and k not in sum(expected.values(), []))
            log.info("    ✗ %-12s cherché : %s — ABSENT",
                     field, ", ".join(candidates))

    unmapped = sorted(k for k in keys
                      if k not in BACKEND_FIELDS
                      and k not in sum(expected.values(), []))
    if unmapped:
        log.info("\n  Clés non mappées (candidates pour les champs absents) :")
        for k in unmapped:
            log.info("    %-28s %s", k, _preview(doc.get(k)))


def main():
    db = get_db()
    inspect(db[CFG.MONGO_COLL_CNN], "ÉPISODES CNN", CNN_EXPECTED)
    inspect(db[CFG.MONGO_COLL_SIGMA], "ALERTES SIGMA", SIGMA_EXPECTED)

    log.info("\n%s", "=" * 70)
    log.info("  Transmets la section « Clés non mappées » pour aligner")
    log.info("  models/detection_models.py sur ton schéma réel.")
    log.info("%s", "=" * 70)


if __name__ == "__main__":
    main()