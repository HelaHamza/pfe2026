"""
build_golden.py
===============
Construit et GELE les deux jeux de donnees dont depend le gate de validation.

    golden/incidents.json          <- A ECRIRE UNE FOIS, a la main
    golden/reference.json          <- A ECRIRE UNE FOIS, a la main
    golden/golden_events.parquet   <- genere ici
    golden/reference_events.parquet<- genere ici
    golden/manifest.json           <- genere ici (SHA-256 : le gel est verifiable)

POURQUOI DEUX JEUX, ET POURQUOI FIGES
-------------------------------------
* golden_events    : tranches d'evenements couvrant les scenarios d'attaque
                     connus (SSH brute-force, persistance cron T1053, ...).
                     Sert au test de NON-REGRESSION FONCTIONNELLE : si le
                     candidat rate un scenario que le courant detectait, il est
                     refuse. C'est le test le plus fort du gate.

* reference_events : tranche BENIGNE, sans aucun incident. Sert aux tests de
                     taux d'alerte et de derive de distribution.

Le mot important est FIGES. Comparer candidat et courant sur des donnees qui
changent d'un mois sur l'autre ne mesure rien : on ne saurait pas si l'ecart
vient du modele ou des donnees. Le manifest SHA-256 rend le gel verifiable --
si quelqu'un regenere le golden set, le gate le signale.

CONSEQUENCE IMPORTANTE
----------------------
Les incidents du golden set sont automatiquement excises du corpus de
reentrainement par decontaminate.load_incidents(). Sans cela, le candidat
serait entraine sur ses propres reponses d'examen et le test (a) ne
prouverait plus rien.

USAGE
-----
    # 1. ecrire golden/incidents.json et golden/reference.json (cf. gabarits)
    # 2. generer
    python -m retraining.build_golden --from dataset_snapshot.parquet
    # 3. verifier
    python -m retraining.build_golden --verify
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from retraining import retrain_config as RC
from retraining.artifact_store import sha256_file, _atomic_write_json
from retraining.decontaminate import _load_json_incidents

GOLDEN_DIR = Path(RC.GOLDEN_DIR)
INCIDENTS_JSON = GOLDEN_DIR / "incidents.json"
REFERENCE_JSON = GOLDEN_DIR / "reference.json"
GOLDEN_PARQUET = GOLDEN_DIR / "golden_events.parquet"
REFERENCE_PARQUET = GOLDEN_DIR / "reference_events.parquet"
GOLDEN_MANIFEST = GOLDEN_DIR / "manifest.json"

# Contexte benin conserve autour de chaque incident. Sans contexte, le
# fenetrage (W=16, stride 1) ne peut pas construire une seule fenetre
# complete : les scores seraient calcules sur des fenetres tronquees.
CONTEXT_SECONDS = 3600


def _slice(df: pd.DataFrame, start, end, log_source=None, host_name=None):
    ts = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    m = (ts >= start) & (ts <= end)
    if log_source:
        m &= df["log_source"] == log_source
    if host_name and "host_name" in df.columns:
        m &= df["host_name"] == host_name
    return df.loc[m.fillna(False)]


def build(source_parquet, context_seconds: int = CONTEXT_SECONDS) -> dict:
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    if not INCIDENTS_JSON.exists():
        _write_templates()
        raise SystemExit(
            f"Gabarits ecrits dans {GOLDEN_DIR}. Renseigne incidents.json et "
            f"reference.json a partir de ton groundtruth, puis relance.")

    df = pd.read_parquet(source_parquet)
    print(f"  Source : {source_parquet} ({len(df):,} evenements)")

    incidents = _load_json_incidents(INCIDENTS_JSON, "golden")
    if not incidents:
        raise SystemExit("golden/incidents.json ne contient aucun incident.")

    ctx = pd.Timedelta(seconds=context_seconds)
    parts, per_incident = [], {}
    for inc in incidents:
        sl = _slice(df, inc.start - ctx, inc.end + ctx,
                    inc.log_source, inc.host_name)
        per_incident[inc.id] = len(sl)
        print(f"    {inc.id:28s} {len(sl):>7,} evenements")
        if len(sl) == 0:
            print(f"      ! ATTENTION : tranche VIDE. Verifie les bornes, "
                  f"log_source et host_name de cet incident.")
        parts.append(sl)
    golden = pd.concat(parts).drop_duplicates().reset_index(drop=True)
    golden.to_parquet(GOLDEN_PARQUET, index=False)
    print(f"  golden_events    : {len(golden):,} evenements")

    with open(REFERENCE_JSON) as f:
        ref = json.load(f)
    ref_df = _slice(df, pd.Timestamp(ref["start"]), pd.Timestamp(ref["end"]))
    # Securite : la fenetre de reference doit etre VIERGE d'incident.
    from retraining.decontaminate import mask_contaminated
    bad = mask_contaminated(ref_df, incidents)
    if bad.any():
        raise SystemExit(
            f"La fenetre de reference chevauche {int(bad.sum())} evenement(s) "
            f"d'incident. Elle doit etre strictement benigne : choisis une "
            f"autre periode dans golden/reference.json.")
    ref_df = ref_df.reset_index(drop=True)
    ref_df.to_parquet(REFERENCE_PARQUET, index=False)
    print(f"  reference_events : {len(ref_df):,} evenements "
          f"({ref['start']} -> {ref['end']})")

    manifest = {
        "created_at": pd.Timestamp.utcnow().isoformat(),
        "source_parquet": str(source_parquet),
        "context_seconds": context_seconds,
        "n_incidents": len(incidents),
        "events_per_incident": per_incident,
        "golden_events": {"rows": len(golden),
                          "sha256": sha256_file(GOLDEN_PARQUET)},
        "reference_events": {"rows": len(ref_df), "window": ref,
                             "sha256": sha256_file(REFERENCE_PARQUET)},
        "incidents_sha256": sha256_file(INCIDENTS_JSON),
    }
    _atomic_write_json(GOLDEN_MANIFEST, manifest)
    print(f"  manifest -> {GOLDEN_MANIFEST}")
    return manifest


def verify() -> list[str]:
    """Le golden set est-il toujours celui qui a ete gele ?"""
    problems = []
    if not GOLDEN_MANIFEST.exists():
        return ["golden/manifest.json absent : golden set jamais construit."]
    with open(GOLDEN_MANIFEST) as f:
        man = json.load(f)
    for key, path in (("golden_events", GOLDEN_PARQUET),
                      ("reference_events", REFERENCE_PARQUET)):
        if not path.exists():
            problems.append(f"{path.name} absent")
        elif sha256_file(path) != man[key]["sha256"]:
            problems.append(
                f"{path.name} a ete modifie depuis le gel "
                f"(SHA-256 divergent). Les comparaisons candidat/courant "
                f"anterieures ne sont plus valides.")
    if INCIDENTS_JSON.exists() and \
            sha256_file(INCIDENTS_JSON) != man.get("incidents_sha256"):
        problems.append("golden/incidents.json modifie depuis le gel.")
    return problems


def _write_templates() -> None:
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    if not INCIDENTS_JSON.exists():
        _atomic_write_json(INCIDENTS_JSON, {"incidents": [
            {"id": "ssh_bruteforce_01", "technique": "T1110.001",
             "log_source": "auth", "host_name": "ASUS-X415JA",
             "start": "2026-06-12T10:00:00Z", "end": "2026-06-12T10:20:00Z",
             "note": "brute-force SSH depuis localhost"},
            {"id": "cron_persistence_01", "technique": "T1053.003",
             "log_source": "auditd", "host_name": "ASUS-X415JA",
             "start": "2026-06-20T14:00:00Z", "end": "2026-06-20T14:10:00Z",
             "note": "/tmp/.update - test de generalisation, score 43.1"},
        ]})
    if not REFERENCE_JSON.exists():
        _atomic_write_json(REFERENCE_JSON, {
            "start": "2026-06-14T00:00:00Z",
            "end": "2026-06-21T00:00:00Z",
            "note": "semaine benigne, sans aucun incident confirme"})


def main(argv=None) -> int:
    import argparse
    import config_cnn as C
    ap = argparse.ArgumentParser(description="Golden set fige du gate")
    ap.add_argument("--from", dest="src", default=C.DATASET_CACHE)
    ap.add_argument("--context-seconds", type=int, default=CONTEXT_SECONDS)
    ap.add_argument("--verify", action="store_true")
    a = ap.parse_args(argv)

    if a.verify:
        problems = verify()
        if problems:
            print("PROBLEMES :")
            for p in problems:
                print(f"  - {p}")
            return 1
        print("OK : golden set intact.")
        return 0
    build(a.src, a.context_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
