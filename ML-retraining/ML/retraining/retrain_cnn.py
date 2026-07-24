"""
retrain_cnn.py
==============
Orchestrateur du cycle mensuel. Point d'entree du timer systemd.

    cd ML && python -m retraining.retrain_cnn

LES SEPT ETAPES
---------------
    0. Verrou + preflight     un seul cycle a la fois, environnement sain
    1. Fenetre glissante      [T - RETRAIN_WINDOW_MONTHS, T]
    2. Incidents confirmes    Mongo (LLM) + quarantaine + golden set
    3. Extraction en flux     ES -> parquet, filtre et decontamine au fil de l'eau
    4. Controle de volume     extraction anemique = cycle abandonne
    5. Entrainement isole     sous-processus, ecrit dans _candidate/
    6. Gate de validation     5 tests bloquants
    7. Promotion atomique     ou rejet archive

L'ISOLATION DU CANDIDAT, EN UNE VARIABLE D'ENVIRONNEMENT
--------------------------------------------------------
    env["SENTINEL_ARTIFACT_DIR"] = artifacts/_candidate

Cette seule ligne (couplee au patch de config_cnn.py) resout QUATRE problemes
d'un coup :

  1. le candidat ecrit ses 4 artefacts dans _candidate/ : la production n'est
     jamais touchee avant le verdict du gate ;
  2. DATASET_CACHE suit ARTIFACT_DIR, donc le snapshot decontamine ecrit a
     l'etape 3 devient AUTOMATIQUEMENT le cache que lit load_dataset(). Le
     mecanisme de cache -- qui etait le bug le plus dangereux du lot, un
     modele "neuf" reentraine silencieusement sur les donnees du mois
     precedent -- devient le point d'injection propre du corpus nettoye ;
  3. la memoire de l'entrainement est integralement rendue a l'OS quand le
     sous-processus se termine, AVANT que le gate ne charge deux modeles ;
  4. train_eval_cnn.py reste RIGOUREUSEMENT INCHANGE. Le pipeline de
     soutenance n'est pas touche par ce chantier.

CODES DE SORTIE
---------------
    0  modele promu
    2  candidat refuse par le gate (comportement NORMAL, pas une panne)
    1  erreur d'execution
"""
from __future__ import annotations

import argparse
import fcntl
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from retraining import retrain_config as RC

log = logging.getLogger("retrain")


# ===========================================================================
# Journalisation
# ===========================================================================
def setup_logging(logfile: Path | None = None) -> None:
    fmt = logging.Formatter("%(asctime)s  %(levelname)-7s %(message)s",
                            "%Y-%m-%d %H:%M:%S")
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers.clear()
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    root.addHandler(sh)
    if logfile:
        logfile.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(logfile)
        fh.setFormatter(fmt)
        root.addHandler(fh)


class Lock:
    """Verrou exclusif : le timer et un lancement manuel ne peuvent pas se
    marcher dessus. flock est libere automatiquement si le processus meurt."""

    def __init__(self, path):
        self.path = Path(path)
        self.fh = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fh = open(self.path, "w")
        try:
            fcntl.flock(self.fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit(
                f"Un cycle de reentrainement est deja en cours "
                f"({self.path}). Abandon.")
        self.fh.write(f"{os.getpid()}\n{datetime.now(timezone.utc)}\n")
        self.fh.flush()
        return self

    def __exit__(self, *exc):
        try:
            fcntl.flock(self.fh, fcntl.LOCK_UN)
            self.fh.close()
        except Exception:
            pass


# ===========================================================================
# Etape 0 : preflight
# ===========================================================================
def preflight() -> list[str]:
    """Verifie ce qui rendrait le cycle inutile AVANT de bruler 4 heures."""
    import config_cnn as C
    import data_loader as DL
    from retraining import artifact_store as AS
    from retraining import build_golden as BG
    from retraining.extract import available_ram_mb

    problems = []

    ram = available_ram_mb()
    if ram is not None:
        log.info("RAM disponible : %d Mo (minimum requis %d Mo)",
                 ram, RC.MIN_AVAILABLE_RAM_MB)
        if ram < RC.MIN_AVAILABLE_RAM_MB:
            problems.append(
                f"RAM disponible insuffisante ({ram} Mo < "
                f"{RC.MIN_AVAILABLE_RAM_MB} Mo). Arrete la stack ELK ou "
                f"abaisse MAX_DOCS_BY_SOURCE.")

    if not C.ES_PASS:
        problems.append("ELASTIC_PWD absent de l'environnement (.env).")
    else:
        try:
            info = DL._es_request("/")
            log.info("Elasticsearch joignable (version %s)",
                     info.get("version", {}).get("number", "?"))
        except Exception as e:
            problems.append(f"Elasticsearch injoignable : {e}")

    golden_problems = BG.verify()
    if golden_problems:
        problems += [f"golden set : {p}" for p in golden_problems]

    cur = AS.current_dir()
    if cur is None:
        log.warning("Aucune version promue : ce cycle sera le premier. "
                    "Les tests comparatifs du gate seront degrades.")
    else:
        bad = AS.check_artifact_set(cur, require_snapshot=False)
        if bad:
            problems.append(
                "la version COURANTE est deja incoherente : " + "; ".join(bad))

    if not Path(RC.TRAIN_ENTRYPOINT).exists():
        problems.append(f"introuvable : {RC.TRAIN_ENTRYPOINT}")

    return problems


# ===========================================================================
# Etape 1 : fenetre glissante
# ===========================================================================
def compute_window(months: int, now: datetime | None = None) -> tuple[str, str]:
    now = now or datetime.now(timezone.utc)
    start = now - timedelta(days=int(round(months * 30.44)))
    return (start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            now.strftime("%Y-%m-%dT%H:%M:%SZ"))


# ===========================================================================
# Etape 5 : entrainement isole
# ===========================================================================
def run_training(candidate: Path, window: tuple[str, str]) -> None:
    env = {
        **os.environ,
        "SENTINEL_ARTIFACT_DIR": str(candidate),
        "SENTINEL_USE_CACHE": "1",
        # Defense en profondeur : si le snapshot venait a manquer, le
        # sous-processus interrogerait ES -- au moins il le ferait sur la
        # bonne fenetre, et non sur tout l'historique.
        "ES_TIME_GTE": window[0],
        "ES_TIME_LTE": window[1],
        "PYTHONUNBUFFERED": "1",
    }
    logfile = candidate / "train.log"
    log.info("Lancement du sous-processus d'entrainement "
             "(SENTINEL_ARTIFACT_DIR=%s)", candidate)
    t0 = time.time()
    with open(logfile, "w") as fh:
        proc = subprocess.Popen(
            [sys.executable, RC.TRAIN_ENTRYPOINT],
            cwd=RC.ML_ROOT, env=env, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1)
        for line in proc.stdout:
            fh.write(line)
            sys.stdout.write("      | " + line)
        rc = proc.wait(timeout=RC.TRAIN_TIMEOUT_SECONDS)
    dt = time.time() - t0
    if rc != 0:
        raise RuntimeError(
            f"Entrainement echoue (code {rc}) apres {dt / 60:.1f} min. "
            f"Journal : {logfile}")
    log.info("Entrainement termine en %.1f min", dt / 60)


# ===========================================================================
# Cycle complet
# ===========================================================================
def run_cycle(args) -> int:
    from retraining import artifact_store as AS
    from retraining import extract as EX
    from retraining import validation_gate as VG
    from retraining.decontaminate import load_incidents

    t_start = time.time()
    AS.artifacts_root()
    candidate = AS.candidate_dir()

    # --- 0. preflight -----------------------------------------------------
    log.info("=" * 66)
    log.info("  SENTINEL CNN -- cycle de reentrainement")
    log.info("=" * 66)
    log.info("[0/7] Preflight")
    problems = preflight()
    if problems:
        for p in problems:
            log.error("  ! %s", p)
        if not args.force:
            log.error("Cycle abandonne. (--force pour passer outre)")
            return 1
        log.warning("--force : on continue malgre %d probleme(s).", len(problems))

    # --- 1. fenetre -------------------------------------------------------
    window = compute_window(args.window_months)
    log.info("[1/7] Fenetre glissante : %s -> %s (%d mois)",
             window[0], window[1], args.window_months)

    # --- 2. incidents -----------------------------------------------------
    log.info("[2/7] Incidents confirmes (boucle de retroaction Sigma/LLM)")
    incidents = load_incidents(include_golden=True)

    # --- 3. extraction ----------------------------------------------------
    snapshot = candidate / "dataset_snapshot.parquet"
    if args.skip_extract and snapshot.exists():
        log.info("[3/7] Extraction ignoree (--skip-extract), snapshot existant")
        extract_report = {"skipped": True}
    else:
        candidate_dir_fresh = AS.reset_candidate()
        snapshot = candidate_dir_fresh / "dataset_snapshot.parquet"
        candidate = candidate_dir_fresh
        log.info("[3/7] Extraction ES en flux -> %s", snapshot.name)
        extract_report = EX.extract_to_parquet(
            snapshot, window[0], window[1], incidents)

    # --- 4. controle de volume -------------------------------------------
    log.info("[4/7] Controle de volume")
    counts = (pd.read_parquet(snapshot, columns=["log_source"])["log_source"]
              .value_counts().to_dict())
    total = int(sum(counts.values()))
    log.info("  total=%s | %s", f"{total:,}",
             ", ".join(f"{k}={v:,}" for k, v in sorted(counts.items())))
    volume_problems = []
    if total < RC.MIN_EVENTS_TOTAL:
        volume_problems.append(
            f"total {total:,} < {RC.MIN_EVENTS_TOTAL:,}")
    for src, mini in RC.MIN_EVENTS_BY_SOURCE.items():
        got = int(counts.get(src, 0))
        if got < mini:
            volume_problems.append(f"{src} {got:,} < {mini:,}")
    if volume_problems:
        log.error("  Extraction anemique : %s", " ; ".join(volume_problems))
        log.error("  Entrainer sur un echantillon non representatif est pire "
                  "que ne pas reentrainer. Cycle abandonne.")
        if not args.force:
            AS.reject(candidate, AS.new_version_id(),
                      {"raison": "extraction_anemique",
                       "details": volume_problems})
            return 1
        log.warning("--force : on continue.")

    # --- 5. entrainement --------------------------------------------------
    log.info("[5/7] Entrainement du candidat (sous-processus isole)")
    if args.dry_run:
        log.info("  --dry-run : entrainement non lance. Arret ici.")
        return 0
    run_training(candidate, window)

    AS.write_manifest(candidate, {
        "window": {"gte": window[0], "lte": window[1],
                   "months": args.window_months},
        "extraction": extract_report,
        "counts_by_source": counts,
        "decontamination": {
            "n_incidents": len(incidents),
            "margin_seconds": RC.DECONTAMINATION_MARGIN_SECONDS,
            "incidents": [i.to_dict() for i in incidents],
        },
        "status": "candidate",
    })

    # --- 6. gate ----------------------------------------------------------
    log.info("[6/7] Gate de validation")
    current = AS.current_dir()
    report = VG.run_gate(candidate, current)
    report_path = AS.reports_dir() / \
        f"gate_{datetime.now(timezone.utc):%Y%m%dT%H%M%S}.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    log.info("  rapport -> %s", report_path)

    # --- 7. promotion ou rejet -------------------------------------------
    version = AS.new_version_id()
    if report["verdict"] != "PROMOTE" and not args.force_promote:
        dest = AS.reject(candidate, version, report["echecs_bloquants"])
        log.error("[7/7] CANDIDAT REFUSE -> %s", dest)
        log.error("  echecs bloquants : %s", report["echecs_bloquants"])
        log.info("  La production reste sur '%s'. Aucun service degrade.",
                 AS.current_version() or "(aucune)")
        log.info("  Duree du cycle : %.1f min", (time.time() - t_start) / 60)
        return 2

    if report["verdict"] != "PROMOTE":
        log.warning("--force-promote : promotion d'un candidat REFUSE par le "
                    "gate. A n'utiliser qu'en connaissance de cause.")
    dest = AS.promote(candidate, version, {
        "gate": {"verdict": report["verdict"],
                 "echecs_bloquants": report["echecs_bloquants"],
                 "rapport": str(report_path)}})
    log.info("[7/7] PROMU : current -> %s", dest.name)
    log.info("  Rollback si besoin : "
             "python -m retraining.artifact_store --rollback")
    log.info("  Duree du cycle : %.1f min", (time.time() - t_start) / 60)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Cycle mensuel de reentrainement du CNN Sentinel")
    ap.add_argument("--window-months", type=int, default=RC.RETRAIN_WINDOW_MONTHS)
    ap.add_argument("--dry-run", action="store_true",
                    help="extraction + controles, sans entrainement")
    ap.add_argument("--skip-extract", action="store_true",
                    help="reutiliser le snapshot du candidat existant")
    ap.add_argument("--force", action="store_true",
                    help="ignorer les echecs de preflight et de volume")
    ap.add_argument("--force-promote", action="store_true",
                    help="promouvoir meme si le gate refuse (dangereux)")
    a = ap.parse_args(argv)

    logfile = Path(RC.REPORTS_DIR) / \
        f"retrain_{datetime.now(timezone.utc):%Y%m%dT%H%M%S}.log"
    setup_logging(logfile)

    with Lock(RC.LOCK_FILE):
        try:
            return run_cycle(a)
        except Exception:
            log.exception("Cycle interrompu par une exception")
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
