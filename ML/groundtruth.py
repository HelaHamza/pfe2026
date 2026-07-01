#!/usr/bin/env python3
"""
groundtruth.py
==============
Harnais d'injection RED-TEAM restreint aux anomalies DETECTABLES PAR L'AUTOENCODEUR
SEUL, c.-a-d. a SIGNATURE STATISTIQUE (volume, frequence, deviation, entropie).

Volontairement EXCLUS (domaine SIGMA, pas AE) :
  * lecture /etc/shadow (T1003.008)  -> signature de chemin sensible
  * service/cron malveillant (T1543) -> signature semantique, evenement bien
    forme ; la seule prise AE serait proc_is_new/et_bigram_new, MORTES au test
    (vocabulaire sature) -> non fiable.
Les inclure plomberait artificiellement le recall de l'AE. Ils relevent de la
couche Sigma et doivent etre evalues separement.

Regles (inchangees) :
  * groundtruth.jsonl = JUGE EXTERNE d'evaluation UNIQUEMENT, jamais
    utilise pour l'entrainement (pipeline non supervise).
  * Injection MAINTENANT -> fenetres dans le split TEST (futur).
  * Charges BENIGNES (reproduction de la signature, pas de l'effet) + nettoyage.

Couverture (anomalies statistiques uniquement) :
  AUTH    T1110.001  brute-force SSH        -> auth_fail_count_5m, fail_ratio, dev
  AUTH    T1136.001  creation utilisateur   -> evenement rare (MSE elevee)
  AUDITD  T1059.004  exec base64            -> cmd_entropy
  SYSLOG  --         rafale volumetrique    -> event_count_5m / event_count_5m_dev

Prerequis :
  * sudo (useradd, journald).  * Fenetres alignees sur juin (DATA_START_BY_SOURCE).
  * ES_TIME_LTE FIGE (pas "now") pour la reproductibilite.

Usage :
    sudo python3 groundtruth.py
    sudo python3 groundtruth.py --source auth
    sudo python3 groundtruth.py --bf-count 60 --burst-count 300
"""
from __future__ import annotations
import os
import sys
import json
import time
import socket
import base64
import argparse
import subprocess
from datetime import datetime, timezone

_HOME = os.path.expanduser("~" + os.environ.get("SUDO_USER", ""))
ML_DIR = os.path.join(_HOME, "pfe-backend-2026", "ML")
GROUNDTRUTH_PATH = os.path.join(ML_DIR, "groundtruth.jsonl")
HOST = socket.gethostname()
TEST_USER = "testintrus"


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _append_groundtruth(entry):
    entry = {**entry, "host": HOST, "injected_at": _now_iso()}
    with open(GROUNDTRUTH_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"  [GT] {entry['name']:24s} [{entry['start']} -> {entry['end']}]")


def _run(cmd, quiet=False):
    if not quiet:
        print(f"    $ {' '.join(cmd)}")
    return subprocess.run(cmd, capture_output=True, text=True)


# ===========================================================================
# AUTH
# ===========================================================================
def inject_ssh_bruteforce(count=60):
    """Echecs SSH en rafale sur localhost (utilisateurs invalides) -> pilote
    auth_fail_count_5m, auth_fail_ratio, event_count_5m_dev. BatchMode=yes ->
    echec immediat, aucun mot de passe reel tente, aucune session etablie."""
    print(f"\n[AUTH] T1110.001 brute-force SSH ({count} echecs)")
    start = _now_iso()
    opts = ["-o", "BatchMode=yes", "-o", "PubkeyAuthentication=no",
            "-o", "PreferredAuthentications=password,keyboard-interactive",
            "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=2"]
    for i in range(1, count + 1):
        _run(["ssh", *opts, f"invaliduser{i}@127.0.0.1", "true"], quiet=True)
    time.sleep(3)
    _append_groundtruth({
        "name": "auth_ssh_bruteforce", "technique": "T1110.001", "source": "auth",
        "start": start, "end": _now_iso(),
        "note": f"{count} echecs SSH invaliduser sur 127.0.0.1.",
    })


def inject_user_creation():
    """Creation puis suppression d'un utilisateur -> evenement rare (MSE elevee).
    Nettoyage garanti."""
    print(f"\n[AUTH] T1136.001 creation utilisateur ({TEST_USER})")
    start = _now_iso()
    try:
        _run(["userdel", "-r", TEST_USER])           # purge reliquat eventuel
        _run(["useradd", "-m", TEST_USER])
        time.sleep(2)
    finally:
        _run(["userdel", "-r", TEST_USER])            # cleanup
    _append_groundtruth({
        "name": "auth_user_creation", "technique": "T1136.001", "source": "auth",
        "start": start, "end": _now_iso(),
        "note": f"useradd {TEST_USER} puis userdel (cleanup).",
    })


# ===========================================================================
# AUDITD
# ===========================================================================
def inject_base64_exec():
    """Commande encodee base64 (charge BENIGNE : echo) -> ligne de commande a
    HAUTE ENTROPIE dans auditd (pilote cmd_entropy)."""
    print("\n[AUDITD] T1059.004 exec commande base64")
    start = _now_iso()
    payload = base64.b64encode(b"echo sentinel-benign-payload").decode()
    _run(["bash", "-c", f"echo {payload} | base64 -d | bash"])
    time.sleep(2)
    _append_groundtruth({
        "name": "auditd_base64_exec", "technique": "T1059.004", "source": "auditd",
        "start": start, "end": _now_iso(),
        "note": "Commande base64 (charge benigne echo). Cible : cmd_entropy.",
    })


# ===========================================================================
# SYSLOG
# ===========================================================================
def inject_volumetric_burst(count=300):
    """Rafale de `count` messages syslog en quelques secondes -> pic de
    event_count_1m/5m. Sonde DIRECTE de la feature volumetrique."""
    print(f"\n[SYSLOG] rafale volumetrique ({count} messages)")
    start = _now_iso()
    t0 = time.time()
    for i in range(count):
        _run(["logger", "-t", "sentinel-burst",
              f"red-team volumetric probe {i+1}/{count}"], quiet=True)
    dur = time.time() - t0
    time.sleep(3)
    print(f"    {count} messages en {dur:.1f}s (~{count/max(dur,1e-3):.0f} msg/s)")
    _append_groundtruth({
        "name": "syslog_volumetric_burst", "technique": None, "source": "syslog",
        "start": start, "end": _now_iso(),
        "note": f"{count} messages logger en {dur:.1f}s. Cible : event_count_5m.",
    })

def inject_arg_heavy_exec(nargs=150):
    """Exec a nombre d'arguments anormalement eleve -> pic arg_count +
    cmd_length_log cote auditd. Proxy d'obfuscation / command stuffing.
    Charge 100% benigne (echo). Signal AE dedie (arg_count monte rarement
    en usage normal, contrairement a event_count sature par les builds)."""
    print(f"\n[AUDITD] exec a arg_count anormal ({nargs} args)")
    start = _now_iso()
    args = [f"a{i}" for i in range(nargs)]
    _run(["/bin/echo", *args], quiet=True)
    time.sleep(2)
    _append_groundtruth({
        "name": "auditd_arg_heavy_exec", "technique": "T1059.004", "source": "auditd",
        "start": start, "end": _now_iso(),
        "note": f"echo {nargs} args. Cible : arg_count / cmd_length_log.",
    })
# ===========================================================================
# Orchestration
# ===========================================================================
SCENARIOS = {
    "auth":   [inject_ssh_bruteforce, inject_user_creation],
    "auditd": [inject_base64_exec,inject_arg_heavy_exec],
    "syslog": [inject_volumetric_burst],
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", choices=["auth", "auditd", "syslog", "all"],
                    default="all")
    ap.add_argument("--bf-count", type=int, default=60)
    ap.add_argument("--burst-count", type=int, default=300)
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("ERREUR : lancer avec sudo (useradd, journald).")
        sys.exit(1)
    if not os.path.isdir(ML_DIR):
        print(f"ERREUR : repertoire ML introuvable : {ML_DIR} (adapter ML_DIR).")
        sys.exit(1)

    print("=" * 64)
    print(f"  RED-TEAM GROUNDTRUTH (AE-only) | host={HOST} | {_now_iso()}")
    print(f"  source={args.source}")
    print("=" * 64)

    sources = ["auth", "auditd", "syslog"] if args.source == "all" else [args.source]
    for src in sources:
        for fn in SCENARIOS[src]:
            if fn is inject_ssh_bruteforce:
                fn(args.bf_count)
            elif fn is inject_volumetric_burst:
                fn(args.burst_count)
            else:
                fn()

    print("\n" + "=" * 64)
    print("  Injection terminee. Etapes suivantes :")
    print("  1. Attendre ~2-3 min l'ingestion ES.")
    print("  2. cd ~/pfe-backend-2026/ML")
    print("  3. rm dataset_snapshot.parquet && python training.py && python inference.py")
    print("  4. Recall AE : croiser groundtruth.jsonl (fenetres) avec")
    print("     alerts_episodes.csv -- une fenetre est DETECTEE si un episode la recouvre.")
    print("  Verif cleanup : 'id testintrus' doit etre introuvable.")
    print("=" * 64)


if __name__ == "__main__":
    main()