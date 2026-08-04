#!/usr/bin/env python3
"""Injecteur d'anomalies BÉNIGNES et RÉVERSIBLES pour évaluer Sentinel.

Toutes les techniques sont atomiques et nettoyées immédiatement (create->delete).
Aucune ne laisse d'état persistant, ne touche un vrai log, ni un vrai compte.
Elles servent uniquement à générer de la télémétrie auditbeat -> ES, avec un
ground-truth horodaté pour l'évaluation.

Nouveautés vs version précédente
--------------------------------
  * --gap : silence imposé ENTRE deux techniques -> épisodes séparables, donc
            attribution épisode<->technique non ambiguë à l'évaluation.
  * --noise N : active N actions BÉNIGNES entre les techniques. Elles ne sont
            PAS écrites dans le ground-truth : elles peuplent les négatifs pour
            que la précision soit réellement mesurable (sinon, sur une machine
            au repos, il n'y a aucun bénin actif à confondre -> précision faussée).
  * run_window.json : borne globale [t0, t1] de la campagne (+ pad), pour lancer
            predict_cnn --since/--until sur EXACTEMENT la bonne fenêtre.
  * Correction MITRE : lecture de /etc/shadow -> T1003.008 (OS Credential
            Dumping: /etc/passwd and /etc/shadow), pas T1552.001.
"""

import os
import sys
import json
import time
import uuid
import random
import shutil
import socket
import argparse
import subprocess
from datetime import datetime, timezone, timedelta

# --------------------------------------------------------------------------- #
#  CONFIG                                                                      #
# --------------------------------------------------------------------------- #
DEFAULT_LOG_SOURCE = "auditbeat"   # doit matcher ton mapping log_source côté ES
GROUNDTRUTH_PATH   = "groundtruth.jsonl"
RUN_WINDOW_PATH    = "run_window.json"
BUFFER_SECONDS      = 3.0          # marge autour de chaque fenêtre (latence ingest)
DWELL_SECONDS       = 2.0          # attente entre run et cleanup
EPISODE_GAP_SECONDS = 300.0        # DOIT matcher EPISODE_GAP de predict_cnn.py
GAP_MARGIN_SECONDS  = 30.0         # silence AU-DESSUS d'EPISODE_GAP entre techniques
SETTLE_SECONDS      = 60.0         # attente finale : auditbeat -> ES
WINDOW_PAD_SECONDS  = 60.0         # marge ajoutée à [t0,t1] dans run_window.json

_RID = uuid.uuid4().hex[:8]        # suffixe unique par run (évite les collisions)


def _u(name: str) -> str:
    """Nom d'artefact unique et traçable (jamais un vrai nom système)."""
    return f"sentinel_{name}_{_RID}"


# --------------------------------------------------------------------------- #
#  REGISTRE DES TECHNIQUES (bénignes, réversibles)                            #
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
#  REGISTRE DES TECHNIQUES (bénignes, réversibles)                            #
#                                                                             #
#  Recalé sur les features RÉELLES de cnn_feature.py. Rareté = 1/(1+vues) sur #
#  vocab GELÉ -> tout identifiant suffixé RID est neuf -> rareté 1.0. Chaque  #
#  technique cite la/les feature(s) qu'elle pousse. Non atteignables depuis   #
#  localhost : geo_rarity, ip_is_external (exigent une IP source externe).    #
#  'needs' = binaires requis (sinon SKIP propre).                             #
# --------------------------------------------------------------------------- #
def build_registry():
    user   = _u("u")[:31]
    hidden = f"/tmp/.{_u('h')}"
    rbin   = f"{hidden}/zqx{_RID}"          # binaire au nom rare, chemin caché neuf
    capf   = f"/tmp/{_u('cap')}"
    tsf    = f"/tmp/{_u('ts')}"
    # argument long + forte entropie -> cmd_entropy + cmd_length_log + arg_count
    entarg = "$(head -c 24 /dev/urandom | base64 | tr -d =) a1 b2 c3 d4 e5 f6 g7 h8"

    return {
        # -- AUTH : is_fail + user_rarity + inter_arrival(ip) -----------------
        "auth_fail_burst": dict(
            technique="T1110.001", needs_sudo=False, needs=["ssh"],
            desc="AUTH is_fail + user_rarity + inter_arrival : 6 échecs SSH (users invalides) sur 127.0.0.1  [sshd requis]",
            run=[f"bash -c 'for i in $(seq 1 6); do ssh -o BatchMode=yes "
                 f"-o ConnectTimeout=2 -o StrictHostKeyChecking=no "
                 f"nouser_{_RID}_$i@127.0.0.1 true 2>/dev/null; done'"],
            cleanup=[]),

        # -- AUTH/AUDITD : user_rarity (compte jamais vu) ---------------------
        "new_user_session": dict(
            technique="T1136.001", needs_sudo=True, needs=["useradd", "usermod", "su"],
            desc="AUTH/AUDITD user_rarity : nouveau compte + ajout sudo + session su",
            run=[f"useradd -M -N -s /bin/bash {user}",
                 f"usermod -aG sudo {user}",
                 f"su - {user} -c 'id; whoami' 2>/dev/null",
                 f"id {user}"],
            cleanup=[f"gpasswd -d {user} sudo 2>/dev/null", f"userdel {user}"]),

        # -- AUDITD : exe_path_rarity + proc_rarity + lignée + burst + forme --
        "rare_binary_burst": dict(
            technique="T1059.004", needs_sudo=False, needs=[],
            desc="AUDITD exe_path_rarity + proc_rarity + parent_child_rarity + inter_arrival + cmd_entropy/length/arg_count",
            run=[f"mkdir -p {hidden}",
                 f"cp /bin/true {rbin}",
                 f"chmod +x {rbin}",
                 f"bash -c 'for i in $(seq 1 12); do {rbin} {entarg} >/dev/null 2>&1; done'"],
            cleanup=[f"rm -rf {hidden}"]),

        # -- AUDITD : syscall_rarity (syscalls quasi absents du baseline) -----
        "ptrace_probe": dict(
            technique="T1055", needs_sudo=False, needs=["strace"],
            desc="AUDITD syscall_rarity : ptrace via strace (syscall quasi jamais vu)",
            run=["strace -o /dev/null /bin/true 2>/dev/null"],
            cleanup=[]),

        "kmod_load_attempt": dict(
            technique="T1547.006", needs_sudo=True, needs=["insmod"],
            desc="AUDITD syscall_rarity : finit_module tenté (insmod /bin/true, rejeté -> rien chargé)",
            run=["insmod /bin/true 2>/dev/null || true"],
            cleanup=[]),

        "capability_set": dict(
            technique="T1548", needs_sudo=True, needs=["setcap", "getcap"],
            desc="AUDITD syscall_rarity(capset) + proc_rarity(setcap) : capability sur un leurre",
            run=[f"cp /bin/true {capf}",
                 f"setcap cap_net_raw+ep {capf}",
                 f"getcap {capf}"],
            cleanup=[f"rm -f {capf}"]),

        # -- AUDITD : signal faible (touch commun), gardé pour couverture -----
        "timestomp_decoy": dict(
            technique="T1070.006", needs_sudo=False, needs=["touch"],
            desc="AUDITD (signal FAIBLE) : utimensat via touch -t date passée sur un leurre",
            run=[f"touch {tsf}",
                 f"touch -t 202001010000.00 {tsf}",
                 f"stat {tsf} >/dev/null"],
            cleanup=[f"rm -f {tsf}"]),
    }


# Actions BÉNIGNES pour --noise : lecture/inventaire système, aucune mutation.
# Volontairement variées pour créer des épisodes bénins non triviaux.
BENIGN_NOISE = [
    "bash -c 'ls -laR /usr/bin > /dev/null 2>&1'",
    "bash -c 'cat /etc/hostname /etc/os-release > /dev/null 2>&1'",
    "bash -c 'find /usr/share -maxdepth 2 -type f > /dev/null 2>&1'",
    "bash -c 'ps aux > /dev/null 2>&1'",
    "bash -c 'grep -r root /etc/passwd > /dev/null 2>&1'",
    "bash -c 'id; uptime; who > /dev/null 2>&1'",
    "bash -c 'stat /bin/* > /dev/null 2>&1'",
    "bash -c 'du -sh /var/log > /dev/null 2>&1'",
]


# --------------------------------------------------------------------------- #
#  Exécution                                                                   #
# --------------------------------------------------------------------------- #
def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _run_cmds(cmds, dry):
    for c in cmds:
        if dry:
            print(f"      [dry] {c}")
            continue
        r = subprocess.run(c, shell=True, capture_output=True, text=True)
        tag = "ok" if r.returncode == 0 else f"RC={r.returncode}"
        print(f"      $ {c}   [{tag}]")
        if r.returncode != 0 and r.stderr.strip():
            print(f"        stderr: {r.stderr.strip().splitlines()[0]}")


def run_noise(n, dry):
    if n <= 0:
        return
    print(f"\n  -- bruit bénin ({n} action(s), NON écrit dans le ground-truth) --")
    for _ in range(n):
        _run_cmds([random.choice(BENIGN_NOISE)], dry)
        if not dry:
            time.sleep(random.uniform(0.5, 1.5))


def inject_one(name, spec, host, log_source, buffer_s, dwell_s, dry):
    aid = f"{spec['technique']}_{name}_{_RID}"
    print(f"\n  >> {name}  ({spec['technique']})  {spec['desc']}")
    if spec["needs_sudo"] and os.geteuid() != 0 and not dry:
        print("     [SKIP] nécessite sudo (relance avec les droits root).")
        return None
    missing = [b for b in spec.get("needs", []) if not shutil.which(b)]
    if missing and not dry:
        print(f"     [SKIP] binaire(s) requis absent(s) : {missing}  "
              f"(apt install ...)")
        return None

    t_start = _now() - timedelta(seconds=buffer_s)
    print("     -- run --")
    _run_cmds(spec["run"], dry)
    if not dry:
        time.sleep(dwell_s)
    t_end = _now() + timedelta(seconds=buffer_s)
    print("     -- cleanup --")
    _run_cmds(spec["cleanup"], dry)

    return {
        "attack_id": aid,
        "technique": spec["technique"],
        "host_name": host,
        "log_source": log_source,
        "t_start": _iso(t_start),
        "t_end": _iso(t_end),
        "description": spec["desc"],
        "injected_at": _iso(_now()),
    }


def append_groundtruth(path, rows):
    with open(path, "a") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def write_run_window(path, rows, left_pad, right_pad, episode_gap_s):
    """Borne globale de la campagne, pour predict_cnn --since/--until.

    predict_cnn calcule watermark = until - EPISODE_GAP et ne finalise que les
    épisodes terminés AVANT le watermark. Pour que la DERNIÈRE attaque (fin t1)
    soit traitable, il faut donc until >= t1 + EPISODE_GAP. On ajoute pad_s de
    marge. Le run total (until - since) dépasse alors EPISODE_GAP, ce qui lève
    aussi le garde-fou 'fenêtre <= EPISODE_GAP'."""
    if not rows:
        return None
    t0 = min(datetime.fromisoformat(r["t_start"].replace("Z", "+00:00")) for r in rows)
    t1 = max(datetime.fromisoformat(r["t_end"].replace("Z", "+00:00")) for r in rows)
    since = t0 - timedelta(seconds=left_pad)                # inclut le warm-up bénin
    until = t1 + timedelta(seconds=episode_gap_s + right_pad)
    watermark = until - timedelta(seconds=episode_gap_s)    # = t1 + right_pad
    win = {
        "since": _iso(since),
        "until": _iso(until),
        "watermark": _iso(watermark),      # lance predict_cnn APRÈS cet instant
        "episode_gap_s": episode_gap_s,
        "run_id": _RID,
        "n_attacks": len(rows),
    }
    with open(path, "w") as f:
        json.dump(win, f, indent=2)
    return win


# --------------------------------------------------------------------------- #
#  CLI                                                                         #
# --------------------------------------------------------------------------- #
def main():
    reg = build_registry()
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="",
                    help="techniques à jouer (csv). défaut : toutes.")
    ap.add_argument("--list", action="store_true", help="liste et sort")
    ap.add_argument("--show-host", action="store_true",
                    help="affiche le host_name qui sera écrit")
    ap.add_argument("--host", default=None,
                    help="force host_name (défaut : hostname système)")
    ap.add_argument("--log-source", default=DEFAULT_LOG_SOURCE)
    ap.add_argument("--groundtruth", default=GROUNDTRUTH_PATH)
    ap.add_argument("--run-window", default=RUN_WINDOW_PATH)
    ap.add_argument("--buffer", type=float, default=BUFFER_SECONDS)
    ap.add_argument("--dwell", type=float, default=DWELL_SECONDS)
    ap.add_argument("--episode-gap", type=float, default=EPISODE_GAP_SECONDS,
                    help="EPISODE_GAP de predict_cnn.py (dimensionne fenêtre + gap)")
    ap.add_argument("--gap", type=float, default=None,
                    help="silence entre techniques (défaut: episode_gap + marge, "
                         "pour garantir 1 épisode distinct par technique)")
    ap.add_argument("--noise", type=int, default=0,
                    help="nb d'actions bénignes entre techniques (peuplent les négatifs)")
    ap.add_argument("--settle", type=float, default=SETTLE_SECONDS)
    ap.add_argument("--pad", type=float, default=WINDOW_PAD_SECONDS,
                    help="marge droite ajoutée à until dans run_window.json")
    ap.add_argument("--warmup", type=float, default=None,
                    help="silence AVANT la 1re attaque (défaut: episode_gap) "
                         "pour sortir les attaques de la zone seed de predict_cnn")
    ap.add_argument("--append", action="store_true",
                    help="CUMULE dans groundtruth.jsonl au lieu de le réinitialiser "
                         "(défaut: fresh, pour ne pas mélanger deux runs)")
    ap.add_argument("--seed", type=int, default=None, help="graine du bruit bénin")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)
    if args.warmup is None:
        args.warmup = args.episode_gap

    # gap par défaut = au-dessus d'EPISODE_GAP -> un épisode distinct par technique.
    if args.gap is None:
        args.gap = args.episode_gap + GAP_MARGIN_SECONDS
    if args.gap <= args.episode_gap:
        print(f"  /!\\ gap ({args.gap:.0f}s) <= episode_gap ({args.episode_gap:.0f}s) : "
              "les techniques risquent de FUSIONNER en un seul épisode.")

    host = args.host or socket.gethostname()

    if args.show_host:
        print(f"host_name = {host}   (vérifie qu'il matche host.name dans ES)")
        return
    if args.list:
        print("Techniques disponibles :")
        for n, s in reg.items():
            sudo = " [sudo]" if s["needs_sudo"] else ""
            print(f"  {n:16s} {s['technique']:12s}{sudo}  {s['desc']}")
        return

    names = [x.strip() for x in args.only.split(",") if x.strip()] or list(reg)
    unknown = [n for n in names if n not in reg]
    if unknown:
        print(f"Inconnu(es) : {unknown}. Voir --list.")
        return

    print("=" * 64)
    print(f"  INJECTION  (run_id={_RID}, host={host}, source={args.log_source})")
    print(f"  {'DRY-RUN — rien exécuté' if args.dry_run else 'RÉEL'}"
          f"   gap={args.gap:.0f}s  warmup={args.warmup:.0f}s  "
          f"episode_gap={args.episode_gap:.0f}s  {'APPEND' if args.append else 'FRESH'}")
    est = args.warmup + (len(names) - 1) * args.gap \
        + len(names) * (args.dwell + 2 * args.buffer)
    print(f"  durée estimée ~{est/60:.0f} min  (+ settle {args.settle:.0f}s)")
    print("=" * 64)

    if not args.append and not args.dry_run:
        open(args.groundtruth, "w").close()   # FRESH : repart d'un GT vide
        print(f"  [fresh] {args.groundtruth} réinitialisé (--append pour cumuler).\n")

    # warm-up : silence avant la 1re attaque -> sort les attaques de la zone seed
    if args.warmup > 0 and not args.dry_run:
        print(f"  ... warm-up {args.warmup:.0f}s (avant 1re attaque) ...")
        time.sleep(args.warmup)

    rows = []
    for idx, n in enumerate(names):
        row = inject_one(n, reg[n], host, args.log_source,
                         args.buffer, args.dwell, args.dry_run)
        if row:
            rows.append(row)
        # bruit + silence ENTRE les techniques (pas après la dernière)
        if idx < len(names) - 1:
            run_noise(args.noise, args.dry_run)
            if args.gap > 0 and not args.dry_run:
                print(f"     ... silence {args.gap:.0f}s ...")
                time.sleep(args.gap)

    if args.dry_run:
        print("\n  [dry-run] groundtruth NON modifié.")
        return
    if not rows:
        print("\n  Aucune ligne écrite (tout skippé ?).")
        return

    append_groundtruth(args.groundtruth, rows)
    win = write_run_window(args.run_window, rows,
                           args.warmup + args.pad, args.pad, args.episode_gap)
    print(f"\n  {len(rows)} ligne(s) écrite(s) -> {args.groundtruth}")
    for r in rows:
        print(f"    {r['attack_id']}  [{r['t_start']} .. {r['t_end']}]")

    if args.settle > 0:
        print(f"\n  Attente settle {args.settle:.0f}s (auditbeat -> ES)...")
        time.sleep(args.settle)

    print("\n  Fenêtre de campagne -> " + args.run_window)
    if win:
        print(f"    since     = {win['since']}")
        print(f"    until     = {win['until']}   (= t1 + episode_gap + pad)")
        print(f"    watermark = {win['watermark']}   (lance predict_cnn APRÈS)")
        print("\n  Étapes suivantes (adapte les chemins predict/triage) :")
        print(f"    python3 predict_cnn.py --since {win['since']} --until {win['until']}")
        print("    python3 triage_cnn.py")
        print("    # --scored = le CSV d'alertes de predict ; --run-id filtre le GT sur CE run")
        print("    python3 evaluate_cnn_vs_llm.py \\")
        print("        --scored   cnn_alerts_episodes.csv \\")
        print(f"        --groundtruth {args.groundtruth} \\")
        print("        --triage   cnn_triage.jsonl \\")
        print(f"        --run-id   {_RID}")
    print("=" * 64)


if __name__ == "__main__":
    main()