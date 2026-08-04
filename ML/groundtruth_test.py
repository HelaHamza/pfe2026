"""
groundtruth.py — Injection de logs anormaux FORGÉS (compatibles evaluation.py)
=============================================================================

But
---
Forger de nouveaux logs anormaux dans l'espace de features réellement appris par
le CNN (cf. feature_engineering.py), puis produire de quoi les évaluer AVEC TA
chaîne existante (inference -> evaluation.py), sans rien réimplémenter du modèle.

Alignement STRICT sur evaluation.py
-----------------------------------
1. MARQUEUR de label ligne : les tentatives auth portent user_name = invaliduser{k}
   (regex `invaliduser\\d+` de label_events). Rotatif -> réaliste ET user_rarity haute.
   (Les scénarios auditd s'appuient sur les FENÊTRES GT, comme ta note "exec auditd
   non etiquete par marqueur -> conservateur".)
2. SCHÉMA GT : groundtruth.jsonl a une ligne par ÉPISODE avec les clés lues par
   load_gt/label_events/episode_level : {name, source, host, start, end, mitre}.
   (source = log_source ; host = host_name.)
3. CASSE HÔTE par source : auditd = 'asus-x415ja' (minuscule), auth/syslog =
   'ASUS-X415JA'. La clé de rareté est `host|token` -> la casse compte.
4. Le SCORING reste le tien : ce fichier ne score pas. Il écrit les logs bruts à
   FUSIONNER dans le dataset avant TON inference, puis tu lances evaluation.py.

Sorties
-------
- injected_events.jsonl : logs BRUTS forgés (à fusionner avant l'inference).
- groundtruth.jsonl      : fenêtres d'attaque (schéma evaluation.py) pour le label.

Rareté maximale (optionnel) : si NOVELTY_STATE_PATH pointe vers le
cnn_novelty_state.pkl gelé, les identifiants sont tirés ABSENTS du vocabulaire
d'entraînement (rarity=1, anomalie maximale dans l'espace du modèle).
"""

from __future__ import annotations

import base64
import json
import pickle
import random
from datetime import datetime, timedelta
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Paramètres
# ─────────────────────────────────────────────────────────────────────────────
HOST_BY_SOURCE = {                      # casse RÉELLE par source (cf. evaluation.py)
    "auth":   "ASUS-X415JA",
    "syslog": "ASUS-X415JA",
    "auditd": "asus-x415ja",
}
INJECT_START       = "2026-07-28T02:00:00+00:00"   # >>> règle après PROD_START
EVENTS_PATH        = "injected_events.jsonl"
GROUNDTRUTH_PATH   = "groundtruth_test.jsonl"
NOVELTY_STATE_PATH = None    # ex: "ML/models/production/current/cnn_novelty_state.pkl"
SEED               = 1337
SCENARIO_GAP_S     = 900     # écart entre scénarios (>> EPISODE_GAP_SECONDS)

RAW_COLUMNS = [
    "timestamp", "host_name", "log_source", "message", "user_name", "source_ip",
    "geo_country", "process_name", "process_executable", "process_args", "cmdline",
    "event_action", "event_outcome", "syscall", "process_pid", "parent_pid",
]

_USER_COUNTER = [0]          # compteur global invaliduser{k}


# ─────────────────────────────────────────────────────────────────────────────
# Utilitaires
# ─────────────────────────────────────────────────────────────────────────────
def _blank(ts: datetime, source: str) -> dict:
    e = {c: "" for c in RAW_COLUMNS}
    e["host_name"] = HOST_BY_SOURCE[source]
    e["log_source"] = source
    # Précision temporelle CONSTANTE (microsecondes) : sinon pd.to_datetime infère
    # un format unique et jette le reste en NaT à la featurisation.
    e["timestamp"] = ts.isoformat(timespec="microseconds")
    return e


def _next_invaliduser() -> str:
    _USER_COUNTER[0] += 1
    return f"invaliduser{_USER_COUNTER[0]}"


def _load_state(path):
    if not path:
        return {}
    try:
        with open(path, "rb") as f:
            return pickle.load(f)
    except FileNotFoundError:
        print(f"  [!] novelty_state introuvable ({path}) -> rareté intra-lot seule")
        return {}


def _novel(state: dict, key: str, prefix: str, host: str, rng: random.Random) -> str:
    seen = state.get(key, {})
    for _ in range(1000):
        cand = f"{prefix}{rng.randrange(10**6):06d}"
        if f"{host}|{cand}" not in seen:
            return cand
    return f"{prefix}{rng.randrange(10**9)}"


# ─────────────────────────────────────────────────────────────────────────────
# Scénarios — chacun renvoie (events, meta). meta.targets = features CNN ciblées.
# ─────────────────────────────────────────────────────────────────────────────
def gen_ssh_bruteforce(t0, rng, state):
    ip  = f"203.0.113.{rng.randint(2, 254)}"          # TEST-NET-3 -> externe garanti
    geo = rng.choice(["RU", "CN", "KP", "IR", "XX"])   # pays jamais vu
    host = HOST_BY_SOURCE["auth"]
    events, t = [], t0
    for _ in range(30):
        user = _next_invaliduser()                     # MARQUEUR + user_rarity haute
        e = _blank(t, "auth")
        e.update(process_name="sshd", event_action="ssh_login",
                 event_outcome="failure", source_ip=ip, geo_country=geo,
                 user_name=user,
                 message=f"Failed password for invalid user {user} from {ip} "
                         f"port {rng.randint(30000, 65000)} ssh2")
        events.append(e)
        t += timedelta(seconds=rng.uniform(0.4, 1.5))    # rafale -> inter_arrival ~0
    meta = dict(scenario="ssh_bruteforce", mitre="T1110.001",
                targets=["is_fail", "ip_is_external", "geo_rarity",
                         "user_rarity", "inter_arrival_log"])
    return events, meta


def gen_user_creation(t0, rng, state):
    host = HOST_BY_SOURCE["auditd"]
    ppid = str(rng.randint(20000, 60000))
    pid  = str(int(ppid) + rng.randint(1, 50))
    parent = _blank(t0, "auditd")                        # shell parent (résout la lignée)
    parent.update(process_name="bash", process_executable="/usr/bin/bash",
                  syscall="execve", event_action="executed", user_name="root",
                  process_pid=ppid, parent_pid=str(rng.randint(1000, 1999)),
                  process_args="bash", cmdline="bash")
    args = "/usr/sbin/useradd -m -o -u 0 -g root -s /bin/bash backdoor_svc"
    child = _blank(t0 + timedelta(seconds=1.2), "auditd")
    child.update(process_name="useradd", process_executable="/usr/sbin/useradd",
                 syscall="execve", event_action="executed", user_name="root",
                 process_pid=pid, parent_pid=ppid, process_args=args, cmdline=args)
    meta = dict(scenario="user_creation", mitre="T1136.001",
                targets=["proc_rarity", "exe_path_rarity", "parent_child_rarity",
                         "arg_count", "cmd_length_log"])
    return [parent, child], meta


def gen_b64_exec(t0, rng, state):
    host = HOST_BY_SOURCE["auditd"]
    blob = base64.b64encode(bytes(rng.randrange(256) for _ in range(120))).decode()
    args = f"bash -c echo {blob} | base64 -d | bash"
    ppid = str(rng.randint(20000, 60000)); pid = str(int(ppid) + 1)
    parent = _blank(t0, "auditd")
    parent.update(process_name="bash", process_executable="/usr/bin/bash",
                  syscall="execve", event_action="executed", user_name="www-data",
                  process_pid=ppid, parent_pid=str(rng.randint(1000, 1999)),
                  process_args="bash", cmdline="bash")
    child = _blank(t0 + timedelta(seconds=0.8), "auditd")
    child.update(process_name="bash", process_executable="/usr/bin/bash",
                 syscall="execve", event_action="executed", user_name="www-data",
                 process_pid=pid, parent_pid=ppid, process_args=args, cmdline=args)
    meta = dict(scenario="b64_exec", mitre="T1059.004",
                targets=["cmd_entropy", "cmd_length_log", "arg_count",
                         "parent_child_rarity"])
    return [parent, child], meta


def gen_reverse_shell(t0, rng, state):
    host = HOST_BY_SOURCE["auditd"]
    ip  = f"203.0.113.{rng.randint(2, 254)}"
    exe = f"/tmp/.{_novel(state, 'exe', 'x', host, rng)}"   # binaire jamais vu
    parent = _blank(t0, "auditd")
    parent.update(process_name="bash", process_executable="/usr/bin/bash",
                  syscall="execve", event_action="executed", user_name="www-data",
                  process_pid="40001", parent_pid="1200",
                  process_args="bash", cmdline="bash")
    child = _blank(t0 + timedelta(seconds=0.6), "auditd")
    child.update(process_name=exe.rsplit("/", 1)[-1], process_executable=exe,
                 syscall="connect", event_action="connected", user_name="www-data",
                 source_ip=ip, process_pid="40002", parent_pid="40001",
                 process_args=exe, cmdline=exe)
    meta = dict(scenario="reverse_shell", mitre="T1059.004",
                targets=["syscall_rarity", "exe_path_rarity", "ip_is_external",
                         "parent_child_rarity"])
    return [parent, child], meta


def gen_novel_binary(t0, rng, state):
    host = HOST_BY_SOURCE["auditd"]
    name = _novel(state, "proc", "kworker_", host, rng)     # proc jamais vu
    exe  = f"/tmp/.cache/{name}"
    e = _blank(t0, "auditd")
    e.update(process_name=name, process_executable=exe, syscall="execve",
             event_action="executed", user_name="nobody",
             process_pid="50010", parent_pid="1",
             process_args=f"{exe} --donate 0 -o pool.evil.example:3333", cmdline=exe)
    meta = dict(scenario="novel_binary", mitre="T1204.002",
                targets=["proc_rarity", "exe_path_rarity", "cmd_length_log",
                         "arg_count"])
    return [e], meta


SCENARIOS = [
    (gen_ssh_bruteforce, 2),
    (gen_user_creation,  2),
    (gen_b64_exec,       1),
    (gen_reverse_shell,  1),
    (gen_novel_binary,   1),
]


# ─────────────────────────────────────────────────────────────────────────────
# Orchestration
# ─────────────────────────────────────────────────────────────────────────────
def build():
    rng = random.Random(SEED)
    _USER_COUNTER[0] = 0
    state = _load_state(NOVELTY_STATE_PATH)
    t = datetime.fromisoformat(INJECT_START)
    events_out, gt_out, counters = [], [], {}

    for gen, n in SCENARIOS:
        for _ in range(n):
            events, meta = gen(t, rng, state)
            scen = meta["scenario"]
            counters[scen] = counters.get(scen, 0) + 1
            name = f"{scen}_{counters[scen]:02d}"
            stamps = [e["timestamp"] for e in events]
            for j, e in enumerate(events):
                e.update(inj_id=f"{name}_{j:03d}", episode=name,
                         scenario=scen, mitre=meta["mitre"], is_injected=1)
                events_out.append(e)
            # fenêtre GT au SCHÉMA de evaluation.py (source/host/start/end/name)
            gt_out.append(dict(
                name=name, source=events[0]["log_source"],
                host=events[0]["host_name"], mitre=meta["mitre"],
                start=min(stamps), end=max(stamps),
                targets=meta["targets"]))
            last = max(datetime.fromisoformat(s) for s in stamps)
            t = last + timedelta(seconds=SCENARIO_GAP_S)

    with open(EVENTS_PATH, "w") as f:
        for e in events_out:
            f.write(json.dumps(e) + "\n")
    with open(GROUNDTRUTH_PATH, "w") as f:
        for g in gt_out:
            f.write(json.dumps(g) + "\n")

    print("=" * 66)
    print("  INJECTION FORGÉE — cohérente features CNN + compatible evaluation.py")
    print("=" * 66)
    print(f"  fenêtre : {gt_out[0]['start']} -> {gt_out[-1]['end']}")
    print(f"  events  : {len(events_out)} bruts  |  épisodes : {len(gt_out)}")
    for g in gt_out:
        print(f"    {g['name']:18s} [{g['mitre']:10s}] {g['source']:6s} "
              f"@ {g['host']} | cible: {', '.join(g['targets'])}")
    print(f"\n  -> {EVENTS_PATH} (à fusionner avant l'inference)")
    print(f"  -> {GROUNDTRUTH_PATH} (fenêtres, schéma evaluation.py)")
    print("=" * 66)
    return events_out, gt_out


def merge_injected(dataset_df):
    """À appeler AVANT ton inference : ajoute les events forgés au dataset et
    uniformise le timestamp (sinon _add_time en jette en NaT). Retourne le df
    augmenté, trié chronologiquement."""
    import pandas as pd
    inj = [json.loads(l) for l in Path(EVENTS_PATH).read_text().splitlines() if l.strip()]
    inj_df = pd.DataFrame([{c: r.get(c, "") for c in RAW_COLUMNS} for r in inj])
    inj_df = inj_df.reindex(columns=list(dataset_df.columns), fill_value="")
    merged = pd.concat([dataset_df, inj_df], ignore_index=True)
    dt = pd.to_datetime(merged["timestamp"], utc=True, format="mixed", errors="coerce")
    merged["timestamp"] = dt.dt.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")
    return merged.sort_values("timestamp").reset_index(drop=True)


if __name__ == "__main__":
    build()