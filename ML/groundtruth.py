"""
regen_groundtruth_full.py
Dérive les fenêtres d'attaque depuis les vrais patterns dans ES.
Couvre tous les types : brute_force_ssh, brute_force_sudo,
credential_dumping, defense_evasion, persistence_cron,
port_scan, initial_access_ssh, privilege_escalation.
"""
import json
from datetime import timedelta
import pandas as pd
from autoencodeur import make_es_client, es_request, ES_INDEX_TRAIN

# --- Paramètres globaux ---
GAP_MIN   = 5    # minutes max entre deux events pour rester dans la même rafale
PAD_SEC   = 300   # marge avant/après chaque fenêtre
MIN_EVENTS = 3   # minimum d'events pour qualifier une rafale




def fetch(query, fields, max_docs=5000):
    """Récupère les docs ES sans scroll (plus robuste pour petits volumes)."""
    ctx, headers = make_es_client()
    q = {
        "size": max_docs,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": query,
        "_source": ["@timestamp", "host.name"] + fields,
    }
    try:
        r = es_request(f"/{ES_INDEX_TRAIN}/_search", q, ctx=ctx, headers=headers)
    except Exception as e:
        print(f"    ERREUR fetch: {e}")
        return pd.DataFrame(columns=["ts", "host"])

    rows = []
    for h in r.get("hits", {}).get("hits", []):
        s = h["_source"]
        row = {
            "ts":   pd.to_datetime(s.get("@timestamp"), utc=True),
            "host": (s.get("host") or {}).get("name", "ASUS-X415JA"),
        }
        for f in fields:
            parts = f.split(".")
            val = s
            for p in parts:
                val = (val or {}).get(p)
            row[f.replace(".", "_")] = val
        rows.append(row)

    if not rows:
        return pd.DataFrame(columns=["ts", "host"])

    return pd.DataFrame(rows).sort_values("ts").reset_index(drop=True)



def build_windows(df, attack_type, min_events=MIN_EVENTS):
    """Groupe les events en rafales et renvoie les fenêtres."""
    wins = []
    if df.empty:
        return wins
    gap   = timedelta(minutes=GAP_MIN)
    pad   = timedelta(seconds=PAD_SEC)
    start = prev = df.iloc[0]["ts"]
    host  = df.iloc[0]["host"]
    count = 1

    for i in range(1, len(df)):
        t = df.iloc[i]["ts"]
        if t - prev <= gap:
            count += 1
            prev = t
        else:
            if count >= min_events:
                wins.append({
                    "start":       (start - pad).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "end":         (prev  + pad).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "attack_type": attack_type,
                    "host":        host,
                    "description": f"{attack_type} — {count} events détectés",
                })
            start = prev = t
            host  = df.iloc[i]["host"]
            count = 1

    if count >= min_events:
        wins.append({
            "start":       (start - pad).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end":         (prev  + pad).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "attack_type": attack_type,
            "host":        host,
            "description": f"{attack_type} — {count} events détectés",
        })
    return wins


# =============================================================================
# Détecteurs par type d'attaque
# =============================================================================

def detect_brute_force_ssh():
    q = {"bool": {
        "filter": [{"term": {"ml.log_source": "auth"}}],  # sans .keyword
        "should": [
            {"match_phrase": {"message": "Failed password"}},
            {"match_phrase": {"message": "Invalid user"}},
            {"match_phrase": {"message": "authentication failure"}},
        ], "minimum_should_match": 1
    }}
    df = fetch(q, ["message"])
    wins = build_windows(df, "brute_force_ssh", min_events=5)
    print(f"  brute_force_ssh      : {len(df):5,} échecs -> {len(wins)} fenêtres")
    return wins


def detect_brute_force_sudo():
    # Cherche séparément sudo + échec
    q = {"bool": {
        "filter": [{"term": {"ml.log_source": "auth"}}],
        "should": [
            {"match_phrase": {"message": "incorrect password attempt"}},
            {"match_phrase": {"message": "3 incorrect password attempts"}},
            {"bool": {"must": [
                {"match_phrase": {"message": "sudo"}},
                {"match_phrase": {"message": "authentication failure"}}
            ]}},
        ], "minimum_should_match": 1
    }}
    df = fetch(q, ["message"])
    wins = build_windows(df, "brute_force_sudo", min_events=3)
    print(f"  brute_force_sudo     : {len(df):5,} events -> {len(wins)} fenêtres")
    return wins


def detect_initial_access_ssh():
    """SSH réussi hors-horaires APRÈS des échecs = vrai accès suspect."""
    q = {"bool": {
        "filter": [{"term": {"ml.log_source": "auth"}}],
        "should": [
            {"match_phrase": {"message": "Accepted password"}},
            {"match_phrase": {"message": "Accepted publickey"}},
        ], "minimum_should_match": 1
    }}
    df = fetch(q, ["message"])
    if not df.empty:
        df["hour"] = df["ts"].dt.hour
        df["dow"]  = df["ts"].dt.dayofweek
        # Nuit profonde uniquement (0h-6h) ET pas weekend (trop de bruit)
        mask = ((df["hour"] < 6) & (df["dow"] < 5))
        df = df[mask].reset_index(drop=True)
    # Rafales de ≥2 connexions réussies en 5min = vrai accès, pas une session normale
    wins = build_windows(df, "initial_access_ssh", min_events=2)
    print(f"  initial_access_ssh   : {len(df):5,} succès nuit -> "
          f"{len(wins)} fenêtres")
    return wins


def detect_credential_dumping():
    """Accès aux fichiers de credentials, détecté par le NOM DU FICHIER
    (observable), pas par le verdict ml.aud_credential_access."""
    q = {"bool": {
        "filter": [{"term": {"ml.log_source": "auditd"}}],
        "should": [
            {"match_phrase": {"message": "/etc/shadow"}},
            {"match_phrase": {"message": "/etc/gshadow"}},
            {"match_phrase": {"message": "/.ssh/id_rsa"}},
            {"match_phrase": {"message": "/.ssh/id_ed25519"}},
            {"match_phrase": {"message": ".aws/credentials"}},
            {"match_phrase": {"message": "/proc/"}},  # avec memdump
            {"match_phrase": {"process.name": "mimikatz"}},
            {"match_phrase": {"process.name": "pypykatz"}},
        ],
        "minimum_should_match": 1,
        "must_not": [
            # Exclure les lectures système normales
            {"match_phrase": {"process.name": "pam_unix"}},
            {"match_phrase": {"process.name": "sshd"}},  # sshd lit id_rsa légitimement
        ]
    }}
    df = fetch(q, ["message", "process.name"])
    wins = build_windows(df, "credential_dumping", min_events=1)
    print(f"  credential_dumping   : {len(df):5,} events -> {len(wins)} fenêtres")
    return wins

def detect_defense_evasion():
    """
    Cherche directement dans les messages plutôt que sur les features ML
    (plus fiable si les features sont à 0 dans les données historiques).
    """
    q = {"bool": {
        "should": [
            # Suppression de logs via auditd
            {"bool": {"filter": [
                {"term": {"ml.log_source": "auditd"}},
                {"bool": {"should": [
                    {"match_phrase": {"message": "auth.log"}},
                    {"match_phrase": {"message": "/var/log"}},
                    {"match_phrase": {"message": "wtmp"}},
                    {"match_phrase": {"message": "btmp"}},
                ], "minimum_should_match": 1}},
                {"bool": {"should": [
                    {"term": {"auditd.data.syscall": "unlink"}},
                    {"term": {"auditd.data.syscall": "truncate"}},
                    {"term": {"auditd.data.syscall": "rename"}},
                ], "minimum_should_match": 1}}
            ]}},
            # history -c ou HISTFILE dans auditd
            {"bool": {"filter": [
                {"term": {"ml.log_source": "auditd"}},
                {"bool": {"should": [
                    {"match_phrase": {"message": "HISTFILE"}},
                    {"match_phrase": {"message": "history -c"}},
                    {"match_phrase": {"message": "unset HIST"}},
                ], "minimum_should_match": 1}}
            ]}},
            # kill auditd/rsyslog depuis syslog
            {"bool": {"filter": [
                {"term": {"ml.log_source": "syslog"}},
                {"bool": {"should": [
                    {"match_phrase": {"message": "rsyslog"}},
                    {"match_phrase": {"message": "auditd"}},
                ], "minimum_should_match": 1}},
                {"bool": {"should": [
                    {"match_phrase": {"message": "stopped"}},
                    {"match_phrase": {"message": "killed"}},
                    {"match_phrase": {"message": "failed"}},
                ], "minimum_should_match": 1}}
            ]}},
        ], "minimum_should_match": 1
    }}
    df = fetch(q, ["message"])
    wins = build_windows(df, "defense_evasion", min_events=1)
    print(f"  defense_evasion      : {len(df):5,} events -> {len(wins)} fenêtres")
    return wins


def detect_persistence_cron():
    """Cron suspect = création/modification uniquement, pas exécution normale."""
    q = {"bool": {
        "filter": [{"term": {"ml.log_source": "syslog"}}],
        "should": [
            {"match_phrase": {"message": "new job"}},
            {"match_phrase": {"message": "crontab"}},
            {"bool": {"must": [
                {"match_phrase": {"message": "systemd"}},
                {"match_phrase": {"message": "created symlink"}}
            ]}},
        ], "minimum_should_match": 1,
        "must_not": [
            {"match_phrase": {"message": "CMD ("}},
            {"match_phrase": {"message": "session opened for user"}},
            {"match_phrase": {"message": "session closed for user"}},
            {"match_phrase": {"message": "pam_unix(cron"}},
            {"match_phrase": {"message": "CRON["}},
        ]
    }}
    df = fetch(q, ["message"])

    # Affiche quelques messages pour diagnostic
    if not df.empty and "message" in df.columns:
        print(f"    Exemples persistence_cron :")
        for msg in df["message"].dropna().head(5):
            print(f"      {str(msg)[:100]}")

    wins = build_windows(df, "persistence_cron", min_events=1)
    print(f"  persistence_cron     : {len(df):5,} events -> {len(wins)} fenêtres")
    return wins




def detect_port_scan():
    """Un scan = beaucoup d'events réseau différents en peu de temps,
    indépendamment des règles Logstash."""
    q = {"bool": {
        "filter": [{"term": {"ml.log_source": "auditd"}}],
        "should": [
            # Process classiques de scan, détectés par leur NOM, pas par un flag
            {"match_phrase": {"process.name": "nmap"}},
            {"match_phrase": {"process.name": "masscan"}},
            {"match_phrase": {"process.name": "zmap"}},
            {"match_phrase": {"process.name": "rustscan"}},
            {"match_phrase": {"process.name": "nc"}},
            # Ou : exécutable nmap dans args
            {"match_phrase": {"message": "nmap"}},
        ],
        "minimum_should_match": 1
    }}
    df = fetch(q, ["message", "process.name"])
    wins = build_windows(df, "port_scan", min_events=3)
    print(f"  port_scan            : {len(df):5,} events -> {len(wins)} fenêtres")
    return wins


def detect_privilege_escalation():
    """Escalade détectée par les actions observables : chmod suid, exécution
    de binaires GTFOBins, sudo réussi par un user normal."""
    q = {"bool": {"should": [
        # SUID/SGID bit ajouté (texte brut, pas le flag Logstash)
        {"bool": {
            "filter": [{"term": {"ml.log_source": "auditd"}}],
            "must": [
                {"bool": {"should": [
                    {"match_phrase": {"process.name": "chmod"}},
                    {"match_phrase": {"message": "chmod"}},
                ], "minimum_should_match": 1}},
                {"bool": {"should": [
                    {"match_phrase": {"message": "u+s"}},
                    {"match_phrase": {"message": "4755"}},
                    {"match_phrase": {"message": "4777"}},
                    {"match_phrase": {"message": "g+s"}},
                ], "minimum_should_match": 1}},
            ]
        }},
        # LD_PRELOAD set
        {"bool": {"filter": [
            {"term": {"ml.log_source": "auditd"}},
            {"match_phrase": {"message": "LD_PRELOAD"}}
        ]}},
        # Binaires GTFOBins lancés par non-root (escalade classique)
        {"bool": {"filter": [
            {"term": {"ml.log_source": "auditd"}},
            {"bool": {"should": [
                {"match_phrase": {"process.name": "pkexec"}},
                {"match_phrase": {"process.name": "doas"}},
            ], "minimum_should_match": 1}}
        ]}},
    ], "minimum_should_match": 1}}
    df = fetch(q, ["message", "process.name"])
    wins = build_windows(df, "privilege_escalation", min_events=1)
    print(f"  privilege_escalation : {len(df):5,} events -> {len(wins)} fenêtres")
    return wins


def detect_data_exfiltration():
    """curl/wget vers IP externe depuis syslog."""
    q = {"bool": {
        "filter": [{"term": {"ml.log_source": "syslog"}}],
        "should": [
            {"match_phrase": {"message": "curl"}},
            {"match_phrase": {"message": "wget"}},
        ], "minimum_should_match": 1,
        "must_not": [
            {"match_phrase": {"message": "apt"}},
            {"match_phrase": {"message": "update"}},
            {"match_phrase": {"message": "upgrade"}},
        ]
    }}
    df = fetch(q, ["message"])
    if not df.empty:
        df["hour"] = df["ts"].dt.hour
        mask = (df["hour"] < 7) | (df["hour"] > 21)
        df = df[mask].reset_index(drop=True)
    wins = build_windows(df, "data_exfiltration", min_events=1)
    print(f"  data_exfiltration    : {len(df):5,} events -> {len(wins)} fenêtres")
    return wins


# def detect_privilege_escalation_syslog():
#     """sudo + su dans syslog hors heures ouvrables."""
#     q = {"bool": {
#         "filter": [{"term": {"ml.log_source": "syslog"}}],
#         "should": [
#             {"match_phrase": {"message": "sudo"}},
#             {"match_phrase": {"message": "su root"}},
#             {"match_phrase": {"message": "COMMAND"}},
#         ], "minimum_should_match": 1,
#         "must_not": [{"match_phrase": {"message": "session"}}]
#     }}
#     df = fetch(q, ["message"])
#     if not df.empty:
#         df["hour"] = df["ts"].dt.hour
#         mask = (df["hour"] < 7) | (df["hour"] > 21)
#         df = df[mask].reset_index(drop=True)
#     wins = build_windows(df, "privilege_escalation", min_events=2)
#     print(f"  privilege_esc syslog : {len(df):5,} events -> {len(wins)} fenêtres")
#     return wins


# =============================================================================
# MAIN
# =============================================================================

def main():
    print("=== Génération groundtruth depuis patterns réels ES ===\n")

    all_wins = []
    all_wins += detect_brute_force_ssh()
    all_wins += detect_brute_force_sudo()
    all_wins += detect_initial_access_ssh()
    all_wins += detect_credential_dumping()
    all_wins += detect_defense_evasion()
    all_wins += detect_persistence_cron()
    all_wins += detect_port_scan()
    all_wins += detect_privilege_escalation()

    # Trie par date de début
    all_wins.sort(key=lambda w: w["start"])

    output = "groundtruth.jsonl"
    with open(output, "w") as f:
        for w in all_wins:
            f.write(json.dumps(w) + "\n")

    print(f"\n=== {len(all_wins)} fenêtres totales -> {output} ===")
    print("\nRécapitulatif par type :")
    from collections import Counter
    counts = Counter(w["attack_type"] for w in all_wins)
    for atk, n in sorted(counts.items()):
        print(f"  {atk:25s} : {n}")

    # Aperçu des 5 premières
    print("\nPremières fenêtres :")
    for w in all_wins[:5]:
        print(f"  {w['attack_type']:25s} | {w['start']} -> {w['end']}")


if __name__ == "__main__":
    main()