# inject_normal_logs.py
"""
Génère des logs normaux réalistes et les injecte dans Elasticsearch.
Simule une journée de travail typique : logins SSH, commandes système banales.
"""

import json, ssl, urllib.request, base64, random, time
from datetime import datetime, timezone, timedelta
import numpy as np

ES_HOST  = "https://localhost:9200"
ES_USER  = "elastic"
ES_PASS  = "pfe2026"
ES_INDEX = "filebeat-logs-injected"

np.random.seed(42)
random.seed(42)

NORMAL_USERS  = ["alice", "bob", "charlie", "david", "emma"]
NORMAL_HOSTS  = ["srv-web-01", "srv-db-01", "srv-app-02"]
KNOWN_IPS     = ["192.168.1.10", "192.168.1.20", "10.0.0.5", "10.0.0.12"]
KNOWN_COUNTRIES = ["TN", "FR"]

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

def random_business_time(base_date=None):
    """Génère un timestamp en heures ouvrables (9h-17h, lundi-vendredi)."""
    if base_date is None:
        base_date = datetime.now(timezone.utc)
    # Trouver un lundi-vendredi
    while base_date.weekday() >= 5:
        base_date -= timedelta(days=1)
    hour   = random.randint(9, 17)
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    return base_date.replace(hour=hour, minute=minute,
                              second=second, microsecond=0)

# ── Générateurs de logs normaux par source ──────────────────────────────────

def gen_auth_normal(n=200):
    """Logins SSH normaux : utilisateurs connus, IPs internes, heures ouvrables."""
    logs = []
    for _ in range(n):
        user  = random.choice(NORMAL_USERS)
        ip    = random.choice(KNOWN_IPS)
        host  = random.choice(NORMAL_HOSTS)
        ts    = random_business_time()

        # Simuler un login SSH réussi
        logs.append({
            "@timestamp": ts.isoformat(),
            "message": f"Accepted password for {user} from {ip} port "
                       f"{random.randint(40000,60000)} ssh2",
            "event":   {"dataset": "system.auth", "outcome": "success"},
            "agent":   {"type": "filebeat"},
            "process": {"name": "sshd"},
            "user":    {"name": user},
            "source":  {"ip": ip, "address": ip},
            "host":    {"name": host},
            # Features ML pré-calculées
            "ml": {
                "log_source":           "auth",
                "hour_of_day":          ts.hour,
                "day_of_week":          ts.weekday() + 1,
                "is_off_hours":         0,
                "is_night":             0,
                "is_weekend":           0,
                "is_business":          1,
                "is_normal_candidate":  1,
                "normal_reject_reason": "none",
                "composite_score":      0,
                "auth_is_brute_force":  0,
                "auth_fail_count_5m":   random.randint(0, 1),
                "auth_fail_ratio":      round(random.uniform(0, 0.1), 3),
                "auth_ip_is_external":  0,
                "auth_known_country":   1,
                "ground_truth":         0,
            }
        })

        # Parfois ajouter une session close après quelques minutes
        if random.random() < 0.7:
            ts_close = ts + timedelta(minutes=random.randint(5, 120))
            logs.append({
                "@timestamp": ts_close.isoformat(),
                "message": f"pam_unix(sshd:session): session closed for user {user}",
                "event":   {"dataset": "system.auth", "outcome": "success"},
                "agent":   {"type": "filebeat"},
                "process": {"name": "sshd"},
                "user":    {"name": user},
                "host":    {"name": host},
                "ml": {
                    "log_source":          "auth",
                    "is_normal_candidate": 1,
                    "composite_score":     0,
                    "ground_truth":        0,
                }
            })
    return logs

def gen_syslog_normal(n=2000):
    """Syslogs normaux : cron, systemd, dhcp."""
    logs = []
    normal_messages = [
        ("cron",    "CRON[{pid}]: ({user}) CMD (/usr/bin/backup.sh)"),
        ("systemd", "Started Daily apt download activities."),
        ("systemd", "Reached target Multi-User System."),
        ("kernel",  "NET: Registered PF_INET6 protocol family"),
        ("dhclient","DHCPREQUEST on eth0 to 255.255.255.255 port 67"),
        ("NetworkManager", "device (eth0): state change: activated"),
        ("cron",    "CRON[{pid}]: ({user}) CMD (run-parts /etc/cron.daily)"),
    ]
    for _ in range(n):
        prog, msg_tmpl = random.choice(normal_messages)
        user = random.choice(NORMAL_USERS)
        pid  = random.randint(1000, 9999)
        host = random.choice(NORMAL_HOSTS)
        ts   = random_business_time()
        msg  = msg_tmpl.format(pid=pid, user=user)

        logs.append({
            "@timestamp": ts.isoformat(),
            "message":    msg,
            "event":      {"dataset": "system.syslog"},
            "agent":      {"type": "filebeat"},
            "process":    {"name": prog, "pid": pid},
            "host":       {"name": host},
            "ml": {
                "log_source":           "syslog",
                "hour_of_day":          ts.hour,
                "day_of_week":          ts.weekday() + 1,
                "is_off_hours":         0,
                "is_night":             0,
                "is_weekend":           0,
                "is_business":          1,
                "is_normal_candidate":  1,
                "normal_reject_reason": "none",
                "composite_score":      0,
                "sys_module_load":      0,
                "sys_log_tamper":       0,
                "sys_oom_kill":         0,
                "ground_truth":         0,
            }
        })
    return logs

def gen_auditd_normal(n=20000):
    """Auditd normaux : ls, cat, vim, scripts de backup."""
    normal_cmds = [
        ("/bin/ls",   ["-la", "/home"]),
        ("/bin/cat",  ["/etc/hostname"]),
        ("/usr/bin/vim", ["/etc/hosts"]),
        ("/bin/bash", ["/usr/local/bin/backup.sh"]),
        ("/usr/bin/python3", ["/opt/app/monitor.py"]),
        ("/bin/cp",   ["/var/log/app.log", "/backup/"]),
        ("/usr/bin/grep", ["-r", "ERROR", "/var/log/"]),
        ("/bin/systemctl", ["status", "nginx"]),
    ]
    logs = []
    for _ in range(n):
        exe, args = random.choice(normal_cmds)
        user = random.choice(NORMAL_USERS)
        host = random.choice(NORMAL_HOSTS)
        ts   = random_business_time()
        cmd  = exe + " " + " ".join(args)

        # Entropie faible pour les commandes normales
        entropy = round(random.uniform(2.0, 3.5), 4)

        logs.append({
            "@timestamp": ts.isoformat(),
            "message":    f"syscall=execve exe={exe} args={' '.join(args)}",
            "event":      {"dataset": "auditd.log", "outcome": "success"},
            "agent":      {"type": "auditbeat"},
            "process":    {"executable": exe, "args": args},
            "user":       {"name": user},
            "host":       {"name": host},
            "auditd":     {"data": {"syscall": "execve", "key": "exec"}},
            "ml": {
                "log_source":            "auditd",
                "hour_of_day":           ts.hour,
                "day_of_week":           ts.weekday() + 1,
                "is_off_hours":          0,
                "is_night":              0,
                "is_weekend":            0,
                "is_business":           1,
                "is_normal_candidate":   1,
                "normal_reject_reason":  "none",
                "composite_score":       0,
                "aud_cmd_entropy":       entropy,
                "aud_cmd_is_obfuscated": 0,
                "aud_reverse_shell":     0,
                "aud_credential_access": 0,
                "aud_process_injection": 0,
                "ground_truth":          0,
            }
        })
    return logs

# ── MAIN ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ctx, headers = make_es_client()

    print("Génération logs normaux...")
    all_logs = (
        gen_auth_normal(200) +
        gen_syslog_normal(200) +
        gen_auditd_normal(20000)
    )
    random.shuffle(all_logs)

    # Injection par batch de 100
    batch_size = 100
    total = 0
    for i in range(0, len(all_logs), batch_size):
        batch = all_logs[i:i+batch_size]
        es_bulk(batch, ctx, headers)
        total += len(batch)
        print(f"  {total}/{len(all_logs)} injectés")

    print(f"\nTerminé : {total} logs normaux dans {ES_INDEX}")
    print("ground_truth=0 pour tous → entraînement propre garanti")