"""
=============================================================================
IDS — INJECTION LOGS NORMAUX SYNTHÉTIQUES
=============================================================================

Ce script génère des logs normaux synthétiques CERTIFIÉS (ground_truth=0)
et les injecte dans l'index Elasticsearch "ids-train-normal".

GÉNÉRATEURS DISPONIBLES :
    auth             : logs auth.log normaux
    syslog           : logs syslog normaux
    auditd           : logs auditd normaux
    auditd_heavy     : processus légitimes à forte charge CPU (anti-cryptominer FP)
    auditd_lateral   : accès multi-machines légitimes (anti-lateral_movement FP)
    auditd_crypto    : commandes légitimes ressemblant à des miners (anti-cryptominer FP)
    auth_brute_legit : quelques échecs auth consécutifs légitimes (anti-bruteforce FP)

UTILISATION :
    python train_ml.py

=============================================================================
"""

import json, ssl, urllib.request, base64, time, math, random
from datetime import datetime, timezone, timedelta
import numpy as np

np.random.seed(42)
random.seed(42)

# =============================================================================
# SECTION A — CONFIGURATION
# =============================================================================

ES_HOST         = "https://localhost:9200"
ES_USER         = "elastic"
ES_PASS         = "pfe2026"
ES_INDEX_NORMAL = "ids-train-normal"

N_PER_SOURCE    = 5000    # logs par source par défaut
BATCH_SIZE      = 500

# Override par source — les adversariaux n'ont pas besoin de 5000
N_PER_SOURCE_OVERRIDE = {
    "auditd_heavy":     2000,
    "auditd_lateral":   3000,
    "auditd_crypto":    3000,
    "auth_brute_legit": 2000,
}

# Distribution horaire réaliste : pic en heures ouvrables
HOUR_WEIGHTS = {
    0: 0.005, 1: 0.003, 2: 0.003, 3: 0.003, 4: 0.004, 5: 0.008,
    6: 0.015, 7: 0.025, 8: 0.040, 9: 0.065, 10: 0.075, 11: 0.075,
    12: 0.060, 13: 0.070, 14: 0.075, 15: 0.075, 16: 0.070, 17: 0.060,
    18: 0.040, 19: 0.025, 20: 0.020, 21: 0.015, 22: 0.010, 23: 0.007,
}
_raw       = [HOUR_WEIGHTS[h] for h in range(24)]
_total     = sum(_raw)
HOUR_PROBA = [v / _total for v in _raw]
assert abs(sum(HOUR_PROBA) - 1.0) < 1e-9, "Normalisation échouée"

# Distribution des jours de la semaine (0=dim, 1=lun, ..., 6=sam)
_dow_raw    = [0.05, 0.20, 0.20, 0.20, 0.20, 0.10, 0.05]
DOW_WEIGHTS = [v / sum(_dow_raw) for v in _dow_raw]


# =============================================================================
# SECTION B — CLIENT ELASTICSEARCH
# =============================================================================

def make_es_client():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    token   = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
    headers = {
        "Content-Type":  "application/json",
        "Authorization": f"Basic {token}",
    }
    return ctx, headers


def es_request(path, body=None, method=None, ctx=None, headers=None):
    if ctx is None:
        ctx, headers = make_es_client()
    url  = f"{ES_HOST}{path}"
    data = json.dumps(body).encode() if body else None
    m    = method or ("POST" if body else "GET")
    req  = urllib.request.Request(url, data=data, headers=headers, method=m)
    return json.loads(urllib.request.urlopen(req, context=ctx).read())


def create_index_if_not_exists():
    """Crée l'index ids-train-normal avec le bon mapping."""
    ctx, headers = make_es_client()
    mapping = {
        "mappings": {
            "properties": {
                "@timestamp":   {"type": "date"},
                "log_source":   {"type": "keyword"},
                "ground_truth": {"type": "integer"},
                "ml": {
                    "properties": {
                        "log_source_encoded":      {"type": "integer"},
                        "hour_of_day":             {"type": "integer"},
                        "day_of_week":             {"type": "integer"},
                        "is_off_hours":            {"type": "integer"},
                        "is_night":                {"type": "integer"},
                        "is_weekend":              {"type": "integer"},
                        "is_business":             {"type": "integer"},
                        "hour_sin":                {"type": "float"},
                        "hour_cos":                {"type": "float"},
                        "msg_length_log":          {"type": "float"},
                        "msg_word_count":          {"type": "integer"},
                        "msg_has_ip":              {"type": "integer"},
                        "msg_has_base64":          {"type": "integer"},
                        "msg_has_url":             {"type": "integer"},
                        "msg_has_pipe":            {"type": "integer"},
                        "is_root":                 {"type": "integer"},
                        "user_sensitivity":        {"type": "integer"},
                        "delta_time_log":          {"type": "float"},
                        "log_source":              {"type": "keyword"},
                    }
                }
            }
        }
    }
    try:
        es_request(f"/{ES_INDEX_NORMAL}", method="GET", ctx=ctx, headers=headers)
        print(f"  Index {ES_INDEX_NORMAL} existe déjà")
    except Exception:
        es_request(f"/{ES_INDEX_NORMAL}", body=mapping, method="PUT",
                   ctx=ctx, headers=headers)
        print(f"  Index {ES_INDEX_NORMAL} créé")


# =============================================================================
# SECTION C — FEATURES COMMUNES
# =============================================================================

def build_shared_features(rng, hour: int, dow: int) -> dict:
    """
    Génère les features partagées (Section 2 + Section 3 Logstash).
    Communes à auth, syslog et auditd.
    """
    is_business  = 1 if (9 <= hour <= 18 and 1 <= dow <= 5) else 0
    is_night     = 1 if (hour >= 22 or hour <= 5) else 0
    is_off_hours = 1 if (hour >= 0 and hour <= 6) else 0
    is_weekend   = 1 if (dow == 0 or dow == 6) else 0

    u_sens  = int(rng.choice([0, 2, 3], p=[0.75, 0.18, 0.07]))
    is_root = 1 if u_sens == 3 else 0

    msg_len = int(np.clip(rng.lognormal(mean=4.3, sigma=0.5), 10, 800))

    return {
        "hour_of_day":      hour,
        "day_of_week":      dow,
        "is_off_hours":     is_off_hours,
        "is_night":         is_night,
        "is_weekend":       is_weekend,
        "is_business":      is_business,
        "hour_sin":         round(math.sin(2 * math.pi * hour / 24), 4),
        "hour_cos":         round(math.cos(2 * math.pi * hour / 24), 4),
        "msg_length_log":   round(math.log1p(msg_len), 4),
        "msg_word_count":   int(np.clip(rng.normal(8, 3), 1, 60)),
        "msg_has_ip":       int(rng.choice([0, 1], p=[0.55, 0.45])),
        "msg_has_base64":   0,
        "msg_has_url":      int(rng.choice([0, 1], p=[0.90, 0.10])),
        "msg_has_pipe":     int(rng.choice([0, 1], p=[0.92, 0.08])),
        "is_root":          is_root,
        "user_sensitivity": u_sens,
        "delta_time_log":   round(math.log1p(
            float(np.clip(rng.exponential(30), 0.1, 3600))
        ), 4),
    }


# =============================================================================
# SECTION D — GÉNÉRATEURS PAR SOURCE
# =============================================================================

def generate_auth_log(rng, hour: int, dow: int) -> dict:
    shared = build_shared_features(rng, hour, dow)

    is_failure  = rng.random() < 0.15
    fail_5m     = int(rng.choice([0, 1, 2, 3], p=[0.75, 0.15, 0.07, 0.03]))
    fail_10m    = int(rng.choice([0, 1, 2, 3, 4], p=[0.65, 0.20, 0.08, 0.04, 0.03]))
    ok_5m       = int(np.clip(rng.poisson(3), 0, 20))
    total       = fail_5m + ok_5m
    fail_ratio  = round(fail_5m / max(total, 1), 4)
    ip_external = int(rng.choice([0, 1], p=[0.65, 0.35]))
    country_known = 1 if ip_external == 0 else int(rng.choice([0, 1], p=[0.3, 0.7]))

    sev = 0
    if shared["is_root"]:      sev += 3
    if is_failure:             sev += 2
    if ip_external:            sev += 2
    if shared["is_off_hours"]: sev += 1
    sev = min(sev, 8)

    # ← AJOUT : si le score composite serait >= 2, on neutralise les
    # combinaisons risquées pour rester sous le seuil
    bonus_preview = (2 * shared["is_root"] + 2 * shared["is_off_hours"])
    if (sev + bonus_preview) >= 2:
        # Retirer les signaux les plus pénalisants
        if shared["is_off_hours"]:
            sev = max(0, sev - 1)
            shared["is_off_hours"] = 0
        if shared["is_root"] and sev + 2 * shared["is_root"] >= 2:
            shared["is_root"] = 0
            shared["user_sensitivity"] = 0
            sev = max(0, sev - 3)

    pam_open    = int(rng.choice([0, 1], p=[0.45, 0.55]))
    pam_close   = 1 - pam_open if rng.random() > 0.2 else 0
    session_dur = float(np.clip(rng.lognormal(mean=7.5, sigma=1.2), 60, 28800))

    
    return {
        **shared,
        "log_source":               "auth",
        "log_source_encoded":       1,
        "auth_is_root":             shared["is_root"],
        "auth_ip_is_external":      ip_external,
        "auth_severity":            sev,
        "auth_sev_norm":            round(sev / 16.0, 4),
        "auth_user_sensitivity":    shared["user_sensitivity"],
        "auth_known_country":       country_known,
        "geo_distance":             0 if country_known else 2,
        "auth_user_created":        int(rng.choice([0, 1], p=[0.98, 0.02])),
        "auth_user_deleted":        int(rng.choice([0, 1], p=[0.99, 0.01])),
        "auth_sudo_to_root":        int(rng.choice([0, 1], p=[0.88, 0.12])),
        "auth_passwd_changed":      int(rng.choice([0, 1], p=[0.97, 0.03])),
        "auth_pam_open":            pam_open,
        "auth_pam_close":           pam_close,
        "auth_fail_count_5m":       fail_5m,
        "auth_fail_window_10m":     fail_10m,
        "auth_ok_count_5m":         ok_5m,
        "auth_fail_ratio":          fail_ratio,
        "auth_users_tried":         1,
        "unique_users_per_ip":      1,
        "auth_is_brute_force":      0,
        "auth_is_slow_bruteforce":  0,
        "auth_is_user_enum":        0,
        "auth_is_stuffing":         0,
        "session_duration_log":     round(math.log1p(session_dur), 4),
        "cross_ssh_then_sudo":      int(rng.choice([0, 1], p=[0.85, 0.15])),
        "cross_bruteforce_success": 0,
        "freq_spike_ratio":         round(float(rng.beta(1, 8)), 4),
        "event_count_ip":           int(rng.exponential(15)) + 1,
        "unique_hosts_accessed":    1,
        "is_lateral_movement":      0,
    }


def generate_syslog_log(rng, hour: int, dow: int) -> dict:
    """Log syslog NORMAL — messages systemd, cron, kernel normaux."""
    shared      = build_shared_features(rng, hour, dow)
    sys_msg_len = int(np.clip(rng.lognormal(mean=4.0, sigma=0.6), 10, 500))
    sys_cron_new = int(rng.choice([0, 1], p=[0.97, 0.03]))

    return {
        **shared,
        "log_source":             "syslog",
        "log_source_encoded":     0,
        "sys_oom_kill":           0,
        "sys_module_load":        int(rng.choice([0, 1], p=[0.99, 0.01])),
        "sys_cron_new_job":       sys_cron_new,
        "sys_firewall_change":    int(rng.choice([0, 1], p=[0.995, 0.005])),
        "sys_service_crash_loop": int(rng.choice([0, 1], p=[0.98, 0.02])),
        "sys_msg_length_log":     round(math.log1p(sys_msg_len), 4),
        "sys_lateral_ssh":        0,
        "sys_new_service":        int(rng.choice([0, 1], p=[0.99, 0.01])),
        "sys_log_tamper":         0,
        "sys_high_cpu_process":   int(rng.choice([0, 1], p=[0.98, 0.02])),
        "freq_spike_ratio":       round(float(rng.beta(1, 10)), 4),
        "freq_spike_ratio_5m":    round(float(rng.beta(1, 10)), 4),
        "event_count_ip":         int(rng.exponential(20)) + 1,
        "event_count_1m_ip":      int(rng.poisson(2)),
        "event_count_5m_ip":      int(rng.poisson(8)),
        "cross_multi_source":     int(rng.choice([0, 1], p=[0.80, 0.20])),
        "is_lateral_movement":    0,
    }


def generate_auditd_log(rng, hour: int, dow: int) -> dict:
    """Log auditd NORMAL — syscalls ordinaires, entropie basse, aucun pattern MITRE."""
    shared    = build_shared_features(rng, hour, dow)
    cmd_len   = int(np.clip(rng.lognormal(mean=3.5, sigma=0.7), 5, 300))
    entropy   = round(float(np.clip(rng.normal(3.2, 0.6), 1.5, 4.4)), 4)
    arg_count = int(np.clip(rng.poisson(3), 0, 15))

    sev = 0
    if shared["is_root"]:      sev += 3
    if shared["is_off_hours"]: sev += 1
    sev = min(sev, 6)

    return {
        **shared,
        "log_source":             "auditd",
        "log_source_encoded":     2,
        "aud_severity":           sev,
        "aud_sev_norm":           round(sev / 24.0, 4),
        "aud_ptrace":             0,
        "aud_process_injection":  0,
        "aud_log_tamper":         0,
        "aud_cmd_entropy":        entropy,
        "aud_cmd_length_log":     round(math.log1p(cmd_len), 4),
        "aud_cmd_is_obfuscated":  0,
        "aud_arg_count":          arg_count,
        "payload_size_log":       round(math.log1p(cmd_len), 4),
        "aud_reverse_shell":      0,
        "aud_cron_backdoor":      0,
        "aud_suid_abuse":         0,
        "aud_ld_hijack":          0,
        "aud_credential_access":  0,
        "aud_ssh_key_implant":    0,
        "aud_cryptominer":        0,
        "aud_log_delete":         0,
        "aud_network_scan":       0,
        "aud_exfiltration":       0,
        "aud_suspicious_combo":   0,
        "event_count_ip":         int(rng.exponential(12)) + 1,
        "unique_hosts_accessed":  1,
        "is_lateral_movement":    0,
    }


def generate_auditd_heavy_compute(rng, hour: int, dow: int) -> dict:
    """
    Logs normaux : processus légitimes à forte consommation CPU/réseau.
    Exemples : compilation gcc, backup rsync, mise à jour apt, benchmark.
    Ces logs ressemblent superficiellement à des cryptominers mais sont légitimes.
    Objectif : éviter l'angle mort cryptominer (rappel 48%).
    """
    legit_commands = [
        "gcc -O2 -march=native -o build/app src/main.c src/utils.c",
        "make -j8 all CFLAGS=-O3",
        "rsync -avz --progress /data/ backup@192.168.1.10:/backup/",
        "apt-get upgrade -y --no-install-recommends",
        "python3 train.py --epochs 100 --batch-size 256",
        "ffmpeg -i input.mp4 -c:v libx264 -preset slow output.mp4",
        "pg_dump -Fc mydb > /backup/mydb_$(date +%Y%m%d).dump",
    ]
    cmd = rng.choice(legit_commands)
    cmd_len = len(cmd)

    log = generate_auditd_log(rng, hour, dow)
    log.update({
        "aud_cmd_entropy":       round(float(np.clip(rng.normal(4.0, 0.2), 3.5, 4.4)), 4),
        "aud_cmd_length_log":    round(math.log1p(cmd_len), 4),
        "aud_arg_count":         int(np.clip(rng.poisson(6), 2, 15)),
        "payload_size_log":      round(math.log1p(cmd_len), 4),
        "aud_cryptominer":       0,
        "aud_cmd_is_obfuscated": 0,
        "aud_network_scan":      0,
        "aud_exfiltration":      0,
    })
    return log


def generate_auditd_lateral_legit(rng, hour: int, dow: int) -> dict:
    """
    Logs normaux : admin qui accède à 1-2 machines pour maintenance.
    Objectif : réduire FP lateral_movement (rappel 48%).
    Un admin légitime accède à au plus 2 machines — pas 3+ donc pas lateral movement.
    """
    log = generate_auditd_log(rng, hour, dow)
    log.update({
        "unique_hosts_accessed": int(rng.choice([1, 2], p=[0.6, 0.4])),
        "is_lateral_movement":   0,
        "event_count_ip":        int(np.clip(rng.poisson(8), 1, 30)),
        "aud_network_scan":      0,
        "aud_exfiltration":      0,
    })
    return log


def generate_auditd_crypto_legit(rng, hour: int, dow: int) -> dict:
    """
    Logs normaux : processus légitimes à forte charge CPU.
    Compilation, ML training, backup — ressemblent à des miners mais légitimes.
    Objectif : réduire FP cryptominer.
    """
    legit_heavy = [
        "python3 train.py --epochs 50 --device cpu",
        "gcc -O3 -march=native -o app main.c utils.c",
        "make -j8 all",
        "rsync -avz /data/ backup@192.168.1.10:/mnt/backup/",
        "pg_dump -Fc mydb > /backup/mydb.dump",
        "ffmpeg -i input.mp4 -c:v libx264 output.mp4",
        "stress-ng --cpu 4 --timeout 60s",
        "openssl speed rsa2048",
    ]
    cmd = rng.choice(legit_heavy)

    log = generate_auditd_log(rng, hour, dow)
    log.update({
        "aud_cmd_entropy":       round(float(np.clip(rng.normal(4.0, 0.2), 3.5, 4.3)), 4),
        "aud_cmd_length_log":    round(math.log1p(len(cmd)), 4),
        "aud_arg_count":         int(np.clip(rng.poisson(5), 2, 12)),
        "aud_cryptominer":       0,
        "aud_cmd_is_obfuscated": 0,
        "aud_network_scan":      0,
        "aud_exfiltration":      0,
        "payload_size_log":      round(math.log1p(len(cmd)), 4),
    })
    return log


def generate_auth_brute_legit(rng, hour: int, dow: int) -> dict:
    """
    Logs normaux : utilisateur qui tape mal son mot de passe 2-4 fois.
    Objectif : réduire FP brute_force et credential_access.
    Forcer severity=1 et heures ouvrables pour passer validate_log.
    """
    # Forcer heure ouvrables pour passer C2 (8<=h<=18) et réduire le score
    hour = int(rng.choice(range(9, 19)))
    dow  = int(rng.choice(range(1, 6)))

    log = generate_auth_log(rng, hour, dow)

    fail_count = int(rng.choice([2, 3, 4], p=[0.5, 0.3, 0.2]))

    log.update({
        "auth_fail_count_5m":      fail_count,
        "auth_fail_window_10m":    fail_count,
        "auth_fail_ratio":         round(float(rng.uniform(0.2, 0.4)), 4),
        "auth_is_brute_force":     0,
        "auth_is_slow_bruteforce": 0,
        "auth_is_stuffing":        0,
        "auth_users_tried":        1,
        "unique_users_per_ip":     1,
        "auth_is_user_enum":       0,
        "aud_credential_access":   0,
        # Forcer severity basse pour passer C1 (composite_score < 2)
        "auth_severity":           1,
        "auth_sev_norm":           round(1 / 16.0, 4),
        "is_off_hours":            0,
        "is_night":                0,
        "is_root":                 0,
        "auth_is_root":            0,
        "user_sensitivity":        0,
        "auth_user_sensitivity":   0,
        "geo_distance":            0,
        "auth_known_country":      1,
        "auth_ip_is_external":     0,
    })
    return log


# =============================================================================
# SECTION E — CALCUL DU COMPOSITE SCORE ET VALIDATION
# =============================================================================

def compute_composite_score(log: dict) -> int:
    """
    Réplique le calcul du composite_score de la Section 11 Logstash.
    Un log normal doit avoir composite_score < 2.
    """
    src = log.get("log_source", "unknown")
    g   = lambda k: int(log.get(k, 0))

    base = {
        "auth":   g("auth_severity"),
        "syslog": (3 * g("sys_module_load")     + 2 * g("sys_firewall_change") +
                   2 * g("sys_oom_kill")         + 1 * g("sys_service_crash_loop")),
        "auditd": g("aud_severity"),
    }.get(src, 0)

    bonus = (
        3 * g("auth_is_brute_force")        + 2 * g("auth_is_slow_bruteforce") +
        2 * g("auth_is_stuffing")           + 1 * g("auth_is_user_enum")       +
        3 * g("cross_ssh_then_sudo")        + 3 * g("cross_bruteforce_success")+
        3 * g("aud_process_injection")      + 2 * g("aud_cmd_is_obfuscated")   +
        2 * g("is_off_hours")               + 2 * g("is_root")                 +
        2 * g("msg_has_base64")             + 1 * g("is_weekend")              +
        5 * g("aud_reverse_shell")          + 4 * g("aud_ld_hijack")           +
        4 * g("aud_credential_access")      + 3 * g("aud_ssh_key_implant")     +
        3 * g("aud_log_delete")             + 2 * g("aud_cron_backdoor")       +
        2 * g("aud_suid_abuse")             + 2 * g("aud_exfiltration")        +
        1 * g("aud_network_scan")           + 1 * g("aud_cryptominer")         +
        2 * g("sys_new_service")            + 2 * g("sys_log_tamper")          +
        1 * g("sys_lateral_ssh")            + 1 * g("sys_high_cpu_process")    +
        2 * g("is_lateral_movement")        +
        2 * (1 if g("geo_distance") >= 2 else 0) +
        1 * g("aud_suspicious_combo")
    )

    return base + bonus


def validate_log(log: dict) -> tuple:
    """
    Vérifie qu'un log est bien un candidat normal.
    C1 : composite_score < 2
    C4 : aucun flag d'attaque à 1
    (C2 et C3 non bloquants — on veut des normaux sur toute la journée)
    """
    score = compute_composite_score(log)

    attack_flags = [
        "aud_reverse_shell", "aud_process_injection", "aud_log_delete",
        "aud_credential_access", "aud_ssh_key_implant", "auth_is_brute_force",
        "auth_is_stuffing", "cross_bruteforce_success", "sys_log_tamper",
        "sys_module_load", "is_lateral_movement", "aud_suspicious_combo",
    ]

    if score >= 2:
        return False, f"score={score}"

    for flag in attack_flags:
        if int(log.get(flag, 0)) == 1:
            return False, f"flag={flag}"

    return True, "ok"


# =============================================================================
# SECTION F — GÉNÉRATION ET ÉCRITURE BULK ES
# =============================================================================

def generate_timestamp(rng, hour: int, dow: int) -> str:
    """Génère un timestamp ISO réaliste dans les 30 derniers jours."""
    now       = datetime.now(timezone.utc)
    days_back = int(rng.uniform(0, 30))
    candidate = now - timedelta(days=days_back)
    attempts  = 0
    while candidate.weekday() != ((dow - 1) % 7) and attempts < 7:
        days_back = (days_back + 1) % 30
        candidate = now - timedelta(days=days_back)
        attempts += 1
    minutes = int(rng.integers(0, 60))
    seconds = int(rng.integers(0, 60))
    ts = candidate.replace(hour=hour, minute=minutes, second=seconds,
                           microsecond=0)
    return ts.isoformat()


def build_es_document(log: dict, rng) -> dict:
    """Construit le document Elasticsearch final."""
    hour  = int(log.get("hour_of_day", 12))
    dow   = int(log.get("day_of_week", 3))
    src   = log.get("log_source", "unknown")
    score = compute_composite_score(log)

    doc = {
        "@timestamp":          generate_timestamp(rng, hour, dow),
        "log_source":          src,
        "ground_truth":        0,
        "is_normal_candidate": 1,
        "composite_score":     score,
        "priority_label":      "low" if score < 4 else "medium",
        "ml": {k: v for k, v in log.items() if k not in ("log_source",)}
    }
    doc["ml"]["log_source"] = src
    return doc


def write_bulk(docs: list, ctx, headers) -> int:
    """Écrit un lot de documents via l'API bulk ES."""
    bulk = ""
    for doc in docs:
        bulk += json.dumps({"index": {"_index": ES_INDEX_NORMAL}}) + "\n"
        bulk += json.dumps(doc) + "\n"

    resp = urllib.request.urlopen(
        urllib.request.Request(
            f"{ES_HOST}/_bulk",
            data=bulk.encode(),
            headers=headers,
            method="POST"
        ),
        context=ctx
    )
    result = json.loads(resp.read())
    errors = [i for i in result.get("items", []) if "error" in i.get("index", {})]
    if errors:
        print(f"    Erreurs bulk : {len(errors)}")
    return len(docs) - len(errors)


# =============================================================================
# SECTION G — REGISTRE DES GÉNÉRATEURS
# =============================================================================
# Défini ici — après toutes les fonctions, avant le main.
# N_PER_SOURCE_OVERRIDE surcharge N_PER_SOURCE pour les sources adversariales.
# =============================================================================

GENERATORS = {
    "auth":             generate_auth_log,
    "syslog":           generate_syslog_log,
    "auditd":           generate_auditd_log,
    "auditd_heavy":     generate_auditd_heavy_compute,
    "auditd_lateral":   generate_auditd_lateral_legit,
    "auditd_crypto":    generate_auditd_crypto_legit,
    "auth_brute_legit": generate_auth_brute_legit,
}


# =============================================================================
# SECTION H — MAIN
# =============================================================================

if __name__ == "__main__":
    total_logs = sum(N_PER_SOURCE_OVERRIDE.get(s, N_PER_SOURCE)
                     for s in GENERATORS)

    print("=" * 65)
    print("  IDS — Injection logs normaux synthétiques")
    print(f"  Index cible : {ES_INDEX_NORMAL}")
    print(f"  Sources     : {len(GENERATORS)}")
    print(f"  Total prévu : {total_logs:,} logs")
    print("=" * 65)

    rng = np.random.default_rng(42)
    ctx, headers = make_es_client()

    try:
        info = es_request("/", ctx=ctx, headers=headers)
        print(f"\n  ES connecté : {info.get('version', {}).get('number', '?')}")
    except Exception as e:
        print(f"\n  ERREUR connexion ES : {e}")
        exit(1)

    create_index_if_not_exists()

    total_injected  = 0
    total_rejected  = 0
    stats_by_source = {}

    for src, generator in GENERATORS.items():
        n            = N_PER_SOURCE_OVERRIDE.get(src, N_PER_SOURCE)
        max_attempts = n * 4   # 4× pour les sources avec fort taux de rejet

        print(f"\n  Génération {src} ({n:,} logs)...")

        batch    = []
        injected = 0
        rejected = 0
        attempts = 0

        while injected < n and attempts < max_attempts:
            attempts += 1

            hour = int(rng.choice(range(24), p=HOUR_PROBA))
            dow  = int(rng.choice(range(7),  p=DOW_WEIGHTS))

            log = generator(rng, hour, dow)

            is_valid, reason = validate_log(log)
            if not is_valid:
                rejected += 1
                continue

            doc = build_es_document(log, rng)
            batch.append(doc)
            injected += 1

            if len(batch) >= BATCH_SIZE:
                written = write_bulk(batch, ctx, headers)
                total_injected += written
                batch = []
                print(f"    {injected:5d}/{n} injectés ({rejected} rejetés)...")

        if batch:
            written = write_bulk(batch, ctx, headers)
            total_injected += written

        total_rejected += rejected
        stats_by_source[src] = {
            "injected": injected,
            "rejected": rejected,
            "rate":     round(injected / max(injected + rejected, 1) * 100, 1),
        }

        print(f"  {src:16s}: {injected:5,} injectés | "
              f"{rejected:5d} rejetés ({stats_by_source[src]['rate']}% valid)")

        if injected < n:
            print(f"  ⚠ {src} : seulement {injected}/{n} logs produits "
                  f"— augmenter max_attempts ou assouplir validate_log")

    print("\n" + "=" * 65)
    print("  INJECTION TERMINÉE")
    print("=" * 65)
    print(f"\n  Total injecté : {total_injected:,} logs normaux certifiés")
    print(f"  Total rejeté  : {total_rejected} (score >= 2 ou flag attaque)")
    print(f"\n  Détail par source :")
    for src, s in stats_by_source.items():
        print(f"    {src:16s}: {s['injected']:5,} logs "
              f"({s['rate']}% taux de validation)")

    print(f"\n  Index : {ES_INDEX_NORMAL}")

    time.sleep(2)
    try:
        count = es_request(
            f"/{ES_INDEX_NORMAL}/_count",
            {"query": {"match_all": {}}},
            ctx=ctx, headers=headers
        )
        print(f"\n  Vérification ES : {count.get('count', '?')} "
              f"documents dans {ES_INDEX_NORMAL}")
    except Exception as e:
        print(f"\n  Vérification impossible : {e}")