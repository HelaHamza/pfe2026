"""
=============================================================================
SCRIPT 2 — CRÉATION INDEX DE TEST + INSERTION LOGS (normaux & anormaux)
=============================================================================
Ce script :
  1. Crée l'index Elasticsearch "ids-test-logs" avec un mapping adapté
  2. Génère des logs normaux synthétiques (8h-18h, jours ouvrés, pas d'attaque)
  3. Génère des logs anormaux pour 8 types d'attaques MITRE ATT&CK
  4. Insère tout via l'API Bulk ES
  5. Exporte le ground truth CSV (utilisé par le script d'évaluation)

Usage :
    python create_test_index.py [--n_normal 600] [--n_attacks 400]

L'index créé contient tous les champs ml.* attendus par le modèle.
Le champ "ground_truth" (0=normal, 1=attaque) et "attack_type" sont ajoutés
pour l'évaluation ultérieure.
=============================================================================




    Crée le jeu de TEST avec ground_truth certifié.

    POURQUOI injecter des attaques synthétiques ?
        Les données réelles de production ne contiennent pas de labels
        (on ne sait pas si un log est une vraie attaque). Pour évaluer
        objectivement le modèle, on injecte des logs d'attaques dont
        on est certain qu'ils sont malveillants (ground_truth = 1).

    Méthode :
        1. On part de logs normaux réels (ground_truth = 0)
        2. On en sélectionne n_attacks et on modifie les features
           correspondant à chaque type d'attaque
        3. On mélange normaux + attaques → dataset de test équilibré

    7 types d'attaques couverts (MITRE ATT&CK) :
        1. Brute Force SSH      → auth_fail_count_5m élevé, auth_is_brute_force=1
        2. Reverse Shell        → aud_reverse_shell=1, entropie commande élevée
        3. Privilege Escalation → auth_sudo_to_root=1, cross_ssh_then_sudo=1
        4. Credential Access    → aud_credential_access=1, nuit
        5. Log Tampering        → aud_log_delete=1, sys_log_tamper=1, root
        6. Cryptominer          → aud_cryptominer=1, sys_high_cpu_process=1
        7. SSH Key Implant      → aud_ssh_key_implant=1, nuit, root

    Args:
        df_normal : DataFrame de logs normaux (source du jeu de test)
        n_attacks : nombre total de logs d'attaques à injecter
        seed      : graine pour la reproductibilité

    Returns:
        df_test : DataFrame mélangé avec colonnes ground_truth et attack_type
    """

import json, ssl, urllib.request, base64, time, argparse
import numpy as np
import pandas as pd
from datetime import datetime, timezone, timedelta

# =============================================================================
# CONFIGURATION
# =============================================================================

ES_HOST        = "https://localhost:9200"
ES_USER        = "elastic"
ES_PASS        = "pfe2026"
ES_TEST_INDEX  = "test-ml-logs"
GROUND_TRUTH_CSV = "test_ground_truth.csv"

SOURCES = ["syslog", "auth", "auditd"]

# =============================================================================
# CLIENT ELASTICSEARCH
# =============================================================================

def make_es_client():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    token   = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
    headers = {"Content-Type": "application/json",
               "Authorization": f"Basic {token}"}
    return ctx, headers

def es_request(path, body=None, method=None, ctx=None, headers=None):
    if ctx is None:
        ctx, headers = make_es_client()
    url  = f"{ES_HOST}{path}"
    data = json.dumps(body).encode() if body else None
    m    = method or ("POST" if body else "GET")
    req  = urllib.request.Request(url, data=data, headers=headers, method=m)
    try:
        resp = urllib.request.urlopen(req, context=ctx)
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"  HTTP {e.code} sur {path} : {body[:200]}")
        return None

# =============================================================================
# MAPPING ELASTICSEARCH
# =============================================================================

INDEX_MAPPING = {
    "settings": {
        "number_of_shards":   1,
        "number_of_replicas": 0,
        "refresh_interval":   "1s",
    },
    "mappings": {
        "properties": {
            "@timestamp":        {"type": "date"},
            "ground_truth":      {"type": "integer"},
            "attack_type":       {"type": "keyword"},
            "log_source":        {"type": "keyword"},
            "ml": {
                "properties": {
                    # Shared — temporelles
                    "hour_of_day":        {"type": "float"},
                    "day_of_week":        {"type": "float"},
                    "is_off_hours":       {"type": "float"},
                    "is_night":           {"type": "float"},
                    "is_weekend":         {"type": "float"},
                    "is_business":        {"type": "float"},
                    "hour_sin":           {"type": "float"},
                    "hour_cos":           {"type": "float"},
                    # Shared — message
                    "msg_length_log":     {"type": "float"},
                    "msg_word_count":     {"type": "float"},
                    "msg_has_ip":         {"type": "float"},
                    "msg_has_base64":     {"type": "float"},
                    "msg_has_url":        {"type": "float"},
                    "msg_has_pipe":       {"type": "float"},
                    "is_root":            {"type": "float"},
                    "user_sensitivity":   {"type": "float"},
                    "delta_time_log":     {"type": "float"},
                    "log_source_encoded": {"type": "float"},
                    # Auth
                    "auth_is_root":           {"type": "float"},
                    "auth_ip_is_external":    {"type": "float"},
                    "auth_severity":          {"type": "float"},
                    "auth_sev_norm":          {"type": "float"},
                    "auth_user_sensitivity":  {"type": "float"},
                    "auth_known_country":     {"type": "float"},
                    "geo_distance":           {"type": "float"},
                    "auth_user_created":      {"type": "float"},
                    "auth_user_deleted":      {"type": "float"},
                    "auth_sudo_to_root":      {"type": "float"},
                    "auth_passwd_changed":    {"type": "float"},
                    "auth_pam_open":          {"type": "float"},
                    "auth_pam_close":         {"type": "float"},
                    "auth_fail_count_5m":     {"type": "float"},
                    "auth_fail_window_10m":   {"type": "float"},
                    "auth_ok_count_5m":       {"type": "float"},
                    "auth_fail_ratio":        {"type": "float"},
                    "auth_users_tried":       {"type": "float"},
                    "unique_users_per_ip":    {"type": "float"},
                    "auth_is_brute_force":    {"type": "float"},
                    "auth_is_slow_bruteforce":{"type": "float"},
                    "auth_is_user_enum":      {"type": "float"},
                    "auth_is_stuffing":       {"type": "float"},
                    "session_duration_log":   {"type": "float"},
                    "cross_ssh_then_sudo":    {"type": "float"},
                    "cross_bruteforce_success":{"type":"float"},
                    "freq_spike_ratio":       {"type": "float"},
                    "event_count_ip":         {"type": "float"},
                    "unique_hosts_accessed":  {"type": "float"},
                    "is_lateral_movement":    {"type": "float"},
                    # Syslog
                    "sys_oom_kill":           {"type": "float"},
                    "sys_module_load":        {"type": "float"},
                    "sys_cron_new_job":       {"type": "float"},
                    "sys_firewall_change":    {"type": "float"},
                    "sys_service_crash_loop": {"type": "float"},
                    "sys_msg_length_log":     {"type": "float"},
                    "sys_lateral_ssh":        {"type": "float"},
                    "sys_new_service":        {"type": "float"},
                    "sys_log_tamper":         {"type": "float"},
                    "sys_high_cpu_process":   {"type": "float"},
                    "freq_spike_ratio_5m":    {"type": "float"},
                    "event_count_1m_ip":      {"type": "float"},
                    "event_count_5m_ip":      {"type": "float"},
                    "cross_multi_source":     {"type": "float"},
                    # Auditd
                    "aud_severity":           {"type": "float"},
                    "aud_sev_norm":           {"type": "float"},
                    "aud_ptrace":             {"type": "float"},
                    "aud_process_injection":  {"type": "float"},
                    "aud_log_tamper":         {"type": "float"},
                    "aud_cmd_entropy":        {"type": "float"},
                    "aud_cmd_length_log":     {"type": "float"},
                    "aud_cmd_is_obfuscated":  {"type": "float"},
                    "aud_arg_count":          {"type": "float"},
                    "payload_size_log":       {"type": "float"},
                    "aud_reverse_shell":      {"type": "float"},
                    "aud_cron_backdoor":      {"type": "float"},
                    "aud_suid_abuse":         {"type": "float"},
                    "aud_ld_hijack":          {"type": "float"},
                    "aud_credential_access":  {"type": "float"},
                    "aud_ssh_key_implant":    {"type": "float"},
                    "aud_cryptominer":        {"type": "float"},
                    "aud_log_delete":         {"type": "float"},
                    "aud_network_scan":       {"type": "float"},
                    "aud_exfiltration":       {"type": "float"},
                    "aud_suspicious_combo":   {"type": "float"},
                    "payload_size_log":       {"type": "float"},
                    # Meta
                    "composite_score":        {"type": "float"},
                    "is_normal_candidate":    {"type": "integer"},
                    "log_source":             {"type": "keyword"},
                },
            },
        }
    },
}

# =============================================================================
# GÉNÉRATEURS DE LOGS
# =============================================================================

def _base_normal(rng, src, idx):
    """Champs communs à tous les logs normaux."""
    # Heure business (8h-18h, lundi-vendredi)
    hour    = int(rng.integers(8, 19))
    dow     = int(rng.integers(1, 6))   # 1=lun … 5=ven
    dt = datetime.now(timezone.utc) - timedelta(
        days=int(rng.integers(0, 30)),
        hours=int(rng.integers(0, 24)),
        minutes=int(rng.integers(0, 60)),
    )

    src_enc = {"syslog": 0, "auth": 1, "auditd": 2}.get(src, 0)

    return {
        "@timestamp":         dt.isoformat(),
        "log_source":         src,
        "ground_truth":       0,
        "attack_type":        "normal",
        "ml": {
            # Shared
            "hour_of_day":        hour,
            "day_of_week":        dow,
            "is_off_hours":       0,
            "is_night":           0,
            "is_weekend":         0,
            "is_business":        1,
            "hour_sin":           float(np.sin(2 * np.pi * hour / 24)),
            "hour_cos":           float(np.cos(2 * np.pi * hour / 24)),
            "msg_length_log":     float(rng.uniform(2.0, 4.5)),
            "msg_word_count":     int(rng.integers(3, 15)),
            "msg_has_ip":         int(rng.random() < 0.2),
            "msg_has_base64":     0,
            "msg_has_url":        0,
            "msg_has_pipe":       0,
            "is_root":            0,
            "user_sensitivity":   0,
            "delta_time_log":     float(rng.uniform(0.5, 4.0)),
            "log_source_encoded": src_enc,
            # Auth (zéros par défaut)
            "auth_is_root": 0, "auth_ip_is_external": 0,
            "auth_severity": 0, "auth_sev_norm": 0,
            "auth_user_sensitivity": 0, "auth_known_country": 1,
            "geo_distance": 0, "auth_user_created": 0,
            "auth_user_deleted": 0, "auth_sudo_to_root": 0,
            "auth_passwd_changed": 0, "auth_pam_open": 0,
            "auth_pam_close": 0, "auth_fail_count_5m": 0,
            "auth_fail_window_10m": 0, "auth_ok_count_5m": float(rng.integers(1,5)),
            "auth_fail_ratio": 0, "auth_users_tried": 0,
            "unique_users_per_ip": 1, "auth_is_brute_force": 0,
            "auth_is_slow_bruteforce": 0, "auth_is_user_enum": 0,
            "auth_is_stuffing": 0, "session_duration_log": float(rng.uniform(1,3)),
            "cross_ssh_then_sudo": 0, "cross_bruteforce_success": 0,
            "freq_spike_ratio": float(rng.uniform(0, 0.1)),
            "event_count_ip": int(rng.integers(1, 10)),
            "unique_hosts_accessed": 1, "is_lateral_movement": 0,
            # Syslog
            "sys_oom_kill": 0, "sys_module_load": 0, "sys_cron_new_job": 0,
            "sys_firewall_change": 0, "sys_service_crash_loop": 0,
            "sys_msg_length_log": float(rng.uniform(2.0, 4.5)),
            "sys_lateral_ssh": 0, "sys_new_service": 0,
            "sys_log_tamper": 0, "sys_high_cpu_process": 0,
            "freq_spike_ratio_5m": float(rng.uniform(0, 0.05)),
            "event_count_1m_ip": int(rng.integers(0, 3)),
            "event_count_5m_ip": int(rng.integers(1, 8)),
            "cross_multi_source": 0,
            # Auditd
            "aud_severity": float(rng.uniform(0, 2)),
            "aud_sev_norm": float(rng.uniform(0, 0.1)),
            "aud_ptrace": 0, "aud_process_injection": 0,
            "aud_log_tamper": 0,
            "aud_cmd_entropy": float(rng.uniform(1.5, 3.0)),
            "aud_cmd_length_log": float(rng.uniform(1.5, 3.0)),
            "aud_cmd_is_obfuscated": 0,
            "aud_arg_count": int(rng.integers(0, 4)),
            "payload_size_log": float(rng.uniform(0.5, 2.5)),
            "aud_reverse_shell": 0, "aud_cron_backdoor": 0,
            "aud_suid_abuse": 0, "aud_ld_hijack": 0,
            "aud_credential_access": 0, "aud_ssh_key_implant": 0,
            "aud_cryptominer": 0, "aud_log_delete": 0,
            "aud_network_scan": 0, "aud_exfiltration": 0,
            "aud_suspicious_combo": 0,
            # Meta
            "composite_score":     0,
            "is_normal_candidate": 1,
            "log_source":          src,
        }
    }

def generate_normal_logs(n, rng):
    """Génère n logs normaux répartis sur les 3 sources."""
    logs = []
    per_src = n // 3
    for i, src in enumerate(SOURCES):
        count = per_src if i < 2 else n - 2 * per_src
        for j in range(count):
            logs.append(_base_normal(rng, src, j))
    rng.shuffle(logs)
    return logs

# ── Attaques ──────────────────────────────────────────────────────────────────

ATTACK_GENERATORS = {}

def _atk(name):
    def decorator(fn):
        ATTACK_GENERATORS[name] = fn
        return fn
    return decorator

@_atk("brute_force_ssh")
def gen_brute_force(rng, n):
    logs = []
    for i in range(n):
        doc = _base_normal(rng, "auth", i)
        doc["ground_truth"] = 1
        doc["attack_type"]  = "brute_force_ssh"
        doc["@timestamp"]   = (
            datetime.now(timezone.utc) - timedelta(hours=int(rng.integers(0,72)))
        ).isoformat()
        ml = doc["ml"]
        # Heure nocturne
        h = int(rng.integers(0, 6))
        ml["hour_of_day"]        = h
        ml["hour_sin"]           = float(np.sin(2*np.pi*h/24))
        ml["hour_cos"]           = float(np.cos(2*np.pi*h/24))
        ml["is_off_hours"]       = 1
        ml["is_night"]           = 1
        ml["is_business"]        = 0
        # Indicateurs brute force
        ml["auth_fail_count_5m"]    = int(rng.integers(20, 150))
        ml["auth_fail_window_10m"]  = int(rng.integers(30, 200))
        ml["auth_fail_ratio"]       = float(rng.uniform(0.85, 0.99))
        ml["auth_is_brute_force"]   = 1
        ml["auth_is_slow_bruteforce"] = 1
        ml["auth_users_tried"]      = int(rng.integers(5, 25))
        ml["auth_is_user_enum"]     = 1
        ml["auth_ip_is_external"]   = 1
        ml["auth_known_country"]    = 0
        ml["geo_distance"]          = 2
        ml["freq_spike_ratio"]      = float(rng.uniform(0.7, 0.99))
        ml["event_count_ip"]        = int(rng.integers(50, 500))
        ml["auth_severity"]         = int(rng.integers(8, 16))
        ml["auth_sev_norm"]         = ml["auth_severity"] / 16.0
        ml["composite_score"]       = int(rng.integers(5, 12))
        ml["is_normal_candidate"]   = 0
        logs.append(doc)
    return logs

@_atk("reverse_shell")
def gen_reverse_shell(rng, n):
    logs = []
    for i in range(n):
        doc = _base_normal(rng, "auditd", i)
        doc["ground_truth"] = 1
        doc["attack_type"]  = "reverse_shell"
        ml = doc["ml"]
        h = int(rng.integers(0, 5))
        ml["hour_of_day"]          = h
        ml["hour_sin"]             = float(np.sin(2*np.pi*h/24))
        ml["hour_cos"]             = float(np.cos(2*np.pi*h/24))
        ml["is_off_hours"]         = 1
        ml["is_night"]             = 1
        ml["is_business"]          = 0
        ml["msg_has_base64"]       = 1
        ml["msg_has_pipe"]         = 1
        ml["aud_reverse_shell"]    = 1
        ml["aud_cmd_entropy"]      = float(rng.uniform(4.2, 5.5))
        ml["aud_cmd_length_log"]   = float(rng.uniform(4.0, 6.0))
        ml["aud_cmd_is_obfuscated"]= 1
        ml["aud_exfiltration"]     = 1
        ml["aud_suspicious_combo"] = 1
        ml["aud_severity"]         = int(rng.integers(12, 24))
        ml["aud_sev_norm"]         = ml["aud_severity"] / 24.0
        ml["aud_arg_count"]        = int(rng.integers(5, 15))
        ml["payload_size_log"]     = float(rng.uniform(3.5, 6.0))
        ml["composite_score"]      = int(rng.integers(8, 15))
        ml["is_normal_candidate"]  = 0
        logs.append(doc)
    return logs

@_atk("privilege_escalation")
def gen_privesc(rng, n):
    logs = []
    for i in range(n):
        doc = _base_normal(rng, "auth", i)
        doc["ground_truth"] = 1
        doc["attack_type"]  = "privilege_escalation"
        ml = doc["ml"]
        ml["auth_sudo_to_root"]        = 1
        ml["cross_ssh_then_sudo"]      = 1
        ml["cross_bruteforce_success"] = 1
        ml["auth_is_root"]             = 1
        ml["is_root"]                  = 1
        ml["user_sensitivity"]         = 3
        ml["auth_user_sensitivity"]    = 3
        ml["auth_ip_is_external"]      = 1
        ml["auth_severity"]            = int(rng.integers(10, 16))
        ml["auth_sev_norm"]            = ml["auth_severity"] / 16.0
        ml["composite_score"]          = int(rng.integers(6, 12))
        ml["is_normal_candidate"]      = 0
        logs.append(doc)
    return logs

@_atk("credential_access")
def gen_cred_access(rng, n):
    logs = []
    for i in range(n):
        doc = _base_normal(rng, "auditd", i)
        doc["ground_truth"] = 1
        doc["attack_type"]  = "credential_access"
        ml = doc["ml"]
        h = int(rng.integers(1, 6))
        ml["hour_of_day"]          = h
        ml["hour_sin"]             = float(np.sin(2*np.pi*h/24))
        ml["hour_cos"]             = float(np.cos(2*np.pi*h/24))
        ml["is_off_hours"]         = 1
        ml["aud_credential_access"]= 1
        ml["aud_severity"]         = int(rng.integers(8, 20))
        ml["aud_sev_norm"]         = ml["aud_severity"] / 24.0
        ml["aud_ptrace"]           = int(rng.random() < 0.5)
        ml["composite_score"]      = int(rng.integers(5, 10))
        ml["is_normal_candidate"]  = 0
        logs.append(doc)
    return logs

@_atk("log_tampering")
def gen_log_tamper(rng, n):
    logs = []
    for i in range(n):
        src = rng.choice(["auditd", "syslog"])
        doc = _base_normal(rng, src, i)
        doc["ground_truth"] = 1
        doc["attack_type"]  = "log_tampering"
        ml = doc["ml"]
        h = int(rng.integers(2, 5))
        ml["hour_of_day"]   = h
        ml["hour_sin"]      = float(np.sin(2*np.pi*h/24))
        ml["hour_cos"]      = float(np.cos(2*np.pi*h/24))
        ml["is_night"]      = 1
        ml["is_off_hours"]  = 1
        ml["is_business"]   = 0
        ml["is_root"]       = 1
        ml["user_sensitivity"] = 3
        ml["aud_log_delete"]   = 1
        ml["aud_log_tamper"]   = 1
        ml["sys_log_tamper"]   = 1
        ml["aud_severity"]     = int(rng.integers(6, 16))
        ml["aud_sev_norm"]     = ml["aud_severity"] / 24.0
        ml["composite_score"]  = int(rng.integers(4, 9))
        ml["is_normal_candidate"] = 0
        logs.append(doc)
    return logs

@_atk("cryptominer")
def gen_cryptominer(rng, n):
    logs = []
    for i in range(n):
        src = rng.choice(["auditd", "syslog"])
        doc = _base_normal(rng, src, i)
        doc["ground_truth"] = 1
        doc["attack_type"]  = "cryptominer"
        ml = doc["ml"]
        ml["aud_cryptominer"]    = 1
        ml["sys_high_cpu_process"] = 1
        ml["aud_cmd_entropy"]    = float(rng.uniform(3.8, 5.0))
        ml["aud_network_scan"]   = 1
        ml["aud_suspicious_combo"] = 1
        ml["aud_severity"]       = int(rng.integers(4, 12))
        ml["aud_sev_norm"]       = ml["aud_severity"] / 24.0
        ml["composite_score"]    = int(rng.integers(3, 8))
        ml["is_normal_candidate"] = 0
        logs.append(doc)
    return logs

@_atk("ssh_key_implant")
def gen_ssh_key(rng, n):
    logs = []
    for i in range(n):
        doc = _base_normal(rng, "auditd", i)
        doc["ground_truth"] = 1
        doc["attack_type"]  = "ssh_key_implant"
        ml = doc["ml"]
        h = int(rng.integers(1, 5))
        ml["hour_of_day"]        = h
        ml["hour_sin"]           = float(np.sin(2*np.pi*h/24))
        ml["hour_cos"]           = float(np.cos(2*np.pi*h/24))
        ml["is_off_hours"]       = 1
        ml["is_night"]           = 1
        ml["is_business"]        = 0
        ml["is_root"]            = 1
        ml["user_sensitivity"]   = 3
        ml["aud_ssh_key_implant"]= 1
        ml["aud_severity"]       = int(rng.integers(10, 20))
        ml["aud_sev_norm"]       = ml["aud_severity"] / 24.0
        ml["composite_score"]    = int(rng.integers(5, 10))
        ml["is_normal_candidate"] = 0
        logs.append(doc)
    return logs

@_atk("lateral_movement")
def gen_lateral(rng, n):
    logs = []
    for i in range(n):
        src = rng.choice(["auth", "syslog"])
        doc = _base_normal(rng, src, i)
        doc["ground_truth"] = 1
        doc["attack_type"]  = "lateral_movement"
        ml = doc["ml"]
        ml["is_lateral_movement"]  = 1
        ml["unique_hosts_accessed"]= int(rng.integers(3, 10))
        ml["sys_lateral_ssh"]      = 1
        ml["cross_multi_source"]   = 1
        ml["auth_ip_is_external"]  = 0   # IP interne
        ml["auth_fail_count_5m"]   = int(rng.integers(2, 8))
        ml["freq_spike_ratio"]     = float(rng.uniform(0.4, 0.8))
        ml["event_count_ip"]       = int(rng.integers(20, 100))
        ml["composite_score"]      = int(rng.integers(4, 9))
        ml["is_normal_candidate"]  = 0
        logs.append(doc)
    return logs

# =============================================================================
# INSERTION ELASTICSEARCH (Bulk API)
# =============================================================================

def create_index(ctx, headers, force_recreate=True):
    """Crée l'index de test (supprime s'il existe déjà)."""
    # Vérification existence
    url = f"{ES_HOST}/{ES_TEST_INDEX}"
    try:
        req  = urllib.request.Request(url, headers=headers, method="HEAD")
        urllib.request.urlopen(req, context=ctx)
        exists = True
    except urllib.error.HTTPError:
        exists = False

    if exists and force_recreate:
        req = urllib.request.Request(url, headers=headers, method="DELETE")
        urllib.request.urlopen(req, context=ctx)
        print(f"  Index {ES_TEST_INDEX} supprimé (recréation)")
        time.sleep(1)

    req  = urllib.request.Request(
        url,
        data=json.dumps(INDEX_MAPPING).encode(),
        headers=headers, method="PUT",
    )
    resp = urllib.request.urlopen(req, context=ctx)
    print(f"  Index {ES_TEST_INDEX} créé : {resp.read().decode()[:60]}")

def bulk_insert(docs, ctx, headers, batch_size=500):
    """Insère les documents via l'API Bulk."""
    total   = 0
    batches = 0

    for start in range(0, len(docs), batch_size):
        batch = docs[start:start + batch_size]
        body  = ""
        for doc in batch:
            body += json.dumps({"index": {"_index": ES_TEST_INDEX}}) + "\n"
            body += json.dumps(doc) + "\n"

        req = urllib.request.Request(
            f"{ES_HOST}/_bulk",
            data=body.encode(),
            headers=headers, method="POST",
        )
        resp = json.loads(urllib.request.urlopen(req, context=ctx).read())
        if resp.get("errors"):
            errs = [it for it in resp["items"]
                    if it.get("index", {}).get("error")]
            print(f"  ⚠ {len(errs)} erreurs dans le batch {batches+1}")

        total   += len(batch)
        batches += 1
        print(f"    {total}/{len(docs)} documents insérés...")

    # Forcer le refresh pour que les docs soient visibles immédiatement
    es_request(f"/{ES_TEST_INDEX}/_refresh", ctx=ctx, headers=headers,
               method="POST")
    print(f"  Total inséré : {total} documents")
    return total

# =============================================================================
# EXPORT GROUND TRUTH
# =============================================================================

def export_ground_truth(all_docs):
    """Exporte un CSV léger avec id, source, ground_truth, attack_type."""
    rows = []
    for i, doc in enumerate(all_docs):
        rows.append({
            "doc_idx":      i,
            "log_source":   doc.get("log_source", "unknown"),
            "ground_truth": doc.get("ground_truth", 0),
            "attack_type":  doc.get("attack_type", "normal"),
        })
    df = pd.DataFrame(rows)
    df.to_csv(GROUND_TRUTH_CSV, index=False)
    print(f"\n  Ground truth exporté : {GROUND_TRUTH_CSV}")
    print(f"    Normaux  : {(df.ground_truth==0).sum()}")
    print(f"    Attaques : {(df.ground_truth==1).sum()}")
    for t, c in df[df.ground_truth==1]["attack_type"].value_counts().items():
        print(f"      {str(t):30s}: {c}")
    return df

# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Création index test + insertion logs IDS"
    )
    parser.add_argument("--n_normal",  type=int, default=600,
                        help="Nombre de logs normaux (défaut: 600)")
    parser.add_argument("--n_attacks", type=int, default=400,
                        help="Nombre de logs d'attaques (défaut: 400)")
    parser.add_argument("--seed",      type=int, default=42,
                        help="Graine aléatoire (défaut: 42)")
    parser.add_argument("--no-recreate", action="store_true",
                        help="Ne pas supprimer l'index s'il existe")
    args = parser.parse_args()

    rng = np.random.default_rng(args.seed)

    print("=" * 65)
    print("  CRÉATION INDEX TEST + INSERTION LOGS")
    print(f"  Index cible  : {ES_TEST_INDEX}")
    print(f"  Logs normaux : {args.n_normal}")
    print(f"  Logs attaques: {args.n_attacks}")
    print("=" * 65)

    ctx, headers = make_es_client()

    # ── 1. Création de l'index ────────────────────────────────────
    print("\n[1/4] Création de l'index...")
    create_index(ctx, headers, force_recreate=not args.no_recreate)

    # ── 2. Génération des logs normaux ────────────────────────────
    print(f"\n[2/4] Génération de {args.n_normal} logs normaux...")
    normal_docs = generate_normal_logs(args.n_normal, rng)
    print(f"  Générés : {len(normal_docs)}")

    # ── 3. Génération des attaques ────────────────────────────────
    attack_names = list(ATTACK_GENERATORS.keys())
    n_types      = len(attack_names)
    per_type     = args.n_attacks // n_types

    print(f"\n[3/4] Génération de {args.n_attacks} logs d'attaques "
          f"({n_types} types × ~{per_type} chacun)...")

    attack_docs = []
    for i, atk_name in enumerate(attack_names):
        count = per_type if i < n_types - 1 else args.n_attacks - i * per_type
        docs  = ATTACK_GENERATORS[atk_name](rng, count)
        attack_docs.extend(docs)
        print(f"  {atk_name:30s}: {len(docs)} logs")

    # Mélange normaux + attaques
    all_docs = normal_docs + attack_docs
    rng.shuffle(all_docs)

    # ── 4. Insertion ──────────────────────────────────────────────
    print(f"\n[4/4] Insertion dans {ES_TEST_INDEX}...")
    bulk_insert(all_docs, ctx, headers)

    # ── Export ground truth ───────────────────────────────────────
    export_ground_truth(all_docs)

    print("\n" + "=" * 65)
    print("  TERMINÉ")
    print(f"  Index ES   : {ES_TEST_INDEX}")
    print(f"  Ground truth: {GROUND_TRUTH_CSV}")
    print("=" * 65)
    print("""
  Étape suivante :
    python evaluate_moe_ae.py
  """)