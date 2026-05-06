
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
 from datetime import datetime, timezone
import random, numpy as np, pandas as pd

np.random.seed(42)


es = Elasticsearch(
    "https://localhost:9200",
    basic_auth=("elastic", "pfe2026"),
    verify_certs=False,
    ssl_show_warn=False,
    request_timeout=120,
    max_retries=5,
    retry_on_timeout=True
)

def hour_features(h):
    return {
        "hour_of_day": h,
        "is_off_hours": 1 if h <= 6 else 0,
        "is_night": 1 if h >= 22 or h <= 5 else 0,
        "is_weekend": 0,
        "is_business": 1 if 9 <= h <= 18 else 0,
        "hour_sin": round(np.sin(2 * np.pi * h / 24), 4),
        "hour_cos": round(np.cos(2 * np.pi * h / 24), 4),
    }

records = []

# 200 logs normaux
for _ in range(200):
    h = int(np.random.choice(range(8, 20)))
    src = np.random.choice(["syslog","auth","auditd"], p=[0.3,0.4,0.3])
    records.append({
        "label": "normal", "log_source": src,
        "log_source_encoded": {"syslog":0,"auth":1,"auditd":2}[src],
        **hour_features(h),
        "auth_type": np.random.choice(["ssh_success","pam_session_open","other"]),
        "auth_user_sensitivity": 0, "auth_is_root": 0,
        "auth_ip_is_external": 0, "auth_known_country": 1,
        "auth_fail_count_5m": np.random.randint(0,2),
        "auth_fail_ratio": round(np.random.uniform(0,0.2),3),
        "auth_users_tried": 1, "auth_is_brute_force": 0,
        "auth_is_user_enum": 0, "auth_severity": np.random.randint(0,3),
        "auth_sev_norm": round(np.random.uniform(0,0.15),4),
        "auth_user_created": 0, "auth_sudo_to_root": 0,
        "aud_syscall_category": "exec", "aud_ptrace": 0,
        "aud_process_injection": 0, "aud_execve": 1,
        "aud_suspicious_exec": 0, "aud_path_etc_passwd": 0,
        "aud_path_ssh_keys": 0, "aud_path_sudoers": 0,
        "aud_path_boot_persist": 0, "aud_log_tamper": 0,
        "aud_path_tmp": 0, "aud_setuid_call": 0,
        "aud_is_root_exec": 0, "aud_key_sensitive": 0,
        "aud_network_connect": 0,
        "aud_cmd_entropy": round(np.random.uniform(2.5,3.8),4),
        "aud_cmd_length_log": round(np.random.uniform(1.5,3.5),4),
        "aud_cmd_is_obfuscated": 0,
        "aud_severity": np.random.randint(0,3),
        "aud_sev_norm": round(np.random.uniform(0,0.12),4),
        "sys_oom_kill": 0, "sys_module_load": 0,
        "sys_cron_new_job": 0, "sys_firewall_change": 0,
        "sys_service_crash_loop": 0,
        "sys_msg_length_log": round(np.random.uniform(2.0,4.5),4),
        "msg_length_log": round(np.random.uniform(2.5,5.0),4),
        "msg_has_base64": 0, "msg_has_url": 0,
        "user_sensitivity": 0, "is_root": 0,
        "freq_syscall_count_1h": np.random.randint(5,80),
        "freq_syscall_count_10m": np.random.randint(1,15),
        "freq_unique_syscalls": np.random.randint(1,8),
        "freq_unique_files": np.random.randint(0,20),
        "freq_spike_ratio": round(np.random.uniform(0.1,0.4),3),
        "cross_ssh_then_sudo": 0, "cross_bruteforce_success": 0,
        "cross_auth_then_exec": 0, "cross_multi_source": 0,
        "cross_max_sev_window": np.random.randint(0,3),
        "composite_score": np.random.randint(0,4),
        "composite_score_norm": round(np.random.uniform(0,0.13),4),
        "is_anomaly_candidate": 0,
    })

# 30 logs d'attaque
attacks = [
    {"label":"attack","log_source":"auth","log_source_encoded":1,
     **hour_features(3),
     "auth_type":"ssh_success","auth_user_sensitivity":2,"auth_is_root":1,
     "auth_ip_is_external":1,"auth_known_country":0,
     "auth_fail_count_5m":47,"auth_fail_ratio":0.979,
     "auth_users_tried":1,"auth_is_brute_force":1,"auth_is_user_enum":0,
     "auth_severity":12,"auth_sev_norm":0.75,
     "auth_user_created":0,"auth_sudo_to_root":1,
     "aud_syscall_category":"exec","aud_ptrace":0,"aud_process_injection":0,
     "aud_execve":1,"aud_suspicious_exec":1,"aud_path_etc_passwd":0,
     "aud_path_ssh_keys":0,"aud_path_sudoers":0,"aud_path_boot_persist":0,
     "aud_log_tamper":0,"aud_path_tmp":1,"aud_setuid_call":1,
     "aud_is_root_exec":1,"aud_key_sensitive":1,"aud_network_connect":1,
     "aud_cmd_entropy":3.8,"aud_cmd_length_log":4.2,"aud_cmd_is_obfuscated":0,
     "aud_severity":8,"aud_sev_norm":0.31,
     "sys_oom_kill":0,"sys_module_load":0,"sys_cron_new_job":0,
     "sys_firewall_change":0,"sys_service_crash_loop":0,"sys_msg_length_log":3.5,
     "msg_length_log":5.2,"msg_has_base64":0,"msg_has_url":0,
     "user_sensitivity":2,"is_root":1,
     "freq_syscall_count_1h":180,"freq_syscall_count_10m":95,
     "freq_unique_syscalls":12,"freq_unique_files":35,"freq_spike_ratio":0.83,
     "cross_ssh_then_sudo":1,"cross_bruteforce_success":1,
     "cross_auth_then_exec":1,"cross_multi_source":1,"cross_max_sev_window":12,
     "composite_score":22,"composite_score_norm":0.73,"is_anomaly_candidate":1},
    {"label":"attack","log_source":"auditd","log_source_encoded":2,
     **hour_features(2),
     "auth_type":"other","auth_user_sensitivity":3,"auth_is_root":1,
     "auth_ip_is_external":0,"auth_known_country":1,
     "auth_fail_count_5m":0,"auth_fail_ratio":0.0,
     "auth_users_tried":1,"auth_is_brute_force":0,"auth_is_user_enum":0,
     "auth_severity":3,"auth_sev_norm":0.19,
     "auth_user_created":0,"auth_sudo_to_root":0,
     "aud_syscall_category":"injection","aud_ptrace":1,"aud_process_injection":1,
     "aud_execve":0,"aud_suspicious_exec":0,"aud_path_etc_passwd":0,
     "aud_path_ssh_keys":0,"aud_path_sudoers":0,"aud_path_boot_persist":0,
     "aud_log_tamper":0,"aud_path_tmp":1,"aud_setuid_call":0,
     "aud_is_root_exec":0,"aud_key_sensitive":1,"aud_network_connect":0,
     "aud_cmd_entropy":3.1,"aud_cmd_length_log":3.2,"aud_cmd_is_obfuscated":0,
     "aud_severity":14,"aud_sev_norm":0.54,
     "sys_oom_kill":0,"sys_module_load":0,"sys_cron_new_job":0,
     "sys_firewall_change":0,"sys_service_crash_loop":0,"sys_msg_length_log":3.0,
     "msg_length_log":4.5,"msg_has_base64":0,"msg_has_url":0,
     "user_sensitivity":3,"is_root":1,
     "freq_syscall_count_1h":25,"freq_syscall_count_10m":20,
     "freq_unique_syscalls":4,"freq_unique_files":3,"freq_spike_ratio":0.91,
     "cross_ssh_then_sudo":0,"cross_bruteforce_success":0,
     "cross_auth_then_exec":0,"cross_multi_source":0,"cross_max_sev_window":14,
     "composite_score":19,"composite_score_norm":0.63,"is_anomaly_candidate":1},
    {"label":"attack","log_source":"syslog","log_source_encoded":0,
     **hour_features(1),
     "auth_type":"none","auth_user_sensitivity":3,"auth_is_root":1,
     "auth_ip_is_external":0,"auth_known_country":1,
     "auth_fail_count_5m":0,"auth_fail_ratio":0.0,
     "auth_users_tried":0,"auth_is_brute_force":0,"auth_is_user_enum":0,
     "auth_severity":3,"auth_sev_norm":0.19,
     "auth_user_created":1,"auth_sudo_to_root":0,
     "aud_syscall_category":"module","aud_ptrace":0,"aud_process_injection":0,
     "aud_execve":0,"aud_suspicious_exec":0,"aud_path_etc_passwd":0,
     "aud_path_ssh_keys":0,"aud_path_sudoers":0,"aud_path_boot_persist":1,
     "aud_log_tamper":1,"aud_path_tmp":0,"aud_setuid_call":0,
     "aud_is_root_exec":1,"aud_key_sensitive":1,"aud_network_connect":0,
     "aud_cmd_entropy":3.2,"aud_cmd_length_log":3.8,"aud_cmd_is_obfuscated":0,
     "aud_severity":18,"aud_sev_norm":0.69,
     "sys_oom_kill":0,"sys_module_load":1,"sys_cron_new_job":1,
     "sys_firewall_change":1,"sys_service_crash_loop":0,"sys_msg_length_log":3.8,
     "msg_length_log":5.0,"msg_has_base64":0,"msg_has_url":0,
     "user_sensitivity":3,"is_root":1,
     "freq_syscall_count_1h":15,"freq_syscall_count_10m":12,
     "freq_unique_syscalls":6,"freq_unique_files":8,"freq_spike_ratio":0.85,
     "cross_ssh_then_sudo":0,"cross_bruteforce_success":0,
     "cross_auth_then_exec":1,"cross_multi_source":1,"cross_max_sev_window":18,
     "composite_score":25,"composite_score_norm":0.83,"is_anomaly_candidate":1},
]

for i in range(30):
    base = attacks[i % len(attacks)].copy()
    base["freq_syscall_count_1h"] = max(0, base["freq_syscall_count_1h"] + random.randint(-3,4))
    base["composite_score_norm"]  = round(min(1.0, max(0.0, base["composite_score_norm"] + random.uniform(-0.05,0.05))), 4)
    records.append(base)

def gen_actions(records):
    for rec in records:
       

        ts = datetime.now(timezone.utc) - timedelta(
             hours=random.randint(0,23),
             minutes=random.randint(0,59)
)
        src = rec.get("log_source","unknown")
        yield {
            "_index": f"ml-logs-{ts.strftime('%Y.%m.%d')}",
            "_source": {
                "@timestamp": ts.isoformat(),
                "event": {
                    "dataset": {"syslog":"system.syslog","auth":"system.auth","auditd":"auditd.kernel"}.get(src,"unknown"),
                    "module":  "auditd" if src == "auditd" else "system"
                },
                "ml": {k:v for k,v in rec.items() if k != "label"},
                "debug_label": rec.get("label","unknown")
            }
        }
print("Connexion ES OK :", es.info()["cluster_name"])
print(es.ping())        # doit afficher True
print(es.info())        # doit afficher cluster info
ok, err = bulk(
    es,
    gen_actions(records),
    chunk_size=200,          # 🔥 CRITIQUE
    max_retries=3,
    request_timeout=60,
    raise_on_error=False
)
print(f"Injectés : {ok} | Erreurs : {len(err) if err else 0}")
