import os
import subprocess
import requests
from datetime import datetime, timezone
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ─────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────
SIGMA_BIN  = "/home/hala-hamza/pfe-venv/bin/sigma"
SIGMA_PATH = os.path.expanduser("~/pfe-backend-2026/sigma/rules")
ES_HOST    = "https://localhost:9200"
ES_USER    = "elastic"
ES_PASS    = "pfe2026"
INDEX      = "filebeat-logs-*,auditbeat-*"
ALERT_INDEX = "sigma-alerts"

COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH"    : "\033[93m",
    "MEDIUM"  : "\033[94m",
    "LOW"     : "\033[96m",
    "OK"      : "\033[92m",
    "RESET"   : "\033[0m"
}

# ─────────────────────────────────────────
# RÈGLES AVEC AGRÉGATION
# ─────────────────────────────────────────
AGGREGATION_RULES = {
    "SSH Multiple Users from Same IP": {
        "index"      : "filebeat-logs-*",
        "level"      : "HIGH",
        "tactic"     : "T1110.004 - Credential Stuffing",
        "window_min" : 10,
        "group_by"   : "source.ip.keyword",
        "agg_field"  : "user.name.keyword",
        "threshold"  : 3,
        "query"      : {
            "bool": {
                "must": [
                    {"term": {"process.name" : "sshd"}},
                    {"term": {"event.outcome": "failure"}}
                ]
            }
        }
    },
    "SSH Rapid Connection Attempts": {
        "index"      : "filebeat-logs-*",
        "level"      : "HIGH",
        "tactic"     : "T1110.001 - Password Guessing",
        "window_min" : 10,
        "group_by"   : "source.ip.keyword",
        "agg_field"  : None,
        "threshold"  : 5,
        "query"      : {
            "bool": {
                "must": [
                    {"term": {"process.name" : "sshd"}},
                    {"term": {"event.outcome": "failure"}}
                ]
            }
        }
    },
    "SSH User Enumeration": {
        "index"      : "filebeat-logs-*",
        "level"      : "HIGH",
        "tactic"     : "T1078 - Valid Accounts",
        "window_min" : 10,
        "group_by"   : "source.ip.keyword",
        "agg_field"  : "user.name.keyword",
        "threshold"  : 3,
        "query"      : {
            "bool": {
                "must": [
                    {"term": {"process.name" : "sshd"}},
                    {"term": {"event.outcome": "failure"}}
                ]
            }
        }
    },
    "SSH Scanning Activity": {
        "index"      : "filebeat-logs-*",
        "level"      : "MEDIUM",
        "tactic"     : "T1046 - Network Service Discovery",
        "window_min" : 10,
        "group_by"   : None,
        "agg_field"  : "source.ip.keyword",
        "threshold"  : 5,
        "query"      : {
            "bool": {
                "must": [
                    {"term"        : {"process.name": "sshd"}},
                    {"match_phrase": {"message"     : "Connection closed"}}
                ]
            }
        }
    },
    "SSH Success After Multiple Failures": {
        "index"      : "filebeat-logs-*",
        "level"      : "CRITICAL",
        "tactic"     : "T1110 - Brute Force Success",
        "window_min" : 10,
        "group_by"   : "source.ip.keyword",
        "agg_field"  : None,
        "threshold"  : 0,
        "query"      : {
            "bool": {
                "must": [
                    {"term": {"process.name" : "sshd"}},
                    {"term": {"event.outcome": "success"}}
                ]
            }
        },
        "correlate_with": {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"process.name" : "sshd"}},
                        {"term": {"event.outcome": "failure"}}
                    ]
                }
            }
        }
    }
}

# ─────────────────────────────────────────
# SAUVEGARDE ALERTE DANS ES
# ─────────────────────────────────────────
def save_alert(title, level, tactic, hits, details):
    alert = {
        "@timestamp"     : datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "alert.title"    : title,
        "alert.level"    : level,
        "alert.tactic"   : tactic,
        "alert.hits"     : hits,
        "alert.details"  : details[:5] if isinstance(details, list) else [details],
        "alert.source"   : "sigma",
        "event.kind"     : "alert",
        "event.category" : "intrusion_detection"
    }
    try:
        r = requests.post(
            f"{ES_HOST}/{ALERT_INDEX}/_doc",
            auth=(ES_USER, ES_PASS),
            verify=False,
            json=alert
        )
        if r.status_code not in [200, 201]:
            print(f"  [WARN] Save alert failed: {r.status_code}")
    except Exception as e:
        print(f"  [ERROR] Save alert: {e}")

# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────
def get_rule_meta(path):
    title, level = os.path.basename(path), "UNKNOWN"
    try:
        with open(path) as f:
            for line in f:
                if line.startswith("title:"):
                    title = line.replace("title:", "").strip()
                if line.startswith("level:"):
                    level = line.replace("level:", "").strip().upper()
    except:
        pass
    return title, level

def sigma_to_lucene(path):
    try:
        # Ignorer les règles en status: test ou experimental
        with open(path) as f:
            for line in f:
                if line.strip().startswith("status:"):
                    if "test" in line:
                        return None
                    break
        r = subprocess.run(
            [SIGMA_BIN, "convert", "-t", "lucene",
             "--without-pipeline", path],
            capture_output=True
        )
        stdout = r.stdout.decode("utf-8", errors="replace").strip()
        return stdout if stdout else None
    except Exception as e:
        return None

def es_search(index, query, source_fields, size=5):
    try:
        r = requests.post(
            f"{ES_HOST}/{index}/_search",
            auth=(ES_USER, ES_PASS), verify=False,
            json={
                "size"   : size,
                "query"  : query,
                "_source": source_fields,
                "sort"   : [{"@timestamp": "desc"}]
            }
        )
        return r.json()
    except:
        return None

def es_aggregate(index, query, window_min, group_by, agg_field, threshold):
    if agg_field:
        inner_agg = {"unique": {"cardinality": {"field": agg_field}}}
    else:
        inner_agg = {}

    if group_by:
        aggs = {
            "groups": {
                "terms": {"field": group_by, "size": 50},
                "aggs" : inner_agg if inner_agg else {}
            }
        }
    else:
        aggs = {"total": {"value_count": {"field": "_id"}}}

    body = {
        "size" : 0,
        "query": {
            "bool": {
                "must"  : [query],
                "filter": [{"range": {"@timestamp": {"gte": f"now-{window_min}m"}}}]
            }
        },
        "aggs": aggs
    }
    try:
        r    = requests.post(f"{ES_HOST}/{index}/_search",
                             auth=(ES_USER, ES_PASS), verify=False, json=body)
        data = r.json()
        alerts = []
        if group_by:
            for bucket in data["aggregations"]["groups"]["buckets"]:
                count = bucket["unique"]["value"] if agg_field else bucket["doc_count"]
                if count > threshold:
                    alerts.append({"group": bucket["key"], "count": count})
        else:
            count = data["aggregations"]["total"]["value"]
            if count > threshold:
                alerts.append({"group": "global", "count": count})
        return alerts
    except:
        return []

def es_correlate(index, query, group_by, window_min):
    body = {
        "size" : 0,
        "query": {
            "bool": {
                "must"  : [query],
                "filter": [{"range": {"@timestamp": {"gte": f"now-{window_min}m"}}}]
            }
        },
        "aggs": {"groups": {"terms": {"field": group_by, "size": 50}}}
    }
    try:
        r    = requests.post(f"{ES_HOST}/{index}/_search",
                             auth=(ES_USER, ES_PASS), verify=False, json=body)
        data = r.json()
        return {b["key"] for b in data["aggregations"]["groups"]["buckets"]}
    except:
        return set()

def get_samples(index, query, window_min, source_ip=None):
    must = [query]
    if source_ip:
        must.append({"term": {"source.ip": source_ip}})
    body = {
        "size"   : 3,
        "query"  : {
            "bool": {
                "must"  : must,
                "filter": [{"range": {"@timestamp": {"gte": f"now-{window_min}m"}}}]
            }
        },
        "_source": ["@timestamp", "user.name", "source.ip",
                    "process.name", "message", "event.outcome"],
        "sort"   : [{"@timestamp": "desc"}]
    }
    try:
        r = requests.post(f"{ES_HOST}/{index}/_search",
                         auth=(ES_USER, ES_PASS), verify=False, json=body)
        return r.json()["hits"]["hits"]
    except:
        return []

def format_sample(hit):
    s    = hit["_source"]
    ts   = s.get("@timestamp", "")[:19]
    usr  = s.get("user",    {}).get("name", "")
    ip   = s.get("source",  {}).get("ip",   "")
    prc  = s.get("process", {}).get("name", "")
    msg  = s.get("message", "")[:70]
    ds   = s.get("event",   {}).get("dataset", "")

    # Construire l'info selon ce qui est disponible
    info_parts = [ts]
    if usr:
        info_parts.append(f"user={usr}")
    if ip:
        info_parts.append(f"ip={ip}")
    if prc:
        info_parts.append(f"process={prc}")
    if ds:
        info_parts.append(f"dataset={ds}")

    return " | ".join(info_parts) + f"\n    {msg}"

# ─────────────────────────────────────────
# AFFICHAGE
# ─────────────────────────────────────────
def print_alert(title, level, tactic, hits_info, hits_count=0):
    color = COLORS.get(level, COLORS["RESET"])
    print(f"\n{color}[ALERT]{COLORS['RESET']} {title}")
    print(f"  Level  : {color}{level}{COLORS['RESET']}")
    print(f"  Tactic : {tactic}")
    for info in hits_info:
        print(f"  → {info}")
    save_alert(title, level, tactic, hits_count, hits_info)

def print_ok(title):
    print(f"{COLORS['OK']}[OK]{COLORS['RESET']}    {title}")

# ─────────────────────────────────────────
# RÈGLES SIMPLES
# ─────────────────────────────────────────
def run_simple_rules(summary):
    AGG_TITLES = set(AGGREGATION_RULES.keys())
    for root, _, files in os.walk(SIGMA_PATH):
        for file in sorted(files):
            if not file.endswith(".yml"):
                continue
            path         = os.path.join(root, file)
            title, level = get_rule_meta(path)
            if title in AGG_TITLES:
                continue

            lucene = sigma_to_lucene(path)
            if not lucene:
                print(f"  [SKIP] {title}")
                continue

            data = es_search(
                INDEX,
                {"query_string": {"query": lucene, "default_field": "message"}},
                ["@timestamp", "process.name", "user.name",
                 "source.ip", "message", "event.outcome"]
            )
            if not data:
                continue

            count = data["hits"]["total"]["value"]
            if count > 0:
                hits_info = []
                for h in data["hits"]["hits"][:3]:
                    hits_info.append(format_sample(h))
                print_alert(title, level, "voir règle", hits_info, count)
                summary.append({"rule": title, "level": level, "hits": count})
            else:
                print_ok(title)

# ─────────────────────────────────────────
# RÈGLES AVEC AGRÉGATION
# ─────────────────────────────────────────
def run_aggregation_rules(summary):
    print(f"\n--- Règles avec agrégation ---\n")
    for title, rule in AGGREGATION_RULES.items():
        level      = rule["level"]
        index      = rule["index"]
        window_min = rule["window_min"]
        group_by   = rule["group_by"]
        agg_field  = rule["agg_field"]
        threshold  = rule["threshold"]
        query      = rule["query"]
        tactic     = rule["tactic"]

        # Corrélation succès après échecs
        if "correlate_with" in rule:
            success_ips = es_correlate(index, query, "source.ip.keyword", window_min)
            failure_ips = es_correlate(
                index, rule["correlate_with"]["query"],
                "source.ip.keyword", window_min
            )
            correlated = success_ips & failure_ips
            if correlated:
                hits_info = [
                    f"IP {ip} — succès SSH après échecs ({window_min}min)"
                    for ip in list(correlated)[:3]
                ]
                print_alert(title, level, tactic, hits_info, len(correlated))
                summary.append({"rule": title, "level": level, "hits": len(correlated)})
            else:
                print_ok(f"{title} (fenêtre: {window_min}min)")
            continue

        # Agrégation standard
        triggered = es_aggregate(index, query, window_min, group_by, agg_field, threshold)
        if triggered:
            hits_info = []
            total = 0
            for t in triggered[:5]:
                label = "users distincts" if agg_field else "connexions"
                hits_info.append(
                    f"IP {t['group']} → {t['count']} {label} en {window_min}min"
                )
                total += t["count"]
                for s in get_samples(index, query, window_min,
                                     source_ip=t["group"] if t["group"] != "global" else None)[:2]:
                    hits_info.append(f"  {format_sample(s)}")

            print_alert(title, level, tactic, hits_info, total)
            summary.append({"rule": title, "level": level, "hits": total})
        else:
            print_ok(f"{title} (fenêtre: {window_min}min, seuil: {threshold})")

# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
def main():
    summary = []
    print(f"\n{'='*65}")
    print(f"  SIGMA DETECTION ENGINE")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*65}\n")

    print("--- Règles simples ---\n")
    run_simple_rules(summary)
    run_aggregation_rules(summary)

    print(f"\n{'='*65}")
    print(f"  RÉSUMÉ : {len(summary)} règle(s) déclenchée(s)")
    print(f"{'='*65}")
    for lvl in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        for a in summary:
            if a["level"] == lvl:
                color = COLORS.get(lvl, COLORS["RESET"])
                print(f"  {color}[{lvl}]{COLORS['RESET']} {a['rule']} — {a['hits']} événement(s)")
    print(f"{'='*65}\n")

    print(f"  Alertes sauvegardées dans : {ALERT_INDEX}")

if __name__ == "__main__":
    main()


    #os-walk : parcourir les sous dossiers de SIGMA_PATH pour trouver les règles, les convertir en lucene, exécuter la requête sur ES, afficher les résultats et sauvegarder les alertes dans ES. Gérer aussi les règles avec agrégation et corrélation.