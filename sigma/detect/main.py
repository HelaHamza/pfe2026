"""
=============================================================================
SIGMA DETECTION ENGINE — version complète avec explication LLM
=============================================================================

MODIFICATIONS vs version originale :
  1. print_alert()          → retourne l'es_id du doc créé dans sigma-alerts
  2. run_simple_rules()     → retourne la liste des alertes avec es_id
  3. run_aggregation_rules()→ retourne la liste des alertes avec es_id
  4. explain_sigma_alerts() → génère une explication LLM pour chaque alerte
  5. main()                 → collecte toutes les alertes et appelle le LLM
=============================================================================
"""

import os
import subprocess
import requests
from datetime import datetime, timezone
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# =============================================================================
# CONFIG
# =============================================================================

SIGMA_BIN   = "/home/hala-hamza/pfe-venv/bin/sigma"
SIGMA_PATH  = os.path.expanduser("~/pfe-backend-2026/sigma/rules")
ES_HOST     = "https://localhost:9200"
ES_USER     = "elastic"
ES_PASS     = "pfe2026"
INDEX       = "filebeat-logs-*,auditbeat-*"
ALERT_INDEX = "sigma-alerts"

COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH"    : "\033[93m",
    "MEDIUM"  : "\033[94m",
    "LOW"     : "\033[96m",
    "OK"      : "\033[92m",
    "RESET"   : "\033[0m"
}

# =============================================================================
# RÈGLES AVEC AGRÉGATION
# =============================================================================

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

# =============================================================================
# SAUVEGARDE ALERTE DANS ES — retourne l'_id généré
# =============================================================================

def save_alert(title, level, tactic, hits, details) -> str:
    """Sauvegarde l'alerte dans sigma-alerts et retourne son _id ES."""
    alert = {
        "@timestamp"     : datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "alert.title"    : title,
        "alert.level"    : level,
        "alert.tactic"   : tactic,
        "alert.hits"     : hits,
        "alert.details"  : details[:5] if isinstance(details, list) else [details],
        "alert.source"   : "sigma",
        "event.kind"     : "alert",
        "event.category" : "intrusion_detection",
        "ae_correlated"  :    False,        # ← ajouter
        "detection_source": "sigma_only", # ← ajouter
    }
    try:
        r = requests.post(
            f"{ES_HOST}/{ALERT_INDEX}/_doc",
            auth=(ES_USER, ES_PASS),
            verify=False,
            json=alert
        )
        return r.json().get("_id")   # ← retourne l'ID pour mise à jour LLM
    except Exception as e:
        print(f"  [SIGMA] Save alert error: {e}")
        return None

# =============================================================================
# HELPERS
# =============================================================================

def get_rule_meta(path):
    title, level = os.path.basename(path), "UNKNOWN"
    try:
        with open(path) as f:
            for line in f:
                if line.startswith("title:"):
                    title = line.replace("title:", "").strip()
                if line.startswith("level:"):
                    level = line.replace("level:", "").strip().upper()
    except Exception:
        pass
    return title, level


def sigma_to_lucene(path):
    try:
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
    except Exception:
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
    except Exception:
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
    except Exception:
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
    except Exception:
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
    except Exception:
        return []


def format_sample(hit):
    s    = hit["_source"]
    ts   = s.get("@timestamp", "")[:19]
    usr  = s.get("user",    {}).get("name", "")
    ip   = s.get("source",  {}).get("ip",   "")
    prc  = s.get("process", {}).get("name", "")
    msg  = s.get("message", "")[:70]
    ds   = s.get("event",   {}).get("dataset", "")

    info_parts = [ts]
    if usr: info_parts.append(f"user={usr}")
    if ip:  info_parts.append(f"ip={ip}")
    if prc: info_parts.append(f"process={prc}")
    if ds:  info_parts.append(f"dataset={ds}")

    return " | ".join(info_parts) + f"\n    {msg}"

# =============================================================================
# AFFICHAGE
# =============================================================================

def print_alert(title, level, tactic, hits_info, hits_count=0) -> str:
    """Affiche l'alerte ET retourne l'es_id du doc sauvegardé."""
    color = COLORS.get(level, COLORS["RESET"])
    print(f"\n{color}[ALERT]{COLORS['RESET']} {title}")
    print(f"  Level  : {color}{level}{COLORS['RESET']}")
    print(f"  Tactic : {tactic}")
    for info in hits_info:
        print(f"  → {info}")
    return save_alert(title, level, tactic, hits_count, hits_info)  # retourne es_id


def print_ok(title):
    print(f"{COLORS['OK']}[OK]{COLORS['RESET']}    {title}")

# =============================================================================
# RÈGLES SIMPLES — retourne la liste des alertes avec es_id
# =============================================================================

def run_simple_rules(summary) -> list:
    """
    Parcourt les règles Sigma simples.
    Retourne une liste de dicts {title, level, tactic, hits, details, es_id}.
    """
    AGG_TITLES = set(AGGREGATION_RULES.keys())
    results    = []

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
                hits_info = [format_sample(h) for h in data["hits"]["hits"][:3]]
                es_id     = print_alert(title, level, "voir règle", hits_info, count)
                summary.append({"rule": title, "level": level, "hits": count})
                results.append({
                    "title":   title,
                    "level":   level,
                    "tactic":  "voir règle",
                    "hits":    count,
                    "details": hits_info,
                    "es_id":   es_id,
                })
            else:
                print_ok(title)

    return results

# =============================================================================
# RÈGLES AVEC AGRÉGATION — retourne la liste des alertes avec es_id
# =============================================================================

def run_aggregation_rules(summary) -> list:
    """
    Parcourt les règles Sigma avec agrégation/corrélation.
    Retourne une liste de dicts {title, level, tactic, hits, details, es_id}.
    """
    print(f"\n--- Règles avec agrégation ---\n")
    results = []

    for title, rule in AGGREGATION_RULES.items():
        level      = rule["level"]
        index      = rule["index"]
        window_min = rule["window_min"]
        group_by   = rule["group_by"]
        agg_field  = rule["agg_field"]
        threshold  = rule["threshold"]
        query      = rule["query"]
        tactic     = rule["tactic"]

        # ── Corrélation succès après échecs ───────────────────────
        if "correlate_with" in rule:
            success_ips = es_correlate(index, query,
                                       "source.ip.keyword", window_min)
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
                es_id = print_alert(title, level, tactic,
                                    hits_info, len(correlated))
                summary.append({"rule": title, "level": level,
                                 "hits": len(correlated)})
                results.append({
                    "title":   title,
                    "level":   level,
                    "tactic":  tactic,
                    "hits":    len(correlated),
                    "details": hits_info,
                    "es_id":   es_id,
                })
            else:
                print_ok(f"{title} (fenêtre: {window_min}min)")
            continue

        # ── Agrégation standard ────────────────────────────────────
        triggered = es_aggregate(index, query, window_min,
                                 group_by, agg_field, threshold)
        if triggered:
            hits_info = []
            total     = 0
            for t in triggered[:5]:
                label = "users distincts" if agg_field else "connexions"
                hits_info.append(
                    f"IP {t['group']} → {t['count']} {label} en {window_min}min"
                )
                total += t["count"]
                for s in get_samples(
                    index, query, window_min,
                    source_ip=t["group"] if t["group"] != "global" else None
                )[:2]:
                    hits_info.append(f"  {format_sample(s)}")

            es_id = print_alert(title, level, tactic, hits_info, total)
            summary.append({"rule": title, "level": level, "hits": total})
            results.append({
                "title":   title,
                "level":   level,
                "tactic":  tactic,
                "hits":    total,
                "details": hits_info,
                "es_id":   es_id,
            })
        else:
            print_ok(f"{title} (fenêtre: {window_min}min, seuil: {threshold})")

    return results

# =============================================================================
# EXPLICATION LLM DES ALERTES SIGMA
# =============================================================================

def explain_sigma_alerts(alerts: list):
    """
    Pour chaque alerte Sigma, génère une explication LLM en français
    et met à jour le document dans sigma-alerts via _update.

    Appelle call_llm_with_retry depuis rag_explainer.py
    → gère automatiquement le rate limit 429 de Groq.
    """
    import json
    import ssl
    import base64
    import urllib.request
    import sys
    import os

    # Ajouter le dossier ML au path pour trouver rag_explainer
    ml_dir = os.path.dirname(os.path.abspath(__file__))
    if ml_dir not in sys.path:
        sys.path.insert(0, ml_dir)
    sys.path.insert(0, os.path.expanduser("~/pfe-backend-2026/ML"))
    from rag_explainer import make_grok_client, call_llm_with_retry

    if not alerts:
        print("  [SIGMA-LLM] Aucune alerte à expliquer")
        return

    try:
        grok = make_grok_client()
    except ValueError as e:
        print(f"  [SIGMA-LLM] Skipped — {e}")
        return

    # Client urllib pour les updates ES
    ctx_ssl = ssl.create_default_context()
    ctx_ssl.check_hostname = False
    ctx_ssl.verify_mode    = ssl.CERT_NONE
    token   = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
    headers = {
        "Content-Type":  "application/json",
        "Authorization": f"Basic {token}",
    }

    print(f"\n  [SIGMA-LLM] Explication de {len(alerts)} alerte(s) Sigma...")
    ok, errors = 0, 0

    for alert in alerts:
        title   = alert["title"]
        level   = alert["level"]
        tactic  = alert["tactic"]
        hits    = alert["hits"]
        details = alert.get("details", [])
        es_id   = alert.get("es_id")

        # Construction du prompt
        details_str = "\n".join(f"  - {d}" for d in details[:5])
        prompt = f"""Tu es un expert SOC spécialisé en détection d'intrusion Linux.
Une règle Sigma a déclenché une alerte.

=== ALERTE SIGMA ===
Règle     : {title}
Niveau    : {level}
Technique : {tactic}
Hits      : {hits} événement(s) détecté(s)
Détails   :
{details_str}

=== INSTRUCTIONS ===
Réponds en français avec ces 4 sections numérotées :

1. **Type d'attaque probable**
   Explique ce que cette règle Sigma a détecté.

2. **Niveau de gravité** : [{level}]
   Justifie en 1-2 phrases.

3. **Analyse détaillée**
   Explique pourquoi ces événements sont suspects.
   Cite les valeurs (nombre de hits, IPs, users si disponibles).

4. **Actions recommandées**
   3-5 actions concrètes et priorisées pour le SOC.

Moins de 350 mots. Factuel uniquement.
"""
        messages = [
            {
                "role"   : "system",
                "content": (
                    "Tu es un expert SOC spécialisé en détection d'intrusion "
                    "sur systèmes Linux. Tu analyses des alertes de règles Sigma. "
                    "Tu réponds toujours en français, de manière concise et factuelle."
                ),
            },
            {"role": "user", "content": prompt},
        ]

        try:
            response    = call_llm_with_retry(grok, messages, max_tokens=500)
            explanation = response.choices[0].message.content
        except Exception as e:
            explanation = f"Erreur LLM : {type(e).__name__} — {e}"
            print(f"  [SIGMA-LLM] Erreur sur '{title}': {e}")

        # Mise à jour du doc dans sigma-alerts
        update_payload = {
            "llm_explanation": explanation,
            "llm_model"      : "llama-3.1-8b-instant",
            "prompt_tokens"  : len(prompt.split()),
        }

        if es_id and es_id not in ("", "None", "nan"):
            try:
                body = json.dumps({"doc": update_payload}).encode()
                req  = urllib.request.Request(
                    f"{ES_HOST}/{ALERT_INDEX}/_update/{es_id}",
                    data=body, headers=headers, method="POST"
                )
                urllib.request.urlopen(req, context=ctx_ssl)
                ok += 1
                print(f"  [SIGMA-LLM] ✓ {level:8s} | {title[:55]}")
            except Exception as e:
                errors += 1
                print(f"  [SIGMA-LLM] Update error {es_id}: {e}")
        else:
            errors += 1
            print(f"  [SIGMA-LLM] ⚠ pas d'es_id pour '{title}'")

    print(f"  [SIGMA-LLM] Terminé — {ok} explications sauvegardées | {errors} erreurs")

# =============================================================================
# MAIN
# =============================================================================

def main():
    summary    = []
    all_alerts = []

    print(f"\n{'='*65}")
    print(f"  SIGMA DETECTION ENGINE")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*65}\n")

    # ── Règles simples ────────────────────────────────────────────
    print("--- Règles simples ---\n")
    all_alerts += run_simple_rules(summary)

    # ── Règles avec agrégation ────────────────────────────────────
    all_alerts += run_aggregation_rules(summary)

    # ── Résumé ────────────────────────────────────────────────────
    print(f"\n{'='*65}")
    print(f"  RÉSUMÉ : {len(summary)} règle(s) déclenchée(s)")
    print(f"{'='*65}")
    for lvl in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        for a in summary:
            if a["level"] == lvl:
                color = COLORS.get(lvl, COLORS["RESET"])
                print(f"  {color}[{lvl}]{COLORS['RESET']} "
                      f"{a['rule']} — {a['hits']} événement(s)")
    print(f"{'='*65}\n")
    print(f"  Alertes sauvegardées dans : {ALERT_INDEX}")

    # ── Explication LLM de toutes les alertes ─────────────────────
    import sys as _sys, os as _os
    for _p in [
        _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), '..', '..', 'core'),
        _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), '..', '..', 'ML'),
    ]:
        if _p not in _sys.path:
            _sys.path.insert(0, _p)
    from fusion_router import FusionRouter
    router = FusionRouter()
    router._sigma_alerts_cache = []
    router.process_sigma_alerts(all_alerts)


if __name__ == "__main__":
    main()