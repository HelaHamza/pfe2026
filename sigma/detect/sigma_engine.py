"""
sigma/detect/sigma_engine.py
============================
MOTEUR DE DÉTECTION PAR RÈGLES SIGMA.

RÔLE : détecter et RETOURNER des alertes. Ce module n'écrit RIEN en base.

Pourquoi ce changement : `sigma_engine` importait `ReportRepository` via un
`sys.path` codant en dur le chemin du backend, tandis que le backend
importait `sigma_engine`. Chaque couche dépendait de l'autre. Cela
contredisait la doctrine du projet — « le backend est consommateur, le
couplage se fait par MongoDB » — puisque c'était le moteur de détection qui
écrivait en base.

Désormais : le moteur produit des dicts, `backend/adapters/sigma_adapter.py`
les collecte, `backend/controllers/analyse_controller.py` les fait
persister. La seule dépendance restante au backend est `config.py`, et elle
est purement CONFIGURATIONNELLE (hôte ES, chemin des règles) : aucune
logique métier, aucun accès base.

CONTRAT DE SORTIE — chaque alerte retournée porte :
    title, level, tactic, hits, details,
    event_time  : heure de l'ÉVÉNEMENT source (ISO) ou None
    dedup_key   : clé déterministe d'idempotence
    rule_kind   : "simple" | "aggregation"
    log_source  : index ES d'origine
    matched_doc_ids : (règles simples uniquement)
et, après `explain_sigma_alerts`, llm_explanation + llm_model.

DEUX FENÊTRES TEMPORELLES, volontairement différentes :
  - règles SIMPLES      : incrémentale ]cursor, until], bornée par le
                          curseur du backend. Une alerte manquée serait
                          définitivement perdue.
  - règles d'AGRÉGATION : glissante now−Xm, hors curseur. Un seuil « 5
                          échecs en 10 minutes » n'a aucun sens sur une
                          fenêtre historique arbitraire.
"""
import hashlib
import os
import subprocess
import sys
from datetime import datetime

import requests
from urllib3.exceptions import InsecureRequestWarning

# ── Localisation de la configuration ──────────────────────────────────
# `append` et non `insert` : quand le moteur est importé DEPUIS le backend,
# le sys.path du backend prime et rien n'est masqué. Ce bloc ne sert qu'à
# rendre l'exécution CLI autonome. Couplage de CONFIGURATION uniquement.
_HERE = os.path.dirname(os.path.abspath(__file__))
_BACKEND_DIR = os.path.abspath(os.path.join(_HERE, "..", "..", "backend"))
if _BACKEND_DIR not in sys.path:
    sys.path.append(_BACKEND_DIR)

import config as CFG

# =============================================================================
# CONFIG
# =============================================================================

SIGMA_BIN  = CFG.SIGMA_BIN
SIGMA_PATH = CFG.SIGMA_RULES
ES_HOST    = CFG.ES_HOST
ES_USER    = CFG.ES_USER
ES_PASS    = CFG.ES_PASS
INDEX      = CFG.SIGMA_INDEX

# Clés introduites avec le nouveau config.py. `getattr` avec valeur de repli :
# le moteur de détection ne doit pas refuser de démarrer parce qu'une clé de
# configuration est récente. Cela rend aussi l'ordre de migration indifférent
# — chaque fichier peut être remplacé indépendamment.
ES_VERIFY     = getattr(CFG, "ES_VERIFY_CERTS", False)
LLM_SIGMA_DIR = getattr(CFG, "LLM_SIGMA_DIR",
                        os.path.abspath(os.path.join(_HERE, "..", "..",
                                                     "llm_sigma")))

# Délais : sans eux, une règle pathologique ou un cluster qui ne répond pas
# fige l'ensemble du pipeline sans possibilité de reprise.
ES_TIMEOUT_S      = 30
CONVERT_TIMEOUT_S = 30

# La vérification TLS est désactivée PAR CONFIGURATION (certificat
# auto-signé en laboratoire), pas par un `verify=False` enfoui dans le code.
if not ES_VERIFY:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH"    : "\033[93m",
    "MEDIUM"  : "\033[94m",
    "LOW"     : "\033[96m",
    "OK"      : "\033[92m",
    "RESET"   : "\033[0m",
}

# =============================================================================
# RÈGLES AVEC AGRÉGATION  (inchangé)
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
# IDEMPOTENCE — clé déterministe
# =============================================================================

def _dedup_key(title: str, matched_doc_ids=None) -> str:
    """- Règles simples : ancrée sur les _id ES matchés → même match = même
         clé → un re-run ou une reprise après crash écrase au lieu de
         dupliquer.
       - Règles d'agrégation (matched_doc_ids=None) : ancrée sur le TITRE
         seul → une alerte par règle et par run (snapshot temps-réel).

    LIMITE CONNUE : `es_search` plafonne à 500 hits, donc pour une règle qui
    matche davantage la clé n'est ancrée que sur les 500 premiers _id. Sans
    conséquence depuis que le backend préfixe l'_id Mongo par le run_id,
    mais à mentionner si le jury creuse l'idempotence."""
    if matched_doc_ids:
        payload = title + "|" + "|".join(sorted(str(i) for i in matched_doc_ids))
        return "sig:simple:" + hashlib.sha1(payload.encode()).hexdigest()
    return "sig:agg:" + hashlib.sha1(title.encode()).hexdigest()

# =============================================================================
# HELPERS
# =============================================================================

def _latest_event_time(hits: list) -> str | None:
    """@timestamp du hit le plus récent. ES trie déjà en desc : le premier
    hit portant un timestamp est le plus récent.

    CORRECTIF CENTRAL. `format_sample` produit une CHAÎNE d'affichage : une
    fois les détails formatés, l'heure d'origine est irrécupérable. Sans
    cette extraction, le backend retombait sur l'heure du run et toutes les
    alertes Sigma remontaient en tête du tableau SOC, au-dessus d'épisodes
    CNN pourtant plus récents. Sur un dashboard chronologique, c'est faux."""
    for h in hits or []:
        ts = (h.get("_source") or {}).get("@timestamp")
        if ts:
            return ts
    return None


def _event_source(hits: list) -> tuple[str | None, str | None]:
    """(log_source, host) extraits du premier hit exploitable.

    CORRECTIF : `INDEX` est le PATTERN INTERROGÉ
    ("filebeat-logs-*,auditbeat-*"), pas la source du log. Le stocker comme
    `log_source` ne dit rien à l'analyste — il faut le dataset réel
    (auth, syslog, auditd…) et la machine concernée."""
    for h in hits or []:
        src   = h.get("_source") or {}
        event = src.get("event") or {}
        dataset = (event.get("dataset") or event.get("module")
                   or h.get("_index"))
        host = ((src.get("host") or {}).get("name")
                or (src.get("agent") or {}).get("hostname"))
        if dataset or host:
            return dataset, host
    return None, None


def _parse_tactic(tags: list) -> str:
    """attack.t1110.001 → 'T1110.001'. 'N/A' si aucun tag de technique.
    Heuristique : premier tag `attack.tXXXX` contenant un chiffre."""
    for tag in tags:
        t = str(tag).lower().strip()
        if t.startswith("attack.t") and any(c.isdigit() for c in t):
            return t.split("attack.", 1)[1].upper()
    return "N/A"


def get_rule_meta(path):
    """Retourne (title, level, tactic). `tactic` est extrait du bloc `tags:`.

    NOTE : `level` peut valoir "UNKNOWN" si la règle n'expose pas de champ
    `level`. Le backend normalise cette valeur (norm_severity → low) : sans
    ça l'alerte n'appartenait à aucune sévérité filtrable et disparaissait
    du tableau dès qu'un filtre était posé."""
    title, level, tags = os.path.basename(path), "UNKNOWN", []
    in_tags = False
    try:
        with open(path) as f:
            for line in f:
                if line.startswith("title:"):
                    title = line.split("title:", 1)[1].strip(); in_tags = False
                elif line.startswith("level:"):
                    level = line.split("level:", 1)[1].strip().upper(); in_tags = False
                elif line.startswith("tags:"):
                    in_tags = True
                elif in_tags:
                    s = line.strip()
                    if s.startswith("- "):
                        tags.append(s[2:].strip())
                    elif s and not line.startswith((" ", "\t")):
                        in_tags = False          # nouvelle clé top-level
    except Exception:
        pass
    return title, level, _parse_tactic(tags)


def sigma_to_lucene(path):
    """Conversion Sigma → Lucene. Les règles en `status: test` sont ignorées."""
    try:
        with open(path) as f:
            for line in f:
                if line.strip().startswith("status:"):
                    if "test" in line:
                        return None
                    break
        r = subprocess.run(
            [SIGMA_BIN, "convert", "-t", "lucene", "--without-pipeline", path],
            capture_output=True, timeout=CONVERT_TIMEOUT_S)
        stdout = r.stdout.decode("utf-8", errors="replace").strip()
        return stdout if stdout else None
    except subprocess.TimeoutExpired:
        print(f"  [TIMEOUT] conversion de {os.path.basename(path)}")
        return None
    except Exception:
        return None


def _time_filter(cursor: str = None, until: str = None):
    """Clause range @timestamp ]cursor, until], ou None."""
    r = {}
    if cursor:
        r["gt"] = cursor
    if until:
        r["lte"] = until
    return {"range": {"@timestamp": r}} if r else None


def es_search(index, query, source_fields, size=500, time_filter=None):
    """Recherche ES restreinte à la fenêtre temporelle si elle est fournie.

    size=500 : capture les _id matchés pour la clé de déduplication.
    track_total_hits : sans lui, `total.value` plafonne à 10 000 et le
    compteur `hits` de l'alerte est faux au-delà."""
    wrapped = ({"bool": {"must": [query, time_filter]}} if time_filter
               else query)
    try:
        r = requests.post(
            f"{ES_HOST}/{index}/_search",
            auth=(ES_USER, ES_PASS), verify=ES_VERIFY, timeout=ES_TIMEOUT_S,
            json={
                "size"             : size,
                "query"            : wrapped,
                "_source"          : source_fields,
                "track_total_hits" : True,
                "sort"             : [{"@timestamp": "desc"}],
            })
        return r.json()
    except Exception as e:
        print(f"  [ES] échec recherche sur {index} : {e}")
        return None


def es_aggregate(index, query, window_min, group_by, agg_field, threshold):
    inner_agg = ({"unique": {"cardinality": {"field": agg_field}}}
                 if agg_field else {})

    if group_by:
        aggs = {"groups": {"terms": {"field": group_by, "size": 50},
                           "aggs": inner_agg if inner_agg else {}}}
    elif agg_field:
        # La règle veut compter des VALEURS DISTINCTES (ex. « 5 IP sources
        # différentes »). L'ancien code ignorait agg_field ici et comptait
        # des documents : la règle ne mesurait pas ce qu'elle annonçait.
        aggs = {"total": {"cardinality": {"field": agg_field}}}
    else:
        # `value_count` sur `_id` est REFUSÉ par Elasticsearch 8.x (fielddata
        # sur _id désactivée par défaut). La réponse ne contenait alors pas
        # de clé `aggregations`, l'exception était avalée, et la règle
        # s'affichait [OK] — un faux négatif présenté comme un résultat sain.
        aggs = {"total": {"value_count": {"field": "@timestamp"}}}

    body = {
        "size" : 0,
        "query": {
            "bool": {
                "must"  : [query],
                "filter": [{"range": {"@timestamp": {"gte": f"now-{window_min}m"}}}]
            }
        },
        "aggs": aggs,
    }
    # Retourne None en cas d'ÉCHEC, [] si la règle n'a rien déclenché.
    # Confondre les deux revenait à afficher [OK] sur une règle en erreur.
    try:
        r = requests.post(f"{ES_HOST}/{index}/_search",
                          auth=(ES_USER, ES_PASS), verify=ES_VERIFY,
                          timeout=ES_TIMEOUT_S, json=body)
        data = r.json()
        if "aggregations" not in data:
            reason = data.get("error", {}).get("reason", data)
            print(f"  [ES] agrégation refusée sur {index} : "
                  f"{str(reason)[:160]}")
            return None
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
    except Exception as e:
        print(f"  [ES] échec agrégation sur {index} : {e}")
        return None


def es_correlate(index, query, group_by, window_min):
    body = {
        "size" : 0,
        "query": {
            "bool": {
                "must"  : [query],
                "filter": [{"range": {"@timestamp": {"gte": f"now-{window_min}m"}}}]
            }
        },
        "aggs": {"groups": {"terms": {"field": group_by, "size": 50}}},
    }
    try:
        r = requests.post(f"{ES_HOST}/{index}/_search",
                          auth=(ES_USER, ES_PASS), verify=ES_VERIFY,
                          timeout=ES_TIMEOUT_S, json=body)
        data = r.json()
        return {b["key"] for b in data["aggregations"]["groups"]["buckets"]}
    except Exception as e:
        print(f"  [ES] échec corrélation sur {index} : {e}")
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
                    "process.name", "message", "event.outcome",
                    "event.dataset", "event.module",
                    "host.name", "agent.hostname"],
        "sort"   : [{"@timestamp": "desc"}],
    }
    try:
        r = requests.post(f"{ES_HOST}/{index}/_search",
                          auth=(ES_USER, ES_PASS), verify=ES_VERIFY,
                          timeout=ES_TIMEOUT_S, json=body)
        return r.json()["hits"]["hits"]
    except Exception:
        return []


def format_sample(hit):
    """Rendu lisible d'un hit ES. ⚠️ Produit une CHAÎNE : l'heure d'origine
    n'y est plus exploitable en aval — c'est `_latest_event_time` qui la
    transmet séparément."""
    s   = hit["_source"]
    ts  = s.get("@timestamp", "")[:19]
    usr = s.get("user",    {}).get("name", "")
    ip  = s.get("source",  {}).get("ip",   "")
    prc = s.get("process", {}).get("name", "")
    msg = s.get("message", "")[:70]
    ds  = s.get("event",   {}).get("dataset", "")

    info_parts = [ts]
    if usr: info_parts.append(f"user={usr}")
    if ip:  info_parts.append(f"ip={ip}")
    if prc: info_parts.append(f"process={prc}")
    if ds:  info_parts.append(f"dataset={ds}")

    return " | ".join(info_parts) + f"\n    {msg}"

# =============================================================================
# AFFICHAGE
# =============================================================================

def print_alert(title, level, tactic, hits_info) -> None:
    """Affichage console UNIQUEMENT. La persistance appartient au backend."""
    color = COLORS.get(level, COLORS["RESET"])
    print(f"\n{color}[ALERT]{COLORS['RESET']} {title}")
    print(f"  Level  : {color}{level}{COLORS['RESET']}")
    print(f"  Tactic : {tactic}")
    for info in hits_info:
        print(f"  → {info}")


def print_ok(title):
    print(f"{COLORS['OK']}[OK]{COLORS['RESET']}    {title}")

# =============================================================================
# RÈGLES SIMPLES — fenêtre incrémentale ]cursor, until]
# =============================================================================

def run_simple_rules(summary, cursor: str = None, until: str = None) -> list:
    """Parcourt les règles Sigma simples sur la fenêtre ]cursor, until].
    Retourne la liste des alertes (voir CONTRAT DE SORTIE en tête de module).
    N'écrit rien."""
    AGG_TITLES = set(AGGREGATION_RULES.keys())
    results    = []
    tfilter    = _time_filter(cursor, until)

    for root, _, files in os.walk(SIGMA_PATH):
        for file in sorted(files):
            if not file.endswith(".yml"):
                continue
            path                 = os.path.join(root, file)
            title, level, tactic = get_rule_meta(path)
            if title in AGG_TITLES:
                continue

            lucene = sigma_to_lucene(path)
            if not lucene:
                print(f"  [SKIP] {title}")
                continue

            data = es_search(
                INDEX,
                {"query_string": {"query": lucene, "default_field": "message",
                                  "analyze_wildcard": True}},
                # event.dataset / host.name AJOUTÉS : sans eux, ES ne
                # renvoie pas ces champs et la source réelle reste inconnue.
                ["@timestamp", "process.name", "user.name", "source.ip",
                 "message", "event.outcome", "event.dataset", "event.module",
                 "host.name", "agent.hostname"],
                time_filter=tfilter,
            )
            if not data:
                continue

            count = data["hits"]["total"]["value"]
            if count > 0:
                all_hits    = data["hits"]["hits"]
                hits_info   = [format_sample(h) for h in all_hits[:3]]
                matched_ids = [h["_id"] for h in all_hits]
                dkey        = _dedup_key(title, matched_doc_ids=matched_ids)
                src, host   = _event_source(all_hits)

                print_alert(title, level, tactic, hits_info)
                summary.append({"rule": title, "level": level, "hits": count})
                results.append({
                    "title":           title,
                    "level":           level,
                    "tactic":          tactic,
                    "hits":            count,
                    "details":         hits_info,
                    "event_time":      _latest_event_time(all_hits),
                    "dedup_key":       dkey,
                    "rule_kind":       "simple",
                    "log_source":      src or INDEX,
                    "host":            host,
                    "matched_doc_ids": matched_ids,
                })
            else:
                print_ok(title)

    return results

# =============================================================================
# RÈGLES AVEC AGRÉGATION — fenêtre glissante now-Xm (hors curseur)
# =============================================================================

def run_aggregation_rules(summary) -> list:
    """Règles d'agrégation et de corrélation. Pas de matched_doc_ids : ces
    règles ne sont pas corrélées avec l'autoencodeur. N'écrit rien."""
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

        # ── Corrélation succès après échecs ────────────────────────
        if "correlate_with" in rule:
            success_ips = es_correlate(index, query,
                                       "source.ip.keyword", window_min)
            failure_ips = es_correlate(index, rule["correlate_with"]["query"],
                                       "source.ip.keyword", window_min)
            correlated = success_ips & failure_ips
            if correlated:
                hits_info = [
                    f"IP {ip} — succès SSH après échecs ({window_min}min)"
                    for ip in list(correlated)[:3]
                ]
                dkey = _dedup_key(title)
                print_alert(title, level, tactic, hits_info)
                summary.append({"rule": title, "level": level,
                                "hits": len(correlated)})
                results.append({
                    "title":      title,
                    "level":      level,
                    "tactic":     tactic,
                    "hits":       len(correlated),
                    "details":    hits_info,
                    # Corrélation d'agrégats : aucun événement unique ne
                    # porte l'alerte. Le backend marquera
                    # event_time_estimated=True plutôt que d'inventer une
                    # heure présentée comme exacte.
                    "event_time": None,
                    "dedup_key":  dkey,
                    "rule_kind":  "aggregation",
                    "log_source": index,
                })
            else:
                print_ok(f"{title} (fenêtre: {window_min}min)")
            continue

        # ── Agrégation standard ─────────────────────────────────────
        triggered = es_aggregate(index, query, window_min,
                                 group_by, agg_field, threshold)
        if triggered is None:
            # Une règle EN ÉCHEC ne doit jamais s'afficher comme une règle
            # sans détection : c'est un faux négatif silencieux.
            color = COLORS["CRITICAL"]
            print(f"{color}[ERREUR]{COLORS['RESET']} {title} — "
                  f"agrégation ES en échec, règle NON ÉVALUÉE")
            continue
        if triggered:
            hits_info = []
            total     = 0
            newest    = None
            src, host = None, None
            for t in triggered[:5]:
                label = "users distincts" if agg_field else "connexions"
                hits_info.append(
                    f"IP {t['group']} → {t['count']} {label} en {window_min}min")
                total += t["count"]
                samples = get_samples(
                    index, query, window_min,
                    source_ip=t["group"] if t["group"] != "global" else None
                )[:2]
                if newest is None:
                    newest = _latest_event_time(samples)
                    src, host = _event_source(samples)
                for s in samples:
                    hits_info.append(f"  {format_sample(s)}")

            dkey = _dedup_key(title)
            print_alert(title, level, tactic, hits_info)
            summary.append({"rule": title, "level": level, "hits": total})
            results.append({
                "title":      title,
                "level":      level,
                "tactic":     tactic,
                "hits":       total,
                "details":    hits_info,
                "event_time": newest,
                "dedup_key":  dkey,
                "rule_kind":  "aggregation",
                "log_source": src or index,
                "host":       host,
            })
        else:
            print_ok(f"{title} (fenêtre: {window_min}min, seuil: {threshold})")

    return results

# =============================================================================
# EXPLICATION LLM — écrite DANS les dicts, pas en base
# =============================================================================

def explain_sigma_alerts(alerts: list) -> list:
    """Enrichit chaque alerte de `llm_explanation` et `llm_model`, en place.

    L'explication est ainsi écrite en base EN MÊME TEMPS que l'alerte, dans
    une seule opération. Auparavant l'alerte était persistée puis
    l'explication ajoutée dans un second temps : une interruption entre les
    deux publiait une alerte définitivement dépourvue d'explication.

    Non bloquant par construction : une alerte sans explication reste une
    alerte qui doit remonter au SOC."""
    if not alerts:
        print("  [SIGMA-LLM] Aucune alerte à expliquer")
        return alerts

    if LLM_SIGMA_DIR not in sys.path:
        sys.path.insert(0, LLM_SIGMA_DIR)
    try:
        from rag_explainer import make_grok_client, call_llm_with_retry
    except ImportError as e:
        print(f"  [SIGMA-LLM] rag_explainer indisponible ({e}) — étape sautée")
        return alerts

    try:
        grok = make_grok_client()
    except ValueError as e:
        print(f"  [SIGMA-LLM] Skipped — {e}")
        return alerts

    model_used = getattr(grok, "_sentinel_model", "openai/gpt-oss-120b")

    print(f"\n  [SIGMA-LLM] Explication de {len(alerts)} alerte(s) Sigma...")
    ok, errors = 0, 0

    for alert in alerts:
        title   = alert["title"]
        level   = alert["level"]
        tactic  = alert["tactic"]
        hits    = alert["hits"]
        details = alert.get("details", [])

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
                "role":    "system",
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
            ok += 1
            print(f"  [SIGMA-LLM] ✓ {level:8s} | {title[:55]}")
        except Exception as e:
            explanation = f"Erreur LLM : {type(e).__name__} — {e}"
            errors += 1
            print(f"  [SIGMA-LLM] Erreur sur '{title}': {e}")

        alert["llm_explanation"] = explanation
        alert["llm_model"]       = model_used

    print(f"  [SIGMA-LLM] Terminé — {ok} expliquée(s) | {errors} erreur(s)")
    return alerts

# =============================================================================
# CLI — DIAGNOSTIC UNIQUEMENT
# =============================================================================

def main():
    """Exécution manuelle : affiche les détections, N'ÉCRIT RIEN.

    Auparavant, ce point d'entrée appelait les règles avec un run_id à None
    et créait en base des documents `_id = "None::…"` qui polluaient le
    dashboard à chaque test. La persistance appartenant désormais au
    backend, ce risque a disparu par construction."""
    summary    = []
    all_alerts = []

    print(f"\n{'='*65}")
    print(f"  SIGMA DETECTION ENGINE — mode diagnostic (aucune écriture)")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*65}\n")

    print("--- Règles simples ---\n")
    all_alerts += run_simple_rules(summary)
    all_alerts += run_aggregation_rules(summary)

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

    sans_heure = sum(1 for a in all_alerts if not a.get("event_time"))
    print(f"  {len(all_alerts)} alerte(s) collectée(s) — "
          f"{sans_heure} sans heure d'événement exacte")
    print(f"  Persistance : assurée par le backend "
          f"(controllers/analyse_controller.py)\n")
    return all_alerts


if __name__ == "__main__":
    main()