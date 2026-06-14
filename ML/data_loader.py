"""
data_loader.py
==============
Chargement des logs depuis Elasticsearch.

Principe clef : on lit les champs ECS *BRUTS* (poses par les modules
Filebeat/Auditbeat, donc presents APRES l'ingest pipeline), et PLUS AUCUN
champ `ml.*`. Cela rend le pipeline independant de la version de Logstash
deployee (le `_search` fourni a montre que l'ancienne pipeline `ml.*` etait
encore en base). `log_source` est derive ici en Python avec la meme logique
que Logstash.

Sortie : un DataFrame "brut" a colonnes normalisees, consomme par
feature_engineering.build_features().
"""
from __future__ import annotations
import os
import ssl
import json
import base64
import urllib.request

import numpy as np
import pandas as pd

import config as C

# Champs ECS bruts a recuperer (tous optionnels selon la source).
_SOURCE_FIELDS = [
    "@timestamp",
    "host.name", "host.hostname",
    "user.name",
    "source.ip", "source.address",
    "source.geo.country_iso_code",
    "process.name", "process.executable", "process.args",
    "process.parent.executable",
    "file.path",
    "message",
    "log.level",
    "event.outcome", "event.action", "event.dataset", "event.module",
    "agent.type",
    "container.name",
    # auditd
    "auditd.data.syscall", "auditd.data.cmdline",
]

# Colonnes normalisees en sortie (noms plats).
RAW_COLUMNS = [
    "timestamp", "host_name", "user_name", "source_ip", "geo_country",
    "process_name", "process_executable", "process_args", "parent_executable",
    "file_path", "message", "log_level", "event_outcome", "event_action",
    "event_dataset", "event_module", "agent_type", "container_name",
    "syscall", "cmdline", "log_source",
]


def _make_es_client():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    token = base64.b64encode(f"{C.ES_USER}:{C.ES_PASS}".encode()).decode()
    headers = {"Content-Type": "application/json",
               "Authorization": f"Basic {token}"}
    return ctx, headers


def _es_request(path, body=None, method=None, ctx=None, headers=None):
    if ctx is None:
        ctx, headers = _make_es_client()
    url = f"{C.ES_HOST}{path}"
    data = json.dumps(body).encode() if body else None
    m = method or ("POST" if body else "GET")
    req = urllib.request.Request(url, data=data, headers=headers, method=m)
    return json.loads(urllib.request.urlopen(req, context=ctx).read())


def _dig(d, dotted):
    """Acces a un champ ECS pointe ('process.parent.executable')."""
    cur = d
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _derive_log_source(event_dataset, agent_type, event_module):
    ds = (event_dataset or "")
    agent = (agent_type or "")
    mod = (event_module or "")
    if ds == "system.syslog":
        return "syslog"
    if ds == "system.auth":
        return "auth"
    if agent == "auditbeat" or ds.startswith("auditd"):
        # On ne garde en "auditd" que les VRAIS syscalls (module auditd).
        # file_integrity (created/moved/deleted) et system (login/user/host)
        # sont des natures differentes -> ecartees (deviennent "unknown").
        if mod == "auditd" or ds.startswith("auditd"):
            return "auditd"
        return "unknown"
    return "unknown"


def _flatten_hit(src):
    def _scalar(dotted):
        v = _dig(src, dotted)
        if v is None:
            return None
        if isinstance(v, list):
            return " ".join(str(x) for x in v if x is not None)
        if isinstance(v, dict):
            return None
        return v if isinstance(v, str) else str(v)

    ts   = _scalar("@timestamp")                          # <-- etait _dig
    host = _scalar("host.name") or _scalar("host.hostname")  # <-- etait _dig

    
    row = {
        "timestamp":          ts,
        "host_name":          host,
        "user_name":          _scalar("user.name"),
        "source_ip":          _scalar("source.ip") or _scalar("source.address"),
        "geo_country":        _scalar("source.geo.country_iso_code"),
        "process_name":       _scalar("process.name"),
        "process_executable": _scalar("process.executable"),
        "process_args":       _scalar("process.args"),
        "parent_executable":  _scalar("process.parent.executable"),
        "file_path":          _scalar("file.path"),
        "message":            _scalar("message"),
        "log_level":          _scalar("log.level"),
        "event_outcome":      _scalar("event.outcome"),
        "event_action":       _scalar("event.action"),
        "event_dataset":      _scalar("event.dataset"),
        "event_module":       _scalar("event.module"),
        "agent_type":         _scalar("agent.type"),
        "container_name":     _scalar("container.name"),
        "syscall":            _scalar("auditd.data.syscall"),
        "cmdline":            _scalar("auditd.data.cmdline"),
    }
    row["log_source"] = _derive_log_source(
        row["event_dataset"], row["agent_type"], row["event_module"])
    return row


def _source_filter_clause(src):
    """Clause ES pour ne ramener qu'une source (meme logique que _derive_log_source)."""
    if src == "syslog":
        return [{"term": {"event.dataset": "system.syslog"}}]
    if src == "auth":
        return [{"term": {"event.dataset": "system.auth"}}]
    if src == "auditd":
        # vrais syscalls auditd : module auditd OU dataset auditd.* , agent auditbeat
        return [{"term": {"agent.type": "auditbeat"}},
                {"bool": {"should": [
                    {"term": {"event.module": "auditd"}},
                    {"prefix": {"event.dataset": "auditd"}}],
                 "minimum_should_match": 1}}]
    return []


def load_from_elasticsearch(max_docs=None):
    """Charge PAR SOURCE avec un plafond par source (anti-troncature globale).
    Applique la fenetre temporelle par source DIRECTEMENT dans la requete ES :
    auditd n'est charge que depuis sa bascule, ce qui evite de gaspiller le
    budget sur les vieux events pre-bascule (mal formes / NaT)."""
    ctx, headers = _make_es_client()
    starts = getattr(C, "DATA_START_BY_SOURCE", {}) or {}
    caps = getattr(C, "MAX_DOCS_BY_SOURCE", {})
    all_rows = []

    for src in C.SOURCES:
        cap = caps.get(src, max_docs or C.MAX_DOCS)
        gte = starts.get(src) or C.ES_TIME_GTE   # auditd -> 07/06 directement
        filt = [{"exists": {"field": "@timestamp"}},
                {"range": {"@timestamp": {"gte": gte, "lte": C.ES_TIME_LTE}}}]
        filt += _source_filter_clause(src)
        query = {"size": 5000, "sort": [{"@timestamp": {"order": "asc"}}],
                 "query": {"bool": {"filter": filt}}, "_source": _SOURCE_FIELDS}

        data = _es_request(f"/{C.ES_INDEX}/_search?scroll=2m", query,
                           ctx=ctx, headers=headers)
        scroll_id = data.get("_scroll_id")
        rows = []

        def extract(d):
            out = []
            for hit in d["hits"]["hits"]:
                r = _flatten_hit(hit.get("_source", {}))
                if r["log_source"] == src:        # garde-fou : la source attendue
                    out.append(r)
            return out

        try:
            rows += extract(data)
            while len(rows) < cap:
                data = _es_request("/_search/scroll",
                                   {"scroll": "2m", "scroll_id": scroll_id},
                                   ctx=ctx, headers=headers)
                new = extract(data)
                if not new:
                    break
                scroll_id = data.get("_scroll_id")
                rows += new
        finally:
            if scroll_id:
                try:
                    _es_request("/_search/scroll", {"scroll_id": [scroll_id]},
                                method="DELETE", ctx=ctx, headers=headers)
                except Exception:
                    pass
        print(f"    {src:8s}: {len(rows):,} logs charges (cap={cap:,}, gte={gte})")
        all_rows += rows

    df = pd.DataFrame(all_rows, columns=RAW_COLUMNS)
    print(f"  Total charge : {len(df):,} logs")
    return df

def filter_time_window(df):
    """Fenetre temporelle d'extraction PAR SOURCE. Sert a n'entrainer auditd
    que sur la collecte PROPRE (post-bascule demon maitre), sans jeter
    l'historique sain de syslog/auth (bornes a None)."""
    if "timestamp" not in df.columns or "log_source" not in df.columns:
        return df
    starts = getattr(C, "DATA_START_BY_SOURCE", {}) or {}
    ends = getattr(C, "DATA_END_BY_SOURCE", {}) or {}
    if not any(starts.values()) and not any(ends.values()):
        return df
    ts = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    keep = pd.Series(True, index=df.index)
    for src, start in starts.items():
        if start:
            t0 = pd.Timestamp(start)
            keep &= ~((df["log_source"] == src) & (ts < t0))
    for src, end in ends.items():
        if end:
            t1 = pd.Timestamp(end)
            keep &= ~((df["log_source"] == src) & (ts > t1))
    n = int((~keep).sum())
    if n > 0:
        print(f"  [FENETRE] {n:,} evenements hors fenetre temporelle exclus "
              f"(pre-bascule auditd)")
        df = df[keep].reset_index(drop=True)
    return df


def filter_host_only(df):
    """SOLUTION OPTIMALE pour le bruit Docker : un IDS HOTE ne doit pas se
    declencher sur le monitoring de sa propre stack. Tout evenement portant un
    container.name est de l'activite CONTENEUR (ex. health-check curl d'ES en
    boucle qui saturait auditd) -> exclu. On ne garde que l'activite de l'hote.
    """
    if not C.EXCLUDE_CONTAINER_EVENTS or "container_name" not in df.columns:
        return df
    cn = df["container_name"].fillna("").astype(str)
    is_container = ~cn.isin(["", "nan", "None"])
    n = int(is_container.sum())
    if n > 0:
        print(f"  [HOST-ONLY] {n:,} evenements conteneur exclus (bruit Docker)")
        df = df[~is_container].reset_index(drop=True)
    return df

def filter_auditd_infra(df):
    """Bruit d'infra auditd qui ECHAPPE a filter_host_only :
      * runtime conteneur (runc/containerd/dockerd) : sur l'hote, pas de
        container.name -> passe le filtre host-only. Bruit Docker pur.
      * process_name purement numerique ('6','9') : artefact de parsing.
    N'affecte QUE auditd (auth/syslog intacts)."""
    if "log_source" not in df.columns or "process_name" not in df.columns:
        return df
    aud  = df["log_source"] == "auditd"
    proc = df["process_name"].fillna("").astype(str).str.strip()
    is_runtime = aud & proc.isin(getattr(C, "CONTAINER_RUNTIME_PROCS", set()))
    is_numeric = pd.Series(False, index=df.index)
    if getattr(C, "EXCLUDE_NUMERIC_PROC", True):
        is_numeric = (aud & proc.str.fullmatch(r"\d+")).fillna(False)
    drop = is_runtime | is_numeric
    n = int(drop.sum())
    if n > 0:
        print(f"  [AUDITD-INFRA] {n:,} evenements infra exclus "
              f"(runtime conteneur + comm numerique)")
        df = df[~drop].reset_index(drop=True)
    return df

def load_dataset(max_docs=None):
    """Charge avec cache parquet (snapshot reproductible)."""
    if C.USE_CACHE and os.path.exists(C.DATASET_CACHE):
        df = pd.read_parquet(C.DATASET_CACHE)
        print(f"  [CACHE] Snapshot recharge ({len(df):,} logs)")
        return filter_time_window(filter_auditd_infra(filter_host_only(df)))
    print("  [CACHE] Chargement depuis ES...")
    df = load_from_elasticsearch(max_docs=max_docs)
    df = filter_host_only(df)
    df = filter_auditd_infra(df)        # <-- NOUVEAU
    df = filter_time_window(df)
    if C.USE_CACHE and len(df) > 0:
        try:
            df.to_parquet(C.DATASET_CACHE, index=False)
            print(f"  [CACHE] Snapshot sauve -> {C.DATASET_CACHE}")
        except Exception as e:
            print(f"  [CACHE] Sauvegarde echouee : {e}")
    return df