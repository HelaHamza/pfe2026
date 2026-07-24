"""
CNN_LLM/live_loader.py — chargement PROD borné ]since - seed, until].
Bornes poussées DANS la requête ES via override de la config lue au call-time
par load_from_elasticsearch (DATA_START_BY_SOURCE + ES_TIME_LTE), SANS modifier
data_loader. Le post-filtrage pandas ne sert plus que de filet.
"""
from __future__ import annotations
import pandas as pd
import config_cnn as C
from data_loader import (load_from_elasticsearch, filter_host_only,
                         filter_auditd_infra)


def _es_iso(ts):
    return ts.tz_convert("UTC").isoformat().replace("+00:00", "Z")


def load_live(until=None, since=None, seed_seconds=0):
    print("  [LIVE] Chargement FRAIS depuis ES (fenêtre poussée dans la requête)...")

    orig_start   = getattr(C, "DATA_START_BY_SOURCE", {}) or {}
    orig_lte     = C.ES_TIME_LTE
    fallback_gte = C.ES_TIME_GTE

    lo = None
    if since is not None:
        lo = pd.to_datetime(since, utc=True, errors="coerce") \
             - pd.Timedelta(seconds=seed_seconds or 0)
        if pd.isna(lo):
            raise ValueError(f"[LIVE] since invalide (ISO attendu) : {since!r}")

    until_ts = None
    if until is not None:
        until_ts = pd.to_datetime(until, utc=True, errors="coerce")
        if pd.isna(until_ts):
            raise ValueError(f"[LIVE] until invalide (ISO attendu) : {until!r}")

    # gte effectif PAR SOURCE = max(début propre source, curseur - seed).
    # Écrire TOUTES les sources neutralise le court-circuit
    #   `starts.get(src) or C.ES_TIME_GTE`  qui ignorait ES_TIME_GTE pour auditd.
    patched_start = dict(orig_start)
    if lo is not None:
        for src in C.SOURCES:
            src_start = orig_start.get(src) or fallback_gte
            src_start_ts = pd.to_datetime(src_start, utc=True, errors="coerce")
            eff = lo if (pd.isna(src_start_ts) or lo > src_start_ts) else src_start_ts
            patched_start[src] = _es_iso(eff)

    try:
        C.DATA_START_BY_SOURCE = patched_start
        if until_ts is not None:
            C.ES_TIME_LTE = _es_iso(until_ts)
        df = load_from_elasticsearch()
    finally:
        C.DATA_START_BY_SOURCE = orig_start
        C.ES_TIME_LTE = orig_lte

    df = filter_host_only(df)
    df = filter_auditd_infra(df)

    if "timestamp" in df.columns and len(df):
        ts = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
        mask = ts.notna()
        if until_ts is not None:
            mask &= ts <= until_ts
        if lo is not None:
            mask &= ts >= lo
        before = len(df)
        df = df[mask].reset_index(drop=True)
        print(f"  [LIVE] {len(df):,}/{before:,} logs retenus (filet pandas)")

    print(f"  [LIVE] {len(df):,} logs chargés "
          f"(fenêtre ]{lo.isoformat() if lo is not None else 'BOOTSTRAP'} , "
          f"{until_ts.isoformat() if until_ts is not None else 'now'}])")
    return df