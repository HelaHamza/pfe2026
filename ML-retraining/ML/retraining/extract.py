"""
extract.py
==========
Extraction Elasticsearch en FLUX vers Parquet. Correctif du blocage OOM.

LE PROBLEME DANS data_loader.load_from_elasticsearch()
------------------------------------------------------
    all_rows = []
    ...
    all_rows += rows                                  # liste de dicts, croissante
    df = pd.DataFrame(all_rows, columns=RAW_COLUMNS)  # copie complete

Avec MAX_DOCS_BY_SOURCE['auditd'] = 900_000, on accumule ~900 000 dicts Python
(chacun ~1,5 Ko avec ses 23 cles) AVANT la conversion, laquelle duplique encore
tout. C'est l'incident OOM deja rencontre a ~350 000 logs -- sauf que cette
fois il se produit a 02:00 pendant un cycle automatique, sans personne pour
relancer quoi que ce soit.

LA CORRECTION
-------------
Pipeline en un seul passage, a memoire BORNEE (~EXTRACT_CHUNK_ROWS lignes) :

    page ES -> aplatissement -> filtres hote/infra/fenetre -> decontamination
            -> ecriture d'un row-group parquet -> le chunk est libere

Trois benefices en plus de la memoire :
  * les filtres retirent le bruit AVANT accumulation (conteneurs, runtime
    Docker, comm numeriques) : le snapshot final est nettement plus petit ;
  * la decontamination est appliquee au fil de l'eau, donc le fichier ecrit
    sur disque n'a JAMAIS contenu les evenements d'attaque ;
  * le schema parquet est declare explicitement (tout en string, ce que
    _flatten_hit produit deja), ce qui elimine une classe entiere de bugs de
    derive de dtype entre deux cycles.

Ce module N'IMPORTE PAS data_loader pour le dupliquer : il en REUTILISE les
helpers (_es_request, _flatten_hit, _source_filter_clause, RAW_COLUMNS, et les
trois fonctions de filtrage). Une seule definition de la logique metier.
"""
from __future__ import annotations

import contextlib
import io
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

import config_cnn as C
import data_loader as DL
from retraining import retrain_config as RC
from retraining.decontaminate import Incident, mask_contaminated

# Tout ce que produit _flatten_hit est str ou None -> schema all-string.
SCHEMA = pa.schema([(c, pa.string()) for c in DL.RAW_COLUMNS])


def _quiet(fn, df):
    """Applique un filtre de data_loader en capturant ses print() par chunk.

    Les fonctions de data_loader affichent un recapitulatif ; appelees des
    centaines de fois, elles noieraient le journal. On capture, on agrege.
    """
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        out = fn(df)
    return out


def _iter_pages(src: str, gte: str, lte: str, cap: int, ctx, headers):
    """Itere les pages ES d'une source. Ne conserve jamais plus d'une page."""
    filt = [{"exists": {"field": "@timestamp"}},
            {"range": {"@timestamp": {"gte": gte, "lte": lte}}}]
    filt += DL._source_filter_clause(src)
    query = {"size": RC.EXTRACT_PAGE_SIZE,
             "sort": [{"@timestamp": {"order": "asc"}}],
             "query": {"bool": {"filter": filt}},
             "_source": DL._SOURCE_FIELDS}

    ka = RC.EXTRACT_SCROLL_KEEPALIVE
    data = DL._es_request(f"/{C.ES_INDEX}/_search?scroll={ka}", query,
                          ctx=ctx, headers=headers)
    scroll_id = data.get("_scroll_id")
    seen = 0
    try:
        while True:
            rows = []
            for hit in data["hits"]["hits"]:
                r = DL._flatten_hit(hit.get("_source", {}))
                if r["log_source"] == src:       # garde-fou identique a DL
                    rows.append(r)
            if rows:
                seen += len(rows)
                yield rows
            if seen >= cap or not data["hits"]["hits"]:
                break
            data = DL._es_request("/_search/scroll",
                                  {"scroll": ka, "scroll_id": scroll_id},
                                  ctx=ctx, headers=headers)
            scroll_id = data.get("_scroll_id") or scroll_id
    finally:
        if scroll_id:
            with contextlib.suppress(Exception):
                DL._es_request("/_search/scroll", {"scroll_id": [scroll_id]},
                               method="DELETE", ctx=ctx, headers=headers)


def _df_to_table(df: pd.DataFrame) -> pa.Table:
    df = df.reindex(columns=DL.RAW_COLUMNS)
    df = df.astype(object).where(pd.notna(df), None)
    return pa.Table.from_pandas(df, schema=SCHEMA, preserve_index=False)


def extract_to_parquet(out_path, window_start: str, window_end: str,
                       incidents: list[Incident] | None = None) -> dict:
    """Extrait la fenetre glissante vers un snapshot parquet decontamine.

    La fenetre EFFECTIVE par source est max(DATA_START_BY_SOURCE[src],
    window_start) : la borne physique d'auditd (bascule du demon maitre) prime
    toujours sur la fenetre glissante, faute de quoi on reintroduirait les
    evenements malformes d'avant bascule.

    Retourne un rapport d'extraction (compteurs par source).
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    incidents = incidents or []
    ctx, headers = DL._make_es_client()

    report = {"window_start": window_start, "window_end": window_end,
              "by_source": {}, "total_written": 0, "total_raw": 0,
              "total_filtered": 0, "total_decontaminated": 0}

    writer = pq.ParquetWriter(out_path, SCHEMA, compression="snappy")
    buffer: list[dict] = []
    try:
        for src in C.SOURCES:
            hard_start = (getattr(C, "DATA_START_BY_SOURCE", {}) or {}).get(src)
            gte = window_start
            if hard_start and pd.Timestamp(hard_start) > pd.Timestamp(window_start):
                gte = hard_start
                print(f"    {src:8s}: borne physique appliquee ({hard_start}) "
                      f"> fenetre glissante ({window_start})")
            cap = RC.MAX_DOCS_BY_SOURCE.get(src, C.MAX_DOCS)

            stat = {"raw": 0, "filtered": 0, "decontaminated": 0,
                    "written": 0, "gte": gte, "cap": cap}
            for rows in _iter_pages(src, gte, window_end, cap, ctx, headers):
                stat["raw"] += len(rows)
                buffer.extend(rows)
                if len(buffer) < RC.EXTRACT_CHUNK_ROWS:
                    continue
                w, f, d = _flush(writer, buffer, incidents)
                stat["written"] += w
                stat["filtered"] += f
                stat["decontaminated"] += d
                buffer = []
                if stat["raw"] >= cap:
                    break
            if buffer:
                w, f, d = _flush(writer, buffer, incidents)
                stat["written"] += w
                stat["filtered"] += f
                stat["decontaminated"] += d
                buffer = []

            report["by_source"][src] = stat
            report["total_raw"] += stat["raw"]
            report["total_filtered"] += stat["filtered"]
            report["total_decontaminated"] += stat["decontaminated"]
            report["total_written"] += stat["written"]
            print(f"    {src:8s}: {stat['raw']:>8,} bruts | "
                  f"-{stat['filtered']:>7,} filtres | "
                  f"-{stat['decontaminated']:>5,} decontamines | "
                  f"{stat['written']:>8,} ecrits  (gte={gte})")
    finally:
        writer.close()

    print(f"  Total ecrit : {report['total_written']:,} evenements "
          f"-> {out_path.name} "
          f"({out_path.stat().st_size / 1e6:.1f} Mo)")
    return report


def _flush(writer, rows: list[dict], incidents) -> tuple[int, int, int]:
    """Filtre + decontamine + ecrit un chunk. Retourne (ecrits, filtres, decontamines)."""
    df = pd.DataFrame(rows, columns=DL.RAW_COLUMNS)
    n0 = len(df)

    df = _quiet(DL.filter_host_only, df)
    df = _quiet(DL.filter_auditd_infra, df)
    df = _quiet(DL.filter_time_window, df)
    n_filtered = n0 - len(df)

    n_decon = 0
    if incidents and len(df):
        bad = mask_contaminated(df, incidents)
        n_decon = int(bad.sum())
        if n_decon:
            df = df.loc[~bad]

    if len(df):
        writer.write_table(_df_to_table(df))
    return len(df), n_filtered, n_decon


def available_ram_mb() -> int | None:
    """MemAvailable de /proc/meminfo (Linux). None si indisponible."""
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except Exception:
        return None
    return None
