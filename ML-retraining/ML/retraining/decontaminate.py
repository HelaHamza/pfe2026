"""
decontaminate.py
================
Fermeture de la boucle de retroaction : la COUCHE 3 nettoie la COUCHE 1.

LE PROBLEME
-----------
Un auto-encodeur apprend "ce qui est normal" a partir de donnees non
etiquetees. Si le corpus de reentrainement contient une attaque, le modele
apprend cette attaque comme normale et ne la detectera PLUS JAMAIS. Pire :
l'attaque disparait de la detection precisement parce qu'elle a reussi assez
longtemps pour peser dans les donnees. Le systeme se degrade la ou il devrait
se renforcer.

Ce mode de defaillance porte un nom : empoisonnement du corpus (poisoning).
Il n'existe PAS en apprentissage supervise classique, ou l'on controle les
labels. Il est structurel en detection d'anomalies non supervisee bouclee.

LA SOLUTION, PROPRE A CETTE ARCHITECTURE
----------------------------------------
Sentinel produit deja les etiquettes qui manquent : les episodes classes
`true_positive` par le triage Sigma + LLM. Ils sont excises du corpus avant
reentrainement. C'est une vraie boucle de retroaction fermee, et c'est
defendable devant un jury bien plus que "je relance le training tous les mois".

Trois sources d'incidents, fusionnees :
  1. MongoDB       episodes tries true_positive par la couche LLM
  2. quarantine.json  incidents confirmes a la main (red-team, scenarios de
                      validation joues sur la machine, faux negatifs decouverts
                      apres coup)
  3. golden/incidents.json  les scenarios du golden set : ils ne doivent
                      JAMAIS entrer dans le corpus, sinon le test (a) du gate
                      valide un modele entraine sur ses propres reponses.

ARTEFACT RESIDUEL, ASSUME
-------------------------
L'excision retire des lignes AVANT le fenetrage. Les fenetres qui enjambent la
coupure raboutent du pre-incident et du post-incident : leur
`inter_arrival_log` porte un ecart artificiel. L'effet touche au plus W-1
fenetres par incident (W=16) et biaise l'erreur de reconstruction vers le
HAUT, donc dans le sens CONSERVATEUR (plus d'alertes, jamais moins). C'est un
compromis mesure et documente, pas un oubli. La marge
DECONTAMINATION_MARGIN_SECONDS l'attenue encore.

CLI
---
    python -m retraining.decontaminate --list
    python -m retraining.decontaminate --check dataset_snapshot.parquet
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict
from pathlib import Path

import pandas as pd

from retraining import retrain_config as RC


@dataclass(frozen=True)
class Incident:
    """Fenetre spatio-temporelle a exciser du corpus d'entrainement."""
    id: str
    start: pd.Timestamp
    end: pd.Timestamp
    log_source: str | None = None    # None = toutes sources
    host_name: str | None = None     # None = tous hotes
    source_ip: str | None = None     # None = toutes IP
    technique: str | None = None
    origin: str = "unknown"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["start"] = self.start.isoformat()
        d["end"] = self.end.isoformat()
        return d


def _ts(v) -> pd.Timestamp:
    t = pd.to_datetime(v, utc=True, errors="coerce")
    if pd.isna(t):
        raise ValueError(f"Horodatage illisible : {v!r}")
    return t


def _from_record(rec: dict, origin: str, idx: int) -> Incident:
    start = _ts(rec["start"])
    end = _ts(rec.get("end") or rec["start"])
    if end < start:
        start, end = end, start
    return Incident(
        id=str(rec.get("id") or f"{origin}_{idx}"),
        start=start, end=end,
        log_source=rec.get("log_source"),
        host_name=rec.get("host_name"),
        source_ip=rec.get("source_ip"),
        technique=rec.get("technique"),
        origin=origin,
    )


# ===========================================================================
# 1. Sources d'incidents
# ===========================================================================
def _load_json_incidents(path: os.PathLike, origin: str) -> list[Incident]:
    path = Path(path)
    if not path.exists():
        return []
    with open(path) as f:
        data = json.load(f)
    records = data.get("incidents", data) if isinstance(data, dict) else data
    out = []
    for i, rec in enumerate(records):
        try:
            out.append(_from_record(rec, origin, i))
        except Exception as e:
            print(f"  [DECONTAM] incident ignore dans {path.name} ({e})")
    return out


def _load_mongo_incidents() -> list[Incident]:
    """Episodes tries true_positive par la couche LLM.

    Le mapping de schema vient de RC.MONGO_FIELD_MAP. Ce module ne DEVINE
    jamais un nom de champ : si le mapping est faux, il le dit franchement au
    lieu de retourner silencieusement zero incident -- ce qui reviendrait a
    desactiver la decontamination sans que personne ne s'en apercoive.
    """
    if not RC.MONGO_URI:
        msg = "MONGO_URI absent : decontamination automatique desactivee."
        if RC.REQUIRE_MONGO:
            raise RuntimeError(msg + " REQUIRE_MONGO=1 -> cycle abandonne.")
        print(f"  [DECONTAM] {msg}")
        return []
    try:
        from pymongo import MongoClient
    except ImportError:
        msg = "pymongo non installe : decontamination automatique desactivee."
        if RC.REQUIRE_MONGO:
            raise RuntimeError(msg)
        print(f"  [DECONTAM] {msg}")
        return []

    fm = RC.MONGO_FIELD_MAP
    verdicts = list(RC.MONGO_VERDICT_TRUE_POSITIVE)
    if RC.DECONTAMINATE_UNCERTAIN:
        verdicts += ["uncertain"]

    try:
        client = MongoClient(RC.MONGO_URI, serverSelectionTimeoutMS=10000)
        coll = client[RC.MONGO_DB][RC.MONGO_EPISODES_COLLECTION]
        cursor = coll.find({fm["verdict"]: {"$in": verdicts}})
        docs = list(cursor)
    except Exception as e:
        msg = f"MongoDB injoignable ({e})"
        if RC.REQUIRE_MONGO:
            raise RuntimeError(msg + " -> cycle abandonne (REQUIRE_MONGO=1).")
        print(f"  [DECONTAM] {msg} : decontamination automatique desactivee.")
        return []
    finally:
        try:
            client.close()
        except Exception:
            pass

    if not docs:
        print("  [DECONTAM] Mongo : aucun episode true_positive trouve.")
        return []

    missing = [k for k in ("start", "end") if fm[k] not in docs[0]]
    if missing:
        raise RuntimeError(
            f"MONGO_FIELD_MAP incorrect : champs {missing} absents des "
            f"documents de '{RC.MONGO_EPISODES_COLLECTION}'. "
            f"Champs disponibles : {sorted(docs[0].keys())}. "
            f"Corrige MONGO_FIELD_MAP dans retrain_config.py.")

    out = []
    for i, doc in enumerate(docs):
        try:
            out.append(_from_record({
                "id": doc.get(fm["id"]) or str(doc.get("_id")),
                "start": doc[fm["start"]],
                "end": doc.get(fm["end"]) or doc[fm["start"]],
                "log_source": doc.get(fm["log_source"]),
                "host_name": doc.get(fm["host_name"]),
                "source_ip": doc.get(fm["source_ip"]),
                "technique": doc.get("technique") or doc.get("mitre_technique"),
            }, "mongo", i))
        except Exception as e:
            print(f"  [DECONTAM] document Mongo ignore ({e})")
    return out


def load_incidents(include_golden: bool = True) -> list[Incident]:
    """Fusionne les trois sources et deduplique."""
    incidents: list[Incident] = []
    incidents += _load_mongo_incidents()
    incidents += _load_json_incidents(RC.QUARANTINE_FILE, "quarantine")
    if include_golden:
        incidents += _load_json_incidents(
            Path(RC.GOLDEN_DIR) / "incidents.json", "golden")

    seen, uniq = set(), []
    for inc in incidents:
        key = (inc.log_source, inc.host_name, inc.start, inc.end)
        if key not in seen:
            seen.add(key)
            uniq.append(inc)

    by_origin: dict[str, int] = {}
    for inc in uniq:
        by_origin[inc.origin] = by_origin.get(inc.origin, 0) + 1
    print(f"  [DECONTAM] {len(uniq)} incident(s) a exciser : "
          + (", ".join(f"{k}={v}" for k, v in sorted(by_origin.items()))
             or "aucun"))
    return uniq


# ===========================================================================
# 2. Masquage
# ===========================================================================
def mask_contaminated(df: pd.DataFrame, incidents: list[Incident],
                      margin_seconds: int | None = None,
                      ts_col: str = "timestamp") -> pd.Series:
    """Retourne un masque booleen : True = ligne CONTAMINEE (a retirer).

    Applicable par chunk pendant l'extraction : empreinte memoire constante.
    """
    if not incidents or len(df) == 0:
        return pd.Series(False, index=df.index)

    margin = pd.Timedelta(
        seconds=RC.DECONTAMINATION_MARGIN_SECONDS
        if margin_seconds is None else margin_seconds)
    ts = pd.to_datetime(df[ts_col], utc=True, errors="coerce")
    bad = pd.Series(False, index=df.index)

    for inc in incidents:
        m = (ts >= inc.start - margin) & (ts <= inc.end + margin)
        if not m.any():
            continue
        if inc.log_source and "log_source" in df.columns:
            m &= df["log_source"] == inc.log_source
        if inc.host_name and "host_name" in df.columns:
            m &= df["host_name"] == inc.host_name
        if inc.source_ip and "source_ip" in df.columns:
            m &= df["source_ip"] == inc.source_ip
        bad |= m.fillna(False)
    return bad


def decontaminate(df: pd.DataFrame, incidents: list[Incident],
                  ts_col: str = "timestamp") -> tuple[pd.DataFrame, int]:
    bad = mask_contaminated(df, incidents, ts_col=ts_col)
    n = int(bad.sum())
    return (df.loc[~bad].reset_index(drop=True) if n else df), n


# ===========================================================================
# 3. CLI
# ===========================================================================
def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        description="Decontamination du corpus de reentrainement")
    ap.add_argument("--list", action="store_true",
                    help="lister les incidents confirmes")
    ap.add_argument("--check", metavar="PARQUET",
                    help="simuler l'excision sur un snapshot (dry-run)")
    a = ap.parse_args(argv)

    incidents = load_incidents()
    if a.list or not a.check:
        for inc in incidents:
            print(f"  [{inc.origin:10s}] {inc.id:28s} {inc.start} -> {inc.end} "
                  f"src={inc.log_source or '*':7s} host={inc.host_name or '*'}")
        if not a.check:
            return 0

    df = pd.read_parquet(a.check)
    bad = mask_contaminated(df, incidents)
    print(f"\n{len(df):,} lignes | {int(bad.sum()):,} seraient exciseees "
          f"({100 * bad.mean():.3f} %)")
    if bad.any() and "log_source" in df.columns:
        print(df.loc[bad, "log_source"].value_counts().to_string())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
