#!/usr/bin/env python3
"""Rappel AE : croise groundtruth.jsonl (fenetres injectees) avec
alerts_episodes.csv. Une fenetre est DETECTEE si un episode de la meme
source la recouvre (tolerance +/- 2 min)."""
import json, pandas as pd

TOL = pd.Timedelta("2min")

# --- fenetres injectees ---
gt = pd.DataFrame(json.loads(l) for l in open("groundtruth.jsonl") if l.strip())
gt["start"] = pd.to_datetime(gt["start"], utc=True)
gt["end"]   = pd.to_datetime(gt["end"],   utc=True)

# --- episodes d'alerte ---
ep = pd.read_csv("alerts_episodes.csv")
ep["start"] = pd.to_datetime(ep["start"], utc=True)
ep["end"]   = pd.to_datetime(ep["end"],   utc=True)

def _load_jsonl(path):
    rows = []
    for l in open(path):
        l = l.strip()
        if not l:
            continue
        try:
            rows.append(json.loads(l))
        except json.JSONDecodeError:
            continue          # ignore les lignes corrompues d'anciennes sessions
    return pd.DataFrame(rows)

gt = _load_jsonl("groundtruth.jsonl")
for c in ("start", "end"):
    gt[c] = pd.to_datetime(gt[c], utc=True, errors="coerce")
gt = gt.dropna(subset=["start", "end"])

ep = pd.read_csv("alerts_episodes.csv")
for c in ("start", "end"):
    ep[c] = pd.to_datetime(ep[c], utc=True, errors="coerce")
    
def detecte(w):
    c = ep[ep["log_source"] == w["source"]]
    hit = c[(c["start"] <= w["end"] + TOL) & (c["end"] >= w["start"] - TOL)]
    return hit["mse_max"].max() if len(hit) else None

print(f"{'SCENARIO':24s} {'SRC':7s} {'DETECTE':8s} conf_max")
det = 0
for _, w in gt.iterrows():
    m = detecte(w)
    ok = m is not None
    det += ok
    print(f"{w['name']:24s} {w['source']:7s} {'OUI' if ok else 'NON':8s} "
          f"{m if ok else '-'}")
print(f"\nRAPPEL AE : {det}/{len(gt)} = {det/len(gt)*100:.0f}%")

# precision episode (borne basse : les 'FP' incluent des anomalies benignes reelles)
def tp(e):
    c = gt[gt["source"] == e["log_source"]]
    return ((c["start"] <= e["end"] + TOL) & (c["end"] >= e["start"] - TOL)).any()
n_tp = ep.apply(tp, axis=1).sum()
print(f"PRECISION episode : {n_tp}/{len(ep)} = {n_tp/len(ep)*100:.0f}% "
      f"(borne basse, cf. anomalies benignes non etiquetees)")