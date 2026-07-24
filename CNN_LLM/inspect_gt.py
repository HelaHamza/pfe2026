#!/usr/bin/env python3
"""Que contient REELLEMENT groundtruth.jsonl ?

Motivation : l'evaluation n'apparie que 2 scenarios alors que le generateur
en couvre 4. Avant de conclure quoi que ce soit sur le rappel, il faut savoir
si le fichier contient 4 scenarios (et l'appariement echoue) ou 2 (et le
2/2 est correct). Aucune hypothese sur les noms de champs : on lit ce qui est
la, pas ce qu'on espere y trouver.

    python inspect_gt.py /home/hala-hamza/pfe-backend-2026/ML/groundtruth.jsonl
"""
import collections
import json
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "groundtruth.jsonl"

records, vides, casses = [], 0, 0
for n, line in enumerate(open(path, encoding="utf-8"), 1):
    if not line.strip():
        vides += 1
        continue
    try:
        records.append(json.loads(line))
    except json.JSONDecodeError as e:
        casses += 1
        if casses <= 3:
            print(f"  [ligne {n}] illisible : {e}")

print(f"\nFichier : {path}")
print(f"  enregistrements lus : {len(records)}")
print(f"  lignes vides        : {vides}")
print(f"  lignes illisibles   : {casses}")

if not records:
    sys.exit("\nAucun enregistrement : le fichier n'est pas du JSONL.")

# --- Quelles cles existent vraiment ? ---------------------------------------
cles = collections.Counter(k for r in records for k in r)
print(f"\nCles presentes ({len(cles)} distinctes) :")
for k, n in cles.most_common():
    ex = next((repr(r[k])[:60] for r in records if k in r), "")
    print(f"  {k:22s} x{n:<4d} ex: {ex}")

# --- Quelle cle porte le nom du scenario ? ----------------------------------
candidats = [k for k in cles
             if any(m in k.lower()
                    for m in ("scenario", "name", "attack", "label", "type",
                              "technique", "mitre", "id"))]
print(f"\nCles candidates pour identifier un scenario : {candidats or 'AUCUNE'}")

for k in candidats:
    vals = collections.Counter(str(r.get(k)) for r in records if k in r)
    print(f"\n  {k} -> {len(vals)} valeur(s) distincte(s)")
    for v, n in vals.most_common(10):
        print(f"      {n:4d}x  {v[:70]}")

# --- Couverture temporelle : le GT tombe-t-il dans le split test ? ----------
tk = [k for k in cles if any(m in k.lower()
                             for m in ("start", "begin", "ts", "time", "@"))]
if tk:
    k = tk[0]
    ts = sorted(str(r[k]) for r in records if r.get(k))
    print(f"\nCouverture temporelle (cle '{k}') :")
    print(f"  du {ts[0]}")
    print(f"  au {ts[-1]}")
    print("  -> comparer aux bornes du split 'test' du CNN : un scenario hors")
    print("     de cette fenetre ne PEUT PAS etre apparie, et son absence")
    print("     n'est alors pas une regression.")