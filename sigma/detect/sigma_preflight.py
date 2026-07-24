# sigma/detect/sigma_preflight.py — DIAGNOSTIC, hors pipeline de prod.
"""Teste chaque regle sur TOUT l'historique, sans filtre temporel.
Une regle qui n'a jamais matche en 4 mois de donnees est structurellement
inexploitable sur ce modele d'ingestion (et non 'rien a signaler')."""
import os, sys, json
sys.path.insert(0, os.path.expanduser("~/pfe-backend-2026/backend"))
from sigma_engine import (SIGMA_PATH, INDEX, get_rule_meta,
                          sigma_to_lucene, es_search)

alive, dead, skipped = [], [], []
for root, _, files in os.walk(SIGMA_PATH):
    for f in sorted(files):
        if not f.endswith(".yml"):
            continue
        path = os.path.join(root, f)
        title, level, _ = get_rule_meta(path)
        lucene = sigma_to_lucene(path)
        if not lucene:
            skipped.append(title); continue
        data = es_search(INDEX,
                         {"query_string": {"query": lucene,
                                           "default_field": "message",
                                           "analyze_wildcard": True}},   # ← ajout
                         ["@timestamp"], size=1, time_filter=None)
        try:
            n = data["hits"]["total"]["value"]
        except (TypeError, KeyError):
            n = -1                      # requete rejetee par ES
        (alive if n > 0 else dead).append((title, n, os.path.relpath(path, SIGMA_PATH)))

print(f"\n{'='*70}")
print(f"  EXPLOITABLES  : {len(alive)}")
print(f"  JAMAIS MATCHE : {len(dead)}")
print(f"  NON CONVERTIES: {len(skipped)}")
print(f"{'='*70}")
for t, n, p in sorted(dead, key=lambda x: x[2]):
    print(f"  [MUETTE] {p:55s} {t[:40]}")
json.dump({"alive": alive, "dead": dead, "skipped": skipped},
          open("sigma_preflight.json", "w"), indent=2, ensure_ascii=False)