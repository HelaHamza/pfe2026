#!/usr/bin/env python3
"""Pourquoi le LLM a-t-il hesite ? Lecture directe de cnn_triage.jsonl.

Un 'uncertain' n'est pas une categorie : c'est un aveu. Reste a savoir de
quoi. Trois causes possibles, trois corrections opposees :
  - garde-fou      -> le LLM avait tranche, la politique l'a bloque
  - fail-open      -> panne API, aucun rapport avec le raisonnement
  - hesitation     -> le LLM n'a pas ose. Lire missing_context.
"""
import json
import sys

import config_llm_cnn as CL

rows = [json.loads(l) for l in open(CL.TRIAGE_JSONL, encoding="utf-8")]
unc = [r for r in rows if r["verdict"] == "uncertain"]

print(f"{len(unc)} episodes 'uncertain' sur {len(rows)}\n" + "=" * 70)
for r in unc:
    print(f"\n{r['episode_id']} | {r['log_source']} | sev={r['severity']} "
          f"| conf={r['confidence']}")
    print(f"  {r['title']}")
    if r.get("policy_flags"):
        print(f"  FLAGS      : {'; '.join(r['policy_flags'])}")
    if r.get("guardrails"):
        print(f"  GARDE-FOUS : {'; '.join(r['guardrails'])}")
        print("     -> cause : la POLITIQUE a bloque le verdict du LLM")
    else:
        print("     -> cause : le LLM a CHOISI d'hesiter (aucun garde-fou)")
    if r.get("missing_context"):
        print(f"  IL LUI MANQUE : {r['missing_context']}")
    print(f"  KB         : {', '.join(r.get('kb_refs') or ['(aucune)'])}")
    print(f"  RAISON     : {r['rationale'][:220]}")

print("\n" + "=" * 70)
gf = sum(1 for r in unc if r.get("guardrails") and "fail-open" not in r["guardrails"])
fo = sum(1 for r in unc if "fail-open" in (r.get("guardrails") or []))
print(f"bloques par la politique : {gf}")
print(f"fail-open (panne API)    : {fo}")
print(f"hesitation du modele     : {len(unc) - gf - fo}")