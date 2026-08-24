"""
triage_cnn.py  (orchestrateur de PRODUCTION -- MODE EXPLICATION SEULE)
=====================================================================
Fichier lance par cnn_adapter.collect() (subprocess). Unique orchestrateur de
triage du pipeline.

REPOSITIONNEMENT (inchange) :
  Le CNN DECIDE ce qui est une alerte. Toute alerte levee est CONSERVEE et
  presentee. Le LLM ne produit AUCUN verdict : il EXPLIQUE (titre, raisonnement,
  MITRE, severite de PRIORISATION, actions). Rappel du systeme = rappel du CNN.

CONSOLIDATION (cette version) :
  1. SOURCE UNIQUE DE PROMPT -- prompts_cnn (SYSTEM_PROMPT / FEWSHOT /
     OUTPUT_SCHEMA / build_user_prompt). Les definitions locales divergentes
     (SYSTEM_EXPLAIN, FEWSHOT, SCHEMA_EXPLAIN) ont ete SUPPRIMEES : il n'existe
     plus qu'un seul prompt, celui que le LLM recoit reellement. Fin du prompt
     fantome (le fichier prompts_cnn n'etait importe par personne).
  2. POLICY_FLAGS ACTIFS -- episode_context_cnn.policy_flags(ep) est injecte
     dans le prompt et impose un PLANCHER de severite (regle 6). C'est de la
     priorisation, jamais du filtrage : l'alerte reste presentee.
  3. GROUNDING APPLIQUE -- grounding_cnn nettoie la SORTIE sans jamais fermer
     d'alerte : MITRE canonise (id valide + tactique/nom issus de la KB),
     kb_refs non montres ecartes, evidence non verifiable signalee. (grounding_cnn
     existait deja mais n'etait cable nulle part.)
  4. SEVERITE NORMALISEE -- seul signal de tri restant en mode explication :
     garantie dans l'echelle CL.SEVERITIES et conforme au plancher POLICY_FLAGS.

CONTRAT DE SORTIE PRESERVE. Toutes les cles historiques de cnn_triage.jsonl et
cnn_triage_report.json sont conservees a l'identique (dont `verdict`, fixe a
CL.ALERT_VERDICT). Les cles AJOUTEES (kb_refs_dropped, mitre_dropped,
evidence_suspects, policy_flags) sont PUREMENT observationnelles : l'aval
(adaptateur, Mongo, API, dashboards) peut les ignorer sans rien casser.

Usage : python triage_cnn.py [--limit N] [--episode EP-xxxx]
"""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter

import config_llm_cnn as CL
import episode_context_cnn as EC
import grounding_cnn as G
import prompts_cnn as P
import rag_cnn
from llm_client_cnn import LLMError, complete_json


# --- normalisation de sortie (jamais de fermeture d'alerte) -----------------
def _iso(v):
    return v.isoformat() if hasattr(v, "isoformat") else str(v)


def _clamp_confidence(c) -> float | None:
    """La confiance est un indice pour l'analyste : on la ramene dans [0,1] ou
    on la neutralise (None) plutot que d'afficher une valeur hors bornes."""
    try:
        return max(0.0, min(1.0, float(c)))
    except (TypeError, ValueError):
        return None


def _clamp_severity(sev, flags: list[str]) -> str:
    """Severite = SEUL signal de tri en mode explication. On garantit deux
    choses, sans jamais fermer d'alerte :
      * valeur DANS l'echelle CL.SEVERITIES (sinon le tri du dashboard casse).
        Une valeur inconnue est ramenee a 'medium' -- sur un outil de securite,
        on ne sous-priorise pas par defaut.
      * PLANCHER POLICY_FLAGS (regle 6) : une primitive sensible impose au moins
        'medium'. On ne fait que MONTER la severite, jamais la descendre, jamais
        cacher l'alerte. C'est un filet pour la non-conformite du prompt, pas un
        filtre.
    """
    order = CL.SEVERITIES  # ("info","low","medium","high","critical")
    s = (str(sev) if sev is not None else "").strip().lower()
    if s not in order:
        s = "medium"
    if flags and order.index(s) < order.index("medium"):
        s = "medium"
    return s


# --- appel LLM (explication, pas verdict) -----------------------------------
def triage_rag(ep: EC.Episode, index: rag_cnn.KBIndex,
               dossier: str, flags: list[str]) -> tuple[dict, list[str]]:
    """Retourne (explication_brute, ids_kb_montres).

    Aucun champ 'verdict' n'est lu du LLM : _build_record le fixe a
    CL.ALERT_VERDICT. `dossier` et `flags` sont calcules EN AMONT (ils ne font
    aucun appel reseau) pour rester disponibles meme sur le chemin fail-open.
    """
    hits = index.retrieve(ep.rag_query(), ep.keys, ep.log_source)
    shown_ids = [c.id for c, _ in hits]
    kb_block = index.render(hits)
    user = P.build_user_prompt(dossier, kb_block, index.allowed_mitre, flags)
    messages = ([{"role": "system", "content": P.SYSTEM_PROMPT}]
                + P.FEWSHOT
                + [{"role": "user", "content": user}])
    return complete_json(messages), shown_ids


def _build_record(ep: EC.Episode, raw: dict, shown: list[str],
                  dossier: str, flags: list[str],
                  index: rag_cnn.KBIndex) -> dict:
    """`verdict` FIXE a CL.ALERT_VERDICT. Grounding applique a la SORTIE :
      - MITRE canonise : id filtre sur la liste fermee, tactique/nom recopies
        depuis la KB (le LLM ne fournit que l'id) ;
      - kb_refs verifiees : seules les sources REELLEMENT montrees sont gardees ;
      - evidence verifiee : items citant un identifiant concret absent du
        dossier signales (observation, pas rejet).
    Rien de tout cela ne ferme l'alerte -- seule la QUALITE de l'explication est
    nettoyee. Toutes les cles historiques restent identiques.
    """
    kept_refs, dropped_refs = G.check_kb_refs(raw.get("kb_refs"), shown)
    mitre_ok, mitre_dropped = G.canonical_mitre(raw.get("mitre"),
                                                index.allowed_mitre)
    evidence = list(raw.get("evidence", []) or [])
    evidence_suspects = G.check_evidence(evidence, dossier)

    return {
        "episode_id": ep.episode_id, "log_source": ep.log_source,
        "host_name": ep.host_name, "start": _iso(ep.start), "end": _iso(ep.end),
        "duration_s": ep.duration_s, "n_alerts": ep.n_alerts,
        "mse_max": round(ep.mse_max, 3), "mse_mean": round(ep.mse_mean, 3),
        "threshold": round(ep.threshold, 3),
        "verdict": CL.ALERT_VERDICT,   # le CNN a leve l'alerte, le LLM ne decide pas
        "confidence": _clamp_confidence(raw.get("confidence")),
        "severity": _clamp_severity(raw.get("severity"), flags),
        "title": str(raw.get("title", raw.get("error", ""))),
        "rationale": raw.get("rationale", ""),
        "mitre": mitre_ok,
        "evidence": evidence,
        "recommendation": raw.get("recommendation", []),
        "kb_refs": kept_refs, "kb_shown": shown,
        # --- additifs PUREMENT observationnels (l'aval peut les ignorer) ----
        "kb_refs_dropped": dropped_refs,
        "mitre_dropped": mitre_dropped,
        "evidence_suspects": evidence_suspects,
        "policy_flags": flags,
    }


def _write_report(results: list[dict], eps: list, index: rag_cnn.KBIndex,
                  n_fail_open: int, elapsed_s: float, sev_counts: Counter) -> None:
    """Ecrit cnn_triage_report.json avec les cles que cnn_adapter._TRIAGE_KEEP
    conserve. Valeurs HONNETES du mode explication : le LLM ne retire plus rien,
    donc noise_reduction_pct=0 et n_episodes_to_analyst = tous les episodes.
    Bloc `grounding` = additif : sante de la couche de verification, sans aucun
    impact sur le contrat de sortie."""
    report = {
        "model": CL.LLM_MODEL,
        "provider": CL.LLM_PROVIDER,
        "temperature": CL.LLM_TEMPERATURE,
        "rag_backend": index.enc.backend,
        "n_kb_chunks": len(index.chunks),
        "n_episodes_in": len(eps),
        "n_alerts_in": sum(e.n_alerts for e in eps),
        "verdicts": dict(Counter(r["verdict"] for r in results)),  # {"true_positive": N}
        "severities": dict(sev_counts),
        "n_fail_open": n_fail_open,
        "n_episodes_to_analyst": len(results),  # tous : rien n'est filtre
        "noise_reduction_pct": 0.0,             # le LLM ne retire plus rien
        "elapsed_s": round(elapsed_s, 1),
        "mode": "explication_seule",
        "grounding": {
            "n_episodes_policy_flagged": sum(1 for r in results if r["policy_flags"]),
            "n_mitre_dropped": sum(len(r["mitre_dropped"]) for r in results),
            "n_kb_refs_dropped": sum(len(r["kb_refs_dropped"]) for r in results),
            "n_evidence_suspects": sum(len(r["evidence_suspects"]) for r in results),
        },
    }
    with open("cnn_triage_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--alerts", default=CL.ALERTS_CSV)
    ap.add_argument("--kb", default=CL.KB_DIR)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--episode", default=None)
    a = ap.parse_args()

    print("=" * 62)
    print("  TRIAGE CNN -- MODE EXPLICATION SEULE (aucun verdict LLM)")
    print("=" * 62)

    eps = EC.build_episodes(a.alerts)
    if a.episode:
        eps = [e for e in eps if e.episode_id == a.episode]
    if a.limit:
        eps = eps[:a.limit]

    print(f"\n{len(eps)} episodes a expliquer "
          f"({sum(e.n_alerts for e in eps)} alertes brutes)")
    print(f"modele={CL.LLM_MODEL} | provider={CL.LLM_PROVIDER} | "
          f"T={CL.LLM_TEMPERATURE} | verdict fixe={CL.ALERT_VERDICT}\n")
    print("[index RAG]")
    index = rag_cnn.get_index(a.kb)
    print()

    t0, results, n_fail_open = time.time(), [], 0
    for i, ep in enumerate(eps, 1):
        # dossier + flags : calcules AVANT l'appel LLM (aucun reseau) -> restent
        # disponibles pour _build_record meme si le LLM echoue (fail-open).
        dossier = ep.render()
        flags = EC.policy_flags(ep)
        try:
            raw, shown = triage_rag(ep, index, dossier, flags)
        except LLMError as e:
            # Fail-open : une panne LLM ne masque JAMAIS l'alerte. L'episode
            # reste affiche (verdict constant), l'explication signale l'echec.
            raw, shown = {"error": str(e), "severity": "medium"}, []
            n_fail_open += 1

        rec = _build_record(ep, raw, shown, dossier, flags, index)
        results.append(rec)

        sev = rec["severity"] if rec["severity"] is not None else "-"
        conf = rec["confidence"] if rec["confidence"] is not None else "-"
        fl = "  [POLICY]" if rec["policy_flags"] else ""
        print(f"  [{i:3d}/{len(eps)}] sev={sev:8s} conf={conf} "
              f"{ep.episode_id} {ep.log_source:7s} | {rec['title'][:46]}{fl}")
        if rec["kb_refs"]:
            print(f"          kb_refs={rec['kb_refs']}  (montres={shown})")
        if rec["kb_refs_dropped"]:
            print(f"          [obs] kb_ref(s) NON montre(s) ecarte(s) : "
                  f"{rec['kb_refs_dropped']}")
        if rec["mitre_dropped"]:
            print(f"          [obs] technique(s) MITRE hors liste ecartee(s) : "
                  f"{rec['mitre_dropped']}")
        if rec["evidence_suspects"]:
            print(f"          [obs] evidence sans appui dans le dossier : "
                  f"{rec['evidence_suspects']}")

    out = "cnn_triage.jsonl"
    with open(out, "w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    sev_counts = Counter(r["severity"] for r in results)
    _write_report(results, eps, index, n_fail_open, time.time() - t0, sev_counts)

    n_flagged = sum(1 for r in results if r["policy_flags"])
    print(f"\nseverites : {dict(sev_counts)}")
    print(f"verdict (fixe pour toutes) : {CL.ALERT_VERDICT} | "
          f"fail-open : {n_fail_open} | bruit retire : 0%")
    print(f"policy-flagged : {n_flagged}/{len(results)} episodes "
          f"(plancher severite >= medium)")
    print(f"{len(eps)} episodes expliques en {round(time.time() - t0, 1)}s")
    print(f"-> {out}")
    print(f"-> cnn_triage_report.json")
    print("=" * 62)


if __name__ == "__main__":
    main()