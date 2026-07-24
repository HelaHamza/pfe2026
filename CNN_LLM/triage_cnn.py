"""
triage_cnn.py
=============
COUCHE 3 de Sentinel (branche CNN) : triage semantique des episodes.

    predict_cnn.py  ->  cnn_alerts.csv          (toutes les alertes de la fenetre)
                        cnn_alerts_episodes.csv (episodes EMIS, watermarkes)
                        cnn_run_meta.json       (since / watermark du run)
                                    |
                                    v
                          triage_cnn.py  (ce module)
                            0. FILTRE DE FENETRE (since < end <= watermark)
                            1. dossier d'episode
                            2. retrieval RAG hybride
                            3. appel LLM (JSON strict)
                            4. validation + garde-fous
                                    |
                                    v
                  cnn_triage.jsonl / cnn_triaged_episodes.csv
                                    |
                                    v
                         dashboard React / FastAPI

Le CNN n'est jamais modifie : cette couche est purement AVAL, elle ne touche ni
le score, ni le seuil, ni le modele. Le CNN mesure la RARETE, le LLM le SENS.

L'etape 0 est INDISPENSABLE : cnn_alerts.csv contient toute la fenetre (seed
inclus, queue non stabilisee incluse). Sans elle, le triage re-traite des
episodes deja triages au run precedent et triage trop tot ceux qui ne sont pas
figes -> doublons d'appels LLM et doublons Mongo.

Usage :
    python triage_cnn.py                     # tous les episodes EMIS du run
    python triage_cnn.py --limit 5           # essai rapide
    python triage_cnn.py --dry-run           # prompts seuls, 0 appel LLM
    python triage_cnn.py --episode EP-xxx    # un episode precis
    python triage_cnn.py --no-window-filter  # run manuel hors orchestrateur
"""
from __future__ import annotations

import argparse
import json
import time

import pandas as pd

import config_llm_cnn as CL
import episode_context_cnn as EC
import prompts_cnn as P
import rag_cnn
from llm_client_cnn import LLMError, complete_json


def _iso(v):
    """Timestamp OU str -> ISO-8601 UTC (séparateur 'T'). Aligne le format des
    dates CNN sur le @timestamp Sigma (.isoformat()) : str(Timestamp) produit un
    séparateur ESPACE (ASCII 32 < 'T' 84) qui casse le tri lexicographique mixte
    CNN/Sigma dans la table de résultats."""
    ts = pd.to_datetime(v, utc=True, errors="coerce")
    return ts.isoformat() if pd.notna(ts) else str(v)


# ---------------------------------------------------------------------------
def _validate(raw: dict, ep: EC.Episode, allowed_mitre: set[str],
              flags: list[str]) -> dict:
    """Garde-fous DETERMINISTES appliques APRES le LLM.

    Un LLM est un composant faillible : il peut halluciner un T-code, se
    montrer trop sur de lui, ou clore une alerte qu'aucun analyste ne
    fermerait. Ces regles sont verifiables ligne a ligne par un jury, ce qui
    rend le systeme auditable meme si le modele derape.
    """
    out: dict = {
        "episode_id": ep.episode_id,
        "log_source": ep.log_source,
        "host_name": ep.host_name,
        "start": _iso(ep.start), "end": _iso(ep.end),
        "duration_s": ep.duration_s, "n_alerts": ep.n_alerts,
        "mse_max": round(ep.mse_max, 3), "mse_mean": round(ep.mse_mean, 3),
        "threshold": round(ep.threshold, 3),
        "policy_flags": flags,
        "guardrails": [],
    }

    # 1. verdict dans la liste fermee
    v = str(raw.get("verdict", "")).strip().lower()
    if v not in CL.VERDICTS:
        out["guardrails"].append(f"verdict invalide '{v}' -> uncertain")
        v = "uncertain"

    # 2. POLICY_FLAGS : interdiction de clore
    if flags and v == "false_positive":
        out["guardrails"].append(
            "false_positive interdit (POLICY_FLAGS actifs) -> uncertain")
        v = "uncertain"
    out["verdict"] = v

    # 3. confiance bornee ; un 'uncertain' ne peut pas etre tres confiant
    try:
        conf = float(raw.get("confidence", 0.5))
    except (TypeError, ValueError):
        conf = 0.5
    conf = min(max(conf, 0.0), 1.0)
    if v == "uncertain" and conf > 0.6:
        out["guardrails"].append(
            f"confiance {conf:.2f} plafonnee a 0.60 (verdict uncertain)")
        out["llm_confidence_raw"] = round(conf, 3)
        conf = 0.6
    out["confidence"] = round(conf, 3)

    # 4. severite coherente avec le verdict
    sev = str(raw.get("severity", "low")).strip().lower()
    if sev not in CL.SEVERITIES:
        sev = "low"
    if v == "false_positive" and sev in ("high", "critical"):
        out["guardrails"].append(f"severite '{sev}' incoherente avec un FP -> info")
        sev = "info"
    out["severity"] = sev

    # 5. MITRE : liste fermee, pas d'invention
    mitre, dropped = [], []
    for m in raw.get("mitre") or []:
        if not isinstance(m, dict):
            continue
        tid = str(m.get("technique_id", "")).strip().upper()
        if tid in allowed_mitre:
            mitre.append({"technique_id": tid,
                          "tactic": str(m.get("tactic", "")).strip(),
                          "name": str(m.get("name", "")).strip()})
        elif tid:
            dropped.append(tid)
    if dropped:
        out["guardrails"].append(
            f"technique(s) hors KB rejetee(s) : {', '.join(dropped)}")
    out["mitre"] = mitre

    # 6. champs texte
    out["title"] = str(raw.get("title", ""))[:120]
    out["rationale"] = str(raw.get("rationale", ""))
    out["missing_context"] = str(raw.get("missing_context", ""))
    for k in ("evidence", "recommendation", "kb_refs"):
        val = raw.get(k) or []
        out[k] = [str(x) for x in val][:6] if isinstance(val, list) else []

    # 7. tracabilite : une conclusion sans source KB est signalee
    if not out["kb_refs"]:
        out["guardrails"].append("aucune source KB citee -> explication non tracable")

    # 8. exigence d'actionnabilite
    if v in ("true_positive", "uncertain"):
        if len(out["rationale"]) < CL.MIN_RATIONALE_CHARS:
            out["guardrails"].append(
                f"explication trop courte ({len(out['rationale'])} car.) "
                f"-> revue humaine requise")
        if not out["evidence"]:
            out["guardrails"].append("aucune preuve citee -> conclusion non verifiable")
        if not out["recommendation"]:
            out["guardrails"].append("aucune recommandation -> repli injecte")
            out["recommendation"] = [CL.FALLBACK_RECOMMENDATION]

    if v == "false_positive" and len(out["rationale"]) < CL.MIN_RATIONALE_CHARS:
        out["guardrails"].append(
            "cloture sans justification suffisante -> uncertain")
        out["verdict"] = "uncertain"
        out["confidence"] = min(out["confidence"], 0.6)

    out["actionable"] = bool(out["recommendation"]) and bool(out["evidence"])
    return out


def _fail_open(ep: EC.Episode, flags: list[str], reason: str) -> dict:
    """Panne LLM : l'episode remonte a l'analyste. Jamais de suppression
    silencieuse d'une alerte de securite."""
    return {
        "episode_id": ep.episode_id, "log_source": ep.log_source,
        "host_name": ep.host_name, "start": _iso(ep.start), "end": _iso(ep.end),
        "duration_s": ep.duration_s, "n_alerts": ep.n_alerts,
        "mse_max": round(ep.mse_max, 3), "mse_mean": round(ep.mse_mean, 3),
        "threshold": round(ep.threshold, 3),
        "verdict": CL.FAIL_OPEN_VERDICT, "confidence": 0.0, "severity": "low",
        "title": f"Triage indisponible ({ep.log_source})",
        "mitre": [], "rationale": f"Echec de la couche LLM : {reason}. "
                                  f"L'episode est conserve pour revue humaine.",
        "evidence": [], "recommendation": ["Revue manuelle requise."],
        "kb_refs": [], "missing_context": "verdict LLM indisponible",
        "policy_flags": flags, "guardrails": ["fail-open"],
    }


# ---------------------------------------------------------------------------
def triage_episode(ep: EC.Episode, index: rag_cnn.KBIndex,
                   dry_run: bool = False) -> dict:
    flags = EC.policy_flags(ep)
    hits = index.retrieve(ep.rag_query(), ep.keys, ep.log_source)
    dossier = ep.render() + f"\nPOLICY_FLAGS: {'; '.join(flags) or '(aucun)'}"
    user = P.build_user_prompt(dossier, index.render(hits),
                              index.allowed_mitre, flags)
    messages = ([{"role": "system", "content": P.SYSTEM_PROMPT}]
                + P.FEWSHOT
                + [{"role": "user", "content": user}])

    if dry_run:
        return {"episode_id": ep.episode_id,
                "kb_hits": [c.id for c, _ in hits],
                "policy_flags": flags,
                "prompt_chars": sum(len(m["content"]) for m in messages),
                "prompt": user}
    try:
        raw = complete_json(messages)
    except LLMError as e:
        return _fail_open(ep, flags, str(e))
    return _validate(raw, ep, index.allowed_mitre, flags)


# ---------------------------------------------------------------------------
_EMPTY_COLS = ["episode_id", "log_source", "host_name", "start", "end",
               "duration_s", "n_alerts", "mse_max", "verdict", "confidence",
               "severity", "title", "mitre", "rationale", "recommendation",
               "kb_refs", "policy_flags"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--alerts", default=CL.ALERTS_CSV)
    ap.add_argument("--kb", default=CL.KB_DIR)
    ap.add_argument("--run-meta", default=CL.RUN_META_JSON)
    ap.add_argument("--no-window-filter", action="store_true",
                    help="Desactive le filtre de fenetre (run manuel hors "
                         "orchestrateur). ATTENTION : re-triage possible.")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--episode", default=None)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    print("=" * 68)
    print("  TRIAGE LLM + RAG - branche CNN (couche 3)")
    print("=" * 68)

    eps_all = EC.build_episodes(a.alerts)
    print(f"\n[0] {len(eps_all)} episodes re-agreges depuis "
          f"{a.alerts.split('/')[-1]}")

    # --- FILTRE DE FENETRE : meme frontiere que predict_cnn -----------------
    if a.no_window_filter:
        print("    /!\\ filtre de fenetre DESACTIVE (--no-window-filter) : "
              "re-triage d'episodes deja traites possible.")
        eps = eps_all
    else:
        meta = EC.load_run_meta(a.run_meta)
        eps, diag = EC.filter_emitted(eps_all, meta)
        print(f"    fenetre du run : ]{diag['since'] or 'BOOTSTRAP'} , "
              f"{diag['watermark']}]")
        print(f"    -> {len(eps)} a triager | "
              f"{len(diag['held'])} non stabilises (run suivant) | "
              f"{len(diag['stale'])} deja traites (zone seed)")
        if diag["broken"]:
            print(f"    /!\\ {len(diag['broken'])} episode(s) sans horodatage "
                  f"exploitable -> triages par precaution (fail-open).")

        # Diagnostic de coherence avec les episodes REELLEMENT emis.
        xc = EC.crosscheck_emitted(eps, CL.EPISODES_CSV)
        if xc["available"]:
            if xc["missing"] or xc["extra"]:
                print(f"    /!\\ DIVERGENCE d'agregation vs predict_cnn "
                      f"({xc['n_emitted']} emis) : "
                      f"{len(xc['missing'])} non re-derive(s), "
                      f"{len(xc['extra'])} en trop.")
                print(f"        -> episode_id instable entre inference et "
                      f"triage : l'upsert Mongo ne dedoublonne plus ces "
                      f"episodes. A corriger (aligner aggregate_alerts et "
                      f"build_episodes) avant mise en production.")
            else:
                print(f"    ✓ coherence episode_id inference/triage : "
                      f"{xc['n_emitted']}/{xc['n_emitted']}")

    if a.episode:
        eps = [e for e in eps if e.episode_id == a.episode]
    if a.limit:
        eps = eps[:a.limit]

    print(f"\n[1] {len(eps)} episodes a trier "
          f"({sum(e.n_alerts for e in eps)} alertes brutes)")

    print("\n[2] Construction de l'index RAG...")
    index = rag_cnn.get_index(a.kb)

    if a.dry_run:
        for ep in eps:
            d = triage_episode(ep, index, dry_run=True)
            print(f"\n--- {d['episode_id']} | {ep.log_source} | "
                  f"{d['prompt_chars']} car. | kb={d['kb_hits']} | "
                  f"flags={d['policy_flags']}")
        print("\n[dry-run] aucun appel LLM effectue.")
        return

    print(f"\n[3] Triage (modele={CL.LLM_MODEL}, provider={CL.LLM_PROVIDER}, "
          f"T={CL.LLM_TEMPERATURE})...")
    t0, results = time.time(), []
    for i, ep in enumerate(eps, 1):
        r = triage_episode(ep, index)
        results.append(r)
        mark = {"true_positive": "TP", "false_positive": "FP",
                "uncertain": "??"}[r["verdict"]]
        print(f"  [{i:3d}/{len(eps)}] {mark} {r['severity']:8s} "
              f"conf={r['confidence']:.2f} {r['episode_id']} "
              f"{r['log_source']:7s} | {r['title'][:52]}")
        if r["guardrails"]:
            print(f"         garde-fous : {'; '.join(r['guardrails'])}")

    # --- garde-fou operationnel : un fail-open TOTAL n'est pas un triage ----
    n_failopen = sum(1 for r in results if "fail-open" in r.get("guardrails", []))
    if results and n_failopen == len(results):
        print(f"\n  /!\\ {n_failopen}/{len(results)} episodes en FAIL-OPEN : "
              f"la couche LLM n'a repondu AUCUNE fois.")
        print(f"      Verifier LLM_PROVIDER / LLM_BASE_URL / cle API avant "
              f"d'exploiter ce run. Aucun triage n'a reellement eu lieu.")

    # --- sorties ------------------------------------------------------------
    with open(CL.TRIAGE_JSONL, "w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    if results:
        df = pd.DataFrame([{
            **{k: r[k] for k in ("episode_id", "log_source", "host_name", "start",
                                 "end", "duration_s", "n_alerts", "mse_max",
                                 "verdict", "confidence", "severity", "title")},
            "mitre": ", ".join(m["technique_id"] for m in r["mitre"]),
            "rationale": r["rationale"],
            "recommendation": " | ".join(r["recommendation"]),
            "kb_refs": ", ".join(r["kb_refs"]),
            "policy_flags": "; ".join(r["policy_flags"]),
        } for r in results])
        sev_rank = {s: i for i, s in enumerate(CL.SEVERITIES)}
        df = df.sort_values(["severity", "mse_max"],
                            key=lambda c: c.map(sev_rank) if c.name == "severity" else c,
                            ascending=[False, False])
    else:
        # DataFrame vide SANS colonnes -> sort_values leve KeyError.
        df = pd.DataFrame(columns=_EMPTY_COLS)
    df.to_csv(CL.TRIAGE_CSV, index=False)

    counts = pd.Series([r["verdict"] for r in results]).value_counts().to_dict() \
        if results else {}
    kept = [r for r in results if r["verdict"] != "false_positive"]
    report = {
        "model": CL.LLM_MODEL, "provider": CL.LLM_PROVIDER,
        "temperature": CL.LLM_TEMPERATURE,
        "rag_backend": index.enc.backend, "n_kb_chunks": len(index.chunks),
        "n_episodes_reaggregated": len(eps_all),
        "n_episodes_in": len(eps),
        "n_alerts_in": int(sum(e.n_alerts for e in eps)),
        "verdicts": counts,
        "n_fail_open": n_failopen,
        "n_episodes_to_analyst": len(kept),
        "noise_reduction_pct": round(
            100 * (1 - len(kept) / max(len(eps), 1)), 1),
        "elapsed_s": round(time.time() - t0, 1),
    }
    with open(CL.TRIAGE_REPORT_JSON, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\n[4] {counts}")
    print(f"    {len(eps)} episodes -> {len(kept)} remontes a l'analyste "
          f"(-{report['noise_reduction_pct']}% de bruit) en {report['elapsed_s']}s")
    print(f"    -> {CL.TRIAGE_JSONL} | {CL.TRIAGE_CSV} | {CL.TRIAGE_REPORT_JSON}")
    print("    Verifier la RETENTION DU RAPPEL : python evaluate_triage_cnn.py")
    print("=" * 68)


if __name__ == "__main__":
    main()