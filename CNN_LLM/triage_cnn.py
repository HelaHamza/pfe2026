"""
triage_llm_rag.py  (etape 2 : LLM + RAG, sans garde-fou de sortie)
==================================================================
Enrichissement d'ENTREE seul (RAG). La sortie du LLM reste BRUTE.

AJOUTS PROMPT (pour recuperer du rappel SANS garde-fou code) :
  1. PRINCIPE D'ASYMETRIE CIBLE dans le system prompt : certaines raretes sont
     des signatures d'attaque connues et ne doivent jamais etre classees
     false_positive par defaut (rafale d'echecs d'auth, syscall rare, execution
     depuis un chemin inhabituel).
  2. FEWSHOT equilibre (3 exemples) : FP benin (protege la precision) + TP
     brute-force + uncertain syscall. Sans le FP, le modele sur-escalade et la
     precision chute. Aucun exemple n'utilise de donnee du jeu de test evalue.

Ce qui reste RETIRE (controles de SORTIE, pas du RAG) :
  _validate, POLICY_FLAGS, grounding, fail-open. Le verdict sort tel quel.

Usage :
    python triage_llm_rag.py [--limit N] [--episode EP-xxxx]
"""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter

import config_llm_cnn as CL
import episode_context_cnn as EC
import rag_cnn
from llm_client_cnn import LLMError, complete_json


SYSTEM_MIN = """Tu es analyste SOC de niveau 2, specialiste des hotes Linux (Ubuntu).

Un auto-encodeur convolutif (CNN) non supervise surveille les journaux d'un
poste Linux. Il leve une alerte quand un evenement est statistiquement RARE
(score mse eleve). Les alertes proches dans le temps sont regroupees en EPISODE.

Point central : le modele detecte ce qui est RARE, pas ce qui est MALVEILLANT.
Beaucoup d'activites benignes sont rares (rotation des journaux, refresh snap,
premier lancement d'un outil, reveil de veille). C'est TOI qui apportes la
couche de SENS que le modele n'a pas.

Pour chaque episode, tranche :
  - false_positive : rarete benigne
  - true_positive  : activite reellement suspecte
  - uncertain      : le dossier ne suffit pas a trancher"""

# --- CHANGEMENT 1 : principe d'asymetrie CIBLE ------------------------------
SYSTEM_ASYMMETRY = """

PRINCIPE D'ASYMETRIE (important). Classer une attaque en false_positive est
l'erreur la plus couteuse. Certaines activites RARES sont des signatures
d'attaque connues : elles ne doivent JAMAIS etre classees false_positive par
defaut -- au minimum "uncertain" :
  - RAFALE D'ECHECS D'AUTHENTIFICATION (plusieurs is_fail rapproches, surtout
    avec des utilisateurs inconnus / user_rarity eleve) = tentative de
    brute-force. L'origine (y compris 127.0.0.1) ne la rend PAS benigne.
  - SYSCALL RARE (ptrace, capset/setcap, finit_module/insmod, utimensat) =
    souvent injection, elevation, chargement de module ou anti-forensique.
  - EXECUTION DEPUIS UN CHEMIN INHABITUEL (/tmp, /dev/shm, /var/tmp, repertoire
    cache commencant par '.') = localisation malware classique.
Ces motifs restent des RARETES pour le CNN : c'est a toi de ne pas les clore.
En dehors de ces motifs, une rarete bien expliquee par un usage systeme normal
reste un false_positive -- n'escalade pas tout."""

SYSTEM_RAG_EXTRA = """

Pour t'aider, on te fournit des extraits d'une base de connaissances, chacun
dans une balise <kb id="..."> : profils d'activites benignes recurrentes et
profils de menaces connues, propres a ce poste.

Utilise le DOSSIER d'episode ET ces extraits <kb>. Quand un extrait fonde ta
conclusion, cite son id dans "kb_refs". Si tu proposes une technique MITRE,
choisis-la dans la liste ALLOWED_MITRE fournie.

Reponds EXCLUSIVEMENT par un objet JSON valide, sans texte avant ni apres et
sans balises markdown."""

SYSTEM_RAG = SYSTEM_MIN + SYSTEM_ASYMMETRY + SYSTEM_RAG_EXTRA


SCHEMA_RAG = {
    "episode_id": "string, recopie a l'identique",
    "verdict": "true_positive | false_positive | uncertain",
    "confidence": "float 0.0-1.0",
    "severity": "info | low | medium | high | critical",
    "title": "string, resume factuel court",
    "mitre": [{"technique_id": "Txxxx[.xxx] issu de ALLOWED_MITRE",
               "tactic": "nom de la tactique", "name": "nom de la technique"}],
    "rationale": "string, 2-4 phrases en francais, le raisonnement decisif",
    "evidence": ["string, faits extraits du dossier"],
    "recommendation": ["string, actions concretes en francais"],
    "kb_refs": ["id des chunks <kb> utilises"],
}


# --- CHANGEMENT 2 : FEWSHOT equilibre (FP / TP brute-force / uncertain) ------
# Exemples SYNTHETIQUES (EP-EXEMPLE-*), aucune donnee du jeu de test evalue.
FEWSHOT = [
    # (a) FP benin -- indispensable pour NE PAS sur-escalader (protege la precision)
    {"role": "user", "content": """EPISODE EP-EXEMPLE-FP
  source          : auditd
  hote            : poste-demo
  fenetre         : 2026-01-05 23:00:00+00:00 -> 2026-01-05 23:00:04+00:00  (4.0 s)
  alertes         : 18
  score mse       : max=44.10  moyen=21.80  (seuil POT=8.50, ratio max/seuil=5.2x)
  utilisateurs    : root x18
  IP sources      : (aucune)
  processus       : logrotate x5, gzip x4, savelog x3, cp x3, rm x3
  types d'evt     : executed x18
  features dom.   : parent_child_rarity x11, exe_path_rarity x7"""},
    {"role": "assistant", "content": json.dumps({
        "episode_id": "EP-EXEMPLE-FP",
        "verdict": "false_positive", "confidence": 0.9, "severity": "info",
        "title": "Rotation quotidienne des journaux (logrotate)",
        "mitre": [],
        "rationale": "Rafale root en 4 s composee uniquement de la chaine "
                     "logrotate -> savelog/gzip/cp/rm sur /var/log, a 23h pile. "
                     "Rarete d'identite attendue pour une tache qui ne tourne "
                     "qu'une fois par 24h. Aucun binaire hors chemin systeme, "
                     "aucun motif d'attaque : rarete benigne.",
        "evidence": ["processus logrotate/gzip/savelog/cp/rm",
                     "user_name = root", "fenetre 23:00:00 -> 23:00:04"],
        "recommendation": ["Aucune action. Ajouter cette signature a la baseline."],
        "kb_refs": ["baseline-logrotate", "ref-features"],
    }, ensure_ascii=False)},

    # (b) TP brute-force -- apprend au modele que les echecs d'auth = suspect
    {"role": "user", "content": """EPISODE EP-EXEMPLE-AUTH
  source          : auth
  hote            : poste-demo
  fenetre         : 2026-01-06 09:12:03+00:00 -> 2026-01-06 09:12:19+00:00  (16.0 s)
  alertes         : 9
  score mse       : max=21.30  moyen=15.70  (seuil POT=6.20, ratio max/seuil=3.4x)
  utilisateurs    : invalid_user x9
  IP sources      : 203.0.113.7 x9
  processus       : sshd x9
  types d'evt     : ssh_login x9
  features dom.   : is_fail x9, user_rarity x7, inter_arrival_log x5"""},
    {"role": "assistant", "content": json.dumps({
        "episode_id": "EP-EXEMPLE-AUTH",
        "verdict": "true_positive", "confidence": 0.8, "severity": "medium",
        "title": "Rafale d'echecs SSH avec utilisateurs invalides (brute-force)",
        "mitre": [{"technique_id": "T1110.001", "tactic": "Credential Access",
                   "name": "Brute Force: Password Guessing"}],
        "rationale": "Neuf echecs d'authentification SSH en 16 s, tous sur des "
                     "noms d'utilisateur inconnus (user_rarity eleve) et a un "
                     "rythme serre. C'est la signature d'une tentative de "
                     "brute-force, pas une rarete benigne : un utilisateur "
                     "legitime ne genere pas 9 echecs consecutifs sur des "
                     "comptes inexistants. Le motif d'echecs repetes prime sur "
                     "la rarete.",
        "evidence": ["9 alertes is_fail en 16 s", "utilisateurs invalides",
                     "processus sshd", "inter_arrival_log rapproche"],
        "recommendation": ["Identifier l'origine des tentatives.",
                           "Confirmer qu'aucune n'a abouti (succes apres la rafale).",
                           "Envisager fail2ban / limitation de tentatives."],
        "kb_refs": ["threat-ssh-bruteforce", "ref-features"],
    }, ensure_ascii=False)},

    # (c) uncertain syscall -- apprend a ESCALADER (pas fermer) les syscalls rares
    {"role": "user", "content": """EPISODE EP-EXEMPLE-SYSCALL
  source          : auditd
  hote            : poste-demo
  fenetre         : 2026-01-07 14:03:11+00:00 -> 2026-01-07 14:03:12+00:00  (1.0 s)
  alertes         : 2
  score mse       : max=18.90  moyen=13.20  (seuil POT=8.50, ratio max/seuil=2.2x)
  utilisateurs    : user-demo x2
  IP sources      : (aucune)
  processus       : strace x1, true x1
  types d'evt     : syscall x2
  features dom.   : syscall_rarity x2, proc_rarity x1"""},
    {"role": "assistant", "content": json.dumps({
        "episode_id": "EP-EXEMPLE-SYSCALL",
        "verdict": "uncertain", "confidence": 0.55, "severity": "medium",
        "title": "Syscall rare (ptrace via strace) -- contexte insuffisant",
        "mitre": [{"technique_id": "T1055", "tactic": "Defense Evasion",
                   "name": "Process Injection"}],
        "rationale": "Appel d'un syscall rarement observe (ptrace via strace). "
                     "ptrace sert au debogage legitime mais aussi a l'injection "
                     "de code et a l'inspection memoire d'un autre processus. Le "
                     "dossier seul ne distingue pas un developpeur qui debugge "
                     "d'une tentative d'injection : rarete de syscall sensible "
                     "-> uncertain, escalade, jamais false_positive.",
        "evidence": ["processus strace", "feature dominante syscall_rarity",
                     "user-demo"],
        "recommendation": ["Identifier le processus cible du ptrace.",
                           "Verifier si strace/gdb est attendu pour cet utilisateur."],
        "kb_refs": ["threat-syscall-rarity", "ref-features"],
    }, ensure_ascii=False)},
]


def _iso(v):
    return v.isoformat() if hasattr(v, "isoformat") else str(v)


def _format_allowed_mitre(allowed_mitre: dict) -> str:
    lignes = []
    for tid in sorted(allowed_mitre):
        info = allowed_mitre[tid] or {}
        tac, nom = info.get("tactic", ""), info.get("name", "")
        suffix = f" ({tac} -- {nom})" if (tac or nom) else ""
        lignes.append(f"{tid}{suffix}")
    return "\n".join(lignes) or "(aucune)"


def triage_rag(ep: EC.Episode, index: rag_cnn.KBIndex) -> tuple[dict, list[str]]:
    hits = index.retrieve(ep.rag_query(), ep.keys, ep.log_source)
    shown_ids = [c.id for c, _ in hits]
    kb_block = index.render(hits)
    user = (
        f"### BASE DE CONNAISSANCES (extraits selectionnes par le RAG)\n"
        f"{kb_block}\n\n"
        f"### ALLOWED_MITRE (techniques citables issues de la KB)\n"
        f"{_format_allowed_mitre(index.allowed_mitre)}\n\n"
        f"### DOSSIER D'EPISODE\n{ep.render()}\n\n"
        f"### SCHEMA DE SORTIE (JSON strict, rien d'autre)\n"
        f"{json.dumps(SCHEMA_RAG, ensure_ascii=False, indent=2)}"
    )
    messages = ([{"role": "system", "content": SYSTEM_RAG}]
                + FEWSHOT
                + [{"role": "user", "content": user}])
    return complete_json(messages), shown_ids


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--alerts", default=CL.ALERTS_CSV)
    ap.add_argument("--kb", default=CL.KB_DIR)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--episode", default=None)
    a = ap.parse_args()

    print("=" * 62)
    print("  TRIAGE LLM + RAG -- asymetrie + fewshot (etape 2b)")
    print("=" * 62)

    eps = EC.build_episodes(a.alerts)
    if a.episode:
        eps = [e for e in eps if e.episode_id == a.episode]
    if a.limit:
        eps = eps[:a.limit]

    print(f"\n{len(eps)} episodes a trier "
          f"({sum(e.n_alerts for e in eps)} alertes brutes)")
    print(f"modele={CL.LLM_MODEL} | provider={CL.LLM_PROVIDER} | "
          f"T={CL.LLM_TEMPERATURE}\n")
    print("[index RAG]")
    index = rag_cnn.get_index(a.kb)
    print()

    t0, results = time.time(), []
    for i, ep in enumerate(eps, 1):
        try:
            raw, shown = triage_rag(ep, index)
            verdict = str(raw.get("verdict", "uncertain"))
        except LLMError as e:
            raw, shown = {"error": str(e)}, []
            verdict = "uncertain"

        cited = [str(x) for x in (raw.get("kb_refs") or [])]
        hallucinees = [c for c in cited if c.lower() not in
                       {s.lower() for s in shown}]
        rec = {
            "episode_id": ep.episode_id, "log_source": ep.log_source,
            "host_name": ep.host_name, "start": _iso(ep.start), "end": _iso(ep.end),
            "duration_s": ep.duration_s, "n_alerts": ep.n_alerts,
            "mse_max": round(ep.mse_max, 3), "mse_mean": round(ep.mse_mean, 3),
            "threshold": round(ep.threshold, 3),
            "verdict": verdict, "confidence": raw.get("confidence"),
            "severity": raw.get("severity"),
            "title": str(raw.get("title", raw.get("error", ""))),
            "rationale": raw.get("rationale", ""), "mitre": raw.get("mitre", []),
            "evidence": raw.get("evidence", []),
            "recommendation": raw.get("recommendation", []),
            "kb_refs": cited, "kb_shown": shown,
        }
        results.append(rec)
        conf = rec["confidence"] if rec["confidence"] is not None else "-"
        print(f"  [{i:3d}/{len(eps)}] {verdict:15s} conf={conf} "
              f"{ep.episode_id} {ep.log_source:7s} | {rec['title'][:46]}")
        if cited:
            print(f"          kb_refs={cited}  (montres={shown})")
        if hallucinees:
            print(f"          [obs] source(s) citee(s) NON montree(s) : {hallucinees}")

    out = "cnn_triage.jsonl"
    with open(out, "w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    counts = Counter(r["verdict"] for r in results)
    print(f"\n{dict(counts)}")
    print(f"{len(eps)} episodes tries en {round(time.time() - t0, 1)}s")
    print(f"-> {out}")
    print("=" * 62)


if __name__ == "__main__":
    main()