from __future__ import annotations

"""Couche de verification de FIDELITE (grounding) - branche CNN (couche 3).

Objectif : reduire l'hallucination du LLM de maniere DETERMINISTE et MESURABLE.
Le RAG limite l'hallucination en AMONT (il donne au modele des faits vrais).
Ce module la traque en AVAL : il verifie que ce que le modele a ECRIT est bien
ancre dans ce qu'on lui a MONTRE. C'est la difference entre "esperer" que le
modele ne mente pas et "prouver" qu'une affirmation donnee est tracable.

Trois verifications, par precision decroissante :

  1. kb_refs   -> appartenance EXACTE a l'ensemble des chunks reellement montres
                  a ce prompt-ci. Precision 100 %, zero faux positif : citer une
                  source qu'on ne t'a pas donnee EST une hallucination, point.

  2. mitre     -> tactic/name RECOPIES depuis la table de verite (allowed_mitre),
                  jamais ceux ecrits par le LLM. Elimine entierement la surface
                  d'hallucination des metadonnees : le modele choisit l'ID
                  (contraint a la liste fermee), le systeme fournit le libelle.

  3. evidence  -> chaque item qui contient un IDENTIFIANT CONCRET (IP, binaire
                  pointe, chemin, horodatage) doit voir cet identifiant present
                  dans le dossier. Filet a haute precision : il attrape la
                  fabrication dangereuse (IP de C2 inventee, binaire inexistant)
                  sans punir la paraphrase interpretative. Il SIGNALE, il ne
                  supprime jamais (doctrine fail-open : une alerte de securite
                  ne disparait pas en silence).
"""

import re


# --- 1. kb_refs -------------------------------------------------------------
def check_kb_refs(kb_refs: list, shown_ids: set[str]) -> tuple[list[str], list[str]]:
    """Separe les kb_refs cites en (montres, hallucines).

    `shown_ids` = ids des chunks reellement injectes dans CE prompt (pas toute
    la KB). Un ref hors de cet ensemble n'a pas pu fonder la conclusion : le
    modele l'a invente ou recopie d'un exemple few-shot.
    """
    shown = {str(s).lower() for s in shown_ids}
    kept, hallucinated = [], []
    for ref in kb_refs or []:
        (kept if str(ref).lower() in shown else hallucinated).append(str(ref))
    return kept, hallucinated


# --- 2. mitre ---------------------------------------------------------------
def canonical_mitre(mitre_items: list, allowed_mitre) -> tuple[list[dict], list[str]]:
    """Filtre sur la liste fermee ET recopie tactic/name depuis la verite terrain.

    `allowed_mitre` : dict {tid -> {"tactic":..., "name":...}} (sortie de
    rag_cnn.allowed_mitre_ids). Le LLM ne fournit QUE l'ID ; le libelle vient
    du systeme. Un T1053.003 que le modele etiquette "Defense Evasion" ressort
    corrige en "Persistence" -- l'ID etait bon, la metadonnee ne l'engage pas.
    """
    is_dict = isinstance(allowed_mitre, dict)
    kept, dropped = [], []
    for m in mitre_items or []:
        if not isinstance(m, dict):
            continue
        tid = str(m.get("technique_id", "")).strip().upper()
        if not tid:
            continue
        if tid in allowed_mitre:
            info = allowed_mitre[tid] if is_dict else {}
            kept.append({
                "technique_id": tid,
                "tactic": (info.get("tactic") or "").strip(),
                "name": (info.get("name") or "").strip(),
            })
        else:
            dropped.append(tid)
    return kept, dropped


# --- 3. evidence ------------------------------------------------------------
# Identifiants CONCRETS : ce sont les valeurs qu'un modele hallucine quand il
# fabrique une preuve (une IP de C2, un binaire, un chemin, une heure). On ne
# controle QUE ceux-la -> haute precision, pas de faux positif sur la prose.
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_PATH = re.compile(r"/[a-z0-9_.][a-z0-9_.\-/]+", re.I)          # /var/log, /tmp/.x
_HIDDEN = re.compile(r"(?<![\w./])\.[a-z0-9][a-z0-9_.\-]*", re.I)  # .payload .rk_beacon
_DOTTED = re.compile(r"\b[a-z0-9_-]+(?:\.[a-z0-9_-]+)+\b", re.I)   # foo.service, a.b.c
_TIME = re.compile(r"\b\d{1,2}:\d{2}(?::\d{2})?\b")            # 23:00:04
_DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")                   # 2026-01-05

_HARD = (_IPV4, _PATH, _HIDDEN, _DOTTED, _TIME, _DATE)


def _hard_ids(text: str) -> set[str]:
    t = (text or "")
    out: set[str] = set()
    for rx in _HARD:
        out |= {m.group(0).lower() for m in rx.finditer(t)}
    return out


def check_evidence(evidence: list, dossier_text: str) -> list[str]:
    """Renvoie les items de preuve dont un identifiant concret est ABSENT du dossier.

    Un item sans identifiant concret (pure interpretation, ex. "comportement de
    beaconing") n'est jamais signale : on ne peut pas le verifier mecaniquement,
    et le sur-signaler noierait le vrai signal. On ne juge que le verifiable.
    """
    hay = (dossier_text or "").lower()
    suspects: list[str] = []
    for item in evidence or []:
        ids = _hard_ids(str(item))
        if ids and not any(tok in hay for tok in ids):
            suspects.append(str(item))
    return suspects