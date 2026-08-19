"""
rag_cnn.py
==========
Retriever HYBRIDE pour la base de connaissances Sentinel/CNN.

Pourquoi hybride et pas "juste des embeddings" :
  * La KB est PETITE (une dizaine de chunks -- le compte exact est affiche a
    l'execution par KBIndex). Un index vectoriel seul se trompe sur les entites
    RARES : "cups-browsed" et "crontab" sont proches dans l'espace semantique
    ("processus systeme Linux"), alors qu'ils separent exactement faux positif
    et vrai positif. Un match EXACT sur process_name est plus fiable que
    n'importe quel cosinus.
  * Inversement, le lexical seul rate les reformulations.
  -> score = ALPHA * cosinus(embeddings) + (1-ALPHA) * recouvrement de cles.

Le tout est hors-ligne : aucune donnee de log ne sort de la machine pour le
retrieval.

Ce module est l'UNIQUE brique "RAG" du pipeline RAG-only : il selectionne les
chunks pertinents et fournit la liste MITRE fermee. Il n'exerce AUCUN controle
sur la sortie du LLM (ca, c'est le role des garde-fous, ajoutes plus tard).

-- Notes de conception (revue du 17/07/2026) --------------------------------

[MESURE] Le terme lexical etait ecrase par le terme "semantique".
    v1 : score = hits / max(3.0, len(ep_keys))
    Le denominateur comptait TOUTES les cles de l'episode, y compris
    dominant_features ('is_fail', 'proc_rarity'...) que la KB ne liste JAMAIS
    dans processes/users/event_types -- donc des cles structurellement
    INCAPABLES de matcher, qui gonflaient le denominateur sans jamais pouvoir
    contribuer au numerateur.
    -> normalisation par les seules cles MATCHABLES (ep_keys inter cles KB).

[HONNETETE] Avec RAG_BACKEND='tfidf', le terme "semantique" EST DEJA lexical
    (TF-IDF + IDF surpondere exactement les tokens rares : 'cups-browsed',
    'crontab', '.rk_beacon'). C'est probablement la vraie raison pour laquelle
    TF-IDF bat les embeddings -- pas l'hybridation. L'explication a defendre :
    "lexical > vectoriel sur un petit corpus a entites rares", pas
    "hybride > vectoriel". -> lancer l'ablation RAG_ALPHA (1.0 / 0.6 / 0.0).

[SILENCIEUX] load_kb ignorait sans un mot tout chunk sans 'id'. Une coquille
    de front-matter faisait disparaitre un chunk -> allowed_mitre retrecissait
    -> des techniques VALIDES devenaient soudain non citables, sans aucun
    signe. Desormais : chaque fichier ignore est affiche.

[BUG] render() faisait `break` au premier chunk depassant le budget. Les
    chunks 'reference' sont TOUJOURS injectes en tete : si l'un d'eux est
    volumineux, il pouvait evincer tous les suivants. Corrige : `continue`.

[FIABILITE] Repli silencieux sur TF-IDF meme quand le backend etait demande
    EXPLICITEMENT. Un run 'sentence-transformers' pouvait etre en realite un
    run TF-IDF. Corrige : echec dur si backend explicite, repli seulement en
    mode 'auto'.

[FIABILITE] allowed_mitre est un dict {id: {tactic, name}} : le LLM ne produit
    que l'identifiant ; tactique et nom viennent de la KB.
"""


from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Iterable

import numpy as np

import config_llm_cnn as CL

_LIST_KEYS = {"log_source", "processes", "users", "event_types", "mitre"}


# ---------------------------------------------------------------------------
# 1. Parsing des chunks (markdown + front-matter YAML minimal, zero dependance)
# ---------------------------------------------------------------------------
@dataclass
class Chunk:
    id: str
    kind: str            # baseline | threat | reference
    path: str
    body: str
    log_source: list[str] = field(default_factory=list)
    processes: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    event_types: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    severity_hint: str = "info"

    @property
    def keys(self) -> set[str]:
        """Toutes les cles structurelles, en minuscules."""
        out = set()
        for coll in (self.processes, self.users, self.event_types):
            out |= {k.lower() for k in coll if k}
        return out


def _parse_front_matter(text: str) -> tuple[dict, str]:
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end == -1:
        return {}, text
    head, body = text[3:end], text[end + 4:]
    meta: dict = {}
    for line in head.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        if k in _LIST_KEYS:
            meta[k] = [p.strip() for p in v.split(",") if p.strip()]
        else:
            meta[k] = v
    return meta, body.strip()


def load_kb(kb_dir: str = CL.KB_DIR) -> list[Chunk]:
    chunks: list[Chunk] = []
    ignores: list[str] = []
    if not os.path.isdir(kb_dir):
        raise FileNotFoundError(f"Base de connaissances introuvable : {kb_dir}")
    for root, _, files in os.walk(kb_dir):
        for fn in sorted(files):
            if not fn.endswith(".md"):
                continue
            path = os.path.join(root, fn)
            with open(path, encoding="utf-8") as f:
                meta, body = _parse_front_matter(f.read())
            if not meta.get("id"):
                # Un chunk sans 'id' disparaitrait du corpus ET de allowed_mitre
                # sans aucun signe. Un chunk perdu doit crier.
                ignores.append(path)
                continue
            chunks.append(Chunk(
                id=meta["id"], kind=meta.get("kind", "reference"), path=path,
                body=body,
                log_source=meta.get("log_source", []),
                processes=meta.get("processes", []),
                users=meta.get("users", []),
                event_types=meta.get("event_types", []),
                mitre=meta.get("mitre", []),
                severity_hint=meta.get("severity_hint", "info"),
            ))
    for p in ignores:
        print(f"  [rag] /!\\ IGNORE (pas de champ 'id' dans le front-matter) : {p}")
    if not chunks:
        raise FileNotFoundError(f"Base de connaissances vide : {kb_dir}")
    ids = [c.id for c in chunks]
    doublons = {i for i in ids if ids.count(i) > 1}
    if doublons:
        # Deux chunks de meme id -> kb_refs devient ambigu, tracabilite perdue.
        print(f"  [rag] /!\\ ids DUPLIQUES dans la KB : {sorted(doublons)}")
    return chunks


def allowed_mitre_ids(chunks: Iterable[Chunk]) -> dict[str, dict]:
    """Ensemble FERME des techniques citables, avec tactique et nom.

    Le LLM ne peut pas en inventer d'autres : tout ID hors de cet ensemble
    n'est PAS present dans le prompt. (Le rejet effectif d'un ID hallucine,
    lui, releve des garde-fous de SORTIE -- absents de la version RAG-only.)

    Deux formats de front-matter acceptes :
        mitre: T1053.003
        mitre: T1053.003|Persistence|Scheduled Task/Job: Cron
    Le second est RECOMMANDE : il permet au systeme de remplir tactic/name
    lui-meme. (Le separateur est '|' et non ',' : les noms MITRE contiennent
    des virgules, sur lesquelles le front-matter splitte deja.)
    """
    out: dict[str, dict] = {}
    for c in chunks:
        for m in c.mitre:
            m = m.strip()
            if not m:
                continue
            parts = [p.strip() for p in m.split("|")]
            tid = parts[0].upper()
            if not tid:
                continue
            info = out.setdefault(tid, {"tactic": "", "name": ""})
            if len(parts) > 1 and parts[1] and not info["tactic"]:
                info["tactic"] = parts[1]
            if len(parts) > 2 and parts[2] and not info["name"]:
                info["name"] = parts[2]
    # Repli sur la table versionnee pour les techniques que la KB n'annote pas.
    # La KB reste PRIORITAIRE : on ne remplit que les trous.
    from mitre_names_cnn import lookup
    comble, orphelines = [], []
    for tid, info in out.items():
        if info["tactic"] and info["name"]:
            continue
        tac, nom = lookup(tid)
        if tac or nom:
            info["tactic"] = info["tactic"] or tac
            info["name"] = info["name"] or nom
            comble.append(tid)
        else:
            orphelines.append(tid)
    if comble:
        print(f"  [rag] {len(comble)} technique(s) completee(s) depuis la table "
              f"de repli (mitre_names_cnn.py) -- la KB ne fournit que les IDs")
    if orphelines:
        # Ni la KB ni la table ne connaissent ces IDs. On ne devine PAS.
        print(f"  [rag] /!\\ technique(s) SANS tactique ni nom (ni KB ni table) : "
              f"{sorted(orphelines)}")
    return out


# ---------------------------------------------------------------------------
# 2. Encodeurs (embeddings -> TF-IDF -> lexical pur)
# ---------------------------------------------------------------------------
class _Encoder:
    """Encapsule la strategie d'encodage effectivement disponible."""

    def __init__(self):
        self.backend = "lexical"
        self._model = None
        self._vec = None

    def fit(self, corpus: list[str]) -> np.ndarray | None:
        explicite = CL.RAG_BACKEND in ("sentence-transformers", "tfidf", "lexical")

        if CL.EMBED_ENABLED:
            try:
                from sentence_transformers import SentenceTransformer
                self._model = SentenceTransformer(CL.EMBED_MODEL)
                self.backend = "sentence-transformers"
                return self._model.encode(corpus, normalize_embeddings=True)
            except Exception as e:                      # noqa: BLE001
                if CL.RAG_BACKEND == "sentence-transformers":
                    raise SystemExit(
                        f"RAG_BACKEND='sentence-transformers' demande "
                        f"EXPLICITEMENT mais indisponible ({e}).\n"
                        f"  pip install sentence-transformers\n"
                        f"  ou RAG_BACKEND=auto pour autoriser le repli.") from e
                print(f"  [rag] sentence-transformers indisponible ({e}) "
                      f"-> repli TF-IDF")

        if CL.RAG_BACKEND == "lexical":
            self.backend = "lexical"
            return None

        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            self._vec = TfidfVectorizer(sublinear_tf=True, ngram_range=(1, 2),
                                        min_df=1)
            M = self._vec.fit_transform(corpus).toarray().astype(np.float32)
            M /= (np.linalg.norm(M, axis=1, keepdims=True) + 1e-9)
            self.backend = "tfidf"
            return M
        except Exception as e:                          # noqa: BLE001
            if explicite and CL.RAG_BACKEND == "tfidf":
                raise SystemExit(
                    f"RAG_BACKEND='tfidf' demande explicitement mais "
                    f"indisponible ({e}).\n  pip install scikit-learn") from e
            print(f"  [rag] TF-IDF indisponible ({e}) -> lexical pur")
            return None

    def encode(self, text: str) -> np.ndarray | None:
        if self.backend == "sentence-transformers":
            return self._model.encode([text], normalize_embeddings=True)[0]
        if self.backend == "tfidf":
            v = self._vec.transform([text]).toarray().astype(np.float32)[0]
            return v / (np.linalg.norm(v) + 1e-9)
        return None


# ---------------------------------------------------------------------------
# 3. Index
# ---------------------------------------------------------------------------
_TOKEN_RE = re.compile(r"[a-z0-9_.\-]+")


def _tokens(text: str) -> set[str]:
    return set(_TOKEN_RE.findall(text.lower()))


class KBIndex:
    def __init__(self, kb_dir: str = CL.KB_DIR):
        self.chunks = load_kb(kb_dir)
        self.allowed_mitre = allowed_mitre_ids(self.chunks)
        # Union des cles structurelles de TOUTE la KB : sert a normaliser le
        # score lexical sur ce qui est reellement matchable (cf. _lexical).
        self.all_kb_keys: set[str] = set()
        for c in self.chunks:
            self.all_kb_keys |= c.keys
        corpus = [f"{c.id}\n{' '.join(c.processes)}\n{' '.join(c.event_types)}\n"
                  f"{c.body}" for c in self.chunks]
        self.enc = _Encoder()
        self.M = self.enc.fit(corpus)
        self.kb_chars = sum(len(c.body) for c in self.chunks)
        print(f"  [rag] {len(self.chunks)} chunks ({self.kb_chars} car.) | "
              f"backend={self.enc.backend} | alpha={CL.RAG_ALPHA} | "
              f"{len(self.allowed_mitre)} techniques MITRE autorisees")
        if self.kb_chars <= CL.RAG_MAX_CHARS:
            print(f"  [rag] NB : la KB entiere ({self.kb_chars} car.) tient sous "
                  f"RAG_MAX_CHARS ({CL.RAG_MAX_CHARS}) -> le retrieval ne filtre "
                  f"rien d'utile a ce volume. Ablation `--no-rag` pour le chiffrer.")

    # -- scoring lexical structurel -----------------------------------------
    def _lexical(self, chunk: Chunk, ep_keys: set[str], source: str) -> float:
        """Recouvrement des cles STRUCTURELLES (process/user/event_type).

        Un match exact de process_name vaut plus que n'importe quelle
        similarite de texte -> c'est la que se joue la separation
        cups-browsed (FP) / crontab (TP). Denominateur = seules cles de
        l'episode SUSCEPTIBLES de matcher un chunk (ep_keys inter cles KB).
        """
        ck = chunk.keys
        if not ck:
            return 0.0
        matchables = ep_keys & self.all_kb_keys
        hits = len(ck & ep_keys)
        score = hits / max(2.0, len(matchables)) if matchables else 0.0
        # bonus de pertinence de source
        if chunk.log_source and source.lower() in [s.lower() for s in chunk.log_source]:
            score += 0.15
        return min(score, 1.0)

    def retrieve(self, query: str, ep_keys: set[str], source: str,
                 top_k: int = CL.RAG_TOP_K) -> list[tuple[Chunk, float]]:
        n = len(self.chunks)
        sem = np.zeros(n, dtype=np.float32)
        if self.M is not None:
            q = self.enc.encode(query)
            if q is not None:
                sem = (self.M @ q).astype(np.float32)
                sem = np.clip(sem, 0.0, 1.0)
        lex = np.array([self._lexical(c, ep_keys, source) for c in self.chunks],
                       dtype=np.float32)
        score = CL.RAG_ALPHA * sem + (1.0 - CL.RAG_ALPHA) * lex

        # La reference sur la semantique des features est TOUJOURS injectee :
        # sans elle le LLM surinterprete inter_arrival_log et ip_is_external.
        # -> consequence importante pour ta question "hors KB" : meme sans aucun
        #    bon match, le LLM recoit AU MOINS ce chunk 'reference'. Il n'est
        #    donc jamais totalement sans contexte, mais il n'a aucun EXEMPLAIRE
        #    de comportement (baseline/threat) sur lequel s'appuyer.
        forced = [i for i, c in enumerate(self.chunks) if c.kind == "reference"]
        order = list(np.argsort(-score))
        picked, seen = [], set()
        for i in forced + order:
            i = int(i)
            if i in seen:
                continue
            seen.add(i)
            picked.append((self.chunks[i], float(score[i])))
            if len(picked) >= top_k:
                break
        return picked

    def retrieve_all(self) -> list[tuple[Chunk, float]]:
        """Ablation `--no-rag` : toute la KB, aucun retrieval.

        A ce volume, la KB tient dans le prompt. Si les resultats sont
        identiques a ceux du RAG, la conclusion defendable n'est pas de cacher
        le RAG mais de le documenter pour ce qu'il est : une brique de passage
        a l'echelle, inutile a ce volume -- preuve a l'appui.
        """
        return [(c, 1.0) for c in self.chunks]

    def render(self, hits: list[tuple[Chunk, float]],
               max_chars: int = CL.RAG_MAX_CHARS) -> str:
        """Rend les chunks dans le prompt AVEC leur id -> le LLM doit citer ses
        sources dans kb_refs, ce qui rend l'explication verifiable.

        `continue` et non `break` : un chunk 'reference' volumineux (toujours
        injecte en tete) ne doit pas evincer tous les suivants.
        """
        out, total = [], 0
        for c, s in hits:
            block = (f"<kb id=\"{c.id}\" kind=\"{c.kind}\" score=\"{s:.3f}\">\n"
                     f"{c.body}\n</kb>")
            if total + len(block) > max_chars:
                continue
            out.append(block)
            total += len(block)
        return "\n\n".join(out)


# ---------------------------------------------------------------------------
_INDEX: KBIndex | None = None


def get_index(kb_dir: str = CL.KB_DIR) -> KBIndex:
    """Singleton : l'index est construit UNE fois pour les N episodes."""
    global _INDEX
    if _INDEX is None:
        _INDEX = KBIndex(kb_dir)
    return _INDEX


if __name__ == "__main__":
    idx = get_index()
    demo = [
        ("logrotate savelog gzip root executed parent_child_rarity", "auditd"),
        ("sshd invaliduser ssh_login is_fail brute force", "auth"),
        ("crontab chmod .rk_beacon bash executed", "auditd"),
    ]
    for q, src in demo:
        print(f"\n### {src} :: {q}")
        for c, s in idx.retrieve(q, _tokens(q), src, top_k=4):
            print(f"   {s:.3f}  {c.id:38s} [{c.kind}]")
    print("\nTechniques autorisees :")
    for tid, m in sorted(idx.allowed_mitre.items()):
        print(f"   {tid:12s} {m['tactic']:22s} {m['name']}")