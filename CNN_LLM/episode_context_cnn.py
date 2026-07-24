"""
episode_context_cnn.py
======================
Transforme cnn_alerts.csv (evenements) en DOSSIERS D'EPISODE prets pour le LLM.

Deux raisons de travailler a l'episode et pas a l'evenement :
  1. Cout / charge : 281 alertes -> ~36 episodes = 36 appels LLM au lieu de 281.
  2. Correctness : la malveillance est une propriete de la SEQUENCE, pas de la
     ligne. `chmod` seul est banal ; `chmod +x .update` -> `crontab` est une
     kill chain. Un LLM qui ne voit qu'une ligne ne peut PAS trancher.

FRONTIERE DE RUN (ajout) : predict_cnn ecrit cnn_alerts.csv SANS filtre
watermark (toute la fenetre, seed inclus). Ce module doit donc RE-APPLIQUER la
meme frontiere que predict_cnn (since < end <= watermark), sinon la couche 3
triage des episodes non stabilises et des episodes deja traites au run
precedent -> doublons LLM + doublons Mongo. cf. filter_emitted().

Echantillonnage : on n'envoie jamais les 62 lignes d'un episode. On prend les
top-N par mse (les plus anormales) + les premieres/dernieres (le contexte
temporel : ce qui declenche et ce qui conclut), dedupliquees et retriees.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field

import pandas as pd

import config_llm_cnn as CL

_FEAT_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(-?\d+(?:\.\d+)?)")


def _s(v, default: str = "-") -> str:
    """float('nan') est TRUTHY en Python : `x or '-'` laisse passer les NaN
    pandas et injecte 'nan' dans le prompt. Un LLM interprete 'nan' comme un
    fait ('utilisateur nan'). On nettoie a la source."""
    if v is None:
        return default
    try:
        if pd.isna(v):
            return default
    except (TypeError, ValueError):
        pass
    t = str(v).strip()
    return t if t and t.lower() != "nan" else default


def parse_top_features(s) -> dict[str, float]:
    """'is_fail=50.0, user_rarity=16.7' -> {'is_fail': 50.0, ...}"""
    if not isinstance(s, str) or not s.strip():
        return {}
    return {m.group(1): float(m.group(2)) for m in _FEAT_RE.finditer(s)}


@dataclass
class Episode:
    episode_id: str
    log_source: str
    host_name: str
    start: pd.Timestamp
    end: pd.Timestamp
    duration_s: float
    n_alerts: int
    threshold: float
    mse_max: float
    mse_mean: float
    rows: pd.DataFrame = field(repr=False)

    # ---- vues agregees -----------------------------------------------------
    @property
    def processes(self) -> dict[str, int]:
        p = self.rows["process_name"].fillna("").astype(str)
        return p[p != ""].value_counts().to_dict()

    @property
    def users(self) -> dict[str, int]:
        u = self.rows["user_name"].fillna("").astype(str)
        return u[u != ""].value_counts().to_dict()

    @property
    def source_ips(self) -> dict[str, int]:
        i = self.rows["source_ip"].fillna("").astype(str)
        return i[i != ""].value_counts().to_dict()

    @property
    def event_types(self) -> dict[str, int]:
        e = self.rows["event_type"].fillna("").astype(str)
        return e[e != ""].value_counts().to_dict()

    @property
    def dominant_features(self) -> dict[str, int]:
        f = self.rows["top_feat"].fillna("").astype(str)
        return f[f != ""].value_counts().to_dict()

    @property
    def keys(self) -> set[str]:
        """Cles structurelles -> alimentent le scoring lexical du RAG."""
        out = {self.log_source.lower()}
        for d in (self.processes, self.users, self.event_types,
                  self.dominant_features):
            out |= {str(k).lower() for k in d}
        return out

    def rag_query(self) -> str:
        top = lambda d, n: " ".join(list(d)[:n])  # noqa: E731
        return (f"source {self.log_source} hote {self.host_name} "
                f"processus {top(self.processes, 6)} "
                f"utilisateurs {top(self.users, 4)} "
                f"evenements {top(self.event_types, 5)} "
                f"features {top(self.dominant_features, 4)} "
                f"{self.n_alerts} alertes en {self.duration_s}s")

    # ---- timeline echantillonnee ------------------------------------------
    def _sample(self) -> pd.DataFrame:
        r = self.rows.sort_values("_ts")
        if len(r) <= CL.DOSSIER_MAX_LINES:
            return r
        idx = set(r.nlargest(CL.DOSSIER_TOP_N, "mse").index)
        idx |= set(r.head(CL.DOSSIER_EDGE_N).index)
        idx |= set(r.tail(CL.DOSSIER_EDGE_N).index)
        out = r.loc[sorted(idx, key=lambda i: r.index.get_loc(i))]
        return out.head(CL.DOSSIER_MAX_LINES)

    def render(self) -> str:
        """Dossier textuel compact. Aucun jugement, uniquement des FAITS :
        le LLM doit conclure a partir des donnees + KB, pas d'un pre-verdict."""
        fmt = lambda d, n=6: ", ".join(f"{k} x{v}" for k, v in list(d.items())[:n])  # noqa: E731
        L = [
            f"EPISODE {self.episode_id}",
            f"  source          : {self.log_source}",
            f"  hote            : {self.host_name}",
            f"  fenetre         : {self.start} -> {self.end}  ({self.duration_s} s)",
            f"  alertes         : {self.n_alerts}",
            f"  score mse       : max={self.mse_max:.2f}  moyen={self.mse_mean:.2f}"
            f"  (seuil POT={self.threshold:.2f}, ratio max/seuil="
            f"{self.mse_max / max(self.threshold, 1e-9):.1f}x)",
            f"  utilisateurs    : {fmt(self.users) or '(aucun)'}",
            f"  IP sources      : {fmt(self.source_ips) or '(aucune)'}",
            f"  processus       : {fmt(self.processes, 8)}",
            f"  types d'evt     : {fmt(self.event_types, 8)}",
            f"  features dom.   : {fmt(self.dominant_features)}",
            "",
            f"  TIMELINE (echantillon : {len(self._sample())}/{self.n_alerts} lignes,"
            f" les plus anormales + les bornes)",
        ]
        for _, r in self._sample().iterrows():
            L.append(
                f"   {r['_ts']}  mse={float(r['mse']):6.2f} "
                f"user={_s(r.get('user_name')):14s} "
                f"ip={_s(r.get('source_ip')):10s} "
                f"proc={_s(r.get('process_name')):22s} "
                f"evt={_s(r.get('event_type')):28s} "
                f"| {_s(r.get('top_features'), '')}")
        return "\n".join(L)


# ---------------------------------------------------------------------------
def _episode_id(source: str, host: str, start) -> str:
    raw = f"{source}|{host}|{start}".encode()
    return "EP-" + hashlib.sha1(raw).hexdigest()[:10]


def build_episodes(alerts_csv: str = CL.ALERTS_CSV,
                   gap_seconds: float = CL.EPISODE_GAP_SECONDS) -> list[Episode]:
    """Regroupement IDENTIQUE a inference_cnn.aggregate_alerts."""
    a = pd.read_csv(alerts_csv)
    a["_ts"] = pd.to_datetime(a["@timestamp"], utc=True, errors="coerce")
    a = a.sort_values(["log_source", "host_name", "_ts"]).reset_index(drop=True)

    grp = a.groupby(["log_source", "host_name"], sort=False)
    dt_prev = grp["_ts"].diff().dt.total_seconds()
    new_ep = dt_prev.isna() | (dt_prev > gap_seconds)
    a["_episode"] = new_ep.groupby([a["log_source"], a["host_name"]]).cumsum()

    eps: list[Episode] = []
    for (src, host, _ep), g in a.groupby(["log_source", "host_name", "_episode"],
                                         sort=False):
        start, end = g["_ts"].min(), g["_ts"].max()
        eps.append(Episode(
            episode_id=_episode_id(src, host, start),
            log_source=str(src), host_name=str(host),
            start=start, end=end,
            duration_s=round((end - start).total_seconds(), 1),
            n_alerts=len(g),
            threshold=float(g["threshold"].iloc[0]),
            mse_max=float(g["mse"].max()), mse_mean=float(g["mse"].mean()),
            rows=g.reset_index(drop=True),
        ))
    # Le plus anormal d'abord : si le budget LLM saute, on a traite le pire.
    eps.sort(key=lambda e: e.mse_max, reverse=True)
    return eps


# ---------------------------------------------------------------------------
# FRONTIERE DE RUN — re-application de la logique curseur de predict_cnn
# ---------------------------------------------------------------------------

def load_run_meta(path: str = None) -> dict:
    """Lit cnn_run_meta.json (ecrit par predict_cnn). Contient watermark/since :
    la SEULE source de verite sur la frontiere du run."""
    path = path or CL.RUN_META_JSON
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"cnn_run_meta.json introuvable ({path}). Lancer predict_cnn.py "
            f"avant le triage, ou passer --no-window-filter pour un run manuel.")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def filter_emitted(eps: list[Episode], meta: dict) -> tuple[list[Episode], dict]:
    """Applique la MEME frontiere que predict_cnn : since < end <= watermark.

    Pourquoi ici et pas en amont : predict_cnn ecrit cnn_alerts.csv avec TOUTES
    les alertes de la fenetre (seed compris), et build_episodes re-agrege depuis
    ce CSV. Sans ce filtre :
      * les episodes de la zone SEED (deja emis/triages au run precedent) sont
        RE-triages   -> doublons d'appels LLM + doublons Mongo ;
      * les episodes non stabilises (end > watermark) sont triages trop tot
        puis RE-emis au run suivant avec un `start` different -> episode_id
        different -> l'upsert Mongo ne dedoublonne plus.

    Retourne (episodes a triager, diagnostic).
    """
    wm = pd.to_datetime(meta.get("watermark"), utc=True, errors="coerce")
    if pd.isna(wm):
        raise ValueError("watermark absent/illisible dans cnn_run_meta.json")

    raw_since = meta.get("since")
    since = pd.to_datetime(raw_since, utc=True, errors="coerce") if raw_since else None
    if since is not None and pd.isna(since):
        since = None

    kept, held, stale, broken = [], [], [], []
    for e in eps:
        if pd.isna(e.end):
            # Horodatage illisible : on NE JETTE PAS (doctrine fail-open),
            # on triage et on signale.
            broken.append(e)
            kept.append(e)
        elif e.end > wm:
            held.append(e)                       # non stabilise -> run suivant
        elif since is not None and e.end <= since:
            stale.append(e)                      # zone seed -> deja traite
        else:
            kept.append(e)

    diag = {"held": held, "stale": stale, "broken": broken,
            "watermark": wm, "since": since}
    return kept, diag


def crosscheck_emitted(eps: list[Episode],
                       episodes_csv: str = CL.EPISODES_CSV) -> dict:
    """Compare les episode_id re-derives par le triage avec ceux REELLEMENT
    emis par predict_cnn (cnn_alerts_episodes.csv).

    Un ecart signifie que aggregate_alerts (inference) et build_episodes
    (triage) ne decoupent pas identiquement -> episode_id instable entre les
    deux couches -> l'upsert Mongo sur episode_id ne garantit plus l'unicite.
    On DIAGNOSTIQUE, on ne corrige pas silencieusement : supprimer un episode
    sur la foi d'un hash divergent violerait 'aucune alerte perdue'."""
    out = {"available": False, "n_emitted": 0, "missing": set(), "extra": set()}
    if not os.path.exists(episodes_csv):
        return out
    try:
        df = pd.read_csv(episodes_csv)
    except Exception:
        return out
    if not len(df) or "start" not in df.columns:
        out["available"] = True
        return out

    ids_emitted = set()
    for _, r in df.iterrows():
        st = pd.to_datetime(r.get("start"), utc=True, errors="coerce")
        ids_emitted.add(_episode_id(str(r.get("log_source")),
                                    str(r.get("host_name")), st))
    ids_triage = {e.episode_id for e in eps}
    out.update(available=True, n_emitted=len(ids_emitted),
               missing=ids_emitted - ids_triage,
               extra=ids_triage - ids_emitted)
    return out


# ---------------------------------------------------------------------------
def policy_flags(ep: Episode) -> list[str]:
    """Garde-fous SOC (POLITIQUE, pas verite terrain) : primitives qu'un
    analyste humain ne clot jamais sans regarder. Le LLM garde le droit
    d'expliquer, pas celui de classer 'false_positive'."""
    flags = []
    procs = {p.lower() for p in ep.processes}
    evts = {e.lower() for e in ep.event_types}
    if procs & {p.lower() for p in CL.NEVER_DISMISS_PROCESSES}:
        hit = sorted(procs & {p.lower() for p in CL.NEVER_DISMISS_PROCESSES})
        flags.append(f"processus sensible: {', '.join(hit)}")
    if evts & {e.lower() for e in CL.NEVER_DISMISS_EVENT_TYPES}:
        flags.append("modification de configuration d'audit/mot de passe")
    n_fail = int((ep.rows["top_feat"].fillna("") == "is_fail").sum())
    if n_fail >= CL.NEVER_DISMISS_FAIL_BURST:
        flags.append(f"rafale d'echecs d'authentification ({n_fail} alertes)")
    if any(str(p).startswith(".") for p in ep.processes):
        flags.append("binaire a nom cache (prefixe '.')")
    return flags


if __name__ == "__main__":
    eps = build_episodes()
    print(f"{len(eps)} episodes (avant filtre de fenetre)\n")
    print(eps[0].render())
    print("\nflags:", policy_flags(eps[0]))