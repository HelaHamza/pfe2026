"""
episode_context_cnn.py  (version RAG-only)
==========================================
Transforme cnn_alerts.csv (evenements) en DOSSIERS D'EPISODE prets pour le LLM.

Deux raisons de travailler a l'episode et pas a l'evenement :
  1. Cout / charge : 281 alertes -> ~36 episodes = 36 appels LLM au lieu de 281.
  2. Correctness : la malveillance est une propriete de la SEQUENCE, pas de la
     ligne. `chmod` seul est banal ; `chmod +x .update` -> `crontab` est une
     kill chain. Un LLM qui ne voit qu'une ligne ne peut PAS trancher.

Echantillonnage : on n'envoie jamais les 62 lignes d'un episode. On prend les
top-N par mse (les plus anormales) + les premieres/dernieres (le contexte
temporel : ce qui declenche et ce qui conclut), dedupliquees et retriees.

NB version RAG-only : ce fichier ne contient QUE ce dont le RAG a besoin
(la classe Episode et build_episodes). policy_flags() -- un garde-fou de
SORTIE -- est volontairement absent : l'orchestrateur RAG (triage_llm_rag.py)
ne l'appelle pas. Il reviendra a l'etape "garde-fous".
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

import config_llm_cnn as CL


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


# ---------------------------------------------------------------------------
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
            # ================== ZONE RECONSTRUITE (a verifier) ==================
            # Verbatim recupere jusqu'a cette ligne. La suite (ligne features
            # dom. + return) est reconstruite pour coller au format des exemples
            # few-shot. SEULE INCONNUE : est-ce que render() ajoute ensuite une
            # timeline echantillonnee via self._sample() ? Si oui, la restaurer
            # ici (c'est LE point qui compte en RAG-only : render() = le dossier
            # que le LLM lit). Si non, _sample() est dormante.
            f"  features dom.   : {fmt(self.dominant_features)}",
        ]
        return "\n".join(L)
        # ==================== FIN ZONE RECONSTRUITE =========================


# ---------------------------------------------------------------------------
def build_episodes(alerts_csv: str = CL.ALERTS_CSV) -> list[Episode]:
    """Lit cnn_alerts.csv (deja tague episode_id par l'inference) et reconstruit
    les objets Episode par simple groupby. AUCUNE re-agregation, AUCUN re-calcul
    d'identite : l'inference a assigne episode_id une fois pour toutes."""
    a = pd.read_csv(alerts_csv)
    if "episode_id" not in a.columns:
        raise SystemExit(
            "cnn_alerts.csv ne contient pas la colonne 'episode_id'. Relancer "
            "l'inference (predict_cnn.py / Test_cnn.py) : c'est elle qui assigne "
            "desormais l'identite d'episode.")
    a["_ts"] = pd.to_datetime(a["@timestamp"], utc=True, errors="coerce")
    eps: list[Episode] = []
    for ep_id, g in a.groupby("episode_id", sort=False):
        g = g.sort_values("_ts").reset_index(drop=True)
        start, end = g["_ts"].min(), g["_ts"].max()
        eps.append(Episode(
            episode_id=str(ep_id),
            log_source=str(g["log_source"].iloc[0]),
            host_name=str(g["host_name"].iloc[0]),
            start=start, end=end,
            duration_s=round((end - start).total_seconds(), 1),
            n_alerts=len(g),
            threshold=float(g["threshold"].iloc[0]),
            mse_max=float(g["mse"].max()), mse_mean=float(g["mse"].mean()),
            rows=g,
        ))
    eps.sort(key=lambda e: e.mse_max, reverse=True)  # le pire d'abord
    return eps


if __name__ == "__main__":
    eps = build_episodes()
    print(f"{len(eps)} episodes\n")
    if eps:
        print(eps[0].render())
        print("\n(rag_query) ->", eps[0].rag_query())