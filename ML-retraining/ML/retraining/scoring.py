"""
scoring.py
==========
Scorer un DataFrame brut avec un jeu d'artefacts ARBITRAIRE.

Necessaire parce que train_eval_cnn.py et predict_cnn.py chargent tous deux
implicitement les artefacts de production. Le gate doit, lui, faire tourner
DEUX modeles cote a cote -- le candidat et le courant -- sur les MEMES donnees
figees. D'ou ce module, qui prend le repertoire d'artefacts en parametre.

La logique de scoring reproduit exactement _score_df() de train_eval_cnn.py :
fenetrage W.build_windows, erreur de reconstruction, comparaison au seuil.
Aucune divergence de semantique entre l'entrainement et la validation.
"""
from __future__ import annotations

import inspect
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch

import cnn_features as FE
import cnn_windowing as W
import config_cnn as C
import thresholding as TH
from autoencoder_cnn import PerSourceHybridConvAE

DEVICE = torch.device("cpu")     # le gate tourne sur CPU : reproductible


# ===========================================================================
# 1. Chargement d'un jeu d'artefacts
# ===========================================================================
class ArtifactSet:
    """Un modele complet charge depuis un repertoire, pret a scorer."""

    def __init__(self, directory, device=DEVICE):
        self.dir = Path(directory)
        self.device = device
        self.bundle = joblib.load(self.dir / "cnn_bundle.pkl")
        self.thresholds = joblib.load(self.dir / "cnn_thresholds.pkl")
        self.novelty_state = joblib.load(self.dir / "cnn_novelty_state.pkl")

        self.model = PerSourceHybridConvAE(
            self.bundle["scalar_dims"], self.bundle["vocab_sizes"],
            win=self.bundle["win"]).to(device)
        state = torch.load(self.dir / "model_cnn.pt", map_location=device,
                           weights_only=False)
        self.model.load_state_dict(state)
        self.model.eval()

    @property
    def sources(self):
        return list(self.bundle["scalar_dims"].keys())

    def threshold(self, src) -> float:
        return TH.get_threshold(self.thresholds, src)

    def __repr__(self):
        return f"<ArtifactSet {self.dir.name} sources={self.sources}>"


# ===========================================================================
# 2. Calcul des features
# ===========================================================================
def build_features(df_raw: pd.DataFrame, novelty_state=None) -> pd.DataFrame:
    """Features avec, si possible, les comptes de rarete GELES.

    ------------------------------------------------------------------------
    ADAPTATEUR A VERIFIER UNE FOIS -- voir cnn_features.py / predict_cnn.py.
    ------------------------------------------------------------------------
    En production, predict_cnn.py doit appliquer novelty_state pour que la
    rarete ne soit pas recalculee sur la fenetre courante (sinon toute rarete
    repart a 1.0 -> decalage de distribution). L'introspection ci-dessous
    detecte automatiquement la bonne signature.

    Si aucune n'est trouvee, on retombe sur le mode entrainement AVEC UN
    AVERTISSEMENT EXPLICITE. Ce repli reste valide pour le gate : le golden
    set et la fenetre de reference sont FIGES, donc la rarete calculee dessus
    est deterministe et strictement identique pour le candidat et le courant.
    La comparaison reste equitable ; seule la fidelite aux conditions de
    production est degradee.
    """
    if novelty_state is None:
        return FE.build_features(df_raw)

    sig = inspect.signature(FE.build_features)
    if "novelty_state" in sig.parameters:
        return FE.build_features(df_raw, novelty_state=novelty_state)
    if "state" in sig.parameters:
        return FE.build_features(df_raw, state=novelty_state)
    for name in ("build_features_prod", "build_features_live",
                 "apply_novelty_state"):
        fn = getattr(FE, name, None)
        if callable(fn):
            try:
                return fn(df_raw, novelty_state)
            except TypeError:
                continue

    print("  [SCORING] AVERTISSEMENT : aucune API de rarete gelee detectee "
          "dans cnn_features. Repli en mode entrainement (deterministe sur "
          "donnees figees, mais non identique a la production).")
    return FE.build_features(df_raw)


# ===========================================================================
# 3. Scoring
# ===========================================================================
def score_dataframe(arts: ArtifactSet, df_feat: pd.DataFrame) -> pd.DataFrame:
    """Score evenement par evenement. Schema aligne sur cnn_scored_test.csv."""
    parts = []
    for src in arts.sources:
        d = df_feat[df_feat["log_source"] == src].reset_index(drop=True)
        if len(d) == 0:
            continue
        feats = arts.bundle["feats"][src]
        Xs, Xt, d_sorted = W.build_windows(
            d, feats, arts.bundle["scalers"][src],
            arts.bundle["vocabs"][src], src)
        if len(d_sorted) == 0:
            continue
        with torch.no_grad():
            score = arts.model.reconstruction_error(
                torch.from_numpy(Xs).to(arts.device),
                torch.from_numpy(Xt).to(arts.device), src)
        score = np.asarray(score.cpu() if torch.is_tensor(score) else score,
                           dtype=float)
        thr = arts.threshold(src)
        parts.append(pd.DataFrame({
            "@timestamp": pd.to_datetime(d_sorted.get("@timestamp"),
                                         utc=True, errors="coerce"),
            "log_source": src,
            "host_name": d_sorted.get("host_name"),
            "score": score,
            "threshold": thr,
            "is_alert": (score > thr).astype(int),
        }))
    if not parts:
        return pd.DataFrame(columns=["@timestamp", "log_source", "host_name",
                                     "score", "threshold", "is_alert"])
    return pd.concat(parts, ignore_index=True)


def score_raw(arts: ArtifactSet, df_raw: pd.DataFrame) -> pd.DataFrame:
    return score_dataframe(arts, build_features(df_raw, arts.novelty_state))


# ===========================================================================
# 4. Agregation en episodes
# ===========================================================================
def to_episodes(scored: pd.DataFrame,
                gap_seconds: int | None = None) -> pd.DataFrame:
    """Alertes consecutives d'un meme (source, hote) separees de moins de
    EPISODE_GAP_SECONDS = un seul episode. Meme regle que le pipeline de
    production : c'est l'unite de charge de travail de l'analyste, et donc
    l'unite de mesure pertinente pour le gate."""
    gap = pd.Timedelta(seconds=gap_seconds or C.EPISODE_GAP_SECONDS)
    a = scored[scored["is_alert"] == 1].copy()
    if len(a) == 0:
        return pd.DataFrame(columns=["log_source", "host_name", "start", "end",
                                     "n_events", "max_score"])
    a["host_name"] = a["host_name"].fillna("(none)")
    a = a.sort_values(["log_source", "host_name", "@timestamp"])
    grp = a.groupby(["log_source", "host_name"], sort=False)
    new_ep = grp["@timestamp"].diff().isna() | (grp["@timestamp"].diff() > gap)
    a["episode_id"] = new_ep.cumsum()
    out = a.groupby(["log_source", "host_name", "episode_id"], sort=False).agg(
        start=("@timestamp", "min"), end=("@timestamp", "max"),
        n_events=("score", "size"), max_score=("score", "max")).reset_index()
    return out.drop(columns=["episode_id"])
