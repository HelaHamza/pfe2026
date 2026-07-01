"""
autoencoder.py
==============
AutoEncodeur CONTRACTIF par source. Un encodeur/decodeur distinct par source
(auth/syslog/auditd), chacun apprend sa propre normalite.

Choix d'architecture (suite a l'audit) :
  * PAS de LayerNorm : sur des features tabulaires heterogenes deja
    StandardScaler-isees, LayerNorm melangerait hour_sin, is_root et des
    comptages log1p le long de l'axe feature sans justification. On garde
    GELU + Dropout. Le score d'anomalie reste deterministe (pas de couplage
    inter-echantillons type BatchNorm).
  * Goulot strictement CONTRACTIF (input -> h -> h/2 -> latent) : empeche la
    reconstruction-identite qui ruine la detection.
  * Perte d'ENTRAINEMENT (Huber, robuste au bruit) distincte du SCORE
    d'anomalie (MSE, sensible). Choix explicite et assume.
"""
from __future__ import annotations
import torch
import torch.nn as nn
import torch.nn.functional as F

import config as C


def make_encoder(input_dim, latent_dim):
    h = max(input_dim, 16)
    h2 = max(h // 2, latent_dim)
    return nn.Sequential(
        nn.Linear(input_dim, h), nn.GELU(), nn.Dropout(C.DROPOUT),
        nn.Linear(h, h2),        nn.GELU(),
        nn.Linear(h2, latent_dim),
    )


def make_decoder(latent_dim, output_dim):
    h = max(output_dim, 16)
    h2 = max(h // 2, latent_dim)
    return nn.Sequential(
        nn.Linear(latent_dim, h2), nn.GELU(),
        nn.Linear(h2, h),          nn.GELU(), nn.Dropout(C.DROPOUT),
        nn.Linear(h, output_dim),
    )


class PerSourceAutoencoder(nn.Module):
    def __init__(self, input_dims, latent_dims=None):
        super().__init__()
        self.input_dims = dict(input_dims)
        self.latent_dims = latent_dims or C.LATENT_DIM_BY_SOURCE
        self.encoders = nn.ModuleDict({
            s: make_encoder(d, self.latent_dims[s]) for s, d in input_dims.items()})
        self.decoders = nn.ModuleDict({
            s: make_decoder(self.latent_dims[s], d) for s, d in input_dims.items()})
        # Stats d'erreur PAR FEATURE, apprises sur le train et persistees avec
        # le state_dict (buffers). Aucun seuil manuel -> si tu ajoutes une
        # feature, ces vecteurs se recreent a la bonne taille au retraining.
        for s, d in input_dims.items():
            self.register_buffer(f"err_mean_{s}", torch.zeros(d))
            self.register_buffer(f"err_std_{s}",  torch.ones(d))

    def _corrupt(self, x):
        """Masquage denoising : actif UNIQUEMENT en mode train."""
        frac = getattr(C, "DENOISE_MASK_FRAC", 0.0)
        if not self.training or frac <= 0:
            return x
        mask = torch.rand_like(x) < frac
        return x.masked_fill(mask, 0.0)          # 0 = moyenne (donnees scalees)

    def encode(self, x, src):
        return self.encoders[src](x)

    def forward(self, x, src):
        # Train : encode une version CORROMPUE, reconstruit vers x PROPRE.
        # Eval : aucune corruption (scoring deterministe).
        return self.decoders[src](self.encoders[src](self._corrupt(x)))

    def train_loss(self, x_hat, x):
        if C.TRAIN_LOSS == "huber":
            return F.huber_loss(x_hat, x, delta=C.HUBER_DELTA)
        return F.mse_loss(x_hat, x)

    # --- normalisation de l'erreur par feature -----------------------------
    @torch.no_grad()
    def fit_error_norm(self, x, src):
        """Apprend mean/std de l'erreur de reconstruction par feature sur le
        TRAIN BRUT. A appeler une fois, apres l'entrainement final."""
        self.eval()
        se = (x - self.forward(x, src)) ** 2                 # (N, F)
        getattr(self, f"err_mean_{src}").copy_(se.mean(dim=0))
        getattr(self, f"err_std_{src}").copy_(se.std(dim=0).clamp_min(1e-6))

    def _feature_z(self, x, src):
        """Erreur standardisee par feature, plancher 0 ET plafond FEATURE_Z_CAP.
        Le plancher : une feature mieux reconstruite que d'habitude n'est pas une
        anomalie. Le plafond : une feature au err_std degenere (~1e-6, feature
        constante au train) ne doit pas produire un z astronomique qui monopolise
        le top-3 -> c'etait la cause des kurtosis a 112/274."""
        se = (x - self.forward(x, src)) ** 2
        mean = getattr(self, f"err_mean_{src}")
        std  = getattr(self, f"err_std_{src}")
        cap  = getattr(C, "FEATURE_Z_CAP", float("inf"))
        return ((se - mean) / std).clamp(0.0, cap)            # 0 <= z <= cap


    def _aggregate(self, z):
        mode = getattr(C, "SCORE_AGG", "topk")
        if mode == "max":
            return z.max(dim=1).values
        k = min(int(getattr(C, "SCORE_TOPK", 3)), z.shape[1])
        return z.topk(k, dim=1).values.mean(dim=1)

    @torch.no_grad()
    def reconstruction_error(self, x, src):
        """Score d'anomalie SCALAIRE par echantillon : erreur standardisee par
        feature (z>=0) puis agregee (C.SCORE_AGG)."""
        self.eval()
        return self._aggregate(self._feature_z(x, src)).cpu().numpy()

    @torch.no_grad()
    def per_feature_zscore(self, x, src):
        """Vecteur de z par feature -> attribution pour le LLM."""
        self.eval()
        return self._feature_z(x, src).cpu().numpy()

    @torch.no_grad()
    def latent(self, x, src):
        self.eval()
        return self.encode(x, src).cpu().numpy()