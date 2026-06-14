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

    def encode(self, x, src):
        return self.encoders[src](x)

    def forward(self, x, src):
        return self.decoders[src](self.encoders[src](x))

    def train_loss(self, x_hat, x):
        if C.TRAIN_LOSS == "huber":
            return F.huber_loss(x_hat, x, delta=C.HUBER_DELTA)
        return F.mse_loss(x_hat, x)

    @torch.no_grad()
    def reconstruction_error(self, x, src):
        """Score d'anomalie par echantillon (MSE par defaut)."""
        self.eval()
        x_hat = self.forward(x, src)
        if C.SCORE_LOSS == "huber":
            err = F.huber_loss(x_hat, x, delta=C.HUBER_DELTA,
                               reduction="none").mean(dim=1)
        else:
            err = ((x - x_hat) ** 2).mean(dim=1)
        return err.cpu().numpy()

    @torch.no_grad()
    def latent(self, x, src):
        """Representation latente (pour HDBSCAN au nettoyage)."""
        self.eval()
        return self.encode(x, src).cpu().numpy()