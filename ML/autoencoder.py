"""
autoencoder.py
==============
AutoEncodeur CONTRACTIF par source. Un encodeur/decodeur distinct par source
(auth/syslog/auditd), chacun apprend sa propre normalite.

Choix d'architecture (suite a l'audit) :
  * PAS de LayerNorm : sur des features tabulaires heterogenes deja
    StandardScaler-isees, LayerNorm melangerait des comptages log1p et des
    raretes le long de l'axe feature sans justification. On garde GELU +
    Dropout. Le score d'anomalie reste deterministe (pas de couplage
    inter-echantillons type BatchNorm).
  * Goulot strictement CONTRACTIF (input -> h -> h/2 -> latent) : empeche la
    reconstruction-identite qui ruine la detection.
  * Perte d'ENTRAINEMENT (Huber, robuste au bruit) distincte du SCORE
    d'anomalie. Choix explicite et assume.

CHANGEMENT (audit v2) : le SCORE est desormais base sur l'ERREUR ABSOLUE
|residu| standardisee par feature, et NON sur residu**2.
  * residu**2 ~ sigma**2 * chi2(1) est lourd a droite PAR CONSTRUCTION, meme
    sur du normal pur -> kurtosis artificielle (108/163 observes), queue GPD
    plus difficile a ajuster.
  * |residu| ~ demi-normale : echelle quasi-lineaire, queue mieux comportee,
    et COHERENT avec la perte d'entrainement Huber (L1 en regime large).
Les buffers err_mean_/err_std_ stockent donc mean/std de |residu| (le nom
generique "err" est conserve).
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
        # Stats de |residu| PAR FEATURE, apprises sur un fold HELD-OUT (calib)
        # et persistees avec le state_dict (buffers). Aucun seuil manuel -> si
        # tu ajoutes une feature, ces vecteurs se recreent a la bonne taille au
        # retraining.
        for s, d in input_dims.items():
            self.register_buffer(f"err_mean_{s}", torch.zeros(d))
            self.register_buffer(f"err_std_{s}",  torch.ones(d))
            # Diagnostic du cap (compat thresholding.py : record_cap / cap_binding_rate)
            self.register_buffer(f"cap_hits_{s}",  torch.zeros(d))
            self.register_buffer(f"cap_total_{s}", torch.zeros(1))

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

    # --- normalisation de l'erreur |residu| par feature --------------------
    @torch.no_grad()
    def fit_error_norm(self, x, src):
        """Apprend mean/std de l'erreur ABSOLUE |residu| par feature.

        A appeler UNE FOIS, apres l'entrainement final, sur un jeu TENU A
        L'ECART (calib de preference, sinon val) -- JAMAIS sur le train :
        sur le train le modele a vu les donnees, donc |residu| est optimiste,
        z biaise positivement en test -> sur-alerte structurelle. Un fold
        held-out donne une echelle d'erreur representative de la
        generalisation.
        """
        self.eval()
        ae = (x - self.forward(x, src)).abs()                # (N, F)  |residu|
        getattr(self, f"err_mean_{src}").copy_(ae.mean(dim=0))
        getattr(self, f"err_std_{src}").copy_(ae.std(dim=0).clamp_min(1e-6))

    def _feature_z(self, x, src, _record_cap=False):
        """Erreur ABSOLUE standardisee par feature, plancher 0 ET plafond FEATURE_Z_CAP.
        NOUVEAU : err_std est planchérisé à RESIDUAL_SCALE_FLOOR. Une feature
        quasi-constante (err_std ~0) ne peut plus produire un z geant sur une
        micro-deviation -> attenue les FP sudo/syslog SANS toucher aux attaques
        (fort residu -> z reste eleve)."""
        ae = (x - self.forward(x, src)).abs()
        mean = getattr(self, f"err_mean_{src}")
        std  = getattr(self, f"err_std_{src}").clamp_min(
            getattr(C, "RESIDUAL_SCALE_FLOOR", 0.0))          # <-- plancher (etait: rien)
        cap  = getattr(C, "FEATURE_Z_CAP", float("inf"))
        z_raw = ((ae - mean) / std).clamp_min(0.0)
        if _record_cap and cap != float("inf"):
            with torch.no_grad():
                hits = (z_raw > cap).float().sum(dim=0)
                getattr(self, f"cap_hits_{src}").add_(hits)
                getattr(self, f"cap_total_{src}").add_(z_raw.shape[0])
        return z_raw.clamp_max(cap)
     
    # def _aggregate(self, z):
    #     """Agrege le z par feature en un score scalaire.
    #     top-k (SCORE_TOPK=2) : moyenne des 2 features les plus deviantes ->
    #     robuste (une seule feature ne suffit pas a alerter) sans diluer comme
    #     la moyenne complete."""
    #     mode = getattr(C, "SCORE_AGG", "topk")
    #     if mode == "max":
    #         return z.max(dim=1).values
    #     k = min(int(getattr(C, "SCORE_TOPK", 3)), z.shape[1])
    #     return z.topk(k, dim=1).values.mean(dim=1)

   
    def _aggregate(self, z):
        """Score scalaire = log-sum-exp (smooth-max) du z par feature."""
        tau = getattr(C, "SCORE_LSE_TAU", 2.0)
        m = z.max(dim=1, keepdim=True).values
        return (m + tau * torch.log(
            torch.exp((z - m) / tau).mean(dim=1, keepdim=True))).squeeze(1)



    @torch.no_grad()
    def reconstruction_error(self, x, src, record_cap=False):
        """Score d'anomalie SCALAIRE par echantillon : |residu| standardise
        par feature (z>=0) puis agrege (C.SCORE_AGG = top-k moyen).

        NB : ce n'est PAS une MSE (nom historique trompeur cote diagnostics).
        """
        self.eval()
        z = self._feature_z(x, src, _record_cap=record_cap)
        return self._aggregate(z).cpu().numpy()

    @torch.no_grad()
    def cap_binding_rate(self, src):
        """Fraction des (echantillon x feature) ayant atteint FEATURE_Z_CAP.
        Avec |residu|, attendu bien plus bas qu'avec residu**2."""
        total = float(getattr(self, f"cap_total_{src}").item())
        if total <= 0:
            return None
        hits = float(getattr(self, f"cap_hits_{src}").sum().item())
        n_features = getattr(self, f"err_mean_{src}").numel()
        return hits / (total * n_features)

    @torch.no_grad()
    def per_feature_zscore(self, x, src):
        """Vecteur de z par feature -> attribution (top-k contributeurs) pour
        le triage Sigma/LLM."""
        self.eval()
        return self._feature_z(x, src).cpu().numpy()

    @torch.no_grad()
    def latent(self, x, src):
        self.eval()
        return self.encode(x, src).cpu().numpy()