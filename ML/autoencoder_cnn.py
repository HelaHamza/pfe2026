"""
autoencoder_cnn.py
==================
Auto-encodeur convolutif 1D HYBRIDE par source (branche optimale).

Entree par evenement-fenetre :
  * Xs : [B, Fs, W]  scalaires (rarete, timing, is_fail, ...)
  * Xt : [B, W]      ids d'event_type -> EMBEDDING appris (canal sequence)

Deux tetes de reconstruction :
  * scalaire     : Conv1d -> [B, Fs, W]   (perte Huber)
  * sequence     : Conv1d -> [B, V, W]    (perte cross-entropy sur les tokens)
Le CNN glisse un noyau sur le TEMPS -> il apprend sequence / co-occurrence /
densite tout seul. Denoising + goulot contractif -> anti reconstruction-identite.

SCORE PAR EVENEMENT (position finale L=W-1, l'evenement courant) :
  z_scalaire (par feature) et z_token (surprise = -log p(token vrai)),
  normalises sur la CALIB, plancher/plafond puis agreges en LSE.
  -> scalaire par evenement -> GPD-POT + episodes reutilises.
Attribution PAR FEATURE conservee (+ composante 'event_type' pour la sequence).
"""
from __future__ import annotations
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

import config_cnn as CC


def _cblock(cin, cout, k, stride=1):
    return nn.Sequential(nn.Conv1d(cin, cout, k, stride=stride, padding=k // 2), nn.GELU())


class HybridConvAE(nn.Module):
    """AE hybride pour UNE source."""

    def __init__(self, n_scalar, vocab_size, win, latent,
                 emb_dim=CC.EMBED_DIM, channels=CC.CONV_CHANNELS,
                 pool_len=CC.POOL_LEN, k=CC.KERNEL_SIZE, dropout=CC.DROPOUT):
        super().__init__()
        c1, c2 = channels
        self.win, self.pool_len, self.c2 = win, pool_len, c2
        self.n_scalar, self.vocab_size = n_scalar, vocab_size
        self.emb = nn.Embedding(vocab_size, emb_dim, padding_idx=CC.PAD_ID)
        cin = n_scalar + emb_dim

        self.enc = nn.Sequential(
            _cblock(cin, c1, k), nn.Dropout(dropout),
            _cblock(c1, c2, k, stride=2), _cblock(c2, c2, k),
            nn.AdaptiveAvgPool1d(pool_len))
        self.to_latent   = nn.Linear(c2 * pool_len, latent)
        self.from_latent = nn.Linear(latent, c2 * pool_len)
        self.dec = nn.Sequential(_cblock(c2, c2, k), _cblock(c2, c1, k), nn.Dropout(dropout))
        self.head_scalar = nn.Conv1d(c1, n_scalar, k, padding=k // 2)
        self.head_token  = nn.Conv1d(c1, vocab_size, k, padding=k // 2)

    def _embed(self, Xt):
        return self.emb(Xt).transpose(1, 2)          # [B, emb, W]

    def _corrupt(self, Xs, Xt):
        """Denoising : masque une fraction de positions (train uniquement)."""
        frac = CC.DENOISE_MASK_FRAC
        if not self.training or frac <= 0:
            return Xs, Xt
        m = torch.rand(Xt.shape, device=Xt.device) < frac      # [B, W]
        Xs2 = Xs.masked_fill(m.unsqueeze(1), 0.0)
        Xt2 = Xt.masked_fill(m, CC.MASK_ID)
        return Xs2, Xt2

    def forward(self, Xs, Xt):
        Xs_c, Xt_c = self._corrupt(Xs, Xt)
        x = torch.cat([Xs_c, self._embed(Xt_c)], dim=1)        # [B, Fs+emb, W]
        z = self.to_latent(self.enc(x).flatten(1))
        h = self.from_latent(z).view(x.size(0), self.c2, self.pool_len)
        h = F.interpolate(h, size=self.win, mode="linear", align_corners=False)
        h = self.dec(h)
        return self.head_scalar(h), self.head_token(h)         # [B,Fs,W], [B,V,W]

    def encode(self, Xs, Xt):
        x = torch.cat([Xs, self._embed(Xt)], dim=1)
        return self.to_latent(self.enc(x).flatten(1))


class PerSourceHybridConvAE(nn.Module):
    def __init__(self, scalar_dims, vocab_sizes, win=CC.WINDOW_SIZE, latent_dims=None):
        super().__init__()
        self.win = win
        ld = latent_dims or CC.LATENT_DIM_BY_SOURCE
        self.nets = nn.ModuleDict({
            s: HybridConvAE(scalar_dims[s], vocab_sizes[s], win, ld[s])
            for s in scalar_dims})
        for s, d in scalar_dims.items():
            self.register_buffer(f"err_mean_{s}", torch.zeros(d))
            self.register_buffer(f"err_std_{s}",  torch.ones(d))
            self.register_buffer(f"nll_mean_{s}", torch.zeros(1))
            self.register_buffer(f"nll_std_{s}",  torch.ones(1))

    # --- pertes d'entrainement ---------------------------------------------
    def train_loss(self, Xs, Xt, src):
        sc_hat, tok_logits = self.nets[src](Xs, Xt)
        l_sc = F.huber_loss(sc_hat, Xs, delta=CC.HUBER_DELTA)
        l_tok = F.cross_entropy(
            tok_logits.permute(0, 2, 1).reshape(-1, tok_logits.size(1)),
            Xt.reshape(-1), ignore_index=CC.PAD_ID)
        return l_sc + CC.TOKEN_LOSS_WEIGHT * l_tok

    # --- composantes a la position finale (evenement courant) --------------
    @torch.no_grad()
    def _last_components(self, Xs, Xt, src):
        self.nets[src].eval()
        sc_hat, tok_logits = self.nets[src](Xs, Xt)            # eval : pas de corruption
        L = self.win - 1
        abs_res = (Xs[:, :, L] - sc_hat[:, :, L]).abs()        # [B, Fs]
        logp = F.log_softmax(tok_logits[:, :, L], dim=1)       # [B, V]
        true_tok = Xt[:, L]
        nll = -logp.gather(1, true_tok.unsqueeze(1)).squeeze(1)  # [B]
        return abs_res, nll

    @torch.no_grad()
    def fit_norms(self, Xs, Xt, src):
        """mean/std de |residu| par feature ET de la NLL token, sur CALIB."""
        abs_res, nll = self._last_components(Xs, Xt, src)
        getattr(self, f"err_mean_{src}").copy_(abs_res.mean(0))
        getattr(self, f"err_std_{src}").copy_(abs_res.std(0).clamp_min(1e-6))
        getattr(self, f"nll_mean_{src}").copy_(nll.mean().reshape(1))
        getattr(self, f"nll_std_{src}").copy_(nll.std().clamp_min(1e-6).reshape(1))

    @torch.no_grad()
    def score_components(self, Xs, Xt, src):
        """Retourne (z_scalaire [B,Fs], z_token [B]) standardises calib."""
        abs_res, nll = self._last_components(Xs, Xt, src)
        floor, cap = CC.RESIDUAL_SCALE_FLOOR, CC.FEATURE_Z_CAP
        std = getattr(self, f"err_std_{src}").clamp_min(floor)
        z_sc = ((abs_res - getattr(self, f"err_mean_{src}")) / std).clamp(0.0, cap)
        z_tok = ((nll - getattr(self, f"nll_mean_{src}")) /
                 getattr(self, f"nll_std_{src}").clamp_min(floor)).clamp(0.0, cap)
        return z_sc, z_tok.squeeze(-1) if z_tok.dim() > 1 else z_tok

    @torch.no_grad()
    def reconstruction_error(self, Xs, Xt, src):
        """Score scalaire par evenement = LSE( z_scalaires , z_token )."""
        z_sc, z_tok = self.score_components(Xs, Xt, src)
        z = torch.cat([z_sc, z_tok.unsqueeze(1)], dim=1)       # [B, Fs+1]
        #tau = CC.SCORE_LSE_TAU
        tau = CC.SCORE_LSE_TAU_BY_SOURCE[src]
        m = z.max(dim=1, keepdim=True).values
        return (m + tau * torch.log(
            torch.exp((z - m) / tau).mean(dim=1, keepdim=True))).squeeze(1).cpu().numpy()

    @torch.no_grad()
    def latent(self, Xs, Xt, src):
        return self.nets[src].encode(Xs, Xt).cpu().numpy()