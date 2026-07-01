"""
training.py
===========
Entrainement NON SUPERVISE de bout en bout (AUCUN label, AUCUN ground truth).

Pipeline :
  load_dataset -> build_features -> validate_feature_coverage
  -> split temporel (pool / calib / test)
  -> preparation par source (filtre variance + scaler, fit TRAIN seul)
  -> entrainement iteratif :  train -> nettoyage (MAD(log mse) + HDBSCAN latent,
     plafonne) -> re-train
  -> calibration du seuil GPD-POT (thresholding.py, non supervise)
  -> sauvegarde modele / scalers / seuils / etat de nouveaute.

Lancer :  python training.py
"""
from __future__ import annotations
import os
import time
import math
import random
import warnings

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
import joblib

import config as C
import data_loader as DL
import feature_engineering as FE
import preprocessing as PP
from autoencoder import PerSourceAutoencoder
import thresholding as TH

warnings.filterwarnings("ignore")

# --- Determinisme -----------------------------------------------------------
random.seed(C.SEED)
np.random.seed(C.SEED)
torch.manual_seed(C.SEED)
torch.cuda.manual_seed_all(C.SEED)
torch.use_deterministic_algorithms(True, warn_only=True)
torch.backends.cudnn.deterministic = True
torch.backends.cudnn.benchmark = False
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

try:
    from hdbscan import HDBSCAN
    _HAS_HDBSCAN = True
except Exception:
    _HAS_HDBSCAN = False


def seed_worker(_wid):
    s = torch.initial_seed() % 2 ** 32
    np.random.seed(s)
    random.seed(s)


# ---------------------------------------------------------------------------
# Split temporel (anti-fuite) : train=passe, calib=present, test=futur
# ---------------------------------------------------------------------------
def temporal_split(df, ratios=C.SPLIT_RATIOS):
    """Split chronologique PAR SOURCE. Anti-fuite preserve (passe->present->futur
    AU SEIN de chaque source), mais chaque source alimente pool/calib/test."""
    pools, calibs, tests = [], [], []
    for s in df["log_source"].unique():
        d = df[df["log_source"] == s].copy()
        d["_ts"] = pd.to_datetime(d["@timestamp"], utc=True, errors="coerce")
        d = d.sort_values("_ts").drop(columns="_ts").reset_index(drop=True)
        n = len(d); i1 = int(n*ratios[0]); i2 = int(n*(ratios[0]+ratios[1]))
        pools.append(d.iloc[:i1]); calibs.append(d.iloc[i1:i2]); tests.append(d.iloc[i2:])
    cat = lambda xs: pd.concat(xs, ignore_index=True) if xs else df.iloc[:0].copy()
    return cat(pools), cat(calibs), cat(tests)

# ---------------------------------------------------------------------------
# Preparation par source
# ---------------------------------------------------------------------------
def prepare_sources(df_pool):
    feats_by_src, keep_by_src, scalers = {}, {}, {}
    data_train, data_val, input_dims = {}, {}, {}
    for s in C.SOURCES:
        d = df_pool[df_pool["log_source"] == s].reset_index(drop=True)
        n = len(d)
        cut = int(n * (1 - C.VAL_RATIO))
        n_train = cut
        if n_train < C.MIN_SOURCE_SAMPLES:
            print(f"  {s:8s}: DONNEES INSUFFISANTES ({n_train} train "
                  f"< {C.MIN_SOURCE_SAMPLES}) -- source ignoree "
                  f"(ni entrainee, ni calibree, ni alertee)")
            continue
        feats = C.FEATURES[s]
        # Split train/val CHRONOLOGIQUE interne au pool (derniers % = val).
        d_tr = d.iloc[:cut].reset_index(drop=True)
        d_va = d.iloc[cut:].reset_index(drop=True)

        # Filtre de variance + scaler : TRAIN UNIQUEMENT.
        X_tr_raw = PP._raw_matrix(d_tr, feats)
        keep, kept_feats = PP.fit_feature_filter(X_tr_raw, feats)
        scaler = PP.fit_scaler(d_tr, feats, keep)
        X_tr = PP.transform(d_tr, feats, scaler, keep)
        X_va = PP.transform(d_va, feats, scaler, keep) if len(d_va) else \
            np.zeros((0, X_tr.shape[1]), dtype=np.float32)

        feats_by_src[s], keep_by_src[s], scalers[s] = feats, keep, scaler
        data_train[s], data_val[s] = X_tr, X_va
        input_dims[s] = X_tr.shape[1]
        print(f"  {s:8s}: {len(d):,} logs | {input_dims[s]} features | "
              f"{len(X_tr):,} train / {len(X_va):,} val")
    return feats_by_src, keep_by_src, scalers, data_train, data_val, input_dims


# ---------------------------------------------------------------------------
# Entrainement par source (early stopping independant par source)
# ---------------------------------------------------------------------------
def train_model(model, data_train, data_val, input_dims):
    src_to_idx = {s: i for i, s in enumerate(C.SOURCES)}
    idx_to_src = {i: s for i, s in enumerate(C.SOURCES)}

    def build_loader(data_dict, shuffle):
        all_x, all_idx = [], []
        for s in C.SOURCES:
            X = data_dict.get(s)
            if X is None or len(X) == 0:
                continue
            pad = np.zeros((len(X), C.MAX_INPUT_DIM), dtype=np.float32)
            pad[:, :X.shape[1]] = X
            all_x.append(pad)
            all_idx += [src_to_idx[s]] * len(X)
        if not all_x:
            return None
        ds = TensorDataset(torch.FloatTensor(np.vstack(all_x)),
                           torch.LongTensor(np.array(all_idx)))
        g = torch.Generator(); g.manual_seed(C.SEED)
        return DataLoader(ds, batch_size=C.BATCH_SIZE, shuffle=shuffle,
                          drop_last=shuffle, num_workers=0,
                          worker_init_fn=seed_worker, generator=g)

    train_loader = build_loader(data_train, True)
    val_loader = build_loader(data_val, False)
    if train_loader is None:
        raise RuntimeError("Aucune donnee d'entrainement.")

    active = [s for s in C.SOURCES if s in input_dims]
    groups = [{"params": (list(model.encoders[s].parameters())
                          + list(model.decoders[s].parameters())),
               "lr": C.LR_BY_SOURCE[s],
               "weight_decay": C.WEIGHT_DECAY_BY_SOURCE[s],
               "name": s} for s in active]
    optimizer = torch.optim.AdamW(groups)

    def cosine_lr(epoch, s):
        t0 = max(C.EPOCHS_BY_SOURCE[s] // 4, 25)
        return 1e-5 + (C.LR_BY_SOURCE[s] - 1e-5) * 0.5 * (
            1 + math.cos(math.pi * (epoch % t0) / t0))

    best_val = {s: float("inf") for s in active}
    best_state = {s: None for s in active}
    pat = {s: 0 for s in active}
    frozen = {s: False for s in active}
    epochs_g = max(C.EPOCHS_BY_SOURCE[s] for s in active)
    train_hist, val_hist = [], []
    t0 = time.time()

    for epoch in range(epochs_g):
        if all(frozen[s] for s in active):
            print(f"  Early stopping global epoch {epoch + 1}")
            break
        for g in optimizer.param_groups:
            g["lr"] = cosine_lr(epoch, g["name"])

        model.train()
        tot, nb = 0.0, 0
        for x_pad, s_idx in train_loader:
            optimizer.zero_grad()
            bl = torch.tensor(0.0, device=DEVICE)
            used = False
            for sid, sname in idx_to_src.items():
                if frozen.get(sname, True):
                    continue
                m = (s_idx == sid)
                if m.sum() < 2:
                    continue
                x_s = x_pad[m, :input_dims[sname]].to(DEVICE)
                bl = bl + model.train_loss(model(x_s, sname), x_s)
                used = True
            if not used:
                continue
            bl.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 0.5)
            optimizer.step()
            tot += float(bl.item()); nb += 1

        model.eval()
        vbs = {}
        with torch.no_grad():
            for x_pad, s_idx in val_loader:
                for sid, sname in idx_to_src.items():
                    m = (s_idx == sid)
                    if m.sum() == 0:
                        continue
                    x_s = x_pad[m, :input_dims[sname]].to(DEVICE)
                    vbs[sname] = vbs.get(sname, 0.0) + float(
                        model.train_loss(model(x_s, sname), x_s).item())

        train_hist.append(tot / max(nb, 1))
        val_hist.append(sum(vbs.values()) / max(len(vbs), 1))

        for s in active:
            if frozen[s]:
                continue
            v = vbs.get(s, float("inf"))
            if v < best_val[s] - 1e-5:
                best_val[s] = v
                best_state[s] = {k: t.clone()
                                 for k, t in model.state_dict().items()
                                 if k.startswith((f"encoders.{s}.",
                                                  f"decoders.{s}."))}
                pat[s] = 0
            else:
                pat[s] += 1
                if pat[s] >= C.PATIENCE_BY_SOURCE[s]:
                    frozen[s] = True
                    if best_state[s]:
                        cur = model.state_dict(); cur.update(best_state[s])
                        model.load_state_dict(cur)
                    print(f"  [{s}] early stop epoch {epoch + 1} "
                          f"(best={best_val[s]:.6f})")

        if (epoch + 1) % 20 == 0 or epoch == 0:
            print(f"  Epoch {epoch + 1:3d}/{epochs_g} | "
                  f"train={train_hist[-1]:.6f} | val={val_hist[-1]:.6f}")

    final = model.state_dict()
    for s in active:
        if best_state[s]:
            final.update(best_state[s])
    model.load_state_dict(final)
    dur = time.time() - t0
    print(f"\n  Duree : {dur:.1f}s")
    for s in active:
        print(f"  {s:8s}: best_val={best_val[s]:.6f} frozen={frozen[s]}")
    return model, train_hist, val_hist, dur, best_val


# ---------------------------------------------------------------------------
# Nettoyage robuste : MAD sur log(mse)  +  HDBSCAN latent  (plafonne)
# ---------------------------------------------------------------------------
def _mad_log_high_error(mse, n_sigma, max_cut):
    """Masque des points a HAUTE erreur via MAD sur log(mse) (re-symetrise la
    queue lourde). Borne par un quantile pour ne pas exploser."""
    lm = np.log(mse + 1e-12)
    med = float(np.median(lm))
    mad = max(float(np.median(np.abs(lm - med))), 1e-6)
    thr_log = max(med + n_sigma * 1.4826 * mad,
                  float(np.quantile(lm, 1.0 - max_cut)))
    high = lm > thr_log
    return high, math.exp(thr_log)


def _hdbscan_noise(Z):
    """Points etiquetes bruit (-1) par HDBSCAN dans l'espace latent.
    Les clusters denses (meme rares) ne sont PAS bruit -> on les conserve."""
    if not (_HAS_HDBSCAN and C.USE_HDBSCAN_CLEAN) or len(Z) < C.HDBSCAN_MIN_CLUSTER * 2:
        return np.zeros(len(Z), dtype=bool)
    try:
        labels = HDBSCAN(min_cluster_size=C.HDBSCAN_MIN_CLUSTER,
                         core_dist_n_jobs=1).fit_predict(Z)
        return labels == -1
    except Exception as e:
        print(f"      HDBSCAN indisponible ({e}) -> ignore")
        return np.zeros(len(Z), dtype=bool)


def clean_training_set(model, data_train, input_dims, total_cut):
    """Coupe un point SI (haute erreur MAD-log) [ET bruit HDBSCAN latent].
    NE TOUCHE PLUS au val set : il reste FIXE et BRUT sur toutes les
    iterations -> best_val devient comparable d'une iteration a l'autre."""
    dt, stats = {}, {}
    print(f"\n  Nettoyage (MAD log-mse, n_sigma={C.CLEAN_N_SIGMA}) :")
    for s in C.SOURCES:
        if s not in data_train:
            continue
        X = data_train[s]
        xt = torch.FloatTensor(X).to(DEVICE)
        mse = model.reconstruction_error(xt, s)
        Z = model.latent(xt, s)
        max_cut = C.CLEAN_MAX_CUT_FRAC_BY_SOURCE.get(s, 0.10)
        high, thr = _mad_log_high_error(mse, C.CLEAN_N_SIGMA, max_cut)
        noise = _hdbscan_noise(Z)
        cut_mask = high & noise if noise.any() else high
        keep = ~cut_mask

        already = total_cut.get(s, 0.0)
        proposed = float((~keep).sum()) / max(len(X), 1)
        if already + proposed > C.MAX_TOTAL_CUT_FRAC:
            allowed = max(C.MAX_TOTAL_CUT_FRAC - already, 0.0)
            k = int(allowed * len(X))
            keep = np.ones(len(X), dtype=bool)
            if k > 0:
                worst = np.argsort(mse)[::-1][:k]
                keep[worst] = False
            print(f"      [{s}] plafond cumule atteint ({already*100:.1f}%) "
                  f"-> coupe limitee a {k}")
            proposed = float((~keep).sum()) / max(len(X), 1)

        total_cut[s] = already + proposed
        dt[s] = X[keep]
        cut_pct = (~keep).sum() / max(len(X), 1) * 100
        stats[s] = {"after": int(keep.sum()), "cut_pct": round(float(cut_pct), 2),
                    "cumul_cut_pct": round(total_cut[s] * 100, 2),
                    "n_high_error": int(high.sum()), "n_noise": int(noise.sum()),
                    "threshold_mse": round(float(thr), 6)}
        print(f"  {s:8s}: {len(X):,} -> {int(keep.sum()):,} "
              f"(coupe {cut_pct:.2f}%, cumul {total_cut[s]*100:.1f}%, "
              f"haute_err={int(high.sum())}, bruit={int(noise.sum())})")
    return dt, stats


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
def main():
    print("=" * 64)
    print(f"  AUTOENCODEUR NON SUPERVISE | Device={DEVICE}")
    print(f"  Perte train={C.TRAIN_LOSS} | score=zscore-feature cap={C.FEATURE_Z_CAP}")
    for s in C.SOURCES:
        print(f"  {s:8s}: {C.INPUT_DIMS[s]} features (avant filtre variance)")
    print("=" * 64)

    print("\n[1] Chargement...")
    df_raw = DL.load_dataset()
    if len(df_raw) == 0:
        print("ERREUR : aucune donnee."); return

    print("\n[2] Feature engineering (causal, sans ml.*)...")
    df = FE.build_features(df_raw)
    FE.validate_feature_coverage(df)

    print("\n[3] Split temporel (pool / calib / test)...")
    df_pool, df_calib, df_test = temporal_split(df)
    print(f"  pool={len(df_pool):,} | calib={len(df_calib):,} | test={len(df_test):,}")

    print("\n[4] Etat de nouveaute -> POOL uniquement (anti-fuite live)...")
    novelty_state = FE.build_novelty_state(df_pool)   # <-- POOL, pas df_raw complet
    joblib.dump(novelty_state, C.NOVELTY_PATH)

    print("\n[5] Preparation par source...")
    feats_by_src, keep_by_src, scalers, data_train, data_val, input_dims = \
        prepare_sources(df_pool)
    if not data_train:
        print("ERREUR : aucune source exploitable."); return

    print("\n[6] Entrainement (train unique)...")
    model = PerSourceAutoencoder(input_dims, C.LATENT_DIM_BY_SOURCE).to(DEVICE)
    model, train_hist, val_hist, dur, best_val = train_model(
        model, data_train, data_val, input_dims)

    print("\n[6b] Normalisation de l'erreur par feature (sur TRAIN brut)...")
    for s in input_dims:
        model.fit_error_norm(torch.FloatTensor(data_train[s]).to(DEVICE), s)
        em = getattr(model, f"err_mean_{s}")
        print(f"    {s:8s}: err_mean moyen={float(em.mean()):.4e} "
              f"| {len(data_train[s]):,} echantillons")

    print("\n[7] Sauvegarde modele + scalers...")
    torch.save(model.state_dict(), C.MODEL_PATH)
    joblib.dump({"scalers": scalers, "keep": keep_by_src,
                 "feats": feats_by_src, "input_dims": input_dims}, C.SCALERS_PATH)
    print(f"  -> {C.MODEL_PATH} | {C.SCALERS_PATH}")

    print("\n[8] Calibration GPD-POT (non supervise, sur CALIB BRUTE)...")
    thresholds = TH.compute_thresholds_from_df(
        model, df_calib, feats_by_src, scalers, keep_by_src, DEVICE)
    joblib.dump(thresholds, C.THRESH_PATH)
    print(f"  -> {C.THRESH_PATH}")

    print("\n[9] QA calibration : taux realise vs cible...")
    r_calib = TH.realized_alert_rate(model, df_calib, feats_by_src, scalers,
                                     keep_by_src, thresholds, DEVICE)
    r_test  = TH.realized_alert_rate(model, df_test, feats_by_src, scalers,
                                     keep_by_src, thresholds, DEVICE)
    for s in r_calib:
        target = C.POT_TARGET_RATE_BY_SOURCE.get(s, C.POT_TARGET_RATE)
        flag = "  <-- calib > 2x cible" if r_calib[s] > 2 * target else ""
        print(f"    {s:8s}: cible={target*100:.2f}% | calib={r_calib[s]*100:.2f}% "
              f"| test={r_test[s]*100:.2f}%{flag}")
        if r_test[s] > 3 * max(r_calib[s], target):
            print(f"             /!\\ test >> calib ({s}) : derive temporelle "
                  f"ou attaques injectees")

    print("\n  Artifacts prets. Lancer : python inference.py")
    print("=" * 64)
    return model, scalers, keep_by_src, feats_by_src, thresholds, df_test

    
if __name__ == "__main__":
    main()