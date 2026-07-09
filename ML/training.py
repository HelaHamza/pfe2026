"""
training.py
===========
Entrainement NON SUPERVISE de bout en bout (AUCUN label, AUCUN ground truth).

Pipeline :
  load_dataset -> build_features -> validate_feature_coverage
  -> split temporel (pool / calib / test)          [splitting.temporal_split]
  -> preparation par source (filtre variance + scaler, fit TRAIN seul)
  -> entrainement (train unique, early stopping independant par source)
  -> normalisation de l'erreur par feature (sur TRAIN brut)
  -> calibration du seuil GPD-POT (thresholding.py, non supervise)
  -> sauvegarde modele / scalers / seuils / etat de nouveaute.

Lancer :  python training.py

NOTE REFACTOR : le decoupage temporel n'est PLUS defini ici. Il vit dans
splitting.temporal_split, importe aussi par inference.py -> une seule
definition du split pour tout le projet (plus de risque de desynchronisation).
"""
from __future__ import annotations
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
from splitting import temporal_split          # <-- SOURCE UNIQUE DE VERITE du split

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


def seed_worker(_wid):
    s = torch.initial_seed() % 2 ** 32
    np.random.seed(s)
    random.seed(s)


# ---------------------------------------------------------------------------
# Preparation par source (filtre variance + scaler, fit TRAIN seul)
# ---------------------------------------------------------------------------
def prepare_sources(df_pool):
    """A partir du POOL (bloc d'entrainement), fabrique par source :
      * la liste de features gardees (filtre de variance, fit TRAIN seul),
      * le StandardScaler (fit TRAIN seul -> aucune fuite calib/test),
      * les matrices X train / X val (le pool est re-decoupe via VAL_RATIO).
    """
    feats_by_src, keep_by_src, scalers = {}, {}, {}
    data_train, data_val, input_dims = {}, {}, {}
    for s in C.SOURCES:
        d = df_pool[df_pool["log_source"] == s].reset_index(drop=True)
        n = len(d)
        # Re-decoupe INTERNE du pool : train (poids) / val (early stopping).
        cut = int(n * (1 - C.VAL_RATIO))
        if cut < C.MIN_SOURCE_SAMPLES:
            print(f"  {s:8s}: DONNEES INSUFFISANTES ({cut} train "
                  f"< {C.MIN_SOURCE_SAMPLES}) -- source ignoree")
            continue
        feats = C.FEATURES[s]
        d_tr = d.iloc[:cut].reset_index(drop=True)
        d_va = d.iloc[cut:].reset_index(drop=True)

        # Filtre de variance + scaler : APPRIS SUR LE TRAIN UNIQUEMENT.
        X_tr_raw = PP._raw_matrix(d_tr, feats)
        keep, _ = PP.fit_feature_filter(X_tr_raw, feats)
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
        # Toutes les sources sont empilees dans un meme loader, chaque ligne
        # etiquetee par son index de source (padding a MAX_INPUT_DIM).
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

    # Un groupe d'optimisation PAR SOURCE (lr / weight_decay propres).
    active = [s for s in C.SOURCES if s in input_dims]
    groups = [{"params": (list(model.encoders[s].parameters())
                          + list(model.decoders[s].parameters())),
               "lr": C.LR_BY_SOURCE[s],
               "weight_decay": C.WEIGHT_DECAY_BY_SOURCE[s],
               "name": s} for s in active]
    optimizer = torch.optim.AdamW(groups)

    def cosine_lr(epoch, s):
        # Recuit cosinus par source (redemarrage tous les t0 epochs).
        t0 = max(C.EPOCHS_BY_SOURCE[s] // 4, 25)
        return 1e-5 + (C.LR_BY_SOURCE[s] - 1e-5) * 0.5 * (
            1 + math.cos(math.pi * (epoch % t0) / t0))

    # Etat d'early stopping INDEPENDANT par source (chaque source gele quand
    # sa propre val stagne, sans attendre les autres).
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

        # --- passe d'entrainement ---
        model.train()
        tot, nb = 0.0, 0
        for x_pad, s_idx in train_loader:
            optimizer.zero_grad()
            bl = torch.tensor(0.0, device=DEVICE)
            used = False
            for sid, sname in idx_to_src.items():
                if frozen.get(sname, True):          # source gelee -> on saute
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

        # --- passe de validation ---
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

        # --- early stopping par source ---
        for s in active:
            if frozen[s]:
                continue
            v = vbs.get(s, float("inf"))
            if v < best_val[s] - 1e-5:
                best_val[s] = v
                # On sauvegarde SEULEMENT les poids de cette source.
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

    # Restaure le meilleur etat de chaque source.
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
    # pool -> entrainement | calib -> seuil GPD-POT | test -> QA (etape 9).
    df_pool, df_calib, df_test = temporal_split(df)
    print(f"  pool={len(df_pool):,} | calib={len(df_calib):,} | test={len(df_test):,}")

    print("\n[4] Etat de nouveaute -> POOL uniquement (anti-fuite live)...")
    # Les vocabulaires de rarete sont appris sur le POOL seul : en live, un
    # terme jamais vu au train reste "nouveau".
    novelty_state = FE.build_novelty_state(df_pool)
    joblib.dump(novelty_state, C.NOVELTY_PATH)

    print("\n[5] Preparation par source...")
    feats_by_src, keep_by_src, scalers, data_train, data_val, input_dims = \
        prepare_sources(df_pool)
    if not data_train:
        print("ERREUR : aucune source exploitable."); return

    print("\n[6] Entrainement...")
    model = PerSourceAutoencoder(input_dims, C.LATENT_DIM_BY_SOURCE).to(DEVICE)
    model, train_hist, val_hist, dur, best_val = train_model(
        model, data_train, data_val, input_dims)

    print("\n[6b] Normalisation |residu| par feature (sur CALIB held-out)...")
    for s in input_dims:
        d = df_calib[df_calib["log_source"] == s].reset_index(drop=True)
        Xn = PP.transform(d, feats_by_src[s], scalers[s], keep_by_src[s]) \
             if len(d) else data_train[s]                    # repli si calib vide
        model.fit_error_norm(torch.FloatTensor(Xn).to(DEVICE), s)

        em = getattr(model, f"err_mean_{s}")
        print(f"    {s:8s}: err_mean moyen={float(em.mean()):.4e} "
              f"| {len(data_train[s]):,} echantillons")

    print("\n[7] Sauvegarde modele + scalers...")
    torch.save(model.state_dict(), C.MODEL_PATH)
    joblib.dump({"scalers": scalers, "keep": keep_by_src,
                 "feats": feats_by_src, "input_dims": input_dims}, C.SCALERS_PATH)
    print(f"  -> {C.MODEL_PATH} | {C.SCALERS_PATH}")

    print("\n[8] Calibration GPD-POT (non supervise, sur CALIB BRUTE)...")
    # Le seuil est cale sur la CALIB (present), jamais sur le train ni le test.
    thresholds = TH.compute_thresholds_from_df(
        model, df_calib, feats_by_src, scalers, keep_by_src, DEVICE)
    joblib.dump(thresholds, C.THRESH_PATH)
    print(f"  -> {C.THRESH_PATH}")

    print("\n[9] QA calibration : taux realise vs cible...")
    # Le TEST ne sert ici QU'A verifier la tenue du seuil (derive / attaques).
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