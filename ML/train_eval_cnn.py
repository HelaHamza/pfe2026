"""
train_eval_cnn.py
=================
Harnais de la branche CNN HYBRIDE : entraine, calibre (GPD-POT reutilise),
score le TEST, ecrit un CSV au MEME schema que alerts.csv.

A/B direct :
    python train_eval_cnn.py
    python evaluation.py --from-csv cnn_scored_test.csv

Reutilise sans modification : data_loader, cnn_features (build_features,
raw_matrix), splitting.temporal_split, thresholding._pot_threshold.
[FIX] Ce module n'utilise PLUS preprocessing.py (module MLP proscrit par
l'architecture CNN) ni feature_engineering.py : cnn_features.py est
totalement autonome et fournit deja tout ce qu'il faut.
"""
from __future__ import annotations
import time, random
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
import joblib

import config_cnn as C            # [FIX] un SEUL alias pour config_cnn.
                                  # Le fichier melangeait C et CC pour le meme
                                  # module (CC.WINDOW_SIZE, CC.FIRST_TOKEN_ID) :
                                  # tout est desormais 'C.' -> plus de risque
                                  # de NameError si l'alias CC disparait.
import data_loader as DL
import cnn_features as FE
import thresholding as TH
from splitting import temporal_split
import cnn_windowing as W
from autoencoder_cnn import PerSourceHybridConvAE

random.seed(C.SEED); np.random.seed(C.SEED); torch.manual_seed(C.SEED)
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


def _train_source(model, Xs_tr, Xt_tr, Xs_va, Xt_va, src):
    ds = TensorDataset(torch.from_numpy(Xs_tr), torch.from_numpy(Xt_tr))
    g = torch.Generator(); g.manual_seed(C.SEED)
    loader = DataLoader(ds, batch_size=C.BATCH_SIZE, shuffle=True,
                        drop_last=True, generator=g)
    opt = torch.optim.AdamW(model.nets[src].parameters(),
                            lr=C.LR_BY_SOURCE[src], weight_decay=C.WEIGHT_DECAY)
    xs_va = torch.from_numpy(Xs_va).to(DEVICE) if len(Xs_va) else None
    xt_va = torch.from_numpy(Xt_va).to(DEVICE) if len(Xt_va) else None
    best, best_state, pat = float("inf"), None, 0
    epochs, patience = C.EPOCHS_BY_SOURCE[src], C.PATIENCE_BY_SOURCE[src]

    for ep in range(epochs):
        model.nets[src].train()
        for xs, xt in loader:
            xs, xt = xs.to(DEVICE), xt.to(DEVICE)
            opt.zero_grad()
            loss = model.train_loss(xs, xt, src)
            loss.backward()
            nn.utils.clip_grad_norm_(model.nets[src].parameters(), 0.5)
            opt.step()
        if xs_va is not None and len(xs_va):
            model.nets[src].eval()
            with torch.no_grad():
                v = float(model.train_loss(xs_va, xt_va, src).item())
            if v < best - 1e-5:
                best, pat = v, 0
                best_state = {k: t.clone() for k, t in model.nets[src].state_dict().items()}
            else:
                pat += 1
                if pat >= patience:
                    print(f"    [{src}] early stop epoch {ep + 1} (val={best:.6f})"); break
        if (ep + 1) % 20 == 0:
            print(f"    [{src}] epoch {ep + 1}/{epochs} val={best:.6f}")
    if best_state:
        model.nets[src].load_state_dict(best_state)


def _score_df(model, d_src, feats, scaler, vocab, src, thr):
    Xs, Xt, d_sorted = W.build_windows(d_src, feats, scaler, vocab, src)
    if len(d_sorted) == 0:
        return pd.DataFrame()
    xs = torch.from_numpy(Xs).to(DEVICE); xt = torch.from_numpy(Xt).to(DEVICE)
    score = model.reconstruction_error(xs, xt, src)          # [N]
    z_sc, z_tok = model.score_components(xs, xt, src)
    z_sc = z_sc.cpu().numpy(); z_tok = z_tok.cpu().numpy()

    names = np.asarray(list(feats) + ["event_type_seq"], dtype=object)
    Z = np.concatenate([z_sc, z_tok[:, None]], axis=1)       # [N, Fs+1]
    idx = np.argsort(-Z, axis=1)[:, :3]
    top_features = np.empty(len(d_sorted), dtype=object)
    top_feat = np.empty(len(d_sorted), dtype=object)
    for i in range(len(d_sorted)):
        pos = [j for j in idx[i] if Z[i, j] > 0]
        top_features[i] = ", ".join(f"{names[j]}={Z[i, j]:.1f}" for j in pos)
        top_feat[i] = names[idx[i, 0]] if Z[i, idx[i, 0]] > 0 else ""

    conf = np.clip(score / thr, 0.0, None)
    return pd.DataFrame({
        "@timestamp": d_sorted.get("@timestamp"), "log_source": src,
        "host_name": d_sorted.get("host_name"), "user_name": d_sorted.get("user_name"),
        "source_ip": d_sorted.get("source_ip"), "process_name": d_sorted.get("process_name"),
        "event_type": d_sorted.get("event_type"),
        "mse": score, "threshold": thr, "is_alert": (score > thr).astype(int),
        "confidence": conf.round(3),
        # [FIX] include_lowest=True : un score exactement nul (conf=0) tombait
        # hors de l'intervalle (0, 1.5] -> label "nan". Il est maintenant "low".
        "confidence_level": pd.cut(conf, bins=[0, 1.5, 3.0, np.inf],
                                   labels=["low", "medium", "high"],
                                   include_lowest=True).astype(str),
        "top_features": top_features, "top_feat": top_feat,
        "split": "test", "role": C.SOURCE_ROLE.get(src, "alert"),
    })


def main():
    print("=" * 64)
    print(f"  AE CONV HYBRIDE (sequence + rarete) | Device={DEVICE} | W={C.WINDOW_SIZE}")
    print("=" * 64)

    print("\n[1] Chargement + features (is_fail inclus)...")
    # [FIX] FE.build_features() applique DEJA add_atomic_channels() en interne
    # (cf. cnn_features.py, section 9). L'ancien code appelait en plus
    # W.add_atomic_channels(...) par-dessus : appel redondant sur une fonction
    # elle-meme dupliquee dans cnn_windowing.py (supprimee, cf. ce module).
    df = FE.build_features(DL.load_dataset())
    novelty_state = FE.build_novelty_state(df)   # comptes gelés (parent_executable déjà présent)
    print("    novelty_state : " +
          ", ".join(f"{k}={len(v)}" for k, v in novelty_state.items()))

    print("\n[2] Split temporel (pool / calib / test)...")
    df_pool, df_calib, df_test = temporal_split(df)

    scalers, vocabs, feats_by, scalar_dims, vocab_sizes = {}, {}, {}, {}, {}
    tr, va = {}, {}
    print("\n[3] Preparation par source (vocab + scaler + fenetres)...")
    for s in C.SOURCES:
        feats = C.CNN_FEATURES[s]
        d = df_pool[df_pool["log_source"] == s].reset_index(drop=True)
        if len(d) < C.MIN_SOURCE_SAMPLES:
            print(f"  {s:8s}: donnees insuffisantes ({len(d)}) -- ignoree"); continue
        cut = int(len(d) * (1 - C.VAL_RATIO))
        d_tr, d_va = d.iloc[:cut], d.iloc[cut:]
        vocab = W.fit_vocab(d_tr); scaler = W.fit_scaler(d_tr, feats)
        Xs_tr, Xt_tr, _ = W.build_windows(d_tr, feats, scaler, vocab, s)
        if len(d_va):
            Xs_va, Xt_va, _ = W.build_windows(d_va, feats, scaler, vocab, s)
        else:
            Xs_va = np.zeros((0, len(feats), C.WINDOW_SIZE), np.float32)   # [FIX] C.
            Xt_va = np.zeros((0, C.WINDOW_SIZE), np.int64)                 # [FIX] C.
        scalers[s], vocabs[s], feats_by[s] = scaler, vocab, feats
        scalar_dims[s] = len(feats)
        vocab_sizes[s] = C.FIRST_TOKEN_ID + len(vocab)                     # [FIX] C.
        tr[s] = (Xs_tr, Xt_tr); va[s] = (Xs_va, Xt_va)
        print(f"  {s:8s}: {len(feats)} scalaires + vocab={len(vocab)} tokens | "
              f"{len(Xs_tr):,} fenetres train / {len(Xs_va):,} val")

    if not scalar_dims:
        print("ERREUR : aucune source exploitable."); return

    print("\n[4] Entrainement (Huber scalaire + CE sequence)...")
    model = PerSourceHybridConvAE(scalar_dims, vocab_sizes, win=C.WINDOW_SIZE).to(DEVICE)
    t0 = time.time()
    for s in scalar_dims:
        _train_source(model, *tr[s], *va[s], s)
    print(f"  duree : {time.time() - t0:.1f}s")

    print("\n[5] Normalisation |residu| + NLL sur CALIB...")
    for s in scalar_dims:
        d = df_calib[df_calib["log_source"] == s].reset_index(drop=True)
        if len(d):
            Xs, Xt, _ = W.build_windows(d, feats_by[s], scalers[s], vocabs[s], s)
        else:
            Xs, Xt = tr[s]
        model.fit_norms(torch.from_numpy(Xs).to(DEVICE),
                        torch.from_numpy(Xt).to(DEVICE), s)

    print("\n[6] Seuil GPD-POT par source (thresholding reutilise)...")
    thresholds = {}
    for s in scalar_dims:
        d = df_calib[df_calib["log_source"] == s].reset_index(drop=True)
        Xs, Xt, _ = W.build_windows(d, feats_by[s], scalers[s], vocabs[s], s)
        scores = model.reconstruction_error(torch.from_numpy(Xs).to(DEVICE),
                                            torch.from_numpy(Xt).to(DEVICE), s)
        rate = C.POT_TARGET_RATE_BY_SOURCE.get(s, C.POT_TARGET_RATE)
        thr, info = TH._pot_threshold(scores, target_rate=rate)
        thresholds[s] = {"threshold": float(thr), "info": info}
        print(f"    {s:8s}: thr={thr:.6f} ({info['method']}) | n_calib={len(d):,}")

    print("\n[7] Sauvegarde artifacts CNN...")
    torch.save(model.state_dict(), C.MODEL_PATH)
    joblib.dump({"scalers": scalers, "vocabs": vocabs, "feats": feats_by,
                 "scalar_dims": scalar_dims, "vocab_sizes": vocab_sizes,
                 "win": C.WINDOW_SIZE}, C.BUNDLE_PATH)
    joblib.dump(thresholds, C.THRESH_PATH)
    joblib.dump(novelty_state, C.NOVELTY_STATE_PATH)
    print(f"    novelty_state -> {C.NOVELTY_STATE_PATH}")

    print("\n[8] Scoring du TEST (schema alerts.csv)...")
    parts = []
    for s in scalar_dims:
        d = df_test[df_test["log_source"] == s].reset_index(drop=True)
        if len(d) == 0:
            continue
        thr = float(thresholds[s]["threshold"])
        out = _score_df(model, d, feats_by[s], scalers[s], vocabs[s], s, thr)
        if len(out):
            parts.append(out)
            print(f"    {s:8s}: {int(out['is_alert'].sum()):5d} alertes / {len(out):,} "
                  f"({100 * out['is_alert'].mean():.2f}%)")
    scored = pd.concat(parts, ignore_index=True) if parts else pd.DataFrame()
    scored.to_csv(C.SCORED_TEST_CSV, index=False)
    print(f"\n  -> {C.SCORED_TEST_CSV}")
    print(f"  A/B : python evaluation.py --from-csv {C.SCORED_TEST_CSV}")
    print("=" * 64)


if __name__ == "__main__":
    main()