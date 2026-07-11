"""
fit_sat_weight.py
=================
Post-hoc (SANS reentrainement) : calcule les poids de demotion par feature
= 1 - taux de saturation du cap sur la CALIB benigne, les persiste dans le
bundle scalers, puis RECALIBRE les seuils GPD-POT sur le score LSE PONDERE.

Le modele AE (model_ae.pt) et err_norm restent GELES : seule l'agregation
change (ponderation des z AVANT le max du LSE). A lancer une fois, avant
inference.py.

Prerequis : appliquer d'abord les 4 edits d'autoencoder.py (fit_sat_weight,
_aggregate pondere, reconstruction_error(src), self.sat_weight={}) et l'edit
d'inference.py (rattachement de sat_weight).

    python fit_sat_weight.py
"""
from __future__ import annotations
import numpy as np
import torch
import joblib

import config as C
import data_loader as DL
import feature_engineering as FE
import preprocessing as PP
from autoencoder import PerSourceAutoencoder
import thresholding as TH
from splitting import temporal_split

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


def main():
    print("=" * 64)
    print("  DEMOTION NOUVEAUTE (poids anti-saturation) + RECALIBRATION")
    print(f"  Modele GELE | cap={C.FEATURE_Z_CAP} | tau_LSE={C.SCORE_LSE_TAU}")
    print("=" * 64)

    # 1. Recharge les artifacts GELES ---------------------------------------
    bundle = joblib.load(C.SCALERS_PATH)
    scalers, keep = bundle["scalers"], bundle["keep"]
    feats, input_dims = bundle["feats"], bundle["input_dims"]
    model = PerSourceAutoencoder(input_dims, C.LATENT_DIM_BY_SOURCE).to(DEVICE)
    model.load_state_dict(torch.load(C.MODEL_PATH, map_location=DEVICE))
    model.eval()

    # 2. Reproduit EXACTEMENT la calib du training (meme split, novelty=None)-
    print("\n[1] Reconstruction de la CALIB (meme split que training.py)...")
    df_raw = DL.load_dataset()
    df_feat = FE.build_features(df_raw, novelty_state=None)
    _, df_calib, _ = temporal_split(df_feat)
    print(f"  calib = {len(df_calib):,} logs")

    # 3. Poids de demotion par feature (sur CALIB benigne) ------------------
    print("\n[2] Taux de saturation du cap par feature (CALIB) -> poids w :")
    for s in C.SOURCES:
        if s not in scalers:
            continue
        d = df_calib[df_calib["log_source"] == s].reset_index(drop=True)
        if len(d) == 0:
            print(f"  {s:8s}: calib vide -> poids=1 (inchange)")
            continue
        X = PP.transform(d, feats[s], scalers[s], keep[s])
        xt = torch.FloatTensor(X).to(DEVICE)
        w = model.fit_sat_weight(xt, s)          # reset compteurs + record + poids

        feats_kept = [f for f, k in zip(feats[s], keep[s]) if k]
        sat = 1.0 - w.cpu().numpy()
        order = np.argsort(-sat)                  # plus saturees d'abord
        print(f"  {s}:")
        for i in order:
            flag = "  <-- DEMOTEE" if sat[i] > 0.5 else ""
            print(f"      {feats_kept[i]:24s} sat={sat[i]:.3f}  w={float(w[i]):.3f}{flag}")

    # 4. Persiste les poids dans le bundle (inference les rattachera) --------
    bundle["sat_weight"] = {s: model.sat_weight[s].cpu().numpy()
                            for s in model.sat_weight}
    joblib.dump(bundle, C.SCALERS_PATH)
    print(f"\n[3] Poids sauves dans {C.SCALERS_PATH} (cle 'sat_weight').")

    # 5. RECALIBRE les seuils sur le score PONDERE (poids deja attaches) -----
    print("\n[4] Recalibration GPD-POT sur le score LSE pondere (CALIB BRUTE)...")
    old_thr = joblib.load(C.THRESH_PATH)
    new_thr = TH.compute_thresholds_from_df(
        model, df_calib, feats, scalers, keep, DEVICE)
    joblib.dump(new_thr, C.THRESH_PATH)

    print("\n[5] Seuils AVANT -> APRES :")
    for s in new_thr:
        o, n = TH.get_threshold(old_thr, s), TH.get_threshold(new_thr, s)
        print(f"  {s:8s}: {o:.4f} -> {n:.4f}")

    # 6. Sanity : taux d'alerte calib pondere ~ cible -----------------------
    print("\n[6] Taux d'alerte calib (pondere) vs cible :")
    r = TH.realized_alert_rate(model, df_calib, feats, scalers, keep, new_thr, DEVICE)
    for s in r:
        tgt = C.POT_TARGET_RATE_BY_SOURCE.get(s, C.POT_TARGET_RATE)
        flag = "  <-- > 2x cible" if r[s] > 2 * tgt else ""
        print(f"  {s:8s}: cible={tgt*100:.2f}% | calib={r[s]*100:.2f}%{flag}")

    print("\n  OK. Lancer maintenant : python inference.py")
    print("=" * 64)


if __name__ == "__main__":
    main()