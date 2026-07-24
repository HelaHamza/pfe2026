"""
rethreshold_cnn.py
==================
Recalcule les seuils GPD-POT du CNN sur la CALIB, avec le modele GELE
(aucun re-entrainement), a partir des cibles POT_TARGET_RATE_BY_SOURCE
actuelles de config.py. Re-sauve cnn_thresholds.pkl.

Workflow rapide pour tester le levier seuil :
    1. editer POT_TARGET_RATE_BY_SOURCE dans config.py
    2. python rethreshold_cnn.py        # ~secondes, pas de train
    3. python inference_cnn.py          # re-score le test -> nouveaux episodes
    4. lire n_alert_episodes + recall dans cnn_evaluation_report.json
"""
from __future__ import annotations
import torch
import joblib

import config as C
import config_cnn as CC
import data_loader as DL
import feature_engineering as FE
import cnn_windowing as W
import thresholding as TH
from splitting import temporal_split
from train_eval_cnn import DEVICE
from inference_cnn import load_artifacts_cnn


def main():
    print("=" * 60)
    print("  RE-SEUIL CNN (modele gele, calib seule)")
    print("=" * 60)

    model, scalers, vocabs, feats_by, old_thr = load_artifacts_cnn()

    df = W.add_atomic_channels(FE.build_features(DL.load_dataset()))
    _, df_calib, _ = temporal_split(df)

    thresholds = {}
    for s in scalers:
        d = df_calib[df_calib["log_source"] == s].reset_index(drop=True)
        if len(d) == 0:
            continue
        Xs, Xt, _ = W.build_windows(d, feats_by[s], scalers[s], vocabs[s], s)
        scores = model.reconstruction_error(
            torch.from_numpy(Xs).to(DEVICE),
            torch.from_numpy(Xt).to(DEVICE), s)
        rate = CC.POT_TARGET_RATE_BY_SOURCE.get(s, C.POT_TARGET_RATE)
        thr, info = TH._pot_threshold(scores, target_rate=rate)
        thresholds[s] = {"threshold": float(thr), "info": info}

        old = float(old_thr[s]["threshold"]) if s in old_thr else float("nan")
        realized = float((scores > thr).mean())
        print(f"  {s:8s}: seuil {old:.4f} -> {thr:.4f}  "
              f"(cible={rate:.4f}, realise_calib={realized:.4%}, "
              f"{info['method']})")

    joblib.dump(thresholds, CC.THRESH_PATH)
    print(f"\n  -> {CC.THRESH_PATH} re-sauve. Lancer : python inference_cnn.py")
    print("=" * 60)


if __name__ == "__main__":
    main()