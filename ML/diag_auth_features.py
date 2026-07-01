# diag_aggregation_compare.py
import numpy as np, pandas as pd, torch
import config as C, data_loader as DL, feature_engineering as FE
import preprocessing as PP, thresholding as TH
from inference import load_artifacts, _test_split

model, scalers, keep, feats, _, thresholds, novelty = load_artifacts()
df_feat = FE.build_features(DL.load_dataset(), novelty_state=None)
df_eval = _test_split(df_feat, C.SPLIT_RATIOS)

def score_with(Z_raw, mode, cap=None):
    Z = np.clip(Z_raw, 0, cap) if cap else Z_raw
    if mode == "max":
        return Z.max(axis=1)
    if mode == "top1":
        return Z.max(axis=1)
    k = min(3, Z.shape[1])
    return np.sort(Z, axis=1)[:, -k:].mean(axis=1)

for src in ["auth", "auditd"]:
    if src not in scalers:
        continue
    d = df_eval[df_eval["log_source"] == src].reset_index(drop=True)
    X = PP.transform(d, feats[src], scalers[src], keep[src])
    Z_raw = model.per_feature_zscore(torch.FloatTensor(X), src)
    thr = TH.get_threshold(thresholds, src)
    kept = [f for f, k in zip(feats[src], keep[src]) if k]

    print(f"\n=== {src} (seuil actuel={thr:.3f}, n={len(d)}) ===")
    for label, mode, cap in [
        ("topk3 brut (actuel)", "topk", None),
        ("topk3 + cap5",        "topk", 5.0),
        ("max brut",            "max",  None),
        ("max + cap5",          "max",  5.0),
    ]:
        s = score_with(Z_raw, mode, cap)
        n_alert = int((s > thr).sum())
        print(f"  {label:22s}: {n_alert:4d} alertes ({n_alert/len(d)*100:.2f}%)")

    # quelle feature domine le max, et à quelle fréquence
    top1 = np.array(kept)[Z_raw.argmax(axis=1)]
    print(f"  feature dominante (max) : "
          f"{pd.Series(top1).value_counts().head(5).to_dict()}")