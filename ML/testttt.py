import json, numpy as np, pandas as pd, torch
from sklearn.metrics import roc_auc_score, average_precision_score
import config as C, data_loader as DL, feature_engineering as FE
import preprocessing as PP
from training import temporal_split
from inference import load_artifacts, DEVICE

TOL = pd.Timedelta("2min")

def load_gt(path="groundtruth.jsonl"):
    rows = []
    for l in open(path):
        l = l.strip()
        if l:
            try: rows.append(json.loads(l))
            except json.JSONDecodeError: pass
    gt = pd.DataFrame(rows)
    for c in ("start", "end"):
        gt[c] = pd.to_datetime(gt[c], utc=True, errors="coerce")
    return gt.dropna(subset=["start", "end"])

def label_events(d, gt, src):
    """1 si l'evenement tombe dans une fenetre d'injection de sa source (+/-2min)."""
    ts = pd.to_datetime(d["@timestamp"], utc=True, errors="coerce")
    y = np.zeros(len(d), dtype=int)
    for _, w in gt[gt["source"] == src].iterrows():
        y |= ((ts >= w["start"] - TOL) & (ts <= w["end"] + TOL)).to_numpy().astype(int)
    return y

model, scalers, keep, feats, _, _, _ = load_artifacts()
df = FE.build_features(DL.load_dataset(), novelty_state=None)
pool, calib, test = temporal_split(df)
gt = load_gt()

for s in scalers:
    xs = torch.FloatTensor(PP.transform(pool[pool.log_source == s],
                                        feats[s], scalers[s], keep[s])).to(DEVICE)
    model.fit_error_norm(xs, s); model.fit_error_ecdf(xs, s)

print(f"{'source':8s} {'mode':7s} {'AUC-ROC':>8s} {'AUPRC':>8s} {'n_pos':>6s} {'n':>7s}")
for s in scalers:
    d = test[test.log_source == s].reset_index(drop=True)
    y = label_events(d, gt, s)
    if y.sum() == 0 or y.sum() == len(y):
        print(f"{s:8s}  (pas d'evenement d'attaque dans le test -> AUC indefinie)")
        continue
    X = torch.FloatTensor(PP.transform(d, feats[s], scalers[s], keep[s])).to(DEVICE)
    for mode in ("zscore", "rank"):
        C.SCORE_MODE = mode
        score = model.reconstruction_error(X, s)          # AUCUN seuil ici
        auc = roc_auc_score(y, score)
        ap  = average_precision_score(y, score)
        print(f"{s:8s} {mode:7s} {auc:8.4f} {ap:8.4f} {int(y.sum()):6d} {len(y):7d}")