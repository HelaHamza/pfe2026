"""
eval_generalization.py
======================
AXE 2 — Generalisation / surapprentissage, SANS reentrainement.

Recharge le modele GELE + le snapshot GELE, reconstruit le POOL par source
(meme decoupage que training.prepare_sources : cut = int(n*(1-VAL_RATIO))) et
mesure la perte Huber de RECONSTRUCTION sur pool-train vs pool-val EN MODE
EVAL (aucune corruption denoising, dropout off) -> ecart de generalisation
propre et comparable entre les deux jeux.

NB : ce n'est PAS la courbe d'apprentissage historique (elle exige un run).
C'est l'ecart FINAL train/val du modele tel qu'il est fige -> la grandeur qui
prouve reellement l'absence de surapprentissage.

ZERO RISQUE POUR LE FREEZE : aucun artifact modele reecrit, aucune
re-execution de groundtruth.py. Le scaler applique aux DEUX jeux est celui
fit sur le train seul -> aucune fuite.

Sortie : eval_generalization.json + generalization_gap.png
"""
from __future__ import annotations
import json
import numpy as np
import torch
import torch.nn.functional as F

import config as C
import data_loader as DL
import feature_engineering as FE
import preprocessing as PP
from splitting import temporal_split
import inference as INF          # reutilise load_artifacts (une seule verite)

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


@torch.no_grad()
def _huber_mean(model, X, src, batch=8192):
    """Perte Huber moyenne (meme delta que l'entrainement) en mode EVAL,
    calculee par batch puis moyennee EXACTEMENT (somme / effectif)."""
    model.eval()
    tot, n = 0.0, 0
    for i in range(0, len(X), batch):
        xb = torch.FloatTensor(X[i:i + batch]).to(DEVICE)
        xh = model(xb, src)                        # eval -> pas de corruption
        l = F.huber_loss(xh, xb, delta=C.HUBER_DELTA, reduction="sum")
        tot += float(l.item()); n += xb.numel()
    return tot / max(n, 1)


def main():
    print("=" * 60)
    print("  AXE 2 -- ecart de generalisation (modele gele, sans retrain)")
    print("=" * 60)

    model, scalers, keep, feats, _, _, _ = INF.load_artifacts()

    # Meme pipeline gele que l'evaluation : build_features(None) + split.
    df_raw = DL.load_dataset()
    df = FE.build_features(df_raw, novelty_state=None)
    df_pool, _, _ = temporal_split(df)             # on ne touche QU'AU pool

    results = {}
    for s in C.SOURCES:
        if s not in scalers:
            continue
        d = df_pool[df_pool["log_source"] == s].reset_index(drop=True)
        n = len(d)
        cut = int(n * (1 - C.VAL_RATIO))           # <-- identique a prepare_sources
        if cut < C.MIN_SOURCE_SAMPLES:
            print(f"  {s:8s}: pool insuffisant ({cut} train), ignore")
            continue
        d_tr, d_va = d.iloc[:cut], d.iloc[cut:]
        X_tr = PP.transform(d_tr, feats[s], scalers[s], keep[s])
        X_va = PP.transform(d_va, feats[s], scalers[s], keep[s])

        l_tr = _huber_mean(model, X_tr, s)
        l_va = _huber_mean(model, X_va, s)
        gap = (l_va - l_tr) / max(l_tr, 1e-12)      # ecart relatif
        results[s] = {
            "huber_train":     round(l_tr, 6),
            "huber_val":       round(l_va, 6),
            "gap_relatif_pct": round(100 * gap, 2),
            "n_train": int(len(d_tr)), "n_val": int(len(d_va)),
        }
        print(f"  {s:8s}: train={l_tr:.6f} | val={l_va:.6f} "
              f"| ecart={100 * gap:+.2f}%  ({len(d_tr):,}/{len(d_va):,})")

    with open("eval_generalization.json", "w") as f:
        json.dump(results, f, indent=2)

    # --- figure : barres train vs val par source -------------------------
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        srcs = list(results)
        x = np.arange(len(srcs)); w = 0.38
        tr = [results[s]["huber_train"] for s in srcs]
        va = [results[s]["huber_val"] for s in srcs]
        fig, ax = plt.subplots(figsize=(7, 4.2))
        ax.bar(x - w / 2, tr, w, label="train (pool)")
        ax.bar(x + w / 2, va, w, label="val (pool)")
        for i, s in enumerate(srcs):
            ax.text(i, max(tr[i], va[i]),
                    f"{results[s]['gap_relatif_pct']:+.1f}%",
                    ha="center", va="bottom", fontsize=9)
        ax.set_xticks(x); ax.set_xticklabels(srcs)
        ax.set_ylabel("perte Huber (reconstruction, mode eval)")
        ax.set_title("Ecart de generalisation train/val par source")
        ax.legend()
        fig.tight_layout(); fig.savefig("generalization_gap.png", dpi=140)
        print("  figure -> generalization_gap.png")
    except Exception as e:
        print(f"  [figure ignoree] {e}")

    print("=" * 60)
    return results


if __name__ == "__main__":
    main()