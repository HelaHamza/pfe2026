"""
diag_aggregation.py
===================
A/B des fonctions d'agregation du score, a Z (z|residu| par feature) FIGE.

Ne reentraine RIEN. Rejoue seulement l'etape _aggregate sur la meme matrice Z,
sur CALIB (pour recalibrer le seuil POT par agregation -> comparaison a armes
egales) et sur TEST (pour mesurer). But : trancher LSE vs top-k vs max pour CE
systeme, en separant :
  - recall_rt_%  : recall des injections red-team (au seuil recalibre),
  - alertes      : volume total d'alertes (proxy charge FP),
  - FP_nouveaute : alertes dont la feature #1 est une pure nouveaute ET non
                   red-team -> les FP structurels.

Sanity check : la ligne 'lse_tau2' doit reproduire ~ la production
(auth thr~3.63 / syslog~10.39 / auditd~5.73, alertes ~348/72/640).

Lancer :  python diag_aggregation.py
"""
import numpy as np
import pandas as pd
import torch

import config as C
import data_loader as DL
import feature_engineering as FE
import preprocessing as PP
import thresholding as TH
from splitting import temporal_split
from inference import load_artifacts

DEV = torch.device("cpu")

# Features de PURE nouveaute : rarity=1.0 des le 1er item vu -> saturent le cap.
NOVELTY = {"proc_rarity", "exe_path_rarity", "parent_child_rarity",
           "syscall_rarity", "et_bigram_rarity", "geo_rarity", "user_rarity"}


# --- agregations : Z (N,F) -> score (N,) -------------------------------------
def agg_max(Z):
    return Z.max(1)


def agg_topk(Z, k):
    k = min(k, Z.shape[1])
    return np.sort(Z, 1)[:, -k:].mean(1)


def agg_lse(Z, tau):
    m = Z.max(1, keepdims=True)
    return (m + tau * np.log(np.exp((Z - m) / tau).mean(1, keepdims=True))).ravel()


AGGS = {
    "max":      agg_max,
    "topk2":    lambda Z: agg_topk(Z, 2),
    "topk3":    lambda Z: agg_topk(Z, 3),
    "lse_tau1": lambda Z: agg_lse(Z, 1.0),
    "lse_tau2": lambda Z: agg_lse(Z, 2.0),   # <- production actuelle
    "lse_tau4": lambda Z: agg_lse(Z, 4.0),
    "lse_tau8": lambda Z: agg_lse(Z, 8.0),
}


def redteam_mask(d):
    """Signature GROSSIERE des 4 scenarios injectes. Sur-detecte (inclut les
    useradd/echo/base64 benins). A REMPLACER par ton groundtruth.jsonl / la
    tolerance +/-2 min pour un chiffre propre. Suffit pour le classement
    RELATIF des agregations."""
    u  = d["user_name"].fillna("").astype(str)
    ip = d["source_ip"].fillna("").astype(str)
    p  = d["process_name"].fillna("").astype(str)
    bf  = ip.eq("127.0.0.1") & p.eq("sshd") & u.str.startswith("invaliduser")
    usr = u.eq("testintrus") | p.isin(["useradd", "userdel"])
    b64 = p.isin(["base64", "echo"])
    return (bf | usr | b64).to_numpy()


def main():
    model, scalers, keep, feats, _, _, _ = load_artifacts()
    df = FE.build_features(DL.load_dataset(), novelty_state=None)
    _, df_cal, df_te = temporal_split(df)

    rows = []
    for s in C.SOURCES:
        if s not in scalers:
            continue
        dc = df_cal[df_cal.log_source == s].reset_index(drop=True)
        dt = df_te[df_te.log_source == s].reset_index(drop=True)
        if len(dc) == 0 or len(dt) == 0:
            continue

        Zc = model.per_feature_zscore(torch.FloatTensor(
            PP.transform(dc, feats[s], scalers[s], keep[s])).to(DEV), s)
        Zt = model.per_feature_zscore(torch.FloatTensor(
            PP.transform(dt, feats[s], scalers[s], keep[s])).to(DEV), s)

        feats_kept = np.array([f for f, k in zip(feats[s], keep[s]) if k])
        dom = feats_kept[Zt.argmax(1)]           # feature #1 par ligne (test)
        nov = np.isin(dom, list(NOVELTY))
        rt  = redteam_mask(dt)
        rate = C.POT_TARGET_RATE_BY_SOURCE.get(s, C.POT_TARGET_RATE)

        for name, fn in AGGS.items():
            sc, st = fn(Zc), fn(Zt)
            thr, _ = TH._pot_threshold(sc, target_rate=rate)   # recalibre par agg
            fired = st > thr
            rows.append({
                "source": s, "agg": name, "thr": round(float(thr), 3),
                "alertes": int(fired.sum()),
                "taux_%": round(100 * fired.mean(), 3),
                "recall_rt_%": (round(100 * fired[rt].mean(), 1)
                                if rt.any() else None),
                "n_rt": int(rt.sum()),
                "FP_nouveaute": int((fired & nov & ~rt).sum()),
            })

    out = pd.DataFrame(rows)
    pd.set_option("display.width", 160)
    print(out.to_string(index=False))
    out.to_csv("diag_aggregation.csv", index=False)
    print("\n-> diag_aggregation.csv")


if __name__ == "__main__":
    main()