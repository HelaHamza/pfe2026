"""
health_cnn.py
Axe NON SUPERVISE de l'evaluation (CRISP-DM : Assess Model / Review Process).

Mesure la SANTE intrinseque du modele CNN, SANS verite terrain :
  1) Qualite de l'ajustement GPD-POT par source : xi dans la bande de regularite
     [POT_XI_MIN, POT_XI_MAX], nombre d'exces >= POT_MIN_EXCESS, recours ou non
     au fallback empirique (queue non modelisable).
  2) QQ-plot des exceedances vs GPD ajustee + K-S indicatif (adequation de queue).
  3) Taux de flag empirique sur le TEST BENIN vs cible POT_TARGET_RATE_BY_SOURCE
     = proxy NON SUPERVISE du taux de fausses alertes / specificite.
     (le seuil est calibre sur CALIB ; le mesurer sur TEST teste sa generalisation.)
  4) Forme de la distribution des scores (mediane, p99, skew, kurtosis).

Aucune injection requise : tout est calcule sur le split propre (calib + test).
Le scoring reutilise EXACTEMENT model.reconstruction_error (meme voie que la
calibration), donc les exceedances recomputees sur CALIB sont celles auxquelles
la GPD a ete ajustee -> QQ-plot fidele.

Sorties : health_summary.json | health_gpd_fit.csv | health_qqplots.png
"""
from __future__ import annotations
import json

import numpy as np
import pandas as pd
import torch
from scipy.stats import genpareto, kstest, skew, kurtosis
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import config_cnn as CC
import cnn_features as FE
import cnn_windowing as W
import data_loader as DL
from splitting import temporal_split
from Test_cnn import load_artifacts_cnn
from train_eval_cnn import DEVICE


def _scores(model, d_src, feats, scaler, vocab, src):
    """Scores d'anomalie (reconstruction_error) pour le sous-df d'une source."""
    if len(d_src) == 0:
        return np.array([], dtype=float)
    Xs, Xt, _ = W.build_windows(d_src, feats, scaler, vocab, src)
    return np.asarray(
        model.reconstruction_error(
            torch.from_numpy(Xs).to(DEVICE),
            torch.from_numpy(Xt).to(DEVICE), src),
        dtype=float)


def main():
    model, scalers, vocabs, feats_by, thresholds = load_artifacts_cnn()

    df = FE.build_features(DL.load_dataset())
    _, df_calib, df_test = temporal_split(df)          # (pool, calib, test)
    print(f"snapshot={len(df):,}  calib={len(df_calib):,}  test={len(df_test):,}")

    sources = [s for s in CC.SOURCES if s in scalers]
    fig, axes = plt.subplots(1, len(sources), figsize=(5 * len(sources), 4.5),
                             squeeze=False)
    axes = axes[0]

    table, summary = [], {}
    for ax, s in zip(axes, sources):
        info = thresholds[s].get("info", {})
        thr = float(thresholds[s]["threshold"])

        d_cal = df_calib[df_calib["log_source"] == s].reset_index(drop=True)
        d_tst = df_test[df_test["log_source"] == s].reset_index(drop=True)
        sc_cal = _scores(model, d_cal, feats_by[s], scalers[s], vocabs[s], s)
        sc_tst = _scores(model, d_tst, feats_by[s], scalers[s], vocabs[s], s)

        # --- 3) taux de flag empirique sur TEST benin vs cible --------------
        target = CC.POT_TARGET_RATE_BY_SOURCE.get(s, CC.POT_TARGET_RATE)
        realized = float((sc_tst > thr).mean()) if sc_tst.size else float("nan")

        # --- 4) forme de la distribution (sur TEST) ------------------------
        shape = {
            "median": float(np.median(sc_tst)) if sc_tst.size else float("nan"),
            "p99": float(np.quantile(sc_tst, 0.99)) if sc_tst.size else float("nan"),
            "skew": float(skew(sc_tst)) if sc_tst.size else float("nan"),
            "kurtosis": float(kurtosis(sc_tst)) if sc_tst.size else float("nan"),
        }

        # --- 1+2) adequation GPD : QQ-plot + K-S sur les exceedances CALIB --
        method = info.get("method", "?")
        ks_stat = ks_p = float("nan")
        if method == "gpd_pot" and sc_cal.size:
            u = float(info["u"]); xi = float(info["xi"]); scale = float(info["scale"])
            exc = np.sort(sc_cal[sc_cal > u] - u)
            if exc.size >= 2:
                n = exc.size
                theo = genpareto.ppf((np.arange(1, n + 1) - 0.5) / n,
                                     c=xi, loc=0.0, scale=scale)
                ax.scatter(theo, exc, s=8, alpha=0.6)
                lim = float(max(np.nanmax(theo), exc.max()))
                ax.plot([0, lim], [0, lim], "r--", lw=1)
                ax.set_title(f"{s}  (xi={xi:.3f}, n_exc={n})")
                ax.set_xlabel("quantiles GPD theoriques")
                ax.set_ylabel("exceedances observees")
                # K-S INDICATIF : parametres estimes -> anti-conservateur
                # (une correction de Lilliefors serait plus stricte). A lire
                # comme un signal d'adequation, pas comme un test formel.
                ks_stat, ks_p = kstest(exc, "genpareto", args=(xi, 0.0, scale))
        else:
            ax.text(0.5, 0.5, f"{s}\nfallback empirique\n(pas d'ajustement GPD a valider)",
                    ha="center", va="center", transform=ax.transAxes)
            ax.set_title(f"{s}  ({method})")

        row = {
            "source": s,
            "method": method,
            "xi": info.get("xi"),
            "n_excess": info.get("n_excess"),
            "floored": info.get("floored"),               # seuil = max(gpd, empirique)
            "finite_endpoint": info.get("finite_endpoint"),  # xi<0 => queue bornee
            "threshold": thr,
            "target_rate": target,
            "realized_rate_test": realized,
            "ratio_realized_target": (realized / target
                                      if target and realized == realized else None),
            "ks_stat": ks_stat, "ks_pvalue": ks_p,
            **shape,
        }
        table.append(row)
        summary[s] = row
        print(f"  {s:8s} method={method:16s} xi={info.get('xi')} "
              f"realized={realized:.4%} (cible {target:.3%}) "
              f"KS_p={ks_p:.3f} floored={info.get('floored')}")

    fig.suptitle("Adequation GPD-POT : QQ-plot des exceedances par source", y=1.02)
    fig.tight_layout()
    fig.savefig("health_qqplots.png", dpi=130, bbox_inches="tight")
    pd.DataFrame(table).to_csv("health_gpd_fit.csv", index=False)
    with open("health_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, default=str)
    print("\n  -> health_summary.json | health_gpd_fit.csv | health_qqplots.png")


if __name__ == "__main__":
    main()