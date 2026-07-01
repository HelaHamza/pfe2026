"""
thresholding.py
===============
Calibration du seuil d'anomalie — ENTIEREMENT NON SUPERVISEE (aucun label).

Methode : GPD-POT (Peaks-Over-Threshold).
  1. seuil de depart u = quantile(POT_INIT_Q) des erreurs (assez HAUT pour
     etre dans le regime de queue : sinon l'ajustement GPD diverge et xi
     explose vers des valeurs non physiques).
  2. ajustement d'une Generalized Pareto Distribution sur les exces (X - u).
  3. extrapolation au niveau correspondant au taux d'exceedance cible.

GARDE-FOUS (corrigent les xi=2.7 / 4.5 observes) :
  * REJET de l'ajustement si xi > POT_XI_MAX (queue non physique) ou si le
    resultat n'est pas fini -> repli sur le quantile empirique.
  * PLANCHER : le seuil final ne descend JAMAIS sous le quantile empirique
    (1 - target_rate). La GPD ne peut que rendre le seuil plus conservateur,
    jamais moins (empeche un seuil sous le p99 comme pour auditd).

IMPORTANT : on calibre sur la CALIBRATION BRUTE (non nettoyee), qui reflete la
vraie variabilite du normal. Calibrer sur des donnees nettoyees (queue retiree)
sous-estimerait le niveau d'alerte normal -> seuil trop bas -> sur-detection.
"""
from __future__ import annotations
import math
import numpy as np
import torch
from scipy.stats import genpareto

import config as C
import preprocessing as PP


def _pot_threshold(mse, target_rate=C.POT_TARGET_RATE,
                   init_q=C.POT_INIT_Q, min_excess=C.POT_MIN_EXCESS,
                   xi_max=C.POT_XI_MAX):
    """Seuil POT/GPD sur un vecteur d'erreurs 1-D, avec garde-fous."""
    mse = np.asarray(mse, dtype=float)
    n = len(mse)
    if n == 0:
        return float("inf"), {"method": "empty"}

    # Plancher empirique : niveau correspondant directement a la cible.
    emp = float(np.quantile(mse, 1.0 - target_rate))

    u = float(np.quantile(mse, init_q))
    exc = mse[mse > u] - u
    nu = len(exc)
    if nu < min_excess:
        return emp, {"method": "quantile_fallback", "reason": "few_excess",
                     "u": u, "n_excess": int(nu), "emp": emp}
    try:
        c, _, scale = genpareto.fit(exc, floc=0.0)   # c = xi
        if not np.isfinite(c) or c > xi_max:
            return emp, {"method": "quantile_fallback", "reason": "xi_rejected",
                         "u": u, "xi": float(c), "n_excess": int(nu), "emp": emp}
        ratio = target_rate * n / nu
        if abs(c) < 1e-6:
            level = u - scale * math.log(ratio)
        else:
            level = u + (scale / c) * (ratio ** (-c) - 1.0)
        if not np.isfinite(level):
            return emp, {"method": "quantile_fallback", "reason": "non_finite",
                         "u": u, "xi": float(c), "n_excess": int(nu), "emp": emp}
        # PLANCHER : jamais sous l'empirique.
        thr = float(max(level, emp))
        return thr, {"method": "gpd_pot", "u": u, "xi": float(c),
                     "scale": float(scale), "n_excess": int(nu),
                     "gpd_level": float(level), "emp": emp,
                     "floored": bool(thr > level)}
    except Exception as e:
        return emp, {"method": "quantile_fallback", "reason": str(e),
                     "u": u, "n_excess": int(nu), "emp": emp}


def compute_thresholds_from_df(model, df_calib, feats_by_src, scalers,
                               keep_by_src, device):
    """Calibre le seuil par source sur la CALIBRATION BRUTE (df_calib).
    Le scaler ayant ete fit sur le train, il n'y a aucune fuite : on se
    contente d'appliquer la transformation puis POT sur l'erreur."""
    thresholds = {}
    print("  Seuil GPD-POT par source (sur calibration BRUTE) :")
    for s in C.SOURCES:
        if s not in scalers:
            continue
        d = df_calib[df_calib["log_source"] == s].reset_index(drop=True)
        if len(d) == 0:
            continue
        X = PP.transform(d, feats_by_src[s], scalers[s], keep_by_src[s])
        mse = model.reconstruction_error(torch.FloatTensor(X).to(device), s)
        rate = C.POT_TARGET_RATE_BY_SOURCE.get(s, C.POT_TARGET_RATE)
        thr, info = _pot_threshold(mse, target_rate=rate)
        thresholds[s] = {"threshold": float(thr), "info": info}
        if info["method"] == "gpd_pot":
            extra = (f"gpd xi={info['xi']:.3f} n_exc={info['n_excess']}"
                     + (" [plancher]" if info.get("floored") else ""))
        else:
            extra = f"{info['method']} ({info.get('reason', '')})"
        print(f"    {s:8s}: thr={thr:.6f}  ({extra}) | n_calib={len(d):,}")
    return thresholds


def get_threshold(thresholds, src):
    t = thresholds.get(src)
    if t is None:
        return float("inf")
    return float(t["threshold"]) if isinstance(t, dict) else float(t)




def realized_alert_rate(model, df, feats_by_src, scalers, keep_by_src,
                        thresholds, device):
    """QA : taux d'alerte REELLEMENT realise par source sur un df donne.
    Sert a verifier que le seuil tient sa cible (calib) et a detecter la
    derive temporelle ou les attaques (test >> calib)."""
    import torch
    rates = {}
    for s in C.SOURCES:
        if s not in scalers:
            continue
        d = df[df["log_source"] == s].reset_index(drop=True)
        if len(d) == 0:
            continue
        X = PP.transform(d, feats_by_src[s], scalers[s], keep_by_src[s])
        mse = model.reconstruction_error(torch.FloatTensor(X).to(device), s)
        thr = get_threshold(thresholds, s)
        rates[s] = float((mse > thr).mean())
    return rates