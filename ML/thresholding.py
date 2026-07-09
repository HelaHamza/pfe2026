"""
thresholding.py
===============
Calibration du seuil d'anomalie — ENTIEREMENT NON SUPERVISEE (aucun label).

Methode : GPD-POT (Peaks-Over-Threshold).
  1. seuil de depart u = quantile(POT_INIT_Q) des scores (assez HAUT pour
     etre dans le regime de queue : sinon l'ajustement GPD diverge et xi
     explose vers des valeurs non physiques).
  2. ajustement d'une Generalized Pareto Distribution sur les exces (X - u).
  3. extrapolation au niveau correspondant au taux d'exceedance cible.

GARDE-FOUS :
  * REJET de l'ajustement si xi HORS de [POT_XI_MIN, POT_XI_MAX], ou si le
    resultat n'est pas fini -> repli sur le quantile empirique.
      - xi > POT_XI_MAX (0.8)  : queue trop lourde (xi>=1 => esperance infinie).
      - xi < POT_XI_MIN (-0.5) : hors regime de regularite du MLE de la GPD
        (Smith 1985) -> estimateur non fiable. Un xi tres negatif = support
        BORNE artificiel (endpoint u-scale/xi colle a u), typiquement du a des
        exces trop peu nombreux / trop groupes -> ne generalise pas.
        Cas observe : auth xi=-2.45 pretendait "score <= ~3.01", dementi par le
        test (p99=19) -> desormais rejete, repli empirique transparent.
  * PLANCHER : le seuil final ne descend JAMAIS sous le quantile empirique
    (1 - target_rate). La GPD ne peut que rendre le seuil plus conservateur,
    jamais moins (empeche un seuil sous le p99 comme pour auditd).

IMPORTANT : on calibre sur la CALIBRATION BRUTE (non nettoyee), qui reflete la
vraie variabilite du normal. Calibrer sur des donnees nettoyees (queue retiree)
sous-estimerait le niveau d'alerte normal -> seuil trop bas -> sur-detection.

NB : `scores` = sortie de model.reconstruction_error = top-k moyen des z
|residu| standardises par feature. Ce n'est PAS une MSE (ancien nom trompeur).
"""
from __future__ import annotations
import math
import numpy as np
import torch
from scipy.stats import genpareto

import config as C
import preprocessing as PP


def _pot_threshold(scores, target_rate=C.POT_TARGET_RATE,
                   init_q=C.POT_INIT_Q, min_excess=C.POT_MIN_EXCESS,
                   xi_max=C.POT_XI_MAX, xi_min=C.POT_XI_MIN):
    """Seuil POT/GPD sur un vecteur de SCORES d'anomalie 1-D, avec garde-fous.

    `scores` = z |residu| agrege (top-k), PAS une MSE brute.
    """
    scores = np.asarray(scores, dtype=float)
    n = len(scores)
    if n == 0:
        return float("inf"), {"method": "empty"}

    # Plancher empirique : niveau correspondant directement a la cible.
    emp = float(np.quantile(scores, 1.0 - target_rate))

    u = float(np.quantile(scores, init_q))
    exc = scores[scores > u] - u
    nu = len(exc)
    if nu < min_excess:
        return emp, {"method": "quantile_fallback", "reason": "few_excess",
                     "u": u, "n_excess": int(nu), "emp": emp}
    try:
        c, _, scale = genpareto.fit(exc, floc=0.0)   # c = xi

        # --- Garde-fou BILATERAL sur xi -----------------------------------
        if not np.isfinite(c) or not (xi_min <= c <= xi_max):
            reason = ("xi_too_high" if (np.isfinite(c) and c > xi_max)
                      else "xi_too_low" if np.isfinite(c)
                      else "xi_non_finite")
            return emp, {"method": "quantile_fallback", "reason": reason,
                         "u": u, "xi": float(c), "n_excess": int(nu),
                         "emp": emp}

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
                     "finite_endpoint": bool(c < 0),   # xi<0 => queue bornee
                     "floored": bool(thr > level)}
    except Exception as e:
        return emp, {"method": "quantile_fallback", "reason": str(e),
                     "u": u, "n_excess": int(nu), "emp": emp}


def compute_thresholds_from_df(model, df_calib, feats_by_src, scalers,
                               keep_by_src, device):
    """Calibre le seuil par source sur la CALIBRATION BRUTE (df_calib).
    Le scaler ayant ete fit sur le train, il n'y a aucune fuite : on se
    contente d'appliquer la transformation puis POT sur le score."""
    thresholds = {}
    n_floored = 0
    n_fallback = 0
    print("  Seuil GPD-POT par source (sur calibration BRUTE) :")
    for s in C.SOURCES:
        if s not in scalers:
            continue
        d = df_calib[df_calib["log_source"] == s].reset_index(drop=True)
        if len(d) == 0:
            continue
        X = PP.transform(d, feats_by_src[s], scalers[s], keep_by_src[s])
        scores = model.reconstruction_error(torch.FloatTensor(X).to(device), s)
        rate = C.POT_TARGET_RATE_BY_SOURCE.get(s, C.POT_TARGET_RATE)
        thr, info = _pot_threshold(scores, target_rate=rate)
        thresholds[s] = {"threshold": float(thr), "info": info}
        if info["method"] == "gpd_pot":
            flags = []
            if info.get("floored"):
                flags.append("plancher")
                n_floored += 1
            if info.get("finite_endpoint"):
                flags.append("xi<0")
            extra = (f"gpd xi={info['xi']:.3f} n_exc={info['n_excess']}"
                     + (f" [{','.join(flags)}]" if flags else ""))
        else:
            extra = f"{info['method']} ({info.get('reason', '')})"
            n_fallback += 1
        print(f"    {s:8s}: thr={thr:.6f}  ({extra}) | n_calib={len(d):,}")

    n_gpd = sum(1 for t in thresholds.values()
                if t["info"].get("method") == "gpd_pot")
    if n_gpd and (n_floored + n_fallback) >= n_gpd:
        print("  [!] POT rarement determinant (plancher/fallback dominant) : "
              "envisager d'abaisser POT_INIT_Q ou d'assumer le quantile "
              "empirique.")
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
    rates = {}
    for s in C.SOURCES:
        if s not in scalers:
            continue
        d = df[df["log_source"] == s].reset_index(drop=True)
        if len(d) == 0:
            continue
        X = PP.transform(d, feats_by_src[s], scalers[s], keep_by_src[s])
        scores = model.reconstruction_error(torch.FloatTensor(X).to(device), s)
        thr = get_threshold(thresholds, s)
        rates[s] = float((scores > thr).mean())
    return rates