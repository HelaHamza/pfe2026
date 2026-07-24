"""
splitting.py
============
SOURCE UNIQUE DE VERITE pour le decoupage temporel par source.

Ce module est importe a la fois par training.py ET inference.py : il devient
donc IMPOSSIBLE de desynchroniser les frontieres pool/calib/test entre
l'entrainement et l'evaluation. Avant ce refactor, training.temporal_split et
inference._test_split recalculaient chacun leur decoupage avec la meme formule
dupliquee -> un changement de C.SPLIT_RATIOS d'un cote seulement aurait fait
diverger silencieusement le "test" des deux modules.

Dependances VOLONTAIREMENT legeres (pandas + config uniquement) : ainsi
inference.py peut importer le split SANS charger torch / le module training
au demarrage.
"""
from __future__ import annotations
import pandas as pd

import config_cnn as C


# ---------------------------------------------------------------------------
# Split temporel (anti-fuite) : train=passe, calib=present, test=futur
# ---------------------------------------------------------------------------
def temporal_split(df, ratios=C.SPLIT_RATIOS):
    """Split chronologique PAR SOURCE (passe -> present -> futur au sein de
    chaque source). Chaque source alimente pool / calib / test.

    Retourne le triplet (pool, calib, test) :
      * pool  = ratios[0]              premiers %  -> ENTRAINEMENT du modele
      * calib = ratios[1]             suivants %   -> CALIBRATION du seuil GPD-POT
      * test  = le reste (1 - i2)                  -> EVALUATION (futur non vu)

    Le tri est fait PAR SOURCE : chaque source (auth/syslog/auditd) a sa propre
    chronologie, donc son propre pool/calib/test, ce qui evite qu'une source
    tardive contamine le train d'une autre.
    """
    pools, calibs, tests = [], [], []
    for s in df["log_source"].unique():
        d = df[df["log_source"] == s].copy()
        # Tri chronologique strict (les timestamps non parsables -> NaT en fin).
        d["_ts"] = pd.to_datetime(d["@timestamp"], utc=True, errors="coerce")
        d = d.sort_values("_ts").drop(columns="_ts").reset_index(drop=True)
        n = len(d)
        i1 = int(n * ratios[0])                    # fin du pool
        i2 = int(n * (ratios[0] + ratios[1]))      # fin de la calib = debut du test
        pools.append(d.iloc[:i1])
        calibs.append(d.iloc[i1:i2])
        tests.append(d.iloc[i2:])
    cat = lambda xs: pd.concat(xs, ignore_index=True) if xs else df.iloc[:0].copy()
    return cat(pools), cat(calibs), cat(tests)