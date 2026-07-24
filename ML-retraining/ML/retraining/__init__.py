"""
retraining/
===========
Couche CT (Continuous Training) de Sentinel.

REGLE D'ARCHITECTURE NON NEGOCIABLE
-----------------------------------
    retraining/  IMPORTE  config_cnn, data_loader, cnn_features, ...
    config_cnn, data_loader, cnn_features  N'IMPORTENT JAMAIS  retraining/

La dependance est strictement unidirectionnelle. Consequence : si ce
repertoire est supprime, le pipeline de soutenance (train_eval_cnn.py,
predict_cnn.py) continue de fonctionner a l'identique. C'est ce qui rend
cet ajout sur en periode de soutenance.

Lancement : toujours depuis ML/ comme racine.
    cd ML && python -m retraining.retrain_cnn
"""
from __future__ import annotations

import os
import sys

# ML/ = parent de retraining/. On le pose sur sys.path pour que
# `import config_cnn` fonctionne quel que soit le cwd du timer systemd.
_ML_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ML_ROOT not in sys.path:
    sys.path.insert(0, _ML_ROOT)

ML_ROOT = _ML_ROOT

__all__ = ["ML_ROOT"]
