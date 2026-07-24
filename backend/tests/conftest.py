"""
tests/conftest.py
=================
Les tests s'exécutent SANS base et SANS réseau : `core/database.py` crée son
client paresseusement, et le repository accepte une base injectée.

Les variables d'environnement sont posées AVANT tout import de `config`,
qui lève si les secrets manquent.
"""
import os
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

os.environ.setdefault("MONGO_URI", "mongodb://localhost:27017/test")
os.environ.setdefault("ELASTIC_PWD", "test")