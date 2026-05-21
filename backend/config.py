"""
backend/config.py
==================
Configuration MongoDB Atlas.
Les credentials sont lus depuis le fichier .env à la racine du projet.

Fichier .env attendu :
    MONGO_URI=mongodb+srv://<user>:<password>@<cluster>.mongodb.net/?retryWrites=true&w=majority
    MONGO_DB=ids_soc
    MONGO_COLL=reports
"""

import os
from dotenv import load_dotenv

load_dotenv()

MONGO_URI  = os.getenv("MONGO_URI")
MONGO_DB   = os.getenv("MONGO_DB")
MONGO_COLL = os.getenv("MONGO_COLL", "reports")

if not MONGO_URI:
    raise EnvironmentError(
        "MONGO_URI manquant. Ajoutez-le dans votre fichier .env :\n"
        "MONGO_URI=mongodb+srv://<user>:<password>@<cluster>.mongodb.net/"
    )