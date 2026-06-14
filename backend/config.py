"""
backend/config.py : décrit la configuration 
==================
Configuration MongoDB Atlas.
Les credentials sont lus depuis le fichier .env à la racine du projet.

Fichier .env attendu :
    MONGO_URI=mongodb+srv://<user>:<password>@<cluster>.mongodb.net/?retryWrites=true&w=majority
    MONGO_DB=ids_soc
    MONGO_COLL=reports
"""
"""
backend/config.py
==================
Source unique de configuration. Seul fichier qui lit le .env.
"""
import os
from dotenv import load_dotenv

load_dotenv()

MONGO_URI  = os.getenv("MONGO_URI")
MONGO_DB   = os.getenv("MONGO_DB", "pfe2026")     # ← défaut aligné sur ta vraie base
MONGO_COLL = os.getenv("MONGO_COLL", "reports")

if not MONGO_URI:
    raise EnvironmentError(
        "MONGO_URI manquant. Ajoutez-le dans votre fichier .env :\n"
        "MONGO_URI=mongodb+srv://<user>:<password>@<cluster>.mongodb.net/"
    )

FRONTEND_URL = "http://localhost:5173"   # base du lien envoyé par email
RESET_TOKEN_TTL_MINUTES = 60             # durée de validité du token