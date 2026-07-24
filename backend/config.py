"""
config.py
=========
Configuration unique du backend. Sectionnée par domaine.

RÈGLE : un SECRET n'a JAMAIS de valeur par défaut. S'il manque, on lève au
démarrage. Un défaut sur un mot de passe transforme une erreur de
configuration bruyante en connexion silencieuse avec de mauvais
identifiants — inacceptable dans un projet de sécurité.
"""
import os
import sys

from dotenv import load_dotenv

load_dotenv()


def _required(name: str, hint: str = "") -> str:
    value = os.getenv(name)
    if not value:
        raise EnvironmentError(
            f"{name} manquant. Ajoutez-le dans votre fichier .env." +
            (f"\n{hint}" if hint else ""))
    return value


def _path(env_name: str, default: str) -> str:
    return os.path.expanduser(os.getenv(env_name, default))


# ══════════════════════════════════════════════════════════════════════
#  SECRETS (obligatoires — aucune valeur par défaut)
# ══════════════════════════════════════════════════════════════════════
MONGO_URI = _required(
    "MONGO_URI",
    "MONGO_URI=mongodb+srv://<user>:<password>@<cluster>.mongodb.net/")
ES_PASS = _required(
    "ELASTIC_PWD",
    "ELASTIC_PWD=<mot de passe du compte elastic>")

# ══════════════════════════════════════════════════════════════════════
#  MONGODB
# ══════════════════════════════════════════════════════════════════════
MONGO_DB           = os.getenv("MONGO_DB", "pfe2026")
MONGO_COLL_CNN     = os.getenv("MONGO_COLL_CNN",     "cnn_alerts")
MONGO_COLL_SIGMA   = os.getenv("MONGO_COLL_SIGMA",   "sigma_alerts")
MONGO_COLL_REPORTS = os.getenv("MONGO_COLL_REPORTS", "reports")
MONGO_COLL_STATE   = os.getenv("MONGO_COLL_STATE",   "pipeline_state")

# Garde-fou stockage (Atlas free tier M0 = 512 Mo on-disk).
ATLAS_QUOTA_MB   = int(os.getenv("ATLAS_QUOTA_MB", "512"))
ATLAS_WARN_RATIO = float(os.getenv("ATLAS_WARN_RATIO", "0.90"))

# LEGACY — conservé le temps de vérifier qu'aucun module ne l'importe :
#     grep -rn "MONGO_COLL\b" --include="*.py" .
# S'il ne sort rien hors de ce fichier, supprime la ligne.
MONGO_COLL = os.getenv("MONGO_COLL", "reports")

# ══════════════════════════════════════════════════════════════════════
#  ELASTICSEARCH (lecture seule)
# ══════════════════════════════════════════════════════════════════════
ES_HOST = os.getenv("ES_HOST", "https://localhost:9200")
ES_USER = os.getenv("ES_USER", "elastic")
# Cluster de laboratoire à certificat auto-signé : la vérification TLS est
# désactivée PAR CONFIGURATION et non par un `verify=False` enfoui dans le
# code. À basculer à true en déploiement réel.
ES_VERIFY_CERTS = os.getenv("ES_VERIFY_CERTS", "false").lower() == "true"

# ══════════════════════════════════════════════════════════════════════
#  API / FRONTEND
# ══════════════════════════════════════════════════════════════════════
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")
CORS_ORIGINS = [o.strip() for o in
                os.getenv("CORS_ORIGINS", FRONTEND_URL).split(",") if o.strip()]
RESET_TOKEN_TTL_MINUTES = int(os.getenv("RESET_TOKEN_TTL_MINUTES", "60"))

# ══════════════════════════════════════════════════════════════════════
#  PIPELINE — frontière temporelle et chemins externes
# ══════════════════════════════════════════════════════════════════════
# Borne train/production : aucun log antérieur n'entre en inférence.
PROD_START = os.getenv("PROD_START", "2026-07-19T00:00:00+00:00")

# Délai maximal d'une étape externe (predict_cnn, triage_cnn). Sans lui, un
# blocage fige l'API sur running=True sans reset possible.
PIPELINE_STEP_TIMEOUT_S = int(os.getenv("PIPELINE_STEP_TIMEOUT_S", "3600"))

REPO_ROOT = _path("REPO_ROOT", "~/pfe-backend-2026")

INFERENCE_DIR    = _path("INFERENCE_DIR", f"{REPO_ROOT}/inference")
CNN_LLM_DIR      = _path("CNN_LLM_DIR",   f"{REPO_ROOT}/CNN_LLM")
CNN_TRIAGE_JSONL = os.path.join(CNN_LLM_DIR,   "cnn_triage.jsonl")
CNN_RUN_META     = os.path.join(INFERENCE_DIR, "cnn_run_meta.json")

SIGMA_DETECT_DIR = _path("SIGMA_DETECT_DIR", f"{REPO_ROOT}/sigma/detect")
SIGMA_RULES      = _path("SIGMA_RULES",      f"{REPO_ROOT}/sigma/rules")
SIGMA_INDEX      = os.getenv("SIGMA_INDEX", "filebeat-logs-*,auditbeat-*")
SIGMA_BIN        = os.getenv("SIGMA_BIN",
                             os.path.join(os.path.dirname(sys.executable), "sigma"))

LLM_SIGMA_DIR = _path("LLM_SIGMA_DIR", f"{REPO_ROOT}/llm_sigma")

# LEGACY — l'index ES `sigma-alerts` a été remplacé par Mongo.
#     grep -rn "ALERT_INDEX" --include="*.py" .
ALERT_INDEX = os.getenv("ALERT_INDEX", "sigma-alerts")