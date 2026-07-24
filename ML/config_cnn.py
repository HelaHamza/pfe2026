"""
config_cnn.py
=============
Configuration COMPLETE et AUTONOME de la branche CNN HYBRIDE.

C'est desormais l'UNIQUE source de verite du pipeline CNN. Aucun module CNN
(data_loader, cnn_features, cnn_windowing, splitting, thresholding,
autoencoder_cnn, train_eval_cnn, inference_cnn) n'importe l'ancienne config MLP
(config.py) ni aucun module MLP (preprocessing.py, feature_engineering.py).
Les deux branches (CNN / MLP) sont totalement independantes.

Architecture : auto-encodeur convolutif 1D par source, DEUX tetes :
  * tete SEQUENCE : embedding appris sur event_type -> le CNN extrait
                    sequence / co-occurrence / densite automatiquement.
  * tete SCALAIRE : rarete longue-portee + timing + flags.
"""
from __future__ import annotations

import os
from dotenv import load_dotenv
load_dotenv()
# Reproductibilite : a poser avant l'import de torch ailleurs.
os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
SEED = 42

# --- Elasticsearch ----------------------------------------------------------
ES_HOST  = os.getenv("ES_HOST", "https://localhost:9200")
ES_USER  = os.getenv("ES_USER", "elastic")
ES_PASS  = os.getenv("ELASTIC_PWD")
ES_INDEX = os.getenv("ES_INDEX", "filebeat-logs-*,auditbeat-*")
ES_TIME_GTE = os.getenv("ES_TIME_GTE", "2026-04-24T00:00:00Z")
ES_TIME_LTE = os.getenv("ES_TIME_LTE", "now")
MAX_DOCS    = int(os.getenv("MAX_DOCS", "400000"))

DATASET_CACHE = "dataset_snapshot.parquet"
USE_CACHE     = True

SOURCES = ["auth", "syslog", "auditd"]

# --- Token de sequence (equivalent "template", deja structure) --------------
TOKEN_FIELD = "event_type"       # sortie de cnn_features._add_event_type
PAD_ID, MASK_ID, UNK_ID = 0, 1, 2
FIRST_TOKEN_ID = 3               # les vrais tokens commencent a 3
EMBED_DIM = 16                   # dimension de l'embedding appris

# --- Canaux SCALAIRES par source (par evenement, non reconstructibles) ------
CNN_FEATURES = {
    "auth":   ["is_fail", "msg_length_log", "user_rarity", "geo_rarity",
               "inter_arrival_log" , "ip_is_external"],
    "syslog": ["msg_length_log", "proc_rarity", 
    #"log_severity",
               "inter_arrival_log"],
    "auditd": ["cmd_entropy", "cmd_length_log", "arg_count",
               "proc_rarity", "exe_path_rarity", "user_rarity",
               "syscall_rarity", "parent_child_rarity", "inter_arrival_log"],
}

# Canaux ATOMIQUES poses APRES build_features_shared (par add_atomic_channels).
# Ils NE DOIVENT PAS figurer dans la coercion de build_features_shared : sinon
# la colonne serait creee a 0.0 AVANT le calcul reel -> is_fail neutralise
# partout (bug silencieux, signal SSH brute-force perdu).
ATOMIC_CHANNELS = {"is_fail"}

# Features de base a garantir numeriques dans build_features_shared
# = tous les canaux CNN SAUF les canaux atomiques ajoutes plus tard.
KNOWN_FEATURES = set()
for _s in SOURCES:
    KNOWN_FEATURES |= set(CNN_FEATURES[_s])
KNOWN_FEATURES -= ATOMIC_CHANNELS

# Cle de fenetrage : jamais deux flux dans une meme fenetre.
WINDOW_KEY = {"auth": "ip", "syslog": "host", "auditd": "host"}

# --- Fenetrage --------------------------------------------------------------
WINDOW_SIZE   = 16     # W
WINDOW_STRIDE = 1      # 1 = un score PAR EVENEMENT -> GPD-POT + episodes reutilises

# --- Architecture conv ------------------------------------------------------
LATENT_DIM_BY_SOURCE = {"auth": 8, "syslog": 6, "auditd": 10}
CONV_CHANNELS = (32, 64)
POOL_LEN      = 4
KERNEL_SIZE   = 3
DROPOUT       = 0.10
DENOISE_MASK_FRAC = 0.15         # masquage denoising -> anti reconstruction-identite

# --- Pertes -----------------------------------------------------------------
HUBER_DELTA       = 0.5          # tete scalaire
TOKEN_LOSS_WEIGHT = 0.25         # lambda : poids de la cross-entropy (tete sequence)

# --- Entrainement -----------------------------------------------------------
BATCH_SIZE         = 256
EPOCHS_BY_SOURCE   = {"auth": 200, "syslog": 200, "auditd": 150}
PATIENCE_BY_SOURCE = {"auth": 30,  "syslog": 30,  "auditd": 20}
LR_BY_SOURCE       = {"auth": 5e-4, "syslog": 1e-3, "auditd": 1e-3}
WEIGHT_DECAY       = 1e-5
SPLIT_RATIOS = (0.60, 0.20, 0.20)   # pool / calib / test
VAL_RATIO    = 0.20
MIN_SOURCE_SAMPLES = 200

# --- Scoring (z par composante -> LSE) --------------------------------------
RESIDUAL_SCALE_FLOOR = 0.1
FEATURE_Z_CAP        = 50.0
#SCORE_LSE_TAU        = 2.0
SCORE_LSE_TAU_BY_SOURCE = {"auth": 1.0, "syslog": 2.0, "auditd": 3.0}
SCALE_CLIP           = 15.0      # clip apres StandardScaler (dans cnn_windowing)

# --- Seuil GPD-POT (NON SUPERVISE) ------------------------------------------
POT_TARGET_RATE = 0.005
POT_INIT_Q      = 0.98
POT_MIN_EXCESS  = 30
POT_XI_MAX = 0.8     # xi>=1 => esperance infinie -> ajustement rejete.
POT_XI_MIN = -0.5    # xi<-0.5 => hors regularite du MLE GPD (Smith 1985) -> rejete.
POT_TARGET_RATE_BY_SOURCE = {"auth": 0.002, "syslog": 0.001, "auditd": 0.0025}

# --- Roles des sources / episodes -------------------------------------------
SOURCE_ROLE = {"auth": "alert", "auditd": "alert", "syslog": "alert"}
EPISODE_GAP_SECONDS = 300        # meme (source,hote) < gap s = 1 seul episode

# --- Collecte : exclusion du bruit conteneur (IDS HOTE) ---------------------
EXCLUDE_CONTAINER_EVENTS = True
CONTAINER_RUNTIME_PROCS = {
    "runc", "containerd", "containerd-shim", "containerd-shim-runc-v2",
    "dockerd", "docker", "docker-proxy", "ctr", "docker-init",   # <-- ajout

}
EXCLUDE_NUMERIC_PROC = True       # process_name purement numerique = artefact parsing.

# --- Fenetre temporelle d'extraction, PAR SOURCE ----------------------------
DATA_START_BY_SOURCE = {
    "auditd": "2026-06-07T21:30:00Z",   # collecte PROPRE post-bascule demon maitre
    "syslog": "2026-06-06T00:00:00Z",
    "auth":   None,
}
DATA_END_BY_SOURCE = {"auditd": None, "syslog": None, "auth": None}
# Plafond PAR SOURCE : empeche syslog d'epuiser le budget avant auditd.
MAX_DOCS_BY_SOURCE = {"syslog": 200000, "auth": 50000, "auditd": 900000}

# --- Artifacts SEPARES (n'ecrasent AUCUN artifact MLP) ----------------------
_HERE = os.path.dirname(os.path.abspath(__file__))

ARTIFACT_DIR = os.getenv("SENTINEL_ARTIFACT_DIR", _HERE)   # <-- la clé


MODEL_PATH      = os.path.join(_HERE, "model_cnn.pt")
BUNDLE_PATH     = os.path.join(_HERE, "cnn_bundle.pkl")
THRESH_PATH     = os.path.join(_HERE, "cnn_thresholds.pkl")
NOVELTY_STATE_PATH = os.path.join(_HERE, "cnn_novelty_state.pkl")

SEED_SECONDS = 6 * 3600   # cf. note ci-dessous pour le calibrer

SCORED_TEST_CSV = "cnn_scored_test.csv"

# --- Coherence : debut de fenetre jamais posterieur a la borne d'extraction --
import pandas as _pd
_lte = _pd.Timestamp.utcnow() if ES_TIME_LTE == "now" else _pd.Timestamp(ES_TIME_LTE)
for _s, _start in DATA_START_BY_SOURCE.items():
    if _start and _pd.Timestamp(_start) > _lte:
        raise ValueError(
            f"Source '{_s}' : debut de fenetre ({_start}) posterieur a "
            f"ES_TIME_LTE ({ES_TIME_LTE}). Aucune donnee extractible.")