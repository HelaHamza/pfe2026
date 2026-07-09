"""
config.py
=========
Constantes PARTAGEES par tous les modules. Centraliser ici evite la
desynchronisation des listes de features entre modules.

Toutes les features sont recalculees en Python depuis les champs ECS BRUTS :
le pipeline est independant de la version de Logstash deployee.
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

# --- Sources ----------------------------------------------------------------
SOURCES = ["auth", "syslog", "auditd"]

# --- Features par source ----------------------------------------------------
# UNIQUEMENT des grandeurs numeriques CONTINUES a distribution statistique.
# Les nouveautes sont exprimees en RARETE continue (1/(1+vues)) et NON en
# indicatrice binaire is_new : une binaire a un taux de base qui derive avec la
# distance au train (vocabulaire qui s'etend) -> instabilite du seuil, comme les
# features temporelles retirees. Les signatures binaires restent au layer Sigma.
FEATURES = {
    "auth": [
        "msg_length_log",
        "user_rarity", "geo_rarity",                     # nouveaute continue
        "auth_fail_count_5m", "auth_fail_ratio",         # fenetre echec
        "auth_fail_then_success",                        # brute-force reussi
        "event_count_5m_ip", "event_count_5m_dev",       # volume + deviation
        "et_bigram_rarity",                              # transition rare
        "distinct_users_5m_ip",                          # spraying (1 IP -> N users)
        "distinct_ips_5m_user",                          # stuffing (1 user -> N IP)
        "inter_arrival_log",                             # rafale
    ],
    "syslog": [
        "msg_length_log",
        "proc_rarity", 
        "log_severity",                   # rarete process + severite
        "event_count_1m_ip", "event_count_5m_ip", "event_count_5m_dev",
        "et_bigram_rarity",
        "inter_arrival_log",
    ],
    "auditd": [
        "cmd_entropy", "cmd_length_log", "arg_count",
        "proc_rarity", "exe_path_rarity", "user_rarity",
        "syscall_rarity",
        "event_count_5m_ip", "event_count_5m_dev",
        "et_bigram_rarity", "parent_child_rarity",
        "inter_arrival_log",
        
    ],
}

INPUT_DIMS    = {s: len(FEATURES[s]) for s in SOURCES}
MAX_INPUT_DIM = max(INPUT_DIMS.values())

# Garde-fou anti-concatenation implicite de chaines (["a" "b"] -> "ab").
KNOWN_FEATURES = set()
for _s in SOURCES:
    KNOWN_FEATURES |= set(FEATURES[_s])

# Comptages -> log1p (ecrase les longues trainees lourdes).
COUNT_FEATURES = {
    "auth_fail_count_5m", "auth_fail_then_success",
    "event_count_1m_ip", "event_count_5m_ip",
    "arg_count",
    "distinct_users_5m_ip", "distinct_ips_5m_user",
}

# Rare-event / deviation : porteuses du signal d'attaque meme si quasi-constantes
# sur le train -> JAMAIS retirees par le filtre de variance.
WHITELIST_FEATURES = {
    "auth_fail_count_5m", "auth_fail_ratio", 
    "auth_fail_then_success",
    "event_count_1m_ip", "event_count_5m_ip", "event_count_5m_dev",
    "user_rarity", "geo_rarity", "proc_rarity", "syscall_rarity",
    "exe_path_rarity", "parent_child_rarity", "et_bigram_rarity",
    "distinct_users_5m_ip", "distinct_ips_5m_user",
    "log_severity",
    "cmd_entropy", "cmd_length_log", "arg_count",
}
VARIANCE_THRESHOLD = 1e-4

# Clip apres StandardScaler (assoupli pour ne pas ecraser les anomalies extremes).
SCALE_CLIP = 15.0

# --- Architecture / entrainement -------------------------------------------
LATENT_DIM_BY_SOURCE   = {"auth": 6, "syslog": 4, "auditd": 6}
BATCH_SIZE             = 256
EPOCHS_BY_SOURCE       = {"auth": 300, "syslog": 250, "auditd": 200}
PATIENCE_BY_SOURCE     = {"auth": 40,  "syslog": 30,  "auditd": 25}
LR_BY_SOURCE           = {"auth": 5e-4, "syslog": 1e-3, "auditd": 1e-3}
WEIGHT_DECAY_BY_SOURCE = {"auth": 1e-4, "syslog": 1e-5, "auditd": 1e-5}
DROPOUT                = 0.10


SCORE_AGG     = "topk"   # "topk" | "max" | "lse"
SCORE_TOPK    = 2

SCORE_LSE_TAU =2.0      # tau->0 : =max | tau->inf : =moyenne

# Denoising : on masque cette fraction de features (mises a 0 = moyenne en
# espace scale) et on reconstruit vers l'entree PROPRE -> apprend la STRUCTURE.
DENOISE_MASK_FRAC = 0.10   # 0 = desactive

# Perte train robuste (Huber) ; le SCORE est le z-feature agrege (pas cette perte).
TRAIN_LOSS  = "huber"
HUBER_DELTA = 0.5



# Plancher d'echelle robuste : les entrees sont StandardScaler-isees (variance
# ~1), donc on ne "fait pas confiance" a une feature en dessous de 0.1 sigma de
# deviation. Empeche les features quasi-constantes (MAD~0) de squatter le top-k.
RESIDUAL_SCALE_FLOOR = 0.1

# Plafond du z par feature : evite qu'une feature a err_std degenere (~1e-6)
# monopolise le top-3 (cause des kurtosis a 112/274).
FEATURE_Z_CAP = 50.0

SOURCE_ROLE = {
    "auth":   "alert",
    "auditd": "alert",
    "syslog": "alert",
}

# --- Decoupage (NON SUPERVISE) : pool=passe, calib=present, test=futur -------
SPLIT_RATIOS = (0.60, 0.20, 0.20)
VAL_RATIO    = 0.20

# --- Seuil GPD-POT (NON SUPERVISE) ------------------------------------------
POT_TARGET_RATE_BY_SOURCE = {"auth": 0.005, "syslog": 0.001, "auditd": 0.005}
POT_TARGET_RATE = 0.005
POT_INIT_Q      = 0.98
POT_MIN_EXCESS  = 30
POT_XI_MAX = 0.8     # xi>=1 => esperance infinie -> ajustement rejete.
POT_XI_MIN = -0.5    # xi<-0.5 => hors regularite du MLE GPD (Smith 1985) -> rejete.


# --- Collecte : exclusion du bruit conteneur (IDS HOTE) ---------------------
EXCLUDE_CONTAINER_EVENTS = True
CONTAINER_RUNTIME_PROCS = {
    "runc", "containerd", "containerd-shim", "containerd-shim-runc-v2",
    "dockerd", "docker", "docker-proxy", "ctr",
}
EXCLUDE_NUMERIC_PROC = True   # process_name purement numerique = artefact de parsing.

# --- Fenetre temporelle d'extraction, PAR SOURCE ----------------------------
DATA_START_BY_SOURCE = {
    "auditd": "2026-06-07T21:30:00Z",
    "syslog": "2026-06-06T00:00:00Z",
    "auth":   None,
}
DATA_END_BY_SOURCE = {"auditd": None, "syslog": None, "auth": None}

# Plafond PAR SOURCE : empeche syslog d'epuiser le budget avant les auditd.
MAX_DOCS_BY_SOURCE = {"syslog": 200000, "auth": 50000, "auditd": 600000}

# En deca, source marquee "donnees insuffisantes" : ni entrainee ni alertee.
MIN_SOURCE_SAMPLES = 200

# Alertes d'une meme (source,hote) a moins de gap secondes = 1 seul episode.
EPISODE_GAP_SECONDS = 300

# --- Chemins de sortie ------------------------------------------------------
MODEL_PATH   = "model_ae.pt"
SCALERS_PATH = "ae_scalers.pkl"
THRESH_PATH  = "ae_thresholds.pkl"
NOVELTY_PATH = "novelty_state.pkl"
REPORT_PATH  = "evaluation_report.json"

# --- Coherence des listes (verifie au chargement) ---------------------------
for _s in SOURCES:
    _f = FEATURES[_s]
    assert len(_f) == len(set(_f)), f"doublon de feature dans '{_s}': {_f}"
    _inconnues = set(_f) - KNOWN_FEATURES
    assert not _inconnues, (
        f"feature(s) inconnue(s) dans '{_s}' (concatenation implicite ?): "
        f"{_inconnues}")

# --- Coherence des fenetres temporelles -------------------------------------
import pandas as _pd
_lte = _pd.Timestamp.utcnow() if ES_TIME_LTE == "now" else _pd.Timestamp(ES_TIME_LTE)
for _s, _start in DATA_START_BY_SOURCE.items():
    if _start and _pd.Timestamp(_start) > _lte:
        raise ValueError(
            f"Source '{_s}' : debut de fenetre ({_start}) posterieur a "
            f"ES_TIME_LTE ({ES_TIME_LTE}). Aucune donnee extractible.")