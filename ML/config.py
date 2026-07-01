"""
config.py
=========
Constantes PARTAGEES par tous les modules. Centraliser ici evite la
desynchronisation des listes de features entre modules (cause racine de
l'ancien bug de concatenation implicite).

NB IMPORTANT : on ne depend PLUS d'aucun champ `ml.*` cote Elasticsearch.
Toutes les features sont recalculees en Python depuis les champs ECS BRUTS,
ce qui rend le pipeline immunise contre la version de Logstash deployee.
"""
from __future__ import annotations
import os
from dotenv import load_dotenv
load_dotenv()
# --- Reproductibilite : doit etre pose avant l'import de torch ailleurs -----
os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
SEED = 42

# --- Elasticsearch ----------------------------------------------------------
ES_HOST  = os.getenv("ES_HOST", "https://localhost:9200")
ES_USER  = os.getenv("ES_USER", "elastic")
ES_PASS  = os.getenv("ELASTIC_PWD")
ES_INDEX = os.getenv("ES_INDEX", "filebeat-logs-*,auditbeat-*")
ES_TIME_GTE = os.getenv("ES_TIME_GTE", "2026-04-24T00:00:00Z")
#ES_TIME_LTE = os.getenv("ES_TIME_LTE", "2026-05-28T00:00:00Z")
ES_TIME_LTE = os.getenv("ES_TIME_LTE", "now")   # au lieu de "2026-05-28"
MAX_DOCS    = int(os.getenv("MAX_DOCS", "400000"))

DATASET_CACHE = "dataset_snapshot.parquet"
USE_CACHE     = True

# --- Sources ----------------------------------------------------------------
SOURCES = ["auth", "syslog", "auditd"]

# --- Blocs de features ------------------------------------------------------
# Temps + identite : pertinent pour TOUTES les sources.
_TIME = ["hour_sin", "hour_cos", "is_night", "is_weekend", "is_root"]
_IDENT = ["is_root"]

# Forme du message : pertinent UNIQUEMENT pour auth/syslog (auditd n'a souvent
# pas de message lisible -> ces colonnes seraient quasi-constantes => retirees
# d'auditd pour ne pas gaspiller de dimensions).
_MSG = ["msg_length_log",
        "msg_has_ip", "msg_has_url", "msg_has_pipe"]

# Features par source (UNIQUEMENT numeriques, toutes calculees en Python).
FEATURES = {
    "auth": _IDENT + _MSG + [
        "ip_is_external", "geo_is_new", "user_is_new",   # nouveaute (ponctuel)
        "auth_fail_count_5m", "auth_ok_count_5m",        # fenetre
        "auth_fail_ratio", "event_count_5m_ip",          # fenetre
        "event_count_5m_dev",                            # deviation (contextuel)
        "et_bigram_new",                                 # sequence (collectif)
        "auth_fail_then_success",                         # sequence (collectif)
    ],
    "syslog": _IDENT + _MSG + [
        "proc_rarity",                    # nouveaute (ponctuel)
        "event_count_1m_ip", "event_count_5m_ip",        # fenetre
        "event_count_5m_dev",                            # deviation (contextuel)
        "et_bigram_new",                                 # sequence (collectif)
    ],
    "auditd": _IDENT + [                                  # PAS de _MSG ici
        "cmd_entropy", "cmd_length_log", "arg_count",    # forme commande (ponctuel)
     "proc_rarity", "user_is_new",     # nouveaute (ponctuel)
        "event_count_5m_ip", "event_count_5m_dev",       # fenetre + deviation
        "et_bigram_new",                                 # sequence (collectif)
        "parent_child_new",

    ],
}

INPUT_DIMS    = {s: len(FEATURES[s]) for s in SOURCES}
MAX_INPUT_DIM = max(INPUT_DIMS.values())

# Vocabulaire connu : garde-fou contre la concatenation implicite de chaines
# Python (["a" "b"] -> "ab"). Toute feature hors de cet ensemble leve.
KNOWN_FEATURES = set()
for _s in SOURCES:
    KNOWN_FEATURES |= set(FEATURES[_s])

# Comptages -> transformation log1p (ecrase les longues trainees lourdes).
COUNT_FEATURES = {
    "auth_fail_count_5m", "auth_ok_count_5m",
    "event_count_1m_ip", "event_count_5m_ip",
    "arg_count", "msg_word_count","auth_fail_then_success",
}

# Features "rare-event" / deviation a NE JAMAIS retirer par le filtre de
# variance, meme si quasi-constantes (elles portent le signal d'attaque).
WHITELIST_FEATURES = {
    "auth_fail_count_5m", "auth_fail_ratio", "auth_ok_count_5m",
    "event_count_1m_ip", "event_count_5m_ip", "event_count_5m_dev",
    "et_bigram_new",  "user_is_new", "geo_is_new",
    # ip_is_external : constant durant l'entrainement (avril, activite locale)
    # mais discriminant au test (IP externes en mai) -> ne JAMAIS le retirer.
    "ip_is_external",
    "cmd_entropy", "cmd_length_log", "arg_count",
    "auth_fail_then_success", "parent_child_new",   # <-- NOUVEAU


}
VARIANCE_THRESHOLD = 1e-4

# Clip apres StandardScaler. Assoupli (15 au lieu de 10) pour ne pas ecraser
# les anomalies ponctuelles extremes avant reconstruction.
SCALE_CLIP = 15.0

# --- Architecture / entrainement -------------------------------------------
LATENT_DIM_BY_SOURCE   = {"auth": 6, "syslog": 4, "auditd": 6}
BATCH_SIZE             = 256
EPOCHS_BY_SOURCE       = {"auth": 300, "syslog": 250, "auditd": 200}
PATIENCE_BY_SOURCE     = {"auth": 40,  "syslog": 30,  "auditd": 25}
LR_BY_SOURCE           = {"auth": 5e-4, "syslog": 1e-3, "auditd": 1e-3}
WEIGHT_DECAY_BY_SOURCE = {"auth": 1e-4, "syslog": 1e-5, "auditd": 1e-5}
DROPOUT                = 0.10
SCORE_AGG  = "topk"   # "max" (anomalie la plus forte) ou "topk" (robuste au bruit)
SCORE_TOPK = 3   

# --- Denoising autoencoder --------------------------------------------------
# A l'entrainement on masque aleatoirement cette fraction de features (mises a
# 0 = moyenne en espace scale) et on reconstruit vers l'entree PROPRE. Force le
# modele a apprendre la STRUCTURE du normal -> erreur plus discriminante.
DENOISE_MASK_FRAC = 0.10   # 0 = desactive

# Pertes : choix EXPLICITE. Train robuste (Huber), score sensible (MSE).
TRAIN_LOSS  = "huber"   # delta=0.5
SCORE_LOSS  = "mse"
HUBER_DELTA = 0.5


FEATURE_Z_CAP = 50.0

SOURCE_ROLE = {
    "auth":   "alert",        # alerte primaire
    "auditd": "alert",        # alerte primaire (process execution)
    "syslog": "alert",  # contexte Sigma, pas alerte autonome
}

# --- Decoupage (NON SUPERVISE : aucun label) --------------------------------
# train_pool = passe, calib = present, test = futur (anti-fuite temporelle).
SPLIT_RATIOS = (0.60, 0.20, 0.20)   # (pool, calib, test)
VAL_RATIO    = 0.20                  # validation interne au pool (chronologique)

# --- Seuil GPD-POT (NON SUPERVISE) ------------------------------------------
POT_TARGET_RATE_BY_SOURCE = {"auth": 0.005, "syslog": 0.001, "auditd": 0.005}   # taux d'exceedance cible (1/200 = 0.5%) 
POT_TARGET_RATE = 0.005   # repli si une source manque au dict ci-dessus

POT_INIT_Q      = 0.98    # quantile de depart pour le seuil d'exces u (releve :
                          # 0.95 etait trop bas -> hors regime POT -> xi aberrant)
POT_MIN_EXCESS  = 30      # nb mini d'exces pour ajuster la GPD (sinon repli)
POT_XI_MAX      = 0.8     # au-dela, l'ajustement GPD est juge non fiable
                          # (xi>=1 => esperance infinie, non physique pour un MSE)
                          # -> on rejette et on retombe sur le quantile empirique.

# --- Collecte : exclusion du bruit conteneur (IDS HOTE) ---------------------
EXCLUDE_CONTAINER_EVENTS = True   # ecarte tout evenement portant container.name
                                  # (ex. health-checks Docker qui saturaient auditd)
# --- Bruit d'infra auditd qui ECHAPPE a filter_host_only --------------------
# runc/containerd/dockerd tournent sur l'HOTE (pas de container.name) -> ils
# passent le filtre host-only alors que c'est de l'infra Docker pure.

# CONTAINER_RUNTIME_PROCS = {
#      "Chrome_ChildIOT", "Chrome_DevTools", "Chrome_IOThread", "chrome",
#     "code", "code-tunnel", "libuv-worker", "cpuUsage.sh","runc", "containerd", "containerd-shim", "containerd-shim-runc-v2",
#     "dockerd", "docker", "docker-proxy", "ctr",
# }
CONTAINER_RUNTIME_PROCS = {
    "runc", "containerd", "containerd-shim", "containerd-shim-runc-v2",
    "dockerd", "docker", "docker-proxy", "ctr",
}
# process_name purement numerique ('6','9') = artefact de parsing (PID/fd en comm).
EXCLUDE_NUMERIC_PROC = True
# --- Fenetre temporelle d'extraction, PAR SOURCE ----------------------------
# auditd : la collecte n'est PROPRE que depuis la bascule "demon auditd maitre"
# (~22:30 CET = 21:30 UTC le 2026-06-07). Avant, la source etait polluee/vide.
# syslog & auth : collecte inchangee -> on garde tout l'historique (None).
# NB transitoire : harmoniser les 3 sources sur une meme fenetre apres ~3 jours.
DATA_START_BY_SOURCE = {
    "auditd": "2026-06-15T21:30:00Z",   # 22:30 heure locale CET = 21:30 UTC
    "syslog": "2026-06-06T00:00:00Z",   # <-- au lieu de None : fenêtre récente, alignée
    "auth":   None,
}
DATA_END_BY_SOURCE = {"auditd": None, "syslog": None, "auth": None}

# Plafond PAR SOURCE : empeche syslog (350k) d'epuiser le budget avant que le
# scroll n'atteigne les auditd de juin. Aligne sur la logique per-source.
MAX_DOCS_BY_SOURCE = {"syslog": 200000, "auth": 50000, "auditd": 600000}


# --- Garde-fou d'effectif minimal par source --------------------------------
# En deca, une source est marquee "donnees insuffisantes" : on ne l'entraine
# pas, on ne la calibre pas, on n'emet aucune alerte (evite l'absurdite d'un
# seuil sur n=9 et d'un taux d'alerte a 55%).
MIN_SOURCE_SAMPLES = 200          # nb mini d'echantillons d'entrainement

# --- Agregation des alertes par episode -------------------------------------
EPISODE_GAP_SECONDS = 300         # alertes d'une meme (source,hote) separees de
                                  # moins de 5 min = 1 seul episode (un reboot
                                  # devient 1 alerte, pas 300).

# --- Chemins de sortie ------------------------------------------------------
MODEL_PATH   = "model_ae.pt"
SCALERS_PATH = "ae_scalers.pkl"
THRESH_PATH  = "ae_thresholds.pkl"
NOVELTY_PATH = "novelty_state.pkl"   # vocabulaires vus (pour l'inference live)
REPORT_PATH  = "evaluation_report.json"


# --- Coherence des listes (verifie au chargement du module) -----------------
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