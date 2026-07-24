"""
retrain_config.py
=================
Configuration de la couche CT. SEPAREE de config_cnn.py a dessein :

  * config_cnn.py  = hyperparametres du MODELE. Ils sont FIGES entre deux
                     cycles de retraining. Les toucher = changer de modele.
  * retrain_config = parametres du PROCESSUS de retraining. Les toucher ne
                     change pas le modele, seulement la facon dont on le
                     reconstruit et dont on l'accepte.

Melanger les deux est la premiere source de confusion dans un pipeline CT :
on ne sait plus si une variation de performance vient d'un changement de
modele ou d'un changement de protocole.
"""
from __future__ import annotations

import os
from dotenv import load_dotenv

load_dotenv()

_HERE = os.path.dirname(os.path.abspath(__file__))
ML_ROOT = os.path.dirname(_HERE)

# ---------------------------------------------------------------------------
# 1. Emplacements
# ---------------------------------------------------------------------------
ARTIFACTS_ROOT = os.getenv("SENTINEL_ARTIFACTS_ROOT",
                           os.path.join(ML_ROOT, "artifacts"))
GOLDEN_DIR = os.path.join(ML_ROOT, "golden")
REPORTS_DIR = os.path.join(ARTIFACTS_ROOT, "_reports")

CANDIDATE_DIRNAME = "_candidate"
REJECTED_DIRNAME = "_rejected"
CURRENT_LINKNAME = "current"

# Fichier de verrou : empeche deux cycles concurrents (timer + lancement main).
LOCK_FILE = os.path.join(ARTIFACTS_ROOT, ".retrain.lock")

# ---------------------------------------------------------------------------
# 2. Fenetre glissante d'entrainement
# ---------------------------------------------------------------------------
# Duree d'historique reconstruite a chaque cycle.
#   Trop court  -> le modele oublie la saisonnalite hebdomadaire, la rarete
#                  longue-portee (user_rarity, proc_rarity) devient instable.
#   Trop long   -> cout memoire, et on rapprend un "normal" perime.
RETRAIN_WINDOW_MONTHS = int(os.getenv("RETRAIN_WINDOW_MONTHS", "6"))

# ATTENTION : la fenetre effective par source est
#       max(config_cnn.DATA_START_BY_SOURCE[src], T - RETRAIN_WINDOW_MONTHS)
# DATA_START_BY_SOURCE['auditd'] n'est PAS une preference, c'est une contrainte
# physique (avant la bascule du demon maitre les evenements sont malformes).
# Une fenetre glissante naive reintroduirait ces donnees pourries.

# Volumes minimaux : en dessous, l'extraction est consideree anemique
# (ES down, index rollover rate, filebeat arrete) -> on ABANDONNE le cycle
# plutot que d'entrainer sur un echantillon non representatif.
MIN_EVENTS_TOTAL = int(os.getenv("RETRAIN_MIN_EVENTS_TOTAL", "20000"))
MIN_EVENTS_BY_SOURCE = {"auth": 300, "syslog": 2000, "auditd": 5000}

# ---------------------------------------------------------------------------
# 3. Extraction (correctif OOM)
# ---------------------------------------------------------------------------
EXTRACT_PAGE_SIZE = 5000       # taille de page ES (identique a data_loader)
EXTRACT_CHUNK_ROWS = 20000     # lignes accumulees avant flush parquet
EXTRACT_SCROLL_KEEPALIVE = "5m"

# Plafonds SPECIFIQUES au retraining. On peut vouloir etre plus conservateur
# qu'en entrainement manuel : le cycle tourne sans surveillance a 02:00.
MAX_DOCS_BY_SOURCE = {"syslog": 200_000, "auth": 50_000, "auditd": 600_000}

# Garde-fou RAM : lu depuis /proc/meminfo avant de commencer.
MIN_AVAILABLE_RAM_MB = int(os.getenv("RETRAIN_MIN_RAM_MB", "1500"))

# ---------------------------------------------------------------------------
# 4. Decontamination (boucle de retroaction Sigma / LLM)
# ---------------------------------------------------------------------------
# Marge appliquee de part et d'autre de chaque incident confirme.
# Elle doit couvrir au moins la duree d'une fenetre CNN, sinon des fenetres
# chevauchant l'attaque survivent a l'excision.
DECONTAMINATION_MARGIN_SECONDS = int(
    os.getenv("RETRAIN_DECONTAM_MARGIN", "600"))

# Fichier de quarantaine manuel : incidents confirmes a la main (exercices
# red-team, scenarios de validation joues sur la machine, faux negatifs
# decouverts a posteriori). Toujours pris en compte, meme si Mongo est HS.
QUARANTINE_FILE = os.path.join(_HERE, "quarantine.json")

# --- Source automatique : episodes tries par la couche LLM ------------------
MONGO_URI = os.getenv("MONGO_URI") or os.getenv("MONGODB_URI")
MONGO_DB = os.getenv("MONGO_DB", "sentinel")
MONGO_EPISODES_COLLECTION = os.getenv("MONGO_EPISODES_COLLECTION", "reports")

# Mapping du schema Mongo -> champs Incident. A AJUSTER une seule fois selon
# report_repository.py. Le module echoue avec un message explicite si un champ
# est introuvable : il ne devine jamais.
MONGO_FIELD_MAP = {
    "verdict":     "verdict",        # champ portant true_positive / false_positive
    "start":       "start_time",
    "end":         "end_time",
    "log_source":  "log_source",
    "host_name":   "host_name",
    "source_ip":   "source_ip",
    "id":          "episode_id",
}
MONGO_VERDICT_TRUE_POSITIVE = ("true_positive", "TRUE_POSITIVE", "confirmed")

# Si True, un Mongo injoignable fait ECHOUER le cycle. Recommande en prod :
# entrainer sans decontamination automatique est precisement le scenario
# d'empoisonnement qu'on cherche a eviter.
REQUIRE_MONGO = os.getenv("RETRAIN_REQUIRE_MONGO", "0") == "1"

# Faut-il aussi exciser les episodes 'uncertain' ? Par defaut NON : ils sont
# routes vers le dashboard Expert AI et non confirmes. Les exclure reviendrait
# a laisser un classifieur non valide amputer le corpus d'entrainement.
DECONTAMINATE_UNCERTAIN = os.getenv("RETRAIN_DECONTAM_UNCERTAIN", "0") == "1"

# ---------------------------------------------------------------------------
# 5. Gate de validation
# ---------------------------------------------------------------------------
# (a) Golden set : recall episodique minimal sur les scenarios d'attaque figes.
GATE_GOLDEN_MIN_RECALL = float(os.getenv("GATE_GOLDEN_MIN_RECALL", "1.0"))

# (b) Bande de taux d'alerte candidat / courant, sur la MEME fenetre de
#     reference figee. Hors bande = regime d'alerte change -> refus.
GATE_ALERT_RATE_BAND = (0.5, 2.0)

# (c) Derive de distribution des scores : statistique de Kolmogorov-Smirnov.
#     On seuille sur D (la statistique) et NON sur la p-value : a N ~ 1e5 la
#     p-value est quasi toujours < 1e-10 meme pour une difference infime, le
#     test devient un refus systematique. D mesure l'ecart reel entre les CDF
#     et ne depend pas de N.
GATE_KS_D_MAX = float(os.getenv("GATE_KS_D_MAX", "0.30"))
GATE_KS_BLOCKING = os.getenv("GATE_KS_BLOCKING", "1") == "1"

# (d) Coherence des seuils : ratio candidat/courant tolere par source.
GATE_THRESHOLD_RATIO_BAND = (0.2, 5.0)

# Nombre minimal d'episodes attendus sur la fenetre de reference cote candidat.
# 0 episode = collapse de l'auto-encodeur (il reconstruit tout parfaitement,
# attaques comprises) : panne silencieuse la plus dangereuse du systeme.
GATE_MIN_REFERENCE_EPISODES = 1

# ---------------------------------------------------------------------------
# 6. Retention
# ---------------------------------------------------------------------------
# Doctrine du projet : `mv`, jamais `rm`, sur tout ce qui porte un resultat.
# Aucune suppression automatique. Le GC se contente de LISTER les candidats.
KEEP_LAST_N_VERSIONS = int(os.getenv("RETRAIN_KEEP_VERSIONS", "6"))
AUTO_DELETE_OLD_VERSIONS = False   # NE PAS passer a True sans sauvegarde

# ---------------------------------------------------------------------------
# 7. Sous-processus d'entrainement
# ---------------------------------------------------------------------------
TRAIN_ENTRYPOINT = os.path.join(ML_ROOT, "train_eval_cnn.py")
TRAIN_TIMEOUT_SECONDS = int(os.getenv("RETRAIN_TRAIN_TIMEOUT", str(5 * 3600)))
