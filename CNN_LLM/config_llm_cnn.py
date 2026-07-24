"""
config_llm_cnn.py
=================
Configuration AUTONOME de la couche 3 (LLM + RAG) de Sentinel, branche CNN.

Frontiere stricte :
  * config_cnn.py      = detection (CNN, POT, episodes)   -> NE CHANGE PAS
  * config_llm_cnn.py  = triage semantique (RAG + LLM)    -> ce fichier
Ce module n'importe RIEN de la branche detection sauf, en lecture seule,
EPISODE_GAP_SECONDS (pour regrouper les alertes exactement comme
inference_cnn.aggregate_alerts -> episodes identiques bit a bit).
"""
from __future__ import annotations
import os
from dotenv import load_dotenv

# --- Ancrage des chemins ----------------------------------------------------
# Tous les chemins sont ancres au DOSSIER DU MODULE, jamais au repertoire
# courant : le pipeline doit donner le meme resultat qu'on le lance depuis
# CNN_LLM/, depuis le home, ou depuis un cron. Un chemin relatif au cwd est un
# bug qui attend le jour de la demo.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _find_dotenv() -> str | None:
    """Cherche le .env en remontant DEPUIS LE MODULE, pas depuis le cwd.

    Deux organisations doivent marcher :
      CNN_LLM/.env                  -> config propre a la couche 3 (prioritaire)
      pfe-backend-2026/.env         -> config partagee du projet (repli)

    Pourquoi pas load_dotenv() nu : il remonte depuis le REPERTOIRE COURANT.
    Le meme code trouverait la cle lance depuis CNN_LLM/ et ne la trouverait
    plus lance depuis le home ou via un subprocess du backend FastAPI.
    """
    d = BASE_DIR
    for _ in range(4):                       # CNN_LLM -> projet -> home -> /
        p = os.path.join(d, ".env")
        if os.path.exists(p):
            return p
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return None


DOTENV_PATH = _find_dotenv()
if DOTENV_PATH:
    load_dotenv(DOTENV_PATH)

# Dossier ou inference_cnn.py a ecrit ses sorties (cnn_alerts.csv...).
# Par defaut : le dossier du module. Surchargeable sans toucher au code :
#   export CNN_OUT_DIR=~/pfe-backend-2026/ML/cnn
CNN_OUT_DIR = os.path.expanduser(os.getenv("CNN_OUT_DIR", BASE_DIR))

# Dossier ou la couche 3 ecrit SES sorties (par defaut : a cote du module,
# pour ne jamais polluer les artefacts de la branche detection).
TRIAGE_OUT_DIR = os.path.expanduser(os.getenv("TRIAGE_OUT_DIR", BASE_DIR))

# --- Entrees (artifacts produits par inference_cnn.py) ----------------------
ALERTS_CSV   = os.path.join(CNN_OUT_DIR, "cnn_alerts.csv")
EPISODES_CSV = os.path.join(CNN_OUT_DIR, "cnn_alerts_episodes.csv")
RUN_META_JSON = os.path.join(CNN_OUT_DIR, "cnn_run_meta.json")   # ← AJOUT

# --- Sorties ----------------------------------------------------------------
TRIAGE_JSONL = os.path.join(TRIAGE_OUT_DIR, "cnn_triage.jsonl")
TRIAGE_CSV   = os.path.join(TRIAGE_OUT_DIR, "cnn_triaged_episodes.csv")
TRIAGE_REPORT_JSON = os.path.join(TRIAGE_OUT_DIR, "cnn_triage_report.json")

# --- Episodes ---------------------------------------------------------------
# DOIT etre identique a config_cnn.EPISODE_GAP_SECONDS, sinon les episodes
# du triage ne correspondent plus a ceux de l'inference.
EPISODE_GAP_SECONDS = 300

# Echantillonnage du dossier d'episode (controle du cout en tokens).
DOSSIER_TOP_N   = 8    # evenements les plus anormaux (mse desc)
DOSSIER_EDGE_N  = 3    # premiers / derniers evenements (contexte temporel)
DOSSIER_MAX_LINES = 25 # plafond dur de la timeline

# --- LLM (GroqCloud) --------------------------------------------------------
# ATTENTION : Groq a annonce le 17/06/2026 la depreciation de
# llama-3.3-70b-versatile et llama-3.1-8b-instant. Migration recommandee :
# openai/gpt-oss-120b (raisonnement) ou openai/gpt-oss-20b (rapide/eco).
# Verifier la liste vivante : GET https://api.groq.com/openai/v1/models
LLM_PROVIDER   = "groq"
LLM_MODEL      = os.getenv("LLM_MODEL", "openai/gpt-oss-120b")
LLM_MODEL_FALLBACK = os.getenv("LLM_MODEL_FALLBACK", "openai/gpt-oss-20b")

# --- Fournisseur : 'groq' (defaut) ou 'ollama' (local) ----------------------
# Le fournisseur est un PARAMETRE, pas une dependance architecturale : passer
# en local ne demande que ces deux lignes dans le .env, aucun module ne change.
#     LLM_PROVIDER=ollama
#     LLM_BASE_URL=http://localhost:11434/v1
#     LLM_MODEL=qwen3:8b
# Contrepartie mesuree sur CPU sans GPU : ~3-4 min/episode contre ~6 s via
# Groq, et un modele 8B degrade le raisonnement multi-etapes. A reserver a la
# demonstration de portabilite, pas au run evalue.
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "groq").strip().lower()
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://localhost:11434/v1")

if LLM_PROVIDER not in ("groq", "ollama"):
    raise SystemExit(f"LLM_PROVIDER='{LLM_PROVIDER}' inconnu : 'groq' ou 'ollama'.")
GROQ_API_KEY   = os.getenv("GROQ_API_KEY")

LLM_TEMPERATURE     = 0.0     # determinisme -> resultats reproductibles au jury
LLM_MAX_TOKENS      = 1400
LLM_SEED            = 42
LLM_TIMEOUT_S       = 60
LLM_MAX_RETRIES     = 3
LLM_BACKOFF_S       = 2.0
LLM_REASONING_EFFORT = "medium"   # gpt-oss uniquement ; ignore ailleurs

# Cache disque : hash(prompt) -> reponse. Rejouer le pipeline = 0 appel, 0 cout,
# et surtout MEME sortie -> le rapport de PFE est reproductible.
LLM_CACHE_DIR = os.path.join(TRIAGE_OUT_DIR, ".llm_cache_cnn")
LLM_CACHE_ENABLED = True

# --- RAG --------------------------------------------------------------------
KB_DIR = os.path.join(BASE_DIR, "kb")   # la KB voyage AVEC le code
RAG_TOP_K = 6
RAG_ALPHA = 0.6           # score = ALPHA*semantique + (1-ALPHA)*lexical
RAG_MAX_CHARS = 12000     # budget car. KB dans le prompt ; KB ~9000 → tient entière


# --- Backend d'encodage -----------------------------------------------------
# 'tfidf'                 : lexical pondere. DEFAUT, et ce n'est pas un repli.
# 'sentence-transformers' : embeddings semantiques.
# 'lexical'               : recouvrement de tokens, zero dependance.
# 'auto'                  : sentence-transformers si dispo, sinon tfidf.
#
# MESURE DU 16/07/2026 -- pourquoi tfidf est le defaut et non 'auto' :
# le passage aux embeddings a DEGRADE les deux vrais positifs du jeu de test.
#     EP-0151688dd2 (.update)    TP critical 0.86  ->  uncertain 0.42
#     EP-7940ba7c5c (.rk_beacon) TP critical 0.92  ->  uncertain 0.50
# Cause : sur 13 chunks, 'cups-browsed' (faux positif) et 'crontab' (vrai
# positif) sont voisins dans l'espace semantique -- ce sont tous deux des
# "processus systeme Linux". Le cosinus les confond ; le match exact sur
# process_name les separe. A ce volume de KB, la similarite semantique dilue
# le signal discriminant au lieu de l'enrichir.
# Resultat negatif documente : les embeddings ne sont pas un progres par
# defaut, ils dependent de la structure du corpus.
RAG_BACKEND = os.getenv("RAG_BACKEND", "tfidf").strip().lower()
EMBED_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
EMBED_ENABLED = RAG_BACKEND in ("sentence-transformers", "auto")

if RAG_BACKEND not in ("tfidf", "sentence-transformers", "lexical", "auto"):
    raise SystemExit(f"RAG_BACKEND='{RAG_BACKEND}' inconnu.")
RAG_INDEX_CACHE = ".rag_index_cnn.pkl"

# --- Politique de triage (garde-fous SOC) -----------------------------------
# Pre-filtre deterministe : si un episode matche une signature benigne connue
# ET qu'aucun marqueur sensible n'est present, on peut le clore SANS appel LLM.
# Par defaut DESACTIVE : une allowlist dure est contournable par masquerading
# (T1036, un binaire renomme "logrotate"). Laisser False = le LLM voit tout,
# la baseline lui est fournie comme CONTEXTE et non comme decision.
# Passer a True = ablation chiffrable (cout LLM vs risque de contournement).
AUTO_CLOSE_ENABLED = False

# Primitives qui ne peuvent JAMAIS etre auto-classees false_positive par le LLM.
# Ce n'est pas de la verite terrain : c'est une POLITIQUE SOC (un analyste
# humain ne clot jamais une creation de compte sans regarder).
NEVER_DISMISS_PROCESSES = {
    "useradd", "userdel", "usermod", "groupadd", "passwd", "chpasswd",
    "visudo", "chattr", "auditctl", "insmod", "modprobe",
}
NEVER_DISMISS_EVENT_TYPES = {
    "changed-audit-configuration", "changed-password",
}
# Rafale d'echecs d'authentification -> jamais clos automatiquement.
NEVER_DISMISS_FAIL_BURST = 5     # n alertes 'is_fail' dominant dans un episode

# Verdicts autorises (schema ferme).
VERDICTS = ("true_positive", "false_positive", "uncertain")
SEVERITIES = ("info", "low", "medium", "high", "critical")

# En cas d'echec LLM (timeout, JSON invalide, quota) : on NE JETTE JAMAIS
# l'alerte. Fail-open = l'episode reste 'uncertain' et remonte a l'analyste.
FAIL_OPEN_VERDICT = "uncertain"


# --- exigence d'actionnabilite (garde-fou 8 de _validate) -------------------
# Un episode remonte sans explication ni action n'apporte rien a l'analyste.
MIN_RATIONALE_CHARS = 80
FALLBACK_RECOMMENDATION = (
    "Le modele n'a pas produit d'action exploitable : investigation manuelle "
    "requise (verifier processus, utilisateur et fenetre temporelle de l'episode)."
)