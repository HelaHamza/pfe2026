"""
config_llm_cnn.py
=================
Configuration de la couche d'EXPLICATION (branche CNN).

Le CNN decide ce qui est une alerte ; le LLM ne classe plus, il EXPLIQUE et
PRIORISE. Le verdict n'est donc plus une sortie du modele : il est fixe ici
(ALERT_VERDICT).

La couche LLM est PURE : la severite d'un episode est celle que le modele
decide, sans aucun plancher ni garde-fou deterministe a cet etage. La detection
des primitives sensibles (creation de compte, persistance cron, modification de
l'audit...) releve de la couche Sigma, pas de la couche d'explication.
"""

from __future__ import annotations
import os
from dotenv import load_dotenv

# --- Ancrage des chemins ----------------------------------------------------
# Tous les chemins sont ancres au DOSSIER DU MODULE, jamais au repertoire
# courant : le pipeline doit donner le meme resultat qu'on le lance depuis
# CNN_LLM/, depuis le home, ou depuis un cron.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _find_dotenv() -> str | None:
    """Cherche le .env en remontant DEPUIS LE MODULE, pas depuis le cwd.

      CNN_LLM/.env             -> config propre a la couche 3 (prioritaire)
      pfe-backend-2026/.env    -> config partagee du projet (repli)

    load_dotenv() nu remonte depuis le REPERTOIRE COURANT : le meme code
    trouverait la cle lance depuis CNN_LLM/ et pas depuis le home.
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
CNN_OUT_DIR = os.path.expanduser(os.getenv("CNN_OUT_DIR", BASE_DIR))
# Dossier ou la couche 3 ecrit SES sorties (par defaut : a cote du module).
TRIAGE_OUT_DIR = os.path.expanduser(os.getenv("TRIAGE_OUT_DIR", BASE_DIR))

# --- Entrees (artifacts produits par inference_cnn.py) ----------------------
ALERTS_CSV   = os.path.join(CNN_OUT_DIR, "cnn_alerts.csv")
EPISODES_CSV = os.path.join(CNN_OUT_DIR, "cnn_alerts_episodes.csv")
RUN_META_JSON = os.path.join(CNN_OUT_DIR, "cnn_run_meta.json")

# --- Sorties ----------------------------------------------------------------
TRIAGE_JSONL = os.path.join(TRIAGE_OUT_DIR, "cnn_triage.jsonl")
TRIAGE_CSV   = os.path.join(TRIAGE_OUT_DIR, "cnn_triaged_episodes.csv")
TRIAGE_REPORT_JSON = os.path.join(TRIAGE_OUT_DIR, "cnn_triage_report.json")

# --- Episodes ---------------------------------------------------------------
# DOIT etre identique a config_cnn.EPISODE_GAP_SECONDS.
EPISODE_GAP_SECONDS = 300

# Echantillonnage du dossier d'episode (controle du cout en tokens).
DOSSIER_TOP_N   = 8    # evenements les plus anormaux (mse desc)
DOSSIER_EDGE_N  = 3    # premiers / derniers evenements (contexte temporel)
DOSSIER_MAX_LINES = 25 # plafond dur de la timeline

# --- LLM (GroqCloud) --------------------------------------------------------
# Groq a annonce le 17/06/2026 la depreciation de llama-3.3-70b-versatile et
# llama-3.1-8b-instant. Migration : openai/gpt-oss-120b (raisonnement) ou
# openai/gpt-oss-20b (rapide). Liste vivante : GET .../openai/v1/models
LLM_MODEL      = os.getenv("LLM_MODEL", "openai/gpt-oss-120b")
LLM_MODEL_FALLBACK = os.getenv("LLM_MODEL_FALLBACK", "openai/gpt-oss-20b")

# --- Fournisseur : 'groq' (defaut) ou 'ollama' (local) ----------------------
# Le fournisseur est un PARAMETRE, pas une dependance architecturale :
#     LLM_PROVIDER=ollama
#     LLM_BASE_URL=http://localhost:11434/v1
#     LLM_MODEL=qwen3:8b
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

# Cache disque : hash(prompt) -> reponse. Rejouer = 0 appel, MEME sortie.
LLM_CACHE_DIR = os.path.join(TRIAGE_OUT_DIR, ".llm_cache_cnn")
LLM_CACHE_ENABLED = True

# --- RAG --------------------------------------------------------------------
KB_DIR = os.path.join(BASE_DIR, "kb")   # la KB voyage AVEC le code
RAG_TOP_K = 6
RAG_ALPHA = 0.6           # score = ALPHA*semantique + (1-ALPHA)*lexical

# Budget caracteres de la KB injectee dans le prompt. Avec RAG_TOP_K=6 chunks
# retenus (+ la reference forcee), le bloc rendu fait typiquement ~5-6k car. et
# tient sous ce budget. Si un run le depasse, render() TRONQUE les derniers
# chunks (par `continue`) -- il ne plante pas.
RAG_MAX_CHARS = 6000

# --- Backend d'encodage -----------------------------------------------------
# 'tfidf'                 : lexical pondere. DEFAUT, et ce n'est pas un repli.
# 'sentence-transformers' : embeddings semantiques.
# 'lexical'               : recouvrement de tokens, zero dependance.
# 'auto'                  : sentence-transformers si dispo, sinon tfidf.
#
# MESURE DU 16/07/2026 (historique, avant repositionnement du LLM) -- pourquoi
# tfidf est le defaut et non 'auto' : le passage aux embeddings a DEGRADE la
# priorisation de deux episodes d'attaque du jeu de test (severite critical
# rabaissee). Cause : sur un petit corpus, 'cups-browsed' et 'crontab' sont
# voisins dans l'espace semantique -- tous deux "processus systeme Linux". Le
# cosinus les confond ; le match exact sur process_name les separe. Resultat
# negatif documente : les embeddings ne sont pas un progres par defaut.
RAG_BACKEND = os.getenv("RAG_BACKEND", "tfidf").strip().lower()
EMBED_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
EMBED_ENABLED = RAG_BACKEND in ("sentence-transformers", "auto")

if RAG_BACKEND not in ("tfidf", "sentence-transformers", "lexical", "auto"):
    raise SystemExit(f"RAG_BACKEND='{RAG_BACKEND}' inconnu.")

# =====================================================================
#  MODE EXPLICATION SEULE : le verdict est FIXE, pas produit par le LLM.
# =====================================================================
# Le CNN DECIDE ce qui est une alerte ; le LLM EXPLIQUE. Toute alerte levee est
# conservee et presentee. 'true_positive' est la valeur que le dashboard SOC
# affiche comme alerte : en la fixant, chaque episode remonte a l'analyste,
# rien n'est clos, et le contrat de sortie reste identique. Le tri utile cote
# analyste devient la SEVERITE, pas le verdict.
ALERT_VERDICT = "true_positive"

# Echelle de severite (seul signal de tri en mode explication). C'est la
# severite DECIDEE PAR LE LLM ; triage_cnn._clamp_severity garantit seulement
# qu'elle reste dans cette echelle (aucun plancher deterministe).
SEVERITIES = ("info", "low", "medium", "high", "critical")