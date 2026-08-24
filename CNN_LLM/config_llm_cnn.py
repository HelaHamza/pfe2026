"""
config_llm_cnn.py
=================
Configuration de la couche de triage (branche CNN).

NB version RAG-only : ce fichier est partage avec le pipeline complet. Les
constantes de la section "Politique de triage (garde-fous SOC)" plus bas
(NEVER_DISMISS_*, MIN_RATIONALE_CHARS, VERDICTS, FAIL_OPEN_VERDICT, ...) NE
SERVENT QU'AUX GARDE-FOUS DE SORTIE (_validate). Elles sont INERTES dans la
version RAG-only (triage_llm_rag.py ne les lit pas), mais on les CONSERVE :
episode_context_cnn.policy_flags() les importe encore, et on les reactivera a
l'etape "garde-fous". Ne pas les supprimer.
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
LLM_PROVIDER   = "groq"
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
# NB : le prompt RAG-only differe du prompt complet -> hash different, aucune
# contamination de cache entre les deux variantes.
LLM_CACHE_DIR = os.path.join(TRIAGE_OUT_DIR, ".llm_cache_cnn")
LLM_CACHE_ENABLED = True

# --- RAG --------------------------------------------------------------------
KB_DIR = os.path.join(BASE_DIR, "kb")   # la KB voyage AVEC le code
RAG_TOP_K = 6
RAG_ALPHA = 0.6           # score = ALPHA*semantique + (1-ALPHA)*lexical

# Budget caracteres de la KB injectee dans le prompt. Avec RAG_TOP_K=6 chunks
# retenus (+ la reference forcee), le bloc rendu fait typiquement ~5-6k car. et
# tient sous ce budget. Si un run le depasse, render() TRONQUE les derniers
# chunks (par `continue`) -- il ne plante pas. Ne PAS augmenter a la legere :
# un budget plus large gonfle les tokens et rapproche du plafond Groq (413).
RAG_MAX_CHARS = 6000

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
# Cause : sur un petit corpus, 'cups-browsed' (FP) et 'crontab' (TP) sont
# voisins dans l'espace semantique -- tous deux "processus systeme Linux". Le
# cosinus les confond ; le match exact sur process_name les separe.
# Resultat negatif documente : les embeddings ne sont pas un progres par
# defaut, ils dependent de la structure du corpus.
RAG_BACKEND = os.getenv("RAG_BACKEND", "tfidf").strip().lower()
EMBED_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
EMBED_ENABLED = RAG_BACKEND in ("sentence-transformers", "auto")

if RAG_BACKEND not in ("tfidf", "sentence-transformers", "lexical", "auto"):
    raise SystemExit(f"RAG_BACKEND='{RAG_BACKEND}' inconnu.")

# =====================================================================
# ↓↓↓  MODE EXPLICATION SEULE (repositionnement du LLM)             ↓↓↓
# =====================================================================
# Le CNN DECIDE ce qui est une alerte ; le LLM n'exerce plus aucun triage, il
# EXPLIQUE. Toute alerte levee par le CNN est conservee et presentee : le
# verdict du dossier n'est donc plus produit par le LLM, il est FIXE ici.
#
# Choix de 'true_positive' : c'est la valeur que le dashboard SOC affiche
# comme alerte. En la fixant, chaque episode remonte a l'analyste, rien n'est
# jamais clos, et AUCUN changement backend / front n'est necessaire (contrat
# de sortie identique). Le tri utile cote analyste devient la SEVERITE, pas le
# verdict. Consequence attendue : le bucket 'uncertain' du dashboard IA reste
# structurellement en place mais vide.
ALERT_VERDICT = "true_positive"

# =====================================================================
# ↓↓↓  A PARTIR D'ICI : garde-fous de SORTIE. INERTES en RAG-only.  ↓↓↓
#      Conserves car episode_context_cnn.policy_flags() les importe,
#      et l'etape "garde-fous" les reactivera.
# =====================================================================

# --- Politique de triage (garde-fous SOC) -----------------------------------
# Pre-filtre deterministe : desactive par defaut (une allowlist dure est
# contournable par masquerading, T1036). Laisser False = le LLM voit tout.
AUTO_CLOSE_ENABLED = False

# Primitives qui ne peuvent JAMAIS etre auto-classees false_positive.
# POLITIQUE SOC, pas verite terrain (un analyste ne clot jamais une creation
# de compte sans regarder).
NEVER_DISMISS_PROCESSES = {
    "useradd", "userdel", "usermod", "groupadd", "passwd", "chpasswd",
    "visudo", "chattr", "auditctl", "insmod", "modprobe",
}
NEVER_DISMISS_EVENT_TYPES = {
    "changed-audit-configuration", "changed-password",
}
NEVER_DISMISS_FAIL_BURST = 5     # n alertes 'is_fail' dominant dans un episode

# Verdicts autorises (schema ferme).
VERDICTS = ("true_positive", "false_positive", "uncertain")
SEVERITIES = ("info", "low", "medium", "high", "critical")

# Echec LLM (timeout, JSON invalide, quota) : on NE JETTE JAMAIS l'alerte.
# Fail-open = l'episode reste 'uncertain' et remonte a l'analyste.
FAIL_OPEN_VERDICT = "uncertain"

# --- exigence d'actionnabilite (garde-fou 8 de _validate) -------------------
MIN_RATIONALE_CHARS = 80
FALLBACK_RECOMMENDATION = (
    "Le modele n'a pas produit d'action exploitable : investigation manuelle "
    "requise (verifier processus, utilisateur et fenetre temporelle de l'episode)."
)