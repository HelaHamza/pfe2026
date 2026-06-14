"""
=============================================================================
RAG EXPLAINER — v5 (adapté flux V9 : tri LLM côté fusion_router)
=============================================================================

CHANGEMENTS v5 (par rapport à v4) :
  1. explain_anomaly() NE court-circuite PLUS sur composite_score < LLM_MIN_SCORE.
     En V9, la décision "LLM vs template" est prise EN AMONT par
     FusionRouter.process_dataframe (tri par percentile de MSE par source).
     Quand explain_anomaly est appelé, c'est que l'anomalie a déjà été
     sélectionnée pour le LLM → on génère toujours l'explication.
     (composite_score n'est plus fiable en V9 : il dérive de mse/seuil et
      vaut quasi toujours 5+, ce qui faussait le filtre.)
  2. LLM_MIN_SCORE conservé UNIQUEMENT pour run_llm_explanation_pipeline()
     (pipeline standalone alternatif, non utilisé par le router V9).

CONSERVÉ de v4 :
  - SIGNAUX COMPORTEMENTAUX (ae_behavioral_signals) au cœur du prompt.
  - reconstruction du sous-dict "ml" (compat knowledge_base, complément).
  - retry 429 avec parse du délai Groq.
=============================================================================
"""

import os
import re
import ssl
import json
import time
import base64
import urllib.request
from openai import OpenAI
from dotenv import load_dotenv
from knowledge_base import retrieve_knowledge_context, get_max_severity, get_matched_entries

load_dotenv()

# =============================================================================
# SECTION A — CONFIGURATION
# =============================================================================

GROQ_API_KEY  = os.getenv("GROK_API_KEY")
GROK_MODEL = "llama-3.1-8b-instant"  # 500k TPD, 14 400 RPD


ES_HOST = os.getenv("ES_HOST", "https://localhost:9200")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASS = os.getenv("ELASTIC_PWD", "pfe2026")

RAG_INDEX     = "ml-autoencoder-scores"
# Conservé pour run_llm_explanation_pipeline() (standalone). Le flux V9 piloté
# par fusion_router ne l'utilise plus (tri par percentile MSE en amont).
LLM_MIN_SCORE = 6

# Features que knowledge_base.py utilise comme indicateurs (complément optionnel :
# en V9 ces flags ne sont plus produits par l'entraînement, mais s'ils existent
# dans le doc ES on les exploite quand même).
KB_INDICATOR_FEATURES = [
    # auth
    "auth_is_brute_force", "auth_is_slow_bruteforce", "auth_fail_count_5m",
    "auth_is_stuffing", "auth_is_user_enum",
    # auditd
    "aud_ptrace", "aud_suid_abuse", "aud_process_injection",
    "aud_log_tamper", "aud_log_delete", "aud_reverse_shell",
    "aud_cmd_is_obfuscated", "msg_has_base64",
    "is_lateral_movement", "sys_lateral_ssh", "cross_ssh_then_sudo",
    "cross_multi_source", "unique_hosts_accessed",
    "aud_exfiltration", "aud_network_scan",
    "aud_cryptominer", "sys_high_cpu_process",
    "aud_credential_access", "aud_ssh_key_implant",
    "aud_ld_hijack", "sys_module_load",
    "aud_cron_backdoor", "sys_cron_new_job",
    "auth_sudo_to_root",
    # syslog
    "sys_log_tamper",
]


# =============================================================================
# SECTION B — CLIENTS
# =============================================================================

def make_grok_client() -> OpenAI:
    if not GROQ_API_KEY:
        raise ValueError(
            "GROK_API_KEY absent du .env — "
            "récupère ta clé sur https://console.groq.com"
        )
    return OpenAI(
        api_key  = GROQ_API_KEY,
        base_url = "https://api.groq.com/openai/v1",
    )


def make_es_python_client():
    try:
        from elasticsearch import Elasticsearch
        return Elasticsearch(
            ES_HOST,
            basic_auth   = (ES_USER, ES_PASS),
            verify_certs = False,
        )
    except ImportError:
        print("  [RAG] elasticsearch-py absent — pip install elasticsearch")
        return None


# =============================================================================
# SECTION C — RECONSTRUCTION DU DICT ML (compat knowledge_base, complément)
# =============================================================================

def build_ml_dict(row: dict) -> dict:
    """
    Reconstruit le sous-dict {"ml": {...}} attendu par knowledge_base.py.
    En V9 les flags-verdict ne sont plus produits ; cette fonction reste utile
    UNIQUEMENT si le doc ES contient malgré tout d'anciens flags (complément).
    Valeur 0 par défaut sinon.
    """
    import math

    all_feature_keys = list(dict.fromkeys(KB_INDICATOR_FEATURES + [
        "log_source", "composite_score", "hour_of_day", "day_of_week",
        "is_off_hours", "is_night", "is_weekend", "is_business",
        "is_root", "auth_ip_is_external", "auth_known_country",
        "auth_fail_count_5m", "auth_fail_window_10m", "auth_fail_ratio",
        "auth_users_tried", "auth_severity", "auth_is_brute_force",
        "auth_is_stuffing", "aud_cmd_entropy", "aud_arg_count",
        "aud_cmd_is_obfuscated", "aud_severity", "aud_process_injection",
        "aud_ptrace", "sys_module_load", "sys_firewall_change",
        "sys_service_crash_loop", "sys_new_service", "sys_log_tamper",
    ]))

    ml = {}
    for key in all_feature_keys:
        v = row.get(key)
        if v is None:
            ml[key] = 0
            continue
        if key == "log_source":
            ml[key] = str(v)
            continue
        try:
            fv = float(v)
            ml[key] = 0 if (math.isnan(fv) or math.isinf(fv)) else fv
        except (TypeError, ValueError):
            ml[key] = 0

    return ml


# =============================================================================
# SECTION D — SIGNAUX COMPORTEMENTAUX + CONSTRUCTION DU PROMPT
# =============================================================================

def _parse_behavioral_signals(anomaly: dict) -> list:
    """Parse la colonne ae_behavioral_signals (str JSON ou liste) -> liste de dicts."""
    raw = anomaly.get("ae_behavioral_signals", "[]")
    try:
        items = json.loads(raw) if isinstance(raw, str) else (raw or [])
    except (ValueError, TypeError):
        items = []
    return items if isinstance(items, list) else []


def format_behavioral_signals(anomaly: dict) -> str:
    """Transforme ae_behavioral_signals en bloc texte lisible pour le LLM."""
    items = _parse_behavioral_signals(anomaly)
    if not items:
        return ("Aucun signal comportemental détaillé disponible "
                "(anomalie statistique globale, MSE élevé sans top-feature isolée).")
    lines = []
    for it in items:
        pct = f"p{it['percentile']}" if it.get("percentile") is not None else "p?"
        lines.append(
            f"  - {str(it.get('feature', '?')):24s} : "
            f"observé={it.get('observed', '?')}, "
            f"attendu≈{it.get('expected', '?')}  "
            f"({pct}, err_recon={it.get('recon_err', '?')})")
    return "\n".join(lines)


def build_prompt(anomaly: dict, knowledge_ctx: str,
                 detection_source: str = "ae_only") -> str:
    """
    Construit le prompt LLM. Le LLM raisonne d'abord sur les SIGNAUX
    COMPORTEMENTAUX (observé vs attendu), la base de connaissances n'étant
    qu'un complément si d'anciens flags existent.
    detection_source : "ae_only" | "sigma_only" | "both"
    """
    import math

    def get(key, default="?"):
        ml = anomaly.get("ml", {})
        v  = ml.get(key)
        if v is None:
            v = anomaly.get(key, default)
        if v is None:
            return default
        try:
            fv = float(v)
            return default if (math.isnan(fv) or math.isinf(fv)) else v
        except (TypeError, ValueError):
            return v

    src = get("log_source", "unknown")

    if detection_source == "both":
        correlation_block = """=== CORRÉLATION SIGMA + AUTOENCODER ===
ATTENTION : cette anomalie a été détectée simultanément par :
  - Une règle Sigma (pattern d'attaque connu)
  - L'autoencoder (comportement statistiquement anormal)
Double confirmation — criticité maximale. Prioriser la réponse immédiate.
"""
    elif detection_source == "sigma_only":
        correlation_block = """=== DÉTECTION SIGMA UNIQUEMENT ===
Pattern d'attaque connu détecté par règle Sigma.
L'autoencoder ne détecte pas d'anomalie statistique associée.
"""
    else:
        correlation_block = """=== ANOMALIE STATISTIQUE PURE (AUTOENCODER) ===
Aucune règle Sigma ne correspond. Comportement inconnu ou nouveau.
L'autoencoder détecte une déviation par rapport aux patterns normaux appris.
"""

    behavioral_block = format_behavioral_signals(anomaly)

    base = f"""Source          : {src}
Horodatage      : {anomaly.get('@timestamp', '?')}
Heure           : {get('hour_of_day')}h {'(weekend)' if get('is_weekend') else '(semaine)'}
Hors heures     : {'oui' if get('is_off_hours') else 'non'}
MSE score       : {anomaly.get('ae_mse_error', '?')}
Anomaly score   : {anomaly.get('ae_anomaly_score', '?')}
Composite score : {anomaly.get('composite_score', '?')}
Est root        : {'oui' if get('is_root') else 'non'}"""

    if src == "auth":
        extra = f"""
IP externe      : {'oui' if get('auth_ip_is_external') else 'non'}
Pays connu      : {'oui' if get('auth_known_country') else 'non'}
Échecs 5min     : {get('auth_fail_count_5m', 0)}
Échecs 10min    : {get('auth_fail_window_10m', 0)}
Ratio échecs    : {get('auth_fail_ratio', 0)}
Users testés    : {get('auth_users_tried', 1)}"""

    elif src == "auditd":
        entropy = get('aud_cmd_entropy', 0)
        try:
            entropy_fmt = f"{float(entropy):.3f}"
        except (ValueError, TypeError):
            entropy_fmt = str(entropy)
        extra = f"""
Entropie cmd    : {entropy_fmt}
Nb arguments    : {get('aud_arg_count', 0)}"""

    elif src == "syslog":
        extra = f"""
Volume msg      : {get('sys_msg_length_log', '?')}"""
    else:
        extra = ""

    prompt = f"""Tu es un expert SOC spécialisé en détection d'intrusion sur systèmes Linux.
Tu reçois une anomalie détectée par un IDS basé sur un autoencodeur.

{correlation_block}
=== SIGNAUX COMPORTEMENTAUX (autoencodeur) ===
Features les plus anormales (écart à la reconstruction normale apprise),
triées par contribution décroissante à l'erreur :
{behavioral_block}
MSE global : {anomaly.get('ae_mse_error', '?')} | score : {anomaly.get('composite_score', '?')}

=== BASE DE CONNAISSANCES (complément, si patterns connus) ===
{knowledge_ctx if knowledge_ctx else "Aucune technique pré-cataloguée — raisonne sur le comportement ci-dessus."}

=== ANOMALIE COURANTE ===
{base + extra}

=== INSTRUCTIONS ===
Réponds UNIQUEMENT en français avec ces 4 sections numérotées :

1. **Type d'attaque probable**
   Déduis le scénario le plus vraisemblable À PARTIR des signaux comportementaux
   (features anormales, valeurs observées vs attendues). Ne te limite pas à la
   base de connaissances : raisonne sur les écarts mesurés.

2. **Niveau de gravité** : [Critical / High / Medium / Low]
   Justifie en 1-2 phrases.

3. **Analyse détaillée**
   Explique pourquoi ces features sont suspectes. Cite les valeurs observées vs
   attendues et les percentiles.

4. **Actions recommandées**
   3-5 actions concrètes et priorisées pour le SOC.

Moins de 400 mots. Factuel uniquement.
"""
    return prompt


# =============================================================================
# SECTION E — RETRY 429 (FIX rate limit)
# =============================================================================

def parse_retry_seconds(error_message: str) -> float:
    """
    Extrait le délai d'attente depuis le message Groq 429.
    Format : "Please try again in 8m23.712s" ou "in 45.3s"
    Retourne le nombre de secondes (float), 60.0 par défaut.
    """
    m = re.search(r'in\s+(?:(\d+)m\s*)?(\d+(?:\.\d+)?)s', error_message)
    if m:
        minutes = float(m.group(1) or 0)
        seconds = float(m.group(2))
        return minutes * 60 + seconds
    return 60.0


def call_llm_with_retry(grok_client, messages, max_tokens=600,
                        temperature=0.1, max_retries=1):
    """
    Appelle Groq avec retry automatique sur 429.
    Parse le délai exact dans le message d'erreur, attend + 5s de marge.
    """
    for attempt in range(max_retries + 1):
        try:
            return grok_client.chat.completions.create(
                model       = GROK_MODEL,
                messages    = messages,
                max_tokens  = max_tokens,
                temperature = temperature,
            )
        except Exception as e:
            err_str = str(e)
            is_429  = "429" in err_str or "rate_limit_exceeded" in err_str

            if is_429 and attempt < max_retries:
                wait = parse_retry_seconds(err_str) + 5.0
                print(f"  [RAG] Rate limit 429 — attente {wait:.0f}s "
                      f"(tentative {attempt + 1}/{max_retries})...")
                time.sleep(wait)
                continue
            raise





def _parse_severity_from_llm(explanation: str) -> str:
    """
    Extrait le niveau de gravité depuis la réponse LLM.
    Le prompt impose : '**2. Niveau de gravité** : [Critical / High / Medium / Low]'
    Retourne "UNKNOWN" si rien n'est trouvé.
    """
    if not explanation:
        return "UNKNOWN"

    # Cherche la section gravité (insensible à la casse, accents inclus)
    patterns = [
        r"niveau\s+de\s+gravit[ée]\s*[:\-–]\s*\*{0,2}(Critical|High|Medium|Low)\*{0,2}",
        r"\*{0,2}(Critical|High|Medium|Low)\*{0,2}\s*[\n\r]",
        r"gravit[ée]\s*\*{0,2}\s*[:\-–]\s*\*{0,2}(Critical|High|Medium|Low)",
        r"\b(Critical|High|Medium|Low)\b",   # fallback : premier mot clé trouvé
    ]
    for pat in patterns:
        m = re.search(pat, explanation, re.IGNORECASE)
        if m:
            raw = m.group(1).strip().capitalize()
            mapping = {
                "Critical": "Critical",
                "High":     "High",
                "Medium":   "Medium",
                "Low":      "Low",
            }
            return mapping.get(raw, "UNKNOWN")
    return "UNKNOWN"

# =============================================================================
# SECTION F — APPEL GROQ
# =============================================================================

def explain_anomaly(anomaly: dict, es, grok_client, detection_source: str = 'ae_only') -> dict:
    """
    Génère l'explication LLM pour une anomalie DÉJÀ sélectionnée par le router.

    v5 : plus de court-circuit sur composite_score. En V9, la sélection
    LLM/template est faite en amont par FusionRouter (percentile MSE par
    source). Si on arrive ici, on génère l'explication, point.
    On reconstruit quand même anomaly["ml"] pour get_max_severity (complément KB).
    """
    # reconstruire ml AVANT tout — utile pour get_max_severity (complément KB)
    anomaly = dict(anomaly)
    ml_rebuilt = build_ml_dict(anomaly)
    if "ml" not in anomaly or not isinstance(anomaly.get("ml"), dict):
        anomaly["ml"] = ml_rebuilt
    else:
        for k, v in ml_rebuilt.items():
            if anomaly["ml"].get(k) is None:
                anomaly["ml"][k] = v

    knowledge_ctx = retrieve_knowledge_context(anomaly)
    prompt        = build_prompt(anomaly, knowledge_ctx, detection_source=detection_source)

    messages = [
        {
            "role":    "system",
            "content": (
                "Tu es un expert SOC spécialisé en détection d'intrusion "
                "sur systèmes Linux. Tu analyses des anomalies détectées "
                "par un IDS basé sur un autoencodeur. Tu réponds toujours "
                "en français, de manière concise et factuelle."
            ),
        },
        {"role": "user", "content": prompt},
    ]

    try:
        response    = call_llm_with_retry(grok_client, messages)
        explanation = response.choices[0].message.content
        error       = None
    except Exception as e:
        explanation = f"Erreur appel LLM : {type(e).__name__} — {e}"
        error       = str(e)
        print(f"  [RAG] LLM error: {e}")

    # <- indentation alignée avec le reste de la fonction (4 espaces)
    kb_sev  = get_max_severity(anomaly)
    llm_sev = _parse_severity_from_llm(explanation) if not error else "UNKNOWN"

    # Priorité : LLM > KB > "UNKNOWN"
    final_severity = (
        llm_sev if llm_sev != "UNKNOWN" else
        kb_sev  if kb_sev  != "UNKNOWN" else
        "UNKNOWN"
    )

    result = {
        "llm_model":        GROK_MODEL,
        "llm_explanation":  explanation,
        "rag_context_n":    0,
        "mitre_flags":      knowledge_ctx[:200] if knowledge_ctx else "aucun",
        "prompt_tokens":    len(prompt.split()),
        "kb_severity":      final_severity,
        "kb_severity_raw":  kb_sev,
        "detection_source": detection_source,
    }
    if error:
        result["llm_error"] = error

    return result

# =============================================================================
# SECTION G — PIPELINE PRINCIPAL (standalone alternatif — conserve LLM_MIN_SCORE)
# =============================================================================

def run_llm_explanation_pipeline(df_result, thresholds, min_score=6):
    """
    Pipeline d'explication LLM standalone (NON utilisé par le router V9).
    Conserve le filtre composite_score >= min_score pour compat ascendante.
    Utilise "_es_write_id" pour les updates dans ml-autoencoder-scores.
    """
    import pandas as pd

    try:
        grok = make_grok_client()
    except ValueError as e:
        print(f"\n  [LLM] Skipped — {e}")
        return

    es = make_es_python_client()

    try:
        scores    = pd.to_numeric(
            df_result.get("composite_score", 0), errors="coerce"
        ).fillna(0)
        anomalies = df_result.get("ae_is_anomaly", 0)
        has_es_id = df_result.get(
            "_es_write_id",
            pd.Series([None] * len(df_result), index=df_result.index)
        ).notna()

        mask          = (anomalies == 1) & (scores >= min_score) & has_es_id
        high_priority = df_result[mask].head(20)

    except Exception as e:
        print(f"\n  [LLM] Erreur filtrage : {e}")
        return

    if len(high_priority) == 0:
        n_anomalies = int((df_result.get("ae_is_anomaly", 0) == 1).sum())
        n_score     = int(((df_result.get("ae_is_anomaly", 0) == 1)
                           & (scores >= min_score)).sum())
        n_with_id   = int(((df_result.get("ae_is_anomaly", 0) == 1)
                           & (scores >= min_score) & has_es_id).sum())
        print(f"\n  [LLM] Aucune anomalie éligible :")
        print(f"         {n_anomalies} anomalies | "
              f"{n_score} score>={min_score} | {n_with_id} avec _es_write_id")
        return

    print(f"\n  [LLM] Explication {len(high_priority)} anomalies "
          f"(score >= {min_score})...")

    ctx_ssl = ssl.create_default_context()
    ctx_ssl.check_hostname = False
    ctx_ssl.verify_mode    = ssl.CERT_NONE
    token   = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
    headers = {
        "Content-Type":  "application/json",
        "Authorization": f"Basic {token}",
    }

    ok, errors = 0, 0
    for idx, row in high_priority.iterrows():
        anomaly_doc = row.to_dict()
        result      = explain_anomaly(anomaly_doc, es, grok)

        es_write_id = str(row.get("_es_write_id", ""))

        if es_write_id and es_write_id not in ("", "None", "nan"):
            try:
                update_payload = {k: v for k, v in result.items()
                                  if k != "ml"}
                body = json.dumps({"doc": update_payload}).encode()
                req  = urllib.request.Request(
                    f"{ES_HOST}/{RAG_INDEX}/_update/{es_write_id}",
                    data=body, headers=headers, method="POST"
                )
                urllib.request.urlopen(req, context=ctx_ssl)
                ok += 1
            except Exception as e:
                errors += 1
                print(f"  [LLM] Update error {es_write_id}: {e}")
        else:
            print(f"  [LLM] ⚠ pas d'_es_write_id pour idx={idx}")
            errors += 1

        src    = row.get("log_source", "?")
        score  = row.get("composite_score", "?")
        tokens = result.get("prompt_tokens", 0)
        sev    = result.get("kb_severity", "?")
        print(f"  [LLM] ✓ {str(src):8s} | score={score} | "
              f"sev={sev} | tokens={tokens}")

    print(f"  [LLM] Terminé — {ok} explications sauvegardées | {errors} erreurs ES")


# =============================================================================
# SECTION H — EXPLICATION TEMPLATE (sans LLM)
# =============================================================================

def generate_auto_explanation(anomaly: dict) -> dict:

    if "ml" not in anomaly or not isinstance(anomaly.get("ml"), dict):
        anomaly = dict(anomaly)
        anomaly["ml"] = build_ml_dict(anomaly)

    matched   = get_matched_entries(anomaly)
    severity  = get_max_severity(anomaly)
    src       = anomaly.get("log_source", "?")
    score     = anomaly.get("composite_score", 0)
    mse       = anomaly.get("ae_mse_error", 0)
    try:
        mse_fmt = f"{float(mse):.6f}"
    except (ValueError, TypeError):
        mse_fmt = str(mse)

    signals = _parse_behavioral_signals(anomaly)

    if not matched:
        # ---- Fallback comportemental (V9 : pas de flags) ----
        if signals:
            top = signals[0]
            feats_summary = ", ".join(
                f"{s.get('feature', '?')} (obs={s.get('observed', '?')}, "
                f"att≈{s.get('expected', '?')})"
                for s in signals[:3]
            )
            explanation = (
                f"**1. Type d'attaque probable**\n"
                f"Déviation comportementale sur source {src} — pas de pattern "
                f"pré-catalogué, à corréler manuellement.\n\n"
                f"**2. Niveau de gravité** : Medium\n"
                f"MSE : {mse_fmt}. "
                f"Écart significatif sur '{top.get('feature', '?')}'.\n\n"
                f"**3. Analyse détaillée**\n"
                f"Features les plus anormales : {feats_summary}. "
                f"Ces valeurs s'écartent nettement du comportement normal appris "
                f"(percentiles élevés), sans correspondre à une signature connue.\n\n"
                f"**4. Actions recommandées**\n"
                f"1. Inspecter le log brut et son contexte temporel\n"
                f"2. Vérifier les valeurs anormales ci-dessus auprès de la source\n"
                f"3. Comparer avec les logs normaux récents de la même source\n"
                f"4. Escalader si l'écart se confirme ou se répète"
            )
        else:
            explanation = (
                f"**1. Type d'attaque probable**\n"
                f"Anomalie statistique globale — MSE élevé sans feature isolée "
                f"ni signature connue.\n\n"
                f"**2. Niveau de gravité** : Low\n"
                f"MSE : {mse_fmt}\n\n"
                f"**3. Analyse détaillée**\n"
                f"Source {src} — erreur de reconstruction au-dessus du seuil sans "
                f"top-feature dominante. Possible bruit ou comportement rare légitime.\n\n"
                f"**4. Actions recommandées**\n"
                f"1. Vérifier le contexte temporel du log\n"
                f"2. Comparer avec les logs normaux de la même source\n"
                f"3. Classer comme faux positif si aucun incident confirmé"
            )
    else:
        # ---- KB matchée (complément, si d'anciens flags subsistent) ----
        attack_names = " + ".join(e["title"] for e in matched)
        mitre_list   = " | ".join(e["mitre"] for e in matched)
        remediations = []
        for e in matched:
            remediations.extend(e["remediation"][:2])
        seen, remediations_unique = set(), []
        for r in remediations:
            if r not in seen:
                seen.add(r)
                remediations_unique.append(r)
        rem_str = "\n".join(
            f"{i+1}. {r}" for i, r in enumerate(remediations_unique[:5])
        )
        behav_note = ""
        if signals:
            behav_note = (
                "\nFeatures comportementales anormales : "
                + ", ".join(f"{s.get('feature', '?')}" for s in signals[:3])
            )
        explanation = (
            f"**1. Type d'attaque probable**\n"
            f"{attack_names} sur source {src}.\n\n"
            f"**2. Niveau de gravité** : {severity}\n"
            f"MSE : {mse_fmt}\n\n"
            f"**3. Analyse détaillée**\n"
            f"Techniques MITRE détectées : {mitre_list}{behav_note}\n"
            f"Explication générée automatiquement par la base de connaissances.\n\n"
            f"**4. Actions recommandées**\n"
            f"{rem_str}"
        )

    # --- Sévérité finale : KB si matchée, sinon déduite du template (jamais UNKNOWN) ---
    if matched:
        final_severity = severity        # KB a matché, on lui fait confiance
    elif signals:
        final_severity = "Medium"        # déviation comportementale sans signature
    else:
        final_severity = "Low"           # anomalie globale sans feature dominante

    return {
        "llm_model":       "kb-auto-template",
        "llm_explanation": explanation,
        "rag_context_n":   len(matched),
        "mitre_flags":     " | ".join(e["mitre"] for e in matched)[:500],
        "prompt_tokens":   0,
        "kb_severity":     final_severity,   # <- plus jamais "UNKNOWN"
    }