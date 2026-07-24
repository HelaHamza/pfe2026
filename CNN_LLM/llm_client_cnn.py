"""
llm_client_cnn.py
=================
Client LLM (GroqCloud, API compatible OpenAI) avec les proprietes exigees par
un usage securite ET par une soutenance :

  * DETERMINISME  : temperature=0 + seed -> deux executions donnent le meme
                    rapport. Indispensable : un jury doit pouvoir rejouer.
  * CACHE DISQUE  : hash(model+prompt) -> reponse. Rejouer le pipeline coute
                    0 appel et 0 token, et garantit la stabilite des chiffres.
  * RETRY         : backoff exponentiel sur 429/5xx (le tier gratuit Groq est
                    rate-limite), puis repli sur un modele secondaire.
  * FAIL-OPEN     : si tout echoue, on leve LLMError -> l'appelant conserve
                    l'alerte en 'uncertain'. On ne perd JAMAIS une alerte a
                    cause d'une panne d'API.

Note modele : Groq a annonce le 17/06/2026 la depreciation de
llama-3.3-70b-versatile / llama-3.1-8b-instant au profit de openai/gpt-oss-120b
et openai/gpt-oss-20b. Utiliser `python llm_client_cnn.py --models` pour lister
les modeles reellement actifs sur le compte avant la soutenance.
"""
from __future__ import annotations

import hashlib
import json
import os
import time

import config_llm_cnn as CL


class LLMError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
def _cache_key(model: str, messages: list[dict]) -> str:
    raw = json.dumps({"m": model, "msg": messages, "t": CL.LLM_TEMPERATURE},
                     sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()[:32]


def _cache_get(key: str) -> str | None:
    if not CL.LLM_CACHE_ENABLED:
        return None
    p = os.path.join(CL.LLM_CACHE_DIR, key + ".json")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            return f.read()
    return None


def _cache_put(key: str, value: str) -> None:
    if not CL.LLM_CACHE_ENABLED:
        return
    os.makedirs(CL.LLM_CACHE_DIR, exist_ok=True)
    with open(os.path.join(CL.LLM_CACHE_DIR, key + ".json"), "w",
              encoding="utf-8") as f:
        f.write(value)


# ---------------------------------------------------------------------------
_CLIENT = None


def _diagnose_missing_key() -> str:
    """Message d'erreur utile plutot que 'GROQ_API_KEY absent'.

    La confusion GROK (xAI) / GROQ (inference) coute regulierement une demi-
    heure de debug : la cle est bien dans le .env, elle est simplement lue
    sous un autre nom. Autant que le code le dise.
    """
    fautes = ["GROK_API_KEY", "GROQ_API_TOKEN", "GROQ_KEY", "GROQAPI_KEY",
              "GROQ_API", "API_KEY_GROQ"]
    presentes = [f for f in fautes if os.getenv(f)]
    ou = CL.DOTENV_PATH or "AUCUN .env trouve"
    msg = [f"GROQ_API_KEY introuvable (.env lu : {ou})"]
    if presentes:
        msg.append("")
        for f in presentes:
            msg.append(f"  -> '{f}' est definie, mais le code lit 'GROQ_API_KEY'.")
        if "GROK_API_KEY" in presentes:
            msg.append("     Attention : Grok (K) = xAI. Groq (Q) = l'inference "
                       "utilisee ici. Un seul caractere d'ecart.")
        msg.append("     Corriger le nom de la variable dans le .env.")
    else:
        env = os.path.join(CL.BASE_DIR, ".env")
        if not os.path.exists(env):
            msg.append(f"  -> aucun fichier .env : cp .env.example .env")
        else:
            msg.append(f"  -> {env} existe mais ne definit pas GROQ_API_KEY.")
        msg.append("     Cle : https://console.groq.com/keys")
    return "\n".join(msg)


def _client():
    global _CLIENT
    if _CLIENT is None:
        if CL.LLM_PROVIDER == "ollama":
            raise LLMError("_client() n'est pas utilise en mode ollama")
        if not CL.GROQ_API_KEY:
            raise LLMError(_diagnose_missing_key())
        if not CL.GROQ_API_KEY.startswith("gsk_"):
            raise LLMError(
                "GROQ_API_KEY ne commence pas par 'gsk_' : cle probablement "
                "tronquee, mal copiee, ou provenant d'un autre fournisseur.")
        try:
            from groq import Groq
        except ImportError as e:
            raise LLMError("pip install groq") from e
        _CLIENT = Groq(api_key=CL.GROQ_API_KEY, timeout=CL.LLM_TIMEOUT_S)
    return _CLIENT


# Dates de fin de service annoncees par Groq (console.groq.com/docs/deprecations).
# Fige une photo du 16/07/2026 : cette table PERIME, elle sert d'avertissement,
# pas de verite. La verite reste la page de deprecation et l'API elle-meme.
SHUTDOWN_DATES = {
    "qwen/qwen3-32b": "2026-07-17",
    "meta-llama/llama-4-scout-17b-16e-instruct": "2026-07-17",
    "llama-3.1-8b-instant": "2026-08-16",
    "llama-3.3-70b-versatile": "2026-08-16",
}


def _shutdown_note(model: str) -> str:
    """Avertissement lisible sur la fin de vie d'un modele."""
    import datetime
    d = SHUTDOWN_DATES.get(model)
    if not d:
        return ""
    reste = (datetime.date.fromisoformat(d) - datetime.date.today()).days
    if reste < 0:
        return f"  [HORS SERVICE depuis le {d}]"
    if reste == 0:
        return f"  [ARRET AUJOURD'HUI {d}]"
    return f"  [arret le {d} -- dans {reste} j]"


def list_models() -> list[str]:
    """Verite terrain sur les modeles actifs -> a lancer avant la soutenance."""
    if CL.LLM_PROVIDER == "ollama":
        import urllib.error
        import urllib.request
        url = f"{CL.LLM_BASE_URL.rstrip('/')}/models"
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                return sorted(m["id"] for m in json.loads(r.read())["data"])
        except urllib.error.URLError as e:
            raise LLMError(
                f"Ollama injoignable sur {CL.LLM_BASE_URL} ({e}).\n"
                f"  Demarrer : ollama serve") from e
    return sorted(m.id for m in _client().models.list().data)


def check_configured_model() -> None:
    """Le modele configure est-il vivant ? A lancer avant tout run evalue."""
    for label, m in (("principal", CL.LLM_MODEL), ("repli", CL.LLM_MODEL_FALLBACK)):
        note = _shutdown_note(m)
        etat = note.strip() if note else "pas de fin de service annoncee"
        print(f"  modele {label:9s} : {m:42s} {etat}")
    if _shutdown_note(CL.LLM_MODEL):
        print("\n  /!\\ Le modele principal a une date d'arret : migrer avant le run\n"
              "      evalue, sinon les chiffres du memoire ne seront pas rejouables.")


def _call(model: str, messages: list[dict]) -> str:
    if CL.LLM_PROVIDER == "ollama":
        return _call_ollama(model, messages)
    kwargs = dict(
        model=model, messages=messages,
        temperature=CL.LLM_TEMPERATURE,
        max_tokens=CL.LLM_MAX_TOKENS,
        seed=CL.LLM_SEED,
        response_format={"type": "json_object"},   # JSON mode natif Groq
    )
    if model.startswith("openai/gpt-oss"):
        kwargs["reasoning_effort"] = CL.LLM_REASONING_EFFORT
    r = _client().chat.completions.create(**kwargs)
    return r.choices[0].message.content


def _call_ollama(model: str, messages: list[dict]) -> str:
    """Inference LOCALE via Ollama (endpoint compatible OpenAI).

    Raison d'etre : un IDS qui envoie ses journaux a une API tierce est
    inacceptable en production (noms d'utilisateurs, IP, chemins de binaires).
    Ce chemin prouve que le choix du fournisseur est un PARAMETRE et non une
    dependance architecturale : seule l'URL de base change, aucun autre module
    n'est touche.

    Ecrit avec urllib (stdlib) : ajouter une dependance juste pour parler a
    localhost serait absurde.
    """
    import urllib.error
    import urllib.request

    payload = json.dumps({
        "model": model,
        "messages": messages,
        "temperature": CL.LLM_TEMPERATURE,
        "max_tokens": CL.LLM_MAX_TOKENS,
        "seed": CL.LLM_SEED,
        "response_format": {"type": "json_object"},
        "stream": False,
    }).encode()

    req = urllib.request.Request(
        f"{CL.LLM_BASE_URL.rstrip('/')}/chat/completions",
        data=payload,
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer ollama"},   # ignore, mais attendu
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=CL.LLM_TIMEOUT_S) as resp:
            body = json.loads(resp.read())
    except urllib.error.URLError as e:
        raise LLMError(
            f"Ollama injoignable sur {CL.LLM_BASE_URL} ({e}).\n"
            f"  Demarrer le serveur :  ollama serve\n"
            f"  Telecharger le modele : ollama pull {model}") from e
    except TimeoutError as e:
        raise LLMError(
            f"Ollama : timeout apres {CL.LLM_TIMEOUT_S}s. Sur CPU, un prompt "
            f"de ~4500 tokens peut depasser plusieurs minutes -> augmenter "
            f"LLM_TIMEOUT_S ou choisir un modele plus petit.") from e
    try:
        return body["choices"][0]["message"]["content"]
    except (KeyError, IndexError) as e:
        raise LLMError(f"Ollama : reponse inattendue {str(body)[:200]}") from e


def complete_json(messages: list[dict], model: str | None = None) -> dict:
    """Appel + parsing JSON, avec cache, retry et repli de modele.
    Leve LLMError si tout echoue -> l'appelant applique le fail-open."""
    model = model or CL.LLM_MODEL
    key = _cache_key(model, messages)
    cached = _cache_get(key)
    if cached is not None:
        return json.loads(cached)

    last_err: Exception | None = None
    for model_try in (model, CL.LLM_MODEL_FALLBACK):
        if not model_try:
            continue
        for attempt in range(CL.LLM_MAX_RETRIES):
            try:
                txt = _call(model_try, messages)
                data = json.loads(_strip_fences(txt))
                _cache_put(_cache_key(model_try, messages),
                           json.dumps(data, ensure_ascii=False))
                if model_try != model:
                    _cache_put(key, json.dumps(data, ensure_ascii=False))
                return data
            except json.JSONDecodeError as e:
                last_err = e
                # Reparation : on renvoie sa propre sortie invalide au modele.
                messages = messages + [
                    {"role": "assistant", "content": txt[:2000]},
                    {"role": "user", "content":
                     "Ta reponse n'est pas un JSON valide. Renvoie UNIQUEMENT "
                     "l'objet JSON conforme au schema, sans aucun autre texte."},
                ]
            except Exception as e:                       # noqa: BLE001
                last_err = e
                msg = str(e).lower()
                if "decommission" in msg or "not found" in msg or "model" in msg:
                    break                                # -> modele de repli
                time.sleep(CL.LLM_BACKOFF_S * (2 ** attempt))
    raise LLMError(f"echec LLM ({model}) : {last_err}")


def _strip_fences(txt: str) -> str:
    t = (txt or "").strip()
    if t.startswith("```"):
        t = t.split("```")[1]
        t = t[4:] if t.lower().startswith("json") else t
    i, j = t.find("{"), t.rfind("}")
    return t[i:j + 1] if i != -1 and j != -1 else t


if __name__ == "__main__":
    import sys
    if "--models" in sys.argv:
        print(f"Fournisseur : {CL.LLM_PROVIDER}\n")
        for m in list_models():
            print(f"  {m}{_shutdown_note(m)}")
        print()
        check_configured_model()
    else:
        print(complete_json([
            {"role": "system", "content": "Reponds en JSON."},
            {"role": "user", "content": 'Renvoie {"ok": true, "modele": "..."}'},
        ]))