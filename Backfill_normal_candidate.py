"""
=============================================================================
BACKFILL — Ajouter is_normal_candidate aux anciens logs ES
=============================================================================
Ce script lit les anciens logs qui n'ont pas is_normal_candidate,
recalcule le champ selon les mêmes critères que la Section 12 du filtre
Logstash, puis met à jour les documents ES via l'API update_by_query
ou bulk update.

UTILISATION :
    python3 backfill_normal_candidate.py

DURÉE ESTIMÉE :
    ~150 000 docs → environ 5-10 minutes selon la machine
=============================================================================
"""

import json, ssl, urllib.request, base64, time
import numpy as np
import pandas as pd

ES_HOST  = "https://localhost:9200"
ES_USER  = "elastic"
ES_PASS  = "pfe2026"
ES_INDEX = "filebeat-logs-*,auditbeat-*"

BATCH_SIZE = 500  # docs mis à jour par batch

def make_es_client():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    token   = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
    headers = {"Content-Type": "application/json",
               "Authorization": f"Basic {token}"}
    return ctx, headers

def es_request(path, body=None, method=None, ctx=None, headers=None):
    if ctx is None: ctx, headers = make_es_client()
    url  = f"{ES_HOST}{path}"
    data = json.dumps(body).encode() if body else None
    m    = method or ("POST" if body else "GET")
    req  = urllib.request.Request(url, data=data, headers=headers, method=m)
    resp = urllib.request.urlopen(req, context=ctx)
    return json.loads(resp.read())

# =============================================================================
# CALCUL DU MASQUE NORMAL (réplique exacte Section 12 du filtre Logstash)
# =============================================================================

# Flags d'attaque qui disqualifient un log comme "normal"
ATTACK_FLAGS = [
    "aud_reverse_shell",    "aud_process_injection",
    "aud_log_delete",       "aud_credential_access",
    "aud_ssh_key_implant",  "auth_is_brute_force",
    "auth_is_stuffing",     "cross_bruteforce_success",
    "sys_log_tamper",       "sys_module_load",
    "is_lateral_movement",  "aud_suspicious_combo",
]

def compute_normal_candidate(ml: dict) -> tuple:
    """
    Calcule is_normal_candidate et normal_reject_reason
    pour un document ml.* existant.

    Retourne (is_normal: int, reason: str)
    """
    def g(field, default=0):
        """Récupère un champ ml.* avec valeur par défaut."""
        v = ml.get(field, default)
        try:
            return float(v) if v is not None else default
        except (TypeError, ValueError):
            return default

    score = g("composite_score", 0)
    hour  = g("hour_of_day",     12)
    dow   = g("day_of_week",      3)

    # Critère 1 : score composite faible
    c1 = score < 2

    # Critère 2 : heures ouvrables (8h-18h)
    c2 = (8 <= hour <= 18)

    # Critère 3 : jour ouvrable (lun=1 ... ven=5)
    # Note : Logstash wday → 0=dim, 1=lun, ..., 6=sam
    c3 = (1 <= dow <= 5)

    # Critère 4 : aucun flag d'attaque
    c4 = all(g(f, 0) == 0 for f in ATTACK_FLAGS)

    if not c1:
        return 0, "score_high"
    elif not c2:
        return 0, "off_hours"
    elif not c3:
        return 0, "weekend"
    elif not c4:
        # Trouver quel flag est actif
        active = next((f for f in ATTACK_FLAGS if g(f, 0) == 1), "unknown")
        return 0, f"attack_flag:{active}"
    else:
        return 1, "none"


# =============================================================================
# MÉTHODE 1 — UPDATE_BY_QUERY (plus simple, moins de contrôle)
# =============================================================================

def backfill_via_update_by_query():
    """
    Utilise le Painless script d'ES pour mettre à jour directement
    tous les documents sans les charger en Python.
    
    Avantage : très rapide (tout se passe dans ES)
    Inconvénient : la logique est en Painless (JS-like), moins lisible
    """
    ctx, headers = make_es_client()

    print("Méthode update_by_query (Painless script dans ES)...")

    # Script Painless qui réplique exactement la Section 12 du filtre
    script = """
        def ml = ctx._source.ml;
        if (ml == null) return;
        
        def score = ml.composite_score != null ? ml.composite_score : 0;
        def hour  = ml.hour_of_day     != null ? ml.hour_of_day     : 12;
        def dow   = ml.day_of_week     != null ? ml.day_of_week     : 3;
        
        boolean c1 = score < 2;
        boolean c2 = (hour >= 8  && hour <= 18);
        boolean c3 = (dow  >= 1  && dow  <= 5);
        
        def flags = [
            'aud_reverse_shell', 'aud_process_injection',
            'aud_log_delete', 'aud_credential_access',
            'aud_ssh_key_implant', 'auth_is_brute_force',
            'auth_is_stuffing', 'cross_bruteforce_success',
            'sys_log_tamper', 'sys_module_load'
        ];
        boolean c4 = true;
        for (def f : flags) {
            if (ml[f] != null && ml[f] == 1) { c4 = false; break; }
        }
        
        String reason;
        int is_normal;
        if (!c1)      { reason = 'score_high';   is_normal = 0; }
        else if (!c2) { reason = 'off_hours';     is_normal = 0; }
        else if (!c3) { reason = 'weekend';       is_normal = 0; }
        else if (!c4) { reason = 'attack_flag';   is_normal = 0; }
        else          { reason = 'none';           is_normal = 1; }
        
        ml.is_normal_candidate  = is_normal;
        ml.normal_reject_reason = reason;
    """

    body = {
        "script": {
            "source": script,
            "lang":   "painless"
        },
        "query": {
            "bool": {
                "must":     [{"exists": {"field": "ml.log_source"}}],
                "must_not": [{"exists": {"field": "ml.is_normal_candidate"}}]
            }
        }
    }

    print("  Lancement update_by_query (peut prendre plusieurs minutes)...")
    try:
        result = es_request(
            f"/{ES_INDEX}/_update_by_query?wait_for_completion=true"
            f"&conflicts=proceed&refresh=true",
            body, ctx=ctx, headers=headers
        )
        updated = result.get("updated", 0)
        total   = result.get("total",   0)
        print(f"  ✓ {updated}/{total} documents mis à jour")
        return updated
    except Exception as e:
        print(f"  ✗ update_by_query échoué : {e}")
        print("  → Basculer sur la méthode bulk Python")
        return -1


# =============================================================================
# MÉTHODE 2 — BULK PYTHON (plus lent, plus robuste)
# =============================================================================

def backfill_via_bulk_python():
    """
    Charge les documents sans is_normal_candidate, calcule le champ
    en Python, puis les met à jour via bulk API.
    
    Avantage : logique Python, plus facile à déboguer
    Inconvénient : charge les données en mémoire
    """
    ctx, headers = make_es_client()

    # Requête scroll pour les docs SANS is_normal_candidate
    query = {
        "size": 2000,
        "query": {
            "bool": {
                "must":     [{"exists": {"field": "ml.log_source"}}],
                "must_not": [{"exists": {"field": "ml.is_normal_candidate"}}]
            }
        },
        "_source": [
            "ml.composite_score", "ml.hour_of_day", "ml.day_of_week",
            "ml.log_source",
        ] + [f"ml.{f}" for f in ATTACK_FLAGS],
    }

    data      = es_request(f"/{ES_INDEX}/_search?scroll=2m",
                           query, ctx=ctx, headers=headers)
    scroll_id = data["_scroll_id"]
    total     = data["hits"]["total"]["value"]
    processed = 0
    updated   = 0
    normal_count = 0
    reject_reasons = {}

    print(f"\n  Documents à mettre à jour : {total}")
    print(f"  Traitement par batch de {BATCH_SIZE}...")

    def process_batch(hits):
        nonlocal updated, normal_count, reject_reasons
        if not hits:
            return

        bulk = ""
        for hit in hits:
            doc_id = hit["_id"]
            index  = hit["_index"]
            ml     = hit.get("_source", {}).get("ml", {})

            is_normal, reason = compute_normal_candidate(ml)

            # Stats
            if is_normal == 1:
                normal_count += 1
            reject_reasons[reason] = reject_reasons.get(reason, 0) + 1

            # Bulk update
            bulk += json.dumps({
                "update": {"_index": index, "_id": doc_id}
            }) + "\n"
            bulk += json.dumps({
                "doc": {
                    "ml": {
                        "is_normal_candidate":  is_normal,
                        "normal_reject_reason": reason,
                    }
                }
            }) + "\n"

        if bulk:
            req = urllib.request.Request(
                f"{ES_HOST}/_bulk?refresh=false",
                data=bulk.encode(),
                headers=headers, method="POST"
            )
            result = json.loads(
                urllib.request.urlopen(req, context=ctx).read()
            )
            updated += len([i for i in result.get("items", [])
                            if not i.get("update", {}).get("error")])

    # Traiter le premier batch
    process_batch(data["hits"]["hits"])
    processed += len(data["hits"]["hits"])

    # Scroll pour les suivants
    page = 2
    while True:
        data = es_request(
            "/_search/scroll",
            {"scroll": "2m", "scroll_id": scroll_id},
            ctx=ctx, headers=headers
        )
        hits = data["hits"]["hits"]
        if not hits:
            break

        scroll_id  = data["_scroll_id"]
        processed += len(hits)
        process_batch(hits)

        if page % 10 == 0 or processed >= total:
            pct = processed / total * 100 if total > 0 else 0
            print(f"  Traité {processed:6d}/{total} ({pct:.0f}%) | "
                  f"mis à jour {updated:6d} | "
                  f"normaux {normal_count:6d}")
        page += 1

    # Forcer refresh
    es_request(f"/{ES_INDEX}/_refresh", method="POST",
               ctx=ctx, headers=headers)

    print(f"\n  ✓ Backfill terminé !")
    print(f"    Documents traités  : {processed}")
    print(f"    Documents mis à jour: {updated}")
    print(f"    Logs normaux       : {normal_count} "
          f"({normal_count/processed*100:.1f}%)")
    print(f"\n  Distribution raisons de rejet :")
    for r, c in sorted(reject_reasons.items(),
                       key=lambda x: -x[1]):
        pct = c / processed * 100 if processed > 0 else 0
        print(f"    {r:40s}: {c:7d} ({pct:.1f}%)")

    return normal_count


# =============================================================================
# VÉRIFICATION POST-BACKFILL
# =============================================================================

def verify_backfill():
    """Vérifie que le backfill a bien fonctionné."""
    ctx, headers = make_es_client()

    query = {
        "size": 0,
        "aggs": {
            "normal_dist": {
                "terms": {"field": "ml.is_normal_candidate", "size": 5}
            },
            "reject_reasons": {
                "terms": {
                    "field":  "ml.normal_reject_reason.keyword",
                    "size":   10,
                    "order":  {"_count": "desc"}
                }
            },
            "missing": {
                "missing": {"field": "ml.is_normal_candidate"}
            }
        }
    }

    data = es_request(f"/{ES_INDEX}/_search", query,
                      ctx=ctx, headers=headers)
    aggs = data.get("aggregations", {})

    total   = data["hits"]["total"]["value"]
    missing = aggs.get("missing", {}).get("doc_count", 0)

    print(f"\n  Vérification post-backfill :")
    print(f"    Total docs          : {total}")
    print(f"    Sans is_normal      : {missing}")

    print(f"\n    Valeurs is_normal_candidate :")
    for b in aggs.get("normal_dist", {}).get("buckets", []):
        pct = b['doc_count'] / total * 100
        label = "← normaux" if b['key'] == 1 else ""
        print(f"      valeur={b['key']} : {b['doc_count']:7d} ({pct:.1f}%) {label}")

    print(f"\n    Top raisons de rejet :")
    for b in aggs.get("reject_reasons", {}).get("buckets", []):
        pct = b['doc_count'] / total * 100
        print(f"      {b['key']:40s}: {b['doc_count']:7d} ({pct:.1f}%)")


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  BACKFILL — is_normal_candidate sur anciens logs")
    print("=" * 60)

    ctx, headers = make_es_client()

    # Compter les docs sans le champ
    count_query = {
        "query": {
            "bool": {
                "must":     [{"exists": {"field": "ml.log_source"}}],
                "must_not": [{"exists": {"field": "ml.is_normal_candidate"}}]
            }
        }
    }
    count_data = es_request(f"/{ES_INDEX}/_count", count_query,
                            ctx=ctx, headers=headers)
    n_missing  = count_data.get("count", 0)

    print(f"\n  Documents sans is_normal_candidate : {n_missing}")

    if n_missing == 0:
        print("  Tous les docs ont déjà le champ — rien à faire")
        verify_backfill()
        exit(0)

    print(f"\n  Choix de méthode :")
    print(f"  1. update_by_query (rapide, tout dans ES)")
    print(f"  2. bulk Python     (lent, robuste)")
    print(f"\n  Lancement méthode 1 (update_by_query)...")

    n_updated = backfill_via_update_by_query()

    # Si update_by_query échoue → fallback bulk Python
    if n_updated < 0:
        print(f"\n  Fallback méthode 2 (bulk Python)...")
        backfill_via_bulk_python()

    # Vérification
    print("\n" + "=" * 60)
    verify_backfill()
    print("\n  Backfill terminé — tu peux relancer le modèle ML")