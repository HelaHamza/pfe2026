# test_integration.py
"""
Teste le pipeline complet sur des logs synthétiques.
Lance SANS clé Groq — vérifie uniquement le routing et l'écriture ES.
"""
import os, json, ssl, base64, urllib.request
from fusion_router import FusionRouter, DetectionSource

ES_HOST = "https://localhost:9200"
ES_USER = "elastic"
ES_PASS = os.getenv("ELASTIC_PWD", "pfe2026")

def es_req(path, body=None, method=None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    token   = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
    headers = {"Content-Type": "application/json",
               "Authorization": f"Basic {token}"}
    url  = f"{ES_HOST}{path}"
    data = json.dumps(body).encode() if body else None
    m    = method or ("POST" if body else "GET")
    req  = urllib.request.Request(url, data=data, headers=headers, method=m)
    return json.loads(urllib.request.urlopen(req, context=ctx).read())

# ── 4 logs de test représentant les 4 cas ───────────────────────
TEST_CASES = [
    {
        "name": "CAS 1 — BOTH (brute force confirmé)",
        "log":  {"log_source": "auth", "hour_of_day": 3,
                 "auth_is_brute_force": 1, "auth_fail_count_5m": 12,
                 "composite_score": 8},
        "sigma_matches": ["SSH Rapid Connection Attempts"],
        "ae_score": 0.91,
        "expected": DetectionSource.BOTH,
    },
    {
        "name": "CAS 2 — SIGMA ONLY (pattern connu, AE normal)",
        "log":  {"log_source": "auth", "hour_of_day": 14,
                 "auth_is_brute_force": 1, "composite_score": 5},
        "sigma_matches": ["SSH Multiple Users from Same IP"],
        "ae_score": 0.40,
        "expected": DetectionSource.SIGMA_ONLY,
    },
    {
        "name": "CAS 3 — AE ONLY (anomalie inconnue)",
        "log":  {"log_source": "auditd", "hour_of_day": 2,
                 "aud_cmd_entropy": 5.2, "composite_score": 3},
        "sigma_matches": [],
        "ae_score": 0.88,
        "expected": DetectionSource.AE_ONLY,
    },
    {
        "name": "CAS 4 — NONE (log normal)",
        "log":  {"log_source": "syslog", "hour_of_day": 10,
                 "composite_score": 0},
        "sigma_matches": [],
        "ae_score": 0.15,
        "expected": DetectionSource.NONE,
    },
]

def run():
    router = FusionRouter(ae_threshold=0.75)
    passed, failed = 0, 0

    print("\n" + "="*60)
    print("  TEST INTÉGRATION FUSION ROUTER")
    print("="*60)

    for tc in TEST_CASES:
        result = router.route(tc["log"], tc["sigma_matches"], tc["ae_score"])
        ok     = result.source == tc["expected"]
        icon   = "✓" if ok else "✗"
        status = "PASS" if ok else f"FAIL (got {result.source.value})"
        print(f"\n  {icon} {tc['name']}")
        print(f"    Source   : {result.source.value}")
        print(f"    Sévérité : {result.severity}")
        print(f"    Statut   : {status}")
        if ok: passed += 1
        else:  failed += 1

    print(f"\n{'='*60}")
    print(f"  RÉSULTAT : {passed}/{len(TEST_CASES)} tests passés")
    print("="*60)

    # Vérification ES — les index existent-ils ?
    print("\n  Vérification des index ES...")
    for idx in ["sigma-alerts", "ml-autoencoder-scores", "ids-fusion-alerts"]:
        try:
            es_req(f"/{idx}")
            print(f"  ✓ {idx}")
        except Exception:
            print(f"  ✗ {idx} — absent ou inaccessible")

if __name__ == "__main__":
    run()