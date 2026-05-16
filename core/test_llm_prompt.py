# test_llm_prompt.py
"""
Vérifie que les 3 prompts sont bien différenciés
et que Groq répond sans erreur.
Lance avec : python test_llm_prompt.py
"""
from rag_explainer import build_prompt, make_grok_client, call_llm_with_retry
from knowledge_base import retrieve_knowledge_context

ANOMALY = {
    "log_source": "auth", "@timestamp": "2026-05-15T03:12:00Z",
    "hour_of_day": 3, "is_off_hours": 1, "is_weekend": 0,
    "ae_mse_error": 0.92, "ae_anomaly_score": 0.95,
    "composite_score": 8, "is_root": 0,
    "ml": {
        "auth_is_brute_force": 1, "auth_fail_count_5m": 14,
        "auth_ip_is_external": 1, "auth_fail_ratio": 0.93,
        "auth_users_tried": 1, "auth_severity": 12,
    }
}

def test_prompt(detection_source: str):
    ctx   = retrieve_knowledge_context(ANOMALY)
    prompt = build_prompt(ANOMALY, ctx, detection_source=detection_source)

    # Vérifier que le bloc de corrélation est bien présent
    if detection_source == "both":
        assert "CORRÉLATION SIGMA" in prompt, "Bloc BOTH absent du prompt"
    elif detection_source == "sigma_only":
        assert "SIGMA UNIQUEMENT" in prompt
    else:
        assert "STATISTIQUE PURE" in prompt

    print(f"  ✓ Prompt {detection_source:12s} : {len(prompt.split())} mots")
    return prompt

if __name__ == "__main__":
    print("\n  Test construction des prompts...")
    for src in ["ae_only", "sigma_only", "both"]:
        test_prompt(src)

    # Test appel Groq réel (coûte des tokens)
    answer = input("\n  Tester l'appel Groq réel ? (o/N) : ")
    if answer.lower() == "o":
        grok  = make_grok_client()
        prompt = test_prompt("both")
        resp   = call_llm_with_retry(grok, [
            {"role": "system", "content": "Tu es un expert SOC Linux."},
            {"role": "user",   "content": prompt}
        ], max_tokens=300)
        print("\n  Réponse Groq :")
        print(resp.choices[0].message.content[:500])