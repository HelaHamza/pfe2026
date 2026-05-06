from knowledge_base import THREAT_KNOWLEDGE
#moteur rag

def retrieve_threats(anomaly_row: dict, top_k: int = 3) -> list:
    """
    Cherche les menaces les plus pertinentes selon
    les indicateurs activés dans l'événement anormal.
    """
    # Indicateurs activés dans l'anomalie
    activated = set()
    for feat, val in anomaly_row.items():
        if val in (1, True, "1"):
            activated.add(feat)
        elif isinstance(val, (int, float)) and val > 0.5:
            activated.add(feat)

    # Score de chaque menace = nombre d'indicateurs en commun
    scores = []
    for threat in THREAT_KNOWLEDGE:
        overlap = len(set(threat["indicators"]) & activated)
        if overlap > 0:
            scores.append((threat, overlap))

    scores.sort(key=lambda x: x[1], reverse=True)
    return [t for t, _ in scores[:top_k]]


def format_context(threats: list) -> str:
    """Formate les menaces pour le prompt LLM."""
    if not threats:
        return "Aucune menace connue ne correspond exactement."

    lines = []
    for t in threats:
        lines.append(f"[{t['severity']}] {t['title']} — MITRE {t['mitre']}")
        lines.append(f"  {t['description']}")
        lines.append(f"  Actions : {' | '.join(t['remediation'][:2])}")
        lines.append("")

    return "\n".join(lines)