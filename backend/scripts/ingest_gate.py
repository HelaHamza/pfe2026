"""CLI de backfill du domaine C. La logique de lecture vit dans
GateAdapter ; ce script ne fait qu'orchestrer lecture + persistance,
exactement comme le pipeline. Utile pour ingérer un gate sans relancer
une analyse."""
import sys

from adapters.gate_adapter import GateAdapter
from repositories.retrain_repository import RetrainRepository


def main() -> None:
    doc = GateAdapter.load_latest()
    if not doc:
        print("ERREUR : aucun gate_*.json trouvé.")
        sys.exit(1)
    RetrainRepository.insert_gate(doc)
    print(f"✓ Gate {doc.created_at} ({doc.verdict}) ingéré. "
          f"Quarantaine : {doc.quarantine_count} incident(s).")


if __name__ == "__main__":
    main()