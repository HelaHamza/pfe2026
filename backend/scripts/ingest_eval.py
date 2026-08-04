"""CLI de backfill du domaine E. La lecture vit dans EvalAdapter. Par défaut,
attache au dernier report ; --run-id pour cibler un run précis (recommandé si
plusieurs analyses ont tourné entre-temps)."""
import argparse
import sys

from adapters.eval_adapter import EvalAdapter
from repositories.report_repository import ReportRepository


def _resolve_run_id(run_id: str | None) -> str:
    if run_id:
        return run_id
    last = ReportRepository.get_last_report()
    if not last:
        print("ERREUR : aucun report en base. Lance d'abord une analyse.")
        sys.exit(1)
    return last["analysis_id"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", default=None, help="défaut = dernier report")
    args = ap.parse_args()

    loaded = EvalAdapter.load_summary()
    if not loaded:
        print(f"ERREUR : eval_summary.json introuvable ou illisible.")
        sys.exit(1)
    raw, mtime = loaded
    run_id = _resolve_run_id(args.run_id)
    ReportRepository.save_eval_comparison(run_id, raw)
    print(f"✓ Comparaison d'éval attachée au report {run_id} "
          f"(éval générée le {mtime.isoformat()}).")


if __name__ == "__main__":
    main()