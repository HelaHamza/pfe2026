"""
scripts/ingest_triage.py
========================
Attache le résumé de triage (CNN_LLM/cnn_triage_report.json) au document
report correspondant (sous-objet `triage`). Passerelle en attendant que
l'orchestrateur l'écrive directement à la fin du run.

Le rapport de triage ne porte pas de run_id → par défaut, dernier report
publiable ; --run-id pour cibler.

Usage (depuis backend/) :
    python -m scripts.ingest_triage ../CNN_LLM/cnn_triage_report.json
    python -m scripts.ingest_triage <fichier.json> --run-id <analysis_id>



"""
import argparse
import json
import os
import sys

from repositories.report_repository import ReportRepository

_KEEP = ("model", "provider", "temperature", "rag_backend", "n_kb_chunks",
         "n_episodes_reaggregated", "n_episodes_in", "n_alerts_in", "verdicts",
         "n_fail_open", "n_episodes_to_analyst", "noise_reduction_pct",
         "elapsed_s")


def _resolve_run_id(run_id: str | None) -> str:
    if run_id:
        return run_id
    last = ReportRepository.get_last_report()
    if not last:
        print("ERREUR : aucun report en base. Lance d'abord une analyse.")
        sys.exit(1)
    return last["analysis_id"]


def ingest(path: str, run_id: str | None) -> None:
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    summary = {k: raw[k] for k in _KEEP if k in raw}
    run_id = _resolve_run_id(run_id)
    ReportRepository.save_triage_summary(run_id, summary)
    print(f"✓ Résumé de triage attaché au report {run_id}.")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("triage_json", help="cnn_triage_report.json")
    ap.add_argument("--run-id", default=None, help="défaut = dernier report")
    args = ap.parse_args()
    if not os.path.exists(args.triage_json):
        print(f"ERREUR : {args.triage_json} introuvable.")
        sys.exit(1)
    ingest(args.triage_json, args.run_id)


if __name__ == "__main__":
    main()