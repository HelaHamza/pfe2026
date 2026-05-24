"""
=============================================================================
scripts/ingest_metrics.py
Ingère un evaluation_report.json dans MongoDB.
Usage : python -m scripts.ingest_metrics ../evaluation_report.json
=============================================================================
"""
import json
import sys

from models.metrics_model import MetricsRepository


def ingest(path: str):
    with open(path, "r", encoding="utf-8") as f:
        metrics = json.load(f)
    repo = MetricsRepository()
    version = repo.insert_metrics(metrics)
    total = repo.count_versions()
    print(f"✓ Version '{version}' ingérée. {total} version(s) en base.")
    if total < 2:
        print("  ℹ Une seule version : le comparatif s'activera au prochain entraînement.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage : python -m scripts.ingest_metrics <evaluation_report.json>")
        sys.exit(1)
    ingest(sys.argv[1])