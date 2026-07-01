
#!/bin/bash
set -e
echo "[1/5] Injection red-team (sudo)..."
sudo python3 groundtruth.py

echo "[2/5] Attente ingestion ES (150s)..."
sleep 150

echo "[3/5] Invalidation cache + training..."
rm -f dataset_snapshot.parquet
python training.py

echo "[4/5] Inference..."
python inference.py

echo "[5/5] Mesure rappel / precision..."
python evaluate.py
