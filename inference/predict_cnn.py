"""
CNN_LLM/predict_cnn.py — INFERENCE PRODUCTION CNN (curseur + watermark).

  python predict_cnn.py --until <ISO borne haute du run> [--since <curseur précédent>]

Sémantique du curseur (watermark de stabilisation)
--------------------------------------------------
  * Fenêtre chargée  : ]since - SEED_SECONDS, until]  (seed = réchauffage ;
    rareté ANCRÉE sur novelty_state gelé → le seed ne recrée AUCUNE stat).
  * watermark        : w = until - EPISODE_GAP_SECONDS.
  * Épisodes ÉMIS    : since < end <= w   (stabilisés ET nouveaux).
  * Épisodes RETENUS : end > w            (queue non figée → run suivant).
  * NOUVEAU curseur  : w  (dans cnn_run_meta.json ; l'orchestrateur avance
    pipeline_state vers CETTE valeur, JAMAIS vers `until`).

Invariant : un épisode complet est émis/triagé EXACTEMENT une fois (0 doublon
SOC, 0 double appel LLM) et aucun épisode n'est perdu à la frontière du run.
"""
from __future__ import annotations
import argparse
import json
import os
import sys

import joblib

_HERE = os.path.dirname(os.path.abspath(__file__))
_ML_DIR = os.path.expanduser("~/pfe-backend-2026/ML")
if _ML_DIR not in sys.path:
    sys.path.insert(0, _ML_DIR)

import pandas as pd

import config_cnn as CC
import cnn_features as FE
from live_loader import load_live
from Test_cnn import load_artifacts_cnn, aggregate_alerts
from train_eval_cnn import _score_df

SCORED_LIVE_CSV = os.path.join(_HERE, "cnn_scored_live.csv")
ALERTS_CSV      = os.path.join(_HERE, "cnn_alerts.csv")
CONTEXT_CSV     = os.path.join(_HERE, "cnn_alerts_context.csv")
EPISODES_CSV    = os.path.join(_HERE, "cnn_alerts_episodes.csv")
RUN_META_JSON   = os.path.join(_HERE, "cnn_run_meta.json")

_EP_COLS = ["log_source", "host_name", "start", "end", "duration_s", "n_alerts",
            "n_distinct_proc", "top_processes", "dominant_features",
            "mse_max", "mse_mean"]


def _parse_ts(value, name, required):
    """ISO -> Timestamp UTC tz-aware. Échoue BRUYAMMENT : un NaT silencieux
    rendrait `end > NaT` tout-faux et viderait l'affichage sans erreur."""
    if value is None:
        if required:
            print(f"ERREUR : --{name} est obligatoire.")
            sys.exit(2)
        return None
    ts = pd.to_datetime(value, utc=True, errors="coerce")
    if pd.isna(ts):
        print(f"ERREUR : --{name} invalide (ISO attendu) : {value!r}")
        sys.exit(2)
    return ts


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--until", required=True, help="Borne haute ISO (début du run, figé).")
    p.add_argument("--since", default=None, help="Curseur (watermark précédent). Absent = bootstrap.")
    args = p.parse_args()

    until_ts = _parse_ts(args.until, "until", required=True)
    since_ts = _parse_ts(args.since, "since", required=False)
    gap       = pd.Timedelta(seconds=CC.EPISODE_GAP_SECONDS)
    watermark = until_ts - gap

    print("=" * 64)
    print("  INFERENCE PRODUCTION CNN")
    print(f"  fenêtre : ]{args.since or 'BOOTSTRAP'} - SEED , {args.until}]")
    print(f"  watermark : {watermark.isoformat()}  (until - {int(gap.total_seconds())}s)")
    print("=" * 64)

    if since_ts is not None and watermark <= since_ts:
        print(f"ERREUR : fenêtre de run ({(until_ts - since_ts).total_seconds():.0f}s) "
              f"<= EPISODE_GAP ({int(gap.total_seconds())}s). Rien ne peut se "
              f"stabiliser ; curseur inchangé. Élargir l'intervalle du run.")
        sys.exit(3)

    for attr in ("MODEL_PATH", "BUNDLE_PATH", "THRESH_PATH", "NOVELTY_STATE_PATH"):
        pth = getattr(CC, attr, None)
        if not pth or not os.path.exists(pth):
            print(f"ERREUR : artefact introuvable ({attr}={pth}). Lancer train_eval_cnn.py.")
            sys.exit(4)

    model, scalers, vocabs, feats_by, thresholds = load_artifacts_cnn()

    novelty_state = joblib.load(CC.NOVELTY_STATE_PATH)
    df = FE.build_features(
        load_live(until=args.until, since=args.since, seed_seconds=CC.SEED_SECONDS),
        novelty_state=novelty_state,
    )
    print(f"\n[1] {len(df):,} logs à scorer (fenêtre incrémentale + seed)")

    print("\n[2] Scoring…")
    parts = []
    for s in scalers:
        d = df[df["log_source"] == s].reset_index(drop=True)
        if len(d) == 0:
            continue
        thr = float(thresholds[s]["threshold"])
        out = _score_df(model, d, feats_by[s], scalers[s], vocabs[s], s, thr)
        if len(out):
            parts.append(out)
            print(f"    {s:8s}: {int(out['is_alert'].sum()):5d} alertes / {len(out):,}")
    scored = pd.concat(parts, ignore_index=True) if parts else pd.DataFrame()

    if len(scored):
        scored["role"] = scored["log_source"].map(CC.SOURCE_ROLE).fillna("alert")
        fired   = scored[scored["is_alert"] == 1]
        primary = fired[fired["role"] == "alert"].copy()
        context = fired[fired["role"] == "correlation"].copy()
    else:
        primary = context = scored

    episodes = aggregate_alerts(primary)

    # [4] Curseur + watermark : émettre uniquement les épisodes STABILISÉS ET
    #     NOUVEAUX. Si end <= watermark, aucun événement t > until ne peut
    #     fusionner (il faudrait t <= end + gap <= until, contradiction) →
    #     DÉFINITIF. Si end > watermark, tronqué → retenu.
    held = 0
    if len(episodes):
        end     = episodes["end"]  # tz-aware UTC (cf. aggregate_alerts)
        settled = end <= watermark
        fresh   = (end > since_ts) if since_ts is not None else pd.Series(True, index=episodes.index)
        emit    = episodes[settled & fresh].reset_index(drop=True)
        held    = int((~settled).sum())
        print(f"\n[4] Émis : {len(emit)}  |  retenus (non stabilisés) : {held}  "
              f"|  total fenêtre : {len(episodes)}")
    else:
        emit = episodes
        print("\n[4] Aucun épisode dans la fenêtre.")

    scored.to_csv(SCORED_LIVE_CSV, index=False)
    if len(primary):
        primary.to_csv(ALERTS_CSV, index=False)
    if len(context):
        context.to_csv(CONTEXT_CSV, index=False)
    if emit is None or emit.shape[1] == 0:
        pd.DataFrame(columns=_EP_COLS).to_csv(EPISODES_CSV, index=False)
    else:
        emit.to_csv(EPISODES_CSV, index=False)

    meta = {
        "until": until_ts.isoformat(),
        "since": since_ts.isoformat() if since_ts is not None else None,
        "watermark": watermark.isoformat(),
        "next_cursor": watermark.isoformat(),
        "episode_gap_seconds": int(gap.total_seconds()),
        "seed_seconds": int(CC.SEED_SECONDS),
        "n_logs_scored": int(len(scored)),
        "n_episodes_window": int(len(episodes)),
        "n_episodes_emitted": int(len(emit)),
        "n_episodes_held": held,
    }
    with open(RUN_META_JSON, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print(f"\n  → {os.path.basename(EPISODES_CSV)} : {len(emit)} épisode(s) à triager")
    print(f"  → next_cursor (à stocker dans pipeline_state) : {watermark.isoformat()}")
    print("=" * 64)


if __name__ == "__main__":
    main()