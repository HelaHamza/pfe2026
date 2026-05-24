#!/bin/bash
# ============================================================
# fix_es_data.sh
# Corrections des données ES identifiées par le diagnostic
#
# FIX 1 : Backfill detection_source=sigma_only sur les docs
#          sigma-alerts qui n'ont pas le champ
# FIX 2 : Vérification du seuil AE (ae_threshold trop bas)
#
# Usage : bash fix_es_data.sh
# ============================================================

ES="https://localhost:9200"
AUTH="elastic:pfe2026"
AE="ml-autoencoder-scores"
SIGMA="sigma-alerts"

echo ""
echo "════════════════════════════════════════════════════════"
echo " FIX ES — IDS SOC"
echo "════════════════════════════════════════════════════════"

# ── FIX 1 : Backfill detection_source sur sigma-alerts ───────────────────────
# 7362 docs n'ont pas le champ → fausse la répartition AE/Sigma/Both

echo ""
echo "── FIX 1 : Backfill detection_source dans sigma-alerts ─"

echo -n "  Docs SANS detection_source : "
curl -sk -u "$AUTH" -H "Content-Type: application/json" \
  "$ES/$SIGMA/_count" -d '{
    "query": {"bool": {"must_not": {"exists": {"field": "detection_source"}}}}
  }' | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])"

echo "  Application du backfill (update_by_query)..."
RESULT=$(curl -sk -u "$AUTH" -H "Content-Type: application/json" \
  -X POST "$ES/$SIGMA/_update_by_query?conflicts=proceed&wait_for_completion=true" -d '{
    "query": {
      "bool": {
        "must_not": {"exists": {"field": "detection_source"}}
      }
    },
    "script": {
      "source": "ctx._source.detection_source = \"sigma_only\"; ctx._source.ae_correlated = false;",
      "lang": "painless"
    }
  }')

UPDATED=$(echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('updated',0))")
echo "  ✓ $UPDATED documents mis à jour"

# ── Vérification après fix ────────────────────────────────────────────────────
echo ""
echo "  Sigma detection_source après fix :"
curl -sk -u "$AUTH" -H "Content-Type: application/json" \
  "$ES/$SIGMA/_search" -d '{
    "size":0,
    "aggs":{"by_det":{"terms":{"field":"detection_source","size":10}}}
  }' | python3 -c "
import sys,json
d=json.load(sys.stdin)
for b in d['aggregations']['by_det']['buckets']:
    print(f'    {b[\"key\"]:15s} : {b[\"doc_count\"]}')
"

# ── FIX 2 : Analyse du seuil AE ──────────────────────────────────────────────
echo ""
echo "── FIX 2 : Analyse seuil AE (ae_is_anomaly=1 sur 100%) ─"
echo ""
echo "  Distribution des ae_mse_error (percentiles) :"
curl -sk -u "$AUTH" -H "Content-Type: application/json" \
  "$ES/$AE/_search" -d '{
    "size": 0,
    "aggs": {
      "mse_percentiles": {
        "percentiles": {
          "field": "ae_mse_error",
          "percents": [50, 75, 90, 95, 99, 99.9]
        }
      },
      "mse_stats": {
        "extended_stats": {"field": "ae_mse_error"}
      }
    }
  }' | python3 -c "
import sys,json
d=json.load(sys.stdin)
aggs=d['aggregations']
print('  Percentiles ae_mse_error :')
for k,v in aggs['mse_percentiles']['values'].items():
    print(f'    p{k:5s} = {v:.6f}')
stats=aggs['mse_stats']
print(f'  Min   : {stats[\"min\"]:.6f}')
print(f'  Max   : {stats[\"max\"]:.6f}')
print(f'  Avg   : {stats[\"avg\"]:.6f}')
print(f'  StdDev: {stats[\"std_deviation\"]:.6f}')
"

echo ""
echo "  Distribution ae_threshold actuel par source :"
curl -sk -u "$AUTH" -H "Content-Type: application/json" \
  "$ES/$AE/_search" -d '{
    "size": 0,
    "aggs": {
      "by_source": {
        "terms": {"field": "log_source", "size": 5},
        "aggs": {
          "thr_stats": {"stats": {"field": "ae_threshold"}},
          "mse_stats": {"stats": {"field": "ae_mse_error"}},
          "anomaly_count": {"filter": {"term": {"ae_is_anomaly": 1}}}
        }
      }
    }
  }' | python3 -c "
import sys,json
d=json.load(sys.stdin)
for b in d['aggregations']['by_source']['buckets']:
    src  = b['key']
    thr  = b['thr_stats']
    mse  = b['mse_stats']
    anom = b['anomaly_count']['doc_count']
    total= b['doc_count']
    pct  = 100*anom/total if total else 0
    print(f'  {src:8s}:')
    print(f'    threshold min/avg/max = {thr[\"min\"]:.4f} / {thr[\"avg\"]:.4f} / {thr[\"max\"]:.4f}')
    print(f'    mse       min/avg/max = {mse[\"min\"]:.4f} / {mse[\"avg\"]:.4f} / {mse[\"max\"]:.4f}')
    print(f'    anomalies = {anom}/{total} ({pct:.1f}%)')
"

echo ""
echo "  → Si pct ≈ 100% : le seuil ae_threshold est trop bas"
echo "    Vérifiez moe_thresholds.pkl et relancez l entraînement"
echo "    ou ajustez le percentile dans autoencodeur.py (get_threshold)"

# ── FIX 3 : Vérification curseur vs timestamp max dans AE ────────────────────
echo ""
echo "── FIX 3 : Cohérence curseur vs timestamps ──────────────"

echo -n "  Timestamp MIN dans AE : "
curl -sk -u "$AUTH" -H "Content-Type: application/json" \
  "$ES/$AE/_search" -d '{
    "size":0,
    "aggs":{"min_ts":{"min":{"field":"@timestamp"}},"max_ts":{"max":{"field":"@timestamp"}}}
  }' | python3 -c "
import sys,json
d=json.load(sys.stdin)
a=d['aggregations']
print()
print(f'    MIN : {a[\"min_ts\"][\"value_as_string\"]}')
print(f'    MAX : {a[\"max_ts\"][\"value_as_string\"]}')
"

echo -n "  Timestamp MIN dans Sigma : "
curl -sk -u "$AUTH" -H "Content-Type: application/json" \
  "$ES/$SIGMA/_search" -d '{
    "size":0,
    "aggs":{"min_ts":{"min":{"field":"@timestamp"}},"max_ts":{"max":{"field":"@timestamp"}}}
  }' | python3 -c "
import sys,json
d=json.load(sys.stdin)
a=d['aggregations']
print()
print(f'    MIN : {a[\"min_ts\"][\"value_as_string\"]}')
print(f'    MAX : {a[\"max_ts\"][\"value_as_string\"]}')
"

echo ""
echo "  Curseur actuel : 2026-05-13T19:25:44.000Z"
echo "  → Les docs AVANT ce timestamp ne sont PAS comptés dans les KPIs"
echo "  → C est normal si vous avez relancé l analyse"
echo "  → Si vous voulez tout recompter : resetlez le curseur :"
echo ""
echo "  curl -sk -u elastic:pfe2026 -X PUT https://localhost:9200/ids-pipeline-cursor/_doc/last_run \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"last_timestamp\": \"now-30d\"}'"

echo ""
echo "════════════════════════════════════════════════════════"
echo " FIN DES CORRECTIONS"
echo "════════════════════════════════════════════════════════"