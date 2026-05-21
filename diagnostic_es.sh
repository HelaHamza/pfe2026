#!/bin/bash
# ============================================================
# diagnostic_es.sh
# Vérification des valeurs ES pour identifier les incohérences
# du dashboard IDS SOC
#
# Usage : bash diagnostic_es.sh
# ============================================================

ES="https://localhost:9200"
AUTH="elastic:pfe2026"
AE="ml-autoencoder-scores"
SIGMA="sigma-alerts"
CURSOR_INDEX="ids-pipeline-cursor"

echo ""
echo "════════════════════════════════════════════════════════"
echo " DIAGNOSTIC ES — IDS SOC Dashboard"
echo "════════════════════════════════════════════════════════"

# ── 1. Curseur actuel ─────────────────────────────────────────────────────────
echo ""
echo "── 1. CURSEUR ACTUEL ────────────────────────────────────"
CURSOR=$(curl -sk -u "$AUTH" "$ES/$CURSOR_INDEX/_doc/last_run" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['_source']['last_timestamp'])" 2>/dev/null)
echo "  cursor = $CURSOR"

# ── 2. AE : total documents dans l'index ─────────────────────────────────────
echo ""
echo "── 2. AE INDEX : ml-autoencoder-scores ─────────────────"

echo -n "  Total docs dans l'index (tous) : "
curl -sk -u "$AUTH" "$ES/$AE/_count" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])"

echo -n "  ae_is_anomaly = 1 (tous) : "
curl -sk -u "$AUTH" -H "Content-Type: application/json" \
  "$ES/$AE/_count" -d '{"query":{"term":{"ae_is_anomaly":1}}}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])"

echo -n "  ae_is_anomaly = 1 DEPUIS curseur : "
curl -sk -u "$AUTH" -H "Content-Type: application/json" \
  "$ES/$AE/_count" -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"ae_is_anomaly\":1}},{\"range\":{\"@timestamp\":{\"gt\":\"$CURSOR\"}}}]}}}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])"

echo ""
echo "  AE par source (ae_is_anomaly=1, tous) :"
curl -sk -u "$AUTH" -H "Content-Type: application/json" \
  "$ES/$AE/_search" -d '{
    "size":0,
    "query":{"term":{"ae_is_anomaly":1}},
    "aggs":{"by_src":{"terms":{"field":"log_source","size":10}}}
  }' | python3 -c "
import sys,json
d=json.load(sys.stdin)
for b in d['aggregations']['by_src']['buckets']:
    print(f'    {b[\"key\"]:10s} : {b[\"doc_count\"]}')
"

echo ""
echo "  AE par detection_source (tous) :"
curl -sk -u "$AUTH" -H "Content-Type: application/json" \
  "$ES/$AE/_search" -d '{
    "size":0,
    "query":{"term":{"ae_is_anomaly":1}},
    "aggs":{"by_det":{"terms":{"field":"detection_source","size":10}}}
  }' | python3 -c "
import sys,json
d=json.load(sys.stdin)
for b in d['aggregations']['by_det']['buckets']:
    print(f'    {b[\"key\"]:15s} : {b[\"doc_count\"]}')
"

# ── 3. SIGMA : total documents dans l'index ───────────────────────────────────
echo ""
echo "── 3. SIGMA INDEX : sigma-alerts ───────────────────────"

echo -n "  Total docs dans l'index (tous) : "
curl -sk -u "$AUTH" "$ES/$SIGMA/_count" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])"

echo -n "  Total alertes DEPUIS curseur : "
curl -sk -u "$AUTH" -H "Content-Type: application/json" \
  "$ES/$SIGMA/_count" -d "{\"query\":{\"range\":{\"@timestamp\":{\"gt\":\"$CURSOR\"}}}}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])"

echo ""
echo "  Sigma par alert.level (tous) :"
curl -sk -u "$AUTH" -H "Content-Type: application/json" \
  "$ES/$SIGMA/_search" -d '{
    "size":0,
    "aggs":{"by_level":{"terms":{"field":"alert.level","size":10}}}
  }' | python3 -c "
import sys,json
d=json.load(sys.stdin)
total=0
for b in d['aggregations']['by_level']['buckets']:
    print(f'    {b[\"key\"]:10s} : {b[\"doc_count\"]}')
    total += b['doc_count']
print(f'    TOTAL BUCKETS : {total}')
"

echo ""
echo "  Sigma par alert.level DEPUIS curseur :"
curl -sk -u "$AUTH" -H "Content-Type: application/json" \
  "$ES/$SIGMA/_search" -d "{
    \"size\":0,
    \"query\":{\"range\":{\"@timestamp\":{\"gt\":\"$CURSOR\"}}},
    \"aggs\":{\"by_level\":{\"terms\":{\"field\":\"alert.level\",\"size\":10}}}
  }" | python3 -c "
import sys,json
d=json.load(sys.stdin)
total=0
for b in d['aggregations']['by_level']['buckets']:
    print(f'    {b[\"key\"]:10s} : {b[\"doc_count\"]}')
    total += b['doc_count']
print(f'    TOTAL BUCKETS : {total}')
"

echo ""
echo "  Sigma ae_correlated=true (tous) :"
curl -sk -u "$AUTH" -H "Content-Type: application/json" \
  "$ES/$SIGMA/_count" -d '{"query":{"term":{"ae_correlated":true}}}' \
  | python3 -c "import sys,json; print('   ', json.load(sys.stdin)['count'])"

echo ""
echo "  Sigma detection_source par valeur (tous) :"
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

# ── 4. Vérification champs présents dans sigma ────────────────────────────────
echo ""
echo "── 4. CHAMPS SIGMA — vérification mapping ───────────────"
echo "  Champs indexés dans sigma-alerts :"
curl -sk -u "$AUTH" "$ES/$SIGMA/_mapping" \
  | python3 -c "
import sys,json
m=json.load(sys.stdin)
idx=list(m.keys())[0]
props=m[idx]['mappings'].get('properties',{})
for k in sorted(props.keys()):
    print(f'    {k}')
"

# ── 5. Exemple de document sigma (1 doc) ─────────────────────────────────────
echo ""
echo "── 5. EXEMPLE DOCUMENT sigma-alerts (dernier) ───────────"
curl -sk -u "$AUTH" -H "Content-Type: application/json" \
  "$ES/$SIGMA/_search" -d '{"size":1,"sort":[{"@timestamp":{"order":"desc"}}]}' \
  | python3 -c "
import sys,json
d=json.load(sys.stdin)
hits=d['hits']['hits']
if hits:
    src=hits[0]['_source']
    for k,v in sorted(src.items()):
        print(f'    {k:30s} = {str(v)[:80]}')
"

# ── 6. Exemple de document AE (1 doc anomalie) ───────────────────────────────
echo ""
echo "── 6. EXEMPLE DOCUMENT ml-autoencoder-scores (anomalie) ─"
curl -sk -u "$AUTH" -H "Content-Type: application/json" \
  "$ES/$AE/_search" -d '{"size":1,"query":{"term":{"ae_is_anomaly":1}},"sort":[{"@timestamp":{"order":"desc"}}]}' \
  | python3 -c "
import sys,json
d=json.load(sys.stdin)
hits=d['hits']['hits']
if hits:
    src=hits[0]['_source']
    for k,v in sorted(src.items()):
        print(f'    {k:30s} = {str(v)[:80]}')
"

echo ""
echo "════════════════════════════════════════════════════════"
echo " FIN DU DIAGNOSTIC"
echo "════════════════════════════════════════════════════════"
echo ""