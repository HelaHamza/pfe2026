#!/bin/bash
set -euo pipefail

ES="https://elasticsearch:9200"
CA="/usr/share/elasticsearch/config/certs/full-chain.crt"

# ─────────────────────────────────────────────
# Vérification des variables d'environnement
# ─────────────────────────────────────────────
: "${ELASTIC_PWD:?ELASTIC_PWD is not set}"
: "${KIBANA_PWD:?KIBANA_PWD is not set}"
: "${LOGSTASH_SYSTEM_PWD:?LOGSTASH_SYSTEM_PWD is not set}"
: "${LOGSTASH_WRITER_PWD:?LOGSTASH_WRITER_PWD is not set}"

# ─────────────────────────────────────────────
# Fonction utilitaire robuste
# ─────────────────────────────────────────────
call_es() {
  local desc="$1"
  local method="$2"
  local endpoint="$3"
  local data="${4:-}"

  echo "==> $desc..."
  echo "URL: $ES$endpoint"

  if [[ -n "$data" ]]; then
    http_code=$(curl -s -o /tmp/es_out.txt -w "%{http_code}" \
      -X "$method" "$ES$endpoint" \
      -u "elastic:${ELASTIC_PWD}" \
      -H "Content-Type: application/json" \
      --cacert "$CA" \
      -d "$data")
  else
    http_code=$(curl -s -o /tmp/es_out.txt -w "%{http_code}" \
      -X "$method" "$ES$endpoint" \
      -u "elastic:${ELASTIC_PWD}" \
      --cacert "$CA")
  fi

  echo "HTTP: $http_code"
  cat /tmp/es_out.txt
  echo ""

  if [[ "$http_code" -lt 200 || "$http_code" -ge 300 ]]; then
    echo "❌ Erreur sur: $desc"
    exit 1
  fi

  echo "✅ OK"
  echo ""
}

# ─────────────────────────────────────────────
# Attente Elasticsearch
# ─────────────────────────────────────────────
echo "==> Attente Elasticsearch..."

until curl -s --cacert "$CA" \
  -u "elastic:${ELASTIC_PWD}" \
  "$ES/_cluster/health?wait_for_status=yellow&timeout=5s" \
  | grep -q '"status"'; do

  echo "    Cluster pas prêt..."
  sleep 5
done

echo "✅ Cluster prêt"

# ─────────────────────────────────────────────
# Attente Security API
# ─────────────────────────────────────────────
echo "==> Attente Security API..."

until curl -s --cacert "$CA" \
  -u "elastic:${ELASTIC_PWD}" \
  "$ES/_security/_authenticate" \
  | grep -q '"username"'; do

  echo "    Security pas prête..."
  sleep 5
done

echo "✅ Security prête"

# ─────────────────────────────────────────────
# Vérification utilisateur elastic
# ─────────────────────────────────────────────
call_es "Vérification elastic user" "GET" "/_security/_authenticate"

# ─────────────────────────────────────────────
# Fonction pour échapper les caractères JSON
# ─────────────────────────────────────────────
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"   # \ → \\
  s="${s//\"/\\\"}"   # " → \"
  s="${s//$'\n'/\\n}" # newline → \n
  s="${s//$'\r'/\\r}" # carriage return → \r
  s="${s//$'\t'/\\t}" # tab → \t
  printf '%s' "$s"
}

# ─────────────────────────────────────────────
# Définition password kibana_system
# ─────────────────────────────────────────────
KIBANA_JSON="{\"password\": \"$(json_escape "$KIBANA_PWD")\"}"

call_es "Set kibana_system password" \
  "POST" "/_security/user/kibana_system/_password" \
  "$KIBANA_JSON"

# ─────────────────────────────────────────────
# Définition password logstash_system
# ─────────────────────────────────────────────
LOGSTASH_SYS_JSON="{\"password\": \"$(json_escape "$LOGSTASH_SYSTEM_PWD")\"}"

call_es "Set logstash_system password" \
  "POST" "/_security/user/logstash_system/_password" \
  "$LOGSTASH_SYS_JSON"


# ─────────────────────────────────────────────
# Création rôle logstash_writer_role
# ─────────────────────────────────────────────
ROLE_JSON='{"cluster":["monitor","manage_index_templates"],"indices":[{"names":["logs-*","logstash-*","filebeat-*","auditbeat-*"],"privileges":["write","create","create_index","manage"]}]}'

call_es "Create role logstash_writer_role" \
  "PUT" "/_security/role/logstash_writer_role" \
  "$ROLE_JSON"

# ─────────────────────────────────────────────
# Création utilisateur logstash_writer
# ─────────────────────────────────────────────
USER_JSON="{\"password\": \"$(json_escape "$LOGSTASH_WRITER_PWD")\", \"roles\": [\"logstash_writer_role\"], \"full_name\": \"Logstash Writer\"}"

call_es "Create user logstash_writer" \
  "PUT" "/_security/user/logstash_writer" \
  "$USER_JSON"

# FIN
# ─────────────────────────────────────────────
echo ""
echo "🎉 Initialisation sécurité Elasticsearch terminée avec succès"





#Le script es-setup.sh utilise curl pour appeler l'API Elasticsearch via HTTPS. Pour établir la connexion TLS, curl doit vérifier le certificat du serveur Elasticsearch — et pour ça il a besoin de la CA qui a signé ce certificat.
#Donc full-chain.crt (qui contient ca-elk + root-ca) permet à curl de valider que le certificat présenté par Elasticsearch est bien signé par une CA de confiance.
#En résumé : es-setup est un client HTTPS qui parle à Elasticsearch, donc il a besoin de la CA comme n'importe quel autre client (Logstash, Kibana, Filebeat).