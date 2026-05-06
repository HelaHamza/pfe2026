#!/bin/bash
set -e

PKI="./pki"
ROOT="$PKI/root-ca"
CA_BEATS="$PKI/ca-beats"
CA_ELK="$PKI/ca-elk"
BEATS="$PKI/beats"
ELK="$PKI/elk"

# ── Création de la structure ────────────────────────────────────────────────
echo "==> Création de la structure PKI..."
mkdir -p $ROOT $CA_BEATS $CA_ELK
mkdir -p $BEATS/{filebeat,winlogbeat}
mkdir -p $ELK/{logstash,logstash-client,elasticsearch,kibana}

# ── Root CA : auto-signé (en utilisant -x509) ─────────────────────────────────────────────────────────────────
echo "==> Root CA..."
openssl genrsa -out $ROOT/root-ca.key 4096
openssl req -new -x509 -days 3650 \
  -key $ROOT/root-ca.key \
  -out $ROOT/root-ca.crt \
  -subj "/CN=RootCA/O=PFE"

# ── CA Beats ────────────────────────────────────────────────────────────────
echo "==> CA Beats..."
openssl genrsa -out $CA_BEATS/ca-beats.key 4096
openssl req -new -key $CA_BEATS/ca-beats.key \
  -out $CA_BEATS/ca-beats.csr -subj "/CN=CA-Beats/O=PFE"
openssl x509 -req -days 1825 \
  -in  $CA_BEATS/ca-beats.csr \
  -CA  $ROOT/root-ca.crt -CAkey $ROOT/root-ca.key \
  -CAcreateserial \
  -out $CA_BEATS/ca-beats.crt \
  -extfile <(printf "[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign") \
  -extensions v3_ca

# ── CA ELK ──────────────────────────────────────────────────────────────────
echo "==> CA ELK..."
openssl genrsa -out $CA_ELK/ca-elk.key 4096
openssl req -new -key $CA_ELK/ca-elk.key \
  -out $CA_ELK/ca-elk.csr -subj "/CN=CA-ELK/O=PFE"
openssl x509 -req -days 1825 \
  -in  $CA_ELK/ca-elk.csr \
  -CA  $ROOT/root-ca.crt -CAkey $ROOT/root-ca.key \
  -CAcreateserial \
  -out $CA_ELK/ca-elk.crt \
  -extfile <(printf "[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign") \
  -extensions v3_ca # c'est pour marquer cette certificat comme CA et non pas un simple certificat

# ── Fonction helper ─────────────────────────────────────────────────────────
gen_cert() {
  local DIR=$1 CN=$2 CA_CRT=$3 CA_KEY=$4

  echo "  -> $CN"

  # Création config SAN
  cat > $DIR/$CN.cnf <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = req_ext

[ dn ]
CN = $CN
O = PFE

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = $CN
DNS.2 = localhost
IP.1  = 127.0.0.1
IP.2  = ::1
EOF

  # Clé privée
  openssl genrsa -out $DIR/$CN.key 4096

  # CSR avec SAN
  openssl req -new -key $DIR/$CN.key \
    -out $DIR/$CN.csr \
    -config $DIR/$CN.cnf

  # Signature avec SAN
  openssl x509 -req -days 365 \
    -in  $DIR/$CN.csr \
    -CA  $CA_CRT -CAkey $CA_KEY \
    -CAcreateserial \
    -out $DIR/$CN.crt \
    -extensions req_ext \
    -extfile $DIR/$CN.cnf


    
}
#auditbeat est configurer manuellement 

# ── Certificats Beats (signés par CA-Beats) ──────────────────────────────────
echo "==> Certificats Beats..."
gen_cert $BEATS/filebeat    filebeat    $CA_BEATS/ca-beats.crt $CA_BEATS/ca-beats.key
gen_cert $BEATS/winlogbeat  winlogbeat  $CA_BEATS/ca-beats.crt $CA_BEATS/ca-beats.key

# ── Certificats ELK (signés par CA-ELK) ─────────────────────────────────────
echo "==> Certificats ELK..."
gen_cert $ELK/logstash        logstash        $CA_BEATS/ca-beats.crt $CA_BEATS/ca-beats.key
gen_cert $ELK/logstash-client logstash-client $CA_ELK/ca-elk.crt $CA_ELK/ca-elk.key
gen_cert $ELK/elasticsearch   elasticsearch   $CA_ELK/ca-elk.crt $CA_ELK/ca-elk.key
gen_cert $ELK/kibana          kibana          $CA_ELK/ca-elk.crt $CA_ELK/ca-elk.key

echo ""

# À la fin de ton script PKI
sudo find ./pki -name "*.key" -exec chown 1000:1000 {} \; -exec chmod 640 {} \;
sudo find ./pki -name "*.crt" -exec chown 1000:1000 {} \; -exec chmod 644 {} \;
sudo find ./pki -type d -exec chmod 755 {} \;

echo "✅ PKI générée avec succès dans $PKI/"


#il faut que les certificats soient lisibles par les processus Elasticsearch et Logstash qui tournent avec l'uid 1000 (utilisateur "elasticsearch" dans le container) pour qu'ils puissent les charger au démarrage et établir des connexions sécurisées. En changeant la propriété des fichiers
# et en ajustant les permissions, tu t'assures que les processus ont les droits nécessaires pour accéder aux certificats tout en maintenant une bonne sécurité (pas de permissions trop larges).
# - Les fichiers .key sont sensibles et doivent être protégés contre les accès non autorisés, d'où les permissions 640 (lecture/écriture pour le propriétaire, lecture pour le groupe, aucune permission pour les autres).
# - Les fichiers .crt sont moins sensibles et peuvent être lisibles par tous, d'où les permissions 644 (lecture/écriture pour le propriétaire, lecture pour le groupe et les autres
# - Les répertoires ont des permissions 755 pour permettre à l'utilisateur de traverser les répertoires et accéder aux fichiers.
# ici on met le .key en 644 pour que le processus Elasticsearch puisse les lire, mais en production il faudrait les protéger avec des permissions plus strictes et s'assurer que seuls les processus qui en ont besoin peuvent y accéder.