#!/usr/bin/env bash
# Generate the mTLS PKI fixture for the gRPC mTLS interop tests.
# Produces a CA, a server certificate, and four client
# certificates whose `rustbgpd://` URI SANs map to ADR-0064 roles
# (and one deliberately-unmapped principal).
#
# By default, all material is written under
# tests/interop/configs/m44-certs/, which is gitignored — the certs
# are regenerated per CI run so validity windows never expire in the
# repo. Set RUSTBGPD_MTLS_CERT_DIR to reuse the same fixture shape for
# sibling tests.
#
# Usage:
#   bash tests/interop/scripts/gen-m44-certs.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR="${RUSTBGPD_MTLS_CERT_DIR:-$SCRIPT_DIR/../configs/m44-certs}"
SERVER_CN="rustbgpd.local"

rm -rf "$CERT_DIR"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

# Helper: emit a client cert with a single rustbgpd:// URI SAN.
gen_client() {
    local name=$1 uri=$2
    openssl req -newkey rsa:2048 -nodes -keyout "${name}.key" \
        -subj "/CN=${name}" -out "${name}.csr" 2>/dev/null
    openssl x509 -req -in "${name}.csr" -CA ca.pem -CAkey ca.key \
        -CAcreateserial -days 3 -sha256 \
        -extfile <(printf 'subjectAltName=URI:%s\nextendedKeyUsage=clientAuth\n' "$uri") \
        -out "${name}.pem" 2>/dev/null
    rm -f "${name}.csr"
}

# 1. Self-signed CA.
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key \
    -subj "/CN=rustbgpd-m44-ca" -days 3 -sha256 -out ca.pem 2>/dev/null

# 2. Server certificate (DNS SAN; grpcurl verifies against -servername).
openssl req -newkey rsa:2048 -nodes -keyout server.key \
    -subj "/CN=${SERVER_CN}" -out server.csr 2>/dev/null
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key \
    -CAcreateserial -days 3 -sha256 \
    -extfile <(printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$SERVER_CN") \
    -out server.pem 2>/dev/null
rm -f server.csr

# 3. Client certs: three role-mapped principals + one unmapped.
gen_client observer   "rustbgpd://observer/ci"
gen_client automation "rustbgpd://automation/ci"
gen_client operator   "rustbgpd://operator/ci"
gen_client intruder   "rustbgpd://intruder/ci"

chmod 0644 ./*.pem ./*.key

echo "mTLS fixture generated in $CERT_DIR:"
ls -1 "$CERT_DIR"
