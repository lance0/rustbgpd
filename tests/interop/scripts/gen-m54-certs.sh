#!/usr/bin/env bash
# Generate the mTLS PKI fixture for M54 gNMI / OpenConfig interop.
#
# Reuses the M44 certificate shape: a CA, a server cert for
# rustbgpd.local, and client certs whose rustbgpd:// URI SANs map to
# ADR-0064 roles.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUSTBGPD_MTLS_CERT_DIR="$SCRIPT_DIR/../configs/m54-certs" \
    exec "$SCRIPT_DIR/gen-m44-certs.sh"
