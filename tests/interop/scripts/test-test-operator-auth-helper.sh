#!/usr/bin/env bash
# Fast unit proof for the shared, public test-only interop bearer helper.
# No daemon or network is used: grpcurl is replaced with an argv recorder.

set -euo pipefail

TOPO="test-operator-auth-helper"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export TOPO INTEROP_TEST_OPERATOR_AUTH

# test-lib runs preflight while sourced. Satisfy its external-command probes
# without Docker or network access; grpcurl remains an argv recorder below.
docker() {
    [ "${1:-}" = "inspect" ]
}
grpcurl() {
    printf '<%s>\n' "$@"
}
jq() {
    return 0
}

# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

expected_token=$(<"$INTEROP_TEST_OPERATOR_TOKEN_FILE")
output=$(grpcurl_call -d '{}' 127.0.0.1:50051 rustbgpd.v1.ControlService/GetHealth)

if ! grep -Fqx "<authorization: Bearer $expected_token>" <<<"$output"; then
    echo "shared grpcurl helper did not inject the test-only bearer token" >&2
    exit 1
fi
if [ "$(grep -Fxc '<-H>' <<<"$output")" -ne 1 ]; then
    echo "shared grpcurl helper must inject exactly one authorization header" >&2
    exit 1
fi
for argument in '<-plaintext>' '<-import-path>' '<.>' '<-proto>' \
    '<proto/rustbgpd.proto>' '<-d>' '<{}>' '<127.0.0.1:50051>' \
    '<rustbgpd.v1.ControlService/GetHealth>'; do
    if ! grep -Fqx "$argument" <<<"$output"; then
        echo "shared grpcurl helper dropped argument $argument" >&2
        exit 1
    fi
done

INTEROP_TEST_OPERATOR_AUTH=0
export INTEROP_TEST_OPERATOR_AUTH
output=$(grpcurl_call 127.0.0.1:50051 rustbgpd.v1.ControlService/GetHealth)
if grep -Fq '<authorization:' <<<"$output"; then
    echo "legacy/dedicated callers must not inherit the shared bearer header" >&2
    exit 1
fi

echo "shared test-only interop authentication helper: PASS"
