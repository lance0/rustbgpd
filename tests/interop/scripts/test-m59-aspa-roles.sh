#!/usr/bin/env bash
# M59 interop test — role-aware ASPA verification (downstream / customer-cone).
#
# rustbgpd (AS 65001) configures BGP Role = customer toward FRR (AS 65003, its
# provider), so routes from FRR are verified with the ASPA downstream procedure
# (draft-ietf-sidrops-aspa-verification-25 §5.5, ADR-0049). The RTR v2 server
# feeds ASPA records chosen so:
#   - 192.168.20.0/24 [65003, 65002, 65001] → downstream Valid
#   - 192.168.21.0/24 [65003, 65007, 65008] → downstream Invalid
#
# Routes may import as Unknown before the RTR ASPA records load, then
# re-validate to the final verdict on the cache update — so the assertions poll.
#
# Prerequisites: containerlab deployed, grpcurl + jq + python3 on the host.

set -euo pipefail

TOPO="m59-aspa-roles-rtr2"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
source "$SCRIPT_DIR/test-lib.sh"
FRR="clab-${TOPO}-frr"
RTR_SERVER="clab-${TOPO}-rtr-server"

# Patch the RTR server's resolved address into the rustbgpd config.
patch_rpki_config() {
    local rtr_ip
    rtr_ip=$(resolve_ip "$RTR_SERVER")
    if [ -z "$rtr_ip" ]; then
        echo "ERROR: cannot resolve management IP for $RTR_SERVER" >&2
        exit 1
    fi
    log "RTR server address: ${rtr_ip}:3323"
    docker exec "$RUSTBGPD" sh -c \
        "sed 's/STAYRTR_ADDR/${rtr_ip}/' /etc/rustbgpd/config.toml > /tmp/config.toml"
}

start_rtr_server() {
    log "Starting RTR v2 server (M59 records)..."
    docker exec -d "$RTR_SERVER" python3 /usr/local/bin/rtr-v2-server-m59.py
    for i in $(seq 1 15); do
        if docker exec "$RTR_SERVER" sh -c 'cat /tmp/rtr-server-status.json 2>/dev/null' \
            | grep -q '"listening": true'; then
            ok "RTR v2 server is listening (attempt $i)"
            return 0
        fi
        sleep 1
    done
    fail "RTR v2 server did not start within 15s"
    return 1
}

grpc_list_received() {
    grpcurl_call \
        -d '{"neighbor_address": "10.0.0.2"}' \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

extract_route_field() {
    local routes=$1 prefix=$2 prefix_len=$3 field=$4
    echo "$routes" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
for r in resp.get('routes', []):
    if r['prefix'] == '$prefix' and r['prefixLength'] == $prefix_len:
        print(r.get('$field', 'missing'))
        break
else:
    print('missing')
" 2>/dev/null || echo "missing"
}

# Poll until <prefix>/<len> reports the expected aspa_state.
assert_aspa_state() {
    local prefix=$1 len=$2 expected=$3
    for i in $(seq 1 45); do
        local state
        state=$(extract_route_field "$(grpc_list_received)" "$prefix" "$len" "aspaState")
        if [ "$state" = "$expected" ]; then
            ok "$prefix/$len aspa_state = $expected (after ${i}s)"
            return 0
        fi
        sleep 1
    done
    fail "$prefix/$len aspa_state never reached '$expected' (last: '$(extract_route_field "$(grpc_list_received)" "$prefix" "$len" "aspaState")')"
}

# ---------------------------------------------------------------------------

preflight
resolve_grpc_addr
patch_rpki_config
start_rtr_server
start_with_custom_config() { start_rustbgpd "/usr/local/bin/rustbgpd /tmp/config.toml > /tmp/rustbgpd.log 2>&1"; }
start_with_custom_config

wait_frr_established "$FRR" "10.0.0.1" "rustbgpd ↔ FRR (provider)"

# Wait for the provider's routes to arrive.
log "Waiting for FRR routes to reach rustbgpd's RIB..."
for i in $(seq 1 30); do
    if [ "$(extract_route_field "$(grpc_list_received)" "192.168.20.0" 24 prefix)" = "192.168.20.0" ]; then
        ok "received 192.168.20.0/24 (after ${i}s)"
        break
    fi
    sleep 1
done

# Role-aware downstream verdicts (converge once the RTR ASPA records load).
assert_aspa_state "192.168.20.0" 24 "valid"
assert_aspa_state "192.168.21.0" 24 "invalid"

print_summary
