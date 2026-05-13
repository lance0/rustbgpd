#!/usr/bin/env bash
# M41 interop test — RFC 7999 BLACKHOLE receiver scoping.
#
# FRR tags 203.0.113.66/32 with BLACKHOLE (65535:666) via an outbound
# route-map. rustbgpd's [global] honor_blackhole = true appends an
# implicit chain-tail import rule that preserves BLACKHOLE and adds
# NO_ADVERTISE. 203.0.113.67/32 is untagged and must not receive the
# implicit NO_ADVERTISE marker.
#
# Prerequisites:
#   - containerlab deploy -t tests/interop/m41-blackhole-frr.clab.yml
#   - grpcurl + jq installed on the host

set -euo pipefail

TOPO="m41-blackhole-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"
FRR="clab-${TOPO}-frr"

preflight
resolve_grpc_addr
start_rustbgpd

wait_frr_established "$FRR" "10.0.0.1" "rustbgpd ↔ FRR"

BLACKHOLE_VALUE=$(( (65535 << 16) | 666 ))     # 4294902426 = 0xFFFF_029A
NO_ADVERTISE_VALUE=$(( (65535 << 16) | 65282 )) # 4294967042 = 0xFFFF_FF02

grpc_list_received() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

route_communities() {
    local prefix=$1
    local payload
    payload=$(grpc_list_received)
    local exists
    exists=$(echo "$payload" | jq -r --arg p "$prefix" \
        '[.routes[]? | select("\(.prefix)/\(.prefixLength)" == $p)] | length')
    if [ "$exists" = "0" ] || [ -z "$exists" ]; then
        echo "MISSING"
        return
    fi
    echo "$payload" | jq -r --arg p "$prefix" \
        '[.routes[]? | select("\(.prefix)/\(.prefixLength)" == $p) | .communities[]?] | join(" ")'
}

has_community() {
    local communities=$1
    local value=$2
    echo " $communities " | grep -qE " ${value}( |$)"
}

dump_state_on_failure() {
    echo "===== rustbgpd ListReceivedRoutes (raw) =====" >&2
    grpc_list_received | jq . >&2 || true
    echo "===== rustbgpd NeighborState 10.0.0.2 =====" >&2
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d '{"address":"10.0.0.2"}' \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState 2>&1 \
        | head -60 >&2 || true
    echo "===== FRR vtysh: BGP summary =====" >&2
    docker exec "$FRR" vtysh -c 'show ip bgp summary' >&2 || true
    echo "===== FRR vtysh: advertised-routes to 10.0.0.1 =====" >&2
    docker exec "$FRR" vtysh -c 'show ip bgp neighbor 10.0.0.1 advertised-routes' >&2 || true
    echo "===== FRR vtysh: route-map TO-RUSTBGPD =====" >&2
    docker exec "$FRR" vtysh -c 'show route-map TO-RUSTBGPD' >&2 || true
}

wait_route_present() {
    local prefix=$1
    log "Waiting for $prefix in rustbgpd's RIB..."
    for i in $(seq 1 30); do
        local comms
        comms=$(route_communities "$prefix")
        if [ "$comms" != "MISSING" ]; then
            ok "$prefix present after ${i}s (communities: ${comms:-<none>})"
            return 0
        fi
        sleep 1
    done
    fail "$prefix never appeared in rustbgpd's RIB within 30s"
    dump_state_on_failure
    return 1
}

wait_route_present "203.0.113.66/32"
wait_route_present "203.0.113.67/32"

tagged_comms=$(route_communities "203.0.113.66/32")
log "203.0.113.66/32 communities: $tagged_comms"
if has_community "$tagged_comms" "$BLACKHOLE_VALUE" \
    && has_community "$tagged_comms" "$NO_ADVERTISE_VALUE"; then
    ok "203.0.113.66/32 carries BLACKHOLE and NO_ADVERTISE — RFC 7999 receiver scoping OK"
else
    fail "203.0.113.66/32 missing BLACKHOLE or NO_ADVERTISE (got: $tagged_comms)"
    dump_state_on_failure
    exit 1
fi

untagged_comms=$(route_communities "203.0.113.67/32")
log "203.0.113.67/32 communities: $untagged_comms"
if has_community "$untagged_comms" "$BLACKHOLE_VALUE" \
    || has_community "$untagged_comms" "$NO_ADVERTISE_VALUE"; then
    fail "203.0.113.67/32 should not carry BLACKHOLE or NO_ADVERTISE (got: $untagged_comms)"
    dump_state_on_failure
    exit 1
else
    ok "203.0.113.67/32 remains untagged (correct)"
fi

print_summary
