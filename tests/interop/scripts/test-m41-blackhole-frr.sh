#!/usr/bin/env bash
# M41 interop test — RFC 7999 BLACKHOLE receiver scoping + FIB discard.
#
# FRR tags 203.0.113.66/32 with BLACKHOLE (65535:666) via an outbound
# route-map. rustbgpd's [global] honor_blackhole = true appends an
# implicit chain-tail import rule that preserves BLACKHOLE and adds
# NO_ADVERTISE, while [global] install_blackhole_discard = true installs
# a local kernel RTN_BLACKHOLE row for the accepted host route.
# 203.0.113.67/32 is untagged and must not receive the implicit marker
# or a kernel discard. 198.51.100.0/24 is tagged but broad, so it is
# rejected by the host-route guard and must not install a kernel route.
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

grpc_blackholes() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListBlackholeDiscards 2>/dev/null
}

normalize_blackhole_state() {
    case "$1" in
        BLACKHOLE_DISCARD_STATE_INSTALLED) echo "installed" ;;
        BLACKHOLE_DISCARD_STATE_REJECTED) echo "rejected" ;;
        BLACKHOLE_DISCARD_STATE_FAILED) echo "failed" ;;
        1) echo "installed" ;;
        2) echo "rejected" ;;
        3) echo "failed" ;;
        *) echo "$1" ;;
    esac
}

blackhole_status() {
    local prefix=$1
    local plen=${prefix#*/}
    local addr=${prefix%/*}
    local status
    status=$(grpc_blackholes | jq -r --arg addr "$addr" --argjson plen "$plen" '
        [.discards[]? | select(.prefix == $addr and .prefixLength == $plen)]
        | if length == 0 then "MISSING" else "\(.[0].state)|\(.[0].reason)" end
    ')
    if [ "$status" = "MISSING" ]; then
        echo "$status"
        return
    fi
    local state=${status%%|*}
    local reason=${status#*|}
    printf '%s|%s\n' "$(normalize_blackhole_state "$state")" "$reason"
}

has_community() {
    local communities=$1
    local value=$2
    echo " $communities " | grep -qE " ${value}( |$)"
}

dump_state_on_failure() {
    echo "===== rustbgpd ListReceivedRoutes (raw) =====" >&2
    grpc_list_received | jq . >&2 || true
    echo "===== rustbgpd ListBlackholeDiscards (raw) =====" >&2
    grpc_blackholes | jq . >&2 || true
    echo "===== rustbgpd container routes =====" >&2
    docker exec "$RUSTBGPD" ip route show >&2 || true
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

wait_blackhole_status() {
    local prefix=$1
    local expected_state=$2
    local expected_reason=${3:-}
    log "Waiting for BLACKHOLE status $prefix -> $expected_state ${expected_reason:+($expected_reason)}..."
    for i in $(seq 1 30); do
        local status
        status=$(blackhole_status "$prefix")
        local state=${status%%|*}
        local reason=${status#*|}
        if [ "$state" = "$expected_state" ] \
            && { [ -z "$expected_reason" ] || [ "$reason" = "$expected_reason" ]; }; then
            ok "$prefix BLACKHOLE status is $state/$reason after ${i}s"
            return 0
        fi
        sleep 1
    done
    fail "$prefix BLACKHOLE status did not become $expected_state/${expected_reason:-*} (last: $(blackhole_status "$prefix"))"
    dump_state_on_failure
    return 1
}

wait_kernel_blackhole_route() {
    local prefix=$1
    log "Waiting for kernel blackhole route $prefix..."
    for i in $(seq 1 30); do
        if docker exec "$RUSTBGPD" ip route show exact "$prefix" \
            | grep -Eq "^blackhole ${prefix%/*}"; then
            ok "$prefix installed as kernel blackhole route after ${i}s"
            return 0
        fi
        sleep 1
    done
    fail "$prefix did not install as kernel blackhole route"
    dump_state_on_failure
    return 1
}

assert_no_kernel_route() {
    local prefix=$1
    if docker exec "$RUSTBGPD" ip route show exact "$prefix" | grep -q .; then
        fail "$prefix unexpectedly present in rustbgpd kernel FIB"
        dump_state_on_failure
        return 1
    fi
    ok "$prefix absent from rustbgpd kernel FIB"
}

wait_no_kernel_route() {
    local prefix=$1
    log "Waiting for kernel route $prefix to be removed..."
    for i in $(seq 1 30); do
        if ! docker exec "$RUSTBGPD" ip route show exact "$prefix" | grep -q .; then
            ok "$prefix removed from rustbgpd kernel FIB after ${i}s"
            return 0
        fi
        sleep 1
    done
    fail "$prefix remained in rustbgpd kernel FIB"
    dump_state_on_failure
    return 1
}

withdraw_frr_network() {
    local prefix=$1
    log "Withdrawing $prefix from FRR..."
    docker exec "$FRR" vtysh \
        -c 'configure terminal' \
        -c 'router bgp 65002' \
        -c 'address-family ipv4 unicast' \
        -c "no network $prefix" >/dev/null 2>&1
}

wait_route_present "203.0.113.66/32"
wait_route_present "203.0.113.67/32"
wait_route_present "198.51.100.0/24"

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

broad_comms=$(route_communities "198.51.100.0/24")
log "198.51.100.0/24 communities: $broad_comms"
if has_community "$broad_comms" "$BLACKHOLE_VALUE" \
    && has_community "$broad_comms" "$NO_ADVERTISE_VALUE"; then
    ok "198.51.100.0/24 carries BLACKHOLE and NO_ADVERTISE before FIB guard"
else
    fail "198.51.100.0/24 missing BLACKHOLE or NO_ADVERTISE (got: $broad_comms)"
    dump_state_on_failure
    exit 1
fi

wait_blackhole_status "203.0.113.66/32" "installed"
wait_kernel_blackhole_route "203.0.113.66/32"
assert_no_kernel_route "203.0.113.67/32"
wait_blackhole_status "198.51.100.0/24" "rejected" "broad_prefix"
assert_no_kernel_route "198.51.100.0/24"

withdraw_frr_network "203.0.113.66/32"
wait_no_kernel_route "203.0.113.66/32"

print_summary
