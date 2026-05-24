#!/usr/bin/env bash
# M50 interop test — ADR-0066 unicast multipath/ECMP FIB install.
#
# Two FRR peers in the same AS each originate 203.0.113.50/32; rustbgpd with
# `[[fib_tables]] maximum_paths = 2` must install a kernel multipath route with
# both gateways, collapse to the survivor when one path withdraws, and restore
# the two-way ECMP when it returns.
#
# Prerequisites:
#   - docker build -t rustbgpd:dev .
#   - containerlab deploy -t tests/interop/m50-fib-ecmp-frr.clab.yml
#   - grpcurl + jq installed on the host

set -euo pipefail

TOPO="m50-fib-ecmp-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"
FRR1="clab-${TOPO}-frr1"
FRR2="clab-${TOPO}-frr2"
TABLE_ID=1000
METRIC=200
PREFIX="203.0.113.50/32"
NH1="10.0.0.2"
NH2="10.0.1.2"

resolve_grpc_addr
start_rustbgpd

wait_frr_established "$FRR1" "10.0.0.1" "rustbgpd ↔ frr1"
wait_frr_established "$FRR2" "10.0.1.1" "rustbgpd ↔ frr2"

grpc_fib_routes() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListFibRoutes
}

kernel_route() {
    docker exec "$RUSTBGPD" ip route show table "$TABLE_ID" exact "$PREFIX" 2>/dev/null || true
}

dump_state_on_failure() {
    echo "===== rustbgpd ListFibRoutes (raw) =====" >&2
    grpc_fib_routes | jq . >&2 || true
    echo "===== rustbgpd table $TABLE_ID =====" >&2
    docker exec "$RUSTBGPD" ip route show table "$TABLE_ID" >&2 || true
    for frr in "$FRR1" "$FRR2"; do
        echo "===== $frr vtysh: BGP summary =====" >&2
        docker exec "$frr" vtysh -c 'show ip bgp summary' >&2 || true
    done
}

# Count distinct expected gateways present in the kernel route, requiring the
# RTPROT_BGP + metric shape on the row.
wait_kernel_ecmp() {
    log "Waiting for ECMP route $PREFIX with both $NH1 and $NH2..."
    for _ in $(seq 1 30); do
        local route
        route=$(kernel_route)
        if echo "$route" | grep -q "proto bgp" \
            && echo "$route" | grep -q "metric $METRIC" \
            && echo "$route" | grep -q "nexthop via $NH1" \
            && echo "$route" | grep -q "nexthop via $NH2"; then
            ok "$PREFIX installed as ECMP via $NH1 + $NH2 (proto bgp metric $METRIC)"
            return 0
        fi
        sleep 1
    done
    fail "$PREFIX did not install as two-way ECMP"
    dump_state_on_failure
    return 1
}

# After a withdraw the route must collapse to exactly the surviving gateway as a
# single-path row (RTA_GATEWAY, no `nexthop` stanzas).
wait_kernel_single() {
    local survivor=$1
    log "Waiting for $PREFIX to collapse to single next-hop via $survivor..."
    for _ in $(seq 1 30); do
        local route
        route=$(kernel_route)
        if echo "$route" | grep -q "proto bgp" \
            && echo "$route" | grep -q "via $survivor" \
            && ! echo "$route" | grep -q "nexthop"; then
            ok "$PREFIX collapsed to single next-hop via $survivor"
            return 0
        fi
        sleep 1
    done
    fail "$PREFIX did not collapse to single next-hop via $survivor"
    dump_state_on_failure
    return 1
}

# gRPC ListFibRoutes surfaces the full next-hop set for the row.
assert_grpc_next_hops() {
    local expected_count=$1
    local json count
    json=$(grpc_fib_routes 2>&1) || { fail "grpcurl ListFibRoutes failed: $json"; return 1; }
    count=$(printf '%s\n' "$json" | jq -r --arg addr "${PREFIX%/*}" '
        [.routes[]? | select(.prefix == $addr)] | .[0].nextHops | length // 0')
    if [ "$count" = "$expected_count" ]; then
        ok "$PREFIX gRPC status reports $count next-hop(s)"
    else
        fail "$PREFIX gRPC next_hops count is $count, expected $expected_count"
        dump_state_on_failure
        return 1
    fi
}

frr_network() {
    local frr=$1 action=$2 cmd
    case "$action" in
        add) cmd="network $PREFIX" ;;
        del) cmd="no network $PREFIX" ;;
        *) fail "invalid FRR network action: $action"; return 1 ;;
    esac
    log "$frr: $cmd..."
    docker exec "$frr" vtysh \
        -c 'configure terminal' \
        -c 'router bgp 65002' \
        -c 'address-family ipv4 unicast' \
        -c "$cmd" >/dev/null 2>&1
}

# Install: both equal-cost paths => kernel ECMP, gRPC reports two next-hops.
wait_kernel_ecmp
assert_grpc_next_hops 2

# Failover: frr2 withdraws => collapse to the frr1 survivor.
frr_network "$FRR2" del
wait_kernel_single "$NH1"
assert_grpc_next_hops 1

# Restore: frr2 re-advertises => two-way ECMP returns.
frr_network "$FRR2" add
wait_kernel_ecmp
assert_grpc_next_hops 2

print_summary
