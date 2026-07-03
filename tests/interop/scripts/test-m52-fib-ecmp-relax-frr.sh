#!/usr/bin/env bash
# M52 interop test — ADR-0066 multipath-relax (`[global].multipath_relax`).
#
# Two FRR peers in DIFFERENT ASes (frr1 AS 65002, frr2 AS 65003) each originate
# 203.0.113.52/32. As seen by rustbgpd the paths have equal AS_PATH *length* (1)
# but different ASNs, so exact-AS_PATH grouping would NOT bundle them. With
# `[global] multipath_relax = true` + `maximum_paths = 2`, rustbgpd must install
# the prefix as a kernel two-way ECMP route; withdrawing one collapses to the
# survivor; re-advertising restores the ECMP.
#
# Prerequisites:
#   - docker build --target dev -t rustbgpd:dev .
#   - containerlab deploy -t tests/interop/m52-fib-ecmp-relax-frr.clab.yml
#   - grpcurl + jq installed on the host

set -euo pipefail

TOPO="m52-fib-ecmp-relax-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"
FRR1="clab-${TOPO}-frr1"
FRR2="clab-${TOPO}-frr2"
TABLE_ID=1000
METRIC=200
PREFIX="203.0.113.52/32"
NH1="10.0.0.2"
NH2="10.0.1.2"

resolve_grpc_addr
start_rustbgpd

wait_frr_established "$FRR1" "10.0.0.1" "rustbgpd ↔ frr1 (AS 65002)"
wait_frr_established "$FRR2" "10.0.1.1" "rustbgpd ↔ frr2 (AS 65003)"

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

# The two paths differ in AS_PATH (different ASNs) and only group because of
# multipath-relax — so a two-way kernel ECMP route proves the knob works.
wait_kernel_ecmp() {
    log "Waiting for relaxed ECMP route $PREFIX with both $NH1 and $NH2..."
    for _ in $(seq 1 30); do
        local route
        route=$(kernel_route)
        if echo "$route" | grep -q "proto bgp" \
            && echo "$route" | grep -q "metric $METRIC" \
            && echo "$route" | grep -q "nexthop via $NH1" \
            && echo "$route" | grep -q "nexthop via $NH2"; then
            ok "$PREFIX installed as relaxed ECMP via $NH1 + $NH2 (different ASes)"
            return 0
        fi
        sleep 1
    done
    fail "$PREFIX did not install as two-way ECMP under multipath-relax"
    dump_state_on_failure
    return 1
}

wait_kernel_single() {
    local survivor=$1
    log "Waiting for $PREFIX to collapse to single next-hop via $survivor..."
    for _ in $(seq 1 30); do
        local route
        route=$(kernel_route)
        if echo "$route" | grep -q "proto bgp" \
            && echo "$route" | grep -q "metric $METRIC" \
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

wait_grpc_next_hops() {
    local expected_count=$1
    local addr=${PREFIX%/*}
    local plen=${PREFIX#*/}
    log "Waiting for $PREFIX gRPC next_hops count -> $expected_count..."
    for _ in $(seq 1 30); do
        local json count
        if json=$(grpc_fib_routes 2>/dev/null); then
            count=$(printf '%s\n' "$json" | jq -r --arg addr "$addr" --argjson plen "$plen" '
                [.routes[]? | select(.prefix == $addr and .prefixLength == $plen)]
                | if length == 0 then -1 else (.[0].nextHops // [] | length) end' 2>/dev/null)
            if [ "$count" = "$expected_count" ]; then
                ok "$PREFIX gRPC reports $count next-hop(s)"
                return 0
            fi
        fi
        sleep 1
    done
    fail "$PREFIX gRPC next_hops count did not reach $expected_count"
    dump_state_on_failure
    return 1
}

# Shut / un-shut frr2's session to rustbgpd (AS 65003, peer 10.0.1.1). Session
# shutdown is a deterministic withdraw of frr2's contribution — more reliable
# here than `no network`, and it still exercises the FIB collapse/restore path.
frr2_session() {
    local action=$1 cmd
    case "$action" in
        down) cmd="neighbor 10.0.1.1 shutdown" ;;
        up) cmd="no neighbor 10.0.1.1 shutdown" ;;
        *) fail "invalid frr2 session action: $action"; return 1 ;;
    esac
    log "frr2 (AS 65003): $cmd..."
    docker exec "$FRR2" vtysh \
        -c 'configure terminal' \
        -c 'router bgp 65003' \
        -c "$cmd" >/dev/null 2>&1
}

# Install: relaxed grouping of the two different-AS paths => kernel ECMP.
wait_kernel_ecmp
wait_grpc_next_hops 2

# Failover: shut frr2's session => its path withdraws => collapse to frr1.
frr2_session down
wait_kernel_single "$NH1"
wait_grpc_next_hops 1

# Restore: bring frr2 back => relaxed two-way ECMP returns.
frr2_session up
wait_frr_established "$FRR2" "10.0.1.1" "rustbgpd ↔ frr2 (restored)"
wait_kernel_ecmp
wait_grpc_next_hops 2

print_summary
