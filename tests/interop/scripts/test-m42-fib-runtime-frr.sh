#!/usr/bin/env bash
# M42 interop test — ADR-0061 opt-in general unicast FIB runtime.
#
# Prerequisites:
#   - docker build -t rustbgpd:dev .
#   - containerlab deploy -t tests/interop/m42-fib-runtime-frr.clab.yml
#   - grpcurl + jq installed on the host

set -euo pipefail

TOPO="m42-fib-runtime-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"
FRR="clab-${TOPO}-frr"
TABLE_ID=1000
METRIC=200
INSTALL_PREFIX="203.0.113.42/32"
FOREIGN_PREFIX="198.51.100.0/24"
NEXT_HOP="10.0.0.2"

resolve_grpc_addr
start_rustbgpd

wait_frr_established "$FRR" "10.0.0.1" "rustbgpd ↔ FRR"

grpc_fib_routes() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListFibRoutes 2>/dev/null
}

normalize_fib_state() {
    case "$1" in
        FIB_ROUTE_STATE_INSTALLED) echo "installed" ;;
        FIB_ROUTE_STATE_REJECTED) echo "rejected" ;;
        FIB_ROUTE_STATE_FAILED) echo "failed" ;;
        1) echo "installed" ;;
        2) echo "rejected" ;;
        3) echo "failed" ;;
        *) echo "$1" ;;
    esac
}

fib_status() {
    local prefix=$1
    local addr=${prefix%/*}
    local plen=${prefix#*/}
    local raw
    raw=$(grpc_fib_routes | jq -r --arg addr "$addr" --argjson plen "$plen" '
        [.routes[]? | select(.prefix == $addr and .prefixLength == $plen)]
        | if length == 0 then "MISSING" else "\(.[0].state)|\(.[0].reason)|\(.[0].tableId)|\(.[0].metric)|\(.[0].nextHop)" end
    ')
    if [ "$raw" = "MISSING" ]; then
        echo "$raw"
        return
    fi
    local state=${raw%%|*}
    local rest=${raw#*|}
    printf '%s|%s\n' "$(normalize_fib_state "$state")" "$rest"
}

kernel_route() {
    local prefix=$1
    docker exec "$RUSTBGPD" ip route show table "$TABLE_ID" exact "$prefix" 2>/dev/null || true
}

dump_state_on_failure() {
    echo "===== rustbgpd ListFibRoutes (raw) =====" >&2
    grpc_fib_routes | jq . >&2 || true
    echo "===== rustbgpd table $TABLE_ID =====" >&2
    docker exec "$RUSTBGPD" ip route show table "$TABLE_ID" >&2 || true
    echo "===== rustbgpd main table =====" >&2
    docker exec "$RUSTBGPD" ip route show >&2 || true
    echo "===== rustbgpd NeighborState 10.0.0.2 =====" >&2
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d '{"address":"10.0.0.2"}' \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState 2>&1 \
        | head -80 >&2 || true
    echo "===== FRR vtysh: BGP summary =====" >&2
    docker exec "$FRR" vtysh -c 'show ip bgp summary' >&2 || true
    echo "===== FRR vtysh: advertised-routes to 10.0.0.1 =====" >&2
    docker exec "$FRR" vtysh -c 'show ip bgp neighbor 10.0.0.1 advertised-routes' >&2 || true
}

wait_fib_status() {
    local prefix=$1
    local expected_state=$2
    local expected_reason=${3:-}
    log "Waiting for FIB status $prefix -> $expected_state ${expected_reason:+($expected_reason)}..."
    for i in $(seq 1 30); do
        local status
        status=$(fib_status "$prefix")
        local state=${status%%|*}
        local rest=${status#*|}
        local reason=${rest%%|*}
        if [ "$state" = "$expected_state" ] \
            && { [ -z "$expected_reason" ] || [ "$reason" = "$expected_reason" ]; }; then
            ok "$prefix FIB status is $state/$reason after ${i}s"
            return 0
        fi
        sleep 1
    done
    fail "$prefix FIB status did not become $expected_state/${expected_reason:-*} (last: $(fib_status "$prefix"))"
    dump_state_on_failure
    return 1
}

wait_fib_status_missing() {
    local prefix=$1
    log "Waiting for FIB status $prefix to disappear..."
    for i in $(seq 1 30); do
        if [ "$(fib_status "$prefix")" = "MISSING" ]; then
            ok "$prefix FIB status disappeared after ${i}s"
            return 0
        fi
        sleep 1
    done
    fail "$prefix FIB status remained present (last: $(fib_status "$prefix"))"
    dump_state_on_failure
    return 1
}

wait_kernel_owned_route() {
    local prefix=$1
    log "Waiting for kernel route $prefix in table $TABLE_ID..."
    for i in $(seq 1 30); do
        local route
        route=$(kernel_route "$prefix")
        if echo "$route" | grep -q "via $NEXT_HOP" \
            && echo "$route" | grep -q "proto bgp" \
            && echo "$route" | grep -q "metric $METRIC"; then
            ok "$prefix installed in table $TABLE_ID via $NEXT_HOP proto bgp metric $METRIC after ${i}s"
            return 0
        fi
        sleep 1
    done
    fail "$prefix did not install with expected kernel shape"
    dump_state_on_failure
    return 1
}

wait_no_kernel_route() {
    local prefix=$1
    log "Waiting for kernel route $prefix to be absent from table $TABLE_ID..."
    for i in $(seq 1 30); do
        if ! kernel_route "$prefix" | grep -q .; then
            ok "$prefix absent from table $TABLE_ID after ${i}s"
            return 0
        fi
        sleep 1
    done
    fail "$prefix remained in table $TABLE_ID"
    dump_state_on_failure
    return 1
}

assert_kernel_foreign_route() {
    local prefix=$1
    local route
    route=$(kernel_route "$prefix")
    if echo "$route" | grep -q "via $NEXT_HOP" \
        && echo "$route" | grep -q "proto static" \
        && echo "$route" | grep -q "metric $METRIC"; then
        ok "$prefix foreign static route preserved in table $TABLE_ID"
    else
        fail "$prefix foreign static route missing or modified: ${route:-<empty>}"
        dump_state_on_failure
        return 1
    fi
}

frr_network() {
    local action=$1
    local prefix=$2
    local cmd
    case "$action" in
        add) cmd="network $prefix" ;;
        del) cmd="no network $prefix" ;;
        *)
            fail "invalid FRR network action: $action"
            return 1
            ;;
    esac
    log "FRR $cmd..."
    docker exec "$FRR" vtysh \
        -c 'configure terminal' \
        -c 'router bgp 65002' \
        -c 'address-family ipv4 unicast' \
        -c "$cmd" >/dev/null 2>&1
}

wait_fib_status "$INSTALL_PREFIX" "installed" "owned"
wait_kernel_owned_route "$INSTALL_PREFIX"

install_status=$(fib_status "$INSTALL_PREFIX")
IFS='|' read -r install_state install_reason install_table install_metric install_nh <<< "$install_status"
if [ "$install_table" = "$TABLE_ID" ] && [ "$install_metric" = "$METRIC" ] && [ "$install_nh" = "$NEXT_HOP" ]; then
    ok "$INSTALL_PREFIX gRPC status reports table=$TABLE_ID metric=$METRIC next-hop=$NEXT_HOP"
else
    fail "$INSTALL_PREFIX gRPC status shape wrong: $install_status"
    dump_state_on_failure
    exit 1
fi

wait_fib_status "$FOREIGN_PREFIX" "rejected" "foreign_route_exists"
assert_kernel_foreign_route "$FOREIGN_PREFIX"

frr_network "del" "$INSTALL_PREFIX"
wait_no_kernel_route "$INSTALL_PREFIX"
wait_fib_status_missing "$INSTALL_PREFIX"
assert_kernel_foreign_route "$FOREIGN_PREFIX"

frr_network "add" "$INSTALL_PREFIX"
wait_fib_status "$INSTALL_PREFIX" "installed" "owned"
wait_kernel_owned_route "$INSTALL_PREFIX"

log "Sending SIGTERM to rustbgpd to validate shutdown drain..."
docker exec "$RUSTBGPD" sh -c 'kill -TERM "$(pidof rustbgpd)"'
wait_no_kernel_route "$INSTALL_PREFIX"
assert_kernel_foreign_route "$FOREIGN_PREFIX"

print_summary
