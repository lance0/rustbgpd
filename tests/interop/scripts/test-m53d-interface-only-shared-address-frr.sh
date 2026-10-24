#!/usr/bin/env bash
# M53d: two interface-only neighbors learn one link-local address on
# parallel links.
set -euo pipefail

TOPO=m53d-interface-only-shared-address-frr
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

FRR="clab-${TOPO}-frr1"
LL=fe80::53:dff:fe00:1
PREFIX=198.51.100.53/32
TABLE_ID=1000
METRIC=200
DAEMON_LOG=/tmp/m53d-rustbgpd.log

save_daemon_log() {
    local rc=$?
    docker exec "$RUSTBGPD" cat "$DAEMON_LOG" >/tmp/m53d-last-daemon.log 2>/dev/null || true
    _cleanup_on_exit
    return "$rc"
}
trap save_daemon_log EXIT

resolve_grpc_addr

neighbors() { grpcurl_call "$GRPC_ADDR" rustbgpd.v1.NeighborService/ListNeighbors; }
received() { grpcurl_call "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes; }
best() {
    grpcurl_call -d '{"prefix_filter":"198.51.100.53","prefix_filter_length":32}' \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListBestRoutes
}
fib() { grpcurl_call "$GRPC_ADDR" rustbgpd.v1.RibService/ListFibRoutes; }
route() { docker exec "$RUSTBGPD" ip route show table "$TABLE_ID" exact "$PREFIX"; }

dump_state() {
    neighbors >&2 || true
    received >&2 || true
    best >&2 || true
    fib >&2 || true
    route >&2 || true
    docker exec "$FRR" ip -6 addr show >&2 || true
    docker exec "$FRR" vtysh -c 'show bgp summary' >&2 || true
}

# Established, non-stale neighbors bound to $LL, as "interface flapCount".
established_rows() {
    neighbors | jq -r --arg ll "$LL" '
        .neighbors[]? | select(.learnedPeerAddress == $ll
            and (.state == "SESSION_STATE_ESTABLISHED" or .state == 6) and .stale != true)
        | "\(.config.interface) \(.flapCount // 0)"'
}

rows_are() { [ "$(established_rows | awk '{ print $1 }' | sort | xargs)" = "$1" ]; }

wait_rows() {
    local expected=$1 label=$2
    if wait_until 45 2 rows_are "$expected"; then
        ok "$label"
        return 0
    fi
    fail "$label"
    dump_state
    exit 1
}

# Received paths, FIB next hops and the kernel route all match the expected
# set of interfaces ("eth1 eth2" or one of them).
paths_match() {
    local expected=$1 count text dev
    count=$(wc -w <<<"$expected")
    received | jq -e --argjson count "$count" '
        [.routes[]? | select(.prefix == "198.51.100.53" and .prefixLength == 32)]
        | length == $count' >/dev/null 2>&1 || return 1
    fib | jq -e --argjson count "$count" '
        [.routes[]? | select(.prefix == "198.51.100.53" and .prefixLength == 32)]
        | length == 1 and (.[0].nextHops | length) == $count' >/dev/null 2>&1 || return 1
    text=$(route) || return 1
    grep -Fq 'proto bgp' <<<"$text" && grep -Fq "metric $METRIC" <<<"$text" || return 1
    for dev in eth1 eth2; do
        if [[ " $expected " == *" $dev "* ]]; then
            grep -Fq "via inet6 $LL dev $dev" <<<"$text" || return 1
        elif grep -Fq "dev $dev" <<<"$text"; then
            return 1
        fi
    done
}

wait_paths() {
    local expected=$1 label=$2
    if wait_until 30 1 paths_match "$expected"; then
        ok "$label"
        return 0
    fi
    fail "$label"
    dump_state
    exit 1
}

best_interface() {
    best | jq -r '[.routes[]? | select(.prefix == "198.51.100.53" and .prefixLength == 32)]
        | if length == 1 then .[0].peerInterface // "" else error("expected one best route") end'
}

assert_best_is_eth1() {
    local label=$1 got
    got=$(best_interface) || { fail "$label: no single best route"; dump_state; exit 1; }
    if [ "$got" != eth1 ]; then
        fail "$label: best path from $got, expected eth1"
        dump_state
        exit 1
    fi
    ok "$label"
}

# Take FRR's end of one link down and back up, so that link's session comes
# up after the other's.
bounce() {
    local dev=$1
    docker exec "$FRR" ip link set "$dev" down
    local other=eth1
    [ "$dev" = eth1 ] && other=eth2
    wait_rows "$other" "carrier loss on $dev left only the $other neighbor Established"
    wait_paths "$other" "carrier loss on $dev removed only the $dev path"
    docker exec "$FRR" ip link set "$dev" up
    wait_rows "eth1 eth2" "$dev neighbor re-established after carrier restoration"
    wait_paths "eth1 eth2" "ECMP restored after $dev carrier restoration"
}

log "M53d: two interface-only neighbors learn one link-local address"

for dev in eth1 eth2; do
    if docker exec "$FRR" ip -4 addr show dev "$dev" | grep -q ' inet '; then
        fail "FRR $dev has an IPv4 fabric address"; exit 1
    fi
    if ! docker exec "$FRR" ip -j -6 addr show dev "$dev" | jq -e --arg ll "$LL" '
        [.[].addr_info[]? | select(.scope == "link")] | length == 1 and .[0].local == $ll' >/dev/null; then
        fail "FRR $dev does not carry the shared EUI-64 link-local $LL"
        docker exec "$FRR" ip -6 addr show >&2
        exit 1
    fi
done
ok "FRR eth1 and eth2 share $LL; no IPv4 on the fabric"

start_rustbgpd "/usr/local/bin/start-rustbgpd.sh >$DAEMON_LOG 2>&1"

wait_rows "eth1 eth2" "both interface-only neighbors learned $LL and established"
wait_paths "eth1 eth2" "$PREFIX installed as ECMP via $LL on eth1 and eth2"
assert_best_is_eth1 "best path is the eth1 neighbor's"

# Bring eth1's session up last, then eth2's: the best path's neighbor does
# not depend on which session came up first.
bounce eth1
assert_best_is_eth1 "best path is still eth1's after eth1 came up last"
bounce eth2
assert_best_is_eth1 "best path is still eth1's after eth2 came up last"
if docker exec "$RUSTBGPD" grep -q '"reason":"bmp_identity_conflict"' "$DAEMON_LOG"; then
    fail "an address was refused although no BMP collector is configured"; exit 1
fi

print_summary
