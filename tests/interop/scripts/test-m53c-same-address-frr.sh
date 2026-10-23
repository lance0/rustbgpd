#!/usr/bin/env bash
# M53c: two neighbors share one link-local address on parallel links.
set -euo pipefail

TOPO=m53c-same-address-frr
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

FRR="clab-${TOPO}-frr1"
LL=fe80::53:cff:fe00:1
PREFIX=198.51.100.53/32
INJECTED=192.0.2.53/32
TABLE_ID=1000
METRIC=200
DAEMON_LOG=/tmp/m53c-rustbgpd.log

save_daemon_log() {
    local rc=$?
    docker exec "$RUSTBGPD" cat "$DAEMON_LOG" >/tmp/m53c-last-daemon.log 2>/dev/null || true
    _cleanup_on_exit
    return "$rc"
}
trap save_daemon_log EXIT

resolve_grpc_addr

neighbors() { grpcurl_call "$GRPC_ADDR" rustbgpd.v1.NeighborService/ListNeighbors; }
received() { grpcurl_call "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes; }
fib() { grpcurl_call "$GRPC_ADDR" rustbgpd.v1.RibService/ListFibRoutes; }
route() { docker exec "$RUSTBGPD" ip route show table "$TABLE_ID" exact "$PREFIX"; }
neighbor_call() {
    local method=$1 interface=$2
    grpcurl_call -d "{\"address\":\"$LL\",\"interface\":\"$interface\"}" \
        "$GRPC_ADDR" "rustbgpd.v1.NeighborService/$method" >/dev/null
}
# rustbgpd's own static link-local address on each link, as FRR names it.
frr_peer() { case $1 in eth1) echo fe80::1 ;; eth2) echo fe80::2 ;; esac; }
frr_neighbor() { docker exec "$FRR" vtysh -c "show bgp neighbors $(frr_peer "$1") json"; }

dump_state() {
    neighbors >&2 || true
    received >&2 || true
    fib >&2 || true
    route >&2 || true
    docker exec "$FRR" ip -6 addr show >&2 || true
    docker exec "$FRR" vtysh -c 'show bgp summary' >&2 || true
}

# Established, non-stale rustbgpd neighbors at $LL, as "interface flapCount".
established_rows() {
    neighbors | jq -r --arg ll "$LL" '
        .neighbors[]? | select(.config.address == $ll
            and (.state == "SESSION_STATE_ESTABLISHED" or .state == 6) and .stale != true)
        | "\(.config.interface) \(.flapCount // 0)"'
}

flaps() { established_rows | awk -v dev="$1" '$1 == dev { print $2 }'; }

frr_established() {
    frr_neighbor "$1" | jq -e '.. | objects | select(.bgpState? == "Established")' >/dev/null 2>&1
}

# Paths for $PREFIX in rustbgpd, the FIB next-hop count, and the kernel route
# all match the expected set of interfaces ("eth1 eth2" or "eth1").
paths_match() {
    local expected=$1 count text
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

wait_rows() {
    local expected=$1 label=$2
    rows_are() { [ "$(established_rows | awk '{ print $1 }' | sort | xargs)" = "$1" ]; }
    if wait_until 45 2 rows_are "$expected"; then
        ok "$label"
        return 0
    fi
    fail "$label"
    dump_state
    exit 1
}

log "M53c: one link-local address on two parallel links"

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

wait_rows "eth1 eth2" "rustbgpd established $LL%eth1 and $LL%eth2 as two neighbors"
if ! wait_until 30 2 frr_established eth1 || ! wait_until 30 2 frr_established eth2; then
    fail "FRR did not establish both interface sessions"; dump_state; exit 1
fi
ok "FRR established both interface sessions"

wait_paths "eth1 eth2" "$PREFIX installed as ECMP via $LL on eth1 and eth2"

grpcurl_call -d "{\"prefix\":\"192.0.2.53\",\"prefix_length\":32,\"next_hop\":\"$(frr_peer eth1)\",\"origin\":0}" \
    "$GRPC_ADDR" rustbgpd.v1.InjectionService/AddPath >/dev/null
frr_has_both() {
    docker exec "$FRR" vtysh -c "show bgp ipv4 unicast $INJECTED json" | jq -e '
        [.paths[]? | (.peer.interface // .peer.hostname // .peer.peerId)] | length == 2' >/dev/null 2>&1
}
if ! wait_until 30 1 frr_has_both; then
    fail "FRR did not receive $INJECTED over both sessions"
    docker exec "$FRR" vtysh -c "show bgp ipv4 unicast $INJECTED json" >&2 || true
    exit 1
fi
ok "FRR received $INJECTED over both sessions"

# Route refresh toward one neighbor reaches only that link's FRR session.
refresh_count() { frr_neighbor "$1" | jq '[.. | objects | .routeRefreshRecv? // empty] | first // 0'; }
before1=$(refresh_count eth1)
before2=$(refresh_count eth2)
flaps1=$(flaps eth1)
flaps2=$(flaps eth2)
neighbor_call SoftResetIn eth1
refreshed() { [ "$(refresh_count eth1)" -gt "$before1" ]; }
if ! wait_until 20 1 refreshed; then
    fail "FRR eth1 session received no route refresh"; dump_state; exit 1
fi
[ "$(refresh_count eth2)" = "$before2" ] || { fail "refresh for eth1 reached the eth2 session"; exit 1; }
wait_paths "eth1 eth2" "route refresh on eth1 kept both paths"
if [ "$(flaps eth1)" != "$flaps1" ] || [ "$(flaps eth2)" != "$flaps2" ]; then
    fail "route refresh flapped a session"; exit 1
fi
ok "route refresh reached only the eth1 session"

# Carrier loss on eth2 takes down only the eth2 neighbor and its path. FRR's
# end of the link goes down, so rustbgpd sees carrier loss and keeps its own
# static link-local address (an admin-down would flush it).
docker exec "$FRR" ip link set eth2 down
wait_rows "eth1" "carrier loss on eth2 left only the eth1 neighbor Established"
wait_paths "eth1" "carrier loss on eth2 removed only the eth2 path"
[ "$(flaps eth1)" = "$flaps1" ] || { fail "carrier loss on eth2 flapped eth1"; exit 1; }
docker exec "$FRR" ip link set eth2 up
wait_rows "eth1 eth2" "eth2 neighbor re-established after carrier restoration"
wait_paths "eth1 eth2" "ECMP restored after carrier restoration"
[ "$(flaps eth1)" = "$flaps1" ] || { fail "eth2 recovery flapped eth1"; exit 1; }

# Deleting the eth2 neighbor keeps the eth1 neighbor; re-adding restores eth2.
neighbor_call DeleteNeighbor eth2
gone() { ! neighbors | jq -e --arg ll "$LL" '.neighbors[]? | select(.config.address == $ll and .config.interface == "eth2")' >/dev/null; }
wait_until 20 1 gone || { fail "eth2 neighbor still listed after delete"; dump_state; exit 1; }
persisted() { docker exec "$RUSTBGPD" grep -c "^interface = \"$1\"" /etc/rustbgpd/config.toml || true; }
if [ "$(persisted eth1)" != 1 ] || [ "$(persisted eth2)" != 0 ]; then
    fail "deleting the eth2 neighbor did not persist only that record"
    docker exec "$RUSTBGPD" cat /etc/rustbgpd/config.toml >&2 || true
    exit 1
fi
ok "deleting the eth2 neighbor removed only its configuration record"
wait_rows "eth1" "deleting the eth2 neighbor left the eth1 neighbor Established"
wait_paths "eth1" "deleting the eth2 neighbor removed only its path"
[ "$(flaps eth1)" = "$flaps1" ] || { fail "deleting eth2 flapped eth1"; exit 1; }
grpcurl_call -d "{\"intent\":{\"config\":{\"address\":\"$LL\",\"interface\":\"eth2\",\"remote_asn\":65002,
    \"description\":\"frr1-m53c-eth2\",\"hold_time\":90,\"families\":[\"ipv4_unicast\",\"ipv6_unicast\"]},
    \"overrideMask\":{\"paths\":[\"families\"]}}}" \
    "$GRPC_ADDR" rustbgpd.v1.NeighborService/AddNeighbor >/dev/null
wait_rows "eth1 eth2" "re-added eth2 neighbor established beside eth1"
if [ "$(persisted eth1)" != 1 ] || [ "$(persisted eth2)" != 1 ]; then
    fail "re-adding the eth2 neighbor did not persist beside eth1"
    docker exec "$RUSTBGPD" cat /etc/rustbgpd/config.toml >&2 || true
    exit 1
fi
wait_paths "eth1 eth2" "ECMP restored after re-adding the eth2 neighbor"
[ "$(flaps eth1)" = "$flaps1" ] || { fail "re-adding eth2 flapped eth1"; exit 1; }

print_summary
