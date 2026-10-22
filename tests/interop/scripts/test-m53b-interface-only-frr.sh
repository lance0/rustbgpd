#!/usr/bin/env bash
# M53b: RA-discovered interface-only peers and scoped RFC 8950 forwarding.
set -euo pipefail

TOPO=m53b-interface-only-frr
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

FRR1="clab-${TOPO}-frr1"
FRR2="clab-${TOPO}-frr2"
PREFIX=198.51.100.53/32
INJECTED_PREFIX=192.0.2.53/32
TABLE_ID=1000
METRIC=200

resolve_grpc_addr

neighbors() { grpcurl_call "$GRPC_ADDR" rustbgpd.v1.NeighborService/ListNeighbors; }
received() { grpcurl_call "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes; }
fib() { grpcurl_call "$GRPC_ADDR" rustbgpd.v1.RibService/ListFibRoutes; }
route() { docker exec "$RUSTBGPD" ip route show table "$TABLE_ID" exact "$PREFIX"; }

dump_state() {
    neighbors >&2 || true
    received >&2 || true
    fib >&2 || true
    route >&2 || true
    for frr in "$FRR1" "$FRR2"; do
        docker exec "$frr" ip -6 addr show dev eth1 >&2 || true
        docker exec "$frr" vtysh -c 'show bgp summary' >&2 || true
    done
}

link_local() {
    local node=$1 dev=$2
    docker exec "$node" ip -j -6 addr show dev "$dev" | jq -r '
        [.[] .addr_info[]? | select(.scope == "link" and (.local | startswith("fe80:"))) | .local]
        | if length == 1 then .[0] else error("expected one kernel link-local address") end'
}

assert_fabric_addresses() {
    for pair in "$RUSTBGPD eth1" "$RUSTBGPD eth2" "$FRR1 eth1" "$FRR2 eth1"; do
        local node=${pair% *} dev=${pair#* }
        if docker exec "$node" ip -4 addr show dev "$dev" | grep -q ' inet '; then
            fail "$node $dev has an IPv4 fabric address"; return 1
        fi
        if ! docker exec "$node" ip -d link show dev "$dev" | grep -q 'addrgenmode eui64'; then
            fail "$node $dev is not generating EUI-64 link-local addresses"; return 1
        fi
        if ! docker exec "$node" ip -j -6 addr show dev "$dev" | jq -e '
            [.[].addr_info[]?] | length == 1 and .[0].scope == "link"' >/dev/null; then
            fail "$node $dev has other IPv6 fabric addresses"; return 1
        fi
        link_local "$node" "$dev" >/dev/null
    done
    LL1=$(link_local "$FRR1" eth1)
    LL2=$(link_local "$FRR2" eth1)
    LOCAL_LL=$(link_local "$RUSTBGPD" eth1)
    if [ "$LL1" = "$LL2" ] || [ "$LOCAL_LL" = "$(link_local "$RUSTBGPD" eth2)" ]; then
        fail "parallel fabric links generated duplicate link-local addresses"; return 1
    fi
    ok "fabric uses distinct kernel EUI-64 link-local addresses and no IPv4"
}

wait_established() {
    local expected=$1
    for _ in $(seq 1 45); do
        local frr_ok=0 rust_ok=0
        if docker exec "$FRR1" vtysh -c 'show bgp summary json' \
            | jq -e '.. | objects | select(.state? == "Established" or .bgpState? == "Established")' >/dev/null 2>&1 \
            && docker exec "$FRR2" vtysh -c 'show bgp summary json' \
            | jq -e '.. | objects | select(.state? == "Established" or .bgpState? == "Established")' >/dev/null 2>&1; then
            frr_ok=1
        fi
        if neighbors | jq -e --argjson count "$expected" --arg one "$LL1" --arg two "$LL2" '
            [.neighbors[]? | select((.config.interface == "eth1" and .config.address == $one
                or .config.interface == "eth2" and .config.address == $two)
                and (.state == "SESSION_STATE_ESTABLISHED" or .state == 6)
                and (.stale != true))] | length == $count' >/dev/null 2>&1; then
            rust_ok=1
        fi
        if [ "$frr_ok" = 1 ] && [ "$rust_ok" = 1 ]; then
            ok "FRR and rustbgpd established $expected interface-only peers"
            return 0
        fi
        sleep 2
    done
    fail "interface-only peers did not establish on both sides"
    dump_state
    return 1
}

wait_paths() {
    local expected=$1
    for _ in $(seq 1 30); do
        if received | jq -e --argjson count "$expected" '
            [.routes[]? | select(.prefix == "198.51.100.53" and .prefixLength == 32)]
            | length == $count' >/dev/null 2>&1 \
            && fib | jq -e --argjson count "$expected" '
                [.routes[]? | select(.prefix == "198.51.100.53" and .prefixLength == 32)]
                | length == 1 and (.[0].nextHops | length) == $count' >/dev/null 2>&1; then
            ok "$expected IPv4 paths received and selected in FIB"
            return 0
        fi
        sleep 1
    done
    fail "IPv4 path count did not reach $expected"
    dump_state
    return 1
}

wait_kernel_route() {
    local expected=$1 text
    for _ in $(seq 1 30); do
        text=$(route)
        if [ "$expected" = 2 ]; then
            if grep -Fq "nexthop via inet6 $LL1 dev eth1" <<<"$text" \
                && grep -Fq "nexthop via inet6 $LL2 dev eth2" <<<"$text" \
                && grep -Fq 'proto bgp' <<<"$text" \
                && grep -Fq "metric $METRIC" <<<"$text"; then
                ok "$PREFIX installed through both scoped link-local next hops"
                return 0
            fi
        elif grep -Fq "via inet6 $LL1 dev eth1" <<<"$text" \
            && ! grep -Fq 'dev eth2' <<<"$text" \
            && grep -Fq 'proto bgp' <<<"$text"; then
            ok "$PREFIX removed failed eth2 next hop"
            return 0
        fi
        sleep 1
    done
    fail "$PREFIX kernel route did not converge to $expected next hops"
    dump_state
    return 1
}

assert_outbound() {
    grpcurl_call -d "{\"prefix\":\"192.0.2.53\",\"prefix_length\":32,\"next_hop\":\"$LOCAL_LL\",\"origin\":0}" \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/AddPath >/dev/null
    for frr in "$FRR1" "$FRR2"; do
        local found=0
        for _ in $(seq 1 30); do
            if docker exec "$frr" vtysh -c "show bgp ipv4 unicast $INJECTED_PREFIX json" \
                | jq -e 'tostring | contains("192.0.2.53") and contains("fe80:")' >/dev/null 2>&1; then
                found=1; break
            fi
            sleep 1
        done
        if [ "$found" != 1 ]; then
            fail "$frr did not receive IPv4 over the link-local session"
            dump_state
            return 1
        fi
    done
    ok "both FRR peers received IPv4 with RFC 8950 link-local next hops"
}

assert_fabric_addresses
start_rustbgpd
wait_established 2
wait_paths 2
wait_kernel_route 2
assert_outbound

docker exec "$FRR2" ip link set eth1 down
down=0
for _ in $(seq 1 30); do
    if neighbors | jq -e '
        any(.neighbors[]?; .config.interface == "eth1"
            and (.state == "SESSION_STATE_ESTABLISHED" or .state == 6))
        and all(.neighbors[]?; .config.interface != "eth2"
            or (.state != "SESSION_STATE_ESTABLISHED" and .state != 6))' >/dev/null 2>&1; then
        ok "carrier loss ended eth2 session"
        down=1
        break
    fi
    sleep 1
done
if [ "$down" != 1 ]; then
    fail "eth2 session did not leave Established with eth1 still up"; dump_state; exit 1
fi
wait_paths 1
wait_kernel_route 1

docker exec "$FRR2" ip link set eth1 up
wait_established 2
wait_paths 2
wait_kernel_route 2
print_summary
