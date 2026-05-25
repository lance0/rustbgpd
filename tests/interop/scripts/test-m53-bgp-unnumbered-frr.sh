#!/usr/bin/env bash
# M53 interop test — ADR-0069 BGP unnumbered / IPv6 link-local peering.
#
# Two FRR peers advertise the same IPv4 prefix to rustbgpd over IPv6
# link-local-only BGP sessions. rustbgpd must retain each remote link-local
# next-hop's interface scope and install kernel ECMP through both devices.

set -euo pipefail

TOPO="m53-bgp-unnumbered-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"

FRR1="clab-${TOPO}-frr1"
FRR2="clab-${TOPO}-frr2"
TABLE_ID=1000
METRIC=200
PREFIX="198.51.100.53/32"
INJECTED_PREFIX="192.0.2.53/32"
REMOTE_LL="fe80::2"
REMOTE_LL2="fe80::3"
LOCAL_LL="fe80::1"

resolve_grpc_addr
start_rustbgpd

grpc_list_received() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes
}

grpc_list_fib() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListFibRoutes
}

grpc_list_neighbors() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/ListNeighbors
}

grpc_inject_route() {
    local addr=${INJECTED_PREFIX%/*}
    local plen=${INJECTED_PREFIX#*/}
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"prefix\": \"$addr\", \"prefix_length\": $plen, \"next_hop\": \"$LOCAL_LL\", \"origin\": 0}" \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/AddPath >/dev/null
}

kernel_route() {
    docker exec "$RUSTBGPD" ip route show table "$TABLE_ID" exact "$PREFIX" 2>/dev/null || true
}

dump_state_on_failure() {
    echo "===== rustbgpd NeighborService/ListNeighbors =====" >&2
    grpc_list_neighbors | jq . >&2 || true
    echo "===== rustbgpd RibService/ListReceivedRoutes =====" >&2
    grpc_list_received | jq . >&2 || true
    echo "===== rustbgpd RibService/ListFibRoutes =====" >&2
    grpc_list_fib | jq . >&2 || true
    echo "===== rustbgpd table $TABLE_ID =====" >&2
    docker exec "$RUSTBGPD" ip route show table "$TABLE_ID" >&2 || true
    for frr in "$FRR1" "$FRR2"; do
        echo "===== $frr interfaces =====" >&2
        docker exec "$frr" ip addr show dev eth1 >&2 || true
        echo "===== $frr BGP summary =====" >&2
        docker exec "$frr" vtysh -c 'show bgp summary' >&2 || true
        echo "===== $frr IPv4 BGP table =====" >&2
        docker exec "$frr" vtysh -c 'show bgp ipv4 unicast json' >&2 || true
    done
}

wait_frr_interface_established() {
    local frr=$1 label=$2
    log "Waiting for $label BGP interface peer to reach Established..."
    for _ in $(seq 1 45); do
        local json
        json=$(docker exec "$frr" vtysh -c "show bgp summary json" 2>/dev/null || true)
        if printf '%s\n' "$json" | grep -q '"state":"Established"\|"bgpState":"Established"'; then
            ok "$label Established"
            return 0
        fi
        sleep 2
    done
    fail "$label did not reach Established"
    dump_state_on_failure
    return 1
}

assert_no_ipv4_on_fabric() {
    if docker exec "$RUSTBGPD" sh -lc 'ip -4 addr show dev eth1; ip -4 addr show dev eth2' | grep -q ' inet '; then
        fail "rustbgpd has an IPv4 address on an unnumbered fabric interface"
        docker exec "$RUSTBGPD" ip addr show >&2 || true
        return 1
    fi
    for frr in "$FRR1" "$FRR2"; do
        if docker exec "$frr" ip -4 addr show dev eth1 | grep -q ' inet '; then
            fail "$frr has an IPv4 address on eth1"
            docker exec "$frr" ip addr show dev eth1 >&2 || true
            return 1
        fi
    done
    ok "No IPv4 addresses present on the unnumbered fabric links"
}

assert_neighbor_scope_status() {
    log "Checking rustbgpd reports both scoped link-local neighbors..."
    local json
    json=$(grpc_list_neighbors)
    for entry in "$REMOTE_LL eth1" "$REMOTE_LL2 eth2"; do
        local addr iface
        addr=${entry% *}
        iface=${entry#* }
        if printf '%s\n' "$json" | jq -e --arg iface "$iface" --arg addr "$addr" '
            any(.neighbors[]?;
                .config.address == $addr
                and .config.interface == $iface
                and (.state == "SESSION_STATE_ESTABLISHED" or .state == 6)
            )' >/dev/null; then
            ok "rustbgpd neighbor status includes $addr%$iface Established"
        else
            fail "rustbgpd neighbor status missing Established $addr%$iface"
            dump_state_on_failure
            return 1
        fi
    done
}

wait_received_paths() {
    local expected=$1
    local addr=${PREFIX%/*}
    local plen=${PREFIX#*/}
    log "Waiting for rustbgpd to receive $expected path(s) for $PREFIX..."
    for _ in $(seq 1 30); do
        local json count
        if json=$(grpc_list_received 2>/dev/null); then
            count=$(printf '%s\n' "$json" | jq -r --arg addr "$addr" --argjson plen "$plen" '
                [.routes[]? | select(.prefix == $addr and .prefixLength == $plen)] | length' 2>/dev/null)
            if [ "$count" = "$expected" ]; then
                ok "rustbgpd received $count path(s) for $PREFIX"
                return 0
            fi
        fi
        sleep 1
    done
    fail "rustbgpd did not receive $expected path(s) for $PREFIX"
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
        if json=$(grpc_list_fib 2>/dev/null); then
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

wait_kernel_ecmp() {
    log "Waiting for $PREFIX kernel ECMP via $REMOTE_LL dev eth1 + $REMOTE_LL2 dev eth2..."
    for _ in $(seq 1 30); do
        local route
        route=$(kernel_route)
        if echo "$route" | grep -q "proto bgp" \
            && echo "$route" | grep -q "metric $METRIC" \
            && echo "$route" | grep -q "nexthop via inet6 $REMOTE_LL dev eth1" \
            && echo "$route" | grep -q "nexthop via inet6 $REMOTE_LL2 dev eth2"; then
            ok "$PREFIX installed as link-local ECMP via eth1 + eth2"
            return 0
        fi
        sleep 1
    done
    fail "$PREFIX did not install as link-local ECMP"
    dump_state_on_failure
    return 1
}

wait_kernel_single() {
    local survivor_dev=$1
    local withdrawn_dev=$2
    local survivor_ll=$3
    log "Waiting for $PREFIX to collapse to $survivor_ll dev $survivor_dev..."
    for _ in $(seq 1 30); do
        local route
        route=$(kernel_route)
        if echo "$route" | grep -q "proto bgp" \
            && echo "$route" | grep -q "metric $METRIC" \
            && echo "$route" | grep -q "via inet6 $survivor_ll dev $survivor_dev" \
            && ! echo "$route" | grep -q "dev $withdrawn_dev" \
            && ! echo "$route" | grep -q "nexthop"; then
            ok "$PREFIX collapsed to single link-local next-hop on $survivor_dev"
            return 0
        fi
        sleep 1
    done
    fail "$PREFIX did not collapse to single next-hop on $survivor_dev"
    dump_state_on_failure
    return 1
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

assert_frr_received_injected_route() {
    local frr=$1 label=$2
    log "Checking $label received injected $INJECTED_PREFIX with link-local next-hop..."
    for _ in $(seq 1 30); do
        local json
        json=$(docker exec "$frr" vtysh -c "show bgp ipv4 unicast $INJECTED_PREFIX json" 2>/dev/null || true)
        if printf '%s\n' "$json" | grep -q "${INJECTED_PREFIX%/*}" \
            && printf '%s\n' "$json" | grep -qi 'fe80:'; then
            ok "$label received injected route with fe80:: next-hop"
            return 0
        fi
        sleep 1
    done
    fail "$label did not receive injected route with link-local next-hop"
    dump_state_on_failure
    return 1
}

assert_no_ipv4_on_fabric
wait_frr_interface_established "$FRR1" "rustbgpd ↔ frr1"
wait_frr_interface_established "$FRR2" "rustbgpd ↔ frr2"
assert_neighbor_scope_status

wait_received_paths 2
wait_kernel_ecmp
wait_grpc_next_hops 2

grpc_inject_route
assert_frr_received_injected_route "$FRR1" "frr1"
assert_frr_received_injected_route "$FRR2" "frr2"

frr_network "$FRR2" del
wait_received_paths 1
wait_kernel_single eth1 eth2 "$REMOTE_LL"
wait_grpc_next_hops 1

frr_network "$FRR2" add
wait_received_paths 2
wait_kernel_ecmp
wait_grpc_next_hops 2

print_summary
