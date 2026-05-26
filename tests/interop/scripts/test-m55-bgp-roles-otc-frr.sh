#!/usr/bin/env bash
# M55 interop test — ADR-0071 BGP Roles + Only-to-Customer (RFC 9234).

set -euo pipefail

TOPO="m55-bgp-roles-otc-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"

FRR_CUSTOMER="clab-${TOPO}-frr-customer"
FRR_RSCLIENT="clab-${TOPO}-frr-rsclient"
FRR_PEER="clab-${TOPO}-frr-peer"
FRR_MISMATCH="clab-${TOPO}-frr-mismatch"
FRR_NOROLE="clab-${TOPO}-frr-norole"
RAW_CUSTOMER="clab-${TOPO}-raw-customer"

INJECTED_PREFIX="192.0.2.55/32"
LEAK_PREFIX="198.51.100.55/32"
MALFORMED_PREFIX="198.51.100.56/32"
WITHDRAWN_PREFIX="198.51.100.57/32"

resolve_grpc_addr
RUST_IP=$(resolve_ip "$RUSTBGPD")
start_rustbgpd

grpc_list_neighbors() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/ListNeighbors
}

grpc_list_received() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes
}

grpc_inject_route() {
    local prefix=$1
    local addr=${prefix%/*}
    local plen=${prefix#*/}
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"prefix\": \"$addr\", \"prefix_length\": $plen, \"next_hop\": \"10.55.1.1\", \"origin\": 0}" \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/AddPath >/dev/null
}

dump_state_on_failure() {
    echo "===== rustbgpd NeighborService/ListNeighbors =====" >&2
    grpc_list_neighbors | jq . >&2 || true
    echo "===== rustbgpd RibService/ListReceivedRoutes =====" >&2
    grpc_list_received | jq . >&2 || true
    echo "===== rustbgpd metrics =====" >&2
    curl -fsS "http://${RUST_IP}:9179/metrics" | grep 'bgp_otc_routes_blocked_total' >&2 || true
    for frr in "$FRR_CUSTOMER" "$FRR_RSCLIENT" "$FRR_PEER" "$FRR_MISMATCH" "$FRR_NOROLE"; do
        echo "===== $frr BGP summary =====" >&2
        docker exec "$frr" vtysh -c 'show bgp summary' >&2 || true
        echo "===== $frr neighbor detail =====" >&2
        docker exec "$frr" vtysh -c 'show bgp neighbors' >&2 || true
    done
    echo "===== raw fixture logs =====" >&2
    docker logs "$RAW_CUSTOMER" >&2 || true
}

wait_rust_role_status() {
    local addr=$1 local_role=$2 remote_role=$3
    log "Waiting for rustbgpd neighbor $addr Role status $local_role/$remote_role..."
    for _ in $(seq 1 30); do
        local json
        if json=$(grpc_list_neighbors 2>/dev/null); then
            if printf '%s\n' "$json" | jq -e \
                --arg addr "$addr" \
                --arg local_role "$local_role" \
                --arg remote_role "$remote_role" '
                any(.neighbors[]?;
                    .config.address == $addr
                    and .localRole == $local_role
                    and .remoteRole == $remote_role
                    and .roleNegotiated == true
                    and (.state == "SESSION_STATE_ESTABLISHED" or .state == 6)
                )' >/dev/null; then
                ok "rustbgpd reports $addr negotiated Role $local_role/$remote_role"
                return 0
            fi
        fi
        sleep 1
    done
    fail "rustbgpd did not report negotiated Role for $addr"
    dump_state_on_failure
    return 1
}

wait_rust_not_established_with_notification() {
    local addr=$1 label=$2
    log "Waiting for $label to fail closed with a sent NOTIFICATION..."
    for _ in $(seq 1 45); do
        local json
        if json=$(grpc_list_neighbors 2>/dev/null); then
            if printf '%s\n' "$json" | jq -e \
                --arg addr "$addr" '
                any(.neighbors[]?;
                    .config.address == $addr
                    and (.state != "SESSION_STATE_ESTABLISHED" and .state != 6)
                    and ((.notificationsSent // 0) | tonumber) > 0
                )' >/dev/null; then
                ok "$label rejected before Established and sent NOTIFICATION"
                return 0
            fi
        fi
        sleep 2
    done
    fail "$label did not fail closed with a sent NOTIFICATION"
    dump_state_on_failure
    return 1
}

assert_frr_route_has_otc() {
    local frr=$1 prefix=$2
    log "Checking $frr received $prefix with OTC..."
    for _ in $(seq 1 30); do
        local text json
        text=$(docker exec "$frr" vtysh -c "show bgp ipv4 unicast $prefix" 2>/dev/null || true)
        json=$(docker exec "$frr" vtysh -c "show bgp ipv4 unicast $prefix json" 2>/dev/null || true)
        if printf '%s\n%s\n' "$text" "$json" \
            | grep -Eiq 'only[ -]?to[ -]?customer|otc|onlyToCustomer' \
            && printf '%s\n%s\n' "$text" "$json" | grep -q '65001'; then
            ok "$frr reports OTC=65001 on $prefix"
            return 0
        fi
        sleep 1
    done
    fail "$frr did not report OTC on $prefix"
    dump_state_on_failure
    return 1
}

wait_received_presence() {
    local prefix=$1 expected=$2 desc=$3
    local addr=${prefix%/*}
    local plen=${prefix#*/}
    log "Waiting for received-route presence for $prefix -> $expected ($desc)..."
    for _ in $(seq 1 30); do
        local json found
        if json=$(grpc_list_received 2>/dev/null); then
            found=$(printf '%s\n' "$json" | jq -r --arg addr "$addr" --argjson plen "$plen" '
                any(.routes[]?; .prefix == $addr and .prefixLength == $plen)' 2>/dev/null)
            if [ "$found" = "$expected" ]; then
                ok "$desc"
                return 0
            fi
        fi
        sleep 1
    done
    fail "$desc"
    dump_state_on_failure
    return 1
}

wait_otc_counter_at_least() {
    local reason=$1 want=$2
    log "Waiting for OTC counter reason=$reason >= $want..."
    for _ in $(seq 1 30); do
        local metrics value
        metrics=$(curl -fsS "http://${RUST_IP}:9179/metrics" 2>/dev/null || true)
        value=$(printf '%s\n' "$metrics" | awk -v reason="$reason" '
            $1 ~ /^bgp_otc_routes_blocked_total/ && $0 ~ "reason=\"" reason "\"" { print $2; found=1 }
            END { if (!found) print 0 }' | tail -1)
        if [ "${value%.*}" -ge "$want" ] 2>/dev/null; then
            ok "OTC counter reason=$reason reached $value"
            return 0
        fi
        sleep 1
    done
    fail "OTC counter reason=$reason did not reach $want"
    dump_state_on_failure
    return 1
}

start_raw_fixture() {
    log "Starting raw Customer-role BGP fixture..."
    docker exec -d "$RAW_CUSTOMER" python3 /usr/local/bin/m55_raw_bgp.py
}

start_raw_fixture

wait_frr_established "$FRR_CUSTOMER" "10.55.1.1" "Provider↔Customer"
wait_frr_established "$FRR_RSCLIENT" "10.55.2.1" "RS↔RS-Client"
wait_frr_established "$FRR_PEER" "10.55.3.1" "Peer↔Peer"

wait_rust_role_status "10.55.1.2" "provider" "customer"
wait_rust_role_status "10.55.2.2" "rs" "rs-client"
wait_rust_role_status "10.55.3.2" "peer" "peer"

wait_rust_not_established_with_notification "10.55.4.2" "Provider↔Provider mismatch"
wait_rust_not_established_with_notification "10.55.5.2" "strict Role with no remote Role"

wait_rust_role_status "10.55.6.2" "provider" "customer"
grpc_inject_route "$INJECTED_PREFIX"
assert_frr_route_has_otc "$FRR_CUSTOMER" "$INJECTED_PREFIX"

wait_received_presence "$WITHDRAWN_PREFIX" true "raw accepted baseline route before malformed withdrawal"
wait_received_presence "$LEAK_PREFIX" false "raw Customer OTC route rejected as I1 leak"
wait_received_presence "$MALFORMED_PREFIX" false "malformed OTC announcement treated as withdraw"
wait_received_presence "$WITHDRAWN_PREFIX" false "withdrawal in malformed OTC UPDATE still applied"
wait_otc_counter_at_least "ingress_from_customer_rsclient" 1
wait_otc_counter_at_least "malformed_length" 1

print_summary
