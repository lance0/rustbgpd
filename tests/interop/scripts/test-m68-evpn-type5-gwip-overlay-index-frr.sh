#!/usr/bin/env bash
# M68 interop test — native rustbgpd GW-IP overlay-index Type 5
# origination consumed by FRR's `enable-resolve-overlay-index` path.

TOPO="m68-evpn-type5-gwip-overlay-index-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

PE1="clab-${TOPO}-pe1"
PE2="clab-${TOPO}-pe2"
RUSTBGPD="$PE1"
export RUSTBGPD

INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

PE1_IP="10.0.0.1"
L3VNI=100
L2VNI=10
TENANT_VRF="vrf1"
PE1_TABLE_ID=100
PE1_ROUTER_MAC="02:00:00:00:01:01"
PE1_GATEWAY_CIDR="10.1.1.1/24"
PE1_GATEWAY_BRIDGE="br10"
PE1_GATEWAY_PORT="veth10a"
GATEWAY_IP="10.1.1.5"
GATEWAY_MAC="02:aa:bb:cc:68:01"
TARGET_PREFIX="203.0.113.0/24"
TARGET_HOST="203.0.113.0"
TARGET_PLEN=24

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required (apt-get install jq)" >&2
    exit 1
fi

frr_vtysh() {
    docker exec "$PE2" vtysh -c "$1" 2>/dev/null || true
}

wait_until() {
    local timeout=$1
    shift
    local attempts=$((timeout / 2))
    for _ in $(seq 1 "$attempts"); do
        if "$@"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

not() { ! "$@"; }

frr_has_type5() {
    frr_vtysh "show bgp l2vpn evpn route type prefix json" \
        | grep -q "\\[5\\]:\\[0\\]:\\[$TARGET_PLEN\\]:\\[$TARGET_HOST\\]"
}

frr_type5_detail_has_gateway() {
    local detail
    detail=$(frr_vtysh "show bgp l2vpn evpn route detail")
    echo "$detail" | awk -v host="$TARGET_HOST" -v gw="$GATEWAY_IP" '
        /^BGP routing table entry/ {
            if (in_block && block ~ gw) {
                found = 1
            }
            in_block = ($0 ~ host)
            block = $0
            next
        }
        in_block {
            block = block "\n" $0
        }
        END {
            if (in_block && block ~ gw) {
                found = 1
            }
            exit(found ? 0 : 1)
        }
    '
}

frr_has_gateway_type2() {
    frr_vtysh "show bgp l2vpn evpn route type macip" \
        | grep -qiE "\\[2\\]:\\[[^]]*\\]:(\\[[^]]*\\]:)?\\[48\\]:\\[$GATEWAY_MAC\\]:\\[32\\]:\\[$GATEWAY_IP\\]"
}

frr_vrf_route_installed() {
    local route_json
    route_json=$(frr_vtysh "show ip route vrf $TENANT_VRF $TARGET_PREFIX json")
    echo "$route_json" | jq -e --arg prefix "$TARGET_PREFIX" --arg gw "$GATEWAY_IP" '
        (($prefix as $p | .[$p] // []) | arrays) as $routes
        | any($routes[]?;
            ((.protocol // .proto // "") | tostring | test("bgp"; "i"))
            and ([.. | objects | .ip? // empty] | any(. == $gw))
        )
    ' >/dev/null 2>&1
}

frr_kernel_route_installed() {
    local route_json
    route_json=$(docker exec "$PE2" ip -j route show vrf "$TENANT_VRF" "$TARGET_PREFIX" 2>/dev/null || true)
    echo "$route_json" | jq -e --arg prefix "$TARGET_PREFIX" --arg gw "$GATEWAY_IP" '
        any(.[]?; (.dst == $prefix or (.dst == null and $prefix == "default")) and .gateway == $gw)
    ' >/dev/null 2>&1
}

pe1_add_target_route() {
    docker exec "$PE1" ip route replace "$TARGET_PREFIX" \
        via "$GATEWAY_IP" dev "$PE1_GATEWAY_BRIDGE" table "$PE1_TABLE_ID"
}

pe1_delete_target_route() {
    docker exec "$PE1" ip route del "$TARGET_PREFIX" \
        via "$GATEWAY_IP" dev "$PE1_GATEWAY_BRIDGE" table "$PE1_TABLE_ID" 2>/dev/null || true
}

pe1_add_gateway_type2() {
    docker exec "$PE1" bridge fdb replace "$GATEWAY_MAC" dev "$PE1_GATEWAY_PORT" master static
    docker exec "$PE1" ip neigh replace "$GATEWAY_IP" lladdr "$GATEWAY_MAC" \
        dev "$PE1_GATEWAY_BRIDGE" nud reachable
}

log "Provisioning PE1 kernel topology (vrf1 + L3VNI 100 + linked L2VNI 10)"
docker exec "$PE1" /usr/local/bin/start-rustbgpd-m68-pe1.sh \
    "$PE1_IP" "$L3VNI" "$TENANT_VRF" "$PE1_ROUTER_MAC" "$L2VNI" "$PE1_GATEWAY_CIDR" >/dev/null

resolve_grpc_addr
start_rustbgpd

wait_frr_established "$PE2" "$PE1_IP" "PE1↔PE2 L2VPN/EVPN" || print_summary

log "[test 1] add the static VRF route before the companion Type 2 exists"
pe1_add_target_route
if wait_until 90 frr_has_type5; then
    ok "FRR received rustbgpd's GW-IP Type 5 for $TARGET_PREFIX"
else
    fail "FRR never received the GW-IP Type 5 for $TARGET_PREFIX"
    frr_vtysh "show bgp l2vpn evpn route type prefix" >&2 || true
fi

if wait_until 30 frr_type5_detail_has_gateway; then
    ok "FRR detail shows Gateway Address $GATEWAY_IP on the Type 5"
else
    fail "FRR detail never showed Gateway Address $GATEWAY_IP"
    frr_vtysh "show bgp l2vpn evpn route detail" >&2 || true
fi

log "[test 2] without the companion Type 2, FRR must keep the prefix out of vrf1"
sleep 6
if frr_vrf_route_installed || frr_kernel_route_installed; then
    fail "FRR installed $TARGET_PREFIX before the Gateway Address Type 2 existed"
    frr_vtysh "show ip route vrf $TENANT_VRF" >&2 || true
    docker exec "$PE2" ip route show vrf "$TENANT_VRF" "$TARGET_PREFIX" >&2 || true
else
    ok "FRR held the overlay-index Type 5 unresolved before Type 2"
fi

log "[test 3] originate the companion MAC+IP Type 2 for $GATEWAY_IP"
pe1_add_gateway_type2
if wait_until 60 frr_has_gateway_type2; then
    ok "FRR received the Gateway Address Type 2 MAC/IP route"
else
    fail "FRR never received MAC+IP Type 2 for $GATEWAY_IP"
    frr_vtysh "show bgp l2vpn evpn route type macip" >&2 || true
fi

log "[test 4] FRR resolves the Type 5 through the Type 2 and imports it into vrf1"
if wait_until 90 frr_vrf_route_installed; then
    ok "FRR's vrf1 RIB installed $TARGET_PREFIX via $GATEWAY_IP"
else
    fail "FRR did not import $TARGET_PREFIX into vrf1 via $GATEWAY_IP"
    frr_vtysh "show ip route vrf $TENANT_VRF" >&2 || true
fi

if wait_until 30 frr_kernel_route_installed; then
    ok "FRR kernel vrf1 route uses gateway $GATEWAY_IP"
else
    fail "FRR kernel did not install $TARGET_PREFIX via $GATEWAY_IP"
    docker exec "$PE2" ip route show vrf "$TENANT_VRF" "$TARGET_PREFIX" >&2 || true
fi

log "[test 5] withdrawing the static route withdraws the Type 5 and removes the VRF route"
pe1_delete_target_route
if wait_until 30 not frr_has_type5; then
    ok "FRR dropped rustbgpd's GW-IP Type 5 after withdraw"
else
    fail "FRR still shows the GW-IP Type 5 after withdraw"
    frr_vtysh "show bgp l2vpn evpn route type prefix" >&2 || true
fi

if wait_until 30 not frr_vrf_route_installed; then
    ok "FRR removed the imported vrf1 route after withdraw"
else
    fail "FRR still has the imported vrf1 route after withdraw"
    frr_vtysh "show ip route vrf $TENANT_VRF" >&2 || true
fi

print_summary
