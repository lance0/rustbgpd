#!/usr/bin/env bash
# M73 interop test — BGP-LS reflection against GoBGP v4.
#
# Validates:
#   1. BGP-LS iBGP sessions establish to both RR clients.
#   2. GoBGP source injects one deterministic RFC 9552 Node NLRI.
#   3. rustbgpd stores it in the BGP-LS Loc-RIB / API view.
#   4. rustbgpd reflects it to the GoBGP sink with the BGP-LS Attribute intact.
#   5. Source withdrawal removes it from rustbgpd and from the sink.
#
# Prerequisites:
#   - docker build -t rustbgpd:dev .
#   - docker build -t gobgp:bgpls -f tests/interop/Dockerfile.gobgp-bgpls tests/interop
#   - containerlab deployed:
#       containerlab deploy -t tests/interop/m73-bgpls-reflection-gobgp.clab.yml

TOPO="m73-bgpls-reflection-gobgp"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"

GOBGP_SRC="clab-${TOPO}-gobgp-src"
GOBGP_SINK="clab-${TOPO}-gobgp-sink"
NODE_NAME="m73-node"

BGPLS_NODE_ARGS=(
    node
    protocol 3
    identifier 77
    local-asn 65001
    local-bgp-ls-id 1
    local-bgp-router-id 10.0.0.2
    node-name "$NODE_NAME"
)

start_gobgpd() {
    local container=${1:?}
    log "Starting gobgpd in $container..."
    docker exec -d "$container" sh -c \
        'nohup gobgpd -f /config/gobgp.toml >/tmp/gobgpd.log 2>&1'
}

gobgp() {
    local container=${1:?}
    shift
    docker exec "$container" gobgp "$@" 2>/dev/null
}

gobgp_neighbor() {
    local container=${1:?}
    gobgp "$container" neighbor 2>/dev/null || true
}

gobgp_ls_json() {
    local container=${1:?}
    gobgp "$container" global rib -a ls -j
}

rustbgpd_bgpls_json() {
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 rib bgpls -j
}

wait_gobgp_established() {
    local container=${1:?}
    local peer=${2:?}
    local label=${3:?}

    log "Waiting for $label session to $peer..."
    for i in $(seq 1 45); do
        local state
        state=$(gobgp_neighbor "$container" | grep "$peer" || true)
        if echo "$state" | grep -qi "establ"; then
            ok "$label session established (attempt $i)"
            return 0
        fi
        sleep 2
    done

    fail "$label session did not reach Established within 90s"
    gobgp_neighbor "$container" || true
    return 1
}

wait_rustbgpd_bgpls_count() {
    local want=${1:?}
    local label=${2:?}

    log "Waiting for rustbgpd BGP-LS count = $want ($label)..."
    for i in $(seq 1 30); do
        local routes matching count
        if ! routes=$(rustbgpd_bgpls_json); then
            fail "rbgp BGP-LS query failed"
            return 1
        fi
        matching=$(echo "$routes" | jq -c '[.[] | select(.family == "linkstate" and .peer_address == "10.0.0.2" and .nlri_type == 1)]')
        count=$(echo "$matching" | jq 'length')
        if [ "$count" -eq "$want" ]; then
            ok "rustbgpd BGP-LS count is $want (attempt $i)"
            if [ "$want" -gt 0 ]; then
                local attr_len payload_len
                attr_len=$(echo "$matching" | jq -r '.[0].bgp_ls_attribute | length')
                payload_len=$(echo "$matching" | jq -r '.[0].payload | length')
                if [ "$attr_len" -gt 0 ] && [ "$payload_len" -gt 0 ]; then
                    ok "rustbgpd exposes non-empty opaque BGP-LS payload and attribute"
                else
                    fail "rustbgpd BGP-LS payload/attribute unexpectedly empty"
                fi
            fi
            return 0
        fi
        sleep 2
    done

    fail "rustbgpd BGP-LS count did not reach $want"
    rustbgpd_bgpls_json | jq . || true
    return 1
}

wait_sink_node_present() {
    log "Waiting for GoBGP sink to receive reflected BGP-LS node..."
    for i in $(seq 1 30); do
        local rib
        if ! rib=$(gobgp_ls_json "$GOBGP_SINK"); then
            fail "GoBGP sink BGP-LS RIB query failed"
            return 1
        fi
        if echo "$rib" | jq -e --arg name "$NODE_NAME" \
            '.. | objects | select(.name? == $name)' >/dev/null; then
            ok "GoBGP sink received reflected node with BGP-LS Attribute (attempt $i)"
            return 0
        fi
        sleep 2
    done

    fail "GoBGP sink did not receive reflected BGP-LS node"
    gobgp_ls_json "$GOBGP_SINK" | jq . || true
    return 1
}

wait_sink_node_absent() {
    log "Waiting for GoBGP sink to remove reflected BGP-LS node..."
    for i in $(seq 1 30); do
        local rib
        if ! rib=$(gobgp_ls_json "$GOBGP_SINK"); then
            fail "GoBGP sink BGP-LS RIB query failed"
            return 1
        fi
        if ! echo "$rib" | jq -e --arg name "$NODE_NAME" \
            '.. | objects | select(.name? == $name)' >/dev/null; then
            ok "GoBGP sink removed reflected node (attempt $i)"
            return 0
        fi
        sleep 2
    done

    fail "GoBGP sink still has reflected BGP-LS node"
    gobgp_ls_json "$GOBGP_SINK" | jq . || true
    return 1
}

test_bgpls_reflection() {
    log "Test 1: GoBGP source injects BGP-LS Node NLRI"
    gobgp "$GOBGP_SRC" global rib add -a ls "${BGPLS_NODE_ARGS[@]}"

    wait_rustbgpd_bgpls_count 1 "source announce"
    wait_sink_node_present
}

test_bgpls_withdrawal() {
    log "Test 2: GoBGP source withdraws BGP-LS Node NLRI"
    gobgp "$GOBGP_SRC" global rib del -a ls "${BGPLS_NODE_ARGS[@]}"

    wait_rustbgpd_bgpls_count 0 "source withdraw"
    wait_sink_node_absent
}

main() {
    log "M73 interop test: BGP-LS reflection via GoBGP"
    log "Topology: $TOPO"

    preflight
    resolve_grpc_addr
    start_gobgpd "$GOBGP_SRC"
    start_gobgpd "$GOBGP_SINK"
    start_rustbgpd

    wait_gobgp_established "$GOBGP_SRC" "10.0.0.1" "source" || exit 1
    wait_gobgp_established "$GOBGP_SINK" "10.0.1.1" "sink" || exit 1

    test_bgpls_reflection
    test_bgpls_withdrawal

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
