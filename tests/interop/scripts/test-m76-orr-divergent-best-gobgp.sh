#!/usr/bin/env bash
# M76 interop test — RFC 9107 Optimal Route Reflection divergent-best
# receipt against GoBGP v4.
#
# gobgp-src injects a 4-link BGP-LS square via `gobgp global rib add -a ls
# link ...`; pe1/pe2 announce the SAME prefix 203.0.113.0/24 with next-hops
# 10.0.9.1 (node X) / 10.0.9.2 (node Y); c1 is pinned to vantage 10.0.8.1
# (node A) and c2 to 10.0.8.2 (node B).
#
#   Square: A→X=1, A→Y=10, B→X=10, B→Y=1
#
# Validates:
#   1. All five iBGP sessions Established; linkstate negotiated on src,
#      ipv4-unicast on PEs and clients.
#   2. rbgp topology shows the injected square: 4 nodes / 4 links.
#   3. rbgp orr shows BOTH vantages resolved with their bound peers.
#   4. THE DIVERGENCE: for the same prefix, c1's best has NEXT_HOP 10.0.9.1
#      (via X, cost 1 from A) while c2's has 10.0.9.2 (via Y, cost 1 from
#      B); ORIGINATOR_ID identifies the respective PE.
#   5. Topology-driven flip: re-adding A→X with metric 100 moves ONLY c1
#      to 10.0.9.2 — no session flap on either client, zero UPDATEs toward
#      c2 (two-sample quiet-counter check).
#   6. Fallback: withdrawing all four links unresolves both vantages and
#      BOTH clients converge to the same standard best (lowest-peer-address
#      PE ⇒ pe1 ⇒ 10.0.9.1).
#   7. RR dataplane clean: no MPLS routes, no kernel route for the prefix.
#   8. Recovery: re-injecting the square restores divergence.
#   9. The linkstate-only src session never flaps across the whole run —
#      wire-level regression pin for the implicit-IPv4 negotiation fix
#      (#632): before it, the RR leaked classic-NLRI IPv4 UPDATEs to the
#      ls-only peer the moment pe1/pe2 announced, and GoBGP hard-reset
#      the session ("rf 65537 not available") in a permanent flap loop.
#
# Prerequisites:
#   - docker build --target dev -t rustbgpd:dev .
#   - docker build -t gobgp:bgpls -f tests/interop/Dockerfile.gobgp-bgpls tests/interop
#   - containerlab deployed:
#       containerlab deploy -t tests/interop/m76-orr-divergent-best-gobgp.clab.yml

TOPO="m76-orr-divergent-best-gobgp"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
source "$SCRIPT_DIR/test-lib.sh"

GOBGP_SRC="clab-${TOPO}-gobgp-src"
GOBGP_PE1="clab-${TOPO}-gobgp-pe1"
GOBGP_PE2="clab-${TOPO}-gobgp-pe2"
GOBGP_C1="clab-${TOPO}-gobgp-c1"
GOBGP_C2="clab-${TOPO}-gobgp-c2"

SRC_ADDR="10.0.0.2"
PE1_ADDR="10.0.1.2"
PE2_ADDR="10.0.2.2"
C1_ADDR="10.0.3.2"
C2_ADDR="10.0.4.2"

PREFIX="203.0.113.0/24"
NH_X="10.0.9.1"
NH_Y="10.0.9.2"
VANTAGE_A="10.0.8.1"
VANTAGE_B="10.0.8.2"

# The square's node identities. Each node's descriptor tuple (protocol,
# identifier, asn, bgp-ls-id, igp-router-id) must be byte-identical across
# every link that names it, so both links into X (A→X, B→X) intern to ONE
# topology node — same for A, B, and Y.
RID_A="1.1.1.1"
RID_B="2.2.2.2"
RID_X="9.9.9.1"
RID_Y="9.9.9.2"

# GoBGP v4.6.0 `gobgp global rib add -a ls link` descriptor arguments for
# one directed link. $1=local rid, $2=remote rid, $3=ipv4-interface-address
# (local side), $4=ipv4-neighbor-address (remote side), $5=IGP metric
# (TLV 1095 in the BGP-LS Attribute).
ls_link_args() {
    echo "link protocol 3 identifier 0 \
local-asn 65001 local-bgp-ls-id 1 local-igp-router-id $1 \
remote-asn 65001 remote-bgp-ls-id 1 remote-igp-router-id $2 \
ipv4-interface-address $3 ipv4-neighbor-address $4 metric $5"
}

ls_link_a_x() { ls_link_args "$RID_A" "$RID_X" "$VANTAGE_A" "$NH_X" "${1:-1}"; }
ls_link_a_y() { ls_link_args "$RID_A" "$RID_Y" "$VANTAGE_A" "$NH_Y" 10; }
ls_link_b_x() { ls_link_args "$RID_B" "$RID_X" "$VANTAGE_B" "$NH_X" 10; }
ls_link_b_y() { ls_link_args "$RID_B" "$RID_Y" "$VANTAGE_B" "$NH_Y" 1; }

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

rbgp() {
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 "$@"
}

rustbgpd_neighbor_json() {
    rbgp neighbor "${1:?}" -j
}

wait_gobgp_established() {
    local container=${1:?}
    local peer=${2:?}
    local label=${3:?}

    log "Waiting for $label session to $peer..."
    for i in $(seq 1 45); do
        local state
        state=$(gobgp_neighbor "$container" | grep -F -- "$peer" || true)
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

# Assert an afi-safi shows "advertised and received" in GoBGP's
# per-neighbor capability view.
assert_family_negotiated() {
    local container=${1:?}
    local peer=${2:?}
    local family=${3:?}
    local label=${4:?}

    if gobgp "$container" neighbor "$peer" \
        | grep -A 30 "Neighbor capabilities" \
        | grep -E "(^|[[:space:]])${family}:" \
        | grep -q "advertised and received"; then
        ok "$label negotiated $family"
    else
        fail "$label did not negotiate $family"
        gobgp "$container" neighbor "$peer" | grep -A 30 "Neighbor capabilities" || true
    fi
}

# NEXT_HOP (attr type 3) of a client's paths for $PREFIX, one per line.
client_nexthops() {
    local container=${1:?}
    gobgp "$container" global rib -a ipv4 -j \
        | jq -r --arg pfx "$PREFIX" \
            '.[$pfx] // [] | .[].attrs[] | select(.type == 3) | .nexthop'
}

# Wait until a client holds exactly one path for $PREFIX whose NEXT_HOP is
# $2 and whose ORIGINATOR_ID (attr type 9) is $3.
wait_client_best() {
    local container=${1:?} nh=${2:?} originator=${3:?} label=${4:?}
    log "Waiting for $label best: $PREFIX via $nh (originator $originator)..."
    for i in $(seq 1 30); do
        if gobgp "$container" global rib -a ipv4 -j 2>/dev/null \
            | jq -e --arg pfx "$PREFIX" --arg nh "$nh" --arg oid "$originator" '
                (.[$pfx] // []) as $paths
                | ($paths | length) == 1
                and ([$paths[0].attrs[] | select(.type == 3 and .nexthop == $nh)] | length) == 1
                and ([$paths[0].attrs[] | select(.type == 9 and .value == $oid)] | length) == 1
            ' >/dev/null; then
            ok "$label holds $PREFIX via $nh, ORIGINATOR_ID=$originator (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label never converged to $PREFIX via $nh (originator $originator)"
    gobgp "$container" global rib -a ipv4 -j | jq . || true
    return 1
}

flap_count() {
    rustbgpd_neighbor_json "${1:?}" | jq -r '.flap_count'
}

updates_sent() {
    rustbgpd_neighbor_json "${1:?}" | jq -r '.updates_sent'
}

assert_no_flap() {
    local peer=${1:?} baseline=${2:?} label=${3:?}
    local now state
    now=$(flap_count "$peer")
    state=$(rustbgpd_neighbor_json "$peer" | jq -r '.state')
    if [ "$now" = "$baseline" ] && [ "$state" = "Established" ]; then
        ok "$label: session Established, flap count unchanged ($now)"
    else
        fail "$label: session flapped (flap_count $baseline -> $now, state $state)"
    fi
}

wait_topology_counts() {
    local nodes=${1:?} links=${2:?} label=${3:?}
    log "Waiting for topology $nodes nodes / $links links ($label)..."
    for i in $(seq 1 30); do
        local got_nodes got_links
        got_nodes=$(rbgp topology nodes -j 2>/dev/null | jq 'length' || echo -1)
        got_links=$(rbgp topology links -j 2>/dev/null | jq 'length' || echo -1)
        if [ "$got_nodes" -eq "$nodes" ] && [ "$got_links" -eq "$links" ]; then
            ok "topology is $nodes nodes / $links links ($label, attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "topology never reached $nodes nodes / $links links ($label)"
    rbgp topology links -j | jq . || true
    return 1
}

# Wait until both vantages report resolved == $1 in rbgp orr -j.
wait_vantages_resolved() {
    local want=${1:?} label=${2:?}
    log "Waiting for both vantages resolved=$want ($label)..."
    for i in $(seq 1 30); do
        if rbgp orr -j 2>/dev/null | jq -e --argjson want "$want" \
            --arg a "$VANTAGE_A" --arg b "$VANTAGE_B" '
            (.vantages | length) == 2
            and ([.vantages[] | select(.vantage == $a and .resolved == $want)] | length) == 1
            and ([.vantages[] | select(.vantage == $b and .resolved == $want)] | length) == 1
        ' >/dev/null; then
            ok "both vantages resolved=$want ($label, attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "vantages never reached resolved=$want ($label)"
    rbgp orr -j | jq . || true
    return 1
}

inject_square() {
    # shellcheck disable=SC2046
    gobgp "$GOBGP_SRC" global rib add -a ls $(ls_link_a_x)
    # shellcheck disable=SC2046
    gobgp "$GOBGP_SRC" global rib add -a ls $(ls_link_a_y)
    # shellcheck disable=SC2046
    gobgp "$GOBGP_SRC" global rib add -a ls $(ls_link_b_x)
    # shellcheck disable=SC2046
    gobgp "$GOBGP_SRC" global rib add -a ls $(ls_link_b_y)
}

withdraw_square() {
    # shellcheck disable=SC2046
    gobgp "$GOBGP_SRC" global rib del -a ls $(ls_link_a_x)
    # shellcheck disable=SC2046
    gobgp "$GOBGP_SRC" global rib del -a ls $(ls_link_a_y)
    # shellcheck disable=SC2046
    gobgp "$GOBGP_SRC" global rib del -a ls $(ls_link_b_x)
    # shellcheck disable=SC2046
    gobgp "$GOBGP_SRC" global rib del -a ls $(ls_link_b_y)
}

test_topology_visible() {
    log "Test 1: src injects the BGP-LS square; rbgp topology shows 4 nodes / 4 links"
    inject_square
    wait_topology_counts 4 4 "square injected"

    if rbgp topology nodes >/dev/null; then
        ok "rbgp topology nodes renders (table mode)"
    else
        fail "rbgp topology nodes table rendering failed"
    fi
}

test_vantages_resolved() {
    log "Test 2: rbgp orr resolves both vantages and binds c1/c2"
    wait_vantages_resolved true "square injected"

    if rbgp orr -j | jq -e --arg a "$VANTAGE_A" --arg b "$VANTAGE_B" \
        --arg c1 "$C1_ADDR" --arg c2 "$C2_ADDR" '
        ([.vantages[] | select(.vantage == $a) | .peers] == [[$c1]])
        and ([.vantages[] | select(.vantage == $b) | .peers] == [[$c2]])
    ' >/dev/null; then
        ok "vantage $VANTAGE_A bound to c1 ($C1_ADDR), $VANTAGE_B bound to c2 ($C2_ADDR)"
    else
        fail "vantage-to-peer binding wrong"
        rbgp orr -j | jq . || true
    fi
}

test_divergence() {
    log "Test 3: THE DIVERGENCE — pe1/pe2 announce $PREFIX; c1 and c2 get different bests"
    gobgp "$GOBGP_PE1" global rib add "$PREFIX" nexthop "$NH_X"
    gobgp "$GOBGP_PE2" global rib add "$PREFIX" nexthop "$NH_Y"

    wait_client_best "$GOBGP_C1" "$NH_X" "$PE1_ADDR" "c1 (vantage A: cost 1 to X, 10 to Y)"
    wait_client_best "$GOBGP_C2" "$NH_Y" "$PE2_ADDR" "c2 (vantage B: cost 10 to X, 1 to Y)"

    local c1_nh c2_nh
    c1_nh=$(client_nexthops "$GOBGP_C1")
    c2_nh=$(client_nexthops "$GOBGP_C2")
    if [ "$c1_nh" != "$c2_nh" ]; then
        ok "same prefix, divergent bests: c1 via $c1_nh, c2 via $c2_nh"
    else
        fail "clients converged to the same next-hop ($c1_nh) — no divergence"
    fi
}

test_metric_flip() {
    log "Test 4: re-add A→X with metric 100 — only c1 flips, no flap, no churn to c2"
    local c1_flaps c2_flaps c2_updates
    c1_flaps=$(flap_count "$C1_ADDR")
    c2_flaps=$(flap_count "$C2_ADDR")
    c2_updates=$(updates_sent "$C2_ADDR")

    # shellcheck disable=SC2046
    gobgp "$GOBGP_SRC" global rib add -a ls $(ls_link_a_x 100)

    wait_client_best "$GOBGP_C1" "$NH_Y" "$PE2_ADDR" "c1 after flip (cost 100 to X, 10 to Y)"

    # c1 has converged, so the RR has processed the topology change end to
    # end; give any (wrong) in-flight UPDATE toward c2 a moment, then pin
    # the second quiet-counter sample.
    sleep 3
    wait_client_best "$GOBGP_C2" "$NH_Y" "$PE2_ADDR" "c2 unchanged after flip"

    local c2_updates_after
    c2_updates_after=$(updates_sent "$C2_ADDR")
    if [ "$c2_updates_after" = "$c2_updates" ]; then
        ok "zero UPDATEs toward c2 across the flip (updates_sent $c2_updates unchanged)"
    else
        fail "RR sent UPDATEs to c2 during a change that only affects c1 ($c2_updates -> $c2_updates_after)"
    fi
    assert_no_flap "$C1_ADDR" "$c1_flaps" "flip/c1"
    assert_no_flap "$C2_ADDR" "$c2_flaps" "flip/c2"
}

test_fallback() {
    log "Test 5: withdraw all links — vantages unresolve, both clients fall back to the SAME standard best"
    withdraw_square
    wait_topology_counts 0 0 "square withdrawn"
    wait_vantages_resolved false "square withdrawn"

    # Standard best: identical attrs, deterministic lowest-peer-address
    # tiebreak ⇒ pe1 ⇒ NH_X.
    wait_client_best "$GOBGP_C1" "$NH_X" "$PE1_ADDR" "c1 fallback"
    wait_client_best "$GOBGP_C2" "$NH_X" "$PE1_ADDR" "c2 fallback"

    local c1_nh c2_nh
    c1_nh=$(client_nexthops "$GOBGP_C1")
    c2_nh=$(client_nexthops "$GOBGP_C2")
    if [ "$c1_nh" = "$c2_nh" ] && [ -n "$c1_nh" ]; then
        ok "fallback bests identical: both via $c1_nh"
    else
        fail "fallback bests differ (c1 via '$c1_nh', c2 via '$c2_nh')"
    fi
}

test_dataplane_clean() {
    log "Test 6: RR installed nothing into any dataplane"

    local mpls ipv4
    if capture_ip_routes mpls "$RUSTBGPD" MPLS -M; then
        if [ -z "$mpls" ]; then
            ok "RR MPLS routing table is empty"
        else
            fail "RR has unexpected MPLS routes"
            printf '%s\n' "$mpls" >&2
        fi
    fi

    if capture_ip_routes ipv4 "$RUSTBGPD" IPv4; then
        if grep -q "${PREFIX%/*}" <<<"$ipv4"; then
            fail "RR kernel routing table contains $PREFIX"
            printf '%s\n' "$ipv4" >&2
        else
            ok "RR kernel routing table has no route for $PREFIX"
        fi
    fi
}

capture_ip_routes() {
    local output_var=$1 container=$2 table_label=$3 captured
    shift 3
    if ! captured=$(docker exec "$container" ip "$@" route show 2>&1); then
        fail "$container $table_label route inspection failed"
        printf '%s\n' "$captured" >&2
        return 1
    fi
    printf -v "$output_var" '%s' "$captured"
}

test_recovery() {
    log "Test 7: re-inject the square — vantages resolve again, divergence returns"
    inject_square
    wait_topology_counts 4 4 "square re-injected"
    wait_vantages_resolved true "square re-injected"

    wait_client_best "$GOBGP_C1" "$NH_X" "$PE1_ADDR" "c1 divergence restored"
    wait_client_best "$GOBGP_C2" "$NH_Y" "$PE2_ADDR" "c2 divergence restored"
}

main() {
    log "M76 interop test: RFC 9107 ORR divergent-best via GoBGP"
    log "Topology: $TOPO"

    preflight
    resolve_grpc_addr
    start_gobgpd "$GOBGP_SRC"
    start_gobgpd "$GOBGP_PE1"
    start_gobgpd "$GOBGP_PE2"
    start_gobgpd "$GOBGP_C1"
    start_gobgpd "$GOBGP_C2"
    start_rustbgpd

    wait_gobgp_established "$GOBGP_SRC" "10.0.0.1" "source" || exit 1
    wait_gobgp_established "$GOBGP_PE1" "10.0.1.1" "pe1" || exit 1
    wait_gobgp_established "$GOBGP_PE2" "10.0.2.1" "pe2" || exit 1
    wait_gobgp_established "$GOBGP_C1" "10.0.3.1" "c1" || exit 1
    wait_gobgp_established "$GOBGP_C2" "10.0.4.1" "c2" || exit 1

    assert_family_negotiated "$GOBGP_SRC" "10.0.0.1" "ls" "source"
    assert_family_negotiated "$GOBGP_PE1" "10.0.1.1" "ipv4-unicast" "pe1"
    assert_family_negotiated "$GOBGP_PE2" "10.0.2.1" "ipv4-unicast" "pe2"
    assert_family_negotiated "$GOBGP_C1" "10.0.3.1" "ipv4-unicast" "c1"
    assert_family_negotiated "$GOBGP_C2" "10.0.4.1" "ipv4-unicast" "c2"

    # Baseline for the end-of-run src stability pin (#632): captured after
    # every session is Established but before any IPv4 route exists.
    local src_flaps
    src_flaps=$(flap_count "$SRC_ADDR")

    test_topology_visible
    test_vantages_resolved
    test_divergence
    test_metric_flip
    test_fallback
    test_dataplane_clean
    test_recovery

    # Regression pin for the implicit-IPv4 negotiation fix (#632): the
    # linkstate-only src session must survive the entire IPv4 announce /
    # flip / withdraw churn without a single flap.
    log "Test 8: linkstate-only src session never flapped (#632 pin)"
    assert_no_flap "$SRC_ADDR" "$src_flaps" "src (linkstate-only)"

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
