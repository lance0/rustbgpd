#!/usr/bin/env bash
# M78 interop test — RFC 9107 multi-cluster ORR with inter-RR Add-Path
# against GoBGP v4.
#
# The closing RFC 9107 deployment story: "optimal routing between clients
# of different clusters relies upon all route reflectors learning all
# paths... BGP ADD-PATH needs to be deployed between route reflectors."
#
# Two rustbgpd RRs — rr1 (cluster 1.1.1.1) and rr2 (cluster 2.2.2.2) —
# hold a standard NON-client iBGP session with Add-Path negotiated both
# directions. gobgp-src (linkstate only) peers with BOTH RRs and injects
# the M76 square (A→X=1, A→Y=10, B→X=10, B→Y=1) into both LSDBs. pe1
# (client of rr1 only) and pe2 (client of rr2 only) announce the SAME
# prefix with next-hops X / Y, so each RR learns one path from its own
# cluster and MUST learn the other cluster's path over the inter-RR
# session. c1 (vantage A, client of rr1) and c2 (vantage B, client of
# rr2) still get divergent, topologically-correct bests.
#
# Validates:
#   1. All seven iBGP sessions Established (src×2, pe×2, c×2, inter-RR);
#      Add-Path configured on the inter-RR session on both RRs.
#   2. Both RRs' rbgp topology show the square (4 nodes / 4 links); each
#      RR's rbgp orr resolves its own vantage and binds its own client.
#   3. THE MULTI-CLUSTER CRUX: each RR holds BOTH candidate paths for the
#      prefix — the local client path in the PE's Adj-RIB-In, and the
#      other cluster's path in the inter-RR Adj-RIB-In carrying a
#      non-zero path_id (wire-level proof Add-Path is live in BOTH
#      directions: each RR received an Add-Path-encoded route from the
#      other).
#   4. Divergence across clusters: c1's best is NH 10.0.9.1 (via X,
#      originator pe1) while c2's is 10.0.9.2 (via Y, originator pe2).
#   5. Metric flip (A→X re-added at 100 via src): c1 flips to 10.0.9.2 —
#      a path rr1 holds ONLY via rr2 — with a CLUSTER_LIST naming both
#      clusters; c2 unchanged, zero UPDATEs toward c2, no session flap on
#      clients or the inter-RR session. Restoring A→X=1 flips c1 back.
#   6. Withdraw pe1's route: the withdrawal propagates over the inter-RR
#      session (rr2's Adj-RIB-In from rr1 empties) and c1 converges to
#      10.0.9.2 via the inter-RR path; c2 quiet throughout. Re-announce
#      restores the divergence.
#   7. Neither RR installed anything into any dataplane.
#
# Prerequisites:
#   - docker build --target dev -t rustbgpd:dev .
#   - docker build -t gobgp:bgpls -f tests/interop/Dockerfile.gobgp-bgpls tests/interop
#   - containerlab deployed:
#       containerlab deploy -t tests/interop/m78-multicluster-orr-gobgp.clab.yml

TOPO="m78-multicluster-orr-gobgp"
RUSTBGPD="clab-${TOPO}-rr1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
source "$SCRIPT_DIR/test-lib.sh"

RR1="clab-${TOPO}-rr1"
RR2="clab-${TOPO}-rr2"
GOBGP_SRC="clab-${TOPO}-gobgp-src"
GOBGP_PE1="clab-${TOPO}-gobgp-pe1"
GOBGP_PE2="clab-${TOPO}-gobgp-pe2"
GOBGP_C1="clab-${TOPO}-gobgp-c1"
GOBGP_C2="clab-${TOPO}-gobgp-c2"

PE1_ADDR="10.0.1.2"
PE2_ADDR="10.0.2.2"
C1_ADDR="10.0.3.2"
C2_ADDR="10.0.4.2"
SRC_RR1_ADDR="10.0.0.2"
SRC_RR2_ADDR="10.0.5.2"
RR1_INTER_ADDR="10.0.12.1" # rr1's address on the inter-RR link
RR2_INTER_ADDR="10.0.12.2" # rr2's address on the inter-RR link
CLUSTER1="1.1.1.1"
CLUSTER2="2.2.2.2"

PREFIX="203.0.113.0/24"
NH_X="10.0.9.1"
NH_Y="10.0.9.2"
VANTAGE_A="10.0.8.1"
VANTAGE_B="10.0.8.2"

# The square's node identities — the M76 recipe verbatim. Each node's
# descriptor tuple (protocol, identifier, asn, bgp-ls-id, igp-router-id)
# must be byte-identical across every link that names it, so both links
# into X (A→X, B→X) intern to ONE topology node — same for A, B, and Y.
# (These are BGP-LS igp-router-ids, a different namespace from the RRs'
# cluster-ids; the visual overlap of A=1.1.1.1 / B=2.2.2.2 is harmless.)
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

# rbgp against one of the two RRs. $1 = RR container, rest = CLI args.
rr_ctl() {
    local rr=${1:?}
    shift
    docker exec "$rr" rbgp -s http://127.0.0.1:50051 "$@"
}

rr_neighbor_json() {
    rr_ctl "${1:?}" neighbor "${2:?}" -j
}

# Start rustbgpd in an RR container and wait for its gRPC surface.
# (test-lib's start_rustbgpd drives a single $RUSTBGPD node; this lab has
# two, so the health wait polls `rbgp global` per container instead.)
start_rr() {
    local rr=${1:?}
    log "Starting rustbgpd in $rr..."
    docker exec -d "$rr" sh -c /usr/local/bin/start-rustbgpd.sh
    for i in $(seq 1 30); do
        if rr_ctl "$rr" global >/dev/null 2>&1; then
            ok "$rr rustbgpd gRPC ready (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$rr rustbgpd gRPC not reachable within 60s"
    docker exec "$rr" sh -c 'timeout 2 /usr/local/bin/rustbgpd /etc/rustbgpd/config.toml 2>&1 || true' >&2 || true
    return 1
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

wait_rr_established() {
    local rr=${1:?} peer=${2:?} label=${3:?}
    log "Waiting for $label session to $peer..."
    for i in $(seq 1 45); do
        local state
        state=$(rr_neighbor_json "$rr" "$peer" 2>/dev/null | jq -r '.state' || true)
        if [ "$state" = "Established" ]; then
            ok "$label session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label session did not reach Established within 90s"
    rr_ctl "$rr" neighbor "$peer" || true
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
    rr_neighbor_json "${1:?}" "${2:?}" | jq -r '.flap_count'
}

updates_sent() {
    rr_neighbor_json "${1:?}" "${2:?}" | jq -r '.updates_sent'
}

assert_no_flap() {
    local rr=${1:?} peer=${2:?} baseline=${3:?} label=${4:?}
    local now state
    now=$(flap_count "$rr" "$peer")
    state=$(rr_neighbor_json "$rr" "$peer" | jq -r '.state')
    if [ "$now" = "$baseline" ] && [ "$state" = "Established" ]; then
        ok "$label: session Established, flap count unchanged ($now)"
    else
        fail "$label: session flapped (flap_count $baseline -> $now, state $state)"
    fi
}

# Adj-RIB-In entries for $PREFIX on RR $1 from peer $2, as a JSON array.
rr_received_prefix() {
    local rr=${1:?} peer=${2:?}
    rr_ctl "$rr" rib received "$peer" -j 2>/dev/null \
        | jq --arg pfx "$PREFIX" '[.[] | select(.prefix == $pfx)]'
}

# Wait until RR $1's Adj-RIB-In from peer $2 holds exactly $3 entries for
# $PREFIX, ALL matching jq predicate $4 (over the entry) — the exact-count
# shape also catches an echo-back leak of the target's own path on the
# inter-RR session. Empty-set wait uses want=0 and predicate "true".
wait_rr_received() {
    local rr=${1:?} peer=${2:?} want=${3:?} predicate=${4:?} label=${5:?}
    log "Waiting for $label..."
    for i in $(seq 1 30); do
        if rr_received_prefix "$rr" "$peer" \
            | jq -e --argjson want "$want" \
                "(length == \$want) and (([.[] | select(${predicate})] | length) == \$want)" \
                >/dev/null 2>&1; then
            ok "$label (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label never held"
    rr_received_prefix "$rr" "$peer" | jq . || true
    return 1
}

wait_topology_counts() {
    local rr=${1:?} nodes=${2:?} links=${3:?} label=${4:?}
    log "Waiting for $rr topology $nodes nodes / $links links ($label)..."
    for i in $(seq 1 30); do
        local got_nodes got_links
        got_nodes=$(rr_ctl "$rr" topology nodes -j 2>/dev/null | jq 'length' || echo -1)
        got_links=$(rr_ctl "$rr" topology links -j 2>/dev/null | jq 'length' || echo -1)
        if [ "$got_nodes" -eq "$nodes" ] && [ "$got_links" -eq "$links" ]; then
            ok "$rr topology is $nodes nodes / $links links ($label, attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$rr topology never reached $nodes nodes / $links links ($label)"
    rr_ctl "$rr" topology links -j | jq . || true
    return 1
}

# Wait until RR $1's single vantage $2 reports resolved == $3 and is bound
# to client $4.
wait_vantage() {
    local rr=${1:?} vantage=${2:?} want=${3:?} client=${4:?} label=${5:?}
    log "Waiting for $rr vantage $vantage resolved=$want bound to $client ($label)..."
    for i in $(seq 1 30); do
        if rr_ctl "$rr" orr -j 2>/dev/null | jq -e --argjson want "$want" \
            --arg v "$vantage" --arg c "$client" '
            (.vantages | length) == 1
            and .vantages[0].vantage == $v
            and .vantages[0].resolved == $want
            and .vantages[0].peers == [$c]
        ' >/dev/null; then
            ok "$rr vantage $vantage resolved=$want, bound to $client ($label, attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$rr vantage never reached resolved=$want bound to $client ($label)"
    rr_ctl "$rr" orr -j | jq . || true
    return 1
}

# Inject / withdraw the square on src. src peers with BOTH RRs, so one
# `gobgp global rib` mutation reaches both LSDBs.
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

test_addpath_configured() {
    log "Test 1: inter-RR Add-Path configured on both RRs (wire proof follows in Test 3)"
    local side
    for side in "$RR1 $RR2_INTER_ADDR rr1->rr2" "$RR2 $RR1_INTER_ADDR rr2->rr1"; do
        # shellcheck disable=SC2086
        set -- $side
        if rr_neighbor_json "$1" "$2" | jq -e '
            .add_path_receive == true
            and .add_path_send == true
            and .add_path_send_max == 4
        ' >/dev/null; then
            ok "$3 session has add_path receive+send (send_max 4)"
        else
            fail "$3 session missing add_path config"
            rr_neighbor_json "$1" "$2" | jq . || true
        fi
    done
}

test_topology_and_vantages() {
    log "Test 2: src injects the square into BOTH RRs; each resolves its own vantage"
    inject_square
    wait_topology_counts "$RR1" 4 4 "square injected"
    wait_topology_counts "$RR2" 4 4 "square injected"
    wait_vantage "$RR1" "$VANTAGE_A" true "$C1_ADDR" "square injected"
    wait_vantage "$RR2" "$VANTAGE_B" true "$C2_ADDR" "square injected"
}

test_cross_cluster_paths() {
    log "Test 3: THE MULTI-CLUSTER CRUX — each RR holds its client path AND the other cluster's path via the inter-RR Add-Path session"
    gobgp "$GOBGP_PE1" global rib add "$PREFIX" nexthop "$NH_X"
    gobgp "$GOBGP_PE2" global rib add "$PREFIX" nexthop "$NH_Y"

    # Local client paths, plain (no Add-Path on the PE sessions).
    wait_rr_received "$RR1" "$PE1_ADDR" 1 ".next_hop == \"$NH_X\"" \
        "rr1 Adj-RIB-In from pe1: $PREFIX via $NH_X"
    wait_rr_received "$RR2" "$PE2_ADDR" 1 ".next_hop == \"$NH_Y\"" \
        "rr2 Adj-RIB-In from pe2: $PREFIX via $NH_Y"

    # Cross-cluster paths: present ONLY via the peer RR, and carrying a
    # non-zero path_id — the wire-level proof that the inter-RR session
    # ran Add-Path encoding in BOTH directions.
    wait_rr_received "$RR1" "$RR2_INTER_ADDR" 1 \
        ".next_hop == \"$NH_Y\" and (.path_id // 0) >= 1" \
        "rr1 Adj-RIB-In from rr2: $PREFIX via $NH_Y with Add-Path path_id"
    wait_rr_received "$RR2" "$RR1_INTER_ADDR" 1 \
        ".next_hop == \"$NH_X\" and (.path_id // 0) >= 1" \
        "rr2 Adj-RIB-In from rr1: $PREFIX via $NH_X with Add-Path path_id"
}

test_divergence() {
    log "Test 4: divergence across clusters — c1 and c2 get different bests for the same prefix"
    wait_client_best "$GOBGP_C1" "$NH_X" "$PE1_ADDR" "c1 (vantage A: cost 1 to X, 10 to Y)"
    wait_client_best "$GOBGP_C2" "$NH_Y" "$PE2_ADDR" "c2 (vantage B: cost 10 to X, 1 to Y)"

    local c1_nh c2_nh
    c1_nh=$(client_nexthops "$GOBGP_C1")
    c2_nh=$(client_nexthops "$GOBGP_C2")
    if [ "$c1_nh" != "$c2_nh" ]; then
        ok "same prefix, divergent bests across clusters: c1 via $c1_nh, c2 via $c2_nh"
    else
        fail "clients converged to the same next-hop ($c1_nh) — no divergence"
    fi
}

test_metric_flip() {
    log "Test 5: re-add A→X at metric 100 — c1 flips to the path rr1 only holds via rr2; c2 quiet"
    local c1_flaps c2_flaps rr1_inter_flaps rr2_inter_flaps c2_updates
    c1_flaps=$(flap_count "$RR1" "$C1_ADDR")
    c2_flaps=$(flap_count "$RR2" "$C2_ADDR")
    rr1_inter_flaps=$(flap_count "$RR1" "$RR2_INTER_ADDR")
    rr2_inter_flaps=$(flap_count "$RR2" "$RR1_INTER_ADDR")
    c2_updates=$(updates_sent "$RR2" "$C2_ADDR")

    # shellcheck disable=SC2046
    gobgp "$GOBGP_SRC" global rib add -a ls $(ls_link_a_x 100)

    wait_client_best "$GOBGP_C1" "$NH_Y" "$PE2_ADDR" "c1 after flip (cost 100 to X, 10 to Y)"

    # The flipped best crossed the cluster boundary: its CLUSTER_LIST
    # (attr type 10) must name BOTH clusters (rr2 reflected pe2's path to
    # rr1; rr1 reflected it on to c1).
    if gobgp "$GOBGP_C1" global rib -a ipv4 -j \
        | jq -e --arg pfx "$PREFIX" --arg c1 "$CLUSTER1" --arg c2 "$CLUSTER2" '
            (.[$pfx] // [])[0].attrs[] | select(.type == 10)
            | (.value | index($c1) != null and index($c2) != null)
        ' >/dev/null; then
        ok "c1's best carries CLUSTER_LIST naming both clusters ($CLUSTER1, $CLUSTER2)"
    else
        fail "c1's best CLUSTER_LIST does not name both clusters"
        gobgp "$GOBGP_C1" global rib -a ipv4 -j | jq . || true
    fi

    # c1 has converged, so rr1 processed the topology change end to end;
    # give any (wrong) in-flight UPDATE toward c2 a moment, then pin the
    # second quiet-counter sample.
    sleep 3
    wait_client_best "$GOBGP_C2" "$NH_Y" "$PE2_ADDR" "c2 unchanged after flip"

    local c2_updates_after
    c2_updates_after=$(updates_sent "$RR2" "$C2_ADDR")
    if [ "$c2_updates_after" = "$c2_updates" ]; then
        ok "zero UPDATEs toward c2 across the flip (updates_sent $c2_updates unchanged)"
    else
        fail "rr2 sent UPDATEs to c2 during a change that only affects c1 ($c2_updates -> $c2_updates_after)"
    fi
    assert_no_flap "$RR1" "$C1_ADDR" "$c1_flaps" "flip/c1"
    assert_no_flap "$RR2" "$C2_ADDR" "$c2_flaps" "flip/c2"
    assert_no_flap "$RR1" "$RR2_INTER_ADDR" "$rr1_inter_flaps" "flip/inter-RR (rr1 side)"
    assert_no_flap "$RR2" "$RR1_INTER_ADDR" "$rr2_inter_flaps" "flip/inter-RR (rr2 side)"

    log "Restoring A→X=1 — divergence returns"
    # shellcheck disable=SC2046
    gobgp "$GOBGP_SRC" global rib add -a ls $(ls_link_a_x 1)
    wait_client_best "$GOBGP_C1" "$NH_X" "$PE1_ADDR" "c1 after metric restore"
}

test_withdraw_restore() {
    log "Test 6: withdraw pe1's route — c1 survives on the inter-RR path; withdrawal crosses the inter-RR session"
    local c2_updates
    c2_updates=$(updates_sent "$RR2" "$C2_ADDR")

    gobgp "$GOBGP_PE1" global rib del "$PREFIX" nexthop "$NH_X"

    # c1's only remaining path is the one rr1 learned from rr2.
    wait_client_best "$GOBGP_C1" "$NH_Y" "$PE2_ADDR" "c1 after pe1 withdraw"
    # The withdrawal propagated over the inter-RR Add-Path session.
    wait_rr_received "$RR1" "$PE1_ADDR" 0 "true" \
        "rr1 Adj-RIB-In from pe1 empty after withdraw"
    wait_rr_received "$RR2" "$RR1_INTER_ADDR" 0 "true" \
        "rr2 Adj-RIB-In from rr1 empty after withdraw (inter-RR withdrawal)"

    wait_client_best "$GOBGP_C2" "$NH_Y" "$PE2_ADDR" "c2 unchanged after pe1 withdraw"

    log "Re-announcing pe1's route — divergence returns"
    gobgp "$GOBGP_PE1" global rib add "$PREFIX" nexthop "$NH_X"
    wait_client_best "$GOBGP_C1" "$NH_X" "$PE1_ADDR" "c1 divergence restored"
    wait_client_best "$GOBGP_C2" "$NH_Y" "$PE2_ADDR" "c2 divergence restored"
    wait_rr_received "$RR2" "$RR1_INTER_ADDR" 1 \
        ".next_hop == \"$NH_X\" and (.path_id // 0) >= 1" \
        "rr2 re-learned pe1's path over the inter-RR session"

    local c2_updates_after
    c2_updates_after=$(updates_sent "$RR2" "$C2_ADDR")
    if [ "$c2_updates_after" = "$c2_updates" ]; then
        ok "zero UPDATEs toward c2 across withdraw + restore (updates_sent $c2_updates unchanged)"
    else
        fail "rr2 sent UPDATEs to c2 across pe1's withdraw/restore ($c2_updates -> $c2_updates_after)"
    fi
}

test_dataplane_clean() {
    log "Test 7: neither RR installed anything into any dataplane"
    local rr
    for rr in "$RR1" "$RR2"; do
        local mpls
        mpls=$(docker exec "$rr" ip -M route show 2>/dev/null || true)
        if [ -z "$mpls" ]; then
            ok "$rr MPLS routing table is empty"
        else
            fail "$rr has unexpected MPLS routes"
            echo "$mpls" >&2
        fi

        if docker exec "$rr" ip route show | grep -q "${PREFIX%/*}"; then
            fail "$rr kernel routing table contains $PREFIX"
            docker exec "$rr" ip route show >&2 || true
        else
            ok "$rr kernel routing table has no route for $PREFIX"
        fi
    done
}

main() {
    log "M78 interop test: RFC 9107 multi-cluster ORR with inter-RR Add-Path"
    log "Topology: $TOPO"

    preflight
    start_gobgpd "$GOBGP_SRC"
    start_gobgpd "$GOBGP_PE1"
    start_gobgpd "$GOBGP_PE2"
    start_gobgpd "$GOBGP_C1"
    start_gobgpd "$GOBGP_C2"
    start_rr "$RR1" || exit 1
    start_rr "$RR2" || exit 1

    wait_gobgp_established "$GOBGP_SRC" "10.0.0.1" "src->rr1" || exit 1
    wait_gobgp_established "$GOBGP_SRC" "10.0.5.1" "src->rr2" || exit 1
    wait_gobgp_established "$GOBGP_PE1" "10.0.1.1" "pe1" || exit 1
    wait_gobgp_established "$GOBGP_PE2" "10.0.2.1" "pe2" || exit 1
    wait_gobgp_established "$GOBGP_C1" "10.0.3.1" "c1" || exit 1
    wait_gobgp_established "$GOBGP_C2" "10.0.4.1" "c2" || exit 1
    wait_rr_established "$RR1" "$RR2_INTER_ADDR" "inter-RR" || exit 1

    assert_family_negotiated "$GOBGP_SRC" "10.0.0.1" "ls" "src->rr1"
    assert_family_negotiated "$GOBGP_SRC" "10.0.5.1" "ls" "src->rr2"
    assert_family_negotiated "$GOBGP_PE1" "10.0.1.1" "ipv4-unicast" "pe1"
    assert_family_negotiated "$GOBGP_PE2" "10.0.2.1" "ipv4-unicast" "pe2"
    assert_family_negotiated "$GOBGP_C1" "10.0.3.1" "ipv4-unicast" "c1"
    assert_family_negotiated "$GOBGP_C2" "10.0.4.1" "ipv4-unicast" "c2"

    # Baselines for the end-of-run stability pin: the linkstate-only src
    # sessions must survive the whole IPv4 announce / flip / withdraw
    # churn without a flap (#632 regression pin, now on both RRs).
    local src1_flaps src2_flaps
    src1_flaps=$(flap_count "$RR1" "$SRC_RR1_ADDR")
    src2_flaps=$(flap_count "$RR2" "$SRC_RR2_ADDR")

    test_addpath_configured
    test_topology_and_vantages
    test_cross_cluster_paths
    test_divergence
    test_metric_flip
    test_withdraw_restore
    test_dataplane_clean

    log "Test 8: linkstate-only src sessions never flapped (#632 pin, both RRs)"
    assert_no_flap "$RR1" "$SRC_RR1_ADDR" "$src1_flaps" "src->rr1 (linkstate-only)"
    assert_no_flap "$RR2" "$SRC_RR2_ADDR" "$src2_flaps" "src->rr2 (linkstate-only)"

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
