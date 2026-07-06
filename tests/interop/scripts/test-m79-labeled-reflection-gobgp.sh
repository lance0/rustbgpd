#!/usr/bin/env bash
# M79 interop test — IPv4/IPv6 labeled-unicast (RFC 8277, SAFI 4) route
# reflection + GR stale preservation against GoBGP v4.
#
# Validates:
#   1. Labeled-unicast (SAFI 4) iBGP sessions establish to both RR clients
#      with ipv4-labelled-unicast AND ipv6-labelled-unicast negotiated, and
#      the PE's GR capability exchange carries both labeled families in the
#      Local and Remote sets.
#   2. GoBGP PE injects three labeled routes: two IPv4 (one single label,
#      one multi-label stack) and one IPv6 (v6 next-hop over the v4
#      session). rustbgpd stores all three in its labeled RIB with label
#      stack, next-hop, and family intact (rbgp rib labeled -j).
#   3. rustbgpd reflects all three to the client with the label stack and
#      next-hop preserved verbatim and RFC 4456 ORIGINATOR_ID (the PE's
#      router-id) + CLUSTER_LIST (the RR's cluster-id) attached — asserted
#      on the client's adj-in view.
#   4. Relabel: the PE re-adds a prefix with a different label — implicit
#      replace end to end (exactly one path with the new label on the RR
#      and the client, no session flap).
#   5. Withdrawal removes exactly that route from rustbgpd and the client
#      with zero session flap; the other routes survive. GoBGP puts the
#      ORIGINAL multi-label stack in the withdraw NLRI rather than the
#      RFC 8277 §2.4 compatibility field — the wire shape that reset the
#      session pre-#651, so the no-flap assert is that fix's live
#      regression pin.
#   6. GR window (RFC 4724): kill -9 of the PE daemon — the RR holds the
#      labeled routes stale, the client keeps its reflected copies with
#      zero UPDATEs on the wire; a controlled `gobgpd -r` relaunch (link
#      held down while only the IPv4 route is re-injected) re-establishes,
#      and the End-of-RIB sweep removes exactly the not-re-advertised IPv6
#      route from the RR and the client.
#   7. Nothing is installed into any dataplane: no MPLS routes and no
#      kernel routes derived from the labeled family on the RR.
#
# GoBGP CLI syntax note (v4.6.0): the labeled family takes the label
# POSITIONALLY — `gobgp global rib add -a ipv4-labeled <prefix> <label>
# nexthop <ip>` (no `label` keyword, unlike vpnv4); multi-label stacks are
# slash-separated (`801/802`); the config-file family name is the
# double-L "ipv4-labelled-unicast".
#
# GoBGP quirk (v4.6.0, upstream): a LABEL-ONLY change to an existing
# labeled-unicast path is never put on the wire — GoBGP's own table and
# adj-out views show the new label, but no UPDATE is sent (the peer's
# updates_received counter stays flat), because the update-suppression
# compare keys on prefix + path attributes and the label stack is neither.
# The relabel test therefore changes a COMMUNITY alongside the label to
# force the UPDATE out; the assertion target (rustbgpd replaces the
# (prefix, path_id) row in place — new label, exactly one path end to end,
# no withdraw churn, no flap) is rustbgpd behavior and unaffected.
#
# Prerequisites:
#   - docker build --target dev -t rustbgpd:dev .
#   - docker build -t gobgp:bgpls -f tests/interop/Dockerfile.gobgp-bgpls tests/interop
#   - containerlab deployed:
#       containerlab deploy -t tests/interop/m79-labeled-reflection-gobgp.clab.yml

TOPO="m79-labeled-reflection-gobgp"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"

GOBGP_PE="clab-${TOPO}-gobgp-pe"
GOBGP_CLIENT="clab-${TOPO}-gobgp-client"

PE_ADDR="10.0.1.2"
CLIENT_ADDR="10.0.0.2"
RR_CLUSTER_ID="10.0.0.1"

V4_PREFIX_A="198.51.100.0/24"
V4_PREFIX_B="198.51.101.0/24"
V6_PREFIX="2001:db8:100::/48"
LABEL_A=800
LABEL_A2=850
STACK_B="801/802"
LABEL_V6=900
V6_NEXTHOP="2001:db8::2"

# ---------------------------------------------------------------------------
# Daemon lifecycle helpers (m77 pattern)
# ---------------------------------------------------------------------------

start_gobgpd() {
    local container=${1:?}
    local extra=${2:-}
    log "Starting gobgpd in $container${extra:+ (flags: $extra)}..."
    docker exec -d "$container" sh -c \
        "nohup gobgpd -f /config/gobgp.toml $extra >/tmp/gobgpd.log 2>&1"
}

# kill -9 so no NOTIFICATION is sent: RFC 4724 GR procedures only trigger
# on a session that drops without one. The gobgp image has no procps, so
# walk /proc.
kill_gobgpd() {
    local container=${1:?}
    log "kill -9 gobgpd in $container..."
    docker exec "$container" sh -c '
        for p in /proc/[0-9]*; do
            [ "$(cat "$p/comm" 2>/dev/null)" = "gobgpd" ] && kill -9 "${p#/proc/}"
        done
        true'
}

pe_link() {
    docker exec "$GOBGP_PE" ip link set eth1 "${1:?}"
}

gobgp() {
    local container=${1:?}
    shift
    docker exec "$container" gobgp "$@" 2>/dev/null
}

gobgp_neighbor() {
    gobgp "${1:?}" neighbor 2>/dev/null || true
}

rbgp() {
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 "$@"
}

rustbgpd_labeled_json() {
    rbgp rib labeled -j
}

rustbgpd_neighbor_json() {
    rbgp neighbor "${1:?}" -j
}

# Client's adj-in table for one labeled family, keyed by prefix.
client_adj_in_json() {
    gobgp "$GOBGP_CLIENT" neighbor "10.0.0.1" adj-in -a "${1:?}" -j
}

# ---------------------------------------------------------------------------
# Metric / session helpers
# ---------------------------------------------------------------------------

gr_active_total() {
    prom_scrape "$RUSTBGPD" \
        | awk '/^bgp_gr_active_peers\{/ {s+=$2} END {print s+0}'
}

wait_gr_active() {
    local want=${1:?} label=${2:?}
    log "Waiting for bgp_gr_active_peers == $want ($label)..."
    for i in $(seq 1 30); do
        if [ "$(gr_active_total)" -eq "$want" ]; then
            ok "bgp_gr_active_peers == $want ($label, attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "bgp_gr_active_peers never reached $want ($label), got $(gr_active_total)"
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

wait_gobgp_established() {
    local container=${1:?} peer=${2:?} label=${3:?}
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

assert_family_negotiated() {
    local container=${1:?} peer=${2:?} family=${3:?} label=${4:?}
    if gobgp "$container" neighbor "$peer" \
        | grep -A 30 "Neighbor capabilities" \
        | grep "    ${family}:" \
        | grep -q "advertised and received"; then
        ok "$label negotiated $family"
    else
        fail "$label did not negotiate $family"
        gobgp "$container" neighbor "$peer" | grep -A 30 "Neighbor capabilities" >&2 || true
    fi
}

# The capability block for one capability name (m77 pattern).
cap_block() {
    local container=${1:?} peer=${2:?} cap=${3:?}
    gobgp "$container" neighbor "$peer" | awk -v cap="    ${cap}:" '
        index($0, cap) == 1 {f=1; print; next}
        f && (/^    [a-z0-9]/ || /^  [A-Z]/) {f=0; next}
        f {print}'
}

# Assert a family appears in the GR capability both advertised and received
# AND in the Remote (= rustbgpd) family set.
assert_gr_cap_family() {
    local container=${1:?} peer=${2:?} family=${3:?} label=${4:?}
    local block first_line family_count
    block=$(cap_block "$container" "$peer" "graceful-restart")
    first_line=${block%%$'\n'*}
    family_count=$(grep -cE "(^|[[:space:]])${family}(,|[[:space:]]|\$)" <<<"$block" || true)
    if [[ "$first_line" == *"advertised and received"* ]] \
        && grep -q "Remote:" <<<"$block" \
        && [ "$family_count" -ge 2 ]; then
        ok "$label: $family in local AND remote graceful-restart capability"
    else
        fail "$label: $family missing from the graceful-restart capability exchange"
        echo "$block" >&2
    fi
}

# ---------------------------------------------------------------------------
# Labeled RIB helpers
# ---------------------------------------------------------------------------

# Count RR labeled rows matching family/prefix/labels/next-hop/peer with a
# given staleness shape ($6: "any" | "fresh" | "stale").
labeled_row_count() {
    local family=${1:?} pfx=${2:?} labels_json=${3:?} nh=${4:?} peer=${5:?} shape=${6:-any}
    rustbgpd_labeled_json | jq --arg family "$family" --arg pfx "$pfx" \
        --argjson labels "$labels_json" --arg nh "$nh" --arg peer "$peer" \
        --arg shape "$shape" '
        [.[] | select(.afi_safi == $family
                      and .prefix == $pfx
                      and .labels == $labels
                      and .next_hop == $nh
                      and .peer_address == $peer)
             | select(
                 if $shape == "fresh" then ((.stale // false) | not)
                 elif $shape == "stale" then (.stale // false)
                 else true end)]
        | length' 2>/dev/null || echo 0
}

# Count of RR labeled rows for one prefix regardless of labels.
labeled_prefix_count() {
    local pfx=${1:?}
    rustbgpd_labeled_json | jq --arg pfx "$pfx" \
        '[.[] | select(.prefix == $pfx)] | length' 2>/dev/null || echo 0
}

wait_labeled_row() {
    local family=${1:?} pfx=${2:?} labels_json=${3:?} nh=${4:?} shape=${5:?} label=${6:?}
    local attempts=${7:-30}
    log "Waiting for RR labeled row $pfx labels=$labels_json ($shape) — $label..."
    for i in $(seq 1 "$attempts"); do
        if [ "$(labeled_row_count "$family" "$pfx" "$labels_json" "$nh" "$PE_ADDR" "$shape")" -ge 1 ]; then
            ok "RR labeled RIB holds $pfx labels=$labels_json nh=$nh as $shape ($label, attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "RR labeled RIB never showed $pfx labels=$labels_json as $shape ($label)"
    rustbgpd_labeled_json | jq . || true
    return 1
}

wait_labeled_prefix_gone() {
    local pfx=${1:?} label=${2:?}
    local attempts=${3:-30}
    log "Waiting for RR labeled RIB to drop $pfx — $label..."
    for i in $(seq 1 "$attempts"); do
        if [ "$(labeled_prefix_count "$pfx")" -eq 0 ]; then
            ok "RR labeled RIB swept $pfx ($label, attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "RR labeled RIB still holds $pfx ($label)"
    rustbgpd_labeled_json | jq . || true
    return 1
}

# ---------------------------------------------------------------------------
# Client adj-in helpers
# ---------------------------------------------------------------------------

# Verbatim reflection check on the client's adj-in view: exactly one path
# for the prefix, with the label stack in the NLRI, the next-hop in the
# MP_REACH attr (type 14), ORIGINATOR_ID (type 9) = the PE's router-id, and
# the RR's cluster-id in CLUSTER_LIST (type 10).
client_has_reflected() {
    local family=${1:?} pfx=${2:?} labels_json=${3:?} nh=${4:?}
    client_adj_in_json "$family" | jq -e \
        --arg pfx "$pfx" --argjson labels "$labels_json" --arg nh "$nh" \
        --arg orig "$PE_ADDR" --arg cluster "$RR_CLUSTER_ID" '
        (.[$pfx] // []) as $paths
        | ($paths | length) == 1
        and ($paths[0] as $p
             | ($p.nlri.labels == $labels)
             and ([$p.attrs[] | select(.type == 14)][0].nexthop == $nh)
             and ([$p.attrs[] | select(.type == 9)][0].value == $orig)
             and ([$p.attrs[] | select(.type == 10)][0].value | index($cluster) != null))' \
        >/dev/null
}

client_prefix_present() {
    local family=${1:?} pfx=${2:?}
    client_adj_in_json "$family" | jq -e --arg pfx "$pfx" 'has($pfx)' >/dev/null
}

wait_client_reflected() {
    local family=${1:?} pfx=${2:?} labels_json=${3:?} nh=${4:?} label=${5:?}
    log "Waiting for client adj-in $pfx labels=$labels_json nh=$nh — $label..."
    for i in $(seq 1 30); do
        if client_has_reflected "$family" "$pfx" "$labels_json" "$nh"; then
            ok "client holds $pfx with labels/next-hop verbatim + ORIGINATOR_ID/CLUSTER_LIST ($label, attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "client adj-in never showed $pfx with labels=$labels_json nh=$nh + RFC 4456 attrs ($label)"
    client_adj_in_json "$family" | jq . || true
    return 1
}

wait_client_prefix_gone() {
    local family=${1:?} pfx=${2:?} label=${3:?}
    local attempts=${4:-30}
    log "Waiting for client to drop $pfx — $label..."
    for i in $(seq 1 "$attempts"); do
        if ! client_prefix_present "$family" "$pfx"; then
            ok "client dropped $pfx ($label, attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "client still holds $pfx ($label)"
    client_adj_in_json "$family" | jq . || true
    return 1
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

test_capabilities() {
    log "Test 1: labeled-unicast + per-family GR capability exchange"

    assert_family_negotiated "$GOBGP_PE" 10.0.1.1 "ipv4-labelled-unicast" "pe"
    assert_family_negotiated "$GOBGP_PE" 10.0.1.1 "ipv6-labelled-unicast" "pe"
    assert_family_negotiated "$GOBGP_CLIENT" 10.0.0.1 "ipv4-labelled-unicast" "client"
    assert_family_negotiated "$GOBGP_CLIENT" 10.0.0.1 "ipv6-labelled-unicast" "client"

    assert_gr_cap_family "$GOBGP_PE" 10.0.1.1 "ipv4-labelled-unicast" "pe"
    assert_gr_cap_family "$GOBGP_PE" 10.0.1.1 "ipv6-labelled-unicast" "pe"
}

test_labeled_reflection() {
    log "Test 2: PE injects three labeled routes; RR stores + reflects verbatim"

    gobgp "$GOBGP_PE" global rib add -a ipv4-labeled "$V4_PREFIX_A" "$LABEL_A" nexthop "$PE_ADDR"
    gobgp "$GOBGP_PE" global rib add -a ipv4-labeled "$V4_PREFIX_B" "$STACK_B" nexthop "$PE_ADDR"
    gobgp "$GOBGP_PE" global rib add -a ipv6-labeled "$V6_PREFIX" "$LABEL_V6" nexthop "$V6_NEXTHOP"

    wait_labeled_row ipv4_labeled_unicast "$V4_PREFIX_A" "[$LABEL_A]" "$PE_ADDR" fresh "baseline"
    wait_labeled_row ipv4_labeled_unicast "$V4_PREFIX_B" "[801,802]" "$PE_ADDR" fresh "baseline (multi-label stack)"
    wait_labeled_row ipv6_labeled_unicast "$V6_PREFIX" "[$LABEL_V6]" "$V6_NEXTHOP" fresh "baseline (v6 next-hop)"

    wait_client_reflected ipv4-labeled "$V4_PREFIX_A" "[$LABEL_A]" "$PE_ADDR" "baseline"
    wait_client_reflected ipv4-labeled "$V4_PREFIX_B" "[801,802]" "$PE_ADDR" "baseline (multi-label stack)"
    wait_client_reflected ipv6-labeled "$V6_PREFIX" "[$LABEL_V6]" "$V6_NEXTHOP" "baseline (v6 next-hop)"
}

test_relabel_implicit_replace() {
    log "Test 3: PE re-adds $V4_PREFIX_A with label $LABEL_A2 — implicit replace"

    local client_flaps
    client_flaps=$(flap_count "$CLIENT_ADDR")

    # The community change rides along to defeat GoBGP's label-blind
    # update suppression (see the header quirk note) — a label-only
    # re-add never reaches the wire.
    gobgp "$GOBGP_PE" global rib add -a ipv4-labeled "$V4_PREFIX_A" "$LABEL_A2" \
        community "65001:850" nexthop "$PE_ADDR"

    wait_labeled_row ipv4_labeled_unicast "$V4_PREFIX_A" "[$LABEL_A2]" "$PE_ADDR" fresh "relabel"
    if [ "$(labeled_prefix_count "$V4_PREFIX_A")" -eq 1 ]; then
        ok "RR holds exactly one row for $V4_PREFIX_A after the relabel (implicit replace)"
    else
        fail "RR holds $(labeled_prefix_count "$V4_PREFIX_A") rows for $V4_PREFIX_A after the relabel"
        rustbgpd_labeled_json | jq . || true
    fi

    # client_has_reflected asserts exactly ONE path — the old label 800
    # copy must be gone without an observable withdraw/re-add churn.
    wait_client_reflected ipv4-labeled "$V4_PREFIX_A" "[$LABEL_A2]" "$PE_ADDR" "relabel"
    assert_no_flap "$CLIENT_ADDR" "$client_flaps" "relabel/client"
}

test_withdrawal() {
    log "Test 4: PE withdraws $V4_PREFIX_B; the other routes must survive"

    # GoBGP withdraws with the ORIGINAL multi-label stack in the NLRI, not
    # the RFC 8277 §2.4 compatibility field — the exact wire shape that
    # reset the session pre-#651 (NOTIFICATION 3/10). The PE no-flap assert
    # below is the regression pin: the withdraw must decode and remove
    # exactly this route with the session staying Established.
    local pe_flaps
    pe_flaps=$(flap_count "$PE_ADDR")

    gobgp "$GOBGP_PE" global rib del -a ipv4-labeled "$V4_PREFIX_B" "$STACK_B" nexthop "$PE_ADDR"

    wait_labeled_prefix_gone "$V4_PREFIX_B" "withdraw"
    wait_client_prefix_gone ipv4-labeled "$V4_PREFIX_B" "withdraw"
    assert_no_flap "$PE_ADDR" "$pe_flaps" "multi-label withdraw/pe (#651 pin)"

    if [ "$(labeled_prefix_count "$V4_PREFIX_A")" -eq 1 ] \
        && [ "$(labeled_prefix_count "$V6_PREFIX")" -eq 1 ]; then
        ok "RR still holds $V4_PREFIX_A and $V6_PREFIX after the withdrawal"
    else
        fail "RR lost an unrelated labeled route alongside the withdrawal"
        rustbgpd_labeled_json | jq . || true
    fi
    if client_prefix_present ipv4-labeled "$V4_PREFIX_A" \
        && client_prefix_present ipv6-labeled "$V6_PREFIX"; then
        ok "client still holds $V4_PREFIX_A and $V6_PREFIX after the withdrawal"
    else
        fail "client lost an unrelated labeled route alongside the withdrawal"
    fi
}

test_gr_window() {
    log "Test 5: kill -9 the PE — labeled routes preserved stale, client untouched"

    local client_flaps client_updates
    client_flaps=$(flap_count "$CLIENT_ADDR")
    client_updates=$(updates_sent "$CLIENT_ADDR")

    kill_gobgpd "$GOBGP_PE"

    wait_gr_active 1 "PE killed"
    wait_labeled_row ipv4_labeled_unicast "$V4_PREFIX_A" "[$LABEL_A2]" "$PE_ADDR" stale "GR window"
    wait_labeled_row ipv6_labeled_unicast "$V6_PREFIX" "[$LABEL_V6]" "$V6_NEXTHOP" stale "GR window"

    # The wire: the client KEEPS both reflected routes and sees nothing.
    if client_prefix_present ipv4-labeled "$V4_PREFIX_A" \
        && client_prefix_present ipv6-labeled "$V6_PREFIX"; then
        ok "client still holds both reflected labeled routes during the GR window"
    else
        fail "client lost a reflected labeled route during the GR window"
    fi

    sleep 6
    local updates_after
    updates_after=$(updates_sent "$CLIENT_ADDR")
    if [ "$updates_after" = "$client_updates" ]; then
        ok "zero UPDATEs toward the client across GR entry (updates_sent $client_updates unchanged)"
    else
        fail "RR sent UPDATEs to the client at GR entry ($client_updates -> $updates_after)"
    fi
    assert_no_flap "$CLIENT_ADDR" "$client_flaps" "GR window/client"
}

test_relaunch_eor_sweep() {
    log "Test 6: gobgpd -r relaunch — v4 re-advertised, v6 swept at End-of-RIB"

    local client_flaps
    client_flaps=$(flap_count "$CLIENT_ADDR")

    # Hold the BGP link down through the relaunch so the v4 re-injection
    # always beats session re-establishment (and therefore the EoR). The
    # gRPC API listens on localhost, unaffected by eth1.
    pe_link down
    start_gobgpd "$GOBGP_PE" "-r"

    log "Re-injecting ONLY the IPv4 route while the link is down..."
    local injected=0
    for i in $(seq 1 20); do
        if gobgp "$GOBGP_PE" global rib add -a ipv4-labeled "$V4_PREFIX_A" "$LABEL_A2" \
            nexthop "$PE_ADDR" 2>/dev/null; then
            injected=1
            ok "IPv4 labeled route re-injected before re-establishment (attempt $i)"
            break
        fi
        sleep 1
    done
    if [ "$injected" -ne 1 ]; then
        fail "could not re-inject the IPv4 labeled route after relaunch"
        docker exec "$GOBGP_PE" cat /tmp/gobgpd.log >&2 || true
    fi
    pe_link up

    wait_gobgp_established "$GOBGP_PE" 10.0.1.1 "pe (restarted)" || return 1

    # v4 was re-advertised: stale flag cleared, route survives.
    wait_labeled_row ipv4_labeled_unicast "$V4_PREFIX_A" "[$LABEL_A2]" "$PE_ADDR" fresh "post-EoR"
    # v6 was NOT: the RFC-strict EoR sweep removes it from the RR...
    wait_labeled_prefix_gone "$V6_PREFIX" "EoR sweep"
    # ...and withdraws it from the client, which keeps the v4 route.
    wait_client_prefix_gone ipv6-labeled "$V6_PREFIX" "EoR sweep/client"
    if client_prefix_present ipv4-labeled "$V4_PREFIX_A"; then
        ok "client kept $V4_PREFIX_A across the PE restart"
    else
        fail "client lost $V4_PREFIX_A across the PE restart"
    fi

    wait_gr_active 0 "GR completed by EoR"
    assert_no_flap "$CLIENT_ADDR" "$client_flaps" "restart/client"
}

test_no_dataplane_install() {
    log "Test 7: RR installed nothing into any dataplane"

    local mpls
    mpls=$(docker exec "$RUSTBGPD" ip -M route show 2>/dev/null || true)
    if [ -z "$mpls" ]; then
        ok "RR MPLS routing table is empty"
    else
        fail "RR has unexpected MPLS routes"
        echo "$mpls" >&2
    fi

    if docker exec "$RUSTBGPD" ip route show \
        | grep -qE "${V4_PREFIX_A%/*}|${V4_PREFIX_B%/*}"; then
        fail "RR kernel routing table contains a labeled-derived route"
        docker exec "$RUSTBGPD" ip route show >&2 || true
    elif docker exec "$RUSTBGPD" ip -6 route show | grep -qF "${V6_PREFIX%/*}"; then
        fail "RR kernel v6 routing table contains a labeled-derived route"
        docker exec "$RUSTBGPD" ip -6 route show >&2 || true
    else
        ok "RR kernel routing tables have no labeled-derived routes"
    fi
}

main() {
    log "M79 interop test: labeled-unicast route reflection + GR via GoBGP"
    log "Topology: $TOPO"

    preflight
    resolve_grpc_addr
    start_gobgpd "$GOBGP_PE"
    start_gobgpd "$GOBGP_CLIENT"
    start_rustbgpd

    wait_gobgp_established "$GOBGP_PE" 10.0.1.1 "pe" || exit 1
    wait_gobgp_established "$GOBGP_CLIENT" 10.0.0.1 "client" || exit 1

    test_capabilities
    test_labeled_reflection
    test_relabel_implicit_replace
    test_withdrawal
    test_gr_window
    test_relaunch_eor_sweep
    test_no_dataplane_install

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
