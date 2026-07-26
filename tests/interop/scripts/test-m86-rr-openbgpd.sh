#!/usr/bin/env bash
# M86 interop test — rustbgpd RR + OpenBGPD 9.1 clients (RFC 4456 + RFC 4724)
#
# Topology: rustbgpd RR (AS 65001, cluster-id 10.86.0.1) with three RR
# clients — obgp1, obgp2 (OpenBGPD 9.1), and a rustbgpd client. Both
# OpenBGPD sessions carry ipv4+ipv6 unicast over v4 transport.
#
# Asserts:
#   1. All three sessions Established; the GR capability is negotiated
#      (bgpctl's view shows rustbgpd's offer — timeout, families, the
#      RFC 8538 graceful-notification bit — and the negotiated set).
#   2. v4+v6 reflection between the OpenBGPD clients, plus both
#      clients' routes reaching the rustbgpd client (via its own rbgp).
#   3. ORIGINATOR_ID = originating client's router-id and CLUSTER_LIST
#      = RR cluster-id, in bgpctl's own view of a reflected route.
#   4. Loop prevention: the RR does not reflect a client's route back
#      to it.
#   5. GR truth: OpenBGPD is a GR HELPER only — its OPEN carries the GR
#      capability with the R bit set, restart time 0, and ZERO address
#      families (captured on the wire during lab bring-up). A bgpd
#      kill -9 must therefore NOT leave stale-preserved routes on the
#      RR: the withdraws propagate to the surviving clients
#      immediately, and re-start converges back.
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m86-rr-openbgpd.clab.yml
#   - grpcurl + jq installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m86-rr-openbgpd.sh
#   bash tests/interop/scripts/test-m86-rr-openbgpd.sh --self-test-diagnostics

set -euo pipefail

TOPO="m86-rr-openbgpd"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
if [ "${1:-}" = "--self-test-diagnostics" ]; then
    ok() { printf 'PASS %s\n' "$*"; }
    fail() { printf 'FAIL %s\n' "$*"; }
else
    # shellcheck source=test-lib.sh
    source "$SCRIPT_DIR/test-lib.sh"
fi
OBGP1="clab-${TOPO}-obgp1"
OBGP2="clab-${TOPO}-obgp2"
CLIENT="clab-${TOPO}-client"

OBGP1_ADDR="10.86.1.2"
RR_FROM_OBGP1="10.86.1.1"
RR_FROM_OBGP2="10.86.2.1"

O1_V4="100.86.1.0/24"
O1_V6="2001:db8:861::/48"
O2_V4="100.86.2.0/24"
O2_V6="2001:db8:862::/48"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# rbgp against the RR / the rustbgpd client with the shared test-only token.
rr_ctl()     { docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 "$@"; }
client_ctl() { docker exec "$CLIENT" rbgp -s http://127.0.0.1:50051 "$@"; }

start_bgpd() {
    docker exec "${1:?}" sh -c \
        'mkdir -p /run/bgpd && (bgpd -d -f /etc/bgpd/bgpd.conf >>/tmp/bgpd.log 2>&1 &)'
}

kill_bgpd() {
    docker exec "${1:?}" sh -c 'pkill -9 bgpd 2>/dev/null; true'
}

wait_obgp_established() {
    local container=${1:?} rr_addr=${2:?} label=${3:?}
    log "Waiting for $label BGP session to reach Established..."
    for i in $(seq 1 45); do
        if docker exec "$container" bgpctl show neighbor "$rr_addr" 2>/dev/null \
            | grep -q "BGP state = Established"; then
            ok "$label session Established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label session did not reach Established within 90s"
    docker exec "$container" sh -c 'tail -10 /tmp/bgpd.log' 2>/dev/null || true
    return 1
}

# Poll until a command succeeds; usage: poll <tries> <sleep> <label> cmd...
poll() {
    local tries=${1:?} pause=${2:?} label=${3:?} last_output=""
    shift 3
    for i in $(seq 1 "$tries"); do
        if last_output=$("$@" 2>&1); then
            ok "$label (attempt $i)"
            return 0
        fi
        sleep "$pause"
    done
    fail "$label — timed out after $((tries * pause))s"
    if [ -n "$last_output" ]; then
        printf 'Last failed observation:\n%s\n' "$last_output" >&2
    fi
    return 1
}

record_absence_check() {
    local absent_message=${1:?} present_message=${2:?} inspection_message=${3:?}
    shift 3
    local status
    if "$@"; then
        ok "$absent_message"
        return
    else
        status=$?
    fi
    case "$status" in
        1) fail "$present_message" ;;
        2) fail "$inspection_message" ;;
        *) fail "$inspection_message (unexpected inspector status $status)" ;;
    esac
}

# True if the OpenBGPD node has a VALID BGP path for the prefix learned
# from the RR (not its own announced network — those carry announced:true).
obgp_has_bgp_route() {
    docker exec "${1:?}" bgpctl -j show rib "${2:?}" 2>/dev/null \
        | jq -e '[.rib[]? | select(((.announced // false) | not) and .valid == true)] | length > 0'
}

obgp_lacks_bgp_route() {
    local container=${1:?} rr_addr=${2:?} prefix=${3:?} neighbor output
    if ! neighbor=$(docker exec "$container" bgpctl show neighbor "$rr_addr" 2>&1); then
        printf 'OpenBGPD neighbor inspection failed for %s in %s:\n%s\n' \
            "$rr_addr" "$container" "$neighbor" >&2
        return 2
    fi
    if ! grep -q 'BGP state = Established' <<<"$neighbor"; then
        printf 'OpenBGPD neighbor %s in %s is not Established:\n%s\n' \
            "$rr_addr" "$container" "$neighbor" >&2
        return 1
    fi
    # An exact-prefix bgpctl query exits nonzero when the route is absent, so
    # inspect the full RIB and apply the exact-prefix predicate with jq.
    if ! output=$(docker exec "$container" bgpctl -j show rib 2>&1); then
        printf 'OpenBGPD RIB inspection failed for %s in %s:\n%s\n' \
            "$prefix" "$container" "$output" >&2
        return 2
    fi
    if ! jq -e '.rib | type == "array"' <<<"$output" >/dev/null 2>&1; then
        printf 'OpenBGPD RIB inspection returned malformed JSON or a non-array .rib:\n%s\n' \
            "$output" >&2
        return 2
    fi
    if ! jq -e '.rib | length > 0 and all(.[]; .prefix | type == "string")' \
        <<<"$output" >/dev/null 2>&1; then
        printf 'OpenBGPD RIB inspection returned no survivor rows or a row without a string prefix:\n%s\n' \
            "$output" >&2
        return 2
    fi
    jq -e --arg p "$prefix" \
        '[.rib[] | select(.prefix == $p and ((.announced // false) | not) and .valid == true)]
         | length == 0' <<<"$output" >/dev/null
}

# True if the rustbgpd client's Loc-RIB has the prefix.
client_has_route() {
    client_ctl rib -j 2>/dev/null | jq -e --arg p "${1:?}" \
        '[.[] | select(.prefix == $p)] | length > 0'
}

client_lacks_route() {
    local prefix=${1:?} output
    if ! client_established; then
        printf 'rustbgpd client session is not Established while checking absence of %s\n' \
            "$prefix" >&2
        return 1
    fi
    if ! output=$(client_ctl rib -j 2>&1); then
        printf 'rustbgpd client RIB inspection failed for %s:\n%s\n' "$prefix" "$output" >&2
        return 2
    fi
    if ! jq -e 'type == "array"' <<<"$output" >/dev/null 2>&1; then
        printf 'rustbgpd client RIB inspection returned malformed or non-array JSON:\n%s\n' \
            "$output" >&2
        return 2
    fi
    if ! jq -e 'all(.[]; .prefix | type == "string")' \
        <<<"$output" >/dev/null 2>&1; then
        printf 'rustbgpd client RIB inspection returned a row without a string prefix:\n%s\n' \
            "$output" >&2
        return 2
    fi
    jq -e --arg p "$prefix" --arg survivor "$O2_V4" \
        '([.[] | select(.prefix == $p)] | length == 0)
         and ([.[] | select(.prefix == $survivor)] | length >= 1)' \
        <<<"$output" >/dev/null
}

rr_lacks_routes_from() {
    local peer=${1:?} output
    if ! output=$(rr_ctl rib -j 2>&1); then
        printf 'RR RIB inspection failed for peer %s:\n%s\n' "$peer" "$output" >&2
        return 2
    fi
    if ! jq -e 'type == "array"' <<<"$output" >/dev/null 2>&1; then
        printf 'RR RIB inspection returned malformed or non-array JSON:\n%s\n' "$output" >&2
        return 2
    fi
    if ! jq -e 'length > 0 and all(.[]; .peer_address | type == "string")' \
        <<<"$output" >/dev/null 2>&1; then
        printf 'RR RIB inspection returned no survivor rows or a row without a string peer_address:\n%s\n' \
            "$output" >&2
        return 2
    fi
    jq -e --arg peer "$peer" '[.[] | select(.peer_address == $peer)] | length == 0' \
        <<<"$output" >/dev/null
}

# True if the rustbgpd client's session to the RR is Established.
client_established() {
    client_ctl neighbor -j 2>/dev/null \
        | jq -e 'type == "array"
                 and ([.[] | select(.state == "Established")] | length >= 1)'
}

# ---------------------------------------------------------------------------
# Test 1: sessions + capability exchange
# ---------------------------------------------------------------------------
test_sessions() {
    log "Test 1: three RR-client sessions Established, GR capability negotiated"

    wait_obgp_established "$OBGP1" "$RR_FROM_OBGP1" "obgp1" || return 1
    wait_obgp_established "$OBGP2" "$RR_FROM_OBGP2" "obgp2" || return 1
    poll 30 2 "rustbgpd client session Established" client_established

    local nbr
    nbr=$(docker exec "$OBGP1" bgpctl show neighbor "$RR_FROM_OBGP1" 2>/dev/null)

    # rustbgpd's offer as OpenBGPD sees it: GR with a timeout, both
    # unicast families, and the RFC 8538 graceful-notification bit.
    if echo "$nbr" | grep -A7 "Neighbor capabilities:" \
        | grep "Graceful Restart:" | grep -q "graceful notification"; then
        ok "obgp1 sees rustbgpd's GR capability with graceful notification (RFC 8538)"
    else
        fail "obgp1 does not report rustbgpd's GR capability with graceful notification"
        echo "$nbr" | sed -n '1,20p' >&2 || true
    fi

    # The negotiated set retains GR for both families.
    if echo "$nbr" | grep -A7 "Negotiated capabilities:" \
        | grep "Graceful Restart:" | grep "IPv4 unicast" | grep -q "IPv6 unicast"; then
        ok "negotiated capabilities include GR for IPv4+IPv6 unicast"
    else
        fail "negotiated capabilities missing GR for IPv4+IPv6 unicast"
        echo "$nbr" | sed -n '1,20p' >&2 || true
    fi
}

# ---------------------------------------------------------------------------
# Test 2: v4 + v6 reflection between all clients
# ---------------------------------------------------------------------------
test_reflection() {
    log "Test 2: v4+v6 reflection obgp1 ↔ obgp2 and toward the rustbgpd client"

    poll 15 2 "obgp2 has $O1_V4 (v4 reflected)"  obgp_has_bgp_route "$OBGP2" "$O1_V4"
    poll 15 2 "obgp2 has $O1_V6 (v6 reflected)"  obgp_has_bgp_route "$OBGP2" "$O1_V6"
    poll 15 2 "obgp1 has $O2_V4 (v4 reflected)"  obgp_has_bgp_route "$OBGP1" "$O2_V4"
    poll 15 2 "obgp1 has $O2_V6 (v6 reflected)"  obgp_has_bgp_route "$OBGP1" "$O2_V6"

    for p in "$O1_V4" "$O1_V6" "$O2_V4" "$O2_V6"; do
        poll 15 2 "rustbgpd client has $p" client_has_route "$p"
    done
}

# ---------------------------------------------------------------------------
# Test 3: ORIGINATOR_ID + CLUSTER_LIST in bgpctl's view
# ---------------------------------------------------------------------------
test_originator_cluster() {
    log "Test 3: ORIGINATOR_ID / CLUSTER_LIST on reflected routes (bgpctl view)"

    local attrs
    attrs=$(docker exec "$OBGP2" bgpctl -j show rib detail "$O1_V4" 2>/dev/null \
        | jq -c '[.rib[]? | select((.announced // false) | not)][0].attributes')

    if echo "$attrs" | jq -e '[.[] | select(.originator == "10.86.1.2")] | length == 1' >/dev/null; then
        ok "obgp2 sees ORIGINATOR_ID 10.86.1.2 on $O1_V4"
    else
        fail "obgp2 missing ORIGINATOR_ID 10.86.1.2 on $O1_V4"
        echo "$attrs" >&2 || true
    fi

    if echo "$attrs" | jq -e '[.[] | select((.cluster_list // []) | index("10.86.0.1"))] | length == 1' >/dev/null; then
        ok "obgp2 sees CLUSTER_LIST 10.86.0.1 on $O1_V4"
    else
        fail "obgp2 missing CLUSTER_LIST 10.86.0.1 on $O1_V4"
        echo "$attrs" >&2 || true
    fi

    # Same on the v6 route in the other direction.
    attrs=$(docker exec "$OBGP1" bgpctl -j show rib detail "$O2_V6" 2>/dev/null \
        | jq -c '[.rib[]? | select((.announced // false) | not)][0].attributes')
    if echo "$attrs" | jq -e '[.[] | select(.originator == "10.86.2.2")] | length == 1' >/dev/null \
        && echo "$attrs" | jq -e '[.[] | select((.cluster_list // []) | index("10.86.0.1"))] | length == 1' >/dev/null; then
        ok "obgp1 sees ORIGINATOR_ID 10.86.2.2 + CLUSTER_LIST on $O2_V6"
    else
        fail "obgp1 missing ORIGINATOR_ID/CLUSTER_LIST on $O2_V6"
        echo "$attrs" >&2 || true
    fi
}

# ---------------------------------------------------------------------------
# Test 4: no reflect-back to the originator
# ---------------------------------------------------------------------------
test_no_reflect_back() {
    log "Test 4: RR does not reflect a client's route back to it"

    local adv
    adv=$(rr_ctl rib advertised "$OBGP1_ADDR" -j 2>/dev/null)
    if echo "$adv" | jq -e --arg p "$O1_V4" '[.[] | select(.prefix == $p)] | length == 0' >/dev/null; then
        ok "rbgp rib advertised to obgp1 excludes obgp1's own $O1_V4"
    else
        fail "RR advertises obgp1's own $O1_V4 back to it"
    fi
    if echo "$adv" | jq -e --arg p "$O2_V4" '[.[] | select(.prefix == $p)] | length == 1' >/dev/null; then
        ok "rbgp rib advertised to obgp1 includes obgp2's $O2_V4"
    else
        fail "RR does not advertise obgp2's $O2_V4 to obgp1"
    fi

    record_absence_check \
        "obgp1 has no BGP-learned path for its own $O1_V4 (announced only)" \
        "obgp1 received its own $O1_V4 back from the RR" \
        "could not verify that obgp1 lacks its own $O1_V4 because OpenBGPD inspection failed" \
        obgp_lacks_bgp_route "$OBGP1" "$RR_FROM_OBGP1" "$O1_V4"
}

# ---------------------------------------------------------------------------
# Test 5: GR truth — helper-only peer, kill means withdraw
# ---------------------------------------------------------------------------
test_gr_helper_only() {
    log "Test 5: kill obgp1 (GR helper-only: R bit, time 0, no AFs) — NO preservation"

    kill_bgpd "$OBGP1"

    # No AF was advertised as preserved, so the RR must withdraw
    # obgp1's routes from the surviving clients immediately.
    poll 20 2 "obgp2 loses $O1_V4 (withdraw propagated)" \
        obgp_lacks_bgp_route "$OBGP2" "$RR_FROM_OBGP2" "$O1_V4"
    poll 10 2 "obgp2 loses $O1_V6 (withdraw propagated)" \
        obgp_lacks_bgp_route "$OBGP2" "$RR_FROM_OBGP2" "$O1_V6"
    poll 10 2 "rustbgpd client loses $O1_V4" client_lacks_route "$O1_V4"

    record_absence_check \
        "no routes from obgp1 remain on the RR (helper-only peer not GR-preserved)" \
        "RR retained routes from helper-only (no-AF) GR peer $OBGP1_ADDR" \
        "could not verify removal of routes from helper-only GR peer $OBGP1_ADDR because RR RIB inspection failed" \
        rr_lacks_routes_from "$OBGP1_ADDR"

    # Recovery: obgp1 comes back, everything re-converges.
    start_bgpd "$OBGP1"
    wait_obgp_established "$OBGP1" "$RR_FROM_OBGP1" "obgp1 (restarted)" || return 1
    poll 15 2 "obgp2 re-learns $O1_V4" obgp_has_bgp_route "$OBGP2" "$O1_V4"
    poll 15 2 "rustbgpd client re-learns $O1_V6" client_has_route "$O1_V6"
}

self_test_output() {
    local output=${1:?} expected=${2:?} rejected=${3:-}
    if [[ "$output" != *"$expected"* ]] \
        || { [ -n "$rejected" ] && [[ "$output" == *"$rejected"* ]]; }; then
        printf 'diagnostic self-test expected %q and rejected %q in:\n%s\n' \
            "$expected" "$rejected" "$output" >&2
        return 1
    fi
}

self_test_status() {
    local status=${1:?}
    if [ "$status" -eq 2 ]; then
        printf 'pinned inspector diagnostic\n' >&2
    fi
    return "$status"
}

self_test_diagnostics() {
    local output
    if output=$(poll 2 0 "self-test poll" self_test_status 2 2>&1); then
        printf 'diagnostic self-test expected poll failure\n' >&2
        return 1
    fi
    self_test_output "$output" "self-test poll — timed out"
    self_test_output "$output" "Last failed observation:"
    self_test_output "$output" "pinned inspector diagnostic"

    output=$(record_absence_check "route absent" "route still present" \
        "inspection failed" self_test_status 0 2>&1)
    self_test_output "$output" "route absent" "route still present"
    self_test_output "$output" "route absent" "inspection failed"

    output=$(record_absence_check "route absent" "route still present" \
        "inspection failed" self_test_status 1 2>&1)
    self_test_output "$output" "route still present" "inspection failed"

    output=$(record_absence_check "route absent" "route still present" \
        "inspection failed" self_test_status 2 2>&1)
    self_test_output "$output" "pinned inspector diagnostic"
    self_test_output "$output" "inspection failed" "route still present"

    output=$(record_absence_check "route absent" "route still present" \
        "inspection failed" self_test_status 7 2>&1)
    self_test_output "$output" "inspection failed (unexpected inspector status 7)"

    printf 'M86 diagnostic self-test passed\n'
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M86 interop test: rustbgpd RR + OpenBGPD 9.1 clients (RFC 4456 + RFC 4724)"
    log "Topology: $TOPO"

    resolve_grpc_addr
    # shellcheck disable=SC2119
    start_rustbgpd

    log "Starting rustbgpd client..."
    docker exec -d "$CLIENT" /usr/local/bin/start-rustbgpd.sh

    log "Starting OpenBGPD clients..."
    start_bgpd "$OBGP1"
    start_bgpd "$OBGP2"

    test_sessions
    test_reflection
    test_originator_cluster
    test_no_reflect_back
    test_gr_helper_only

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

if [ "${1:-}" = "--self-test-diagnostics" ]; then
    self_test_diagnostics
else
    main "$@"
fi
