#!/usr/bin/env bash
# M85 interop test — rustbgpd RR + BIRD 2 clients (RFC 4456 + RFC 4724)
#
# Topology: rustbgpd RR (AS 65001, cluster-id 10.85.0.1) with three RR
# clients — bird1 (GR on), bird2 (GR default/aware), and a rustbgpd
# client. Both BIRD sessions carry ipv4+ipv6 unicast over v4 transport.
#
# Asserts:
#   1. All three sessions Established; BIRD reports rustbgpd's
#      capabilities (incl. graceful restart) on the session.
#   2. v4+v6 reflection between the BIRD clients, plus both clients'
#      routes reaching the rustbgpd client (asserted via its own rbgp).
#   3. ORIGINATOR_ID = originating client's router-id and CLUSTER_LIST
#      = RR cluster-id, in BIRD's own view of a reflected route.
#   4. Loop prevention: the RR does not reflect a client's route back
#      to it (bird1's own prefix absent from `rbgp rib advertised` to
#      bird1 and from bird1's BGP table).
#   5. GR helper truth, bird1 (`graceful restart on` — BIRD lists the
#      AFs in its GR capability): kill -9 bird1 → routes preserved
#      stale on the RR, NOT withdrawn from bird2/client; restart →
#      stale clears, routes fresh.
#   6. GR truth, bird2 (BIRD default `graceful restart aware` — the GR
#      capability is sent with restart time 0 and NO address families):
#      kill -9 bird2 → NO stale preservation; the RR withdraws bird2's
#      routes from bird1 and the client. Restart converges back.
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m85-rr-bird.clab.yml
#   - grpcurl + jq installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m85-rr-bird.sh


TOPO="m85-rr-bird"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"
BIRD1="clab-${TOPO}-bird1"
BIRD2="clab-${TOPO}-bird2"
CLIENT="clab-${TOPO}-client"

BIRD1_ADDR="10.85.1.2"

B1_V4="100.85.1.0/24"
B1_V6="2001:db8:851::/48"
B2_V4="100.85.2.0/24"
B2_V6="2001:db8:852::/48"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# rbgp against the RR / the rustbgpd client with the shared test-only token.
rr_ctl()     { docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 "$@"; }
client_ctl() { docker exec "$CLIENT" rbgp -s http://127.0.0.1:50051 "$@"; }

start_bird() {
    local container=${1:?}
    docker exec "$container" sh -c \
        'mkdir -p /run/bird && (bird -d -c /etc/bird/bird.conf >>/tmp/bird.log 2>&1 &)'
}

# SIGKILL bird (ungraceful). The slim image has no pkill/pidof; find the
# pid via /proc comm names.
kill_bird() {
    docker exec "${1:?}" sh -c \
        'for p in /proc/[0-9]*; do
             [ "$(cat "$p/comm" 2>/dev/null)" = "bird" ] && kill -9 "${p#/proc/}"
         done; true' 2>/dev/null || true
}

wait_bird_established() {
    local container=${1:?} label=${2:?}
    log "Waiting for $label BGP session to reach Established..."
    for i in $(seq 1 45); do
        if docker exec "$container" birdc show protocols reflector 2>/dev/null \
            | grep -q "Established"; then
            ok "$label session Established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label session did not reach Established within 90s"
    docker exec "$container" birdc show protocols all reflector 2>/dev/null | tail -20 || true
    return 1
}

# BIRD's full view of one route (all attributes).
birdc_route_all() {
    docker exec "${1:?}" birdc show route all for "${2:?}" 2>/dev/null
}

grpc_get_metrics() {
    grpcurl_call \
        "$GRPC_ADDR" rustbgpd.v1.ControlService/GetMetrics 2>/dev/null
}

# Sum of bgp_gr_stale_routes across peers on the RR.
rr_stale_count() {
    local total=0
    while IFS= read -r val; do
        total=$((total + ${val%.*}))
    done < <(grpc_get_metrics | grep -oP 'bgp_gr_stale_routes\{[^}]*\}\s+\K[0-9.]+' || true)
    echo "$total"
}

# Poll until a command succeeds; usage: poll <tries> <sleep> <label> cmd...
poll() {
    local tries=${1:?} pause=${2:?} label=${3:?}
    shift 3
    for i in $(seq 1 "$tries"); do
        if "$@" >/dev/null 2>&1; then
            ok "$label (attempt $i)"
            return 0
        fi
        sleep "$pause"
    done
    fail "$label — timed out after $((tries * pause))s"
    return 1
}

# True if BIRD has a BGP-sourced path for the prefix.
bird_has_bgp_route() {
    birdc_route_all "${1:?}" "${2:?}" | grep -q "BGP.as_path"
}

bird_lacks_bgp_route() { ! bird_has_bgp_route "$1" "$2"; }

# True if the rustbgpd client's session to the RR is Established.
client_established() {
    client_ctl neighbor -j 2>/dev/null \
        | jq -e '[.[] | select(.state == "Established")] | length >= 1'
}

# True if the rustbgpd client's Loc-RIB has the prefix.
client_has_route() {
    client_ctl rib -j 2>/dev/null | jq -e --arg p "${1:?}" \
        '[.[] | select(.prefix == $p)] | length > 0'
}

client_lacks_route() { ! client_has_route "$1"; }

# ---------------------------------------------------------------------------
# Test 1: sessions + capability exchange
# ---------------------------------------------------------------------------
test_sessions() {
    log "Test 1: three RR-client sessions Established, GR capability on the wire"

    wait_bird_established "$BIRD1" "bird1" || return 1
    wait_bird_established "$BIRD2" "bird2" || return 1

    poll 30 2 "rustbgpd client session Established" client_established

    # BIRD reports the peer's (rustbgpd's) capabilities; graceful_restart =
    # true on both BIRD neighbors, so BIRD must see restart-capable.
    local caps
    caps=$(docker exec "$BIRD1" birdc show protocols all reflector 2>/dev/null)
    if echo "$caps" | grep -qi "restart"; then
        ok "bird1 sees a graceful-restart capability from rustbgpd"
    else
        fail "bird1 does not report a graceful-restart capability from rustbgpd"
        echo "$caps" | tail -25 >&2 || true
    fi
}

# ---------------------------------------------------------------------------
# Test 2: v4 + v6 reflection between all clients
# ---------------------------------------------------------------------------
test_reflection() {
    log "Test 2: v4+v6 reflection bird1 ↔ bird2 and toward the rustbgpd client"

    poll 15 2 "bird2 has $B1_V4 (v4 reflected)"  bird_has_bgp_route "$BIRD2" "$B1_V4"
    poll 15 2 "bird2 has $B1_V6 (v6 reflected)"  bird_has_bgp_route "$BIRD2" "$B1_V6"
    poll 15 2 "bird1 has $B2_V4 (v4 reflected)"  bird_has_bgp_route "$BIRD1" "$B2_V4"
    poll 15 2 "bird1 has $B2_V6 (v6 reflected)"  bird_has_bgp_route "$BIRD1" "$B2_V6"

    for p in "$B1_V4" "$B1_V6" "$B2_V4" "$B2_V6"; do
        poll 15 2 "rustbgpd client has $p" client_has_route "$p"
    done
}

# ---------------------------------------------------------------------------
# Test 3: ORIGINATOR_ID + CLUSTER_LIST in BIRD's view
# ---------------------------------------------------------------------------
test_originator_cluster() {
    log "Test 3: ORIGINATOR_ID / CLUSTER_LIST on reflected routes (BIRD view)"

    local view
    view=$(birdc_route_all "$BIRD2" "$B1_V4")

    if echo "$view" | grep -q "BGP.originator_id: 10.85.1.2"; then
        ok "bird2 sees ORIGINATOR_ID 10.85.1.2 on $B1_V4"
    else
        fail "bird2 missing ORIGINATOR_ID 10.85.1.2 on $B1_V4"
        echo "$view" >&2 || true
    fi

    if echo "$view" | grep -q "BGP.cluster_list: 10.85.0.1"; then
        ok "bird2 sees CLUSTER_LIST 10.85.0.1 on $B1_V4"
    else
        fail "bird2 missing CLUSTER_LIST 10.85.0.1 on $B1_V4"
        echo "$view" >&2 || true
    fi

    # Same on the v6 route in the other direction.
    view=$(birdc_route_all "$BIRD1" "$B2_V6")
    if echo "$view" | grep -q "BGP.originator_id: 10.85.2.2" \
        && echo "$view" | grep -q "BGP.cluster_list: 10.85.0.1"; then
        ok "bird1 sees ORIGINATOR_ID 10.85.2.2 + CLUSTER_LIST on $B2_V6"
    else
        fail "bird1 missing ORIGINATOR_ID/CLUSTER_LIST on $B2_V6"
        echo "$view" >&2 || true
    fi
}

# ---------------------------------------------------------------------------
# Test 4: no reflect-back to the originator
# ---------------------------------------------------------------------------
test_no_reflect_back() {
    log "Test 4: RR does not reflect a client's route back to it"

    local adv
    adv=$(rr_ctl rib advertised "$BIRD1_ADDR" -j 2>/dev/null)
    if echo "$adv" | jq -e --arg p "$B1_V4" '[.[] | select(.prefix == $p)] | length == 0' >/dev/null; then
        ok "rbgp rib advertised to bird1 excludes bird1's own $B1_V4"
    else
        fail "RR advertises bird1's own $B1_V4 back to it"
    fi
    if echo "$adv" | jq -e --arg p "$B2_V4" '[.[] | select(.prefix == $p)] | length == 1' >/dev/null; then
        ok "rbgp rib advertised to bird1 includes bird2's $B2_V4"
    else
        fail "RR does not advertise bird2's $B2_V4 to bird1"
    fi

    if bird_lacks_bgp_route "$BIRD1" "$B1_V4"; then
        ok "bird1 has no BGP path for its own $B1_V4 (static only)"
    else
        fail "bird1 received its own $B1_V4 back from the RR"
    fi
}

stale_at_least() { [ "$(rr_stale_count)" -ge "${1:?}" ]; }
stale_is_zero()  { [ "$(rr_stale_count)" -eq 0 ]; }

# ---------------------------------------------------------------------------
# Test 5: GR helper — bird1 (graceful restart on)
# ---------------------------------------------------------------------------
test_gr_bird1() {
    log "Test 5: kill bird1 (GR on) — stale preservation, no withdraws"

    kill_bird "$BIRD1"

    poll 15 2 "RR stale-preserves bird1's routes (bgp_gr_stale_routes >= 2)" \
        stale_at_least 2

    # rbgp view: bird1's routes are retained in the RR's Loc-RIB through
    # the window (staleness itself is pinned by the metric above — the
    # unicast gRPC route surface does not expose the stale flag).
    if rr_ctl rib -j 2>/dev/null | jq -e --arg peer "$BIRD1_ADDR" \
        '[.[] | select(.peer_address == $peer)] | length >= 2' >/dev/null; then
        ok "rbgp rib keeps bird1's v4+v6 routes in the Loc-RIB through the GR window"
    else
        fail "bird1's routes missing from the RR Loc-RIB during the GR window"
        rr_ctl rib -j 2>/dev/null | head -30 >&2 || true
    fi

    # No withdraws toward the surviving clients during the GR window.
    if bird_has_bgp_route "$BIRD2" "$B1_V4" && bird_has_bgp_route "$BIRD2" "$B1_V6"; then
        ok "bird2 still holds bird1's v4+v6 routes through the GR window"
    else
        fail "bird1's routes were withdrawn from bird2 during the GR window"
    fi
    if client_has_route "$B1_V4"; then
        ok "rustbgpd client still holds $B1_V4 through the GR window"
    else
        fail "$B1_V4 withdrawn from the rustbgpd client during the GR window"
    fi

    # Restart bird1 — re-establish, re-advertise, stale clears.
    start_bird "$BIRD1"
    wait_bird_established "$BIRD1" "bird1 (restarted)" || return 1
    poll 20 2 "stale routes cleared after re-establish + EoR" stale_is_zero

    if bird_has_bgp_route "$BIRD2" "$B1_V4"; then
        ok "bird2 converged back on $B1_V4 after bird1's restart"
    else
        fail "bird2 lost $B1_V4 after bird1's restart"
    fi
}

# ---------------------------------------------------------------------------
# Test 6: GR truth — bird2 (default aware: capability with no AFs)
# ---------------------------------------------------------------------------
test_gr_bird2_aware() {
    log "Test 6: kill bird2 (GR aware, no AFs advertised) — NO preservation"

    kill_bird "$BIRD2"

    # The RR must withdraw bird2's routes: aware-mode BIRD advertised no
    # AF as preserved, so there is nothing to stale-keep.
    poll 20 2 "bird1 loses $B2_V4 (withdraw propagated)" \
        bird_lacks_bgp_route "$BIRD1" "$B2_V4"
    poll 10 2 "bird1 loses $B2_V6 (withdraw propagated)" \
        bird_lacks_bgp_route "$BIRD1" "$B2_V6"
    poll 10 2 "rustbgpd client loses $B2_V4" client_lacks_route "$B2_V4"

    if stale_is_zero; then
        ok "no stale routes on the RR (aware-mode peer not GR-preserved)"
    else
        fail "RR stale-preserved an aware-mode (no-AF) GR peer: $(rr_stale_count) stale"
    fi

    # Recovery: bird2 comes back, everything re-converges.
    start_bird "$BIRD2"
    wait_bird_established "$BIRD2" "bird2 (restarted)" || return 1
    poll 15 2 "bird1 re-learns $B2_V4" bird_has_bgp_route "$BIRD1" "$B2_V4"
    poll 15 2 "rustbgpd client re-learns $B2_V6" client_has_route "$B2_V6"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M85 interop test: rustbgpd RR + BIRD 2 clients (RFC 4456 + RFC 4724)"
    log "Topology: $TOPO"

    resolve_grpc_addr
    # shellcheck disable=SC2119
    start_rustbgpd

    log "Starting rustbgpd client..."
    docker exec -d "$CLIENT" /usr/local/bin/start-rustbgpd.sh

    log "Starting BIRD clients..."
    start_bird "$BIRD1"
    start_bird "$BIRD2"

    test_sessions
    test_reflection
    test_originator_cluster
    test_no_reflect_back
    test_gr_bird1
    test_gr_bird2_aware

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
