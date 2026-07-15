#!/usr/bin/env bash
# M87 interop test — exact-export rejection against GoBGP 4.6 + BIRD 2.0.12.
#
# The source first advertises a small route that reaches BIRD, then implicitly
# replaces it with an RFC-legal 4,095-byte UPDATE containing only ORIGIN,
# one-AS AS_PATH, NEXT_HOP, and exactly 337 Large Communities.  That bare
# source-attribute shape is part of the boundary calculation and is asserted
# in rustbgpd's Loc-RIB before the sink verdict.  The BIRD-only export policy
# adds one more Large Community, so
# rustbgpd's exact encoder sees a 4,107-byte post-policy candidate for a peer
# whose negotiated maximum is 4,096 bytes.
#
# Load-bearing regression proofs (run manually before merge):
#   1. Delete only the `owed_withdrawals.insert(key.clone())` in
#      reconcile_exact_export_overlay.  Rejection evidence still fires, but
#      "BIRD withdrew the previously advertised route" MUST turn red because
#      the independent receiver retains the stale baseline route.
#   2. Disable the `probe.encoded_len > probe.max_len` exact-export guard.
#      "message_too_long advanced exactly once" MUST turn red (and any wire
#      oversize/session failure is also a valid red signal).
#   3. Accidentally negotiate Extended Messages or reduce the source below 337
#      Large Communities and the exact-rejection metric assertion turns red.
#
# No production-only hook is used: GoBGP creates the wire stimulus, BIRD is the
# independent receiver, and rustbgpd is the normal daemon/encoder image.

TOPO="m87-exact-export-rejection"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/test-lib.sh"

GOBGP_SOURCE="clab-${TOPO}-gobgp-source"
BIRD_SINK="clab-${TOPO}-bird-sink"
SOURCE_ADDR="10.87.1.2"
RS_SOURCE_ADDR="10.87.1.1"
SINK_ADDR="10.87.2.2"
PREFIX="203.0.113.0/24"
SOURCE_LC_COUNT=337

rbgp() {
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 "$@"
}

gobgp() {
    docker exec "$GOBGP_SOURCE" gobgp "$@" 2>/dev/null
}

start_gobgpd() {
    log "Starting GoBGP 4.6 source..."
    docker exec -d "$GOBGP_SOURCE" sh -c \
        'nohup gobgpd -f /config/gobgp.toml >/tmp/gobgpd.log 2>&1'
}

start_bird() {
    log "Starting BIRD 2.0.12 sink..."
    docker exec -d "$BIRD_SINK" sh -c \
        'bird -d -c /etc/bird/bird.conf >/tmp/bird.log 2>&1'
}

wait_gobgp_established() {
    for _ in $(seq 1 45); do
        if gobgp neighbor "$RS_SOURCE_ADDR" | grep -qi "establ"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

bird_protocol() {
    docker exec "$BIRD_SINK" birdc show protocols all routeserver 2>/dev/null
}

wait_bird_established() {
    for _ in $(seq 1 45); do
        if bird_protocol | grep -q "Established"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

neighbor_state() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"address\": \"${1:?}\"}" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState 2>/dev/null
}

neighbor_established() {
    neighbor_state "${1:?}" | jq -e '.state == "SESSION_STATE_ESTABLISHED"' >/dev/null
}

wait_rustbgpd_established() {
    local peer=${1:?}
    for _ in $(seq 1 45); do
        if neighbor_established "$peer"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

bird_route() {
    docker exec "$BIRD_SINK" birdc show route all for "$PREFIX" 2>/dev/null
}

bird_has_route() {
    bird_route | grep -q "BGP.as_path"
}

bird_lacks_route() {
    ! bird_has_route
}

wait_condition() {
    local attempts=${1:?} pause=${2:?}
    shift 2
    for _ in $(seq 1 "$attempts"); do
        if "$@"; then
            return 0
        fi
        sleep "$pause"
    done
    return 1
}

rr_routes() {
    rbgp rib --prefix "$PREFIX" -j 2>/dev/null
}

rr_has_exact_source_shape() {
    rr_routes | jq -e --arg prefix "$PREFIX" --arg peer "$SOURCE_ADDR" \
        --argjson count "$SOURCE_LC_COUNT" '
        [.[] | select(
            .prefix == $prefix
            and .peer_address == $peer
            and .origin == "igp"
            and .as_path == [65002]
            and .next_hop == $peer
            and (.communities | length) == 0
            and (.large_communities | length) == $count
        )] | length == 1
    ' >/dev/null
}

rr_lacks_prefix() {
    rr_routes | jq -e --arg prefix "$PREFIX" \
        '[.[] | select(.prefix == $prefix)] | length == 0' >/dev/null
}

advertised_routes() {
    rbgp rib advertised "$SINK_ADDR" -j 2>/dev/null
}

adj_has_prefix() {
    advertised_routes | jq -e --arg prefix "$PREFIX" \
        '[.[] | select(.prefix == $prefix)] | length == 1' >/dev/null
}

adj_lacks_prefix() {
    advertised_routes | jq -e --arg prefix "$PREFIX" \
        '[.[] | select(.prefix == $prefix)] | length == 0' >/dev/null
}

export_explain() {
    rbgp rib --prefix "$PREFIX" advertised "$SINK_ADDR" --explain -j 2>/dev/null
}

explain_rejected_exactly() {
    export_explain | jq -e '
        .decision == "deny"
        and ([.reasons[].code] | index("exact_export_rejected") != null)
        and ([.gates[] | select(
            .gate == "exact_export"
            and .code == "exact_export_rejected"
            and .verdict == "stop"
        )] | length == 1)
    ' >/dev/null
}

explain_advertises() {
    export_explain | jq -e '
        .decision == "advertise"
        and ([.reasons[].code] | index("exact_export_rejected") == null)
    ' >/dev/null
}

metrics_text() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.ControlService/GetMetrics 2>/dev/null \
        | jq -r '.prometheusText // ""'
}

exact_rejections() {
    local value
    value=$(metrics_text | awk '
        $1 == "bgp_exact_export_rejections_total{family=\"ipv4_unicast\",peer=\"10.87.2.2\",reason=\"message_too_long\"}" {
            print $2
        }
    ' | tail -1)
    printf '%s\n' "${value:-0}"
}

exact_rejections_are() {
    [ "$(exact_rejections)" = "${1:?}" ]
}

source_large_communities() {
    local result="" i
    for i in $(seq 1 "$SOURCE_LC_COUNT"); do
        result+="${result:+,}65002:87:${i}"
    done
    printf '%s\n' "$result"
}

inject_small_route() {
    gobgp global rib add -a ipv4 "$PREFIX" origin igp nexthop "$SOURCE_ADDR"
}

inject_boundary_route() {
    local communities
    communities=$(source_large_communities)
    gobgp global rib add -a ipv4 "$PREFIX" origin igp nexthop "$SOURCE_ADDR" \
        large-community "$communities"
}

withdraw_route() {
    gobgp global rib del -a ipv4 "$PREFIX"
}

assert_session_continuity() {
    local baseline_flaps=${1:?} baseline_uptime=${2:?} phase=${3:?}
    local state flaps uptime bird_state
    state=$(neighbor_state "$SINK_ADDR")
    flaps=$(echo "$state" | jq -r '.flapCount // 0 | tonumber')
    uptime=$(echo "$state" | jq -r '.uptimeSeconds // 0 | tonumber')
    bird_state=$(bird_protocol)

    if echo "$state" | jq -e '.state == "SESSION_STATE_ESTABLISHED"' >/dev/null \
        && [ "$flaps" -eq "$baseline_flaps" ] \
        && [ "$uptime" -ge "$baseline_uptime" ] \
        && echo "$bird_state" | grep -q "Established"; then
        ok "$phase: BIRD session stayed Established (flapCount=$flaps, uptime ${baseline_uptime}->${uptime})"
    else
        fail "$phase: BIRD session continuity failed (flapCount ${baseline_flaps}->${flaps}, uptime ${baseline_uptime}->${uptime})"
        echo "$state" | jq . >&2 || true
        echo "$bird_state" >&2 || true
    fi
}

preflight
resolve_grpc_addr
start_rustbgpd 'exec /usr/local/bin/rustbgpd /etc/rustbgpd/config.toml >/tmp/rustbgpd.log 2>&1'
start_gobgpd
start_bird

log "Waiting for all three independent-stack sessions..."
if wait_gobgp_established; then
    ok "GoBGP 4.6 source session Established"
else
    fail "GoBGP source session did not establish"
    docker exec "$GOBGP_SOURCE" cat /tmp/gobgpd.log >&2 2>/dev/null || true
    exit 1
fi
if wait_bird_established; then
    ok "BIRD 2.0.12 sink session Established"
else
    fail "BIRD sink session did not establish"
    docker exec "$BIRD_SINK" cat /tmp/bird.log >&2 2>/dev/null || true
    exit 1
fi
if wait_rustbgpd_established "$SOURCE_ADDR" && wait_rustbgpd_established "$SINK_ADDR"; then
    ok "rustbgpd reports both route-server members Established"
else
    fail "rustbgpd did not report both members Established"
    rbgp neighbor -j | jq . >&2 || true
    exit 1
fi

bird_local_capabilities=$(bird_protocol \
    | sed -n '/Local capabilities/,/Neighbor capabilities/p' \
    | sed '$d')
if echo "$bird_local_capabilities" | grep -q 'Multiprotocol' \
    && echo "$bird_local_capabilities" | grep -q '4-octet AS numbers' \
    && ! echo "$bird_local_capabilities" | grep -q 'Extended message'; then
    ok "BIRD local capabilities omit Extended Message as configured"
else
    fail "BIRD local-capability proof is missing sentinels or unexpectedly advertises Extended Message"
    echo "$bird_local_capabilities" >&2 || true
fi

log "Phase 1: establish the previously-advertised baseline"
if inject_small_route; then
    ok "GoBGP injected small baseline $PREFIX"
else
    fail "GoBGP baseline injection failed"
    exit 1
fi
if wait_condition 30 1 bird_has_route; then
    ok "BIRD received the baseline route"
else
    fail "BIRD never received the baseline route"
    bird_route >&2 || true
    exit 1
fi
if wait_condition 30 1 adj_has_prefix; then
    ok "rustbgpd Adj-RIB-Out records the baseline route toward BIRD"
else
    fail "baseline route missing from rustbgpd Adj-RIB-Out"
    advertised_routes | jq . >&2 || true
    exit 1
fi

metric_before=$(exact_rejections)
state_before=$(neighbor_state "$SINK_ADDR")
flaps_before=$(echo "$state_before" | jq -r '.flapCount // 0 | tonumber')
uptime_before=$(echo "$state_before" | jq -r '.uptimeSeconds // 0 | tonumber')
if [ "$uptime_before" -gt 0 ]; then
    ok "captured live BIRD-session baseline (metric=$metric_before, flapCount=$flaps_before, uptime=$uptime_before)"
else
    fail "BIRD session baseline has uptimeSeconds=0"
    exit 1
fi

log "Phase 2: replace with 337 Large Communities (4,095 bytes before sink policy)"
if inject_boundary_route; then
    ok "GoBGP injected the 337-Large-Community replacement"
else
    fail "GoBGP boundary-route injection failed"
    exit 1
fi

# Prove that the legal source stimulus reached the RR before interpreting any
# sink-side absence as an export-gate result.
if wait_condition 30 1 rr_has_exact_source_shape; then
    ok "rustbgpd Loc-RIB holds one bare source path with AS_PATH 65002 and exactly 337 Large Communities"
else
    fail "bare 337-Large-Community source shape never reached rustbgpd Loc-RIB"
    rr_routes | jq . >&2 || true
    exit 1
fi

metric_after=$((metric_before + 1))
if wait_condition 30 1 exact_rejections_are "$metric_after"; then
    ok "message_too_long advanced exactly once ($metric_before -> $metric_after)"
else
    fail "message_too_long did not advance exactly once (want $metric_after, got $(exact_rejections))"
fi
if docker exec "$RUSTBGPD" grep -qF \
    'encoded UPDATE is 4107 bytes; negotiated maximum is 4096 bytes' \
    /tmp/rustbgpd.log; then
    ok "exact encoder reports the expected 4,107-byte candidate / 4,096-byte ceiling"
else
    fail "exact encoder log does not pin 4,107 bytes against the 4,096-byte ceiling"
    docker exec "$RUSTBGPD" tail -60 /tmp/rustbgpd.log >&2 2>/dev/null || true
fi

if wait_condition 30 1 bird_lacks_route; then
    ok "BIRD withdrew the previously advertised route after exact rejection"
else
    fail "BIRD retained the stale baseline route after exact rejection"
    bird_route >&2 || true
fi
if wait_condition 30 1 adj_lacks_prefix; then
    ok "rustbgpd Adj-RIB-Out excludes the rejected replacement"
else
    fail "rustbgpd Adj-RIB-Out still lists the rejected replacement"
    advertised_routes | jq . >&2 || true
fi
if wait_condition 30 1 explain_rejected_exactly; then
    ok "export explain denies at exact_export_rejected"
else
    fail "export explain does not expose exact_export_rejected"
    export_explain | jq . >&2 || true
fi
assert_session_continuity "$flaps_before" "$uptime_before" "exact rejection"

log "Phase 3: replace with a small route and prove recovery without a flap"
if inject_small_route; then
    ok "GoBGP restored the small route"
else
    fail "GoBGP recovery injection failed"
    exit 1
fi
if wait_condition 30 1 bird_has_route; then
    ok "BIRD received the recovered route"
else
    fail "BIRD did not receive the recovered route"
    bird_route >&2 || true
fi
if wait_condition 30 1 adj_has_prefix; then
    ok "rustbgpd Adj-RIB-Out contains the recovered route"
else
    fail "recovered route missing from rustbgpd Adj-RIB-Out"
    advertised_routes | jq . >&2 || true
fi
if wait_condition 30 1 explain_advertises; then
    ok "export explain recovered to advertise"
else
    fail "export explain did not recover to advertise"
    export_explain | jq . >&2 || true
fi
if [ "$(exact_rejections)" = "$metric_after" ]; then
    ok "recovery did not add another exact-rejection event"
else
    fail "exact-rejection metric changed during recovery (want $metric_after, got $(exact_rejections))"
fi
assert_session_continuity "$flaps_before" "$uptime_before" "recovery"

log "Phase 4: withdraw the source route"
if withdraw_route; then
    ok "GoBGP withdrew $PREFIX"
else
    fail "GoBGP withdrawal failed"
fi
if wait_condition 30 1 bird_lacks_route && wait_condition 30 1 rr_lacks_prefix; then
    ok "source withdrawal left BIRD and rustbgpd clean"
else
    fail "source withdrawal did not converge cleanly"
    bird_route >&2 || true
    rr_routes | jq . >&2 || true
fi
assert_session_continuity "$flaps_before" "$uptime_before" "source withdrawal"

echo
# `pass` and `fail` are initialized by the sourced shared test library.
# shellcheck disable=SC2154
echo "M87 results: $pass passed, $fail failed"
if [ "$fail" -gt 0 ]; then
    exit 1
fi
