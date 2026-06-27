#!/usr/bin/env bash
# M35 interop test — RFC 8326 BGP Graceful Shutdown (both legs).
#
# Receiver leg (rustbgpd inbound honor):
#   FRR tags 192.168.1.0/24 with GRACEFUL_SHUTDOWN (65535:0) via an
#   outbound route-map. rustbgpd's [global] honor_graceful_shutdown
#   = true appends an implicit chain-tail rule that sets
#   local_pref = 0 on tagged routes. Assertion: 192.168.1.0/24 lands
#   in rustbgpd's RIB with local_pref = 0; 192.168.2.0/24 (untagged)
#   keeps the default 100.
#
# Initiator leg (rustbgpd outbound advertise):
#   The test injects 172.16.0.0/24 via InjectionService.AddPath, then
#   toggles GRACEFUL_SHUTDOWN community attachment on the FRR session
#   via NeighborService.SetGracefulShutdown. After a brief settle,
#   FRR's `show ip bgp 172.16.0.0/24 json` must list the 65535:0
#   community. Then we toggle clear and assert the community is gone.
#
# Prerequisites:
#   - containerlab deploy -t tests/interop/m35-graceful-shutdown-frr.clab.yml
#   - grpcurl + jq installed on the host

set -euo pipefail

TOPO="m35-graceful-shutdown-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"
FRR="clab-${TOPO}-frr"

preflight
resolve_grpc_addr
start_rustbgpd

# ---------------------------------------------------------------------------
# 1. Session establishment
# ---------------------------------------------------------------------------

wait_frr_established "$FRR" "10.0.0.1" "rustbgpd ↔ FRR"

GSHUT_VALUE=$(( (65535 << 16) | 0 ))    # 4294901760 = 0xFFFF_0000

grpc_list_received() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

route_communities() {
    # Returns space-separated communities (numeric u32) for the given
    # prefix in rustbgpd's RIB, or "MISSING" if the prefix isn't
    # present at all.
    local prefix=$1
    local payload
    payload=$(grpc_list_received)
    local exists
    exists=$(echo "$payload" | jq -r --arg p "$prefix" \
        '[.routes[]? | select("\(.prefix)/\(.prefixLength)" == $p)] | length')
    if [ "$exists" = "0" ] || [ -z "$exists" ]; then
        echo "MISSING"
        return
    fi
    echo "$payload" | jq -r --arg p "$prefix" \
        '[.routes[]? | select("\(.prefix)/\(.prefixLength)" == $p) | .communities[]?] | join(" ")'
}

# Returns the explicit local_pref_attr value if a LOCAL_PREF attribute
# is present, or 'absent' if the route has no LOCAL_PREF on the wire
# (the proto field is `optional uint32 local_pref_attr = 16` so it is
# omitted from JSON when None — distinguishes "policy set it to 0"
# from "no attribute").
route_local_pref_attr() {
    local prefix=$1
    grpc_list_received \
        | jq -r --arg p "$prefix" \
            '[.routes[]? | select("\(.prefix)/\(.prefixLength)" == $p) | .localPrefAttr] | first // "absent"'
}

dump_state_on_failure() {
    echo "===== rustbgpd ListReceivedRoutes (raw) =====" >&2
    grpc_list_received | jq . >&2 || true
    echo "===== rustbgpd NeighborState 10.0.0.2 =====" >&2
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d '{"address":"10.0.0.2"}' \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState 2>&1 \
        | head -60 >&2 || true
    echo "===== FRR vtysh: BGP summary =====" >&2
    docker exec "$FRR" vtysh -c 'show ip bgp summary' >&2 || true
    echo "===== FRR vtysh: advertised-routes to 10.0.0.1 =====" >&2
    docker exec "$FRR" vtysh -c 'show ip bgp neighbor 10.0.0.1 advertised-routes' >&2 || true
    echo "===== FRR vtysh: route-map TO-RUSTBGPD =====" >&2
    docker exec "$FRR" vtysh -c 'show route-map TO-RUSTBGPD' >&2 || true
}

wait_route_present() {
    local prefix=$1
    log "Waiting for $prefix in rustbgpd's RIB (any communities)..."
    for i in $(seq 1 30); do
        local comms
        comms=$(route_communities "$prefix")
        if [ "$comms" != "MISSING" ]; then
            ok "$prefix present after ${i}s (communities: ${comms:-<none>})"
            return 0
        fi
        sleep 1
    done
    fail "$prefix never appeared in rustbgpd's RIB within 30s"
    dump_state_on_failure
    return 1
}

# ---------------------------------------------------------------------------
# 2. Receiver leg — community presence is the unambiguous signal
# ---------------------------------------------------------------------------
# 192.168.1.0/24 is GShut-tagged via FRR's outbound route-map. After
# rustbgpd accepts it, the route's Communities attribute must include
# 0xFFFF_0000 (the implicit chain-tail rule SETs local_pref=0
# but the policy modification is observable indirectly: the only
# unambiguous signal at the wire/proto level is community presence,
# since proto3 omits zero-valued local_pref the same way regardless of
# whether policy explicitly set it to 0 or no LOCAL_PREF was attached).
# Implicit-rule-fired claims at the data-structure level are covered
# by the unit tests in src/config/tests.rs; the interop test here pins
# wire compatibility — FRR can tag, rustbgpd accepts, the community
# survives import.
#
# 192.168.2.0/24 is untagged on FRR's egress route-map; assert the
# community is NOT present.

wait_route_present "192.168.1.0/24"
wait_route_present "192.168.2.0/24"

tagged_comms=$(route_communities "192.168.1.0/24")
log "192.168.1.0/24 communities: $tagged_comms"
if echo " $tagged_comms " | grep -qE " ${GSHUT_VALUE}( |$)"; then
    ok "192.168.1.0/24 carries GRACEFUL_SHUTDOWN community — receiver leg wire interop OK"
else
    fail "192.168.1.0/24 missing GRACEFUL_SHUTDOWN community (got: $tagged_comms); \
         either FRR's outbound route-map didn't tag, or rustbgpd's import dropped the community"
    dump_state_on_failure
    exit 1
fi

untagged_comms=$(route_communities "192.168.2.0/24")
log "192.168.2.0/24 communities: $untagged_comms"
if echo " $untagged_comms " | grep -qE " ${GSHUT_VALUE}( |$)"; then
    fail "192.168.2.0/24 should NOT carry GRACEFUL_SHUTDOWN (got: $untagged_comms); \
         FRR's outbound route-map permit 10 may be matching too broadly"
    dump_state_on_failure
    exit 1
else
    ok "192.168.2.0/24 does not carry GRACEFUL_SHUTDOWN community (correct)"
fi

# Verify the implicit RFC 8326 §4 demotion actually fired:
#   * GShut-tagged 192.168.1.0/24 must have an explicit LOCAL_PREF=0
#     attribute (proto3 `optional uint32` surfaces as the value when
#     present, omitted when absent).
#   * Untagged 192.168.2.0/24 must have NO LOCAL_PREF attribute
#     (FRR doesn't send LOCAL_PREF over EBGP and no policy modified
#     the route on import).
tagged_lp_attr=$(route_local_pref_attr "192.168.1.0/24")
log "192.168.1.0/24 local_pref_attr: $tagged_lp_attr"
if [ "$tagged_lp_attr" = "0" ]; then
    ok "192.168.1.0/24 has explicit local_pref_attr=0 — RFC 8326 implicit demotion fired"
else
    fail "192.168.1.0/24 should have explicit local_pref_attr=0 (RFC 8326 receiver), \
         got: $tagged_lp_attr"
    dump_state_on_failure
    exit 1
fi

untagged_lp_attr=$(route_local_pref_attr "192.168.2.0/24")
log "192.168.2.0/24 local_pref_attr: $untagged_lp_attr"
if [ "$untagged_lp_attr" = "absent" ]; then
    ok "192.168.2.0/24 has no LOCAL_PREF attribute (correct — EBGP, no policy match)"
else
    fail "192.168.2.0/24 should have no LOCAL_PREF (untagged EBGP, no policy match); \
         got explicit local_pref_attr=$untagged_lp_attr"
    dump_state_on_failure
    exit 1
fi

# ---------------------------------------------------------------------------
# 3. Initiator leg — INJECT FIRST so the route is steady-state in
#    AdjRibOut, THEN toggle and verify the community appears on the
#    wire WITHOUT a delete+re-add. This is the actual maintenance-
#    window behaviour: an operator running `rbgp gshut` against
#    a peer with active routes expects them to re-emit with the
#    community attached. It exercises the runtime force-emit path
#    (RibUpdate::RefreshPeerOutbound bypassing AdjRibOut equality
#    suppression) end-to-end.
# ---------------------------------------------------------------------------

frr_route_json() {
    docker exec "$FRR" vtysh -c 'show ip bgp 172.16.0.0/24 json' 2>/dev/null
}

# FRR's `show ip bgp X/Y json` renders the community two ways:
#
#   "community": {
#     "string": "graceful-shutdown",     <- hyphenated well-known name
#     "list":   ["gracefulShutdown"]      <- camelCase well-known name
#   }
#
# Numeric form (65535:0) appears in `.string` only when FRR doesn't
# recognize the well-known name. Check both forms defensively, and
# coalesce missing fields to safe defaults so jq -e doesn't false-
# negative when `.community` is absent entirely.
frr_has_gshut_community() {
    frr_route_json | jq -e '
        ((.paths // []) | first) as $p
        | ($p.community // {}) as $c
        | ((($c.list // []) | any(
              . == "gracefulShutdown"
              or . == "graceful-shutdown"
              or . == "65535:0"
           ))
           or (($c.string // "") | test("graceful-shutdown|65535:0")))
    ' > /dev/null 2>&1
}

frr_has_route() {
    frr_route_json | jq -e '(.paths // []) | length > 0' > /dev/null 2>&1
}

log "Injecting 172.16.0.0/24 via InjectionService.AddPath (steady state)..."
grpcurl -plaintext -import-path . -proto "$PROTO" \
    -d '{"prefix":"172.16.0.0","prefixLength":24,"nextHop":"10.0.0.1","origin":2,"asPath":[]}' \
    "$GRPC_ADDR" rustbgpd.v1.InjectionService/AddPath > /dev/null

log "Verifying initial advertise is UNTAGGED at FRR (toggle is still off)..."
for i in $(seq 1 30); do
    if frr_has_route && ! frr_has_gshut_community; then
        ok "FRR has 172.16.0.0/24 without graceful-shutdown community after ${i}s (steady state)"
        break
    fi
    if [ "$i" = "30" ]; then
        echo "===== FRR vtysh: show ip bgp 172.16.0.0/24 (text) =====" >&2
        docker exec "$FRR" vtysh -c 'show ip bgp 172.16.0.0/24' >&2 || true
        fail "FRR never received untagged 172.16.0.0/24 (or unexpectedly carries GShut)"
        dump_state_on_failure
        exit 1
    fi
    sleep 1
done

log "Toggling GRACEFUL_SHUTDOWN advertise ON for 10.0.0.2 via gRPC..."
log "(no delete + re-add — this exercises RibUpdate::RefreshPeerOutbound force-emit)"
grpcurl -plaintext -import-path . -proto "$PROTO" \
    -d '{"address":"10.0.0.2","enabled":true}' \
    "$GRPC_ADDR" rustbgpd.v1.NeighborService/SetGracefulShutdown > /dev/null

log "Waiting for FRR to see graceful-shutdown community on 172.16.0.0/24..."
for i in $(seq 1 30); do
    if frr_has_gshut_community; then
        ok "FRR sees graceful-shutdown after ${i}s — runtime force-emit works without delete+re-add"
        break
    fi
    if [ "$i" = "30" ]; then
        echo "===== FRR vtysh: show ip bgp 172.16.0.0/24 (text) =====" >&2
        docker exec "$FRR" vtysh -c 'show ip bgp 172.16.0.0/24' >&2 || true
        echo "===== FRR vtysh: show ip bgp 172.16.0.0/24 (json) =====" >&2
        frr_route_json >&2 || true
        fail "FRR never saw graceful-shutdown community on toggle-on within 30s — \
             RefreshPeerOutbound force-emit may not be bypassing AdjRibOut equality suppression"
        dump_state_on_failure
        exit 1
    fi
    sleep 1
done

# ---------------------------------------------------------------------------
# 4. Clear leg — toggle OFF, no delete+re-add, verify community gone.
#    Same force-emit path as the toggle-on side; the bool flip should
#    be observable on the wire without a route churn.
# ---------------------------------------------------------------------------

log "Toggling GRACEFUL_SHUTDOWN advertise OFF for 10.0.0.2 via gRPC..."
grpcurl -plaintext -import-path . -proto "$PROTO" \
    -d '{"address":"10.0.0.2","enabled":false}' \
    "$GRPC_ADDR" rustbgpd.v1.NeighborService/SetGracefulShutdown > /dev/null

log "Waiting for FRR to see 172.16.0.0/24 WITHOUT graceful-shutdown..."
for i in $(seq 1 30); do
    if frr_has_route && ! frr_has_gshut_community; then
        ok "FRR no longer sees graceful-shutdown after ${i}s — clear via runtime force-emit OK"
        break
    fi
    if [ "$i" = "30" ]; then
        echo "===== FRR vtysh: show ip bgp 172.16.0.0/24 (text) =====" >&2
        docker exec "$FRR" vtysh -c 'show ip bgp 172.16.0.0/24' >&2 || true
        echo "===== FRR vtysh: show ip bgp 172.16.0.0/24 (json) =====" >&2
        frr_route_json >&2 || true
        fail "graceful-shutdown community stuck on 172.16.0.0/24 after clear toggle"
        dump_state_on_failure
        exit 1
    fi
    sleep 1
done

print_summary
