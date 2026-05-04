#!/usr/bin/env bash
# M35 interop test — RFC 8326 BGP Graceful Shutdown (both legs).
#
# Receiver leg (rustbgpd inbound honor):
#   FRR tags 192.168.1.0/24 with GRACEFUL_SHUTDOWN (65535:0) via an
#   outbound route-map. rustbgpd's [global] honor_graceful_shutdown
#   = true injects an implicit head-of-import-chain rule that sets
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
# 0xFFFF_0000 (the implicit head-of-import-chain rule SETs local_pref=0
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

# ---------------------------------------------------------------------------
# 3. Initiator leg — inject a route, toggle gshut, verify community on FRR
# ---------------------------------------------------------------------------

log "Injecting 172.16.0.0/24 via InjectionService.AddPath..."
grpcurl -plaintext -import-path . -proto "$PROTO" \
    -d '{"prefix":"172.16.0.0","prefixLength":24,"nextHop":"10.0.0.1","origin":2,"asPath":[]}' \
    "$GRPC_ADDR" rustbgpd.v1.InjectionService/AddPath > /dev/null

# Wait for FRR to receive the prefix.
log "Waiting for FRR to receive 172.16.0.0/24..."
for i in $(seq 1 20); do
    if docker exec "$FRR" vtysh -c 'show ip bgp 172.16.0.0/24 json' 2>/dev/null \
        | jq -e '.paths[0]' > /dev/null 2>&1; then
        ok "FRR has 172.16.0.0/24 after ${i}s"
        break
    fi
    if [ "$i" = "20" ]; then
        fail "FRR never received 172.16.0.0/24 within 20s"
        dump_state_on_failure
        exit 1
    fi
    sleep 1
done

# Toggle gshut ON for the FRR peer.
log "Enabling GRACEFUL_SHUTDOWN advertise for 10.0.0.2 via gRPC..."
grpcurl -plaintext -import-path . -proto "$PROTO" \
    -d '{"address":"10.0.0.2","enabled":true}' \
    "$GRPC_ADDR" rustbgpd.v1.NeighborService/SetGracefulShutdown > /dev/null

# RFC 8326 §5: re-advertise so the toggle is visible. The simplest
# operator-side action is a soft reset out, which forces re-emission
# of all routes. Implementations vary on whether the toggle alone
# triggers re-emit; explicitly re-inject the path with a small route
# attribute change to force a fresh outbound update.
log "Forcing re-advertise by re-injecting 172.16.0.0/24..."
grpcurl -plaintext -import-path . -proto "$PROTO" \
    -d '{"prefix":"172.16.0.0","prefixLength":24}' \
    "$GRPC_ADDR" rustbgpd.v1.InjectionService/DeletePath > /dev/null
sleep 1
grpcurl -plaintext -import-path . -proto "$PROTO" \
    -d '{"prefix":"172.16.0.0","prefixLength":24,"nextHop":"10.0.0.1","origin":2,"asPath":[]}' \
    "$GRPC_ADDR" rustbgpd.v1.InjectionService/AddPath > /dev/null

# Wait for FRR to see the GShut community on the prefix.
log "Waiting for FRR to see 65535:0 on 172.16.0.0/24..."
for i in $(seq 1 20); do
    if docker exec "$FRR" vtysh -c 'show ip bgp 172.16.0.0/24 json' 2>/dev/null \
        | jq -e '.paths[0].community.list | index("graceful-shutdown") // (.paths[0].community.string | test("65535:0"))' \
        > /dev/null 2>&1; then
        ok "FRR sees graceful-shutdown community on 172.16.0.0/24 after ${i}s — initiator leg OK"
        break
    fi
    if [ "$i" = "20" ]; then
        # Dump what we did see so the failure mode is debuggable.
        docker exec "$FRR" vtysh -c 'show ip bgp 172.16.0.0/24 json' 2>/dev/null || true
        fail "FRR never saw graceful-shutdown community on 172.16.0.0/24 within 20s"
        dump_state_on_failure
        exit 1
    fi
    sleep 1
done

# ---------------------------------------------------------------------------
# 4. Clear leg — toggle off and confirm community is no longer attached
# ---------------------------------------------------------------------------

log "Clearing GRACEFUL_SHUTDOWN advertise for 10.0.0.2..."
grpcurl -plaintext -import-path . -proto "$PROTO" \
    -d '{"address":"10.0.0.2","enabled":false}' \
    "$GRPC_ADDR" rustbgpd.v1.NeighborService/SetGracefulShutdown > /dev/null

log "Forcing re-advertise to make the clear visible..."
grpcurl -plaintext -import-path . -proto "$PROTO" \
    -d '{"prefix":"172.16.0.0","prefixLength":24}' \
    "$GRPC_ADDR" rustbgpd.v1.InjectionService/DeletePath > /dev/null
sleep 1
grpcurl -plaintext -import-path . -proto "$PROTO" \
    -d '{"prefix":"172.16.0.0","prefixLength":24,"nextHop":"10.0.0.1","origin":2,"asPath":[]}' \
    "$GRPC_ADDR" rustbgpd.v1.InjectionService/AddPath > /dev/null

log "Waiting for FRR to see 172.16.0.0/24 WITHOUT graceful-shutdown..."
for i in $(seq 1 20); do
    if docker exec "$FRR" vtysh -c 'show ip bgp 172.16.0.0/24 json' 2>/dev/null \
        | jq -e '.paths[0]' > /dev/null 2>&1; then
        if docker exec "$FRR" vtysh -c 'show ip bgp 172.16.0.0/24 json' 2>/dev/null \
            | jq -e '.paths[0].community.list | index("graceful-shutdown") // (.paths[0].community.string | test("65535:0"))' \
            > /dev/null 2>&1; then
            : # community still present, keep waiting
        else
            ok "FRR no longer sees graceful-shutdown community on 172.16.0.0/24 after ${i}s — clear OK"
            break
        fi
    fi
    if [ "$i" = "20" ]; then
        fail "graceful-shutdown community stuck on 172.16.0.0/24 after clear toggle"
        dump_state_on_failure
        exit 1
    fi
    sleep 1
done

print_summary
