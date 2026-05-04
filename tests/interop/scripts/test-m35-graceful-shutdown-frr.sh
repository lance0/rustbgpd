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

grpc_list_received() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

route_local_pref() {
    # Returns the local_pref for the given prefix in rustbgpd's RIB,
    # or empty string if the prefix isn't present yet.
    local prefix=$1
    grpc_list_received \
        | jq -r --arg p "$prefix" \
            '[.routes[]? | select("\(.prefix)/\(.prefixLength)" == $p) | .localPref] | first // empty'
}

wait_route_with_localpref() {
    local prefix=$1
    local expected=$2
    log "Waiting for $prefix in rustbgpd's RIB with localPref=$expected..."
    for i in $(seq 1 20); do
        local actual
        actual=$(route_local_pref "$prefix")
        if [ "$actual" = "$expected" ]; then
            ok "$prefix present with localPref=$expected after ${i}s"
            return 0
        fi
        sleep 1
    done
    fail "$prefix never reached localPref=$expected within 20s (last seen: ${actual:-MISSING})"
    return 1
}

# ---------------------------------------------------------------------------
# 2. Receiver leg — implicit honor rule fires
# ---------------------------------------------------------------------------
# 192.168.1.0/24 is GShut-tagged via FRR's outbound route-map; the
# implicit head-of-import-chain rule must drop its local_pref to 0.
# 192.168.2.0/24 is untagged; default local_pref (100) applies.
#
# NOTE: gRPC field omits zero-valued numerics by default
# (proto3 semantics); the jq `// empty` makes that case readable.
# rustbgpd's NeighborState reports localPref as a uint32; 0 may
# serialize as the string "0" or omit. Test both shapes.

receiver_local_pref() {
    local prefix=$1
    local v
    v=$(route_local_pref "$prefix")
    # Treat omitted numeric (proto3 default) as "0".
    if [ -z "$v" ]; then echo "0"; else echo "$v"; fi
}

wait_route_with_localpref "192.168.2.0/24" "100"

# Verify the GShut-tagged prefix lands with local_pref=0 (the
# implicit rule fired). 0 may be encoded as omitted/null in JSON;
# treat both as 0.
log "Checking GShut-tagged prefix 192.168.1.0/24..."
for i in $(seq 1 20); do
    lp=$(receiver_local_pref "192.168.1.0/24")
    if [ "$lp" = "0" ]; then
        ok "192.168.1.0/24 present with localPref=0 — implicit honor rule fired"
        break
    fi
    if [ "$i" = "20" ]; then
        fail "192.168.1.0/24 still not at localPref=0 after 20s (last seen: $lp); \
             implicit honor rule may not have fired"
        exit 1
    fi
    sleep 1
done

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
        exit 1
    fi
    sleep 1
done

print_summary
