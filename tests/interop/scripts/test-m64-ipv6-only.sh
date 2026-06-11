#!/usr/bin/env bash
# M64 — true IPv6-only peering via disable_ipv4_unicast.
#
# Two sessions to the same FRR over one wire:
#
#  * fd00:64::1 ↔ fd00:64::2 — IPv6-only. rustbgpd: families =
#    ["ipv6_unicast"] + disable_ipv4_unicast = true. FRR: no neighbor
#    activate in ipv4 unicast, activate in ipv6 unicast.
#  * 10.64.0.1 ↔ 10.64.0.2 — §8 regression guard. rustbgpd: defaults
#    (no flag). FRR: dont-capability-negotiate (OPEN carries no
#    capabilities at all), so IPv4 unicast can only be negotiated via
#    the RFC 4760 §8 implicit fallback.
#
# Asserts:
#
# 1. Both sessions reach Established (FRR's view is authoritative).
# 2. FRR's capability view of the v6-only session shows NO IPv4-unicast
#    MultiProtocol capability received from rustbgpd (the "received" /
#    "advertisedAndReceived" markers reflect rustbgpd's OPEN), and
#    ipv6Unicast as advertisedAndReceived — the §8 implicit-IPv4
#    fallback was really suppressed at the capability layer.
# 3. IPv6 routes flow both directions on the v6-only session: FRR's
#    2001:db8:64::/48 lands in rustbgpd's RIB, and an injected
#    2001:db8:65::/48 lands in FRR's ipv6 unicast table.
# 4. FRR's ipv4 unicast table contains nothing from the v6-only
#    session — no IPv4 NLRI leaked onto it.
# 5. Regression guard: IPv4 routes flow both directions on the
#    capability-less session (FRR's 10.99.1.0/24 lands in rustbgpd's
#    RIB; an injected 10.98.1.0/24 lands in FRR's ipv4 unicast table)
#    — the §8 implicit-IPv4 fallback still works for peers without the
#    flag.
#
# Usage:
#   docker build -t rustbgpd:dev .
#   containerlab deploy -t tests/interop/m64-ipv6-only.clab.yml
#   bash tests/interop/scripts/test-m64-ipv6-only.sh
#   containerlab destroy -t tests/interop/m64-ipv6-only.clab.yml --cleanup

set -eu

TOPO="m64-ipv6-only"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

FRR="clab-${TOPO}-frr"
RUSTBGPD_V6="fd00:64::1"
RUSTBGPD_V4="10.64.0.1"
FRR_V6="fd00:64::2"
FRR_V4="10.64.0.2"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

frr_neighbor_json() {
    docker exec "$FRR" vtysh -c "show bgp neighbors $1 json" 2>/dev/null
}

grpc_routes_from_peer() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"neighbor_address\": \"$1\"}" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

inject_route() {
    local prefix=$1 len=$2 next_hop=$3
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{
            \"prefix\": \"${prefix}\",
            \"prefix_length\": ${len},
            \"next_hop\": \"${next_hop}\",
            \"origin\": 0,
            \"as_path\": [65001],
            \"local_pref\": 100
        }" \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/AddPath >/dev/null 2>&1
}

dump_state_on_failure() {
    echo "===== FRR vtysh: BGP summary =====" >&2
    docker exec "$FRR" vtysh -c 'show bgp summary' >&2 || true
    echo "===== FRR capabilities (v6-only neighbor) =====" >&2
    frr_neighbor_json "$RUSTBGPD_V6" \
        | jq --arg p "$RUSTBGPD_V6" '.[$p].neighborCapabilities' >&2 || true
    echo "===== rustbgpd log tail =====" >&2
    docker exec "$RUSTBGPD" tail -60 /var/log/rustbgpd.log >&2 || true
}

# ---------------------------------------------------------------------------
# Phase 1 — start rustbgpd, both sessions Established
# ---------------------------------------------------------------------------

resolve_grpc_addr
log "rustbgpd container: $RUSTBGPD"
log "FRR container: $FRR"

start_rustbgpd || exit 1

wait_frr_established "$FRR" "$RUSTBGPD_V6" "IPv6-only (disable_ipv4_unicast)" || {
    dump_state_on_failure
    print_summary
}
wait_frr_established "$FRR" "$RUSTBGPD_V4" "§8 regression (dont-capability-negotiate)" || {
    dump_state_on_failure
    print_summary
}

# ---------------------------------------------------------------------------
# Phase 2 — capability assertions on the v6-only session
# ---------------------------------------------------------------------------

# FRR's "received" / "advertisedAndReceived" markers reflect what
# rustbgpd put in its OPEN. With disable_ipv4_unicast, rustbgpd must
# not have sent an IPv4-unicast MP capability — and since FRR has the
# neighbor deactivated in ipv4 unicast, the key should carry no
# received-side marker at all.
caps=$(frr_neighbor_json "$RUSTBGPD_V6" \
    | jq --arg p "$RUSTBGPD_V6" '.[$p].neighborCapabilities.multiprotocolExtensions // {}')

ipv4_mp_received=$(printf '%s\n' "$caps" \
    | jq '[(.ipv4Unicast // {}) | (.received // false), (.advertisedAndReceived // false)] | any')
if [ "$ipv4_mp_received" = "false" ]; then
    ok "rustbgpd sent NO IPv4-unicast MP capability on the v6-only session"
else
    fail "FRR reports an IPv4-unicast MP capability received from rustbgpd: $caps"
    dump_state_on_failure
fi

ipv6_mp_both=$(printf '%s\n' "$caps" \
    | jq '(.ipv6Unicast // {}) | (.advertisedAndReceived // false)')
if [ "$ipv6_mp_both" = "true" ]; then
    ok "IPv6-unicast MP capability advertised and received on the v6-only session"
else
    fail "ipv6Unicast not advertisedAndReceived on the v6-only session: $caps"
    dump_state_on_failure
fi

# ---------------------------------------------------------------------------
# Phase 3 — IPv6 routes both directions on the v6-only session
# ---------------------------------------------------------------------------

# FRR → rustbgpd
got_v6=0
for _ in $(seq 1 15); do
    if grpc_routes_from_peer "$FRR_V6" | grep -q '"prefix": "2001:db8:64::"'; then
        got_v6=1
        break
    fi
    sleep 2
done
if [ "$got_v6" = "1" ]; then
    ok "FRR's 2001:db8:64::/48 received over the v6-only session"
else
    fail "2001:db8:64::/48 missing from rustbgpd's RIB (peer $FRR_V6)"
    dump_state_on_failure
fi

# rustbgpd → FRR
inject_route "2001:db8:65::" 48 "$RUSTBGPD_V6" \
    || fail "InjectionService.AddPath (IPv6) failed"
sent_v6=0
for _ in $(seq 1 15); do
    if docker exec "$FRR" vtysh -c 'show bgp ipv6 unicast 2001:db8:65::/48 json' 2>/dev/null \
        | jq -e '.paths // empty | length > 0' >/dev/null 2>&1; then
        sent_v6=1
        break
    fi
    sleep 2
done
if [ "$sent_v6" = "1" ]; then
    ok "injected 2001:db8:65::/48 advertised to FRR over the v6-only session"
else
    fail "2001:db8:65::/48 never appeared in FRR's ipv6 unicast table"
    dump_state_on_failure
fi

# ---------------------------------------------------------------------------
# Phase 4 — no IPv4 NLRI on the v6-only session
# ---------------------------------------------------------------------------

v4_from_v6peer=$(docker exec "$FRR" vtysh -c 'show bgp ipv4 unicast json' 2>/dev/null \
    | jq --arg p "$RUSTBGPD_V6" \
        '[.routes // {} | .[][]? | select(.peerId == $p)] | length')
if [ "${v4_from_v6peer:-0}" = "0" ]; then
    ok "FRR's ipv4 unicast table has nothing from the v6-only session"
else
    fail "FRR learned ${v4_from_v6peer} ipv4 route(s) from the v6-only session"
    dump_state_on_failure
fi

# ---------------------------------------------------------------------------
# Phase 5 — §8 regression guard: implicit IPv4 still works without the flag
# ---------------------------------------------------------------------------

# FRR → rustbgpd over the capability-less session
got_v4=0
for _ in $(seq 1 15); do
    if grpc_routes_from_peer "$FRR_V4" | grep -q '"prefix": "10.99.1.0"'; then
        got_v4=1
        break
    fi
    sleep 2
done
if [ "$got_v4" = "1" ]; then
    ok "§8 fallback: FRR's 10.99.1.0/24 received over the capability-less session"
else
    fail "10.99.1.0/24 missing from rustbgpd's RIB (peer $FRR_V4) — §8 fallback broken?"
    dump_state_on_failure
fi

# rustbgpd → FRR
inject_route "10.98.1.0" 24 "$RUSTBGPD_V4" \
    || fail "InjectionService.AddPath (IPv4) failed"
sent_v4=0
for _ in $(seq 1 15); do
    if docker exec "$FRR" vtysh -c 'show bgp ipv4 unicast 10.98.1.0/24 json' 2>/dev/null \
        | jq -e '.paths // empty | length > 0' >/dev/null 2>&1; then
        sent_v4=1
        break
    fi
    sleep 2
done
if [ "$sent_v4" = "1" ]; then
    ok "§8 fallback: injected 10.98.1.0/24 advertised to FRR over the capability-less session"
else
    fail "10.98.1.0/24 never appeared in FRR's ipv4 unicast table"
    dump_state_on_failure
fi

print_summary
