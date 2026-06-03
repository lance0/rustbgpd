#!/usr/bin/env bash
# M57 interop test — Outbound Route Filtering (RFC 5291/5292), receive side.
#
# rustbgpd (AS 65001) is the route server with `prefix_orf_receive = true` for
# the FRR neighbor. Three prefixes are injected into its Loc-RIB. FRR (AS 65002)
# negotiates `capability orf prefix-list both` and pushes an inbound
# prefix-list as an ORF; rustbgpd applies it to what it advertises to FRR.
#
#   Phase 1: prefix-list permits only 10.10.1.0/24 → FRR receives only that
#            (the other two are filtered out by the ORF before being sent).
#   Phase 2: widen the prefix-list to permit-all and re-send the ORF
#            (`clear bgp ... in prefix-filter`) → FRR receives all three
#            (re-expansion: REMOVE-ALL + ADD).
#
# Prerequisites:
#   - containerlab deploy -t tests/interop/m57-orf-frr.clab.yml
#   - grpcurl + jq installed on the host

set -euo pipefail

TOPO="m57-orf-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"
FRR="clab-${TOPO}-frr"

PERMITTED="10.10.1.0/24"
FILTERED_A="10.10.2.0/24"
FILTERED_B="192.168.50.0/24"

preflight
resolve_grpc_addr
start_rustbgpd

wait_frr_established "$FRR" "10.0.0.1" "rustbgpd ↔ FRR"

# Inject the three route-server prefixes into rustbgpd's Loc-RIB. Order vs the
# inbound ORF does not matter: the RFC 5291 §6 gate holds advertisement until
# FRR's ORF arrives, then the filtered set is flooded.
inject() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"prefix\":\"${1%/*}\",\"prefixLength\":${1#*/},\"nextHop\":\"10.0.0.1\",\"origin\":2,\"asPath\":[]}" \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/AddPath > /dev/null
}
log "Injecting route-server prefixes into rustbgpd's Loc-RIB..."
inject "$PERMITTED"
inject "$FILTERED_A"
inject "$FILTERED_B"

# Set of IPv4 unicast prefixes FRR currently has in its BGP table (received
# from rustbgpd), one per line.
frr_received_prefixes() {
    docker exec "$FRR" vtysh -c "show bgp ipv4 unicast json" 2>/dev/null \
        | jq -r '(.routes // {}) | keys[]' 2>/dev/null | sort
}

frr_has() { frr_received_prefixes | grep -qx "$1"; }

dump_frr() {
    echo "===== FRR: show bgp ipv4 unicast =====" >&2
    docker exec "$FRR" vtysh -c "show bgp ipv4 unicast" >&2 || true
    echo "===== FRR: show bgp neighbors 10.0.0.1 (ORF) =====" >&2
    docker exec "$FRR" vtysh -c "show bgp neighbors 10.0.0.1" >&2 | grep -iE "orf|filter|prefix" >&2 || true
}

# ---------------------------------------------------------------------------
# Phase 1 — ORF filters the advertised set to the single permitted prefix.
# ---------------------------------------------------------------------------
log "Phase 1: FRR must receive ONLY $PERMITTED (ORF permits just that prefix)..."
phase1=0
for i in $(seq 1 45); do
    if frr_has "$PERMITTED" && ! frr_has "$FILTERED_A" && ! frr_has "$FILTERED_B"; then
        ok "FRR received only $PERMITTED after ${i}s — ORF honored, others filtered"
        phase1=1
        break
    fi
    sleep 2
done
if [ "$phase1" -ne 1 ]; then
    fail "ORF did not constrain the advertised set to $PERMITTED"
    dump_frr
    print_summary
fi

# ---------------------------------------------------------------------------
# Phase 2 — widen the ORF and re-send it; the advertised set re-expands.
# ---------------------------------------------------------------------------
log "Phase 2: widening FRR's inbound prefix-list to permit-all and re-sending the ORF..."
docker exec "$FRR" vtysh -c "configure terminal" \
    -c "ip prefix-list ORF-IN seq 10 permit 0.0.0.0/0 le 32" >/dev/null 2>&1 || true
docker exec "$FRR" vtysh -c "clear bgp 10.0.0.1 in prefix-filter" >/dev/null 2>&1 || true

phase2=0
for i in $(seq 1 45); do
    if frr_has "$PERMITTED" && frr_has "$FILTERED_A" && frr_has "$FILTERED_B"; then
        ok "FRR received all three prefixes after ${i}s — ORF re-expansion works"
        phase2=1
        break
    fi
    sleep 2
done
if [ "$phase2" -ne 1 ]; then
    fail "ORF re-send did not re-expand the advertised set to all three prefixes"
    dump_frr
fi

print_summary
