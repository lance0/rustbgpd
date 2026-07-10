#!/usr/bin/env bash
# M80 interop test — rpol policy parity against FRR route-maps
# (ADR-0096 arc closer).
#
# rustbgpd runs its whole policy surface from an `.rpol` file
# ([policy] rpol_files); the `parity` FRR node expresses the SAME
# intent as classic route-maps / prefix-lists / community-lists.
# Both receive one route matrix from `src` and export to `down`.
#
# Phases:
#   1. Sessions Established, the route matrix flows (IPv4 + IPv6
#      unicast over the same MP-BGP sessions).
#   2. Import parity — for every matrix route, rustbgpd's rpol
#      decision (accepted / rejected / LP / MED / communities) equals
#      the parity node's route-map outcome. Exercises: prefix-set
#      ge/le boundary, community add + remove, LOCAL_PREF set,
#      as-path regex reject, a modify-then-continue term, the same
#      parameterized policy instantiated as customer-in(200) (src
#      peer) vs customer-in(300) (down peer), asn-set origin-AS
#      probes (route.origin-as in partners vs anchored as-path
#      regex), and route.family branching: v4/v6 partner twins with
#      the SAME origin 64999 diverge on LP/community purely by
#      family, so the family predicate is provably non-vacuous.
#   3. Export parity — `down` compares the path rustbgpd exported
#      (rpol edge-out) against the path parity exported (route-map
#      RPOL-OUT): same MED, same communities, same deny — v4 (MED
#      50) and v6 (MED 60 via the family-branched med-v6 term).
#   4. `rbgp policy check` runs the .rpol file's in-language tests
#      (exit 0), including the family-fixture tests.
#   5. `rbgp policy test` — candidate customer-in(500) dry-run over
#      the live RIB (both families): counts + per-term hits +
#      before/after diffs.
#   6. `rbgp policy stats` — live per-term hit counters, export AND
#      import (--direction, #761), plus explain traces naming the
#      deciding source term on both directions.
#   7. .rpol edit under traffic (m34 pattern): flip src-default's LP
#      100 -> 150, SIGHUP; no session flap, Route Refresh fired at
#      the src peer ONLY (down's chains are content-identical), the
#      new LP visible in the post-policy RIB, and the import-chain
#      install generation bumps for src only.
#   8. No dataplane writes (v4 or v6).
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m80-rpol-policy-parity-frr.clab.yml
#   - grpcurl + jq installed on the host

set -euo pipefail

TOPO="m80-rpol-policy-parity-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"
SRC="clab-${TOPO}-src"
PARITY="clab-${TOPO}-parity"
DOWN="clab-${TOPO}-down"

SRC_PEER="10.0.0.2"     # src as seen by rustbgpd
DOWN_PEER="10.0.1.2"    # down as seen by rustbgpd

preflight
resolve_grpc_addr
start_rustbgpd

rbgp() {
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 "$@"
}

grpc_list_best() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListBestRoutes 2>/dev/null
}

grpc_list_received_for_peer() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"neighbor_address\": \"$1\"}" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

neighbor_state() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"address\": \"$1\"}" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState 2>/dev/null
}

# Route Refresh messages an FRR node has RECEIVED from rustbgpd.
frr_refresh_recv() {
    local container=$1 neighbor=$2
    docker exec "$container" vtysh -c "show bgp neighbors $neighbor json" 2>/dev/null \
        | jq -r --arg n "$neighbor" '.[$n].messageStats.routeRefreshRecv // 0'
}

# ---------------------------------------------------------------------------
# 1. Sessions + route matrix
# ---------------------------------------------------------------------------

wait_frr_established "$SRC" "10.0.0.1" "src ↔ rustbgpd"
wait_frr_established "$DOWN" "10.0.1.1" "down ↔ rustbgpd"
wait_frr_established "$SRC" "10.0.2.1" "src ↔ parity"
wait_frr_established "$DOWN" "10.0.3.1" "down ↔ parity"

# rustbgpd's post-import-policy view of one prefix as a normalized
# {lp, med, comms} tuple ("absent" when not in the table). LP absent
# on the wire reads as the RFC 4271 default 100 — same normalization
# FRR's display uses.
rust_import_tuple() {
    local addr=${1%/*} len=${1#*/}
    grpc_list_best | jq -c --arg p "$addr" --argjson l "$len" '
        [.routes[]? | select(.prefix == $p and (.prefixLength // 0) == $l)][0]
        | if . == null then "absent" else
            {lp: (.localPref // 100), med: (.med // 0),
             comms: ((.communities // []) | sort)}
          end'
}

# The parity node's post-route-map view of the same prefix (the path
# learned directly from src), normalized identically. FRR communities
# are strings ("65000:100") — re-encode as (asn << 16) | value.
# $2 selects the address family (ipv4 default, ipv6 for the v6 matrix).
parity_import_tuple() {
    local cidr=$1 af=${2:-ipv4}
    docker exec "$PARITY" vtysh -c "show bgp $af unicast $cidr json" 2>/dev/null \
        | jq -c --arg peer "10.0.2.2" '
            [.paths[]? | select(.peer.peerId == $peer)][0]
            | if . == null then "absent" else
                {lp: (.locPrf // 100), med: (.metric // 0),
                 comms: ([.community.list[]? | split(":")
                          | (.[0] | tonumber) * 65536 + (.[1] | tonumber)]
                         | sort)}
              end'
}

wait_matrix() {
    log "Waiting for the route matrix on rustbgpd + parity (v4 + v6)..."
    local accepted="10.10.1.0/24 10.10.2.0/27 192.168.1.0/24 198.51.100.0/24 10.20.1.0/24"
    local accepted6="2001:db8:64::/48 2001:db8:99::/48"
    for i in $(seq 1 30); do
        local missing=0 cidr r p
        for cidr in $accepted; do
            r=$(rust_import_tuple "$cidr")
            p=$(parity_import_tuple "$cidr")
            # A converged route renders as a {lp, med, comms} object.
            { [ "${r:0:1}" = "{" ] && [ "${p:0:1}" = "{" ]; } || missing=1
        done
        for cidr in $accepted6; do
            r=$(rust_import_tuple "$cidr")
            p=$(parity_import_tuple "$cidr" ipv6)
            { [ "${r:0:1}" = "{" ] && [ "${p:0:1}" = "{" ]; } || missing=1
        done
        # The second-instantiation route from the down peer.
        r=$(rust_import_tuple "10.10.3.0/24")
        [ "${r:0:1}" = "{" ] || missing=1
        if [ "$missing" -eq 0 ]; then
            ok "route matrix (v4 + v6) present on both engines (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "route matrix did not converge within 60s"
    return 1
}
wait_matrix

# ---------------------------------------------------------------------------
# 2. Import parity — rpol vs route-maps, route for route
# ---------------------------------------------------------------------------

# expected tuple encodes the shared INTENT so a bug both engines share
# can't silently pass as "parity". Communities pre-encoded:
#   65000:100 = 4259840100, 65001:999 = 4259906535
C_CUST=$((65000 * 65536 + 100))
C_TAG=$((65001 * 65536 + 999))
C_P4=$((65001 * 65536 + 604))
C_P6=$((65001 * 65536 + 606))

check_import_parity() {
    local cidr=$1 expected=$2 label=$3 af=${4:-ipv4}
    local r p
    r=$(rust_import_tuple "$cidr")
    p=$(parity_import_tuple "$cidr" "$af")
    if [ "$r" = "$p" ] && [ "$r" = "$expected" ]; then
        ok "import parity $cidr ($label): rustbgpd == FRR == intent: $r"
    else
        fail "import parity $cidr ($label): rustbgpd=$r frr=$p expected=$expected"
    fi
}

log "Test 2: import parity (rpol customer-in(200) vs route-map RPOL-IN)"
check_import_parity "10.10.1.0/24" \
    "{\"lp\":200,\"med\":0,\"comms\":[$C_CUST,$C_TAG]}" \
    "prefix-set + community-set match -> LP 200 + 65001:999"
check_import_parity "10.10.2.0/27" \
    "{\"lp\":100,\"med\":0,\"comms\":[$C_CUST]}" \
    "/27 outside 'le 26' -> prefix-set miss, default accept"
check_import_parity "192.168.1.0/24" \
    "{\"lp\":200,\"med\":0,\"comms\":[$C_CUST,$C_TAG]}" \
    "scrub term removed 65000:666 + MED 300->0, then fell through to LP 200"
check_import_parity "198.51.100.0/24" \
    "{\"lp\":100,\"med\":0,\"comms\":[]}" \
    "untagged -> default accept"
check_import_parity "203.0.113.0/24" \
    '"absent"' \
    "as-path _65500_ regex -> rejected by both engines"

log "Test 2b: parameterized policy — customer-in(200) vs customer-in(300)"
lp_down=$(rust_import_tuple "10.10.3.0/24" | jq -r '.lp? // "absent"')
if [ "$lp_down" = "300" ]; then
    ok "10.10.3.0/24 (down peer, customer-in(300)) has LP 300 while 10.10.1.0/24 (src peer, customer-in(200)) has LP 200"
else
    fail "10.10.3.0/24 LP expected 300 (customer-in(300) instantiation), got '$lp_down'"
fi

log "Test 2c: asn-set origin-AS + route.family predicates (LAN-297)"
check_import_parity "10.20.1.0/24" \
    "{\"lp\":210,\"med\":0,\"comms\":[$C_P4]}" \
    "origin 64999 in asn-set partners + family ipv4-unicast -> LP 210 + 65001:604"
check_import_parity "2001:db8:64::/48" \
    "{\"lp\":220,\"med\":0,\"comms\":[$C_P6]}" \
    "origin 64999 in asn-set partners + family ipv6-unicast -> LP 220 + 65001:606" \
    ipv6
check_import_parity "2001:db8:99::/48" \
    "{\"lp\":100,\"med\":0,\"comms\":[]}" \
    "v6 route with origin 65002 outside the asn-set -> default accept" \
    ipv6

# Non-vacuity pin: the v4/v6 partner twins carry the SAME origin
# (64999) and differ only in address family, so their divergent
# outcomes can only come from the route.family guards.
lp_p4=$(rust_import_tuple "10.20.1.0/24" | jq -r '.lp? // "absent"')
lp_p6=$(rust_import_tuple "2001:db8:64::/48" | jq -r '.lp? // "absent"')
if [ "$lp_p4" = "210" ] && [ "$lp_p6" = "220" ]; then
    ok "route.family fired non-vacuously: identical origin 64999, v4 -> LP 210 (partner-v4), v6 -> LP 220 (partner-v6)"
else
    fail "family divergence broken: v4 LP='$lp_p4' (want 210), v6 LP='$lp_p6' (want 220)"
fi

# ---------------------------------------------------------------------------
# 3. Export parity — down compares rustbgpd's path vs parity's path
# ---------------------------------------------------------------------------

# {med, comms} of the path a given upstream exported to down.
# $3 selects the address family (ipv4 default).
down_export_tuple() {
    local cidr=$1 via=$2 af=${3:-ipv4}
    docker exec "$DOWN" vtysh -c "show bgp $af unicast $cidr json" 2>/dev/null \
        | jq -c --arg peer "$via" '
            [.paths[]? | select(.peer.peerId == $peer)][0]
            | if . == null then "absent" else
                {med: (.metric // 0),
                 comms: ([.community.list[]? | split(":")
                          | (.[0] | tonumber) * 65536 + (.[1] | tonumber)]
                         | sort)}
              end'
}

check_export_parity() {
    local cidr=$1 label=$2 af=${3:-ipv4}
    local via_rust via_parity
    via_rust=$(down_export_tuple "$cidr" "10.0.1.1" "$af")
    via_parity=$(down_export_tuple "$cidr" "10.0.3.1" "$af")
    if [ "$via_rust" = "$via_parity" ] && [ "$via_rust" != "null" ] \
        && [ "$via_rust" != "absent" ]; then
        ok "export parity $cidr ($label): via rustbgpd == via FRR: $via_rust"
    else
        fail "export parity $cidr ($label): via_rustbgpd=$via_rust via_frr=$via_parity"
    fi
}

wait_down_routes() {
    log "Waiting for exported routes from both upstreams on down..."
    for i in $(seq 1 30); do
        local r p r6 p6
        r=$(down_export_tuple "10.10.1.0/24" "10.0.1.1")
        p=$(down_export_tuple "10.10.1.0/24" "10.0.3.1")
        r6=$(down_export_tuple "2001:db8:64::/48" "10.0.1.1" ipv6)
        p6=$(down_export_tuple "2001:db8:64::/48" "10.0.3.1" ipv6)
        if [ "$r" != "absent" ] && [ "$p" != "absent" ] \
            && [ "$r6" != "absent" ] && [ "$p6" != "absent" ]; then
            ok "down sees 10.10.1.0/24 + 2001:db8:64::/48 from both upstreams (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "down never received the v4 + v6 exports from both upstreams within 60s"
    return 1
}
wait_down_routes

log "Test 3: export parity (rpol edge-out vs route-map RPOL-OUT)"
check_export_parity "10.10.1.0/24" "MED 50 + 65001:777 on top of import mods"
check_export_parity "10.10.2.0/27" "MED 50 + 65001:777"
check_export_parity "192.168.1.0/24" "scrubbed import survives export identically"
check_export_parity "198.51.100.0/24" "no-leak term == route-map deny (absent from both)"
check_export_parity "10.20.1.0/24" "partner import tag 65001:604 survives export + MED 50"
check_export_parity "2001:db8:64::/48" "family-branched med-v6 term == v6-scoped route-map entry" ipv6
check_export_parity "2001:db8:99::/48" "v6 fallthrough route still takes the med-v6 branch" ipv6

med_rust=$(down_export_tuple "10.10.1.0/24" "10.0.1.1" | jq -r '.med? // "absent"')
if [ "$med_rust" = "50" ]; then
    ok "export intent: MED 50 actually on the wire from rustbgpd"
else
    fail "export intent: MED expected 50 from rustbgpd, got '$med_rust'"
fi

# The v6 MED receipt pins the export-side family branch to the wire:
# only edge-out's med-v6 term (guard: route.family == ipv6-unicast)
# sets 60 — the v4 catch-all sets 50.
med6_rust=$(down_export_tuple "2001:db8:64::/48" "10.0.1.1" ipv6 | jq -r '.med? // "absent"')
if [ "$med6_rust" = "60" ]; then
    ok "export intent: family-branched MED 60 on the wire from rustbgpd for the v6 route"
else
    fail "export intent: v6 MED expected 60 from rustbgpd (med-v6 term), got '$med6_rust'"
fi

# ---------------------------------------------------------------------------
# 4. rbgp policy check — the file's in-language test block
# ---------------------------------------------------------------------------

log "Test 4: rbgp policy check runs the .rpol in-language tests"
if check_out=$(docker exec "$RUSTBGPD" rbgp policy check /etc/rustbgpd/policies/core.rpol); then
    ok "policy check exit 0: $check_out"
else
    fail "policy check failed: $check_out"
fi

# ---------------------------------------------------------------------------
# 5. rbgp policy test — candidate dry run over the live RIB
# ---------------------------------------------------------------------------

log "Test 5: rbgp policy test — customer-in(500) candidate over the live RIB"
test_json=$(rbgp --json policy test /etc/rustbgpd/policies/core.rpol \
    --policy "customer-in(500)" --direction import --peer "$SRC_PEER" \
    --show-changes 2)

read -r t_eval t_acc t_rej t_mod <<<"$(echo "$test_json" \
    | jq -r '"\(.routes_evaluated) \(.accepted) \(.rejected) \(.modified)"')"
# src's post-policy Adj-RIB-In holds 7 routes across both families
# (203.0.113.0/24 was denied on import): 5 v4 + 2 v6. The candidate
# accepts all 7 and modifies 4: the two customer routes to LP 500
# plus the two partner twins (family-branched LP + community).
if [ "$t_eval" = "7" ] && [ "$t_acc" = "7" ] && [ "$t_rej" = "0" ] && [ "$t_mod" = "4" ]; then
    ok "dry-run counts: evaluated=7 accepted=7 rejected=0 modified=4 (v4 + v6 snapshot)"
else
    fail "dry-run counts: evaluated=$t_eval accepted=$t_acc rejected=$t_rej modified=$t_mod (expected 7/7/0/4)"
    echo "$test_json" | jq . >&2 || true
fi

cust_hits=$(echo "$test_json" \
    | jq -r '[.term_hits[] | select(.term == "customer-routes")][0].hits // 0')
if [ "$cust_hits" = "2" ]; then
    ok "dry-run term hits: customer-routes=2"
else
    fail "dry-run term hits: customer-routes expected 2, got '$cust_hits'"
fi

p4_hits=$(echo "$test_json" \
    | jq -r '[.term_hits[] | select(.term == "partner-v4")][0].hits // 0')
p6_hits=$(echo "$test_json" \
    | jq -r '[.term_hits[] | select(.term == "partner-v6")][0].hits // 0')
if [ "$p4_hits" = "1" ] && [ "$p6_hits" = "1" ]; then
    ok "dry-run term hits: partner-v4=1 partner-v6=1 (one twin each, family-split)"
else
    fail "dry-run term hits: partner-v4=$p4_hits partner-v6=$p6_hits (expected 1/1)"
fi

if echo "$test_json" | jq -e '[.diffs[].changes[] | select(contains("500"))] | length >= 1' >/dev/null; then
    ok "dry-run before/after diff shows the LP 500 change"
else
    fail "dry-run diffs missing the LP -> 500 line"
    echo "$test_json" | jq .diffs >&2 || true
fi

# ---------------------------------------------------------------------------
# 6. rbgp policy stats — live per-term export hit counters
# ---------------------------------------------------------------------------

log "Test 6: rbgp policy stats shows nonzero live term hits for edge-out"
stats_json=$(rbgp --json policy stats --peer "$DOWN_PEER")
noleak_hits=$(echo "$stats_json" | jq -r '
    [.[] | select(.peer_address == "'"$DOWN_PEER"'") | .terms[]
     | select(.policy == "edge-out" and .term == "no-leak")][0].hits // 0')
tag_hits=$(echo "$stats_json" | jq -r '
    [.[] | select(.peer_address == "'"$DOWN_PEER"'") | .terms[]
     | select(.policy == "edge-out" and (.term // "" | startswith("tag-and-med")))
     | .hits] | add // 0')
medv6_hits=$(echo "$stats_json" | jq -r '
    [.[] | select(.peer_address == "'"$DOWN_PEER"'") | .terms[]
     | select(.policy == "edge-out" and .term == "med-v6")][0].hits // 0')
if [ "$noleak_hits" -ge 1 ] && [ "$tag_hits" -ge 1 ] && [ "$medv6_hits" -ge 2 ]; then
    ok "live export term hits: no-leak=$noleak_hits tag-and-med=$tag_hits med-v6=$medv6_hits"
else
    fail "live export term hits: no-leak=$noleak_hits tag-and-med=$tag_hits med-v6=$medv6_hits (expected >=1/>=1/>=2)"
    echo "$stats_json" | jq . >&2 || true
fi

log "Test 6b: rbgp policy stats --direction import — live import term hits (#761)"
import_stats=$(rbgp --json policy stats --peer "$SRC_PEER" --direction import)
ip4_hits=$(echo "$import_stats" | jq -r '
    [.[] | select(.peer_address == "'"$SRC_PEER"'") | .terms[]
     | select(.term == "partner-v4")][0].hits // 0')
ip6_hits=$(echo "$import_stats" | jq -r '
    [.[] | select(.peer_address == "'"$SRC_PEER"'") | .terms[]
     | select(.term == "partner-v6")][0].hits // 0')
guard_hits=$(echo "$import_stats" | jq -r '
    [.[] | select(.peer_address == "'"$SRC_PEER"'") | .terms[]
     | select(.term == "transit-guard")][0].hits // 0')
if [ "$ip4_hits" -ge 1 ] && [ "$ip6_hits" -ge 1 ] && [ "$guard_hits" -ge 1 ]; then
    ok "live import term hits: partner-v4=$ip4_hits partner-v6=$ip6_hits transit-guard=$guard_hits"
else
    fail "live import term hits: partner-v4=$ip4_hits partner-v6=$ip6_hits transit-guard=$guard_hits (expected all >= 1)"
    echo "$import_stats" | jq . >&2 || true
fi

# The first install is generation 0 — assert presence, not value.
import_gen=$(echo "$import_stats" | jq -r '
    [.[] | select(.peer_address == "'"$SRC_PEER"'")][0]
    | if has("policy_generation") then .policy_generation else "missing" end')
if [ "$import_gen" != "missing" ] && [ "$import_gen" != "null" ]; then
    ok "import chain reports install generation $import_gen"
else
    fail "import chain install generation missing (got '$import_gen')"
    echo "$import_stats" | jq . >&2 || true
fi

log "Test 6c: explain traces name the deciding source term (import + export)"
explain_v6=$(rbgp policy explain --neighbor "$SRC_PEER" --prefix 2001:db8:64::/48)
if echo "$explain_v6" | grep -q "partner-v6"; then
    ok "import explain for 2001:db8:64::/48 names deciding term partner-v6"
else
    fail "import explain for 2001:db8:64::/48 does not name partner-v6"
    echo "$explain_v6" >&2
fi
explain_v4=$(rbgp policy explain --neighbor "$SRC_PEER" --prefix 10.20.1.0/24)
if echo "$explain_v4" | grep -q "partner-v4"; then
    ok "import explain for 10.20.1.0/24 names deciding term partner-v4"
else
    fail "import explain for 10.20.1.0/24 does not name partner-v4"
    echo "$explain_v4" >&2
fi
export_explain=$(rbgp rib --prefix 2001:db8:64::/48 advertised "$DOWN_PEER" --explain)
if echo "$export_explain" | grep -q "^Advertise" \
    && echo "$export_explain" | grep -q "med-v6"; then
    ok "export explain for 2001:db8:64::/48 -> Advertise via deciding term med-v6"
else
    fail "export explain for 2001:db8:64::/48 missing Advertise/med-v6"
    echo "$export_explain" >&2
fi

# ---------------------------------------------------------------------------
# 7. .rpol edit under traffic — SIGHUP hot-apply (m34 pattern)
# ---------------------------------------------------------------------------

log "Test 7: .rpol edit + SIGHUP — LP flip, no flap, refresh scoped to src"

initial_state=$(neighbor_state "$SRC_PEER")
initial_flaps=$(echo "$initial_state" | jq -r '.flapCount // 0 | tonumber')
initial_uptime=$(echo "$initial_state" | jq -r '.uptimeSeconds // 0 | tonumber')
src_refresh_before=$(frr_refresh_recv "$SRC" "10.0.0.1")
down_refresh_before=$(frr_refresh_recv "$DOWN" "10.0.1.1")
# Import-chain install generations (#761) — the reload must bump
# src's (its resolved chain changed) and leave down's alone.
import_chain_gen() {
    rbgp --json policy stats --peer "$1" --direction import \
        | jq -r '[.[] | select(.peer_address == "'"$1"'")][0].policy_generation // 0'
}
gen_src_before=$(import_chain_gen "$SRC_PEER")
gen_down_before=$(import_chain_gen "$DOWN_PEER")
log "Pre-SIGHUP: src flapCount=$initial_flaps uptime=$initial_uptime; \
routeRefreshRecv src=$src_refresh_before down=$down_refresh_before; \
import generations src=$gen_src_before down=$gen_down_before"

docker exec "$RUSTBGPD" sh -c '
    set -e
    cp /etc/rustbgpd/core.lp150.rpol /etc/rustbgpd/policies/core.rpol
    pid=$(grep -lF rustbgpd /proc/[0-9]*/comm 2>/dev/null | head -1 | cut -d/ -f3)
    if [ -z "$pid" ]; then
        echo "ERROR: rustbgpd PID not found in /proc" >&2
        exit 1
    fi
    kill -HUP "$pid"
    echo "SIGHUP sent to PID $pid"
'

# The reload recompiles the file, sees only src-default changed
# (customer-in / edge-out are content-identical), refreshes src, and
# re-imports 198.51.100.0/24 under the new LP.
lp_flipped=0
lp=""
for i in $(seq 1 20); do
    lp=$(rust_import_tuple "198.51.100.0/24" | jq -r '.lp? // 0')
    if [ "$lp" = "150" ]; then
        lp_flipped=1
        ok "198.51.100.0/24 LP 100 -> 150 after .rpol edit + SIGHUP (${i}s)"
        break
    fi
    sleep 1
done
if [ "$lp_flipped" -ne 1 ]; then
    fail "198.51.100.0/24 LP never reached 150 after SIGHUP (last: '$lp') — \
         .rpol hot-apply or the auto Route Refresh did not fire"
fi

post_state=$(neighbor_state "$SRC_PEER")
post_flaps=$(echo "$post_state" | jq -r '.flapCount // 0 | tonumber')
post_uptime=$(echo "$post_state" | jq -r '.uptimeSeconds // 0 | tonumber')
if [ "$post_flaps" = "$initial_flaps" ] && [ "$post_uptime" -ge "$initial_uptime" ]; then
    ok "no session flap across SIGHUP (flapCount=$post_flaps, uptime $initial_uptime -> $post_uptime)"
else
    fail "session disturbed by SIGHUP (flaps $initial_flaps -> $post_flaps, uptime $initial_uptime -> $post_uptime)"
fi

src_refresh_after=$(frr_refresh_recv "$SRC" "10.0.0.1")
down_refresh_after=$(frr_refresh_recv "$DOWN" "10.0.1.1")
if [ "$src_refresh_after" -gt "$src_refresh_before" ]; then
    ok "Route Refresh fired at src (routeRefreshRecv $src_refresh_before -> $src_refresh_after)"
else
    fail "no Route Refresh at src (routeRefreshRecv stayed $src_refresh_after)"
fi
if [ "$down_refresh_after" = "$down_refresh_before" ]; then
    ok "down NOT refreshed (its chains were content-identical): routeRefreshRecv stayed $down_refresh_after"
else
    fail "down unexpectedly refreshed (routeRefreshRecv $down_refresh_before -> $down_refresh_after) — \
         reload should scope refresh to peers whose resolved chains changed"
fi

# The customer routes keep their pre-edit outcome (customer-in didn't change).
lp_cust=$(rust_import_tuple "10.10.1.0/24" | jq -r '.lp? // 0')
if [ "$lp_cust" = "200" ]; then
    ok "10.10.1.0/24 still LP 200 (customer-in(200) untouched by the edit)"
else
    fail "10.10.1.0/24 LP changed to '$lp_cust' — the edit leaked beyond src-default"
fi

# The reload reinstalled src's chain — its install generation bumps,
# so counters that reset read as a chain replacement (#761 contract).
# NOTE: down's generation bumps too (a content-equal reinstall —
# explicitly documented #761 behavior); the WIRE-visible scoping is
# the Route Refresh assertion above, so only src's bump is asserted.
gen_src_after=$(import_chain_gen "$SRC_PEER")
if [ "$gen_src_after" -gt "$gen_src_before" ]; then
    ok "src import-chain install generation bumped ($gen_src_before -> $gen_src_after)"
else
    fail "src import-chain generation did not bump ($gen_src_before -> $gen_src_after)"
fi

# ---------------------------------------------------------------------------
# 8. No dataplane writes
# ---------------------------------------------------------------------------

log "Test 8: policy processing installed nothing into any dataplane"
dp_hits=$(docker exec "$RUSTBGPD" ip route show 2>/dev/null \
    | grep -cE "10\.10\.|10\.20\.|192\.168\.1\.|198\.51\.100\.|203\.0\.113\." || true)
dp6_hits=$(docker exec "$RUSTBGPD" ip -6 route show 2>/dev/null \
    | grep -c "2001:db8" || true)
if [ "$dp_hits" -eq 0 ] && [ "$dp6_hits" -eq 0 ]; then
    ok "no kernel routes for any test prefix (v4 or v6)"
else
    fail "unexpected kernel routes for test prefixes:"
    docker exec "$RUSTBGPD" ip route show >&2 || true
    docker exec "$RUSTBGPD" ip -6 route show >&2 || true
fi

print_summary
