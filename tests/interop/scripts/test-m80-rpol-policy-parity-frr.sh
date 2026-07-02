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
#   1. Sessions Established, the route matrix flows.
#   2. Import parity — for every matrix route, rustbgpd's rpol
#      decision (accepted / rejected / LP / MED / communities) equals
#      the parity node's route-map outcome. Exercises: prefix-set
#      ge/le boundary, community add + remove, LOCAL_PREF set,
#      as-path regex reject, a modify-then-continue term, and the
#      same parameterized policy instantiated as customer-in(200)
#      (src peer) vs customer-in(300) (down peer).
#   3. Export parity — `down` compares the path rustbgpd exported
#      (rpol edge-out) against the path parity exported (route-map
#      RPOL-OUT): same MED, same communities, same deny.
#   4. `rbgp policy check` runs the .rpol file's in-language tests
#      (exit 0).
#   5. `rbgp policy test` — candidate customer-in(500) dry-run over
#      the live RIB: counts + per-term hits + before/after diffs.
#   6. `rbgp policy stats` — live per-term export hit counters.
#   7. .rpol edit under traffic (m34 pattern): flip src-default's LP
#      100 -> 150, SIGHUP; no session flap, Route Refresh fired at
#      the src peer ONLY (down's chains are content-identical), the
#      new LP visible in the post-policy RIB.
#   8. No dataplane writes.
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
parity_import_tuple() {
    local cidr=$1
    docker exec "$PARITY" vtysh -c "show bgp ipv4 unicast $cidr json" 2>/dev/null \
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
    log "Waiting for the route matrix on rustbgpd + parity..."
    local accepted="10.10.1.0/24 10.10.2.0/27 192.168.1.0/24 198.51.100.0/24"
    for i in $(seq 1 30); do
        local missing=0 cidr r p
        for cidr in $accepted; do
            r=$(rust_import_tuple "$cidr")
            p=$(parity_import_tuple "$cidr")
            # A converged route renders as a {lp, med, comms} object.
            { [ "${r:0:1}" = "{" ] && [ "${p:0:1}" = "{" ]; } || missing=1
        done
        # The second-instantiation route from the down peer.
        r=$(rust_import_tuple "10.10.3.0/24")
        [ "${r:0:1}" = "{" ] || missing=1
        if [ "$missing" -eq 0 ]; then
            ok "route matrix present on both engines (attempt $i)"
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

check_import_parity() {
    local cidr=$1 expected=$2 label=$3
    local r p
    r=$(rust_import_tuple "$cidr")
    p=$(parity_import_tuple "$cidr")
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

# ---------------------------------------------------------------------------
# 3. Export parity — down compares rustbgpd's path vs parity's path
# ---------------------------------------------------------------------------

# {med, comms} of the path a given upstream exported to down.
down_export_tuple() {
    local cidr=$1 via=$2
    docker exec "$DOWN" vtysh -c "show bgp ipv4 unicast $cidr json" 2>/dev/null \
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
    local cidr=$1 label=$2
    local via_rust via_parity
    via_rust=$(down_export_tuple "$cidr" "10.0.1.1")
    via_parity=$(down_export_tuple "$cidr" "10.0.3.1")
    if [ "$via_rust" = "$via_parity" ] && [ "$via_rust" != "null" ]; then
        ok "export parity $cidr ($label): via rustbgpd == via FRR: $via_rust"
    else
        fail "export parity $cidr ($label): via_rustbgpd=$via_rust via_frr=$via_parity"
    fi
}

wait_down_routes() {
    log "Waiting for exported routes from both upstreams on down..."
    for i in $(seq 1 30); do
        local r p
        r=$(down_export_tuple "10.10.1.0/24" "10.0.1.1")
        p=$(down_export_tuple "10.10.1.0/24" "10.0.3.1")
        if [ "$r" != "absent" ] && [ "$p" != "absent" ]; then
            ok "down sees 10.10.1.0/24 from both upstreams (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "down never received 10.10.1.0/24 from both upstreams within 60s"
    return 1
}
wait_down_routes

log "Test 3: export parity (rpol edge-out vs route-map RPOL-OUT)"
check_export_parity "10.10.1.0/24" "MED 50 + 65001:777 on top of import mods"
check_export_parity "10.10.2.0/27" "MED 50 + 65001:777"
check_export_parity "192.168.1.0/24" "scrubbed import survives export identically"
check_export_parity "198.51.100.0/24" "no-leak term == route-map deny (absent from both)"

med_rust=$(down_export_tuple "10.10.1.0/24" "10.0.1.1" | jq -r '.med? // "absent"')
if [ "$med_rust" = "50" ]; then
    ok "export intent: MED 50 actually on the wire from rustbgpd"
else
    fail "export intent: MED expected 50 from rustbgpd, got '$med_rust'"
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
# src's post-policy Adj-RIB-In holds 4 routes (203.0.113.0/24 was
# denied on import); the candidate accepts all 4 and re-modifies the
# two customer routes to LP 500.
if [ "$t_eval" = "4" ] && [ "$t_acc" = "4" ] && [ "$t_rej" = "0" ] && [ "$t_mod" = "2" ]; then
    ok "dry-run counts: evaluated=4 accepted=4 rejected=0 modified=2"
else
    fail "dry-run counts: evaluated=$t_eval accepted=$t_acc rejected=$t_rej modified=$t_mod (expected 4/4/0/2)"
    echo "$test_json" | jq . >&2 || true
fi

cust_hits=$(echo "$test_json" \
    | jq -r '[.term_hits[] | select(.term == "customer-routes")][0].hits // 0')
if [ "$cust_hits" = "2" ]; then
    ok "dry-run term hits: customer-routes=2"
else
    fail "dry-run term hits: customer-routes expected 2, got '$cust_hits'"
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
if [ "$noleak_hits" -ge 1 ] && [ "$tag_hits" -ge 1 ]; then
    ok "live term hits: no-leak=$noleak_hits tag-and-med=$tag_hits"
else
    fail "live term hits: no-leak=$noleak_hits tag-and-med=$tag_hits (expected both >= 1)"
    echo "$stats_json" | jq . >&2 || true
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
log "Pre-SIGHUP: src flapCount=$initial_flaps uptime=$initial_uptime; \
routeRefreshRecv src=$src_refresh_before down=$down_refresh_before"

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

# ---------------------------------------------------------------------------
# 8. No dataplane writes
# ---------------------------------------------------------------------------

log "Test 8: policy processing installed nothing into any dataplane"
dp_hits=$(docker exec "$RUSTBGPD" ip route show 2>/dev/null \
    | grep -cE "10\.10\.|192\.168\.1\.|198\.51\.100\.|203\.0\.113\." || true)
if [ "$dp_hits" -eq 0 ]; then
    ok "no kernel routes for any test prefix"
else
    fail "unexpected kernel routes for test prefixes:"
    docker exec "$RUSTBGPD" ip route show >&2 || true
fi

print_summary
