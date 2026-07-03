#!/usr/bin/env bash
# M83 interop test — route-server profile, multi-stack receipt
# (RFC 7947 / RFC 7948 / RFC 9234 / ADR-0101 proof-ladder closer).
#
# rustbgpd is the route server (AS 65500) for three member stacks —
# BIRD 2.0.12, GoBGP 3.x (Add-Path receive), FRR 10.3.1 — with a
# StayRTR RTR fixture feeding ROV and a tshark capture on the RS↔BIRD
# link for the byte-level assertions.
#
# First-AS relaxation per stack (client-side, RFC 7947 §2.2.2.1):
#   FRR 10.3.1  — per-neighbor `no neighbor X enforce-first-as`
#                 (global form alone is insufficient, the M19 finding)
#   BIRD 2.0.12 — `enforce first as off` (explicit; also the default)
#   GoBGP 3.x   — no first-AS enforcement exists; nothing to disable
#
# Assertions:
#    1  RTR: both VRPs loaded from StayRTR (bgp_rpki_vrp_count == 2)
#    2  BIRD member session Established
#    3  GoBGP member session Established
#    4  FRR member session Established
#   --- transparency, client views (RFC 7947 §2.2) ---
#    5  BIRD: 100.66.0.0/24 AS_PATH = "65002" (leftmost = originator,
#       no 65500 anywhere)
#    6  BIRD: NEXT_HOP = 10.83.2.2 (GoBGP's address, not the RS's)
#    7  BIRD: MED 77 verbatim
#    8  BIRD: standard community 65002:222 verbatim
#    9  BIRD: large community 65002:2:2 verbatim
#   10  FRR: 203.0.113.0/24 AS_PATH = "65001", no 65500
#   11  FRR: NEXT_HOP = 10.83.1.2 (BIRD's address)
#   12  FRR: MED 120 verbatim
#   13  FRR: standard community 65001:111 verbatim
#   14  FRR: large community 65001:1:1 verbatim
#   15  GoBGP: 100.67.0.0/24 AS_PATH = [65003], no 65500
#   16  GoBGP: NEXT_HOP = 10.83.3.2 (FRR's address)
#   --- RFC 9234 OTC toward clients (role = route_server) ---
#   17  FRR reports OTC on a reflected route
#   18  BIRD reports BGP.otc: 65500 on a reflected route
#   --- per-member policy views ---
#   19  FRR lacks 100.69.0.0/24 (member-scoped deny chain)
#   20  GoBGP holds 100.69.0.0/24 (deny is scoped to FRR only)
#   21  `rbgp rib advertised` to FRR agrees (prefix absent)
#   22  `rbgp rib advertised` to GoBGP agrees (prefix present)
#   --- ROV at import (RTR fixture) ---
#   23  RPKI-invalid 100.68.0.0/24 absent on BIRD
#   24  RPKI-invalid 100.68.0.0/24 absent on GoBGP
#   25  import explain names the reject-rpki-invalid deny
#   --- RFC 7947 §2.3 path-hiding contrast (ADR-0101) ---
#   26  (a) FRR single-best: 100.65.0.0/24 absent (the best is denied
#       toward FRR by community 65001:666 — path hidden, pinned)
#   27  (a) GoBGP holds BIRD's best for the same prefix (sanity)
#   28  (a) export explain toward FRR: Deny, naming deny-to-frr
#   29  (b) after per_client_best flip (sed + SIGHUP + session bounce):
#       `rbgp neighbor` shows Distribution Mode per-client-best
#   30  (b) FRR receives the runner-up: AS_PATH 65002
#   31  (b) FRR runner-up NEXT_HOP = 10.83.2.2 (still the originator's)
#   32  (b) export explain: per-client ladder — candidate 1 of 2 denied
#       by deny-to-frr, runner-up advertised
#   33  (b) export explain decision Advertise with route peer = GoBGP
#   34  (c) withdrawing the runner-up's source converges FRR to nothing
#       (best still denied — no stale runner-up)
#   35  (d) Add-Path member: GoBGP holds BOTH paths for 100.70.0.0/24
#       (from AS 65001 and AS 65003)
#   --- byte-level wire assertions (tshark, RS→BIRD) ---
#   36  no RS→BIRD UPDATE carries 65500 in any AS_PATH segment
#   37  wire NEXT_HOP 10.83.2.2 on the 100.66.0.0/24 UPDATE
#   38  wire MED 77 verbatim
#   39  wire community 65002:222 verbatim
#   40  wire large community 65002:2:2 verbatim
#   41  wire OTC path attribute (type code 35) present on RS→BIRD
#       announcements (value pinned as 65500 by assertion 18)
#   42  EoR: RS→BIRD IPv4-unicast End-of-RIB present, after the first
#       NLRI-bearing UPDATE (ordering sanity)
#   --- withdraw propagation + reload stability ---
#   43  BIRD withdraws 203.0.113.0/24 → gone on FRR
#   44  BIRD withdraws 203.0.113.0/24 → gone on GoBGP
#   45  policy reload (import-chain LP edit + SIGHUP): FRR session
#       survives (connectionsEstablished unchanged)
#   46  after the reload BIRD still holds 100.66.0.0/24 (no spurious
#       withdraw/churn — the OpenBGPd bug class, negative)
#
# Prerequisites:
#   - docker build --target dev -t rustbgpd:dev .
#   - docker build -t bird:2-bookworm -f tests/interop/Dockerfile.bird tests/interop
#   - docker build -t gobgp:interop -f tests/interop/Dockerfile.gobgp tests/interop
#   - containerlab deploy -t tests/interop/m83-routeserver-multistack.clab.yml
#
# Usage:
#   bash tests/interop/scripts/test-m83-routeserver-multistack.sh

TOPO="m83-routeserver-multistack"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"

BIRD="clab-${TOPO}-bird"
GOBGP="clab-${TOPO}-gobgp"
FRR="clab-${TOPO}-frr"
STAYRTR="clab-${TOPO}-stayrtr"

RS_BIRD_ADDR="10.83.1.1"
RS_GOBGP_ADDR="10.83.2.1"
RS_FRR_ADDR="10.83.3.1"
BIRD_ADDR="10.83.1.2"
GOBGP_ADDR="10.83.2.2"
FRR_ADDR="10.83.3.2"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

rs_ctl() {
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 "$@" 2>/dev/null
}

birdc_route_all() {
    docker exec "$BIRD" birdc show route all for "${1:?}" 2>/dev/null
}

frr_prefix_json() {
    docker exec "$FRR" vtysh -c "show bgp ipv4 unicast ${1:?} json" 2>/dev/null
}

gobgp_prefix_json() {
    docker exec "$GOBGP" gobgp global rib -a ipv4 "${1:?}" -j 2>/dev/null || echo "{}"
}

gobgp_has_prefix() {
    gobgp_prefix_json "$1" | jq -e --arg p "$1" '.[$p] | length >= 1' >/dev/null 2>&1
}

frr_has_prefix() {
    frr_prefix_json "$1" | jq -e '.paths | length >= 1' >/dev/null 2>&1
}

# AS_PATH string of the first path FRR holds for a prefix.
frr_aspath() {
    frr_prefix_json "$1" | jq -r '.paths[0].aspath.string // empty' 2>/dev/null
}

frr_nexthop() {
    frr_prefix_json "$1" | jq -r '.paths[0].nexthops[0].ip // empty' 2>/dev/null
}

wait_bird_established() {
    log "Waiting for BIRD session to reach Established..."
    for i in $(seq 1 45); do
        if docker exec "$BIRD" birdc show protocols 2>/dev/null \
            | awk '$1 == "routeserver"' | grep -q "Established"; then
            ok "BIRD session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "BIRD session did not reach Established within 90s"
    docker exec "$BIRD" birdc show protocols all routeserver 2>/dev/null | tail -20 || true
    return 1
}

wait_gobgp_established() {
    log "Waiting for GoBGP session to reach Established..."
    for i in $(seq 1 45); do
        if docker exec "$GOBGP" gobgp neighbor "$RS_GOBGP_ADDR" 2>/dev/null \
            | grep -qi "state = ESTABLISHED\|BGP state = established"; then
            ok "GoBGP session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "GoBGP session did not reach Established within 90s"
    docker exec "$GOBGP" gobgp neighbor 2>/dev/null || true
    return 1
}

# Poll until a predicate command succeeds. wait_for <label> <attempts> cmd...
wait_for() {
    local label=${1:?} attempts=${2:?}
    shift 2
    for _ in $(seq 1 "$attempts"); do
        if "$@" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    log "timeout waiting for: $label"
    return 1
}

# tshark over the RS→BIRD capture (runs inside the BIRD container).
bird_tshark() {
    docker exec "$BIRD" tshark -r /tmp/m83.pcap "$@" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Phase 0: bring the stacks up
# ---------------------------------------------------------------------------

start_capture() {
    log "Starting tshark capture on the RS↔BIRD link (inside $BIRD)..."
    docker exec "$BIRD" sh -c 'rm -f /tmp/m83.pcap' || true
    docker exec -d "$BIRD" sh -c \
        'tshark -i eth1 -w /tmp/m83.pcap port 179 >/tmp/tshark.log 2>&1'
    sleep 2
}

stop_capture() {
    log "Stopping tshark capture..."
    docker exec "$BIRD" sh -c \
        'pkill -INT tshark >/dev/null 2>&1 || pkill tshark >/dev/null 2>&1 || true'
    sleep 2
}

start_bird() {
    log "Starting BIRD..."
    docker exec "$BIRD" sh -c \
        'mkdir -p /run/bird && (bird -d -c /etc/bird/bird.conf >/tmp/bird.log 2>&1 &)'
}

start_gobgpd() {
    log "Starting gobgpd..."
    docker exec -d "$GOBGP" sh -c \
        'nohup gobgpd -f /config/gobgp.toml >/tmp/gobgpd.log 2>&1'
}

# Patch the StayRTR management address into a /tmp copy of the RS
# config (the M21 pattern) so the per_client_best flip can edit +
# SIGHUP the live file. The rpol file rides along: relative
# `rpol_files` paths resolve against the config file's directory.
patch_rs_config() {
    local stayrtr_ip
    stayrtr_ip=$(resolve_ip "$STAYRTR")
    if [ -z "$stayrtr_ip" ]; then
        echo "ERROR: cannot resolve management IP for $STAYRTR" >&2
        exit 1
    fi
    log "StayRTR address: ${stayrtr_ip}:3323"
    docker exec "$RUSTBGPD" sh -c \
        "sed 's/STAYRTR_ADDR/${stayrtr_ip}/' /etc/rustbgpd/config.toml > /tmp/config.toml \
         && cp /etc/rustbgpd/m83-hygiene.rpol /tmp/m83-hygiene.rpol"
}

rs_sighup() {
    docker exec "$RUSTBGPD" sh -c '
        pid=$(grep -lF rustbgpd /proc/[0-9]*/comm 2>/dev/null | head -1 | cut -d/ -f3)
        [ -n "$pid" ] && kill -HUP "$pid"
    '
}

inject_gobgp_routes() {
    log "Injecting GoBGP member routes..."
    docker exec "$GOBGP" gobgp global rib add -a ipv4 100.66.0.0/24 \
        origin igp nexthop "$GOBGP_ADDR" med 77 \
        community 65002:222 large-community 65002:2:2 \
        && ok "GoBGP probe 100.66.0.0/24 injected (MED 77, 65002:222, 65002:2:2)" \
        || fail "GoBGP probe injection failed"
    docker exec "$GOBGP" gobgp global rib add -a ipv4 100.65.0.0/24 \
        origin igp nexthop "$GOBGP_ADDR" \
        && ok "GoBGP overlap runner-up 100.65.0.0/24 injected" \
        || fail "GoBGP overlap injection failed"
}

# ---------------------------------------------------------------------------
# Assertion phases
# ---------------------------------------------------------------------------

test_rtr_vrps() {
    log "Assertion 1: StayRTR VRPs loaded over RTR"
    local count=""
    for _ in $(seq 1 30); do
        count=$(prom_value "$RUSTBGPD" 'bgp_rpki_vrp_count{af="ipv4"}')
        [ "${count:-0}" = "2" ] && break
        sleep 2
    done
    if [ "${count:-0}" = "2" ]; then
        ok "bgp_rpki_vrp_count = 2 (both VRPs delivered)"
    else
        fail "bgp_rpki_vrp_count = '${count:-}' (want 2)"
    fi
}

assert_bird_probe() {
    log "Assertions 5-9: BIRD's view of GoBGP's probe 100.66.0.0/24"
    local out=""
    for _ in $(seq 1 30); do
        out=$(birdc_route_all 100.66.0.0/24)
        echo "$out" | grep -q "BGP.as_path" && break
        sleep 2
    done

    local aspath
    aspath=$(echo "$out" | grep "BGP.as_path" | head -1 | sed 's/.*BGP.as_path: *//')
    if [ "$aspath" = "65002" ]; then
        ok "BIRD AS_PATH = '65002' (leftmost = originator, no 65500)"
    else
        fail "BIRD AS_PATH = '$aspath' (want '65002')"
        echo "$out" >&2
    fi
    if echo "$out" | grep -q "BGP.next_hop: ${GOBGP_ADDR}$"; then
        ok "BIRD NEXT_HOP = $GOBGP_ADDR (originator's, unmodified)"
    else
        fail "BIRD NEXT_HOP not preserved (want $GOBGP_ADDR)"
        echo "$out" | grep "BGP.next_hop" >&2 || true
    fi
    if echo "$out" | grep -q "BGP.med: 77"; then
        ok "BIRD MED = 77 verbatim"
    else
        fail "BIRD MED missing/modified (want 77)"
    fi
    if echo "$out" | grep -q "BGP.community:.*(65002,222)"; then
        ok "BIRD standard community (65002,222) verbatim"
    else
        fail "BIRD standard community 65002:222 missing"
    fi
    if echo "$out" | grep -q "BGP.large_community:.*(65002, 2, 2)"; then
        ok "BIRD large community (65002, 2, 2) verbatim"
    else
        fail "BIRD large community 65002:2:2 missing"
    fi
}

assert_frr_probe() {
    log "Assertions 10-14: FRR's view of BIRD's probe 203.0.113.0/24"
    wait_for "203.0.113.0/24 on FRR" 30 frr_has_prefix 203.0.113.0/24 || true

    local aspath
    aspath=$(frr_aspath 203.0.113.0/24)
    if [ "$aspath" = "65001" ]; then
        ok "FRR AS_PATH = '65001' (no 65500)"
    else
        fail "FRR AS_PATH = '$aspath' (want '65001')"
    fi
    local nh
    nh=$(frr_nexthop 203.0.113.0/24)
    if [ "$nh" = "$BIRD_ADDR" ]; then
        ok "FRR NEXT_HOP = $BIRD_ADDR (originator's, unmodified)"
    else
        fail "FRR NEXT_HOP = '$nh' (want $BIRD_ADDR)"
    fi
    local med
    med=$(frr_prefix_json 203.0.113.0/24 | jq -r '.paths[0].med // .paths[0].metric // empty')
    if [ "$med" = "120" ]; then
        ok "FRR MED = 120 verbatim"
    else
        fail "FRR MED = '$med' (want 120)"
    fi
    if frr_prefix_json 203.0.113.0/24 | jq -e '.paths[0].community.string | test("65001:111")' >/dev/null 2>&1; then
        ok "FRR standard community 65001:111 verbatim"
    else
        fail "FRR standard community 65001:111 missing"
    fi
    if frr_prefix_json 203.0.113.0/24 | jq -e '.paths[0].largeCommunity.string | test("65001:1:1")' >/dev/null 2>&1; then
        ok "FRR large community 65001:1:1 verbatim"
    else
        fail "FRR large community 65001:1:1 missing"
    fi
}

assert_gobgp_probe() {
    log "Assertions 15-16: GoBGP's view of FRR's probe 100.67.0.0/24"
    wait_for "100.67.0.0/24 on GoBGP" 30 gobgp_has_prefix 100.67.0.0/24 || true

    if gobgp_prefix_json 100.67.0.0/24 | jq -e '
        .["100.67.0.0/24"][0].attrs[] | select(.type == 2) |
        .as_paths == [{"segment_type": 2, "num": 1, "asns": [65003]}]' >/dev/null 2>&1; then
        ok "GoBGP AS_PATH = [65003] (no 65500)"
    else
        fail "GoBGP AS_PATH for 100.67.0.0/24 not [65003]"
        gobgp_prefix_json 100.67.0.0/24 | jq '.["100.67.0.0/24"][0].attrs' >&2 || true
    fi
    if gobgp_prefix_json 100.67.0.0/24 | jq -e --arg nh "$FRR_ADDR" '
        .["100.67.0.0/24"][0].attrs[] | select(.type == 3) | .nexthop == $nh' >/dev/null 2>&1; then
        ok "GoBGP NEXT_HOP = $FRR_ADDR (originator's, unmodified)"
    else
        fail "GoBGP NEXT_HOP for 100.67.0.0/24 not $FRR_ADDR"
    fi
}

assert_otc_client_views() {
    log "Assertions 17-18: RFC 9234 OTC toward clients (role = route_server)"
    if frr_prefix_json 203.0.113.0/24 \
        | grep -Eiq 'only[ -]?to[ -]?customer|"otc"|onlyToCustomer'; then
        ok "FRR reports OTC on the reflected route"
    else
        fail "FRR does not report OTC on 203.0.113.0/24"
    fi
    if birdc_route_all 100.66.0.0/24 | grep -q "BGP.otc: 65500"; then
        ok "BIRD reports BGP.otc: 65500"
    else
        fail "BIRD does not report BGP.otc: 65500 on 100.66.0.0/24"
        birdc_route_all 100.66.0.0/24 >&2 || true
    fi
}

assert_member_scoped_deny() {
    log "Assertions 19-22: member-scoped export view (100.69.0.0/24 denied to FRR only)"
    wait_for "100.69.0.0/24 on GoBGP" 30 gobgp_has_prefix 100.69.0.0/24 || true

    if frr_has_prefix 100.69.0.0/24; then
        fail "FRR holds 100.69.0.0/24 (member-scoped deny leaked)"
    else
        ok "FRR lacks 100.69.0.0/24 (deny-to-frr applied)"
    fi
    if gobgp_has_prefix 100.69.0.0/24; then
        ok "GoBGP holds 100.69.0.0/24 (deny scoped to FRR only)"
    else
        fail "GoBGP missing 100.69.0.0/24"
    fi
    if rs_ctl rib advertised "$FRR_ADDR" -a ipv4 | grep -qF "100.69.0.0/24"; then
        fail "rbgp rib advertised to FRR lists 100.69.0.0/24"
    else
        ok "rbgp rib advertised to FRR agrees: 100.69.0.0/24 absent"
    fi
    if rs_ctl rib advertised "$GOBGP_ADDR" -a ipv4 | grep -qF "100.69.0.0/24"; then
        ok "rbgp rib advertised to GoBGP agrees: 100.69.0.0/24 present"
    else
        fail "rbgp rib advertised to GoBGP missing 100.69.0.0/24"
    fi
}

assert_rov() {
    log "Assertions 23-25: ROV — RPKI-invalid rejected at import, explain names the term"
    # 100.67.0.0/24 (same member, not-found) already propagated, so the
    # absence of the invalid twin is convergence-safe to assert now.
    if birdc_route_all 100.68.0.0/24 | grep -q "BGP.as_path"; then
        fail "BIRD holds RPKI-invalid 100.68.0.0/24"
    else
        ok "BIRD lacks RPKI-invalid 100.68.0.0/24"
    fi
    if gobgp_has_prefix 100.68.0.0/24; then
        fail "GoBGP holds RPKI-invalid 100.68.0.0/24"
    else
        ok "GoBGP lacks RPKI-invalid 100.68.0.0/24"
    fi
    local explain
    explain=$(rs_ctl policy explain --neighbor "$FRR_ADDR" --prefix 100.68.0.0/24)
    if echo "$explain" | grep -q "reject-rpki-invalid"; then
        ok "import explain names reject-rpki-invalid for 100.68.0.0/24"
    else
        fail "import explain does not name reject-rpki-invalid"
        echo "$explain" >&2
    fi
}

assert_path_hiding_single_best() {
    log "Assertions 26-28: path hiding pinned (FRR single-best, best denied)"
    wait_for "100.65.0.0/24 on GoBGP" 30 \
        sh -c "docker exec $GOBGP gobgp global rib -a ipv4 100.65.0.0/24 -j 2>/dev/null \
            | jq -e '.\"100.65.0.0/24\" | length >= 1'" || true

    if frr_has_prefix 100.65.0.0/24; then
        fail "FRR holds 100.65.0.0/24 in single-best mode (path hiding NOT observed?)"
    else
        ok "FRR receives NOTHING for 100.65.0.0/24 (RFC 7947 §2.3 path hiding, pinned)"
    fi
    # Sanity: the best (BIRD's, tagged 65001:666) does flow to a member
    # whose chain permits it.
    if gobgp_prefix_json 100.65.0.0/24 | jq -e '
        [.["100.65.0.0/24"][].attrs[] | select(.type == 2) | .as_paths[0].asns[0]]
        | index(65001) != null' >/dev/null 2>&1; then
        ok "GoBGP holds BIRD's best for 100.65.0.0/24 (deny is FRR-scoped)"
    else
        fail "GoBGP missing BIRD's path for 100.65.0.0/24"
    fi
    local explain
    explain=$(rs_ctl rib --prefix 100.65.0.0/24 advertised "$FRR_ADDR" --explain)
    if echo "$explain" | grep -q "^Deny" && echo "$explain" | grep -q "deny-to-frr"; then
        ok "export explain: Deny naming deny-to-frr (truthful single-best hiding)"
    else
        fail "export explain did not report Deny via deny-to-frr"
        echo "$explain" >&2
    fi
}

flip_frr_per_client_best() {
    log "Flipping the FRR member to per_client_best (sed + SIGHUP + session bounce)..."
    docker exec "$RUSTBGPD" sh -c \
        'sed -i "s/^per_client_best = false/per_client_best = true/" /tmp/config.toml'
    rs_sighup
    sleep 2
    # The knob is live-effective-next-session (docs/reload-matrix.md):
    # bounce the session from the member side so the new session
    # registers per-client-best with the RIB manager.
    docker exec "$FRR" vtysh -c "clear bgp ${RS_FRR_ADDR}" >/dev/null 2>&1 || true
    wait_frr_established "$FRR" "$RS_FRR_ADDR" "FRR (post per_client_best flip)"
}

assert_per_client_best() {
    log "Assertions 29-33: per-client best-path (RFC 7947 §2.3.2, ADR-0101)"
    if rs_ctl neighbor "$FRR_ADDR" | grep -q "per-client-best"; then
        ok "rbgp neighbor shows Distribution Mode per-client-best"
    else
        fail "Distribution Mode per-client-best not reported"
        rs_ctl neighbor "$FRR_ADDR" >&2 || true
    fi

    wait_for "runner-up 100.65.0.0/24 on FRR" 30 frr_has_prefix 100.65.0.0/24 || true
    local aspath nh
    aspath=$(frr_aspath 100.65.0.0/24)
    if [ "$aspath" = "65002" ]; then
        ok "FRR receives the runner-up (AS_PATH 65002) instead of nothing"
    else
        fail "FRR runner-up AS_PATH = '$aspath' (want '65002')"
    fi
    nh=$(frr_nexthop 100.65.0.0/24)
    if [ "$nh" = "$GOBGP_ADDR" ]; then
        ok "runner-up NEXT_HOP = $GOBGP_ADDR (originator's, still transparent)"
    else
        fail "runner-up NEXT_HOP = '$nh' (want $GOBGP_ADDR)"
    fi

    local explain
    explain=$(rs_ctl rib --prefix 100.65.0.0/24 advertised "$FRR_ADDR" --explain)
    if echo "$explain" | grep -q "candidate 1 of 2" \
        && echo "$explain" | grep -q "denied by export policy" \
        && echo "$explain" | grep -q "deny-to-frr"; then
        ok "explain walks the per-client ladder: candidate 1 of 2 denied by deny-to-frr"
    else
        fail "per-client explain ladder missing/wrong"
        echo "$explain" >&2
    fi
    if echo "$explain" | grep -q "^Advertise" \
        && echo "$explain" | grep -q "Route peer: ${GOBGP_ADDR}"; then
        ok "explain decision Advertise with route peer $GOBGP_ADDR (the runner-up)"
    else
        fail "explain decision/route-peer wrong for the runner-up"
        echo "$explain" >&2
    fi
}

assert_runner_up_withdraw_converges() {
    log "Assertion 34: withdrawing the runner-up's source converges FRR"
    docker exec "$GOBGP" gobgp global rib del -a ipv4 100.65.0.0/24 >/dev/null 2>&1 \
        || log "gobgp rib del returned non-zero"
    local gone=0
    for _ in $(seq 1 30); do
        if ! frr_has_prefix 100.65.0.0/24; then
            gone=1
            break
        fi
        sleep 2
    done
    if [ "$gone" = "1" ]; then
        ok "FRR converged to no path (best still denied, runner-up withdrawn cleanly)"
    else
        fail "FRR still holds 100.65.0.0/24 after the runner-up withdraw"
        frr_prefix_json 100.65.0.0/24 | jq . >&2 || true
    fi
}

assert_add_path_both() {
    log "Assertion 35: Add-Path member sees BOTH paths for 100.70.0.0/24"
    wait_for "2 paths for 100.70.0.0/24 on GoBGP" 30 \
        sh -c "docker exec $GOBGP gobgp global rib -a ipv4 100.70.0.0/24 -j 2>/dev/null \
            | jq -e '.\"100.70.0.0/24\" | length == 2'" || true
    if gobgp_prefix_json 100.70.0.0/24 | jq -e '
        [.["100.70.0.0/24"][].attrs[] | select(.type == 2) | .as_paths[0].asns[0]]
        | sort == [65001, 65003]' >/dev/null 2>&1; then
        ok "GoBGP holds both candidate paths (AS 65001 + AS 65003) via Add-Path"
    else
        fail "GoBGP does not hold both paths for 100.70.0.0/24"
        gobgp_prefix_json 100.70.0.0/24 | jq . >&2 || true
    fi
}

assert_wire() {
    log "Assertions 36-42: byte-level wire pins (tshark on the RS→BIRD capture)"
    # RS→BIRD BGP UPDATEs regardless of which side initiated TCP.
    local base="ip.src == ${RS_BIRD_ADDR} && bgp.type == 2"

    local paths
    paths=$(bird_tshark -Y "$base" -T fields \
        -e bgp.update.path_attribute.as_path_segment.as4 | tr ',' '\n' | sort -u)
    if [ -n "$paths" ] && ! echo "$paths" | grep -qx "65500"; then
        ok "no RS→BIRD UPDATE carries 65500 in any AS_PATH segment (saw: $(echo "$paths" | grep -v '^$' | tr '\n' ' '))"
    else
        fail "AS_PATH wire check failed (segments: $(echo "$paths" | tr '\n' ' '))"
    fi

    if bird_tshark -Y "$base && bgp.nlri_prefix == 100.66.0.0 && bgp.update.path_attribute.next_hop == ${GOBGP_ADDR}" \
        -T fields -e frame.number | grep -q .; then
        ok "wire NEXT_HOP ${GOBGP_ADDR} on the 100.66.0.0/24 UPDATE"
    else
        fail "wire NEXT_HOP for 100.66.0.0/24 not ${GOBGP_ADDR}"
    fi

    if bird_tshark -Y "$base && bgp.nlri_prefix == 100.66.0.0 && bgp.update.path_attribute.multi_exit_disc == 77" \
        -T fields -e frame.number | grep -q .; then
        ok "wire MED 77 verbatim"
    else
        fail "wire MED 77 missing"
    fi

    if bird_tshark -Y "$base && bgp.nlri_prefix == 100.66.0.0 && bgp.update.path_attribute.community_as == 65002 && bgp.update.path_attribute.community_value == 222" \
        -T fields -e frame.number | grep -q .; then
        ok "wire community 65002:222 verbatim"
    else
        fail "wire community 65002:222 missing"
    fi

    if bird_tshark -Y "$base && bgp.nlri_prefix == 100.66.0.0 && bgp.large_communities.ga == 65002 && bgp.large_communities.ldp1 == 2 && bgp.large_communities.ldp2 == 2" \
        -T fields -e frame.number | grep -q .; then
        ok "wire large community 65002:2:2 verbatim"
    else
        fail "wire large community 65002:2:2 missing"
    fi

    if bird_tshark -Y "$base && bgp.update.path_attribute.type_code == 35 && bgp.nlri_prefix" \
        -T fields -e frame.number | grep -q .; then
        ok "wire OTC path attribute (type 35) on RS→BIRD announcements"
    else
        fail "wire OTC attribute (type 35) missing"
    fi

    # EoR ordering over the LAST BIRD session (bounced above over a
    # full RS table, so the flood-then-EoR order is deterministic —
    # the very first session's EoR may legitimately precede member
    # routes that hadn't arrived yet). EoR = empty UPDATE (no
    # withdrawn routes, no path attributes). >= because rustbgpd may
    # pack the last UPDATE and the EoR into one TCP segment.
    local last_open first_eor first_nlri
    last_open=$(bird_tshark -Y "ip.src == ${RS_BIRD_ADDR} && bgp.type == 1" \
        -T fields -e frame.number | tail -1)
    first_eor=$(bird_tshark -Y "$base && frame.number > ${last_open:-0} && bgp.update.withdrawn_routes.length == 0 && bgp.update.path_attributes.length == 0" \
        -T fields -e frame.number | head -1)
    first_nlri=$(bird_tshark -Y "$base && frame.number > ${last_open:-0} && bgp.nlri_prefix" \
        -T fields -e frame.number | head -1)
    if [ -n "$first_eor" ] && [ -n "$first_nlri" ] && [ "$first_eor" -ge "$first_nlri" ]; then
        ok "IPv4-unicast EoR after the table flood (session at frame ${last_open}: NLRI $first_nlri → EoR $first_eor)"
    else
        fail "EoR ordering check failed (open='$last_open', first NLRI='$first_nlri', first EoR='$first_eor')"
    fi
}

# Bounce the BIRD session over the now-full RS table so the last
# session in the capture has a deterministic flood-then-EoR order.
bounce_bird_session() {
    log "Bouncing the BIRD session over the full RS table (EoR ordering probe)..."
    docker exec "$BIRD" birdc restart routeserver >/dev/null 2>&1 || true
    wait_bird_established
    wait_for "100.66.0.0/24 back on BIRD" 30 sh -c \
        "docker exec $BIRD birdc show route all for 100.66.0.0/24 2>/dev/null | grep -q BGP.as_path" \
        || true
}

assert_withdraw_propagation() {
    log "Assertions 43-44: withdraw propagation (BIRD withdraws 203.0.113.0/24)"
    docker exec "$BIRD" birdc disable statics_uniq >/dev/null 2>&1 || true
    local gone_frr=0 gone_gobgp=0
    for _ in $(seq 1 30); do
        frr_has_prefix 203.0.113.0/24 || gone_frr=1
        gobgp_has_prefix 203.0.113.0/24 || gone_gobgp=1
        [ "$gone_frr" = "1" ] && [ "$gone_gobgp" = "1" ] && break
        sleep 2
    done
    if [ "$gone_frr" = "1" ]; then
        ok "203.0.113.0/24 withdrawn from FRR"
    else
        fail "203.0.113.0/24 still on FRR after withdraw"
    fi
    if [ "$gone_gobgp" = "1" ]; then
        ok "203.0.113.0/24 withdrawn from GoBGP"
    else
        fail "203.0.113.0/24 still on GoBGP after withdraw"
    fi
}

assert_reload_stability() {
    log "Assertions 45-46: session stability through a policy reload"
    local estab_before estab_after
    estab_before=$(docker exec "$FRR" vtysh -c "show bgp neighbors ${RS_FRR_ADDR} json" 2>/dev/null \
        | jq -r --arg p "$RS_FRR_ADDR" '.[$p].connectionsEstablished // 0')

    # Content-changing import-chain edit (LP 200 → 210 in
    # prefer-rpki-valid) + SIGHUP: refresh, not session reset.
    docker exec "$RUSTBGPD" sh -c \
        'sed -i "s/set_local_pref = 200/set_local_pref = 210/" /tmp/config.toml'
    rs_sighup
    sleep 6

    estab_after=$(docker exec "$FRR" vtysh -c "show bgp neighbors ${RS_FRR_ADDR} json" 2>/dev/null \
        | jq -r --arg p "$RS_FRR_ADDR" '.[$p].connectionsEstablished // 0')
    if [ -n "$estab_before" ] && [ "$estab_before" = "$estab_after" ] \
        && [ "$estab_after" != "0" ]; then
        ok "FRR session survived the policy reload (connectionsEstablished $estab_before → $estab_after)"
    else
        fail "FRR session bounced across the reload ($estab_before → $estab_after)"
    fi

    if birdc_route_all 100.66.0.0/24 | grep -q "BGP.as_path: 65002"; then
        ok "BIRD still holds 100.66.0.0/24 after the reload (no spurious churn)"
    else
        fail "BIRD lost 100.66.0.0/24 across the policy reload"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    log "M83 interop test: route-server profile, multi-stack (BIRD 2 + GoBGP + FRR + RTR)"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_capture
    start_bird
    start_gobgpd
    patch_rs_config
    start_rustbgpd "/usr/local/bin/rustbgpd /tmp/config.toml"

    test_rtr_vrps
    wait_bird_established
    wait_gobgp_established
    wait_frr_established "$FRR" "$RS_FRR_ADDR" "FRR member"

    inject_gobgp_routes

    assert_bird_probe
    assert_frr_probe
    assert_gobgp_probe
    assert_otc_client_views
    assert_member_scoped_deny
    assert_rov
    assert_path_hiding_single_best
    flip_frr_per_client_best
    assert_per_client_best
    assert_runner_up_withdraw_converges
    assert_add_path_both

    bounce_bird_session
    stop_capture
    assert_wire

    assert_withdraw_propagation
    assert_reload_stability

    print_summary
}

main "$@"
