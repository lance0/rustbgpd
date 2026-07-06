#!/usr/bin/env bash
# M77 interop test — GR/LLGR stale preservation for the RR families
# (RFC 4724 / RFC 9494) against GoBGP v4.
#
# rustbgpd is the RECEIVING speaker: a GoBGP PE (VPNv4 + RTC, GR
# restart-time 60 + LLGR 30 per family) is killed and relaunched with
# `gobgpd -r`; a GoBGP client holds the reflected VPN routes throughout; a
# GoBGP linkstate source (plain GR, restart-time 30) pins the BGP-LS arm.
#
# Validates:
#   1. GR capability negotiated per family: GoBGP's per-neighbor capability
#      view shows l3vpn-ipv4-unicast + rtc in BOTH the Local and Remote GR
#      (and LLGR) family sets, and ls in the LS source's GR set. rustbgpd
#      does not expose negotiated GR families through its own API, so the
#      Remote section of GoBGP's view is the assertion surface for what
#      rustbgpd advertised; rustbgpd's HELPER behavior is asserted by the
#      wire tests below.
#   2. Baseline reflection: PE's blue+red VPN routes reach the client (its
#      RTC membership is blue from config + red CLI-widened), the client's
#      own blue VPN route reaches the PE, the LS square resolves the ORR
#      vantage.
#   3. kill -9 of the PE daemon: RR enters GR (bgp_gr_active_peers), the
#      PE's VPN and RTC routes stay in the RR's RIB marked stale, the
#      client KEEPS both reflected routes (no withdraws on the wire — flap
#      and UPDATE counters toward the client stay flat).
#   4. Controlled `gobgpd -r` relaunch (link held down while the blue VPN
#      route is re-injected, so the re-add always beats End-of-RIB): on
#      re-establish the PE immediately re-receives the client's blue VPN
#      route from its GR-PRESERVED RTC membership (RFC 4684 strict empty-
#      membership start would stall it; the wire-observable pin here is
#      the end state plus no extended blackout — GoBGP suppresses its own
#      updates until it has the RR's EoR, so exact "before RTC
#      re-advertisement" ordering is not assertable from outside).
#   5. RFC-strict End-of-RIB sweep: the red VPN route was deliberately NOT
#      re-injected — after the PE's EoR it is swept from the RR and
#      WITHDRAWN from the client, while blue survives with zero client
#      flaps.
#   6. LLGR two-phase (PE killed again, never returns): at GR-timer expiry
#      the PE's routes promote to llgr_stale (visible in rbgp rib vpn/rtc
#      -j) instead of purging, and the client's copy of blue is
#      re-advertised carrying the LLGR_STALE community (65535:6 — the
#      client advertises the LLGR capability; rustbgpd strips the
#      community toward LLGR-incapable peers); at LLGR-timer expiry
#      everything is swept and the client finally sees the withdraw.
#   7. BGP-LS/ORR survival: killing the LS source leaves the topology feed
#      intact (stale) — rbgp topology stays 4 nodes / 4 links and the ORR
#      vantage stays RESOLVED through the GR window; the source never
#      returns, so GR expiry purges the topology and un-resolves the
#      vantage (no LLGR on this peer on purpose).
#   8. No dataplane writes on the RR.
#
# Prerequisites:
#   - docker build --target dev -t rustbgpd:dev .
#   - docker build -t gobgp:bgpls -f tests/interop/Dockerfile.gobgp-bgpls tests/interop
#   - containerlab deployed:
#       containerlab deploy -t tests/interop/m77-gr-llgr-rr-gobgp.clab.yml

TOPO="m77-gr-llgr-rr-gobgp"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"

GOBGP_PE="clab-${TOPO}-gobgp-pe"
GOBGP_CLIENT="clab-${TOPO}-gobgp-client"
GOBGP_LS="clab-${TOPO}-gobgp-ls"

PE_ADDR="10.0.1.2"
CLIENT_ADDR="10.0.0.2"

BLUE_PREFIX="10.100.1.0/24"
RED_PREFIX="10.200.1.0/24"
CLIENT_PREFIX="10.150.1.0/24"
BLUE_RD="65001:100"
RED_RD="65001:200"
CLIENT_RD="65001:101"
# PE-unique import-only RT (see gobgp-m77-pe.toml red VRF).
PE_UNIQUE_RT="65001:222"

# RFC 9494 LLGR_STALE community 65535:6 as GoBGP's JSON renders it (u32).
LLGR_STALE_COMMUNITY=4294901766

# The M76 square: vantage A (10.0.8.1) is a node with cost-1 and cost-10
# links; only its presence/absence matters here, not the metrics.
VANTAGE_A="10.0.8.1"
RID_A="1.1.1.1"
RID_B="2.2.2.2"
RID_X="9.9.9.1"
RID_Y="9.9.9.2"

ls_link_args() {
    echo "link protocol 3 identifier 0 \
local-asn 65001 local-bgp-ls-id 1 local-igp-router-id $1 \
remote-asn 65001 remote-bgp-ls-id 1 remote-igp-router-id $2 \
ipv4-interface-address $3 ipv4-neighbor-address $4 metric $5"
}

inject_square() {
    # shellcheck disable=SC2046
    gobgp "$GOBGP_LS" global rib add -a ls $(ls_link_args "$RID_A" "$RID_X" 10.0.8.1 10.0.9.1 1)
    # shellcheck disable=SC2046
    gobgp "$GOBGP_LS" global rib add -a ls $(ls_link_args "$RID_A" "$RID_Y" 10.0.8.1 10.0.9.2 10)
    # shellcheck disable=SC2046
    gobgp "$GOBGP_LS" global rib add -a ls $(ls_link_args "$RID_B" "$RID_X" 10.0.8.2 10.0.9.1 10)
    # shellcheck disable=SC2046
    gobgp "$GOBGP_LS" global rib add -a ls $(ls_link_args "$RID_B" "$RID_Y" 10.0.8.2 10.0.9.2 1)
}

# ---------------------------------------------------------------------------
# Daemon lifecycle helpers
# ---------------------------------------------------------------------------

start_gobgpd() {
    local container=${1:?}
    local extra=${2:-}
    log "Starting gobgpd in $container${extra:+ (flags: $extra)}..."
    docker exec -d "$container" sh -c \
        "nohup gobgpd -f /config/gobgp.toml $extra >/tmp/gobgpd.log 2>&1"
}

# kill -9 so no NOTIFICATION is sent: RFC 4724 GR procedures only trigger
# on a session that drops without one. The gobgp image has no procps, so
# walk /proc.
kill_gobgpd() {
    local container=${1:?}
    log "kill -9 gobgpd in $container..."
    docker exec "$container" sh -c '
        for p in /proc/[0-9]*; do
            [ "$(cat "$p/comm" 2>/dev/null)" = "gobgpd" ] && kill -9 "${p#/proc/}"
        done
        true'
}

pe_link() {
    docker exec "$GOBGP_PE" ip link set eth1 "${1:?}"
}

gobgp() {
    local container=${1:?}
    shift
    docker exec "$container" gobgp "$@" 2>/dev/null
}

gobgp_neighbor() {
    gobgp "${1:?}" neighbor 2>/dev/null || true
}

rbgp() {
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 "$@"
}

rustbgpd_vpn_json() {
    rbgp rib vpn -j
}

rustbgpd_rtc_json() {
    rbgp rib rtc -j
}

rustbgpd_bgpls_json() {
    rbgp rib bgpls -j
}

rustbgpd_neighbor_json() {
    rbgp neighbor "${1:?}" -j
}

# ---------------------------------------------------------------------------
# Metric helpers (prometheus text over the RR's management IP)
# ---------------------------------------------------------------------------

gr_active_total() {
    prom_scrape "$RUSTBGPD" \
        | awk '/^bgp_gr_active_peers\{/ {s+=$2} END {print s+0}'
}

gr_timer_expired_count() {
    prom_scrape "$RUSTBGPD" \
        | awk '/^bgp_gr_timer_expired_total\{/ {s+=$2} END {print s+0}'
}

wait_gr_active() {
    local want=${1:?} label=${2:?}
    log "Waiting for bgp_gr_active_peers == $want ($label)..."
    for i in $(seq 1 30); do
        if [ "$(gr_active_total)" -eq "$want" ]; then
            ok "bgp_gr_active_peers == $want ($label, attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "bgp_gr_active_peers never reached $want ($label), got $(gr_active_total)"
    return 1
}

# ---------------------------------------------------------------------------
# Session + capability helpers
# ---------------------------------------------------------------------------

wait_gobgp_established() {
    local container=${1:?} peer=${2:?} label=${3:?}
    log "Waiting for $label session to $peer..."
    for i in $(seq 1 45); do
        local state
        state=$(gobgp_neighbor "$container" | grep -F -- "$peer" || true)
        if echo "$state" | grep -qi "establ"; then
            ok "$label session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label session did not reach Established within 90s"
    gobgp_neighbor "$container" || true
    return 1
}

# The capability block for one capability name: from "    <cap>:" up to (not
# including) the next 4-space-indented capability or the 2-space-indented
# "Message statistics" section.
cap_block() {
    local container=${1:?} peer=${2:?} cap=${3:?}
    gobgp "$container" neighbor "$peer" | awk -v cap="    ${cap}:" '
        index($0, cap) == 1 {f=1; print; next}
        f && (/^    [a-z0-9]/ || /^  [A-Z]/) {exit}
        f {print}'
}

# Assert a family appears in a capability block that is both advertised and
# received AND carries a Remote (peer = rustbgpd) section listing it.
assert_gr_cap_family() {
    local container=${1:?} peer=${2:?} cap=${3:?} family=${4:?} label=${5:?}
    local block first_line family_count
    block=$(cap_block "$container" "$peer" "$cap")
    first_line=${block%%$'\n'*}
    family_count=$(grep -cE "(^|[[:space:]])${family}(,|[[:space:]]|\$)" <<<"$block" || true)
    if [[ "$first_line" == *"advertised and received"* ]] \
        && grep -q "Remote:" <<<"$block" \
        && [ "$family_count" -ge 2 ]; then
        ok "$label: $family in local AND remote $cap capability"
    else
        fail "$label: $family missing from the $cap capability exchange"
        echo "$block" >&2
    fi
}

# m75 wire pin: GoBGP must ACCEPT the RR's self-originated default RTC NLRI
# into adj-in — it is what defeats GoBGP's outbound RTC filter toward the
# RR, so the PE's VPN routes flow at all.
wait_default_rtc_accepted() {
    local container=${1:?} rr=${2:?} label=${3:?}
    log "Waiting for $label to accept the RR's default RTC NLRI..."
    for i in $(seq 1 30); do
        if gobgp "$container" neighbor "$rr" adj-in -a rtc | grep -qi "default"; then
            ok "$label accepted the RR's default RTC NLRI (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label never accepted the RR's default RTC NLRI"
    gobgp "$container" neighbor "$rr" adj-in -a rtc || true
    return 1
}

flap_count() {
    rustbgpd_neighbor_json "${1:?}" | jq -r '.flap_count'
}

updates_sent() {
    rustbgpd_neighbor_json "${1:?}" | jq -r '.updates_sent'
}

assert_no_flap() {
    local peer=${1:?} baseline=${2:?} label=${3:?}
    local now state
    now=$(flap_count "$peer")
    state=$(rustbgpd_neighbor_json "$peer" | jq -r '.state')
    if [ "$now" = "$baseline" ] && [ "$state" = "Established" ]; then
        ok "$label: session Established, flap count unchanged ($now)"
    else
        fail "$label: session flapped (flap_count $baseline -> $now, state $state)"
    fi
}

# ---------------------------------------------------------------------------
# VPN / RTC RIB helpers
# ---------------------------------------------------------------------------

# Count RR VPN rows matching rd/prefix/peer with a given staleness shape.
# $4: "any" | "fresh" | "stale" | "llgr"
vpn_row_count() {
    local rd=${1:?} pfx=${2:?} peer=${3:?} shape=${4:-any}
    rustbgpd_vpn_json | jq --arg rd "$rd" --arg pfx "$pfx" \
        --arg peer "$peer" --arg shape "$shape" '
        [.[] | select(.route_distinguisher == $rd
                      and .prefix == $pfx
                      and .peer_address == $peer)
             | select(
                 if $shape == "fresh" then ((.stale // false) | not) and ((.llgr_stale // false) | not)
                 elif $shape == "stale" then (.stale // false)
                 elif $shape == "llgr" then (.llgr_stale // false)
                 else true end)]
        | length' 2>/dev/null || echo 0
}

wait_vpn_row() {
    local rd=${1:?} pfx=${2:?} peer=${3:?} shape=${4:?} label=${5:?}
    local attempts=${6:-30}
    log "Waiting for RR VPN row $rd:$pfx from $peer ($shape) — $label..."
    for i in $(seq 1 "$attempts"); do
        if [ "$(vpn_row_count "$rd" "$pfx" "$peer" "$shape")" -ge 1 ]; then
            ok "RR VPN RIB holds $rd:$pfx from $peer as $shape ($label, attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "RR VPN RIB never showed $rd:$pfx from $peer as $shape ($label)"
    rustbgpd_vpn_json | jq . || true
    return 1
}

wait_vpn_row_gone() {
    local rd=${1:?} pfx=${2:?} peer=${3:?} label=${4:?}
    local attempts=${5:-30}
    log "Waiting for RR VPN row $rd:$pfx from $peer to be swept — $label..."
    for i in $(seq 1 "$attempts"); do
        if [ "$(vpn_row_count "$rd" "$pfx" "$peer" any)" -eq 0 ]; then
            ok "RR VPN RIB swept $rd:$pfx from $peer ($label, attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "RR VPN RIB still holds $rd:$pfx from $peer ($label)"
    rustbgpd_vpn_json | jq . || true
    return 1
}

# Count of the PE's non-default RTC rows in a staleness shape, optionally
# pinned to one route_target. NOTE: rbgp rib rtc reads the Loc-RIB (best
# path per NLRI only) and the blue /96 is dual-originated by the PE and the
# client (and the red /96 by the client's CLI widen) — a PE-attributed row
# legitimately flips to the client's fresh copy the moment the PE's goes
# stale (stale rank demotion). The PE's staleness lifecycle is therefore
# pinned on the import-only RT 65001:222 /96 that ONLY the PE originates.
pe_rtc_row_count() {
    local shape=${1:-any} rt=${2:-}
    rustbgpd_rtc_json | jq --arg peer "$PE_ADDR" --arg shape "$shape" --arg rt "$rt" '
        [.[] | select(.is_default == false and .peer_address == $peer)
             | select($rt == "" or .route_target == $rt)
             | select(
                 if $shape == "fresh" then ((.stale // false) | not) and ((.llgr_stale // false) | not)
                 elif $shape == "stale" then (.stale // false)
                 elif $shape == "llgr" then (.llgr_stale // false)
                 else true end)]
        | length' 2>/dev/null || echo 0
}

wait_pe_unique_rtc_row() {
    local shape=${1:?} label=${2:?}
    local attempts=${3:-30}
    log "Waiting for the PE's RT:$PE_UNIQUE_RT RTC row ($shape) — $label..."
    for i in $(seq 1 "$attempts"); do
        if [ "$(pe_rtc_row_count "$shape" "RT:$PE_UNIQUE_RT")" -ge 1 ]; then
            ok "RR RTC RIB holds the PE's RT:$PE_UNIQUE_RT row as $shape ($label, attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "RR RTC RIB never showed the PE's RT:$PE_UNIQUE_RT row as $shape ($label)"
    rustbgpd_rtc_json | jq . || true
    return 1
}

# GoBGP vpnv4 JSON is keyed "<rd>:<prefix>".
vpnv4_key_present() {
    gobgp "${1:?}" global rib -a vpnv4 -j \
        | jq -e --arg key "${2:?}" 'has($key)' >/dev/null
}

wait_vpnv4_key() {
    local container=${1:?} key=${2:?} label=${3:?}
    log "Waiting for $label to hold $key..."
    for i in $(seq 1 30); do
        if vpnv4_key_present "$container" "$key"; then
            ok "$label holds $key (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label missing $key"
    gobgp "$container" global rib -a vpnv4 -j | jq . || true
    return 1
}

wait_vpnv4_key_gone() {
    local container=${1:?} key=${2:?} label=${3:?}
    local attempts=${4:-30}
    log "Waiting for $label to drop $key..."
    for i in $(seq 1 "$attempts"); do
        if ! vpnv4_key_present "$container" "$key"; then
            ok "$label dropped $key (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label still holds $key"
    gobgp "$container" global rib -a vpnv4 -j | jq . || true
    return 1
}

# ---------------------------------------------------------------------------
# Topology / ORR helpers
# ---------------------------------------------------------------------------

topology_counts() {
    local nodes links
    nodes=$(rbgp topology nodes -j 2>/dev/null | jq 'length' || echo -1)
    links=$(rbgp topology links -j 2>/dev/null | jq 'length' || echo -1)
    echo "$nodes $links"
}

wait_topology_counts() {
    local nodes=${1:?} links=${2:?} label=${3:?}
    local attempts=${4:-30}
    log "Waiting for topology $nodes nodes / $links links ($label)..."
    for i in $(seq 1 "$attempts"); do
        if [ "$(topology_counts)" = "$nodes $links" ]; then
            ok "topology is $nodes nodes / $links links ($label, attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "topology never reached $nodes nodes / $links links ($label), got: $(topology_counts)"
    rbgp topology links -j | jq . || true
    return 1
}

vantage_resolved() {
    rbgp orr -j 2>/dev/null | jq -e --arg v "$VANTAGE_A" \
        '[.vantages[] | select(.vantage == $v and .resolved == true)] | length == 1' \
        >/dev/null
}

wait_vantage_resolved() {
    local want=${1:?} label=${2:?}
    local attempts=${3:-30}
    log "Waiting for vantage $VANTAGE_A resolved=$want ($label)..."
    for i in $(seq 1 "$attempts"); do
        local got=false
        vantage_resolved && got=true
        if [ "$got" = "$want" ]; then
            ok "vantage $VANTAGE_A resolved=$want ($label, attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "vantage $VANTAGE_A never reached resolved=$want ($label)"
    rbgp orr -j | jq . || true
    return 1
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

test_capabilities() {
    log "Test 1: per-family GR/LLGR capability exchange"

    assert_gr_cap_family "$GOBGP_PE" 10.0.1.1 "graceful-restart" "l3vpn-ipv4-unicast" "pe"
    assert_gr_cap_family "$GOBGP_PE" 10.0.1.1 "graceful-restart" "rtc" "pe"
    assert_gr_cap_family "$GOBGP_PE" 10.0.1.1 "long-lived-graceful-restart" "l3vpn-ipv4-unicast" "pe"
    assert_gr_cap_family "$GOBGP_PE" 10.0.1.1 "long-lived-graceful-restart" "rtc" "pe"
    assert_gr_cap_family "$GOBGP_LS" 10.0.2.1 "graceful-restart" "ls" "ls-source"
    # The client's LLGR capability is load-bearing for Test 5: rustbgpd
    # strips the LLGR_STALE community toward LLGR-incapable peers. One-sided
    # on purpose — the strip gate keys on what the CLIENT advertised, and
    # the RR (no llgr_stale_time on the client neighbor) advertises none
    # back, so there is no "advertised and received" or Remote section.
    local client_llgr local_families
    client_llgr=$(cap_block "$GOBGP_CLIENT" 10.0.0.1 "long-lived-graceful-restart")
    local_families=$(awk '
        /Local:/ {f=1; n=0; next}
        f && n < 4 {print; n++}
    ' <<<"$client_llgr")
    if grep -qE "(^|[[:space:]])l3vpn-ipv4-unicast(,|[[:space:]]|\$)" <<<"$local_families"; then
        ok "client advertised the LLGR capability for l3vpn-ipv4-unicast"
    else
        fail "client did not advertise the LLGR capability for l3vpn-ipv4-unicast"
        echo "$client_llgr" >&2
    fi
}

test_baseline() {
    log "Test 2: baseline — VPN reflection per RTC membership, LS square resolves the vantage"

    # PE VPN routes (CLI: these die with the daemon — the GR test material).
    gobgp "$GOBGP_PE" vrf blue rib add "$BLUE_PREFIX" nexthop "$PE_ADDR"
    gobgp "$GOBGP_PE" vrf red rib add "$RED_PREFIX" nexthop "$PE_ADDR"
    # The client's own VPN route. Its red membership comes from the
    # config-file red-import VRF (see gobgp-m77-client.toml for why it is
    # NOT a CLI `global rib add -a rtc` widen), so the PE's red route is
    # client-visible and its EoR sweep observable.
    gobgp "$GOBGP_CLIENT" vrf blue rib add "$CLIENT_PREFIX" nexthop "$CLIENT_ADDR"
    inject_square

    wait_vpn_row "$BLUE_RD" "$BLUE_PREFIX" "$PE_ADDR" fresh "baseline"
    wait_vpn_row "$RED_RD" "$RED_PREFIX" "$PE_ADDR" fresh "baseline"
    wait_vpn_row "$CLIENT_RD" "$CLIENT_PREFIX" "$CLIENT_ADDR" fresh "baseline"

    wait_vpnv4_key "$GOBGP_CLIENT" "${BLUE_RD}:${BLUE_PREFIX}" "client"
    wait_vpnv4_key "$GOBGP_CLIENT" "${RED_RD}:${RED_PREFIX}" "client"
    wait_vpnv4_key "$GOBGP_PE" "${CLIENT_RD}:${CLIENT_PREFIX}" "pe"

    wait_topology_counts 4 4 "square injected"
    wait_vantage_resolved true "square injected"
}

test_kill_preserves_stale() {
    log "Test 3: kill -9 the PE — routes preserved stale, client untouched"

    local client_flaps client_updates
    client_flaps=$(flap_count "$CLIENT_ADDR")
    client_updates=$(updates_sent "$CLIENT_ADDR")

    kill_gobgpd "$GOBGP_PE"

    wait_gr_active 1 "PE killed"
    wait_vpn_row "$BLUE_RD" "$BLUE_PREFIX" "$PE_ADDR" stale "GR window"
    wait_vpn_row "$RED_RD" "$RED_PREFIX" "$PE_ADDR" stale "GR window"
    wait_pe_unique_rtc_row stale "GR window"

    # The client's own route must NOT be stale.
    if [ "$(vpn_row_count "$CLIENT_RD" "$CLIENT_PREFIX" "$CLIENT_ADDR" fresh)" -eq 1 ]; then
        ok "client's own VPN route unaffected by the PE's GR"
    else
        fail "client's VPN route went stale alongside the PE's"
        rustbgpd_vpn_json | jq . || true
    fi

    # The wire: the client KEEPS both reflected routes and sees nothing.
    if vpnv4_key_present "$GOBGP_CLIENT" "${BLUE_RD}:${BLUE_PREFIX}" \
        && vpnv4_key_present "$GOBGP_CLIENT" "${RED_RD}:${RED_PREFIX}"; then
        ok "client still holds both reflected VPN routes during the GR window"
    else
        fail "client lost a reflected VPN route during the GR window"
        gobgp "$GOBGP_CLIENT" global rib -a vpnv4 -j | jq . || true
    fi

    sleep 6
    local updates_after
    updates_after=$(updates_sent "$CLIENT_ADDR")
    if [ "$updates_after" = "$client_updates" ]; then
        ok "zero UPDATEs toward the client across GR entry (updates_sent $client_updates unchanged)"
    else
        fail "RR sent UPDATEs to the client at GR entry ($client_updates -> $updates_after)"
    fi
    assert_no_flap "$CLIENT_ADDR" "$client_flaps" "GR window/client"
}

test_relaunch_gr_completes() {
    log "Test 4: gobgpd -r relaunch — blue re-advertised, red swept at End-of-RIB"

    local client_flaps
    client_flaps=$(flap_count "$CLIENT_ADDR")

    # Hold the BGP link down through the relaunch so the blue re-injection
    # always beats session re-establishment (and therefore the EoR that
    # gates GoBGP's LocalRestarting sync). The gRPC API listens on
    # localhost, unaffected by eth1.
    pe_link down
    start_gobgpd "$GOBGP_PE" "-r"

    log "Re-injecting ONLY the blue VPN route while the link is down..."
    local injected=0
    for i in $(seq 1 20); do
        if gobgp "$GOBGP_PE" vrf blue rib add "$BLUE_PREFIX" nexthop "$PE_ADDR" 2>/dev/null; then
            injected=1
            ok "blue VPN route re-injected before re-establishment (attempt $i)"
            break
        fi
        sleep 1
    done
    if [ "$injected" -ne 1 ]; then
        fail "could not re-inject the blue VPN route after relaunch"
        docker exec "$GOBGP_PE" cat /tmp/gobgpd.log >&2 || true
    fi
    pe_link up

    wait_gobgp_established "$GOBGP_PE" 10.0.1.1 "pe (restarted)" || return 1

    # No R-bit assertion here on purpose: gobgp's CLI recomputes the
    # "Local" capability view from CURRENT config state, and gobgpd clears
    # LocalRestarting the moment sync finishes — so the restart flag it
    # really sent in the OPEN is no longer displayed by the time the
    # session is queryable ("sync finished" lands ~40 ms after Peer Up).
    # The -r behavior is pinned by the EoR-driven assertions below instead.

    # GR-preserved RTC membership: the client's blue route flows to the PE
    # again in the initial dump (empty-membership start would stall it).
    wait_vpnv4_key "$GOBGP_PE" "${CLIENT_RD}:${CLIENT_PREFIX}" "restarted pe"

    # Blue was re-advertised: stale flag cleared, route survives.
    wait_vpn_row "$BLUE_RD" "$BLUE_PREFIX" "$PE_ADDR" fresh "post-EoR"
    # Red was NOT: the RFC-strict EoR sweep removes it from the RR...
    wait_vpn_row_gone "$RED_RD" "$RED_PREFIX" "$PE_ADDR" "EoR sweep"
    # ...and withdraws it from the client, which keeps blue.
    wait_vpnv4_key_gone "$GOBGP_CLIENT" "${RED_RD}:${RED_PREFIX}" "client"
    if vpnv4_key_present "$GOBGP_CLIENT" "${BLUE_RD}:${BLUE_PREFIX}"; then
        ok "client kept the blue route across the PE restart"
    else
        fail "client lost the blue route across the PE restart"
    fi

    # RTC membership re-advertised from the config VRFs: rows fresh again.
    wait_pe_unique_rtc_row fresh "post-EoR"
    wait_gr_active 0 "GR completed by EoR"
    assert_no_flap "$CLIENT_ADDR" "$client_flaps" "restart/client"
}

test_llgr_two_phase() {
    log "Test 5: PE killed and never returns — LLGR promotion, then sweep"

    local expired_before
    expired_before=$(gr_timer_expired_count)

    kill_gobgpd "$GOBGP_PE"
    wait_gr_active 1 "second PE kill"
    wait_vpn_row "$BLUE_RD" "$BLUE_PREFIX" "$PE_ADDR" stale "pre-promotion"

    # GR restart-time is 60 s (PE-advertised): poll well past it for the
    # LLGR promotion instead of sleeping blind.
    wait_vpn_row "$BLUE_RD" "$BLUE_PREFIX" "$PE_ADDR" llgr "LLGR promotion" 50
    wait_pe_unique_rtc_row llgr "LLGR promotion" 15

    if [ "$(gr_timer_expired_count)" -gt "$expired_before" ]; then
        ok "bgp_gr_timer_expired_total incremented on promotion"
    else
        fail "bgp_gr_timer_expired_total did not increment"
    fi

    # RFC 9494 §4.6 toward the client: the retained route is re-advertised
    # carrying LLGR_STALE (65535:6).
    log "Waiting for the client's blue route to carry LLGR_STALE..."
    local tagged=0
    for i in $(seq 1 15); do
        if gobgp "$GOBGP_CLIENT" global rib -a vpnv4 -j 2>/dev/null \
            | jq -e --arg key "${BLUE_RD}:${BLUE_PREFIX}" --argjson c "$LLGR_STALE_COMMUNITY" '
                (.[$key] // [])
                | [.[] | .attrs[] | select(.type == 8) | .communities // []
                       | select(index($c) != null)]
                | length >= 1' >/dev/null; then
            tagged=1
            ok "client's blue route carries the LLGR_STALE community (attempt $i)"
            break
        fi
        sleep 2
    done
    if [ "$tagged" -ne 1 ]; then
        fail "client's blue route never carried LLGR_STALE (65535:6)"
        gobgp "$GOBGP_CLIENT" global rib -a vpnv4 -j | jq . || true
    fi

    # Effective LLGR stale time = min(local 120, PE per-family 30) = 30 s.
    wait_vpn_row_gone "$BLUE_RD" "$BLUE_PREFIX" "$PE_ADDR" "LLGR sweep" 40
    wait_vpnv4_key_gone "$GOBGP_CLIENT" "${BLUE_RD}:${BLUE_PREFIX}" "client (LLGR sweep)" 20

    if [ "$(pe_rtc_row_count any)" -eq 0 ]; then
        ok "PE's RTC rows swept with the LLGR expiry"
    else
        fail "PE RTC rows survived the LLGR sweep"
        rustbgpd_rtc_json | jq . || true
    fi
    wait_gr_active 0 "LLGR retention over"

    # The client's own route must have survived the whole lifecycle.
    if [ "$(vpn_row_count "$CLIENT_RD" "$CLIENT_PREFIX" "$CLIENT_ADDR" fresh)" -eq 1 ]; then
        ok "client's own VPN route survived the PE's full GR+LLGR lifecycle"
    else
        fail "client's VPN route was damaged by the PE's GR+LLGR lifecycle"
        rustbgpd_vpn_json | jq . || true
    fi
}

test_ls_gr_window() {
    log "Test 6: LS source killed — topology stale but ORR stays resolved; expiry un-resolves"

    local expired_before
    expired_before=$(gr_timer_expired_count)

    kill_gobgpd "$GOBGP_LS"
    wait_gr_active 1 "LS source killed"

    # Stale BGP-LS routes stay in the topology feed on purpose (that is
    # what keeps ORR vantages resolved through the restart window).
    local stale_ls
    stale_ls=$(rustbgpd_bgpls_json \
        | jq '[.[] | select(.stale // false)] | length' 2>/dev/null || echo 0)
    if [ "$stale_ls" -ge 4 ]; then
        ok "BGP-LS routes marked stale during the GR window ($stale_ls rows)"
    else
        fail "expected >= 4 stale BGP-LS rows, got $stale_ls"
        rustbgpd_bgpls_json | jq . || true
    fi

    if [ "$(topology_counts)" = "4 4" ]; then
        ok "topology intact (4 nodes / 4 links) during the LS GR window"
    else
        fail "topology degraded during the LS GR window: $(topology_counts)"
    fi
    if vantage_resolved; then
        ok "ORR vantage $VANTAGE_A still RESOLVED during the LS GR window"
    else
        fail "ORR vantage un-resolved during the LS GR window"
        rbgp orr -j | jq . || true
    fi

    # Never comes back: GR expiry (restart-time 30, no LLGR) purges the
    # topology and un-resolves the vantage.
    wait_topology_counts 0 0 "LS GR expiry" 40
    wait_vantage_resolved false "LS GR expiry"
    if [ "$(gr_timer_expired_count)" -gt "$expired_before" ]; then
        ok "bgp_gr_timer_expired_total incremented for the LS source"
    else
        fail "bgp_gr_timer_expired_total did not increment for the LS source"
    fi
}

test_no_dataplane_install() {
    log "Test 7: RR installed nothing into any dataplane"

    local mpls
    mpls=$(docker exec "$RUSTBGPD" ip -M route show 2>/dev/null || true)
    if [ -z "$mpls" ]; then
        ok "RR MPLS routing table is empty"
    else
        fail "RR has unexpected MPLS routes"
        echo "$mpls" >&2
    fi

    if docker exec "$RUSTBGPD" ip route show \
        | grep -qE "${BLUE_PREFIX%/*}|${RED_PREFIX%/*}|${CLIENT_PREFIX%/*}"; then
        fail "RR kernel routing table contains a VPN-derived route"
        docker exec "$RUSTBGPD" ip route show >&2 || true
    else
        ok "RR kernel routing table has no VPN-derived routes"
    fi
}

main() {
    log "M77 interop test: GR/LLGR RR-family stale preservation via GoBGP"
    log "Topology: $TOPO"

    preflight
    resolve_grpc_addr
    start_gobgpd "$GOBGP_PE"
    start_gobgpd "$GOBGP_CLIENT"
    start_gobgpd "$GOBGP_LS"
    start_rustbgpd

    wait_gobgp_established "$GOBGP_PE" 10.0.1.1 "pe" || exit 1
    wait_gobgp_established "$GOBGP_CLIENT" 10.0.0.1 "client" || exit 1
    wait_gobgp_established "$GOBGP_LS" 10.0.2.1 "ls-source" || exit 1

    wait_default_rtc_accepted "$GOBGP_PE" 10.0.1.1 "pe"
    wait_default_rtc_accepted "$GOBGP_CLIENT" 10.0.0.1 "client"

    test_capabilities
    test_baseline
    test_kill_preserves_stale
    test_relaunch_gr_completes
    test_llgr_two_phase
    test_ls_gr_window
    test_no_dataplane_install

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
