#!/usr/bin/env bash
# M77 interop test — GR/LLGR stale preservation for the RR families
# (RFC 4724 / RFC 9494) against checksum-built GoBGP v4.8.0.
#
# rustbgpd is the RECEIVING speaker: a GoBGP PE (VPNv4 + VPNv6 + RTC, GR
# restart-time 60 + LLGR 30 per family) is killed and relaunched with
# `gobgpd -r`; a GoBGP client holds the reflected VPN routes throughout; a
# GoBGP linkstate source (plain GR, restart-time 30) pins the BGP-LS arm.
#
# Validates:
#   1. GR capability negotiated per family: GoBGP's per-neighbor capability
#      view shows both VPN SAFI-128 families + rtc in BOTH the Local and
#      Remote GR (and LLGR) family sets, and ls in the LS source's GR set. rustbgpd
#      does not expose negotiated GR families through its own API, so the
#      Remote section of GoBGP's view is the assertion surface for what
#      rustbgpd advertised; rustbgpd's HELPER behavior is asserted by the
#      wire tests below.
#   2. Baseline reflection: the PE's blue+red VPNv4 routes and two explicit
#      M74-shaped VPNv6 routes reach the client with exact family/source/RD/
#      prefix inventories; the client's own blue VPNv4 route reaches the PE,
#      and the LS square resolves the ORR vantage.
#   3. kill -9 of the PE daemon: RR enters GR (bgp_gr_active_peers), the
#      PE's VPNv4/VPNv6 and RTC routes stay in the RR's RIB marked stale, the
#      client KEEPS the reflected routes (no withdraws on the wire — flap
#      and UPDATE counters toward the client stay flat).
#   4. Controlled `gobgpd -r` relaunch (link held down while the blue VPN
#      route is re-injected, so the re-add always beats End-of-RIB): on
#      re-establish the PE immediately re-receives the client's blue VPNv4
#      route from its GR-PRESERVED RTC membership (RFC 4684 strict empty-
#      membership start would stall it; the wire-observable pin here is
#      the end state plus no extended blackout — GoBGP suppresses its own
#      updates until it has the RR's EoR, so exact "before RTC
#      re-advertisement" ordering is not assertable from outside).
#   5. RFC-strict End-of-RIB sweep: the red VPNv4 and VPNv6 routes were
#      deliberately NOT re-injected — after the PE's family EoRs they are
#      swept from the RR and WITHDRAWN from the client, while both blue
#      routes survive with zero client flaps.
#   6. LLGR two-phase (PE killed again, never returns): at GR-timer expiry
#      the PE's routes promote to llgr_stale (visible in rbgp rib vpn/rtc
#      -j) instead of purging, and the client's copies of blue are
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
#   - docker build --build-arg TARGETARCH=amd64 --build-arg GOBGP_VERSION=4.8.0 \
#       --build-arg GOBGP_SHA256=43b570ae5cc1afab7aebdd9d8f4536e27656465848270c8a6f5fda1ffe093a03 \
#       -t gobgp:v4.8.0-m77 -f tests/interop/Dockerfile.gobgp-v47 tests/interop
#   - containerlab deployed:
#       containerlab deploy -t tests/interop/m77-gr-llgr-rr-gobgp.clab.yml

TOPO="m77-gr-llgr-rr-gobgp"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH

GOBGP_PE="clab-${TOPO}-gobgp-pe"
GOBGP_CLIENT="clab-${TOPO}-gobgp-client"
GOBGP_LS="clab-${TOPO}-gobgp-ls"
readonly GOBGP_IMAGE="gobgp:v4.8.0-m77"
readonly GOBGP_VERSION="gobgp version 4.8.0"
readonly GOBGPD_VERSION="gobgpd version 4.8.0"
readonly GOBGP_BINARY_SHA256="5bd2c6eddab475746d5257c4466f8377b3790bcf7159e18e03a9d44a1685348b"
readonly GOBGPD_BINARY_SHA256="710b7c28d2b83aef887cc28ae6ddcffe82f11a27e0ba263d9f747658b45f8a97"

PE_ADDR="10.0.1.2"
CLIENT_ADDR="10.0.0.2"

BLUE_PREFIX="10.100.1.0/24"
RED_PREFIX="10.200.1.0/24"
CLIENT_PREFIX="10.150.1.0/24"
BLUE_RD="65001:100"
RED_RD="65001:200"
CLIENT_RD="65001:101"
VPN4_FAMILY="l3vpn_ipv4_unicast"
VPN6_FAMILY="l3vpn_ipv6_unicast"

# Explicit M74-proven GoBGP VPNv6 CLI shape. These are MP-BGP routes over the
# existing IPv4 sessions; no IPv6 transport or topology address is required.
BLUE_V6_PREFIX="2001:db8:77:100::/64"
RED_V6_PREFIX="2001:db8:77:200::/64"
VPNV6_NH="2001:db8:77::2"
BLUE_V6_LABEL=77100
RED_V6_LABEL=77200
BLUE_V6_ROUTE=("$BLUE_V6_PREFIX" label "$BLUE_V6_LABEL" rd "$BLUE_RD" rt "$BLUE_RD" nexthop "$VPNV6_NH")
RED_V6_ROUTE=("$RED_V6_PREFIX" label "$RED_V6_LABEL" rd "$RED_RD" rt "$RED_RD" nexthop "$VPNV6_NH")
# PE-unique import-only RT (see gobgp-m77-pe.toml red VRF).
PE_UNIQUE_RT="65001:222"

# RFC 9494 LLGR_STALE community 65535:6 as GoBGP's JSON renders it (u32).
LLGR_STALE_COMMUNITY=4294901766

require_exact() {
    local actual=${1:?} expected=${2:?} label=${3:?}
    if [ "$actual" != "$expected" ]; then
        printf 'ERROR: %s: expected %s, got %s\n' "$label" "$expected" "$actual" >&2
        exit 1
    fi
}

count_exact_default_rtc_rows() {
    local rr=${1:?}
    jq -er --arg rr "$rr" '
        [to_entries[]
         | select(.key == "default" or .key == "0:0:0/0")
         | .key as $prefix
         | .value[]?
         | select(
             .Family == 0
             and .nlri.prefix == $prefix
             and .best == false
             and .stale == false
             and .["peer-address"] == $rr
             and ([.attrs[]? | select(.type == 1 and .value == 0)] | length) == 1
             and ([.attrs[]? | select(.type == 2 and .as_paths == [])] | length) == 1
             and ([.attrs[]? | select(.type == 5 and .value == 100)] | length) == 1
             and ([.attrs[]? | select(
                 .type == 14
                 and .nexthop == $rr
                 and .afi == 1
                 and .safi == 132
                 and (.value | type) == "array"
                 and (.value | length) == 1
                 and .value[0].NLRI.prefix == $prefix
                 and .value[0].ID == 0
             )] | length) == 1
         )]
        | length
    '
}

default_rtc_fixture() {
    local prefix=${1:?} peer=${2:?} nexthop=${3:?}
    jq -cn --arg prefix "$prefix" --arg peer "$peer" --arg nexthop "$nexthop" '
        {($prefix): [{
            Family: 0,
            nlri: {prefix: $prefix},
            best: false,
            stale: false,
            "peer-address": $peer,
            attrs: [
                {type: 1, value: 0},
                {type: 2, as_paths: []},
                {type: 5, value: 100},
                {type: 14, nexthop: $nexthop, afi: 1, safi: 132,
                 value: [{NLRI: {prefix: $prefix}, ID: 0}]}
            ]
        }]}
    '
}

self_test_default_rtc_parser() {
    local rr=10.0.1.1 v46 v48 wrong_membership nonempty_as duplicate
    v46=$(default_rtc_fixture default "$rr" "$rr")
    v48=$(default_rtc_fixture 0:0:0/0 "$rr" "$rr")

    require_exact "$(count_exact_default_rtc_rows "$rr" <<<"$v46")" 1 \
        "GoBGP 4.6 default RTC rendering"
    require_exact "$(count_exact_default_rtc_rows "$rr" <<<"$v48")" 1 \
        "GoBGP 4.8 canonical default RTC rendering"
    require_exact "$(default_rtc_fixture default 10.0.1.9 "$rr" \
        | count_exact_default_rtc_rows "$rr")" 0 "wrong RTC peer-address refusal"
    require_exact "$(default_rtc_fixture default "$rr" 10.0.1.9 \
        | count_exact_default_rtc_rows "$rr")" 0 "wrong RTC next-hop refusal"

    wrong_membership=$(jq -c '
        .default[0].attrs |= map(
            if .type == 14 then .value[0].NLRI.prefix = "65001:65001:100" else . end
        )' <<<"$v46")
    require_exact "$(count_exact_default_rtc_rows "$rr" <<<"$wrong_membership")" 0 \
        "wrong RTC membership refusal"
    nonempty_as=$(jq -c '
        .default[0].attrs |= map(
            if .type == 2 then .as_paths = [{type: 2, asns: [65001]}] else . end
        )' <<<"$v46")
    require_exact "$(count_exact_default_rtc_rows "$rr" <<<"$nonempty_as")" 0 \
        "non-empty default RTC AS_PATH refusal"
    duplicate=$(jq -c '.default += .default' <<<"$v46")
    require_exact "$(count_exact_default_rtc_rows "$rr" <<<"$duplicate")" 2 \
        "duplicate default RTC detection"
    echo "M77 exact default RTC parser self-test passed (7 cases)"
}

preflight_gobgp_identity() {
    local container image_id

    image_id=$(docker image inspect -f '{{.Id}}' "$GOBGP_IMAGE")
    require_exact "$(docker image inspect -f '{{.Architecture}}' "$GOBGP_IMAGE")" \
        amd64 "GoBGP image architecture"
    for container in "$GOBGP_PE" "$GOBGP_CLIENT" "$GOBGP_LS"; do
        require_exact "$(docker inspect -f '{{.Config.Image}}' "$container")" \
            "$GOBGP_IMAGE" "$container configured image"
        require_exact "$(docker inspect -f '{{.Image}}' "$container")" \
            "$image_id" "$container local image identity"
        require_exact "$(docker exec "$container" uname -m)" x86_64 \
            "$container runtime architecture"
        require_exact "$(docker exec "$container" gobgp --version)" \
            "$GOBGP_VERSION" "$container gobgp version"
        require_exact "$(docker exec "$container" gobgpd --version)" \
            "$GOBGPD_VERSION" "$container gobgpd version"
        require_exact "$(docker exec "$container" sha256sum /usr/local/bin/gobgp | cut -d' ' -f1)" \
            "$GOBGP_BINARY_SHA256" "$container gobgp binary SHA-256"
        require_exact "$(docker exec "$container" sha256sum /usr/local/bin/gobgpd | cut -d' ' -f1)" \
            "$GOBGPD_BINARY_SHA256" "$container gobgpd binary SHA-256"
    done
    log "Verified exact GoBGP 4.8.0 image, amd64 runtime, and binary identities"
}

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

strict_prom_scrape() {
    local ip
    ip=$(resolve_ip "$RUSTBGPD") || return 1
    [ -n "$ip" ] || return 1
    curl -sfm 5 "http://${ip}:9179/metrics" 2>/dev/null \
        || wget -qO- -T 5 "http://${ip}:9179/metrics" 2>/dev/null
}

gr_active_total() {
    local scrape
    scrape=$(strict_prom_scrape) || return 1
    awk '/^bgp_gr_active_peers\{/ {s+=$2} END {print s+0}' <<<"$scrape"
}

gr_timer_expired_count() {
    local scrape
    scrape=$(strict_prom_scrape) || return 1
    awk '/^bgp_gr_timer_expired_total\{/ {s+=$2} END {print s+0}' <<<"$scrape"
}

wait_gr_active() {
    local want=${1:?} label=${2:?}
    local current="unavailable"
    log "Waiting for bgp_gr_active_peers == $want ($label)..."
    for i in $(seq 1 30); do
        if current=$(gr_active_total) && [ "$current" -eq "$want" ]; then
            ok "bgp_gr_active_peers == $want ($label, attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "bgp_gr_active_peers never reached $want ($label), got ${current:-unavailable}"
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
        f && (/^    [a-z0-9]/ || /^  [A-Z]/) {f=0; next}
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
    local container=${1:?} rr=${2:?} label=${3:?} count json
    log "Waiting for $label to accept the RR's default RTC NLRI..."
    for i in $(seq 1 30); do
        if json=$(gobgp "$container" neighbor "$rr" adj-in -a rtc -j) \
            && count=$(count_exact_default_rtc_rows "$rr" <<<"$json") \
            && [ "$count" = 1 ]; then
            ok "$label accepted the RR's default RTC NLRI (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label never accepted the RR's default RTC NLRI"
    gobgp "$container" neighbor "$rr" adj-in -a rtc -j | jq . || true
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

# Count RR VPN rows matching family/rd/prefix/peer with a staleness shape.
# $5: "any" | "fresh" | "stale" | "llgr". A failed query returns failure,
# never a synthetic zero: every negative assertion below depends on that.
vpn_row_count() {
    local family=${1:?} rd=${2:?} pfx=${3:?} peer=${4:?} shape=${5:-any}
    local json
    json=$(rustbgpd_vpn_json) || return 1
    jq --arg family "$family" --arg rd "$rd" --arg pfx "$pfx" \
        --arg peer "$peer" --arg shape "$shape" '
        if type == "array" then
            [.[] | select(.afi_safi == $family
                          and .route_distinguisher == $rd
                          and .prefix == $pfx
                          and .peer_address == $peer)
                 | select(
                     if $shape == "fresh" then ((.stale // false) | not) and ((.llgr_stale // false) | not)
                     elif $shape == "stale" then (.stale // false)
                     elif $shape == "llgr" then (.llgr_stale // false)
                     else true end)]
            | length
        else error("VPN query did not return an array") end' <<<"$json"
}

wait_vpn_row() {
    local family=${1:?} rd=${2:?} pfx=${3:?} peer=${4:?} shape=${5:?} label=${6:?}
    local attempts=${7:-30}
    log "Waiting for RR $family row $rd:$pfx from $peer ($shape) — $label..."
    for i in $(seq 1 "$attempts"); do
        local count
        if count=$(vpn_row_count "$family" "$rd" "$pfx" "$peer" "$shape") \
            && [ "$count" -ge 1 ]; then
            ok "RR $family RIB holds $rd:$pfx from $peer as $shape ($label, attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "RR $family RIB never showed $rd:$pfx from $peer as $shape ($label)"
    rustbgpd_vpn_json | jq . || true
    return 1
}

wait_vpn_row_gone() {
    local family=${1:?} rd=${2:?} pfx=${3:?} peer=${4:?} label=${5:?}
    local attempts=${6:-30}
    log "Waiting for RR $family row $rd:$pfx from $peer to be swept — $label..."
    for i in $(seq 1 "$attempts"); do
        local count
        if count=$(vpn_row_count "$family" "$rd" "$pfx" "$peer" any) \
            && [ "$count" -eq 0 ]; then
            ok "RR $family RIB swept $rd:$pfx from $peer ($label, attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "RR $family RIB still holds $rd:$pfx from $peer ($label)"
    rustbgpd_vpn_json | jq . || true
    return 1
}

rustbgpd_vpn_exact_inventory() {
    local family=${1:?} peer=${2:?}
    shift 2
    local json keys
    json=$(rustbgpd_vpn_json) || return 1
    if [ "$#" -eq 0 ]; then
        keys='[]'
    else
        keys=$(printf '%s\n' "$@" | jq -R . | jq -cs .)
    fi
    jq -e --arg family "$family" --arg peer "$peer" --argjson keys "$keys" '
        type == "array"
        and ([.[] | select(.afi_safi == $family and .peer_address == $peer)] as $rows
             | ([$rows[] | "\(.route_distinguisher)|\(.prefix)"] | sort) == ($keys | sort)
               and all($rows[]; .afi_safi == $family and .peer_address == $peer))' \
        <<<"$json" >/dev/null
}

wait_rustbgpd_vpn_inventory() {
    local family=${1:?} peer=${2:?} label=${3:?}
    shift 3
    log "Waiting for exact RR $family inventory from $peer ($label)..."
    for i in $(seq 1 30); do
        if rustbgpd_vpn_exact_inventory "$family" "$peer" "$@"; then
            ok "RR $family has exact family/source/RD/prefix inventory ($label, attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "RR $family family/source/RD/prefix inventory drifted ($label)"
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
    local json
    json=$(rustbgpd_rtc_json) || return 1
    jq --arg peer "$PE_ADDR" --arg shape "$shape" --arg rt "$rt" '
        if type == "array" then
            [.[] | select(.is_default == false and .peer_address == $peer)
                 | select($rt == "" or .route_target == $rt)
                 | select(
                     if $shape == "fresh" then ((.stale // false) | not) and ((.llgr_stale // false) | not)
                     elif $shape == "stale" then (.stale // false)
                     elif $shape == "llgr" then (.llgr_stale // false)
                     else true end)]
            | length
        else error("RTC query did not return an array") end' <<<"$json"
}

wait_pe_unique_rtc_row() {
    local shape=${1:?} label=${2:?}
    local attempts=${3:-30}
    log "Waiting for the PE's RT:$PE_UNIQUE_RT RTC row ($shape) — $label..."
    for i in $(seq 1 "$attempts"); do
        local count
        if count=$(pe_rtc_row_count "$shape" "RT:$PE_UNIQUE_RT") \
            && [ "$count" -ge 1 ]; then
            ok "RR RTC RIB holds the PE's RT:$PE_UNIQUE_RT row as $shape ($label, attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "RR RTC RIB never showed the PE's RT:$PE_UNIQUE_RT row as $shape ($label)"
    rustbgpd_rtc_json | jq . || true
    return 1
}

# GoBGP VPN JSON is keyed "<rd>:<prefix>". State helpers print true/false
# only after a successful command and JSON decode, so absence is fail-closed.
vpnv4_key_state() {
    local container=${1:?} key=${2:?} json
    json=$(gobgp "$container" global rib -a vpnv4 -j) || return 1
    jq -r --arg key "$key" 'if type == "object" then has($key) else error("not an object") end' \
        <<<"$json"
}

vpnv4_key_present() {
    local state
    state=$(vpnv4_key_state "${1:?}" "${2:?}") && [ "$state" = true ]
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
        local state
        if state=$(vpnv4_key_state "$container" "$key") && [ "$state" = false ]; then
            ok "$label dropped $key (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label still holds $key"
    gobgp "$container" global rib -a vpnv4 -j | jq . || true
    return 1
}

client_vpn6_json() {
    gobgp "$GOBGP_CLIENT" neighbor 10.0.0.1 adj-in -a vpnv6 -j
}

client_vpn6_key_state() {
    local key=${1:?} json
    json=$(client_vpn6_json) || return 1
    jq -r --arg key "$key" 'if type == "object" then has($key) else error("not an object") end' \
        <<<"$json"
}

client_vpn6_exact_inventory() {
    local json keys
    json=$(client_vpn6_json) || return 1
    if [ "$#" -eq 0 ]; then
        keys='[]'
    else
        keys=$(printf '%s\n' "$@" | jq -R . | jq -cs .)
    fi
    jq -e --argjson keys "$keys" --arg source "$PE_ADDR" '
        type == "object"
        and ((keys | sort) == ($keys | sort))
        and all(.[];
            length == 1
            and ([.[0].attrs[] | select(.type == 9) | .value] == [$source]))' \
        <<<"$json" >/dev/null
}

wait_client_vpn6_inventory() {
    local label=${1:?}
    shift
    log "Waiting for exact client VPNv6 adj-in inventory ($label)..."
    for i in $(seq 1 30); do
        if client_vpn6_exact_inventory "$@"; then
            ok "client VPNv6 has exact RD/prefix inventory from PE originator ($label, attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "client VPNv6 family/source/RD/prefix inventory drifted ($label)"
    client_vpn6_json | jq . || true
    return 1
}

wait_client_vpn6_key_gone() {
    local key=${1:?} label=${2:?} attempts=${3:-30}
    log "Waiting for client VPNv6 to drop $key ($label)..."
    for i in $(seq 1 "$attempts"); do
        local state
        if state=$(client_vpn6_key_state "$key") && [ "$state" = false ]; then
            ok "client VPNv6 dropped $key ($label, attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "client VPNv6 still holds $key ($label)"
    client_vpn6_json | jq . || true
    return 1
}

wait_client_llgr_stale() {
    local family=${1:?} key=${2:?} label=${3:?}
    log "Waiting for the client's $family $key to carry LLGR_STALE..."
    for i in $(seq 1 15); do
        local json
        if json=$(gobgp "$GOBGP_CLIENT" global rib -a "$family" -j) \
            && jq -e --arg key "$key" --argjson c "$LLGR_STALE_COMMUNITY" '
                (.[$key] // [])
                | [.[] | .attrs[] | select(.type == 8) | .communities // []
                       | select(index($c) != null)]
                | length >= 1' <<<"$json" >/dev/null; then
            ok "client's $label route carries LLGR_STALE (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "client's $label route never carried LLGR_STALE (65535:6)"
    gobgp "$GOBGP_CLIENT" global rib -a "$family" -j | jq . || true
    return 1
}

# ---------------------------------------------------------------------------
# Topology / ORR helpers
# ---------------------------------------------------------------------------

topology_counts() {
    local nodes links
    nodes=$(rbgp topology nodes -j 2>/dev/null \
        | jq 'if type == "array" then length else error("nodes not an array") end' \
        || echo -1)
    links=$(rbgp topology links -j 2>/dev/null \
        | jq 'if type == "array" then length else error("links not an array") end' \
        || echo -1)
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

vantage_state() {
    local json
    json=$(rbgp orr -j 2>/dev/null) || return 1
    jq -r --arg v "$VANTAGE_A" '
        [.vantages[] | select(.vantage == $v and .resolved == true)] | length == 1' \
        <<<"$json"
}

wait_vantage_resolved() {
    local want=${1:?} label=${2:?}
    local attempts=${3:-30}
    log "Waiting for vantage $VANTAGE_A resolved=$want ($label)..."
    for i in $(seq 1 "$attempts"); do
        local got
        if got=$(vantage_state) && [ "$got" = "$want" ]; then
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
    assert_gr_cap_family "$GOBGP_PE" 10.0.1.1 "graceful-restart" "l3vpn-ipv6-unicast" "pe"
    assert_gr_cap_family "$GOBGP_PE" 10.0.1.1 "graceful-restart" "rtc" "pe"
    assert_gr_cap_family "$GOBGP_PE" 10.0.1.1 "long-lived-graceful-restart" "l3vpn-ipv4-unicast" "pe"
    assert_gr_cap_family "$GOBGP_PE" 10.0.1.1 "long-lived-graceful-restart" "l3vpn-ipv6-unicast" "pe"
    assert_gr_cap_family "$GOBGP_PE" 10.0.1.1 "long-lived-graceful-restart" "rtc" "pe"
    assert_gr_cap_family "$GOBGP_LS" 10.0.2.1 "graceful-restart" "ls" "ls-source"
    # The client's LLGR capability is load-bearing for Test 5: rustbgpd
    # strips the LLGR_STALE community toward LLGR-incapable peers. One-sided
    # on purpose — the strip gate keys on what the CLIENT advertised, and
    # the RR (no llgr_stale_time on the client neighbor) advertises none
    # back, so there is no "advertised and received" or Remote section.
    local client_llgr local_families family
    client_llgr=$(cap_block "$GOBGP_CLIENT" 10.0.0.1 "long-lived-graceful-restart")
    local_families=$(awk '
        /Local:/ {f=1; next}
        f && /Remote:/ {exit}
        f {print}
    ' <<<"$client_llgr")
    for family in l3vpn-ipv4-unicast l3vpn-ipv6-unicast; do
        if grep -qE "(^|[[:space:]])${family}(,|[[:space:]]|\$)" <<<"$local_families"; then
            ok "client advertised the LLGR capability for $family"
        else
            fail "client did not advertise the LLGR capability for $family"
            echo "$client_llgr" >&2
        fi
    done
}

test_baseline() {
    log "Test 2: baseline — exact dual-family VPN reflection, LS square resolves the vantage"

    # PE VPN routes (CLI: these die with the daemon — the GR test material).
    gobgp "$GOBGP_PE" vrf blue rib add "$BLUE_PREFIX" nexthop "$PE_ADDR"
    gobgp "$GOBGP_PE" vrf red rib add "$RED_PREFIX" nexthop "$PE_ADDR"
    gobgp "$GOBGP_PE" global rib add -a vpnv6 "${BLUE_V6_ROUTE[@]}"
    gobgp "$GOBGP_PE" global rib add -a vpnv6 "${RED_V6_ROUTE[@]}"
    # The client's own VPN route. Its red membership comes from the
    # config-file red-import VRF (see gobgp-m77-client.toml for why it is
    # NOT a CLI `global rib add -a rtc` widen), so the PE's red route is
    # client-visible and its EoR sweep observable.
    gobgp "$GOBGP_CLIENT" vrf blue rib add "$CLIENT_PREFIX" nexthop "$CLIENT_ADDR"
    inject_square

    wait_vpn_row "$VPN4_FAMILY" "$BLUE_RD" "$BLUE_PREFIX" "$PE_ADDR" fresh "baseline"
    wait_vpn_row "$VPN4_FAMILY" "$RED_RD" "$RED_PREFIX" "$PE_ADDR" fresh "baseline"
    wait_vpn_row "$VPN4_FAMILY" "$CLIENT_RD" "$CLIENT_PREFIX" "$CLIENT_ADDR" fresh "baseline"
    wait_vpn_row "$VPN6_FAMILY" "$BLUE_RD" "$BLUE_V6_PREFIX" "$PE_ADDR" fresh "baseline"
    wait_vpn_row "$VPN6_FAMILY" "$RED_RD" "$RED_V6_PREFIX" "$PE_ADDR" fresh "baseline"
    wait_rustbgpd_vpn_inventory "$VPN6_FAMILY" "$PE_ADDR" baseline \
        "$BLUE_RD|$BLUE_V6_PREFIX" "$RED_RD|$RED_V6_PREFIX"

    wait_vpnv4_key "$GOBGP_CLIENT" "${BLUE_RD}:${BLUE_PREFIX}" "client"
    wait_vpnv4_key "$GOBGP_CLIENT" "${RED_RD}:${RED_PREFIX}" "client"
    wait_vpnv4_key "$GOBGP_PE" "${CLIENT_RD}:${CLIENT_PREFIX}" "pe"
    wait_client_vpn6_inventory baseline \
        "${BLUE_RD}:${BLUE_V6_PREFIX}" "${RED_RD}:${RED_V6_PREFIX}"

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
    wait_vpn_row "$VPN4_FAMILY" "$BLUE_RD" "$BLUE_PREFIX" "$PE_ADDR" stale "GR window"
    wait_vpn_row "$VPN4_FAMILY" "$RED_RD" "$RED_PREFIX" "$PE_ADDR" stale "GR window"
    wait_vpn_row "$VPN6_FAMILY" "$BLUE_RD" "$BLUE_V6_PREFIX" "$PE_ADDR" stale "GR window"
    wait_vpn_row "$VPN6_FAMILY" "$RED_RD" "$RED_V6_PREFIX" "$PE_ADDR" stale "GR window"
    wait_pe_unique_rtc_row stale "GR window"

    # The client's own route must NOT be stale.
    local own_count
    if own_count=$(vpn_row_count "$VPN4_FAMILY" "$CLIENT_RD" "$CLIENT_PREFIX" "$CLIENT_ADDR" fresh) \
        && [ "$own_count" -eq 1 ]; then
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
    wait_client_vpn6_inventory "GR window" \
        "${BLUE_RD}:${BLUE_V6_PREFIX}" "${RED_RD}:${RED_V6_PREFIX}"

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

    log "Re-injecting ONLY the blue VPNv4/VPNv6 routes while the link is down..."
    local injected_v4=0 injected_v6=0
    for i in $(seq 1 20); do
        if gobgp "$GOBGP_PE" vrf blue rib add "$BLUE_PREFIX" nexthop "$PE_ADDR" 2>/dev/null; then
            injected_v4=1
            ok "blue VPNv4 route re-injected before re-establishment (attempt $i)"
            break
        fi
        sleep 1
    done
    for i in $(seq 1 20); do
        if gobgp "$GOBGP_PE" global rib add -a vpnv6 "${BLUE_V6_ROUTE[@]}" 2>/dev/null; then
            injected_v6=1
            ok "blue VPNv6 route re-injected before re-establishment (attempt $i)"
            break
        fi
        sleep 1
    done
    if [ "$injected_v4" -ne 1 ] || [ "$injected_v6" -ne 1 ]; then
        fail "could not re-inject both blue VPN routes after relaunch"
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
    wait_vpn_row "$VPN4_FAMILY" "$BLUE_RD" "$BLUE_PREFIX" "$PE_ADDR" fresh "post-EoR"
    wait_vpn_row "$VPN6_FAMILY" "$BLUE_RD" "$BLUE_V6_PREFIX" "$PE_ADDR" fresh "post-EoR"
    # Red was NOT: each family's RFC-strict EoR sweep removes it from the RR...
    wait_vpn_row_gone "$VPN4_FAMILY" "$RED_RD" "$RED_PREFIX" "$PE_ADDR" "EoR sweep"
    wait_vpn_row_gone "$VPN6_FAMILY" "$RED_RD" "$RED_V6_PREFIX" "$PE_ADDR" "EoR sweep"
    # ...and withdraws it from the client, which keeps both blue routes.
    wait_vpnv4_key_gone "$GOBGP_CLIENT" "${RED_RD}:${RED_PREFIX}" "client"
    wait_client_vpn6_key_gone "${RED_RD}:${RED_V6_PREFIX}" "EoR sweep"
    if vpnv4_key_present "$GOBGP_CLIENT" "${BLUE_RD}:${BLUE_PREFIX}"; then
        ok "client kept the blue VPNv4 route across the PE restart"
    else
        fail "client lost the blue VPNv4 route across the PE restart"
    fi
    wait_rustbgpd_vpn_inventory "$VPN6_FAMILY" "$PE_ADDR" post-EoR \
        "$BLUE_RD|$BLUE_V6_PREFIX"
    wait_client_vpn6_inventory post-EoR "${BLUE_RD}:${BLUE_V6_PREFIX}"

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
    wait_vpn_row "$VPN4_FAMILY" "$BLUE_RD" "$BLUE_PREFIX" "$PE_ADDR" stale "pre-promotion"
    wait_vpn_row "$VPN6_FAMILY" "$BLUE_RD" "$BLUE_V6_PREFIX" "$PE_ADDR" stale "pre-promotion"
    wait_client_vpn6_inventory "second GR window" "${BLUE_RD}:${BLUE_V6_PREFIX}"

    # GR restart-time is 60 s (PE-advertised): poll well past it for the
    # LLGR promotion instead of sleeping blind.
    wait_vpn_row "$VPN4_FAMILY" "$BLUE_RD" "$BLUE_PREFIX" "$PE_ADDR" llgr "LLGR promotion" 50
    wait_vpn_row "$VPN6_FAMILY" "$BLUE_RD" "$BLUE_V6_PREFIX" "$PE_ADDR" llgr "LLGR promotion" 15
    wait_pe_unique_rtc_row llgr "LLGR promotion" 15

    local expired_after
    if expired_after=$(gr_timer_expired_count) && [ "$expired_after" -gt "$expired_before" ]; then
        ok "bgp_gr_timer_expired_total incremented on promotion"
    else
        fail "bgp_gr_timer_expired_total did not increment"
    fi

    # RFC 9494 §4.6 toward the client: both retained routes are re-advertised
    # carrying LLGR_STALE (65535:6), including the new VPNv6 peer proof.
    wait_client_llgr_stale vpnv4 "${BLUE_RD}:${BLUE_PREFIX}" "blue VPNv4"
    wait_client_llgr_stale vpnv6 "${BLUE_RD}:${BLUE_V6_PREFIX}" "blue VPNv6"

    # Effective LLGR stale time = min(local 120, PE per-family 30) = 30 s.
    wait_vpn_row_gone "$VPN4_FAMILY" "$BLUE_RD" "$BLUE_PREFIX" "$PE_ADDR" "LLGR sweep" 40
    wait_vpn_row_gone "$VPN6_FAMILY" "$BLUE_RD" "$BLUE_V6_PREFIX" "$PE_ADDR" "LLGR sweep" 20
    wait_vpnv4_key_gone "$GOBGP_CLIENT" "${BLUE_RD}:${BLUE_PREFIX}" "client (LLGR sweep)" 20
    wait_client_vpn6_key_gone "${BLUE_RD}:${BLUE_V6_PREFIX}" "LLGR sweep" 20
    wait_rustbgpd_vpn_inventory "$VPN6_FAMILY" "$PE_ADDR" expiry
    wait_client_vpn6_inventory expiry

    local rtc_count
    if rtc_count=$(pe_rtc_row_count any) && [ "$rtc_count" -eq 0 ]; then
        ok "PE's RTC rows swept with the LLGR expiry"
    else
        fail "PE RTC rows survived the LLGR sweep"
        rustbgpd_rtc_json | jq . || true
    fi
    wait_gr_active 0 "LLGR retention over"

    # The client's own route must have survived the whole lifecycle.
    local own_count
    if own_count=$(vpn_row_count "$VPN4_FAMILY" "$CLIENT_RD" "$CLIENT_PREFIX" "$CLIENT_ADDR" fresh) \
        && [ "$own_count" -eq 1 ]; then
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
    local vantage
    if vantage=$(vantage_state) && [ "$vantage" = true ]; then
        ok "ORR vantage $VANTAGE_A still RESOLVED during the LS GR window"
    else
        fail "ORR vantage un-resolved during the LS GR window"
        rbgp orr -j | jq . || true
    fi

    # Never comes back: GR expiry (restart-time 30, no LLGR) purges the
    # topology and un-resolves the vantage.
    wait_topology_counts 0 0 "LS GR expiry" 40
    wait_vantage_resolved false "LS GR expiry"
    local expired_after
    if expired_after=$(gr_timer_expired_count) && [ "$expired_after" -gt "$expired_before" ]; then
        ok "bgp_gr_timer_expired_total incremented for the LS source"
    else
        fail "bgp_gr_timer_expired_total did not increment for the LS source"
    fi
}

test_no_dataplane_install() {
    log "Test 7: RR installed nothing into any dataplane"

    local mpls ipv4 ipv6
    if capture_ip_routes mpls "$RUSTBGPD" MPLS -M route show; then
        if [ -z "$mpls" ]; then
            ok "RR MPLS routing table is empty"
        else
            fail "RR has unexpected MPLS routes"
            printf '%s\n' "$mpls" >&2
        fi
    fi

    if capture_ip_routes ipv4 "$RUSTBGPD" IPv4 -4 route show table all; then
        if grep -qE "${BLUE_PREFIX%/*}|${RED_PREFIX%/*}|${CLIENT_PREFIX%/*}" <<<"$ipv4"; then
            fail "RR kernel routing table contains a VPN-derived route"
            printf '%s\n' "$ipv4" >&2
        else
            ok "RR kernel routing table has no VPN-derived routes"
        fi
    fi

    if capture_ip_routes ipv6 "$RUSTBGPD" IPv6 -6 route show table all; then
        if grep -qF "${BLUE_V6_PREFIX%/*}" <<<"$ipv6" \
            || grep -qF "${RED_V6_PREFIX%/*}" <<<"$ipv6"; then
            fail "RR IPv6 table-all contains a VPNv6 inner prefix"
            printf '%s\n' "$ipv6" >&2
        else
            ok "RR IPv6 table-all lacks both VPNv6 inner prefixes"
        fi
    fi
}

capture_ip_routes() {
    local output_var=$1 container=$2 table_label=$3 captured
    shift 3
    if ! captured=$(docker exec "$container" ip "$@" 2>&1); then
        fail "$container $table_label route inspection failed"
        printf '%s\n' "$captured" >&2
        return 1
    fi
    printf -v "$output_var" '%s' "$captured"
}

main() {
    log "M77 interop test: VPNv4/VPNv6/RTC GR+LLGR and BGP-LS GR via GoBGP"
    log "Topology: $TOPO"

    preflight
    preflight_gobgp_identity
    resolve_grpc_addr
    start_gobgpd "$GOBGP_PE"
    start_gobgpd "$GOBGP_CLIENT"
    start_gobgpd "$GOBGP_LS"
    # M77 uses the topology-bound default config.
    # shellcheck disable=SC2119
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

if [ "${1:-}" = "--self-test-default-rtc-parser" ]; then
    self_test_default_rtc_parser
    exit 0
fi

# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

main "$@"
