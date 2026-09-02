#!/usr/bin/env bash
# M107 interop test — RFC 8950 uniform-fleet route server.
#
# Two GoBGP members exchange IPv4 (and IPv6) unicast over IPv6-only
# sessions through a transparent rustbgpd route server whose
# configuration is rendered by tools/rs-config-render from the site under
# tests/interop/m107-rs-rfc8950-uniform-fleet/ (arouteserver `rfc8950`,
# both members IPv6): every member session carries both unicast families,
# so the extended next hop is negotiated, and `next_hop_ownership =
# "strict_peer"` accepts an IPv4 route only with the announcing member's
# own IPv6 address as its next hop.
#
# Exact contract (all assertions counted by test-lib):
#   1     rs-config-render renders the site (exit 0)
#   2-4   the rendered config carries both families, strict_peer, and an
#         explicit rs_control_communities on both member sessions
#   5     rustbgpd --check --strict accepts the rendered config
#   6-8   every generated .rpol passes rbgp policy check
#   9     rustbgpd's UDS management surface answers
#   10    both member sessions reach Established
#   11-12 each member negotiated the extended next-hop capability with the RS
#   13-16 announcements injected: member1 198.51.100.0/24 and 2001:db8:1::/48
#         with next hop 2001:db8:107::11; member2 203.0.113.0/24 with next hop
#         2001:db8:107::12; member1 198.51.100.128/25 with member2's address
#         as a FOREIGN next hop
#   17-19 the RS accepted the three owned routes with the wire next hop intact
#   20    the RS rejected the foreign-next-hop route before policy with reason
#         next_hop_ownership / foreign_next_hop, naming the violating next hop
#   21-23 transparent export: member2 holds 198.51.100.0/24 and 2001:db8:1::/48
#         with next hop 2001:db8:107::11, member1 holds 203.0.113.0/24 with
#         next hop 2001:db8:107::12 — the originating member's IPv6 address,
#         never the route server's
#   24    member2 never receives the foreign-next-hop route
#   25    both sessions are still Established afterwards
#
# Prerequisites:
#   - docker build --target dev -t rustbgpd:dev .
#   - the checksum-pinned gobgp:v4.8.0-m107 image (see the topology header)
#   - containerlab deploy -t tests/interop/m107-rs-rfc8950-uniform-fleet.clab.yml
#   - jq on the host; cargo (builds rs-config-render)
#
# Usage:
#   bash tests/interop/scripts/test-m107-rs-rfc8950-uniform-fleet.sh

TOPO="m107-rs-rfc8950-uniform-fleet"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

REPO_DIR="${REPO_DIR:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"
LAB_DIR="$SCRIPT_DIR/../m107-rs-rfc8950-uniform-fleet"
RS_ADDR="2001:db8:107::9"
MEMBER1_ADDR="2001:db8:107::11"
MEMBER2_ADDR="2001:db8:107::12"
GOBGP_VERSION="gobgpd version 4.8.0"

rs_ctl() {
    docker exec "$RUSTBGPD" rbgp -s unix:///var/lib/rustbgpd/grpc.sock "$@" 2>/dev/null
}

member_container() { echo "clab-${TOPO}-${1:?}"; }

poll() {
    local tries=${1:?} pause=${2:?} label=${3:?}
    shift 3
    for i in $(seq 1 "$tries"); do
        if "$@" >/dev/null 2>&1; then
            ok "$label (attempt $i)"
            return 0
        fi
        sleep "$pause"
    done
    fail "$label — timed out after $((tries * pause))s"
    return 1
}

rs_established_count() {
    rs_ctl neighbor -j | jq '[.[] | select(.state == "Established")] | length' 2>/dev/null || echo 0
}
rs_sessions_up() { [ "$(rs_established_count)" -ge 2 ]; }

# The RS's accepted view of one member, as [{prefix, next_hop}] pairs.
rs_received_next_hop() {
    rs_ctl rib received "${1:?}" -a "${2:?}" -j \
        | jq -r --arg p "${3:?}" '.[]? | select(.prefix == $p) | .next_hop' 2>/dev/null | head -1
}
rs_received_has() { [ -n "$(rs_received_next_hop "$1" "$2" "$3")" ]; }

rs_rejected_ownership() {
    rs_ctl rib received "${1:?}" --rejected -j \
        | jq -e --arg p "${2:?}" --arg nh "${3:?}" '
            [.rejected_routes[]
             | select(.prefix == $p and .reason == "next_hop_ownership"
                      and .reason_detail == "foreign_next_hop" and .next_hop == $nh)]
            | length > 0' >/dev/null 2>&1
}

# A member's Adj-RIB-In from the RS for one prefix: the next hop, or "".
# An RFC 8950 IPv4 route and every IPv6 route carry it inside MP_REACH_NLRI
# (attribute 14); a classic IPv4 route would carry it as NEXT_HOP.
member_next_hop_from_rs() {
    docker exec "$(member_container "${1:?}")" \
        gobgp neighbor "$RS_ADDR" adj-in -a "${2:?}" -j 2>/dev/null \
        | jq -r --arg p "${3:?}" '
            ((.[$p] // [])[0] // {}) as $path
            | ($path.nexthop // ([$path.attrs[]? | select(.type == 14) | .nexthop][0])) // empty'
}
member_has_from_rs()   { [ -n "$(member_next_hop_from_rs "$1" "$2" "$3")" ]; }
member_lacks_from_rs() { [ -z "$(member_next_hop_from_rs "$1" "$2" "$3")" ]; }

# Both OPENs carried the Extended Next Hop capability with the exact
# (IPv4 unicast NLRI, IPv6 next hop) tuple.
member_negotiated_extended_next_hop() {
    docker exec "$(member_container "${1:?}")" gobgp neighbor "$RS_ADDR" -j 2>/dev/null \
        | jq -e '
            def enh_v4_over_v6: any(.[]?; .Cap.ExtendedNexthop.tuples[]?
                | .nlri_family == {afi: 1, safi: 1} and .nexthop_family == {afi: 2, safi: 1});
            (.state.remote_cap | enh_v4_over_v6) and (.state.local_cap | enh_v4_over_v6)
        ' >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Phase 0: render the route server from the site
# ---------------------------------------------------------------------------

RENDER_DIR=""

render_rustbgpd_config() {
    log "Rendering rustbgpd config with rs-config-render from context.yml..."
    RENDER_DIR=$(mktemp -d)
    if cargo run --release -q -p rs-config-render --manifest-path "$REPO_DIR/Cargo.toml" -- \
        --context "$LAB_DIR/context.yml" --out-dir "$RENDER_DIR"; then
        ok "rs-config-render rendered the RFC 8950 uniform fleet (exit 0)"
    else
        fail "rs-config-render refused or failed"
        exit 1
    fi
    local config="$RENDER_DIR/config.toml"
    if [ "$(grep -c '^families = \["ipv4_unicast", "ipv6_unicast"\]$' "$config")" -eq 2 ]; then
        ok "both member sessions carry ipv4_unicast and ipv6_unicast"
    else
        fail "rendered sessions do not carry both unicast families"
    fi
    if [ "$(grep -c '^next_hop_ownership = "strict_peer"$' "$config")" -eq 2 ]; then
        ok "both member sessions bind next_hop_ownership = strict_peer"
    else
        fail "rendered sessions lack strict_peer"
    fi
    if [ "$(grep -c '^rs_control_communities = false$' "$config")" -eq 2 ]; then
        ok "both member sessions state rs_control_communities explicitly (off: no site control communities)"
    else
        fail "rendered sessions do not state rs_control_communities"
    fi

    docker cp "$config" "$RUSTBGPD":/etc/rustbgpd/config.toml
    docker cp "$RENDER_DIR/policy" "$RUSTBGPD":/etc/rustbgpd/policy
    docker cp "$RENDER_DIR/datasets" "$RUSTBGPD":/etc/rustbgpd/datasets

    if docker exec "$RUSTBGPD" /usr/local/bin/rustbgpd --check --strict /etc/rustbgpd/config.toml >/dev/null 2>&1; then
        ok "rendered config passes rustbgpd --check --strict"
    else
        fail "rendered config FAILS rustbgpd --check --strict"
        docker exec "$RUSTBGPD" /usr/local/bin/rustbgpd --check --strict /etc/rustbgpd/config.toml >&2 || true
        exit 1
    fi
    local rpol
    for rpol in rs-hygiene client-as64500-1 client-as64501-1; do
        if docker exec "$RUSTBGPD" rbgp policy check "/etc/rustbgpd/policy/${rpol}.rpol" >/dev/null 2>&1; then
            ok "rbgp policy check ${rpol}.rpol"
        else
            fail "rbgp policy check ${rpol}.rpol failed"
        fi
    done
}

# ---------------------------------------------------------------------------
# Phase 1: daemons and sessions
# ---------------------------------------------------------------------------

start_daemons() {
    log "Starting rustbgpd..."
    docker exec -d "$RUSTBGPD" sh -c \
        '/usr/local/bin/rustbgpd /etc/rustbgpd/config.toml >>/var/log/rustbgpd.log 2>&1'
    poll 20 1 "rustbgpd gRPC (UDS) ready" rs_ctl global \
        || { docker exec "$RUSTBGPD" tail -40 /var/log/rustbgpd.log >&2 || true; exit 1; }

    log "Starting GoBGP members (exact $GOBGP_VERSION)..."
    local m
    for m in member1 member2; do
        if [ "$(docker exec "$(member_container "$m")" gobgpd --version 2>/dev/null)" != "$GOBGP_VERSION" ]; then
            fail "$m does not run $GOBGP_VERSION"
            exit 1
        fi
        docker exec -d "$(member_container "$m")" sh -c \
            'nohup gobgpd -f /config/gobgp.toml >/tmp/gobgpd.log 2>&1'
    done
    poll 45 2 "rustbgpd RS: 2 member sessions Established" rs_sessions_up \
        || rs_ctl neighbor >&2 || true
    for m in member1 member2; do
        poll 10 2 "$m negotiated the extended next-hop capability with the RS" \
            member_negotiated_extended_next_hop "$m" \
            || docker exec "$(member_container "$m")" gobgp neighbor "$RS_ADDR" -j >&2 || true
    done
}

# ---------------------------------------------------------------------------
# Phase 2: announcements
# ---------------------------------------------------------------------------

inject() {
    local member=${1:?} family=${2:?} prefix=${3:?} next_hop=${4:?} label=${5:?}
    if docker exec "$(member_container "$member")" \
        gobgp global rib add -a "$family" "$prefix" origin igp nexthop "$next_hop" >/dev/null 2>&1; then
        ok "$member injected $prefix with next hop $next_hop ($label)"
    else
        fail "$member failed to inject $prefix with next hop $next_hop ($label)"
    fi
}

inject_announcements() {
    log "Injecting IPv4 and IPv6 unicast with IPv6 next hops..."
    inject member1 ipv4 198.51.100.0/24 "$MEMBER1_ADDR" "own next hop, RFC 8950"
    inject member1 ipv6 2001:db8:1::/48 "$MEMBER1_ADDR" "own next hop"
    inject member2 ipv4 203.0.113.0/24 "$MEMBER2_ADDR" "own next hop, RFC 8950"
    inject member1 ipv4 198.51.100.128/25 "$MEMBER2_ADDR" "FOREIGN next hop: member2's address"
}

# ---------------------------------------------------------------------------
# Phase 3: ownership at the route server
# ---------------------------------------------------------------------------

assert_ownership() {
    log "strict_peer at the route server: owned next hops accepted, the foreign one rejected..."
    local prefix member family nh
    for spec in "member1 $MEMBER1_ADDR ipv4 198.51.100.0/24" \
                "member1 $MEMBER1_ADDR ipv6 2001:db8:1::/48" \
                "member2 $MEMBER2_ADDR ipv4 203.0.113.0/24"; do
        set -- $spec
        member=$1; nh=$2; family=$3; prefix=$4
        poll 15 2 "RS accepted $prefix from $member" rs_received_has "$nh" "$family" "$prefix" || continue
        local got
        got=$(rs_received_next_hop "$nh" "$family" "$prefix")
        if [ "$got" = "$nh" ]; then
            ok "RS keeps the wire next hop $got on $prefix from $member"
        else
            fail "RS shows next hop '$got' on $prefix from $member, expected $nh"
        fi
    done
    poll 15 2 "RS rejected 198.51.100.128/25 from member1: next_hop_ownership / foreign_next_hop naming $MEMBER2_ADDR" \
        rs_rejected_ownership "$MEMBER1_ADDR" "198.51.100.128/25" "$MEMBER2_ADDR" \
        || rs_ctl rib received "$MEMBER1_ADDR" --rejected -j >&2 || true
    if [ -z "$(rs_received_next_hop "$MEMBER1_ADDR" ipv4 198.51.100.128/25)" ]; then
        ok "RS accepted view clean of the foreign-next-hop route"
    else
        fail "the foreign-next-hop route leaked into the RS accepted view"
    fi
}

# ---------------------------------------------------------------------------
# Phase 4: transparent export at the members
# ---------------------------------------------------------------------------

assert_transparent_export() {
    log "Transparent export: each member receives the other's routes with the ORIGINATOR's IPv6 next hop..."
    local spec target family prefix nh got
    for spec in "member2 ipv4 198.51.100.0/24 $MEMBER1_ADDR" \
                "member2 ipv6 2001:db8:1::/48 $MEMBER1_ADDR" \
                "member1 ipv4 203.0.113.0/24 $MEMBER2_ADDR"; do
        set -- $spec
        target=$1; family=$2; prefix=$3; nh=$4
        if poll 15 2 "$target receives $prefix from the RS" member_has_from_rs "$target" "$family" "$prefix"; then
            got=$(member_next_hop_from_rs "$target" "$family" "$prefix")
            if [ "$got" = "$nh" ]; then
                ok "$target sees next hop $got on $prefix (originator's address, RS transparent)"
            else
                fail "$target sees next hop '$got' on $prefix, expected the originator $nh"
            fi
        fi
    done
    sleep 2
    if member_lacks_from_rs member2 ipv4 198.51.100.128/25; then
        ok "member2 never receives the foreign-next-hop route"
    else
        fail "member2 RECEIVED the foreign-next-hop route (next hop $(member_next_hop_from_rs member2 ipv4 198.51.100.128/25))"
    fi
}

assert_sessions_survived() {
    log "Post-verdict sanity..."
    if rs_sessions_up; then
        ok "rustbgpd still holds 2 Established member sessions"
    else
        fail "rustbgpd lost a member session ($(rs_established_count)/2 Established)"
    fi
}

cleanup_workdirs() { [ -n "$RENDER_DIR" ] && rm -rf "$RENDER_DIR" || true; }

main() {
    log "M107 interop test: RFC 8950 uniform-fleet route server"
    log "Topology: $TOPO"
    trap 'cleanup_workdirs; _cleanup_on_exit' EXIT

    render_rustbgpd_config
    start_daemons
    inject_announcements
    assert_ownership
    assert_transparent_export
    assert_sessions_survived

    print_summary
}

main "$@"
