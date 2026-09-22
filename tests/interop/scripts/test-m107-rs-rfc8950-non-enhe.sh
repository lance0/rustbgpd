#!/usr/bin/env bash
# M107 sibling interop test — RFC 8950 suppression to non-ENHE receiver.
#
# Validates:
#   1. Route server establishes sessions to:
#      - member1 (GoBGP, AS64500): capable of ENHE (RFC 8950)
#      - member2 (GoBGP, AS64501): capable of ENHE (RFC 8950)
#      - member3 (FRR,   AS64502): non-ENHE client (no capability extended-nexthop)
#   2. member1 injects:
#      - IPv4 198.51.100.0/24 with IPv6 next-hop 2001:db8:107::11
#      - IPv6 2001:db8:1::/48 with IPv6 next-hop 2001:db8:107::11
#   3. RS accepts both routes with wire next-hops preserved.
#   4. Transparent export:
#      - member2 (capable) receives 198.51.100.0/24 with next hop 2001:db8:107::11
#      - member3 (non-ENHE) has 198.51.100.0/24 WITHHELD (RFC 8950 suppression; paths=0)
#      - member3 (non-ENHE) still receives 2001:db8:1::/48 normally
#   5. Enabling extended-nexthop capability on member3 restores 198.51.100.0/24 to member3.

set -euo pipefail

TOPO="m107-rs-rfc8950-non-enhe"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

RS_ADDR="2001:db8:107::9"
MEMBER1_ADDR="2001:db8:107::11"
MEMBER2_ADDR="2001:db8:107::12"
MEMBER3_ADDR="2001:db8:107::13"

FRR_M3="clab-${TOPO}-member3"

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

rs_sessions_up() { [ "$(rs_established_count)" -ge 3 ]; }

rs_received_next_hop() {
    rs_ctl rib received "${1:?}" -a "${2:?}" -j \
        | jq -r --arg p "${3:?}" '.[]? | select(.prefix == $p) | .next_hop' 2>/dev/null | head -1
}
rs_received_has() { [ -n "$(rs_received_next_hop "$1" "$2" "$3")" ]; }

member_next_hop_from_rs() {
    docker exec "$(member_container "${1:?}")" \
        gobgp neighbor "$RS_ADDR" adj-in -a "${2:?}" -j 2>/dev/null \
        | jq -r --arg p "${3:?}" '
            ((.[$p] // [])[0] // {}) as $path
            | ($path.nexthop // ([$path.attrs[]? | select(.type == 14) | .nexthop][0])) // empty'
}
member_has_from_rs() { [ -n "$(member_next_hop_from_rs "$1" "$2" "$3")" ]; }

member_negotiated_extended_next_hop() {
    docker exec "$(member_container "${1:?}")" gobgp neighbor "$RS_ADDR" -j 2>/dev/null \
        | jq -e '
            def enh_v4_over_v6: any(.[]?; .Cap.ExtendedNexthop.tuples[]?
                | .nlri_family == {afi: 1, safi: 1} and .nexthop_family == {afi: 2, safi: 1});
            (.state.remote_cap | enh_v4_over_v6) and (.state.local_cap | enh_v4_over_v6)
        ' >/dev/null 2>&1
}

start_daemons() {
    log "Starting rustbgpd..."
    docker exec -d "$RUSTBGPD" sh -c \
        '/usr/local/bin/rustbgpd /etc/rustbgpd/config.toml >>/var/log/rustbgpd.log 2>&1'
    poll 20 1 "rustbgpd gRPC (UDS) ready" rs_ctl global \
        || { docker exec "$RUSTBGPD" tail -40 /var/log/rustbgpd.log >&2 || true; exit 1; }

    log "Starting GoBGP members..."
    for m in member1 member2; do
        docker exec -d "$(member_container "$m")" sh -c \
            'nohup gobgpd -f /config/gobgp.toml >/tmp/gobgpd.log 2>&1'
    done

    log "Starting FRR member3..."
    docker exec "$FRR_M3" /usr/lib/frr/frrinit.sh start >/dev/null

    poll 45 2 "rustbgpd RS: 3 member sessions Established" rs_sessions_up \
        || rs_ctl neighbor >&2 || true

    for m in member1 member2; do
        poll 10 2 "$m negotiated extended next-hop capability with RS" \
            member_negotiated_extended_next_hop "$m" \
            || docker exec "$(member_container "$m")" gobgp neighbor "$RS_ADDR" -j >&2 || true
    done

    local m3_caps
    m3_caps=$(docker exec "$FRR_M3" vtysh -c "show bgp neighbors $RS_ADDR json" 2>/dev/null || true)
    if echo "$m3_caps" | grep -qi "extendedNexthop"; then
        fail "member3 unexpectedly negotiated extended-nexthop"
    else
        ok "member3 (FRR) did NOT negotiate extended-nexthop capability"
    fi
}

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
    log "Injecting IPv4 and IPv6 unicast from member1..."
    inject member1 ipv4 198.51.100.0/24 "$MEMBER1_ADDR" "IPv4 with IPv6 NH (RFC 8950)"
    inject member1 ipv6 2001:db8:1::/48 "$MEMBER1_ADDR" "IPv6 native"
}

assert_ownership() {
    log "Verifying RS accepted both routes from member1..."
    poll 15 2 "RS accepted 198.51.100.0/24 from member1" rs_received_has "$MEMBER1_ADDR" ipv4 198.51.100.0/24
    poll 15 2 "RS accepted 2001:db8:1::/48 from member1" rs_received_has "$MEMBER1_ADDR" ipv6 2001:db8:1::/48

    local nh4 nh6
    nh4=$(rs_received_next_hop "$MEMBER1_ADDR" ipv4 198.51.100.0/24)
    nh6=$(rs_received_next_hop "$MEMBER1_ADDR" ipv6 2001:db8:1::/48)
    [ "$nh4" = "$MEMBER1_ADDR" ] && ok "RS preserved wire IPv6 next-hop $nh4 on IPv4 route" || fail "RS next-hop $nh4 != $MEMBER1_ADDR"
    [ "$nh6" = "$MEMBER1_ADDR" ] && ok "RS preserved wire IPv6 next-hop $nh6 on IPv6 route" || fail "RS next-hop $nh6 != $MEMBER1_ADDR"
}

assert_rfc8950_suppression() {
    log "Asserting export behavior: present on capable client, withheld on non-capable client..."

    # member2 (capable of ENHE) must receive the IPv4 route with IPv6 next-hop
    poll 15 2 "member2 receives 198.51.100.0/24 from RS" member_has_from_rs member2 ipv4 198.51.100.0/24
    local got_nh
    got_nh=$(member_next_hop_from_rs member2 ipv4 198.51.100.0/24)
    if [ "$got_nh" = "$MEMBER1_ADDR" ]; then
        ok "member2 (capable) received 198.51.100.0/24 with originator IPv6 next-hop $got_nh"
    else
        fail "member2 received 198.51.100.0/24 with unexpected next-hop $got_nh"
    fi

    # member3 (non-ENHE) must have the IPv4 route WITHHELD
    sleep 3
    local m3_v4_routes m3_v4_count
    m3_v4_routes=$(docker exec "$FRR_M3" vtysh -c "show bgp ipv4 unicast 198.51.100.0/24 json" 2>/dev/null || true)
    m3_v4_count=$(echo "$m3_v4_routes" | jq '.paths | length' 2>/dev/null || echo 0)
    if [ "$m3_v4_count" -eq 0 ] || [ -z "$m3_v4_routes" ]; then
        ok "member3 (non-ENHE): IPv4 route with IPv6 next-hop is WITHHELD (paths=0, RFC 8950 suppression)"
    else
        fail "member3 (non-ENHE): IPv4 route was unexpectedly exported: $m3_v4_routes"
    fi

    # member3 (non-ENHE) must STILL receive the IPv6 route
    local m3_v6_routes m3_v6_count
    m3_v6_routes=$(docker exec "$FRR_M3" vtysh -c "show bgp ipv6 unicast 2001:db8:1::/48 json" 2>/dev/null || true)
    m3_v6_count=$(echo "$m3_v6_routes" | jq '.paths | length' 2>/dev/null || echo 0)
    if [ "$m3_v6_count" -gt 0 ]; then
        ok "member3 (non-ENHE): IPv6 route 2001:db8:1::/48 received normally ($m3_v6_count path)"
    else
        fail "member3 (non-ENHE): IPv6 route was lost"
    fi

    # Now enable extended-nexthop on member3 (FRR) and verify the withheld route is exported
    log "Enabling capability extended-nexthop on member3 (FRR)..."
    docker exec "$FRR_M3" vtysh \
        -c "configure terminal" \
        -c "router bgp 64502" \
        -c "neighbor $RS_ADDR capability extended-nexthop" >/dev/null 2>&1
    docker exec "$FRR_M3" vtysh -c "clear bgp $RS_ADDR" >/dev/null 2>&1

    poll 20 2 "member3 re-established with extended-nexthop enabled" \
        bash -c "docker exec '$FRR_M3' vtysh -c 'show bgp neighbors $RS_ADDR json' 2>/dev/null | jq -e '.\"$RS_ADDR\".bgpState == \"Established\"'"

    poll 15 2 "member3 receives 198.51.100.0/24 after enabling extended-nexthop" \
        bash -c "docker exec '$FRR_M3' vtysh -c 'show bgp ipv4 unicast 198.51.100.0/24 json' 2>/dev/null | jq -e '(.paths | length) > 0'"

    local m3_restored_nh
    m3_restored_nh=$(docker exec "$FRR_M3" vtysh -c "show bgp ipv4 unicast 198.51.100.0/24 json" 2>/dev/null \
        | jq -r '.paths[0].nexthops[0].ip // empty')
    if [ "$m3_restored_nh" = "$MEMBER1_ADDR" ]; then
        ok "member3 receives 198.51.100.0/24 with wire IPv6 next-hop $m3_restored_nh after capability negotiation"
    else
        fail "member3 next-hop $m3_restored_nh != $MEMBER1_ADDR"
    fi
}

main() {
    log "M107 sibling interop test: RFC 8950 suppression to non-ENHE receiver"
    log "Topology: $TOPO"
    trap '_cleanup_on_exit' EXIT

    start_daemons
    inject_announcements
    assert_ownership
    assert_rfc8950_suppression

    print_summary
}

main "$@"
