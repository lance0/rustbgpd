#!/usr/bin/env bash
# M53 spike — ADR-0069 BGP unnumbered FRR behavior observation.
#
# This is not the final rustbgpd interop. It records the target FRR behavior
# needed for Tranche 3:
#   - interface-bound BGP session over IPv6 link-local only;
#   - IPv4 NLRI exchanged with IPv6 link-local next-hop;
#   - exact MP_REACH next-hop length for IPv4-over-link-local;
#   - whether FRR exposes RFC 8950 Extended Next Hop and capability 77.

set -euo pipefail

TOPO="m53-bgp-unnumbered-spike"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUSTBGPD="clab-${TOPO}-frr-left"
source "$SCRIPT_DIR/test-lib.sh"

LEFT="clab-${TOPO}-frr-left"
RIGHT="clab-${TOPO}-frr-right"

wait_any_established() {
    local frr=$1 label=$2
    log "Waiting for $label BGP interface peer to reach Established..."
    for _ in $(seq 1 45); do
        local json
        json=$(docker exec "$frr" vtysh -c "show bgp summary json" 2>/dev/null || true)
        if printf '%s\n' "$json" | grep -q '"state":"Established"\|"bgpState":"Established"'; then
            ok "$label Established"
            return 0
        fi
        sleep 2
    done
    fail "$label did not reach Established"
    dump_debug
    return 1
}

assert_no_ipv4_on_fabric() {
    for frr in "$LEFT" "$RIGHT"; do
        if docker exec "$frr" ip -4 addr show dev eth1 | grep -q ' inet '; then
            fail "$frr has an IPv4 address on eth1"
            docker exec "$frr" ip addr show dev eth1 >&2 || true
            return 1
        fi
    done
    ok "No IPv4 addresses present on the FRR-FRR fabric link"
}

assert_ipv4_route_with_link_local_nh() {
    local frr=$1 prefix=$2 label=$3
    log "Checking $label learned $prefix with an IPv6 link-local next-hop..."
    for _ in $(seq 1 30); do
        local json
        json=$(docker exec "$frr" vtysh -c "show bgp ipv4 unicast $prefix json" 2>/dev/null || true)
        if printf '%s\n' "$json" | grep -qi 'fe80:'; then
            ok "$label learned $prefix with fe80:: next-hop"
            return 0
        fi
        sleep 1
    done
    fail "$label did not show $prefix with a link-local next-hop"
    dump_debug
    return 1
}

observe_capabilities() {
    local frr=$1 label=$2
    local json
    json=$(docker exec "$frr" vtysh -c "show bgp neighbors json" 2>/dev/null || true)

    if printf '%s\n' "$json" | grep -qi 'extendedNexthop\|extended-nexthop\|capabilityCode":5'; then
        ok "$label reports RFC 8950 Extended Next Hop capability"
    else
        fail "$label did not expose Extended Next Hop capability in FRR JSON"
    fi

    if printf '%s\n' "$json" | grep -q 'capabilityCode":77\|linkLocalNextHop\|link-local next-hop'; then
        log "ADR-0069 observation: $label appears to advertise Link-Local Next Hop capability 77"
    else
        log "ADR-0069 observation: $label did not expose Link-Local Next Hop capability 77"
    fi
}

ensure_tcpdump() {
    if docker exec "$LEFT" sh -lc 'command -v tcpdump >/dev/null'; then
        return 0
    fi

    log "Installing tcpdump in $LEFT for MP_REACH wire-shape observation..."
    docker exec "$LEFT" sh -lc \
        'apk add --no-cache tcpdump >/tmp/m53-apk-tcpdump.log 2>&1 || { cat /tmp/m53-apk-tcpdump.log >&2; exit 1; }'
}

start_bgp_capture() {
    ensure_tcpdump
    docker exec "$LEFT" sh -lc 'rm -f /tmp/m53-bgp.pcap /tmp/m53-tcpdump.log'
    docker exec -d "$LEFT" sh -lc \
        'tcpdump -i eth1 -s 0 -w /tmp/m53-bgp.pcap "tcp port 179" >/tmp/m53-tcpdump.log 2>&1'
    sleep 1
}

stop_bgp_capture() {
    docker exec "$LEFT" sh -lc 'pkill -INT tcpdump >/dev/null 2>&1 || pkill tcpdump >/dev/null 2>&1 || true'
    sleep 1
}

assert_mp_reach_wire_shape() {
    log "Capturing FRR MP_REACH shape after BGP clear..."
    start_bgp_capture

    docker exec "$LEFT" vtysh -c "clear bgp *" >/dev/null 2>&1 || true
    docker exec "$RIGHT" vtysh -c "clear bgp *" >/dev/null 2>&1 || true

    wait_any_established "$LEFT" "frr-left after clear"
    wait_any_established "$RIGHT" "frr-right after clear"
    assert_ipv4_route_with_link_local_nh "$LEFT" "198.51.100.1/32" "frr-left after clear"
    assert_ipv4_route_with_link_local_nh "$RIGHT" "192.0.2.1/32" "frr-right after clear"

    # FRR can repopulate local route state before tcpdump has flushed the UPDATE
    # carrying MP_REACH to disk; keep the capture open briefly after convergence.
    sleep 5
    stop_bgp_capture

    local decoded
    decoded=$(docker exec "$LEFT" sh -lc 'tcpdump -nn -vvv -r /tmp/m53-bgp.pcap 2>/dev/null' || true)
    if printf '%s\n' "$decoded" | grep -q 'Multi-Protocol Reach NLRI' \
        && printf '%s\n' "$decoded" | grep -q 'nh-length: 32' \
        && printf '%s\n' "$decoded" | grep -qi 'fe80' \
        && printf '%s\n' "$decoded" | grep -q '198.51.100.1/32\|192.0.2.1/32'; then
        ok "FRR MP_REACH for IPv4-over-link-local uses 32-byte IPv6 next-hop"
    else
        fail "FRR MP_REACH capture did not show a 32-byte link-local next-hop"
        echo "$decoded" >&2
    fi

    if printf '%s\n' "$decoded" | grep -q 'Capability 77\|Link-Local Next Hop'; then
        log "ADR-0069 observation: packet capture appears to include Link-Local Next Hop capability 77"
    else
        ok "FRR OPEN capture did not expose Link-Local Next Hop capability 77"
    fi
}

dump_debug() {
    for frr in "$LEFT" "$RIGHT"; do
        echo "===== $frr interfaces =====" >&2
        docker exec "$frr" ip addr show dev eth1 >&2 || true
        echo "===== $frr show bgp summary =====" >&2
        docker exec "$frr" vtysh -c "show bgp summary" >&2 || true
        echo "===== $frr show bgp neighbors json =====" >&2
        docker exec "$frr" vtysh -c "show bgp neighbors json" >&2 || true
        echo "===== $frr show bgp ipv4 unicast json =====" >&2
        docker exec "$frr" vtysh -c "show bgp ipv4 unicast json" >&2 || true
    done
}

main() {
    log "M53 spike: FRR BGP unnumbered behavior"
    preflight

    assert_no_ipv4_on_fabric
    wait_any_established "$LEFT" "frr-left"
    wait_any_established "$RIGHT" "frr-right"
    assert_ipv4_route_with_link_local_nh "$LEFT" "198.51.100.1/32" "frr-left"
    assert_ipv4_route_with_link_local_nh "$RIGHT" "192.0.2.1/32" "frr-right"
    observe_capabilities "$LEFT" "frr-left"
    observe_capabilities "$RIGHT" "frr-right"
    assert_mp_reach_wire_shape

    print_summary
}

main "$@"
