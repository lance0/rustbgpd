#!/usr/bin/env bash
# Guided route-server RPKI and import-policy exercise.
set -euo pipefail

if [[ $# != 1 ]]; then
    echo 'usage: lab.sh up|verify|break|explain|down' >&2
    exit 2
fi
case "$1" in
    up|verify|break|explain|down) ;;
    *) echo "unknown ixp phase: $1" >&2; exit 2 ;;
esac

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
compose=(docker compose --project-name rustbgpd-lab-ixp
    --file "$repo_root/labs/ixp/docker-compose.yml")

rb() {
    "${compose[@]}" exec -T rustbgpd rbgp -s http://127.0.0.1:50051 "$@"
}

member_a() {
    "${compose[@]}" exec -T member-a vtysh "$@"
}

sessions() {
    rb --json neighbor | python3 -c '
import json, sys
peers = json.load(sys.stdin)
sys.exit(not all(any(p.get("address") == address and p.get("remote_asn") == asn
    and p.get("state") == "Established" and not p.get("stale", False) for p in peers)
    for address, asn in (("10.98.0.20", 65002), ("10.98.0.30", 65003))))
'
}

cache_ready() {
    rb --json rpki caches | python3 -c '
import json, sys
sys.exit(not any(c.get("address") == "10.98.0.40:3323" and c.get("connected") is True
    and (c.get("accepted") or {}).get("vrp_v4_count") == 1
    for c in json.load(sys.stdin).get("caches", [])))
'
}

member_b_route() {
    "${compose[@]}" exec -T member-b vtysh -c "show bgp ipv4 unicast ${1:-198.51.100.0/24} json"
}

verify() {
    sessions || return 1
    cache_ready || return 1
    rb --json rib --prefix 198.51.100.0/24 | python3 -c '
import json, sys
sys.exit(not any(r.get("prefix") == "198.51.100.0/24" and r.get("best") is True
    and r.get("peer_address") == "10.98.0.20" and r.get("validation_state") == "valid"
    for r in json.load(sys.stdin)))
' || return 1
    member_b_route | python3 -c '
import json, sys
sys.exit(not any(p.get("valid") is True and p.get("aspath", {}).get("string") == "65002"
    and any(n.get("ip") == "10.98.0.20" for n in p.get("nexthops", []))
    for p in json.load(sys.stdin).get("paths", [])))
'
}

rejected() {
    local prefix
    sessions || return 1
    cache_ready || return 1
    rb --json rib received 10.98.0.20 --rejected | python3 -c '
import json, sys
data = json.load(sys.stdin)
routes = data.get("rejected_routes", [])
sys.exit(not (data.get("retention_enabled") is True and data.get("evictions_since_reset") == 0
    and any(r.get("prefix") == "198.51.100.0/24" and r.get("reason") == "policy_reject"
        and r.get("reason_detail") == "reject-rpki-invalid"
        and r.get("rpki_validation") == "invalid" for r in routes)
    and any(r.get("prefix") == "203.0.113.0/25" and r.get("reason") == "policy_reject"
        and r.get("reason_detail") == "reject-long-prefixes"
        and r.get("rpki_validation") == "not_found" for r in routes)))
' || return 1
    for prefix in 198.51.100.0/24 203.0.113.0/25; do
        rb --json rib --prefix "$prefix" | python3 -c '
import json, sys
sys.exit(json.load(sys.stdin) != [])
' || return 1
        member_b_route "$prefix" | python3 -c '
import json, sys
sys.exit(bool(json.load(sys.stdin).get("paths", [])))
' || return 1
    done
}

wait_for() {
    local attempt
    for ((attempt = 0; attempt < 60; attempt++)); do
        if "$@" >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    echo "Timed out waiting for $*. Run 'just lab ixp explain' or 'just lab ixp down'." >&2
    return 1
}

case "$1" in
    up)
        echo 'Building and starting the IXP lab.'
        "${compose[@]}" up -d --build
        wait_for sessions
        wait_for cache_ready
        running_config=$(member_a -c 'show running-config')
        if [[ "$running_config" == *'network 203.0.113.0/25'* ]]; then
            member_a -c 'configure terminal' -c 'router bgp 65002' \
                -c 'address-family ipv4 unicast' -c 'no network 203.0.113.0/25'
        fi
        member_a -c 'configure terminal' -c 'router bgp 65002' \
            -c 'address-family ipv4 unicast' \
            -c 'no neighbor 10.98.0.10 route-map lab-invalid-origin out' \
            -c end \
            -c 'clear bgp 10.98.0.10 soft out'
        wait_for verify
        echo 'Ready: both members Established; the valid route reaches member-b unchanged.'
        ;;
    verify)
        if ! verify; then
            echo 'Verification failed: expected two members, live VRPs, and a valid route exported to member-b.' >&2
            exit 1
        fi
        echo 'Verified: 198.51.100.0/24 is RPKI valid and reaches member-b with AS_PATH 65002 and next hop 10.98.0.20.'
        ;;
    break)
        member_a -c 'configure terminal' -c 'router bgp 65002' \
            -c 'address-family ipv4 unicast' \
            -c 'neighbor 10.98.0.10 route-map lab-invalid-origin out' \
            -c 'network 203.0.113.0/25' -c end \
            -c 'clear bgp 10.98.0.10 soft out'
        wait_for rejected
        echo '198.51.100.0/24: origin AS65099 is RPKI-invalid; reject-rpki-invalid matched.'
        echo '203.0.113.0/25: RPKI NotFound; reject-long-prefixes matched.'
        echo 'Both sessions remain Established; neither rejected prefix is present at member-b.'
        echo 'Inspect the reasons with: just lab ixp explain'
        ;;
    explain)
        echo 'Member sessions:'
        rb neighbor
        echo 'Retained rejected routes:'
        rb rib received 10.98.0.20 --rejected
        echo 'Why the changed origin is invalid (the VRP authorizes AS65002):'
        rb rpki validate 198.51.100.0/24 65099
        echo 'Import policy decisions:'
        rb policy explain --neighbor 10.98.0.20 --prefix 198.51.100.0/24
        rb policy explain --neighbor 10.98.0.20 --prefix 203.0.113.0/25
        echo 'Why member-b cannot receive the rejected route:'
        rb rib --prefix 198.51.100.0/24 advertised 10.98.0.30 --explain
        echo 'Import policy counters:'
        rb policy stats --neighbor 10.98.0.20 --direction import
        ;;
    down)
        "${compose[@]}" down --volumes
        ;;
esac
