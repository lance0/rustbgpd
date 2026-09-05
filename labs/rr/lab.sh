#!/usr/bin/env bash
# Diagnose an unintended duplicate prefix announcement to a route reflector.
set -euo pipefail

if [[ $# != 1 ]]; then
    echo 'usage: lab.sh up|verify|break|explain|down' >&2
    exit 2
fi
case "$1" in
    up|verify|break|explain|down) ;;
    *) echo "unknown rr phase: $1" >&2; exit 2 ;;
esac

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
compose=(docker compose --project-name rustbgpd-lab-rr
    --file "$repo_root/labs/rr/docker-compose.yml")

rb() {
    "${compose[@]}" exec -T rustbgpd rbgp -s http://127.0.0.1:50051 "$@"
}

client_b() {
    "${compose[@]}" exec -T client-b vtysh "$@"
}

sessions() {
    rb --json neighbor | python3 -c '
import json, sys
peers = json.load(sys.stdin)
sys.exit(not all(any(p.get("address") == address and p.get("remote_asn") == 65001
    and p.get("state") == "Established" and p.get("route_reflector_client") is True
    and not p.get("stale", False) for p in peers)
    for address in ("10.97.0.20", "10.97.0.30")))
'
}

reflected_to() {
    "${compose[@]}" exec -T "$1" vtysh -c 'show bgp ipv4 unicast 198.51.100.0/24 json' |
        python3 -c '
import json, sys
originator, next_hop = sys.argv[1:]
sys.exit(not any(p.get("valid") is True and p.get("originatorId") == originator
    and p.get("peer", {}).get("peerId") == "10.97.0.1"
    and "10.97.0.1" in p.get("clusterList", {}).get("list", [])
    and any(n.get("ip") == next_hop for n in p.get("nexthops", []))
    for p in json.load(sys.stdin).get("paths", [])))
' "$2" "$3"
}

not_reflected_to() {
    rb --json rib --prefix 198.51.100.0/24 advertised "$2" --explain | python3 -c '
import json, sys
data = json.load(sys.stdin)
sys.exit(not (data.get("decision") == "deny"
    and data.get("route_peer_address") == sys.argv[1]
    and any(g.get("gate") == "split_horizon" and g.get("verdict") == "stop"
        for g in data.get("gates", []))))
' "$2" || return 1
    rb --json rib --prefix 198.51.100.0/24 advertised "$2" | python3 -c '
import json, sys
sys.exit(json.load(sys.stdin) != [])
' || return 1
    "${compose[@]}" exec -T "$1" vtysh -c 'show bgp ipv4 unicast 198.51.100.0/24 json' |
        python3 -c '
import json, sys
sys.exit(any(p.get("peer", {}).get("peerId") == "10.97.0.1"
    for p in json.load(sys.stdin).get("paths", [])))
'
}

verify() {
    sessions || return 1
    rb --json rib --prefix 198.51.100.0/24 --explain | python3 -c '
import json, sys
data = json.load(sys.stdin)
best = data.get("best_route") or {}
sys.exit(not (best.get("peer_address") == "10.97.0.20"
    and best.get("prefix") == "198.51.100.0/24" and best.get("best") is True
    and data.get("candidates") == []))
' || return 1
    reflected_to client-b 10.97.0.20 10.97.0.20 || return 1
    not_reflected_to client-a 10.97.0.20
}

duplicate_selected() {
    sessions || return 1
    rb --json rib --prefix 198.51.100.0/24 --explain | python3 -c '
import json, sys
data = json.load(sys.stdin)
best = data.get("best_route") or {}
candidates = data.get("candidates", [])
sys.exit(not (best.get("peer_address") == "10.97.0.30"
    and best.get("prefix") == "198.51.100.0/24" and best.get("best") is True
    and data.get("best_reason") == "lower_bgp_identifier"
    and len(candidates) == 1
    and any((c.get("route") or {}).get("peer_address") == "10.97.0.20"
        and c.get("vs_best_reason") == "lower_bgp_identifier"
        and c.get("vs_best_ordering") == "worse" for c in candidates)))
' || return 1
    reflected_to client-a 10.97.0.10 10.97.0.30 || return 1
    not_reflected_to client-b 10.97.0.30
}

wait_for() {
    local attempt
    for ((attempt = 0; attempt < 60; attempt++)); do
        if "$@" >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    echo "Timed out waiting for $*. Run 'just lab rr explain' or 'just lab rr down'." >&2
    return 1
}

case "$1" in
    up)
        echo 'Building and starting the route-reflector lab.'
        "${compose[@]}" up -d --build
        wait_for sessions
        running_config=$(client_b -c 'show running-config')
        if [[ "$running_config" == *'network 198.51.100.0/24'* ]]; then
            client_b -c 'configure terminal' -c 'router bgp 65001' \
                -c 'address-family ipv4 unicast' -c 'no network 198.51.100.0/24'
        fi
        wait_for verify
        echo 'Ready: client A is the only origin; client B receives its reflected route.'
        ;;
    verify)
        if ! verify; then
            echo 'Verification failed: expected client A as the sole origin, reflection to B, and no reflection back to A.' >&2
            exit 1
        fi
        echo 'Verified: client A owns 198.51.100.0/24; reflection preserves its originator and next hop.'
        ;;
    break)
        client_b -c 'configure terminal' -c 'router bgp 65001' \
            -c 'address-family ipv4 unicast' -c 'network 198.51.100.0/24'
        wait_for duplicate_selected
        echo 'Client B now incorrectly originates the same prefix and wins on its lower BGP Identifier.'
        echo 'Both sessions remain Established. Diagnose the changed source: just lab rr explain'
        ;;
    explain)
        echo 'Client sessions:'
        rb neighbor
        echo 'Intended source: client A (10.97.0.20). Compare the actual winning source and candidates:'
        rb rib --prefix 198.51.100.0/24 --explain
        for peer in 10.97.0.20 10.97.0.30; do
            echo "Export decision toward $peer (the selected source must stop at split_horizon):"
            rb rib --prefix 198.51.100.0/24 advertised "$peer" --explain
        done
        ;;
    down)
        "${compose[@]}" down --volumes
        ;;
esac
