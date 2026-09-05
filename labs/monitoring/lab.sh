#!/usr/bin/env bash
# A BMP collector outage leaves the BGP session and selected route intact.
set -euo pipefail

if [[ $# != 1 ]]; then
    echo 'usage: lab.sh up|verify|break|explain|down' >&2
    exit 2
fi
case "$1" in
    up|verify|break|explain|down) ;;
    *) echo "unknown monitoring phase: $1" >&2; exit 2 ;;
esac

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
compose=(docker compose --project-name rustbgpd-lab-monitoring
    --file "$repo_root/labs/monitoring/docker-compose.yml")

rb() {
    "${compose[@]}" exec -T rustbgpd rbgp -s http://127.0.0.1:50051 "$@"
}

routing() {
    rb --json neighbor | python3 -c '
import json, sys
sys.exit(not any(p.get("address") == "10.96.0.20" and p.get("remote_asn") == 65002
    and p.get("state") == "Established" and not p.get("stale", False)
    for p in json.load(sys.stdin)))
' || return 1
    rb --json rib --prefix 198.51.100.0/24 | python3 -c '
import json, sys
sys.exit(not any(r.get("prefix") == "198.51.100.0/24" and r.get("best") is True
    and r.get("peer_address") == "10.96.0.20" for r in json.load(sys.stdin)))
'
}

verify() {
    routing || return 1
    "${compose[@]}" exec -T receiver cat /tmp/bmp-raw-11019.jsonl \
        | python3 "$repo_root/labs/monitoring/check_bmp.py"
}

probe_route() {
    rb --json rib --prefix 203.0.113.0/24 | python3 -c '
import json, sys
routes = json.load(sys.stdin)
present = any(r.get("prefix") == "203.0.113.0/24" and r.get("best") is True
    and r.get("peer_address") == "10.96.0.20" for r in routes)
sys.exit(not present if sys.argv[1] == "present" else routes != [])
' "$1"
}

wait_for() {
    local attempt
    for ((attempt = 0; attempt < 60; attempt++)); do
        if "$@" >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    echo "Timed out waiting for $*. Run 'just lab monitoring explain' or 'just lab monitoring down'." >&2
    return 1
}

case "$1" in
    up)
        "${compose[@]}" up -d --build --no-recreate rustbgpd frr
        wait_for routing
        # A fresh receiver cannot accidentally certify a previous capture.
        "${compose[@]}" up -d --force-recreate receiver
        wait_for verify
        verify
        echo 'Ready: BGP is Established and the collector decoded the selected route snapshot.'
        ;;
    verify)
        if ! verify; then
            echo 'Verification failed: expected live BGP and a decoded BMP route snapshot.' >&2
            exit 1
        fi
        ;;
    break)
        "${compose[@]}" stop receiver
        # Produce BMP writes so the exporter discovers the closed TCP stream;
        # the selected example route and its BGP session stay unchanged.
        "${compose[@]}" exec -T frr vtysh -c 'configure terminal' \
            -c 'router bgp 65002' -c 'address-family ipv4 unicast' \
            -c 'network 203.0.113.0/24'
        wait_for probe_route present
        "${compose[@]}" exec -T frr vtysh -c 'configure terminal' \
            -c 'router bgp 65002' -c 'address-family ipv4 unicast' \
            -c 'no network 203.0.113.0/24'
        wait_for probe_route absent
        routing
        echo 'Collector stopped; the BGP session and 198.51.100.0/24 remain live.'
        echo 'Inspect BMP delivery with: just lab monitoring explain'
        ;;
    explain)
        rb neighbor
        rb rib --prefix 198.51.100.0/24 --explain
        echo 'Collector lifecycle and retry logs:'
        logs=$("${compose[@]}" logs --tail 30 rustbgpd)
        printf '%s\n' "$logs" | grep -E 'BMP|collector' || true
        echo 'Replay attempts count collector connections, not successful route delivery.'
        echo 'Drop counters describe queue/dump failures; a stopped receiver need not increment them.'
        metrics=$(rb metrics)
        printf '%s\n' "$metrics" | grep -E '^bmp_(replay_attempts_total|collector_drops_total)' || true
        echo 'Doctor reports TCP reachability from the CLI; it does not verify BMP delivery.'
        rb doctor
        ;;
    down)
        "${compose[@]}" down --volumes
        ;;
esac
