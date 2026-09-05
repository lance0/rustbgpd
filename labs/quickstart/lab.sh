#!/usr/bin/env bash
# Guided RFC 8212 exercise using the existing two-node Compose demo.
set -euo pipefail

if [[ $# != 1 ]]; then
    echo 'usage: lab.sh up|verify|break|explain|down' >&2
    exit 2
fi
case "$1" in
    up|verify|break|explain|down) ;;
    *) echo "unknown quickstart phase: $1" >&2; exit 2 ;;
esac

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
compose=(docker compose --project-name rustbgpd-lab-quickstart
    --file "$repo_root/examples/docker-compose/docker-compose.yml")

rb() {
    "${compose[@]}" exec -T rustbgpd rbgp -s http://127.0.0.1:50051 "$@"
}

healthy() {
    rb --json health | python3 -c '
import json, sys
sys.exit(json.load(sys.stdin).get("healthy") is not True)
'
}

verify() {
    rb --json neighbor | python3 -c '
import json, sys
peers = json.load(sys.stdin)
sys.exit(not any(p.get("address") == "10.99.0.20"
    and p.get("remote_asn") == 65002 and p.get("state") == "Established"
    and not p.get("stale", False) for p in peers))
' || return 1
    rb --json rib --prefix 192.168.1.0/24 | python3 -c '
import json, sys
routes = json.load(sys.stdin)
sys.exit(not any(r.get("prefix") == "192.168.1.0/24"
    and r.get("peer_address") == "10.99.0.20" and r.get("best") is True
    for r in routes))
'
}

rejected() {
    rb metrics | grep -x 'bgp_rfc8212_missing_import_policy{peer="10.99.0.20"} 1' >/dev/null
}

wait_for() {
    local attempt
    for ((attempt = 0; attempt < 60; attempt++)); do
        if "$@" >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    echo "Timed out waiting for $*. Run 'just lab quickstart explain' or 'just lab quickstart down'." >&2
    return 1
}

case "$1" in
    up)
        echo 'Building and starting the quickstart lab.'
        "${compose[@]}" up -d --build
        wait_for healthy
        rb policy chain set-import lab-permit-all-import
        wait_for verify
        echo 'Ready: FRR is Established and 192.168.1.0/24 is selected.'
        ;;
    verify)
        if ! verify; then
            echo 'Verification failed: expected FRR Established and 192.168.1.0/24 selected.' >&2
            exit 1
        fi
        echo 'Verified: FRR is Established and 192.168.1.0/24 is selected.'
        ;;
    break)
        rb policy chain clear-import
        wait_for rejected
        echo 'Import policy removed. Inspect the rejected routes with: just lab quickstart explain'
        ;;
    explain)
        echo 'Session state:'
        rb neighbor
        echo 'Retained rejected routes:'
        rb rib received 10.99.0.20 --rejected
        echo 'Import decision for 192.168.1.0/24:'
        rb policy explain --neighbor 10.99.0.20 --prefix 192.168.1.0/24
        echo 'Missing import policy (1 means RFC 8212 is blocking imports):'
        rb metrics | grep '^bgp_rfc8212_missing_import_policy{'
        ;;
    down)
        "${compose[@]}" down --volumes
        ;;
esac
