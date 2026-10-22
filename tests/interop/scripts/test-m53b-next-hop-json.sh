#!/usr/bin/env bash
# The prefix and peer address cannot substitute for a path's actual next hop.
set -euo pipefail
filter="$(dirname "$0")/m53b-next-hop.jq"
good='{"prefix":"192.0.2.53/32","paths":[{"valid":true,"peerId":"fe80::1","nexthops":[{"afi":"ipv6","scope":"link-local","used":true,"ip":"fe80::1"}]}]}'
bad='{"prefix":"192.0.2.53/32","paths":[{"valid":true,"peerId":"fe80::1","nexthops":[{"afi":"ipv6","scope":"link-local","used":true,"ip":"fe80::2"}]}]}'
printf '%s\n' "$good" | jq -e --arg prefix 192.0.2.53/32 --arg nh fe80::1 -f "$filter" >/dev/null
if printf '%s\n' "$bad" | jq -e --arg prefix 192.0.2.53/32 --arg nh fe80::1 -f "$filter" >/dev/null; then
    echo 'wrong path next hop passed' >&2
    exit 1
fi
