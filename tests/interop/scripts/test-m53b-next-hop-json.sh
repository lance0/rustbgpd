#!/usr/bin/env bash
# Seeded counterexamples must fail the same M53b oracles used by the live lab.
set -euo pipefail
filter="$(dirname "$0")/m53b-next-hop.jq"

good='{"prefix":"192.0.2.53/32","paths":[{"valid":true,"peerId":"fe80::1","nexthops":[{"afi":"ipv6","scope":"link-local","used":true,"ip":"fe80::1"}]}]}'
bad='{"prefix":"192.0.2.53/32","paths":[{"valid":true,"peerId":"fe80::1","nexthops":[{"afi":"ipv6","scope":"link-local","used":true,"ip":"fe80::2"}]}]}'
printf '%s\n' "$good" | jq -e --arg prefix 192.0.2.53/32 --arg nh fe80::1 -f "$filter" >/dev/null
if printf '%s\n' "$bad" | jq -e --arg prefix 192.0.2.53/32 --arg nh fe80::1 -f "$filter" >/dev/null; then
    echo 'wrong path next hop passed' >&2; exit 1
fi

packet_ok() {
    printf '%s\n' "$1" | jq -e --arg mode packets --argjson recovery 150 \
        --arg ll fe80::2 --arg own fe80::1 --argjson before 1 -f "$filter" >/dev/null
}
packets='[{"ns":100,"type":"RA","src":"fe80::2"},{"ns":200,"type":"RS","src":"fe80::1"},{"ns":250,"type":"RA","src":"fe80::2"}]'
packet_ok "$packets"
for mutation in \
    'map(select(.type != "RS"))' \
    'map(if .type == "RS" then .src = "fe80::3" else . end)' \
    '. + [{"ns":225,"type":"RS","src":"fe80::3"}]' \
    'map(if .ns == 250 then .ns = 200000000101 else . end)'; do
    if packet_ok "$(printf '%s\n' "$packets" | jq -c "$mutation")"; then
        echo "packet oracle passed broken fixture: $mutation" >&2; exit 1
    fi
done

event_ok() {
    local mode=$1 json=$2
    printf '%s\n' "$json" | jq -e --arg mode "$mode" --arg source fe80::1 \
        --arg bound fe80::2 --arg other fe80::3 \
        --argjson drop_before 0 --argjson learned_before 0 --argjson conflict_before 0 \
        --argjson expired_before 0 --argjson other_expired_before 0 \
        --argjson binding_before 0 --argjson added_before 0 --argjson ending_before 0 \
        -f "$filter" >/dev/null
}
own='[{"fields":{"message":"router discovery packet dropped","source":"fe80::1","reason":"own_address"}}]'
event_ok own "$own"
conflict='[{"fields":{"message":"unnumbered: peer address learned","interface":"eth2","address":"fe80::3"}},{"fields":{"message":"unnumbered: a second router advertises on an interface-only link","interface":"eth2","bound":"fe80::2","other":"fe80::3"}}]'
event_ok conflict "$conflict"
expiry='[{"fields":{"message":"unnumbered: peer address expired","interface":"eth2","address":"fe80::2"}}]'
event_ok expiry "$expiry"
for entry in \
    'own|map(select(.fields.message != "router discovery packet dropped"))' \
    'own|map(if .fields.source? then .fields.source = "fe80::4" else . end)' \
    'own|. + [{"fields":{"message":"unnumbered: peer address learned","interface":"eth2","address":"fe80::1"}}]' \
    'conflict|map(select(.fields.message != "unnumbered: a second router advertises on an interface-only link"))' \
    'conflict|map(if .fields.other? then .fields.other = "fe80::4" else . end)' \
    'conflict|map(select(.fields.message != "unnumbered: peer address learned"))' \
    'expiry|map(select(.fields.message != "unnumbered: peer address expired"))' \
    'expiry|map(if .fields.address? then .fields.address = "fe80::4" else . end)' \
    'expiry|. + [{"fields":{"message":"unnumbered: peer address expired","interface":"eth2","address":"fe80::3"}}]' \
    'expiry|. + [{"fields":{"message":"unnumbered: ending the bound session","interface":"eth2"}}]' \
    'expiry|. + [{"fields":{"message":"unnumbered: bound peer added","interface":"eth2"}}]' \
    'expiry|. + [{"fields":{"message":"unnumbered: binding changed","interface":"eth2"}}]'; do
    mode=${entry%%|*}
    mutation=${entry#*|}
    case "$mode" in own) fixture=$own ;; conflict) fixture=$conflict ;; expiry) fixture=$expiry ;; esac
    if event_ok "$mode" "$(printf '%s\n' "$fixture" | jq -c "$mutation")"; then
        echo "$mode oracle passed broken fixture: $mutation" >&2; exit 1
    fi
done

down='{"neighbors":[{"config":{"interface":"eth1"},"state":"SESSION_STATE_ESTABLISHED"},{"config":{"interface":"eth2"},"state":"SESSION_STATE_IDLE"}]}'
down_ok() { printf '%s\n' "$1" | jq -e --arg mode down -f "$filter" >/dev/null; }
down_ok "$down"
for mutation in \
    '(.neighbors[] | select(.config.interface == "eth1")).stale = true' \
    '(.neighbors[] | select(.config.interface == "eth2")).stale = true' \
    '(.neighbors[] | select(.config.interface == "eth2")).state = "SESSION_STATE_ESTABLISHED"'; do
    if down_ok "$(printf '%s\n' "$down" | jq -c "$mutation")"; then
        echo "carrier oracle passed broken fixture: $mutation" >&2; exit 1
    fi
done
