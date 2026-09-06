#!/usr/bin/env bash
# M111: FRR SRv6 L3VPN advertisements reflected unchanged to GoBGP.
set -euo pipefail
TOPO=m111-srv6-l3vpn-reflection
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLEANUP="${CLEANUP:-1}"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck disable=SC1091 # resolved from SCRIPT_DIR at runtime
source "$SCRIPT_DIR/test-lib.sh"
FRR="clab-${TOPO}-frr"
SINK="clab-${TOPO}-gobgp"
CAPTURE="${TOPO}-capture"
CAPTURE_IMAGE=bmpsink:m102
ARTIFACT_DIR="${M111_ARTIFACT_DIR:-/tmp/m111-srv6-l3vpn-artifacts}"
CAPTURE_OWNED=0
VOLUME_OWNED=0

wait_for() {
    local label=$1
    shift
    for _ in $(seq 1 60); do
        if "$@"; then return 0; fi
        sleep 1
    done
    echo "ERROR: timed out: $label" >&2
    return 1
}

capture_cleanup() {
    if [ "$CAPTURE_OWNED" -eq 1 ]; then
        docker rm -f "$CAPTURE" >/dev/null 2>&1 || true
    fi
    if [ "$VOLUME_OWNED" -eq 1 ]; then
        docker volume rm "$CAPTURE" >/dev/null 2>&1 || true
    fi
}

on_exit() {
    local status=$?
    trap - EXIT INT TERM HUP
    if [ "$status" -ne 0 ] && [ "$CAPTURE_OWNED" -eq 1 ] \
        && [ "$(docker inspect -f '{{.State.Running}}' "$CAPTURE" 2>/dev/null)" = true ]; then
        stop_capture >"$ARTIFACT_DIR/capture-stop.log" 2>&1 || true
    fi
    if [ -d "$ARTIFACT_DIR" ]; then
        docker exec "$RUSTBGPD" cat /tmp/m111-rustbgpd.log >"$ARTIFACT_DIR/rustbgpd.log" 2>&1 || true
        docker exec "$SINK" cat /tmp/m111-gobgp.log >"$ARTIFACT_DIR/gobgp.log" 2>&1 || true
        docker exec "$FRR" vtysh -c 'show running-config' >"$ARTIFACT_DIR/frr-running.conf" 2>&1 || true
        docker logs "$CAPTURE" >"$ARTIFACT_DIR/capture.log" 2>&1 || true
    fi
    capture_cleanup
    _cleanup_on_exit
    exit "$status"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

capture_ready() {
    docker logs "$CAPTURE" 2>&1 | grep -q 'Capturing on'
}

sink_ready() {
    docker exec "$SINK" gobgp neighbor 2001:db8:111:20::1 -j >/dev/null 2>&1
}

start_capture() {
    # Refuse existing names rather than remove resources from another run.
    if docker container inspect "$CAPTURE" >/dev/null 2>&1 \
        || docker volume inspect "$CAPTURE" >/dev/null 2>&1; then
        echo "ERROR: capture resource already exists: $CAPTURE" >&2
        return 1
    fi
    docker volume create --label rustbgpd.interop.milestone=M111 "$CAPTURE" >/dev/null
    VOLUME_OWNED=1
    docker run -d --name "$CAPTURE" --label rustbgpd.interop.milestone=M111 \
        --network "container:$RUSTBGPD" --cap-add=NET_ADMIN --cap-add=NET_RAW \
        --mount "type=volume,src=$CAPTURE,dst=/capture" \
        "$CAPTURE_IMAGE" tshark -p -i any -f 'tcp port 179' -w /capture/m111.pcap >/dev/null
    CAPTURE_OWNED=1
    wait_for 'packet capture ready' capture_ready
}

stop_capture() {
    timeout 10 docker kill --signal=SIGINT "$CAPTURE" >/dev/null
    local status
    status=$(timeout 10 docker wait "$CAPTURE")
    case "$status" in 0|130) ;; *) return 1 ;; esac
    docker run --rm --mount "type=volume,src=$CAPTURE,dst=/capture,readonly" \
        "$CAPTURE_IMAGE" sh -ec 'test -s /capture/m111.pcap; cat /capture/m111.pcap' \
        >"$ARTIFACT_DIR/m111.pcap"
    docker run --rm --mount "type=volume,src=$CAPTURE,dst=/capture,readonly" \
        "$CAPTURE_IMAGE" tshark -r /capture/m111.pcap -Y 'tcp.len > 0' \
        -T fields -E 'separator=/t' -e tcp.stream -e ipv6.src -e ipv6.dst \
        -e tcp.seq_raw -e tcp.payload >"$ARTIFACT_DIR/payloads.tsv"
}

rs_state() {
    local family=$1 count=$2 prefix=$3
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 rib vpn \
        -a "$family" --neighbor 2001:db8:111:10::2 -j \
        | jq -e --arg family "$family" --arg prefix "$prefix" --argjson count "$count" '
            length == $count and all(.[]; .afi_safi == $family
              and .peer_address == "2001:db8:111:10::2"
              and .route_distinguisher == "65001:111" and .prefix == $prefix)' >/dev/null
}

sink_state() {
    local family=$1 count=$2 prefix=$3
    docker exec "$SINK" gobgp neighbor 2001:db8:111:20::1 adj-in -a "$family" -j \
        | jq -e --arg key "65001:111:$prefix" --argjson count "$count" '
            if $count == 0 then length == 0
            else keys == [$key] and (.[$key] | length == 1) end' >/dev/null
}

family_state() {
    local family=$1 count=$2 prefix=$3 api_family=$4
    wait_for "$family RR count $count" rs_state "$api_family" "$count" "$prefix"
    wait_for "$family sink count $count" sink_state "$family" "$count" "$prefix"
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 rib vpn -a "$api_family" -j \
        >"$ARTIFACT_DIR/$family-count-$count-rr.json"
    docker exec "$SINK" gobgp neighbor 2001:db8:111:20::1 adj-in -a "$family" -j \
        >"$ARTIFACT_DIR/$family-count-$count-sink.json"
}

main() {
    preflight
    mkdir -p "$ARTIFACT_DIR"
    docker exec "$RUSTBGPD" rustbgpd --check --strict /etc/rustbgpd/config.toml
    docker exec "$SINK" gobgpd -d -f /config/gobgp.toml
    docker exec "$FRR" vtysh -C -f /etc/frr/frr.conf
    docker inspect "$FRR" "$RUSTBGPD" "$SINK" \
        | jq '[.[] | {name:.Name,image:.Image,configured_image:.Config.Image}]' \
        >"$ARTIFACT_DIR/images.json"
    docker exec "$FRR" /usr/lib/frr/bgpd --version >"$ARTIFACT_DIR/frr-version.txt"
    grep -q '^bgpd version 10\.7\.1' "$ARTIFACT_DIR/frr-version.txt"
    docker exec "$SINK" gobgpd --version >"$ARTIFACT_DIR/gobgp-version.txt"
    grep -qx 'gobgpd version 3\.37\.0' "$ARTIFACT_DIR/gobgp-version.txt"
    docker exec "$RUSTBGPD" rustbgpd --version >"$ARTIFACT_DIR/rustbgpd-version.txt"
    start_capture
    docker exec -d "$SINK" sh -c 'gobgpd -f /config/gobgp.toml >/tmp/m111-gobgp.log 2>&1'
    docker exec "$FRR" /usr/lib/frr/frrinit.sh start
    wait_for 'GoBGP configured' sink_ready
    # Passive vendor peers are configured before the RR initiates either link.
    docker exec -d "$RUSTBGPD" sh -c '/usr/local/bin/start-rustbgpd.sh >/tmp/m111-rustbgpd.log 2>&1'
    family_state vpnv4 1 198.51.111.0/24 l3vpn_ipv4_unicast
    family_state vpnv6 1 2001:db8:111:1000::/64 l3vpn_ipv6_unicast
    docker exec "$FRR" vtysh -c 'show segment-routing srv6 locator' >"$ARTIFACT_DIR/frr-locator.txt"
    docker exec "$FRR" vtysh -c 'show segment-routing srv6 locator srv6-proof sid json' \
        >"$ARTIFACT_DIR/frr-sids.json"
    docker exec "$FRR" vtysh -c 'show bgp segment-routing srv6' >"$ARTIFACT_DIR/frr-bgp-sids.txt"
    docker exec "$FRR" vtysh -c 'show bgp ipv4 vpn json' >"$ARTIFACT_DIR/frr-vpnv4.json"
    docker exec "$FRR" vtysh -c 'show bgp ipv6 vpn json' >"$ARTIFACT_DIR/frr-vpnv6.json"
    for family in 4 6; do
        docker exec "$RUSTBGPD" ip -j "-$family" route show table all >"$ARTIFACT_DIR/rr-ipv$family-routes.json"
        jq -e 'all(.[]; .dst != "198.51.111.0/24" and .dst != "2001:db8:111:1000::/64")' \
            "$ARTIFACT_DIR/rr-ipv$family-routes.json" >/dev/null
    done
    docker exec "$FRR" vtysh -c 'configure terminal' -c 'router bgp 65001 vrf vrf111' \
        -c 'address-family ipv6 unicast' -c 'no network 2001:db8:111:1000::/64'
    family_state vpnv6 0 2001:db8:111:1000::/64 l3vpn_ipv6_unicast
    family_state vpnv4 1 198.51.111.0/24 l3vpn_ipv4_unicast
    docker exec "$FRR" vtysh -c 'configure terminal' -c 'router bgp 65001 vrf vrf111' \
        -c 'address-family ipv4 unicast' -c 'no network 198.51.111.0/24'
    family_state vpnv4 0 198.51.111.0/24 l3vpn_ipv4_unicast
    docker exec "$SINK" gobgp neighbor 2001:db8:111:20::1 -j >"$ARTIFACT_DIR/sink-final-session.json"
    jq -e '.state.session_state == 6' "$ARTIFACT_DIR/sink-final-session.json" >/dev/null
    docker exec "$FRR" vtysh -c 'show bgp neighbors 2001:db8:111:10::1 json' \
        >"$ARTIFACT_DIR/source-final-session.json"
    jq -e '.["2001:db8:111:10::1"].bgpState == "Established"' \
        "$ARTIFACT_DIR/source-final-session.json" >/dev/null
    stop_capture
    python3 "$SCRIPT_DIR/m111_capture_oracle.py" "$ARTIFACT_DIR/payloads.tsv" >"$ARTIFACT_DIR/wire.json"
    jq -e --slurpfile wire "$ARTIFACT_DIR/wire.json" '
        . as $allocated | all($wire[0].families | to_entries[];
            . as $route | $allocated[$route.value.service_sid] as $sid |
            $sid.sid == $route.value.service_sid
            and $sid.behavior == (if $route.key == "vpnv4" then "End.DT4" else "End.DT6" end)
            and $sid.context.vrfName == "vrf111" and $sid.context.table == 111
            and $sid.locator == "srv6-proof"
            and any($sid.clients[]; .protocol == "bgp"))' "$ARTIFACT_DIR/frr-sids.json" >/dev/null
    echo 'PASS: dual-family SRv6 L3VPN wire preservation and independent withdrawals'
}
main "$@"
