#!/usr/bin/env bash
# M125: FRR global-table SRv6 advertisements reflected unchanged to GoBGP.
set -euo pipefail
TOPO=m125-srv6-global-reflection
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
ARTIFACT_DIR="${M125_ARTIFACT_DIR:-/tmp/m125-srv6-global-$(date -u +%Y%m%dT%H%M%SZ)}"
ARTIFACT_DIR_OWNED=0
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
    if [ "$ARTIFACT_DIR_OWNED" -eq 1 ]; then
        docker exec "$RUSTBGPD" cat /tmp/m125-rustbgpd.log >"$ARTIFACT_DIR/rustbgpd.log" 2>&1 || true
        docker exec "$SINK" cat /tmp/m125-gobgp.log >"$ARTIFACT_DIR/gobgp.log" 2>&1 || true
        docker exec "$FRR" vtysh -c 'show running-config' >"$ARTIFACT_DIR/frr-running.conf" 2>&1 || true
        docker logs "$CAPTURE" >"$ARTIFACT_DIR/capture.log" 2>&1 || true
    fi
    capture_cleanup
    _cleanup_on_exit
    if [ "$ARTIFACT_DIR_OWNED" -eq 1 ]; then printf '%s\n' "$status" >"$ARTIFACT_DIR/exit-code.txt"; fi
    exit "$status"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

sink_ready() {
    docker exec "$SINK" gobgp neighbor 2001:db8:125:20::1 -j >/dev/null 2>&1
}

start_capture() {
    # Refuse existing names rather than remove resources from another run.
    if docker container inspect "$CAPTURE" >/dev/null 2>&1 \
        || docker volume inspect "$CAPTURE" >/dev/null 2>&1; then
        echo "ERROR: capture resource already exists: $CAPTURE" >&2
        return 1
    fi
    docker volume create --label rustbgpd.interop.milestone=M125 "$CAPTURE" >/dev/null
    VOLUME_OWNED=1
    docker create --cpuset-cpus="${M125_CPUSET:-}" --name "$CAPTURE" --label rustbgpd.interop.milestone=M125 \
        --network "container:$RUSTBGPD" --cap-add=NET_ADMIN --cap-add=NET_RAW \
        --mount "type=volume,src=$CAPTURE,dst=/capture" \
        "$CAPTURE_IMAGE" tshark -p -i any -f 'tcp port 179' -w /capture/m125.pcap >/dev/null
    CAPTURE_OWNED=1
    docker inspect "$CAPTURE" \
        | jq '[.[] | {name:.Name,image:.Image,configured_image:.Config.Image}]' >"$ARTIFACT_DIR/capture-image.json"
    docker start "$CAPTURE" >/dev/null
    wait_capture_ready "$CAPTURE" /capture/m125.pcap -
}

stop_capture() {
    timeout 10 docker kill --signal=SIGINT "$CAPTURE" >/dev/null
    local status
    status=$(timeout 10 docker wait "$CAPTURE")
    case "$status" in 0|130) ;; *) return 1 ;; esac
    docker run --rm --cpuset-cpus="${M125_CPUSET:-}" --mount "type=volume,src=$CAPTURE,dst=/capture,readonly" \
        "$CAPTURE_IMAGE" sh -ec 'test -s /capture/m125.pcap; cat /capture/m125.pcap' \
        >"$ARTIFACT_DIR/m125.pcap"
    docker run --rm --cpuset-cpus="${M125_CPUSET:-}" --mount "type=volume,src=$CAPTURE,dst=/capture,readonly" \
        "$CAPTURE_IMAGE" tshark -r /capture/m125.pcap -Y 'tcp.len > 0' \
        -T fields -E 'separator=/t' -e tcp.stream -e ipv6.src -e ipv6.dst \
        -e tcp.seq_raw -e tcp.payload >"$ARTIFACT_DIR/payloads.tsv"
}

rr_state() {
    local view=$1 count=$2 prefix=$3
    local -a args=(rib --prefix "$prefix")
    case "$view" in
        received) args+=(received 2001:db8:125:10::2) ;;
        advertised) args+=(advertised 2001:db8:125:20::2) ;;
    esac
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 "${args[@]}" -j \
        >"$ARTIFACT_DIR/rr-current.json"
    jq -e --arg prefix "$prefix" --arg view "$view" --argjson count "$count" '
        length == $count and all(.[]; .prefix == $prefix
            and .peer_address == "2001:db8:125:10::2"
            and .next_hop == "2001:db8:125:10::2"
            and ($view != "best" or .best == true))' "$ARTIFACT_DIR/rr-current.json" >/dev/null
}

sink_state() {
    local family=$1 count=$2 prefix=$3
    docker exec "$SINK" gobgp neighbor 2001:db8:125:20::1 adj-in -a "$family" -j \
        >"$ARTIFACT_DIR/sink-current.json"
    jq -e --arg prefix "$prefix" --argjson count "$count" '
        if $count == 0 then length == 0
        else keys == [$prefix] and (.[$prefix] | length == 1) end' \
        "$ARTIFACT_DIR/sink-current.json" >/dev/null
}

family_state() {
    local family=$1 count=$2 prefix=$3 phase=$4
    for view in received best advertised; do
        wait_for "$phase $family RR $view" rr_state "$view" "$count" "$prefix"
        cp "$ARTIFACT_DIR/rr-current.json" "$ARTIFACT_DIR/$phase-$family-$view.json"
    done
    wait_for "$phase $family sink" sink_state "$family" "$count" "$prefix"
    cp "$ARTIFACT_DIR/sink-current.json" "$ARTIFACT_DIR/$phase-$family-sink.json"
}

main() {
    preflight
    mkdir "$ARTIFACT_DIR"
    ARTIFACT_DIR_OWNED=1
    local source_id image_source_id
    source_id=$(scripts/source-id.sh)
    image_source_id=$(docker exec "$RUSTBGPD" cat /usr/local/share/rustbgpd/source-id)
    [ "$source_id" = "$image_source_id" ] || { echo 'DUT build input content differs from this tree' >&2; return 1; }
    jq -n --arg source_id "$source_id" --arg harness_revision "$(git rev-parse HEAD)" \
        '{source_id:$source_id,harness_revision:$harness_revision}' >"$ARTIFACT_DIR/identity.json"
    git diff HEAD -- tests/interop >"$ARTIFACT_DIR/harness.diff"
    git status --porcelain -- tests/interop >"$ARTIFACT_DIR/harness-status.txt"
    sha256sum tests/interop/scripts/{m125_capture_oracle,m111_capture_oracle,m105_capture_oracle}.py \
        tests/interop/scripts/{test-m125-srv6-global-reflection,test-lib,start-rustbgpd}.sh \
        tests/interop/configs/{frr-daemons,frr-m125-srv6-global.conf,gobgp-m125-srv6-global-sink.toml,rustbgpd-m125-srv6-global-rr.toml} \
        tests/interop/m125-srv6-global-reflection.clab.yml >"$ARTIFACT_DIR/harness-sha256.txt"
    docker exec "$RUSTBGPD" sha256sum /usr/local/bin/rustbgpd /usr/local/bin/rbgp >"$ARTIFACT_DIR/binary-sha256.txt"
    docker exec "$RUSTBGPD" rustbgpd --check --strict /etc/rustbgpd/config.toml
    docker exec "$SINK" gobgpd -d -f /config/gobgp.toml
    docker exec "$FRR" vtysh -C -f /etc/frr/frr.conf
    docker inspect "$FRR" "$RUSTBGPD" "$SINK" \
        | jq '[.[] | {name:.Name,image:.Image,configured_image:.Config.Image}]' >"$ARTIFACT_DIR/images.json"
    docker exec "$FRR" /usr/lib/frr/bgpd --version >"$ARTIFACT_DIR/frr-version.txt"
    grep -q '^bgpd version 10\.7\.1' "$ARTIFACT_DIR/frr-version.txt"
    docker exec "$SINK" gobgpd --version >"$ARTIFACT_DIR/gobgp-version.txt"
    grep -qx 'gobgpd version 3\.37\.0' "$ARTIFACT_DIR/gobgp-version.txt"
    docker exec "$RUSTBGPD" rustbgpd --version >"$ARTIFACT_DIR/rustbgpd-version.txt"
    start_capture
    docker exec -d "$SINK" sh -c 'gobgpd -f /config/gobgp.toml >/tmp/m125-gobgp.log 2>&1'
    docker exec "$FRR" /usr/lib/frr/frrinit.sh start
    wait_for 'GoBGP configured' sink_ready
    docker exec -d "$RUSTBGPD" sh -c '/usr/local/bin/start-rustbgpd.sh >/tmp/m125-rustbgpd.log 2>&1'
    family_state ipv4 1 198.51.125.0/24 initial
    family_state ipv6 1 2001:db8:125:1000::/64 initial
    docker exec "$FRR" vtysh -c 'show bgp segment-routing srv6' >"$ARTIFACT_DIR/frr-bgp-sids.txt"
    docker exec "$FRR" vtysh -c 'show segment-routing srv6 locator srv6-proof sid json' >"$ARTIFACT_DIR/frr-sids.json"
    docker exec "$FRR" vtysh -c 'show bgp ipv4 unicast json' >"$ARTIFACT_DIR/frr-ipv4.json"
    docker exec "$FRR" vtysh -c 'show bgp ipv6 unicast json' >"$ARTIFACT_DIR/frr-ipv6.json"
    for family in 4 6; do
        docker exec "$RUSTBGPD" ip -j "-$family" route show table all >"$ARTIFACT_DIR/rr-ipv$family-routes.json"
        jq -e 'all(.[]; .dst != "198.51.125.0/24" and .dst != "2001:db8:125:1000::/64")' \
            "$ARTIFACT_DIR/rr-ipv$family-routes.json" >/dev/null
    done
    docker exec "$FRR" vtysh -c 'configure terminal' -c 'router bgp 65001' \
        -c 'address-family ipv6 unicast' -c 'no network 2001:db8:125:1000::/64'
    family_state ipv6 0 2001:db8:125:1000::/64 ipv6-withdrawn
    family_state ipv4 1 198.51.125.0/24 ipv6-withdrawn
    docker exec "$FRR" vtysh -c 'configure terminal' -c 'router bgp 65001' \
        -c 'address-family ipv4 unicast' -c 'no network 198.51.125.0/24'
    family_state ipv4 0 198.51.125.0/24 final
    family_state ipv6 0 2001:db8:125:1000::/64 final
    docker exec "$SINK" gobgp neighbor 2001:db8:125:20::1 -j >"$ARTIFACT_DIR/sink-final-session.json"
    jq -e '.state.session_state == 6' "$ARTIFACT_DIR/sink-final-session.json" >/dev/null
    docker exec "$FRR" vtysh -c 'show bgp neighbors 2001:db8:125:10::1 json' >"$ARTIFACT_DIR/source-final-session.json"
    jq -e '.["2001:db8:125:10::1"].bgpState == "Established"' "$ARTIFACT_DIR/source-final-session.json" >/dev/null
    stop_capture
    python3 "$SCRIPT_DIR/m125_capture_oracle.py" "$ARTIFACT_DIR/payloads.tsv" >"$ARTIFACT_DIR/wire.json"
    jq -e --slurpfile wire "$ARTIFACT_DIR/wire.json" '
        . as $allocated | all($wire[0].families | to_entries[];
            . as $route | $allocated[$route.value.service_sid] as $sid |
            $sid.sid == $route.value.service_sid
            and $sid.behavior == (if $route.key == "ipv4" then "End.DT4" else "End.DT6" end)
            and $sid.locator == "srv6-proof" and any($sid.clients[]; .protocol == "bgp"))' \
        "$ARTIFACT_DIR/frr-sids.json" >/dev/null
    jq -n --slurpfile wire "$ARTIFACT_DIR/wire.json" '{passed:true,wire:$wire[0]}' >"$ARTIFACT_DIR/verdict.json"
    echo 'PASS: native dual-family global SRv6 selection, byte-preserving reflection and withdrawals'
}
main "$@"
