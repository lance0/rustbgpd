#!/usr/bin/env bash
# M112: controlled SRv6 L2 EVPN reflection with a pinned GoBGP observer.
set -euo pipefail
TOPO=m112-srv6-l2-reflection
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLEANUP="${CLEANUP:-1}"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck disable=SC1091 # resolved from SCRIPT_DIR at runtime
source "$SCRIPT_DIR/test-lib.sh"
RAW="clab-${TOPO}-source"
SINK="clab-${TOPO}-gobgp"
CAPTURE="${TOPO}-capture"
CAPTURE_IMAGE=bmpsink:m102
ARTIFACT_DIR="${M112_ARTIFACT_DIR:-/tmp/m112-srv6-l2-$(date -u +%Y%m%dT%H%M%SZ)}"
ARTIFACT_DIR_OWNED=0
REQUIRE_TYPED="${M112_REQUIRE_TYPED:-1}"
CAPTURE_OWNED=0
VOLUME_OWNED=0
CAPTURE_STOPPED=0
SINK_ADDR=""
TYPED_ARGS=()
if [ "$REQUIRE_TYPED" = 1 ]; then TYPED_ARGS=(--require-typed); fi

wait_for() {
    local label=$1
    shift
    for _ in $(seq 1 60); do
        if "$@"; then return 0; fi
        sleep 1
    done
    echo "ERROR: timed out: $label; see $ARTIFACT_DIR" >&2
    return 1
}

stop_capture() {
    timeout 10 docker kill --signal=SIGINT "$CAPTURE" >/dev/null
    local status
    status=$(timeout 10 docker wait "$CAPTURE")
    case "$status" in 0|130) ;; *) return 1 ;; esac
    CAPTURE_STOPPED=1
    docker run --rm --mount "type=volume,src=$CAPTURE,dst=/capture,readonly" \
        "$CAPTURE_IMAGE" sh -ec 'test -s /capture/m112.pcap; cat /capture/m112.pcap' \
        >"$ARTIFACT_DIR/m112.pcap"
    docker run --rm --mount "type=volume,src=$CAPTURE,dst=/capture,readonly" \
        "$CAPTURE_IMAGE" tshark -r /capture/m112.pcap -Y 'tcp.len > 0' \
        -T fields -E 'separator=/t' -e tcp.stream -e ipv6.src -e ipv6.dst \
        -e tcp.seq_raw -e tcp.payload >"$ARTIFACT_DIR/payloads.tsv"
}

on_exit() {
    local status=$?
    trap - EXIT INT TERM HUP
    if [ "$CAPTURE_OWNED" -eq 1 ] && [ "$CAPTURE_STOPPED" -eq 0 ] \
        && [ "$(docker inspect -f '{{.State.Running}}' "$CAPTURE" 2>/dev/null)" = true ]; then
        stop_capture >"$ARTIFACT_DIR/capture-stop.log" 2>&1 || true
    fi
    if [ "$ARTIFACT_DIR_OWNED" -eq 1 ]; then
        docker exec "$RUSTBGPD" cat /tmp/m112-rustbgpd.log >"$ARTIFACT_DIR/rustbgpd.log" 2>&1 || true
        docker exec "$SINK" cat /tmp/m112-gobgp.log >"$ARTIFACT_DIR/gobgp.log" 2>&1 || true
        docker exec "$RAW" cat /tmp/m112-source.log >"$ARTIFACT_DIR/source.log" 2>&1 || true
        docker exec "$RAW" cat /tmp/m112-source.json >"$ARTIFACT_DIR/source-final.json" 2>&1 || true
        if [ "$CAPTURE_OWNED" -eq 1 ]; then
            docker logs "$CAPTURE" >"$ARTIFACT_DIR/capture.log" 2>&1 || true
        fi
    fi
    if [ "$CAPTURE_OWNED" -eq 1 ]; then
        if ! docker rm -f "$CAPTURE" >/dev/null 2>&1; then
            echo "ERROR: failed to remove owned capture container $CAPTURE" >&2
            status=1
        fi
    fi
    if [ "$VOLUME_OWNED" -eq 1 ]; then
        if ! docker volume rm "$CAPTURE" >/dev/null 2>&1; then
            echo "ERROR: failed to remove owned capture volume $CAPTURE" >&2
            status=1
        fi
    fi
    _cleanup_on_exit
    if [ "$CLEANUP" = 1 ]; then
        for container in "$RAW" "$RUSTBGPD" "$SINK"; do
            if docker container inspect "$container" >/dev/null 2>&1; then
                echo "ERROR: topology cleanup left $container" >&2
                status=1
            fi
        done
    fi
    if [ "$ARTIFACT_DIR_OWNED" -eq 1 ]; then printf '%s\n' "$status" >"$ARTIFACT_DIR/exit-code.txt"; fi
    exit "$status"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

capture_ready() {
    docker logs "$CAPTURE" 2>&1 | grep 'Capturing on' >/dev/null
}

start_capture() {
    if docker container inspect "$CAPTURE" >/dev/null 2>&1 \
        || docker volume inspect "$CAPTURE" >/dev/null 2>&1; then
        echo "ERROR: capture resource already exists: $CAPTURE" >&2
        return 1
    fi
    docker volume create --label rustbgpd.interop.milestone=M112 "$CAPTURE" >/dev/null
    VOLUME_OWNED=1
    docker create --name "$CAPTURE" --label rustbgpd.interop.milestone=M112 \
        --network "container:$RUSTBGPD" --cap-add=NET_ADMIN --cap-add=NET_RAW \
        --mount "type=volume,src=$CAPTURE,dst=/capture" \
        "$CAPTURE_IMAGE" tshark -p -i any -f 'tcp port 179' -w /capture/m112.pcap >/dev/null
    CAPTURE_OWNED=1
    docker inspect "$CAPTURE" \
        | jq '[.[] | {name:.Name,image:.Image,configured_image:.Config.Image}]' >"$ARTIFACT_DIR/capture-image.json"
    docker start "$CAPTURE" >/dev/null
    wait_for 'capture ready' capture_ready
}

source_state() {
    local phase=$1
    docker exec "$RAW" cat /tmp/m112-source.json \
        | jq -e --arg phase "$phase" '
            .error == "" and .listening and
            (if $phase == "listening" then true
             else .established and .phase == $phase and .last_receive_age_seconds < 90 end)' >/dev/null
}

sink_ready() {
    docker exec "$SINK" gobgp neighbor 2001:db8:112:20::1 -j >/dev/null 2>&1
}

rr_state() {
    local phase=$1
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 evpn \
        --route-type 2 --peer 2001:db8:112:10::2 -j >"$ARTIFACT_DIR/rr-current.json" \
        && python3 "$SCRIPT_DIR/m112_capture_oracle.py" rr "$ARTIFACT_DIR/rr-current.json" \
            --phase "$phase" "${TYPED_ARGS[@]}" >"$ARTIFACT_DIR/rr-current-check.json" 2>"$ARTIFACT_DIR/rr-current-error.log"
}

observer_state() {
    local phase=$1
    # GLOBAL table and only-binary output bypass GoBGP's typed L2 reverse
    # conversion. jq -s preserves a successful empty server stream as [].
    grpcurl -plaintext -max-time 5 -import-path tests/interop/configs \
        -proto gobgp-m112-listpath.proto \
        -d '{"table_type":0,"family":{"afi":25,"safi":70},"enable_only_binary":true}' \
        "$SINK_ADDR" apipb.GobgpApi/ListPath \
        | jq -s . >"$ARTIFACT_DIR/observer-current.json" \
        && python3 "$SCRIPT_DIR/m112_capture_oracle.py" observer "$ARTIFACT_DIR/observer-current.json" \
            --phase "$phase" >"$ARTIFACT_DIR/observer-current-check.json" 2>"$ARTIFACT_DIR/observer-current-error.log"
}

phase() {
    local name=$1
    docker exec "$RAW" python3 /m112_raw_peer.py command "$name"
    wait_for "source phase $name" source_state "$name"
    wait_for "RR phase $name" rr_state "$name"
    wait_for "observer phase $name" observer_state "$name"
    for kind in rr observer; do
        cp "$ARTIFACT_DIR/$kind-current.json" "$ARTIFACT_DIR/$name-$kind.json"
        cp "$ARTIFACT_DIR/$kind-current-check.json" "$ARTIFACT_DIR/$name-$kind-check.json"
    done
    docker exec "$RAW" cat /tmp/m112-source.json >"$ARTIFACT_DIR/$name-source.json"
    echo "PASS: $name"
}

main() {
    case "$REQUIRE_TYPED" in 0|1) ;; *) echo 'M112_REQUIRE_TYPED must be 0 or 1' >&2; return 1 ;; esac
    : "${M112_SOURCE_REVISION:?Set M112_SOURCE_REVISION to the exact labeled DUT image revision}"
    mkdir "$ARTIFACT_DIR"
    ARTIFACT_DIR_OWNED=1
    local revision
    revision=$(docker inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$RUSTBGPD")
    [ "$revision" = "$M112_SOURCE_REVISION" ] || { echo 'DUT source revision label differs' >&2; return 1; }
    jq -n --arg source_revision "$revision" --arg harness_revision "$(git rev-parse HEAD)" \
        --argjson require_typed "$REQUIRE_TYPED" \
        '{source_revision:$source_revision,harness_revision:$harness_revision,require_typed:($require_typed == 1)}' \
        >"$ARTIFACT_DIR/identity.json"
    git diff HEAD -- tests/interop >"$ARTIFACT_DIR/harness.diff"
    git status --porcelain -- tests/interop >"$ARTIFACT_DIR/harness-status.txt"
    sha256sum tests/interop/scripts/{m112_raw_peer,m112_capture_oracle,m105_capture_oracle,m94_as4_oracle,evpn_peer_sync_oracle}.py \
        tests/interop/scripts/{test-m112-srv6-l2-reflection,test-lib,start-rustbgpd}.sh \
        tests/interop/configs/{gobgp-m112-listpath.proto,gobgp-m112-srv6-sink.toml,rustbgpd-m112-srv6-rr.toml} \
        tests/interop/m112-srv6-l2-reflection.clab.yml >"$ARTIFACT_DIR/harness-sha256.txt"
    docker inspect "$RAW" "$RUSTBGPD" "$SINK" \
        | jq '[.[] | {name:.Name,image:.Image,configured_image:.Config.Image}]' >"$ARTIFACT_DIR/images.json"
    docker exec "$RUSTBGPD" rustbgpd --check --strict /etc/rustbgpd/config.toml
    docker exec "$SINK" gobgpd -d -f /config/gobgp.toml
    docker exec "$SINK" gobgpd --version >"$ARTIFACT_DIR/gobgp-version.txt"
    grep -qx 'gobgpd version 3\.37\.0' "$ARTIFACT_DIR/gobgp-version.txt"
    docker exec "$RUSTBGPD" rustbgpd --version >"$ARTIFACT_DIR/rustbgpd-version.txt"
    SINK_ADDR="$(resolve_ip "$SINK"):50051"
    start_capture
    docker exec -d "$RAW" sh -c 'python3 /m112_raw_peer.py serve >/tmp/m112-source.log 2>&1'
    docker exec -d "$SINK" sh -c 'gobgpd -f /config/gobgp.toml >/tmp/m112-gobgp.log 2>&1'
    wait_for 'source listener ready' source_state listening
    wait_for 'GoBGP configured' sink_ready
    # Both passive peers are ready before the RR opens the two sessions.
    docker exec -d "$RUSTBGPD" sh -c '/usr/local/bin/start-rustbgpd.sh >/tmp/m112-rustbgpd.log 2>&1'
    for name in baseline malformed recovery withdraw cleanup; do phase "$name"; done
    source_state cleanup
    docker exec "$SINK" gobgp neighbor 2001:db8:112:20::1 -j >"$ARTIFACT_DIR/sink-final-session.json"
    jq -e '.state.session_state == 6' "$ARTIFACT_DIR/sink-final-session.json" >/dev/null
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 neighbor -j >"$ARTIFACT_DIR/rr-final-sessions.json"
    jq -e 'length == 2 and all(.[]; .state == "Established" and (.stale | not))
        and ([.[].address] | sort) == ["2001:db8:112:10::2", "2001:db8:112:20::2"]' \
        "$ARTIFACT_DIR/rr-final-sessions.json" >/dev/null
    stop_capture
    python3 "$SCRIPT_DIR/m112_capture_oracle.py" wire "$ARTIFACT_DIR/payloads.tsv" >"$ARTIFACT_DIR/wire.json"
    echo "PASS: MAC-only SRv6 L2 reflection, malformed replacement, recovery and withdrawals (typed required=$REQUIRE_TYPED)"
}
main "$@"
