#!/usr/bin/env bash
# M105 — live AS_SET receiver behavior across five current route servers.
set -euo pipefail

TOPO=m105-live-as-set
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLEANUP="${CLEANUP:-1}"
INTEROP_TEST_OPERATOR_AUTH=1
export CLEANUP INTEROP_TEST_OPERATOR_AUTH
# shellcheck disable=SC1091 # resolved from SCRIPT_DIR at runtime
source "$SCRIPT_DIR/test-lib.sh"

BIRD="clab-${TOPO}-bird"
OPENBGPD="clab-${TOPO}-openbgpd"
GOBGP="clab-${TOPO}-gobgp"
FRR="clab-${TOPO}-frr"
RAW="clab-${TOPO}-raw"
RAW_ADDR=10.105.0.10
BASELINE=198.51.104.0/24
PROBE=198.51.105.0/24
CAPTURE_IMAGE=bmpsink:m102
CAPTURE_CONTAINER=m105-live-as-set-capture
CAPTURE_VOLUME=m105-live-as-set-capture
ARTIFACT_DIR="${M105_ARTIFACT_DIR:-/tmp/m105-live-as-set-artifacts}"
CAPTURE_RUNNING=0

declare -A OUTCOMES=()

die() {
    echo "ERROR: $*" >&2
    exit 1
}

check() {
    local label=${1:?}
    shift
    if "$@"; then
        printf 'PASS: %s\n' "$label"
    else
        die "$label"
    fi
}

wait_until() {
    local label=${1:?}
    shift
    for _ in $(seq 1 45); do
        "$@" >/dev/null 2>&1 && return 0
        sleep 1
    done
    echo "timeout waiting for $label" >&2
    return 1
}

process_running() {
    local container=${1:?} process=${2:?}
    docker exec "$container" sh -c 'grep -qx "$1" /proc/[0-9]*/comm 2>/dev/null' sh "$process"
}

configured_image_is_local() {
    local container=${1:?} image=${2:?}
    [ "$(docker inspect -f '{{.Config.Image}}' "$container")" = "$image" ] \
        && [ "$(docker inspect -f '{{.Image}}' "$container")" \
            = "$(docker image inspect -f '{{.Id}}' "$image")" ]
}

bird_identity() {
    configured_image_is_local "$BIRD" bird:v3.3.2-m101 \
        && [ "$(docker exec "$BIRD" bird --version 2>&1)" = "BIRD version 3.3.2" ]
}

openbgpd_identity() {
    local image='openbgpd/openbgpd@sha256:b2e94bd1538102a89cff96867993eabb6dbb27720de4ab7b588860880e3e3bf9'
    configured_image_is_local "$OPENBGPD" "$image" \
        && [ "$(docker exec "$OPENBGPD" bgpd -V 2>&1)" = "OpenBGPD 9.2" ]
}

gobgp_identity() {
    configured_image_is_local "$GOBGP" gobgp:v4.8.0-m103 \
        && [ "$(docker exec "$GOBGP" gobgpd --version 2>&1)" = "gobgpd version 4.8.0" ]
}

frr_identity() {
    local image='quay.io/frrouting/frr@sha256:f90d26a9fd5c14fc5795a73b4254ac88bc3186c45bbeb220a225fb6182de812c'
    configured_image_is_local "$FRR" "$image" \
        && [ "$(docker exec "$FRR" /usr/lib/frr/bgpd --version 2>&1 | sed -n 1p)" \
            = "bgpd version 10.3.1_git" ]
}

preflight_receivers() {
    check "rustbgpd image is the current local build" \
        configured_image_is_local "$RUSTBGPD" rustbgpd:dev
    check "BIRD image and runtime are exact" bird_identity
    check "OpenBGPD image and runtime are exact" openbgpd_identity
    check "GoBGP image and runtime are exact" gobgp_identity
    check "FRR image and runtime are exact" frr_identity

    check "rustbgpd accepts its M105 config" \
        docker exec "$RUSTBGPD" rustbgpd --check --strict /etc/rustbgpd/config.toml
    check "BIRD accepts its M105 config" \
        docker exec "$BIRD" bird -p -c /etc/bird/bird.conf
    check "OpenBGPD accepts its M105 config" \
        docker exec "$OPENBGPD" bgpd -n -f /etc/bgpd.conf
    check "GoBGP accepts its M105 config" \
        docker exec "$GOBGP" gobgpd -d -f /config/gobgp.toml
    check "FRR accepts its M105 config" \
        docker exec "$FRR" /usr/lib/frr/bgpd -C -f /etc/frr/frr.conf
}

write_identities() {
    jq -n \
        --arg rust_image "$(docker inspect -f '{{.Image}}' "$RUSTBGPD")" \
        --arg rust_version "$(docker exec "$RUSTBGPD" rustbgpd --version 2>&1)" \
        --arg bird_image "$(docker inspect -f '{{.Image}}' "$BIRD")" \
        --arg bird_version "$(docker exec "$BIRD" bird --version 2>&1)" \
        --arg open_image "$(docker inspect -f '{{.Image}}' "$OPENBGPD")" \
        --arg open_version "$(docker exec "$OPENBGPD" bgpd -V 2>&1)" \
        --arg gobgp_image "$(docker inspect -f '{{.Image}}' "$GOBGP")" \
        --arg gobgp_version "$(docker exec "$GOBGP" gobgpd --version 2>&1)" \
        --arg frr_image "$(docker inspect -f '{{.Image}}' "$FRR")" \
        --arg frr_version "$(docker exec "$FRR" /usr/lib/frr/bgpd --version 2>&1 | sed -n 1p)" \
        --arg capture_image "$(docker image inspect -f '{{.Id}}' "$CAPTURE_IMAGE")" \
        '{schema:"m105-identities/1",receivers:{rustbgpd:{image:$rust_image,version:$rust_version},bird:{image:$bird_image,version:$bird_version},openbgpd:{image:$open_image,version:$open_version},gobgp:{image:$gobgp_image,version:$gobgp_version},frr:{image:$frr_image,version:$frr_version}},raw_and_capture_image:$capture_image}' \
        >"$ARTIFACT_DIR/identities.json"
}

cleanup_capture() {
    set +e
    if docker container inspect "$CAPTURE_CONTAINER" >/dev/null 2>&1; then
        if [ "$(docker inspect -f '{{.State.Running}}' "$CAPTURE_CONTAINER" 2>/dev/null)" = true ]; then
            timeout 10 docker kill --signal=SIGINT "$CAPTURE_CONTAINER" >/dev/null 2>&1
            timeout 10 docker wait "$CAPTURE_CONTAINER" >/dev/null 2>&1
        fi
        docker rm -f "$CAPTURE_CONTAINER" >/dev/null 2>&1
    fi
    docker volume rm -f "$CAPTURE_VOLUME" >/dev/null 2>&1
}

m105_on_exit() {
    local status=$?
    trap - EXIT INT TERM HUP
    if [ "$status" -ne 0 ] && [ -d "$ARTIFACT_DIR" ]; then
        docker exec "$RAW" cat /tmp/m105-events.jsonl \
            >"$ARTIFACT_DIR/events.partial.jsonl" 2>/dev/null || true
        docker exec "$RAW" cat /tmp/m105-raw.log \
            >"$ARTIFACT_DIR/raw-peer.partial.log" 2>/dev/null || true
        for pair in \
            "$RUSTBGPD:/tmp/m105-rustbgpd.log:rustbgpd" \
            "$BIRD:/tmp/m105-bird.log:bird" \
            "$OPENBGPD:/tmp/m105-openbgpd.log:openbgpd" \
            "$GOBGP:/tmp/m105-gobgp.log:gobgp"; do
            IFS=: read -r container path name <<<"$pair"
            docker exec "$container" cat "$path" \
                >"$ARTIFACT_DIR/${name}.partial.log" 2>/dev/null || true
        done
        docker logs "$FRR" >"$ARTIFACT_DIR/frr.partial.log" 2>&1 || true
    fi
    cleanup_capture
    _cleanup_on_exit
    exit "$status"
}
trap m105_on_exit EXIT INT TERM HUP

start_capture() {
    cleanup_capture
    docker volume create --label rustbgpd.interop.milestone=M105 "$CAPTURE_VOLUME" >/dev/null
    docker run -d --name "$CAPTURE_CONTAINER" \
        --label rustbgpd.interop.milestone=M105 \
        --network "container:$RAW" \
        --cap-add=NET_ADMIN --cap-add=NET_RAW \
        --mount "type=volume,src=$CAPTURE_VOLUME,dst=/capture" \
        "$CAPTURE_IMAGE" tshark -p -i any \
        -f 'tcp port 179 and net 10.105.0.0/24' -w /capture/m105.pcap >/dev/null
    for _ in $(seq 1 20); do
        if [ "$(docker inspect -f '{{.State.Running}}' "$CAPTURE_CONTAINER" 2>/dev/null)" = true ] \
            && docker logs "$CAPTURE_CONTAINER" 2>&1 | grep 'Capturing on' >/dev/null; then
            CAPTURE_RUNNING=1
            return 0
        fi
        sleep .25
    done
    return 1
}

stop_capture() {
    [ "$CAPTURE_RUNNING" -eq 1 ] || return 1
    timeout 10 docker kill --signal=SIGINT "$CAPTURE_CONTAINER" >/dev/null
    local status
    status=$(timeout 10 docker wait "$CAPTURE_CONTAINER")
    case "$status" in 0|130) ;; *) return 1 ;; esac
    CAPTURE_RUNNING=0
    docker run --rm \
        --mount "type=volume,src=$CAPTURE_VOLUME,dst=/capture,readonly" \
        "$CAPTURE_IMAGE" sh -ec 'test -s /capture/m105.pcap; cat /capture/m105.pcap' \
        >"$ARTIFACT_DIR/m105.pcap"
    docker run --rm \
        --mount "type=volume,src=$CAPTURE_VOLUME,dst=/capture,readonly" \
        "$CAPTURE_IMAGE" tshark -r /capture/m105.pcap -Y 'tcp.len > 0' \
        -T fields -E 'separator=/t' \
        -e tcp.stream -e ip.src -e ip.dst -e tcp.seq_raw -e tcp.payload \
        >"$ARTIFACT_DIR/payloads.tsv"
}

start_daemons() {
    docker exec -d "$RUSTBGPD" sh -c \
        '/usr/local/bin/start-rustbgpd.sh >/tmp/m105-rustbgpd.log 2>&1'
    docker exec -d "$BIRD" sh -c \
        'bird -d -c /etc/bird/bird.conf >/tmp/m105-bird.log 2>&1'
    docker exec "$OPENBGPD" sh -c \
        'mkdir -p /run/bgpd; rm -f /run/bgpd/bgpd.sock.* /run/bgpd/bgpd.rsock*; bgpd -d -f /etc/bgpd.conf >/tmp/m105-openbgpd.log 2>&1 &'
    docker exec -d "$GOBGP" sh -c \
        'gobgpd -f /config/gobgp.toml >/tmp/m105-gobgp.log 2>&1'
    docker exec "$FRR" /usr/lib/frr/frrinit.sh start >/dev/null
}

rs_ctl() {
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 "$@" 2>/dev/null
}

rust_has() {
    rs_ctl rib received "$RAW_ADDR" -a ipv4 -j \
        | jq -e --arg prefix "$1" 'any(.[]?; .prefix == $prefix)' >/dev/null
}

rust_absent() {
    rs_ctl rib received "$RAW_ADDR" -a ipv4 -j \
        | jq -e --arg prefix "$1" 'all(.[]?; .prefix != $prefix)' >/dev/null
}

bird_has() {
    docker exec "$BIRD" birdc -r show route for "$1" protocol raw_peer all 2>/dev/null \
        | grep -F "$1" >/dev/null
}

bird_absent() {
    local output
    output=$(docker exec "$BIRD" birdc -r show route for "$1" protocol raw_peer all 2>/dev/null)
    ! grep -F "$1" <<<"$output" >/dev/null
}

open_has() {
    docker exec "$OPENBGPD" bgpctl -j show rib "$1" 2>/dev/null \
        | jq -e --arg prefix "$1" 'any(.rib[]?; .prefix == $prefix)' >/dev/null
}

open_absent() {
    docker exec "$OPENBGPD" bgpctl -j show rib "$1" 2>/dev/null \
        | jq -e --arg prefix "$1" 'all(.rib[]?; .prefix != $prefix)' >/dev/null
}

gobgp_has() {
    # A route-server-client path remains in the peer's accepted Adj-RIB-In;
    # GoBGP does not copy this single-client control into its global table.
    docker exec "$GOBGP" gobgp neighbor "$RAW_ADDR" adj-in -a ipv4 -j 2>/dev/null \
        | jq -e --arg prefix "$1" 'has($prefix) and (.[$prefix] | length > 0)' >/dev/null
}

gobgp_absent() {
    docker exec "$GOBGP" gobgp neighbor "$RAW_ADDR" adj-in -a ipv4 -j 2>/dev/null \
        | jq -e --arg prefix "$1" '((.[$prefix] // []) | length) == 0' >/dev/null
}

frr_has() {
    docker exec "$FRR" vtysh -c "show bgp ipv4 unicast $1 json" 2>/dev/null \
        | jq -e '.paths | length > 0' >/dev/null
}

frr_absent() {
    docker exec "$FRR" vtysh -c "show bgp ipv4 unicast $1 json" 2>/dev/null \
        | jq -e '((.paths // []) | length) == 0' >/dev/null
}

rust_established() {
    rs_ctl neighbor "$RAW_ADDR" 2>/dev/null | grep -i established >/dev/null
}

bird_established() {
    docker exec "$BIRD" birdc -r show protocols raw_peer 2>/dev/null \
        | grep -i established >/dev/null
}

open_established() {
    docker exec "$OPENBGPD" bgpctl -j show 2>/dev/null \
        | jq -e 'any(.neighbors[]?; .remote_addr == "10.105.0.10" and .state == "Established")' >/dev/null
}

gobgp_established() {
    docker exec "$GOBGP" gobgp neighbor "$RAW_ADDR" 2>/dev/null \
        | grep -i established >/dev/null
}

frr_established() {
    docker exec "$FRR" vtysh -c "show bgp neighbors $RAW_ADDR json" 2>/dev/null \
        | jq -e --arg peer "$RAW_ADDR" '.[$peer].bgpState == "Established"' >/dev/null
}

all_have() {
    local prefix=${1:?}
    rust_has "$prefix" && bird_has "$prefix" && open_has "$prefix" \
        && gobgp_has "$prefix" && frr_has "$prefix"
}

all_absent() {
    local prefix=${1:?}
    rust_absent "$prefix" && bird_absent "$prefix" && open_absent "$prefix" \
        && gobgp_absent "$prefix" && frr_absent "$prefix"
}

all_established() {
    rust_established && bird_established && open_established \
        && gobgp_established && frr_established
}

report_presence() {
    local prefix=${1:?} receiver
    for receiver in rust bird open gobgp frr; do
        if "${receiver}_has" "$prefix"; then
            printf 'presence %s %s: installed\n' "$receiver" "$prefix" >&2
        else
            printf 'presence %s %s: absent-or-uninspectable\n' "$receiver" "$prefix" >&2
        fi
    done
}

all_processes_running() {
    process_running "$RUSTBGPD" rustbgpd \
        && process_running "$BIRD" bird \
        && process_running "$OPENBGPD" bgpd \
        && process_running "$GOBGP" gobgpd \
        && process_running "$FRR" bgpd
}

raw_events_clean() {
    docker exec "$RAW" sh -c '
        test -s /tmp/m105-events.jsonl || exit 2
        grep -Eq "$1" /tmp/m105-events.jsonl
        case $? in
            0) exit 1 ;;
            1) exit 0 ;;
            *) exit 2 ;;
        esac
    ' sh '"event":"(notification|closed|reader_error|fatal)"|"prefix_bearing":true'
}

both_routes_absent() {
    all_absent "$BASELINE" && all_absent "$PROBE"
}

raw_listener_ready() {
    docker exec "$RAW" sh -c \
        'test -s /tmp/m105-events.jsonl && grep -F '"'"'"event":"listening"'"'"' /tmp/m105-events.jsonl >/dev/null'
}

record_outcomes() {
    local receiver
    for receiver in rust bird open gobgp frr; do
        if "${receiver}_has" "$PROBE"; then
            OUTCOMES[$receiver]=installed
        elif "${receiver}_absent" "$PROBE"; then
            OUTCOMES[$receiver]=not_installed
        else
            die "could not classify $receiver AS_SET observation"
        fi
    done
    jq -n \
        --arg rustbgpd "${OUTCOMES[rust]}" \
        --arg bird "${OUTCOMES[bird]}" \
        --arg openbgpd "${OUTCOMES[open]}" \
        --arg gobgp "${OUTCOMES[gobgp]}" \
        --arg frr "${OUTCOMES[frr]}" \
        '{schema:"m105-outcomes/1",prefix:"198.51.105.0/24",as_path:{segment_type:1,members:[64512,64513]},outcomes:{rustbgpd:$rustbgpd,bird:$bird,openbgpd:$openbgpd,gobgp:$gobgp,frr:$frr}}' \
        >"$ARTIFACT_DIR/outcomes.json"
}

snapshot_as_set_observations() {
    local directory="$ARTIFACT_DIR/observations"
    mkdir -p "$directory"
    rs_ctl rib received "$RAW_ADDR" -a ipv4 -j >"$directory/rustbgpd.json"
    docker exec "$BIRD" birdc -r show route for "$PROBE" protocol raw_peer all \
        >"$directory/bird.txt"
    docker exec "$OPENBGPD" bgpctl -j show rib "$PROBE" \
        >"$directory/openbgpd.json"
    docker exec "$GOBGP" gobgp neighbor "$RAW_ADDR" adj-in -a ipv4 -j \
        >"$directory/gobgp.json"
    docker exec "$FRR" vtysh -c "show bgp ipv4 unicast $PROBE json" \
        >"$directory/frr.json"
}

mkdir -p "$ARTIFACT_DIR"
preflight_receivers
write_identities

docker exec -d "$RAW" sh -c 'python3 /m105_raw_peer.py >/tmp/m105-raw.log 2>&1'
wait_until "raw listener" raw_listener_ready
check "capture sidecar is ready before receiver startup" start_capture
start_daemons
wait_until "all five raw sessions" docker exec "$RAW" test -s /tmp/m105-ready
check "all five receiver sessions established" all_established

docker exec "$RAW" touch /tmp/m105-send-baseline
if ! wait_until "baseline route at all five receivers" all_have "$BASELINE"; then
    report_presence "$BASELINE"
    die "ordinary AS_SEQUENCE control did not reach every receiver"
fi
check "ordinary AS_SEQUENCE control reaches every receiver" all_have "$BASELINE"

docker exec "$RAW" touch /tmp/m105-send-as-set
sleep 5
snapshot_as_set_observations
record_outcomes
check "all receiver sessions survive the AS_SET observation" all_established
check "all receiver daemons remain live" all_processes_running
check "raw peer saw no notification, closure, error, or reverse route" raw_events_clean

docker exec "$RAW" touch /tmp/m105-send-withdraw
wait_until "baseline withdrawal at all receivers" all_absent "$BASELINE"
wait_until "AS_SET withdrawal at all receivers" all_absent "$PROBE"
check "both routes are absent after withdrawal" both_routes_absent
check "all receiver sessions survive withdrawal" all_established
check "raw peer remains clean through withdrawal" raw_events_clean

docker exec "$RAW" touch /tmp/m105-stop
sleep 1
docker exec "$RAW" cat /tmp/m105-events.jsonl >"$ARTIFACT_DIR/events.jsonl"
docker exec "$RAW" cat /tmp/m105-raw.log >"$ARTIFACT_DIR/raw-peer.log"
check "capture flushes with payload evidence" stop_capture
python3 "$SCRIPT_DIR/m105_capture_oracle.py" "$ARTIFACT_DIR/payloads.tsv" \
    >"$ARTIFACT_DIR/wire.json"
check "packet oracle covers all five receivers" jq -e \
    '.schema == "m105-wire/1" and (.receivers | keys | sort) == ["bird","frr","gobgp","openbgpd","rustbgpd"]' \
    "$ARTIFACT_DIR/wire.json"

printf 'M105 artifacts: %s\n' "$ARTIFACT_DIR"
jq . "$ARTIFACT_DIR/outcomes.json"
printf 'M105 live discovery complete\n'
