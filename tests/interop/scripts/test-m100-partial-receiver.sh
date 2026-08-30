#!/usr/bin/env bash
# M100 — malformed Partial flag receiver behavior across four current daemons.
set -euo pipefail

TOPO=m100-partial-receiver
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLEANUP="${CLEANUP:-1}"
INTEROP_TEST_OPERATOR_AUTH=1
export CLEANUP INTEROP_TEST_OPERATOR_AUTH
# shellcheck disable=SC1091 # resolved from SCRIPT_DIR at runtime
source "$SCRIPT_DIR/test-lib.sh"

BIRD="clab-${TOPO}-bird"
OPENBGPD="clab-${TOPO}-openbgpd"
FRR="clab-${TOPO}-frr"
RAW="clab-${TOPO}-raw"
SWITCH="clab-${TOPO}-switch"
RAW_ADDR=10.105.0.10
CANDIDATE=198.51.100.0/24
SURVIVOR=198.51.101.0/24
ARTIFACT_DIR="${M100_ARTIFACT_DIR:-/tmp/m100-partial-receiver-artifacts}"
CASES=(med originator_id cluster_list mp_reach mp_unreach)
RECEIVERS=(rustbgpd bird openbgpd frr)

m100_on_exit() {
    local status=$?
    trap - EXIT INT TERM HUP
    if [ "$status" -ne 0 ] && docker inspect "$RAW" >/dev/null 2>&1; then
        mkdir -p "$ARTIFACT_DIR"
        docker exec "$RAW" cat /tmp/m100-events.jsonl \
            >"$ARTIFACT_DIR/events.partial.jsonl" 2>/dev/null || true
        docker exec "$RAW" cat /tmp/m100-raw.log \
            >"$ARTIFACT_DIR/raw-peer.partial.log" 2>/dev/null || true
        docker exec "$RUSTBGPD" cat /tmp/m100-rustbgpd.log \
            >"$ARTIFACT_DIR/rustbgpd.partial.log" 2>/dev/null || true
        docker exec "$BIRD" cat /tmp/m100-bird.log \
            >"$ARTIFACT_DIR/bird.partial.log" 2>/dev/null || true
        docker exec "$OPENBGPD" cat /tmp/m100-openbgpd.log \
            >"$ARTIFACT_DIR/openbgpd.partial.log" 2>/dev/null || true
        docker logs "$FRR" >"$ARTIFACT_DIR/frr.partial.log" 2>&1 || true
    fi
    _cleanup_on_exit
    exit "$status"
}
trap m100_on_exit EXIT INT TERM HUP

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
    for _ in $(seq 1 120); do
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

configure_rust_network() {
    docker run --rm \
        --network "container:$RUSTBGPD" \
        --cap-add=NET_ADMIN \
        bmpsink:m100 sh -ec \
        'ip addr replace 10.105.0.1/24 dev eth1; ip link set eth1 up'
}

preflight_receivers() {
    local rust_image='ghcr.io/lance0/rustbgpd@sha256:cc6207fe950ee15f6793ca0119d531067c7b358b6c6193b0fda929495714c9da'
    local open_image='openbgpd/openbgpd@sha256:b2e94bd1538102a89cff96867993eabb6dbb27720de4ab7b588860880e3e3bf9'
    local frr_image='quay.io/frrouting/frr@sha256:f90d26a9fd5c14fc5795a73b4254ac88bc3186c45bbeb220a225fb6182de812c'
    check "rustbgpd image is exact v0.67.0" configured_image_is_local "$RUSTBGPD" "$rust_image"
    check "rustbgpd runtime is exact v0.67.0" test \
        "$(docker exec "$RUSTBGPD" rustbgpd --version 2>&1)" = "rustbgpd 0.67.0"
    check "BIRD image is exact" configured_image_is_local "$BIRD" bird:v2.19.2-m100
    check "BIRD runtime is exact 2.19.2" test \
        "$(docker exec "$BIRD" bird --version 2>&1)" = "BIRD version 2.19.2"
    check "OpenBGPD image is exact" configured_image_is_local "$OPENBGPD" "$open_image"
    check "OpenBGPD runtime is exact 9.2" test \
        "$(docker exec "$OPENBGPD" bgpd -V 2>&1)" = "OpenBGPD 9.2"
    check "FRR image is exact" configured_image_is_local "$FRR" "$frr_image"
    check "FRR runtime is exact 10.3.1" test \
        "$(docker exec "$FRR" /usr/lib/frr/bgpd --version 2>&1 | sed -n 1p)" \
        = "bgpd version 10.3.1_git"
    check "raw fixture image is exact" configured_image_is_local "$RAW" bmpsink:m100
    check "switch fixture image is exact" configured_image_is_local "$SWITCH" bmpsink:m100
    check "raw fixture exact-hex self-test" docker exec "$RAW" \
        python3 /m100_partial_raw_peer.py --self-test

    check "rustbgpd accepts the M100 receiver config" \
        docker exec "$RUSTBGPD" rustbgpd --check --strict /etc/rustbgpd/config.toml
    check "BIRD accepts the M100 receiver config" \
        docker exec "$BIRD" bird -p -c /etc/bird/bird.conf
    check "OpenBGPD accepts the M100 receiver config" \
        docker exec "$OPENBGPD" bgpd -n -f /etc/bgpd.conf
    check "FRR accepts the M100 receiver config" \
        docker exec "$FRR" /usr/lib/frr/bgpd -C -f /etc/frr/frr.conf
}

start_daemons() {
    docker exec -d "$RUSTBGPD" sh -c \
        '/usr/local/bin/start-rustbgpd.sh >/tmp/m100-rustbgpd.log 2>&1'
    docker exec -d "$BIRD" sh -c \
        'bird -d -c /etc/bird/bird.conf >/tmp/m100-bird.log 2>&1'
    docker exec "$OPENBGPD" sh -c \
        'mkdir -p /run/bgpd; rm -f /run/bgpd/bgpd.sock.* /run/bgpd/bgpd.rsock*; bgpd -d -f /etc/bgpd.conf >/tmp/m100-openbgpd.log 2>&1 &'
    docker exec "$FRR" /usr/lib/frr/frrinit.sh start >/dev/null
}

restart_openbgpd_case() {
    docker exec "$OPENBGPD" sh -c '
        pkill -9 bgpd 2>/dev/null || true
        rm -f /run/bgpd/bgpd.sock.* /run/bgpd/bgpd.rsock*
        bgpd -d -f /etc/bgpd.conf >>/tmp/m100-openbgpd.log 2>&1 &
    '
}

rs_ctl() {
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 "$@" 2>/dev/null
}

rustbgpd_has() {
    rs_ctl rib received "$RAW_ADDR" -a ipv4 -j \
        | jq -e --arg prefix "$1" 'any(.[]?; .prefix == $prefix)' >/dev/null
}

rustbgpd_absent() {
    rs_ctl rib received "$RAW_ADDR" -a ipv4 -j \
        | jq -e --arg prefix "$1" 'all(.[]?; .prefix != $prefix)' >/dev/null
}

bird_has() {
    docker exec "$BIRD" birdc -r show route for "$1" protocol source_peer all 2>/dev/null \
        | grep -F "$1" >/dev/null
}

bird_absent() {
    local output
    output=$(docker exec "$BIRD" birdc -r show route for "$1" protocol source_peer all 2>/dev/null)
    ! grep -F "$1" <<<"$output" >/dev/null
}

openbgpd_has() {
    docker exec "$OPENBGPD" bgpctl -j show rib "$1" 2>/dev/null \
        | jq -e --arg prefix "$1" 'any(.rib[]?; .prefix == $prefix)' >/dev/null
}

openbgpd_absent() {
    docker exec "$OPENBGPD" bgpctl -j show rib "$1" 2>/dev/null \
        | jq -e --arg prefix "$1" 'all(.rib[]?; .prefix != $prefix)' >/dev/null
}

frr_has() {
    docker exec "$FRR" vtysh -c "show bgp ipv4 unicast $1 json" 2>/dev/null \
        | jq -e '.paths | length > 0' >/dev/null
}

frr_absent() {
    docker exec "$FRR" vtysh -c "show bgp ipv4 unicast $1 json" 2>/dev/null \
        | jq -e '((.paths // []) | length) == 0' >/dev/null
}

rustbgpd_established() {
    rs_ctl neighbor "$RAW_ADDR" 2>/dev/null | grep -i established >/dev/null
}

bird_established() {
    docker exec "$BIRD" birdc -r show protocols source_peer 2>/dev/null \
        | grep -i established >/dev/null
}

openbgpd_established() {
    docker exec "$OPENBGPD" bgpctl -j show 2>/dev/null \
        | jq -e 'any(.neighbors[]?; .remote_addr == "10.105.0.10" and .state == "Established")' >/dev/null
}

frr_established() {
    docker exec "$FRR" vtysh -c "show bgp neighbors $RAW_ADDR json" 2>/dev/null \
        | jq -e --arg peer "$RAW_ADDR" '.[$peer].bgpState == "Established"' >/dev/null
}

all_have() {
    local prefix=${1:?} receiver
    for receiver in "${RECEIVERS[@]}"; do
        "${receiver}_has" "$prefix" || return 1
    done
}

all_established() {
    local receiver
    for receiver in "${RECEIVERS[@]}"; do
        "${receiver}_established" || return 1
    done
}

all_processes_running() {
    process_running "$RUSTBGPD" rustbgpd \
        && process_running "$BIRD" bird \
        && process_running "$OPENBGPD" bgpd \
        && process_running "$FRR" bgpd
}

last_event_epoch() {
    local receiver=${1:?} event=${2:?} case_name=${3:-}
    docker exec "$RAW" cat /tmp/m100-events.jsonl \
        | jq -rs --arg peer "$receiver" --arg event "$event" --arg case "$case_name" \
            '[.[] | select(.peer == $peer and .channel == "source" and .event == $event and ($case == "" or .case == $case))] | last | .epoch // 0'
}

notification_for_epoch() {
    local receiver=${1:?} epoch=${2:?}
    docker exec "$RAW" cat /tmp/m100-events.jsonl \
        | jq -cs --arg peer "$receiver" --argjson epoch "$epoch" \
            '[.[] | select(.peer == $peer and .channel == "source" and .event == "notification" and .epoch == $epoch)] | last // {}'
}

snapshot_receiver() {
    local receiver=${1:?} case_name=${2:?} phase=${3:?} expected_present=${4:?}
    local directory="$ARTIFACT_DIR/observations/$case_name"
    local output status=0
    mkdir -p "$directory"
    case "$receiver" in
        rustbgpd)
            output="$directory/${phase}-rustbgpd.json"
            rs_ctl rib received "$RAW_ADDR" -a ipv4 -j >"$output" || status=$?
            ;;
        bird)
            output="$directory/${phase}-bird.txt"
            docker exec "$BIRD" birdc -r show route for "$CANDIDATE" protocol source_peer all \
                >"$output" 2>&1 || status=$?
            if [ "$status" -ne 0 ] && grep -F "Network not found" "$output" >/dev/null; then
                status=0
            fi
            ;;
        openbgpd)
            output="$directory/${phase}-openbgpd.json"
            docker exec "$OPENBGPD" bgpctl -j show rib "$CANDIDATE" >"$output" || status=$?
            ;;
        frr)
            output="$directory/${phase}-frr.json"
            docker exec "$FRR" vtysh -c "show bgp ipv4 unicast $CANDIDATE json" \
                >"$output" || status=$?
            ;;
        *) die "unknown receiver $receiver" ;;
    esac
    [ "$status" -eq 0 ] || return 75
    python3 "$SCRIPT_DIR/m100_partial_raw_peer.py" --validate-snapshot \
        "$receiver" "$output" "$case_name" "$expected_present" || return 76
}

classify_receiver() {
    local receiver=${1:?} case_name=${2:?} before_epoch=${3:?}
    local after_epoch notification candidate survivor outcome
    after_epoch=$(last_event_epoch "$receiver" established)
    notification=$(notification_for_epoch "$receiver" "$before_epoch")
    candidate=false
    survivor=false
    "${receiver}_has" "$CANDIDATE" && candidate=true
    "${receiver}_has" "$SURVIVOR" && survivor=true
    if [ "$after_epoch" -gt "$before_epoch" ] || [ "$(jq -r '.code // 0' <<<"$notification")" -ne 0 ]; then
        outcome=reset
    elif [ "$survivor" != true ]; then
        die "$receiver/$case_name lost the survivor without a recorded reset"
    elif [ "$candidate" = true ]; then
        outcome=accepted
    elif [ "$case_name" = mp_unreach ]; then
        outcome=same_session_withdrawal
    else
        outcome=treat_as_withdraw
    fi
    jq -cn \
        --arg receiver "$receiver" \
        --arg case "$case_name" \
        --arg outcome "$outcome" \
        --argjson epoch_before "$before_epoch" \
        --argjson epoch_after "$after_epoch" \
        --argjson candidate "$candidate" \
        --argjson survivor "$survivor" \
        --argjson notification "$notification" \
        '{receiver:$receiver,case:$case,outcome:$outcome,epoch_before:$epoch_before,epoch_after:$epoch_after,candidate_present:$candidate,survivor_present:$survivor,notification:$notification}'
}

mkdir -p "$ARTIFACT_DIR/observations"
: >"$ARTIFACT_DIR/outcomes.jsonl"
check "release-image network namespace configured" configure_rust_network
preflight_receivers

docker exec -d "$RAW" sh -c 'python3 /m100_partial_raw_peer.py >/tmp/m100-raw.log 2>&1'
wait_until "raw listener" docker exec "$RAW" test -s /tmp/m100-events.jsonl
start_daemons
wait_until "all four raw sessions" docker exec "$RAW" test -s /tmp/m100-ready
check "all four receiver sessions established" all_established

for case_name in "${CASES[@]}"; do
    docker exec "$RAW" touch "/tmp/m100-${case_name}-prepare"
    wait_until "$case_name baseline send" docker exec "$RAW" test -s "/tmp/m100-${case_name}-prepare.sent"
    wait_until "$case_name candidate at all receivers" all_have "$CANDIDATE"
    wait_until "$case_name survivor at all receivers" all_have "$SURVIVOR"
    for receiver in "${RECEIVERS[@]}"; do
        snapshot_receiver "$receiver" "$case_name" baseline true
    done

    docker exec "$RAW" touch "/tmp/m100-${case_name}-malformed"
    wait_until "$case_name malformed send" docker exec "$RAW" test -s "/tmp/m100-${case_name}-malformed.sent"
    sleep 4
    for receiver in "${RECEIVERS[@]}"; do
        before_epoch=$(last_event_epoch "$receiver" send "$case_name")
        [ "$before_epoch" -gt 0 ] || die "$receiver/$case_name has no malformed send epoch"
        row=$(classify_receiver "$receiver" "$case_name" "$before_epoch")
        printf '%s\n' "$row" >>"$ARTIFACT_DIR/outcomes.jsonl"
        candidate_present=$(jq -r '.candidate_present' <<<"$row")
        snapshot_status=0
        snapshot_receiver "$receiver" "$case_name" malformed "$candidate_present" \
            || snapshot_status=$?
        if [ "$snapshot_status" -ne 0 ]; then
            [ "$snapshot_status" -eq 75 ] \
                || die "$receiver/$case_name observation output failed validation"
            [ "$(jq -r '.outcome' <<<"$row")" = reset ] \
                || die "$receiver/$case_name observation command failed for a non-reset outcome"
            printf 'status command unavailable during recorded reset\n' \
                >"$ARTIFACT_DIR/observations/$case_name/malformed-${receiver}.unavailable.txt"
        fi
    done
    check "$case_name leaves all receiver daemons live" all_processes_running
    check "$case_name resets OpenBGPD case isolation" restart_openbgpd_case
    wait_until "$case_name case-isolated sessions" all_established
done

check "M100 produced exactly 20 unique cells" jq -se \
    'length == 20 and ([.[] | (.receiver + "/" + .case)] | unique | length) == 20' \
    "$ARTIFACT_DIR/outcomes.jsonl"
check "every M100 row has an explicit outcome" jq -se \
    'all(.[]; (.outcome | IN("accepted","treat_as_withdraw","same_session_withdrawal","reset")))' \
    "$ARTIFACT_DIR/outcomes.jsonl"

docker exec "$RAW" touch /tmp/m100-stop
sleep 1
docker exec "$RAW" cat /tmp/m100-events.jsonl >"$ARTIFACT_DIR/events.jsonl"
docker exec "$RAW" cat /tmp/m100-raw.log >"$ARTIFACT_DIR/raw-peer.log"
check "M100 exact observed matrix and evidence" python3 \
    "$SCRIPT_DIR/m100_partial_raw_peer.py" --verify-results \
    "$ARTIFACT_DIR/outcomes.jsonl" "$ARTIFACT_DIR/events.jsonl"

printf 'M100 artifacts: %s\n' "$ARTIFACT_DIR"
jq -s . "$ARTIFACT_DIR/outcomes.jsonl"
printf 'M100 live discovery complete\n'
