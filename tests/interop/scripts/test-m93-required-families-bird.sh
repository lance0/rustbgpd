#!/usr/bin/env bash
# Load-bearing: removing the required-family guard establishes phase 1 instead
# of producing the exact OPEN 2/7 frame; the final phase pins empty-list parity.

TOPO="m93-required-families-bird"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

BIRD="clab-${TOPO}-bird"
PEER="10.93.0.2"
EXPECTED_NOTIFICATION="ffffffffffffffffffffffffffffffff001b030207010400020001"

rbgp() {
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 "$@"
}

assert_true() {
    local label=${1:?}; shift
    if "$@"; then ok "$label"; else fail "$label"; fi
}

kill_named() {
    local container=${1:?} comm=${2:?}
    docker exec "$container" sh -c \
        "for p in /proc/[0-9]*; do
             [ \"\$(cat \"\$p/comm\" 2>/dev/null)\" = '$comm' ] && kill -9 \"\${p#/proc/}\"
         done; true" 2>/dev/null || true
}

start_bird() {
    local config=${1:?}
    docker exec "$BIRD" sh -c \
        "mkdir -p /run/bird && (bird -d -c $config >/tmp/bird.log 2>&1 &)"
}

wait_bird_established() {
    local label=${1:?}
    for i in $(seq 1 45); do
        if docker exec "$BIRD" birdc show protocols rustbgpd 2>/dev/null \
            | grep -q Established; then
            ok "$label Established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label did not establish within 90s"
    docker exec "$BIRD" sh -c 'tail -40 /tmp/bird.log' >&2 || true
    return 1
}

neighbor_matches() {
    local required=${1-} negotiated_count=${2:?}
    rbgp neighbor "$PEER" -j 2>/dev/null | jq -e \
        --arg required "$required" --argjson count "$negotiated_count" '
        .state == "Established"
        and ((.required_families // []) == (if $required == "" then [] else [$required] end))
        and (.negotiated_session.families | length == $count)
    ' >/dev/null
}

neighbor_down() {
    rbgp neighbor "$PEER" -j 2>/dev/null | jq -e '.state != "Established"' >/dev/null
}

start_capture() {
    docker exec "$BIRD" sh -c 'rm -f /tmp/m93.pcap /tmp/tshark.log'
    docker exec -d "$BIRD" sh -c \
        'tshark -i eth1 -w /tmp/m93.pcap port 179 >/tmp/tshark.log 2>&1'
    sleep 2
}

capture_has_exact_rejection() {
    docker exec "$BIRD" tshark -r /tmp/m93.pcap \
        -Y 'ip.src == 10.93.0.1 && bgp.type == 3' \
        -T fields -e tcp.payload 2>/dev/null \
        | tr -d ':\r' \
        | grep -Fxq "$EXPECTED_NOTIFICATION"
}

main() {
    log "M93: required-family enforcement against BIRD 2"
    resolve_grpc_addr
    docker exec "$BIRD" sh -c \
        "sed '/M93_V6_BEGIN/,/M93_V6_END/d' /fixtures/dual.conf >/tmp/m93-bird-v4.conf"
    docker exec "$RUSTBGPD" sh -c \
        "sed '/required_families/d' /fixtures/required.toml >/tmp/m93-legacy.toml"
    start_rustbgpd \
        'exec /usr/local/bin/rustbgpd /fixtures/required.toml >/tmp/rustbgpd.log 2>&1'

    log "Phase 1: IPv4-only BIRD must receive exact OPEN 2/7 for missing IPv6"
    start_capture
    start_bird /tmp/m93-bird-v4.conf
    sleep 8
    docker exec "$BIRD" sh -c \
        'pkill -INT tshark >/dev/null 2>&1 || pkill tshark >/dev/null 2>&1 || true'
    sleep 2
    assert_true "exact OPEN 2/7 Data=010400020001 (missing IPv6 only)" \
        capture_has_exact_rejection
    assert_true "strict session remains down" neighbor_down

    log "Phase 2: explicitly restart/re-enable BIRD with both MP channels"
    kill_named "$BIRD" bird
    start_bird /fixtures/dual.conf
    wait_bird_established "dual-stack BIRD"
    assert_true "required IPv6 and two negotiated families" \
        neighbor_matches ipv6_unicast 2

    log "Phase 3: clear requirement, restart both speakers, restore IPv4-only BIRD"
    kill_named "$BIRD" bird
    kill_named "$RUSTBGPD" rustbgpd
    start_rustbgpd \
        'exec /usr/local/bin/rustbgpd /tmp/m93-legacy.toml >/tmp/rustbgpd.log 2>&1'
    start_bird /tmp/m93-bird-v4.conf
    wait_bird_established "legacy IPv4-only BIRD"
    assert_true "empty requirement preserves one-family partial negotiation" \
        neighbor_matches '' 1

    log "Results: $pass passed, $fail failed"
    [ "$fail" -eq 0 ]
}

main "$@"
