#!/usr/bin/env bash
# M43 interop test — TCP-AO with BIRD 3.x
#
# Validates:
#   1. BGP establishes with the preferred entry in a two-key startup ring.
#   2. GET_KEYS exposes the complete redacted inventory and selected IDs.
#   3. SIGHUP appends a nonpreferred successor without changing selection or
#      flapping the BIRD session.
#   4. A later immutable generation selects the installed successor, first
#      reports awaiting_peer, then observation-gates predecessor deprecation.
#   5. BIRD advertises a route without a session flap throughout both phases.
#   6. A mismatch in the selected key fails closed and does not re-establish.
#
# Prerequisites:
#   - BIRD image built:
#       docker build -t bird:3.3.1-tcpao -f tests/interop/Dockerfile.bird3 tests/interop
#   - rustbgpd image built:
#       docker build --target dev -t rustbgpd:dev .
#   - containerlab deployed:
#       containerlab deploy -t tests/interop/m43-tcp-ao-bird.clab.yml
#
# Usage:
#   bash tests/interop/scripts/test-m43-tcp-ao-bird.sh

TOPO="m43-tcp-ao-bird"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"
BIRD="clab-${TOPO}-bird"
GOOD_CONF="/etc/bird/bird.conf"
BAD_CONF="/etc/bird/bird-bad.conf"
TEST_PREFIX="203.0.113.43"

grpc_list_received() {
    grpcurl_call \
        -d '{"neighbor_address": "10.0.43.2"}' \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

grpc_neighbor_state() {
    grpcurl_call \
        -d '{"address": "10.0.43.2"}' \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState 2>/dev/null
}

bird_state() {
    docker exec "$BIRD" birdc show protocols rustbgpd 2>/dev/null || true
}

bird_since() {
    bird_state | awk '$1 == "rustbgpd" { print $5; exit }'
}

dump_diagnostics() {
    echo "--- rustbgpd logs ---" >&2
    docker logs --tail 120 "$RUSTBGPD" >&2 || true
    echo "--- BIRD logs ---" >&2
    docker logs --tail 120 "$BIRD" >&2 || true
    echo "--- BIRD protocol state ---" >&2
    docker exec "$BIRD" birdc show protocols all rustbgpd >&2 || true
    echo "--- rustbgpd TCP-AO support ---" >&2
    grpcurl_call \
        "$GRPC_ADDR" rustbgpd.v1.GlobalService/GetGlobal >&2 || true
}

stop_bird() {
    docker exec "$BIRD" sh -lc '
        if pids=$(pidof bird 2>/dev/null); then
            kill $pids 2>/dev/null || true
            for _ in 1 2 3 4 5; do
                pidof bird >/dev/null 2>&1 || break
                sleep 1
            done
            if pids=$(pidof bird 2>/dev/null); then
                kill -9 $pids 2>/dev/null || true
            fi
        fi
        find /run/bird -name bird.ctl -delete 2>/dev/null || true
    ' \
        >/dev/null 2>&1 || true
}

start_bird() {
    local conf=${1:?}
    stop_bird
    docker exec "$BIRD" mkdir -p /run/bird
    docker exec -d "$BIRD" bird -d -c "$conf"

    for i in $(seq 1 15); do
        if docker exec "$BIRD" birdc show status >/dev/null 2>&1; then
            log "BIRD control socket ready for $conf (attempt $i)"
            return 0
        fi
        sleep 1
    done
    fail "BIRD control socket did not become ready for $conf"
    return 1
}

wait_bird_established() {
    log "Waiting for BIRD TCP-AO session to reach Established..."
    for i in $(seq 1 45); do
        if bird_state | grep -q 'Established'; then
            ok "BIRD TCP-AO session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "BIRD TCP-AO session did not reach Established within 90s"
    dump_diagnostics
    return 1
}

wait_route_present() {
    log "Waiting for $TEST_PREFIX/32 from BIRD..."
    for i in $(seq 1 20); do
        local routes
        routes=$(grpc_list_received || echo '{}')
        if echo "$routes" | grep -q "\"prefix\": \"$TEST_PREFIX\""; then
            ok "$TEST_PREFIX/32 received over TCP-AO session (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$TEST_PREFIX/32 not received over TCP-AO session"
    dump_diagnostics
    return 1
}

assert_two_key_inventory() {
    log "Checking selected IDs and complete redacted TCP-AO inventory..."
    local state
    state=$(grpc_neighbor_state || echo '{}')

    if printf '%s' "$state" | grep -Eq \
        'interop-(old|next)-secret-m43|wrong-next-secret-m43'; then
        fail "Neighbor state leaked TCP-AO secret material"
        return 1
    fi

    if ! jq -e '
        .authentication == "AUTHENTICATION_MODE_TCP_AO" and
        .tcpAoHealth == "TCP_AO_HEALTH_HEALTHY" and
        .tcpAo.currentKeyId == 2 and
        .tcpAo.rnextKeyId == 12 and
        (.tcpAo.keys | length == 2) and
        any(.tcpAo.keys[];
          .peerAddress == "10.0.43.2" and .prefixLength == 32 and
          .sendId == 1 and .recvId == 11 and
          .algorithm == "hmac(sha256)" and .deprecated == true and
          .preferred != true and .isCurrent != true and .isRnext != true) and
        any(.tcpAo.keys[];
          .peerAddress == "10.0.43.2" and .prefixLength == 32 and
          .sendId == 2 and .recvId == 12 and
          .algorithm == "hmac(sha256)" and .preferred == true and
          .deprecated != true and .isCurrent == true and .isRnext == true)
    ' >/dev/null <<<"$state"; then
        fail "TCP-AO state did not report the exact selected two-key inventory"
        printf '%s\n' "$state" >&2
        return 1
    fi

    ok "Selected IDs are Current=2/RNext=12; GET_KEYS inventory is exact and redacted"
}

wait_successor_generation() {
    log "Waiting for TCP-AO successor generation to converge..."
    local state='{}'
    for i in $(seq 1 30); do
        state=$(grpc_neighbor_state || echo '{}')
        if printf '%s' "$state" | grep -Eq \
            'interop-(old|next|successor)-secret-m43|wrong-next-secret-m43'; then
            fail "Neighbor state leaked TCP-AO secret material after rotation"
            return 1
        fi
        if jq -e '
            (.tcpAoDesiredGeneration | tonumber) == 2 and
            (.tcpAoAppliedGeneration | tonumber) == 2 and
            .tcpAoRotationPhase == "idle" and
            (.tcpAoRotationError // "") == "" and
            .authentication == "AUTHENTICATION_MODE_TCP_AO" and
            .tcpAoHealth == "TCP_AO_HEALTH_HEALTHY" and
            .tcpAo.currentKeyId == 2 and
            .tcpAo.rnextKeyId == 12 and
            ((.tcpAo.packetsBad // 0) | tonumber) == 0 and
            ((.tcpAo.packetsKeyNotFound // 0) | tonumber) == 0 and
            ((.tcpAo.packetsAoRequired // 0) | tonumber) == 0 and
            (.tcpAo.keys | length) == 3 and
            any(.tcpAo.keys[];
              .sendId == 1 and .recvId == 11 and
              .algorithm == "hmac(sha256)" and
              .preferred != true and .deprecated == true and
              .isCurrent != true and .isRnext != true) and
            any(.tcpAo.keys[];
              .sendId == 2 and .recvId == 12 and
              .algorithm == "hmac(sha256)" and
              .preferred == true and .deprecated != true and
              .isCurrent == true and .isRnext == true) and
            any(.tcpAo.keys[];
              .sendId == 3 and .recvId == 13 and
              .algorithm == "hmac(sha256)" and
              .preferred != true and .deprecated != true and
              .isCurrent != true and .isRnext != true)
        ' >/dev/null <<<"$state"; then
            ok "Generation 2 converged with the exact three-key inventory (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "TCP-AO successor generation did not converge within 60s"
    printf '%s\n' "$state" >&2
    dump_diagnostics
    return 1
}

apply_successor_generation() {
    log "Appending the nonpreferred TCP-AO successor with SIGHUP..."
    docker exec "$RUSTBGPD" cp \
        /etc/rustbgpd/config-successor.toml /tmp/m43-config.toml
    if ! docker exec "$RUSTBGPD" sh -lc '
        pid=$(pidof rustbgpd)
        [ -n "$pid" ]
        kill -HUP "$pid"
    '; then
        fail "could not deliver SIGHUP to rustbgpd"
        return 1
    fi
    ok "SIGHUP delivered for the add-only successor generation"
}

deliver_rust_sighup() {
    docker exec "$RUSTBGPD" sh -lc '
        pid=$(pidof rustbgpd)
        [ -n "$pid" ]
        kill -HUP "$pid"
    '
}

begin_selection_generation() {
    log "Selecting the installed TCP-AO successor with SIGHUP..."
    docker exec "$RUSTBGPD" cp \
        /etc/rustbgpd/config-selection.toml /tmp/m43-config.toml
    if ! deliver_rust_sighup; then
        fail "could not deliver selection SIGHUP to rustbgpd"
        return 1
    fi
}

wait_selection_awaiting() {
    log "Waiting for the one-shot selection pass to report awaiting_peer..."
    local state='{}'
    for i in $(seq 1 20); do
        state=$(grpc_neighbor_state || echo '{}')
        if jq -e '
            (.tcpAoDesiredGeneration | tonumber) == 3 and
            (.tcpAoAppliedGeneration | tonumber) == 2 and
            .tcpAoRotationPhase == "awaiting_peer" and
            .tcpAo.rnextKeyId == 13 and
            any(.tcpAo.keys[];
              .sendId == 2 and .recvId == 12 and .deprecated != true) and
            any(.tcpAo.keys[];
              .sendId == 3 and .recvId == 13 and
              .preferred == true and .deprecated != true)
        ' >/dev/null <<<"$state"; then
            ok "Generation 3 is awaiting peer successor use (attempt $i)"
            return 0
        fi
        sleep 1
    done
    fail "selection generation did not expose desired=3/applied=2 awaiting_peer"
    printf '%s\n' "$state" >&2
    dump_diagnostics
    return 1
}

select_bird_successor() {
    log "Reconfiguring BIRD to prefer the preinstalled successor..."
    if ! docker exec "$BIRD" birdc 'configure "/etc/bird/bird-successor.conf"'; then
        fail "BIRD rejected successor-key reconfiguration"
        dump_diagnostics
        return 1
    fi
}

wait_selection_generation() {
    log "Retrying the identical generation 3 until one-shot observation commits..."
    local state='{}'
    for i in $(seq 1 30); do
        if ! deliver_rust_sighup; then
            fail "could not deliver identical selection retry SIGHUP"
            return 1
        fi
        sleep 2
        state=$(grpc_neighbor_state || echo '{}')
        if printf '%s' "$state" | grep -Eq \
            'interop-(old|next|successor)-secret-m43|wrong-next-secret-m43'; then
            fail "Neighbor state leaked TCP-AO secret material after selection"
            return 1
        fi
        if jq -e '
            (.tcpAoDesiredGeneration | tonumber) == 3 and
            (.tcpAoAppliedGeneration | tonumber) == 3 and
            .tcpAoRotationPhase == "idle" and
            (.tcpAoRotationError // "") == "" and
            .tcpAoHealth == "TCP_AO_HEALTH_HEALTHY" and
            .tcpAo.currentKeyId == 3 and
            .tcpAo.rnextKeyId == 13 and
            ((.tcpAo.packetsBad // 0) | tonumber) == 0 and
            ((.tcpAo.packetsKeyNotFound // 0) | tonumber) == 0 and
            ((.tcpAo.packetsAoRequired // 0) | tonumber) == 0 and
            (.tcpAo.keys | length) == 3 and
            any(.tcpAo.keys[];
              .sendId == 1 and .recvId == 11 and .deprecated == true) and
            any(.tcpAo.keys[];
              .sendId == 2 and .recvId == 12 and
              .preferred != true and .deprecated == true) and
            any(.tcpAo.keys[];
              .sendId == 3 and .recvId == 13 and
              .preferred == true and .deprecated != true and
              .isCurrent == true and .isRnext == true and
              ((.packetsGood // 0) | tonumber) > 0)
        ' >/dev/null <<<"$state"; then
            ok "Generation 3 selected and observed the successor (attempt $i)"
            return 0
        fi
    done
    fail "TCP-AO selection generation did not converge within 60s"
    printf '%s\n' "$state" >&2
    dump_diagnostics
    return 1
}

wait_route_absent() {
    log "Waiting for $TEST_PREFIX/32 to be absent..."
    for i in $(seq 1 20); do
        local routes
        routes=$(grpc_list_received || echo '{}')
        if ! echo "$routes" | grep -q "\"prefix\": \"$TEST_PREFIX\""; then
            ok "$TEST_PREFIX/32 absent (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$TEST_PREFIX/32 still present"
    dump_diagnostics
    return 1
}

assert_bad_key_does_not_establish() {
    log "Verifying mismatched TCP-AO key fails closed..."
    for i in $(seq 1 20); do
        if bird_state | grep -q 'Established'; then
            fail "BIRD reached Established with mismatched TCP-AO key"
            dump_diagnostics
            return 1
        fi
        sleep 2
    done
    ok "Mismatched TCP-AO key did not establish within 40s"
}

main() {
    log "M43 interop test: TCP-AO live successor rotation with BIRD 3.3.1"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_bird "$GOOD_CONF"
    docker exec "$RUSTBGPD" cp /etc/rustbgpd/config.toml /tmp/m43-config.toml
    start_rustbgpd "exec /usr/local/bin/rustbgpd /tmp/m43-config.toml"

    wait_bird_established
    wait_route_present
    assert_two_key_inventory
    local established_since
    local initial_flaps
    established_since=$(bird_since)
    initial_flaps=$(grpc_neighbor_state | jq -r '((.flapCount // 0) | tonumber)')
    if [ -z "$established_since" ]; then
        fail "could not capture BIRD's Established-since token"
        return 1
    fi

    apply_successor_generation
    wait_successor_generation
    wait_route_present
    wait_bird_established
    local rotated_since
    local rotated_flaps
    rotated_since=$(bird_since)
    rotated_flaps=$(grpc_neighbor_state | jq -r '((.flapCount // 0) | tonumber)')
    if [ "$rotated_since" = "$established_since" ] && \
        [ "$rotated_flaps" -eq "$initial_flaps" ]; then
        ok "Session did not flap across SIGHUP (BIRD since $rotated_since; flapCount $rotated_flaps)"
    else
        fail "Session flapped across SIGHUP (BIRD since $established_since -> $rotated_since; flapCount $initial_flaps -> $rotated_flaps)"
        dump_diagnostics
        return 1
    fi

    begin_selection_generation
    wait_selection_awaiting
    select_bird_successor
    wait_selection_generation
    wait_route_present
    wait_bird_established
    local selected_since
    local selected_flaps
    selected_since=$(bird_since)
    selected_flaps=$(grpc_neighbor_state | jq -r '((.flapCount // 0) | tonumber)')
    if [ "$selected_since" = "$established_since" ] && \
        [ "$selected_flaps" -eq "$initial_flaps" ]; then
        ok "Session did not flap across selection (BIRD since $selected_since; flapCount $selected_flaps)"
    else
        fail "Session flapped across selection (BIRD since $established_since -> $selected_since; flapCount $initial_flaps -> $selected_flaps)"
        dump_diagnostics
        return 1
    fi

    log "Restarting BIRD with a mismatched preferred TCP-AO secret"
    start_bird "$BAD_CONF"
    wait_route_absent
    assert_bad_key_does_not_establish

    print_summary
}

main "$@"
