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
#   5. A final generation deletes both deprecated predecessors while preserving
#      the selected successor, authenticated traffic, session, and the route at
#      every sample from a 100ms polling oracle.
#   6. BIRD advertises a route without a session flap throughout every phase.
#   7. A mismatch in the selected key fails closed and does not re-establish.
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
POST_DELETE_PROBE_PREFIX="203.0.113.44"
ROUTE_CONTINUITY_PID=""
ROUTE_CONTINUITY_FAILURE=""

grpc_list_received() {
    grpcurl_call \
        -max-time 2 \
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

start_route_continuity_oracle() {
    log "Starting 100ms route-continuity oracle for $TEST_PREFIX/32..."
    local routes
    if ! routes=$(grpc_list_received); then
        fail "route-continuity oracle could not query RibService before deletion"
        return 1
    fi
    if [[ "$routes" != *"\"prefix\": \"$TEST_PREFIX\""* ]]; then
        fail "route-continuity oracle did not find $TEST_PREFIX/32 before deletion"
        return 1
    fi

    ROUTE_CONTINUITY_FAILURE=$(mktemp -t m43-route-continuity.XXXXXX)
    (
        local sample=0
        local observed
        # The explicit stop below and the EXIT trap own this process lifetime;
        # the 30-minute hosted job timeout remains the outer wedge bound.
        while :; do
            sample=$((sample + 1))
            if ! observed=$(grpc_list_received); then
                printf 'RibService query failed at sample %s\n' "$sample" \
                    >"$ROUTE_CONTINUITY_FAILURE"
                exit 1
            fi
            if [[ "$observed" != *"\"prefix\": \"$TEST_PREFIX\""* ]]; then
                printf '%s/32 missing at sample %s\n' "$TEST_PREFIX" "$sample" \
                    >"$ROUTE_CONTINUITY_FAILURE"
                exit 1
            fi
            sleep 0.1
        done
    ) &
    ROUTE_CONTINUITY_PID=$!
}

stop_route_continuity_oracle() {
    if [ -z "$ROUTE_CONTINUITY_PID" ] || [ -z "$ROUTE_CONTINUITY_FAILURE" ]; then
        fail "route-continuity oracle was not started"
        return 1
    fi

    local stopped=true
    if ! kill "$ROUTE_CONTINUITY_PID" 2>/dev/null; then
        stopped=false
    fi
    wait "$ROUTE_CONTINUITY_PID" 2>/dev/null || true
    ROUTE_CONTINUITY_PID=""

    if [ -s "$ROUTE_CONTINUITY_FAILURE" ]; then
        local reason
        reason=$(<"$ROUTE_CONTINUITY_FAILURE")
        rm -f "$ROUTE_CONTINUITY_FAILURE"
        ROUTE_CONTINUITY_FAILURE=""
        fail "route continuity failed: $reason"
        return 1
    fi

    if [ "$stopped" != true ]; then
        rm -f "$ROUTE_CONTINUITY_FAILURE"
        ROUTE_CONTINUITY_FAILURE=""
        fail "route-continuity oracle exited before its explicit stop"
        return 1
    fi

    rm -f "$ROUTE_CONTINUITY_FAILURE"
    ROUTE_CONTINUITY_FAILURE=""
    ok "$TEST_PREFIX/32 was present at every 100ms oracle sample through deletion and post-delete traffic"
}

_m43_cleanup_on_exit() {
    local exit_code=$?
    if [ -n "$ROUTE_CONTINUITY_PID" ]; then
        kill "$ROUTE_CONTINUITY_PID" 2>/dev/null || true
        wait "$ROUTE_CONTINUITY_PID" 2>/dev/null || true
    fi
    if [ -n "$ROUTE_CONTINUITY_FAILURE" ]; then
        rm -f "$ROUTE_CONTINUITY_FAILURE"
    fi

    if [ "${CLEANUP:-0}" = "1" ]; then
        local topo_file
        topo_file="$(_clab_topology_file)"
        if [ -f "$topo_file" ]; then
            log "[cleanup] containerlab destroy -t $topo_file"
            containerlab destroy -t "$topo_file" --cleanup >/dev/null 2>&1 || true
        fi
    fi
    return "$exit_code"
}

trap _m43_cleanup_on_exit EXIT INT TERM HUP

assert_two_key_inventory() {
    log "Checking selected IDs and complete redacted TCP-AO inventory..."
    local state
    state=$(grpc_neighbor_state || echo '{}')

    if printf '%s' "$state" | grep -Eq \
        'interop-(old|next)-secret-m43|wrong-(next|successor)-secret-m43'; then
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
            'interop-(old|next|successor)-secret-m43|wrong-(next|successor)-secret-m43'; then
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
            'interop-(old|next|successor)-secret-m43|wrong-(next|successor)-secret-m43'; then
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

successor_packets_good() {
    local state=${1:?}
    jq -er '
        [.tcpAo.keys[] | select(
          .peerAddress == "10.0.43.2" and .prefixLength == 32 and
          .sendId == 3 and .recvId == 13)] |
        if length == 1 then ((.[0].packetsGood // 0) | tonumber)
        else error("expected exactly one successor MKT")
        end
    ' <<<"$state"
}

apply_deletion_generation() {
    log "Deleting the deprecated TCP-AO predecessors with SIGHUP..."
    docker exec "$RUSTBGPD" cp \
        /etc/rustbgpd/config-deletion.toml /tmp/m43-config.toml
    if ! deliver_rust_sighup; then
        fail "could not deliver deletion SIGHUP to rustbgpd"
        return 1
    fi
}

wait_deletion_generation() {
    log "Waiting for TCP-AO deletion generation 4 to converge..."
    local state='{}'
    for i in $(seq 1 20); do
        state=$(grpc_neighbor_state || echo '{}')
        if printf '%s' "$state" | grep -Eq \
            'interop-(old|next|successor)-secret-m43|wrong-(next|successor)-secret-m43'; then
            fail "Neighbor state leaked TCP-AO secret material after deletion"
            return 1
        fi
        if jq -e '
            (.tcpAoDesiredGeneration | tonumber) == 4 and
            (.tcpAoAppliedGeneration | tonumber) == 4 and
            .tcpAoRotationPhase == "idle" and
            (.tcpAoRotationError // "") == "" and
            .authentication == "AUTHENTICATION_MODE_TCP_AO" and
            .tcpAoHealth == "TCP_AO_HEALTH_HEALTHY" and
            .tcpAo.currentKeyId == 3 and
            .tcpAo.rnextKeyId == 13 and
            ((.tcpAo.packetsBad // 0) | tonumber) == 0 and
            ((.tcpAo.packetsKeyNotFound // 0) | tonumber) == 0 and
            ((.tcpAo.packetsAoRequired // 0) | tonumber) == 0 and
            (.tcpAo.keys | length) == 1 and
            (.tcpAo.keys[0] |
              .peerAddress == "10.0.43.2" and .prefixLength == 32 and
              .sendId == 3 and .recvId == 13 and
              .algorithm == "hmac(sha256)" and
              .preferred == true and .deprecated != true and
              .isCurrent == true and .isRnext == true)
        ' >/dev/null <<<"$state"; then
            ok "Generation 4 deleted both predecessors and preserved the exact selected successor (attempt $i)"
            return 0
        fi
        sleep 1
    done
    fail "TCP-AO deletion generation did not converge within 20s"
    printf '%s\n' "$state" >&2
    dump_diagnostics
    return 1
}

request_authenticated_bird_traffic() {
    log "Enabling BIRD's post-delete route probe over the surviving TCP-AO key..."
    if ! docker exec "$BIRD" birdc 'enable m43_post_delete_probe'; then
        fail "BIRD rejected the post-delete route-probe enable"
        dump_diagnostics
        return 1
    fi
}

wait_successor_traffic_after_deletion() {
    local before=${1:?}
    log "Waiting for authenticated traffic on the sole surviving MKT..."
    local state='{}'
    local routes='{}'
    local after=0
    for i in $(seq 1 20); do
        state=$(grpc_neighbor_state || echo '{}')
        routes=$(grpc_list_received || echo '{}')
        if printf '%s' "$state" | grep -Eq \
            'interop-(old|next|successor)-secret-m43|wrong-(next|successor)-secret-m43'; then
            fail "Neighbor state leaked TCP-AO secret material after route-probe enable"
            return 1
        fi
        if after=$(successor_packets_good "$state") &&
            [ "$after" -gt "$before" ] &&
            printf '%s' "$routes" | grep -q \
                "\"prefix\": \"$POST_DELETE_PROBE_PREFIX\"" &&
            jq -e '
                (.tcpAoDesiredGeneration | tonumber) == 4 and
                (.tcpAoAppliedGeneration | tonumber) == 4 and
                .tcpAoRotationPhase == "idle" and
                (.tcpAoRotationError // "") == "" and
                .tcpAoHealth == "TCP_AO_HEALTH_HEALTHY" and
                .tcpAo.currentKeyId == 3 and
                .tcpAo.rnextKeyId == 13 and
                ((.tcpAo.packetsBad // 0) | tonumber) == 0 and
                ((.tcpAo.packetsKeyNotFound // 0) | tonumber) == 0 and
                ((.tcpAo.packetsAoRequired // 0) | tonumber) == 0 and
                (.tcpAo.keys | length) == 1
            ' >/dev/null <<<"$state"; then
            ok "Authenticated packets on successor increased $before -> $after (attempt $i)"
            return 0
        fi
        sleep 1
    done
    fail "post-delete probe route and successor packetsGood increase were not both observed"
    printf '%s\n' "$state" >&2
    dump_diagnostics
    return 1
}

wait_route_absent() {
    log "Waiting for $TEST_PREFIX/32 to be absent..."
    local routes
    for i in $(seq 1 20); do
        if ! routes=$(grpc_list_received); then
            fail "RibService query failed while checking $TEST_PREFIX/32 withdrawal"
            dump_diagnostics
            return 1
        fi
        if [[ "$routes" != *"\"prefix\": \"$TEST_PREFIX\""* ]]; then
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
    local state
    for i in $(seq 0 20); do
        if ! state=$(timeout 3 docker exec "$BIRD" \
            birdc show protocols rustbgpd 2>/dev/null); then
            fail "BIRD control socket became unavailable during wrong-key window"
            dump_diagnostics
            return 1
        fi
        if ! awk '$1 == "rustbgpd" { found = 1 } END { exit found ? 0 : 1 }' \
            <<<"$state"; then
            fail "BIRD rustbgpd protocol row disappeared during wrong-key window"
            printf '%s\n' "$state" >&2
            dump_diagnostics
            return 1
        fi
        if [[ "$state" == *Established* ]]; then
            fail "BIRD reached Established with mismatched TCP-AO key"
            dump_diagnostics
            return 1
        fi
        if [ "$i" -lt 20 ]; then
            sleep 2
        fi
    done
    ok "BIRD stayed observable and non-Established throughout the 40s wrong-key window"
}

main() {
    log "M43 interop test: TCP-AO full live key rotation with BIRD 3.3.1"
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

    start_route_continuity_oracle
    apply_deletion_generation
    wait_deletion_generation
    wait_route_present
    wait_bird_established
    local deleted_since
    local deleted_flaps
    deleted_since=$(bird_since)
    deleted_flaps=$(grpc_neighbor_state | jq -r '((.flapCount // 0) | tonumber)')
    if [ "$deleted_since" = "$established_since" ] && \
        [ "$deleted_flaps" -eq "$initial_flaps" ]; then
        ok "Session did not flap across deletion (BIRD since $deleted_since; flapCount $deleted_flaps)"
    else
        fail "Session flapped across deletion (BIRD since $established_since -> $deleted_since; flapCount $initial_flaps -> $deleted_flaps)"
        dump_diagnostics
        return 1
    fi

    local post_delete_state
    local post_delete_good
    post_delete_state=$(grpc_neighbor_state || echo '{}')
    if ! post_delete_good=$(successor_packets_good "$post_delete_state"); then
        fail "could not capture successor packetsGood after deletion"
        printf '%s\n' "$post_delete_state" >&2
        return 1
    fi

    request_authenticated_bird_traffic
    wait_successor_traffic_after_deletion "$post_delete_good"
    stop_route_continuity_oracle
    wait_route_present
    wait_bird_established
    local traffic_since
    local traffic_flaps
    traffic_since=$(bird_since)
    traffic_flaps=$(grpc_neighbor_state | jq -r '((.flapCount // 0) | tonumber)')
    if [ "$traffic_since" = "$established_since" ] && \
        [ "$traffic_flaps" -eq "$initial_flaps" ]; then
        ok "Session stayed established through authenticated post-delete traffic"
    else
        fail "Session flapped after authenticated post-delete traffic (BIRD since $established_since -> $traffic_since; flapCount $initial_flaps -> $traffic_flaps)"
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
