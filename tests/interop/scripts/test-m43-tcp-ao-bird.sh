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
#   7. An unsigned peer cannot establish while its static MKT remains installed,
#      and the kernel accounts the matching unsigned traffic as TCPAORequired.
#   8. A mismatch in the selected key fails closed and does not re-establish.
#   9. The same signed/unsigned/recovery boundary holds for a direct dynamic
#      `/24`, whose accepted session reports the dynamic owner and prefix MKT.
#
# Prerequisites:
#   - BIRD image built:
#       docker build -t bird:3.3.2-tcpao -f tests/interop/Dockerfile.bird3 tests/interop
#   - rustbgpd image built:
#       docker build --target dev -t rustbgpd:dev .
#   - containerlab deployed:
#       containerlab deploy -t tests/interop/m43-tcp-ao-bird.clab.yml
#
# Usage:
#   bash tests/interop/scripts/test-m43-tcp-ao-bird.sh
#   M43_MODE=crash-restart \
#     bash tests/interop/scripts/test-m43-tcp-ao-bird.sh
#   bash tests/interop/scripts/test-m43-tcp-ao-bird.sh --self-test-pid-signal

TOPO="m43-tcp-ao-bird"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
if [ "${1:-}" = "--self-test-pid-signal" ]; then
    set -euo pipefail
    RUSTBGPD="fixture-rustbgpd"
else
    # shellcheck source=tests/interop/scripts/test-lib.sh
    source "$SCRIPT_DIR/test-lib.sh"
fi
BIRD="clab-${TOPO}-bird"
BIRD_VERSION="3.3.2"
BIRD_IMAGE="bird:${BIRD_VERSION}-tcpao"
BIRD_VERSION_OUTPUT="BIRD version ${BIRD_VERSION}"
GOOD_CONF="/etc/bird/bird.conf"
BAD_CONF="/etc/bird/bird-bad.conf"
UNSIGNED_CONF="/etc/bird/bird-unsigned.conf"
SUCCESSOR_CONF="/etc/bird/bird-successor.conf"
DYNAMIC_CONFIG="/etc/rustbgpd/config-dynamic.toml"
TEST_PREFIX="203.0.113.43"
POST_DELETE_PROBE_PREFIX="203.0.113.44"
ROUTE_CONTINUITY_PID=""
ROUTE_CONTINUITY_FAILURE=""
CRASHED_RUST_PID=""

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

bird_state_strict() {
    timeout 3 docker exec "$BIRD" birdc show protocols rustbgpd 2>/dev/null
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

preflight_bird_container() {
    local configured_image container_image_id local_image_id configured_command
    local runtime_path runtime_args reported_version conf

    if ! configured_image=$(docker inspect --format '{{.Config.Image}}' "$BIRD"); then
        fail "Could not inspect BIRD container image tag"
        return 1
    fi
    if [ "$configured_image" != "$BIRD_IMAGE" ]; then
        fail "BIRD container image tag drifted: $configured_image (expected $BIRD_IMAGE)"
        return 1
    fi
    if ! container_image_id=$(docker inspect --format '{{.Image}}' "$BIRD"); then
        fail "Could not inspect BIRD container image ID"
        return 1
    fi
    if ! local_image_id=$(docker image inspect --format '{{.Id}}' "$BIRD_IMAGE"); then
        fail "Could not inspect local $BIRD_IMAGE image ID"
        return 1
    fi
    if [ "$container_image_id" != "$local_image_id" ]; then
        fail "BIRD container image ID differs from local $BIRD_IMAGE"
        return 1
    fi

    if ! configured_command=$(docker inspect --format '{{json .Config.Cmd}}' "$BIRD"); then
        fail "Could not inspect BIRD container configured command"
        return 1
    fi
    if ! runtime_path=$(docker inspect --format '{{.Path}}' "$BIRD"); then
        fail "Could not inspect BIRD container runtime path"
        return 1
    fi
    if ! runtime_args=$(docker inspect --format '{{json .Args}}' "$BIRD"); then
        fail "Could not inspect BIRD container runtime arguments"
        return 1
    fi
    if [ "$configured_command" != '["sleep","infinity"]' ] || \
        [ "$runtime_path" != sleep ] || [ "$runtime_args" != '["infinity"]' ]; then
        fail "BIRD container command is not the pinned sleeping command"
        return 1
    fi

    if ! reported_version=$(docker exec "$BIRD" bird --version 2>&1); then
        fail "Could not execute the BIRD runtime version check"
        return 1
    fi
    if [ "$reported_version" != "$BIRD_VERSION_OUTPUT" ]; then
        fail "BIRD runtime version drifted: $reported_version (expected $BIRD_VERSION_OUTPUT)"
        return 1
    fi
    for conf in "$GOOD_CONF" "$BAD_CONF" "$UNSIGNED_CONF" "$SUCCESSOR_CONF"; do
        if ! docker exec "$BIRD" bird -p -c "$conf" >/dev/null; then
            fail "BIRD $BIRD_VERSION rejected bound configuration $conf"
            return 1
        fi
    done
    ok "BIRD $BIRD_VERSION image identity, sleeping command, and four configs preflighted"
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

tcp_ao_required() {
    docker exec "$RUSTBGPD" awk '
        $1 == "TcpExt:" {
            if (column > 0) {
                print $column
                found = 1
                exit
            }
            for (i = 2; i <= NF; i++) {
                if ($i == "TCPAORequired") column = i
            }
        }
        END { if (!found) exit 1 }
    ' /proc/net/netstat
}

prove_unsigned_peer_requires_ao() {
    local owner=${1:?}
    local recovery_conf=${2:?}
    local before
    if ! before=$(tcp_ao_required); then
        fail "Linux did not expose the TCPAORequired accounting oracle"
        return 1
    fi

    log "Starting a bounded unsigned BIRD attempt from the $owner..."
    start_bird "$UNSIGNED_CONF"
    local after=$before
    local state
    for _ in $(seq 1 10); do
        if ! state=$(bird_state_strict); then
            fail "unsigned BIRD protocol state became unavailable"
            dump_diagnostics
            return 1
        fi
        if ! awk '$1 == "rustbgpd" { found = 1 } END { exit found ? 0 : 1 }' \
            <<<"$state"; then
            fail "unsigned BIRD protocol row disappeared"
            return 1
        fi
        if [[ "$state" == *Established* ]]; then
            fail "unsigned BIRD reached Established against the TCP-AO listener"
            dump_diagnostics
            return 1
        fi
        if ! after=$(tcp_ao_required); then
            fail "TCPAORequired accounting disappeared during the unsigned attempt"
            return 1
        fi
        sleep 1
    done
    if [ "$after" -le "$before" ]; then
        fail "unsigned traffic did not increase TCPAORequired ($before -> $after)"
        dump_diagnostics
        return 1
    fi
    ok "unsigned BIRD stayed non-Established and TCPAORequired increased $before -> $after"

    start_bird "$recovery_conf"
    wait_bird_established
    wait_route_present
    ok "authenticated BIRD re-established normally for the $owner after the unsigned receipt"
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

assert_dynamic_two_key_inventory() {
    log "Checking dynamic owner provenance and prefix-scoped TCP-AO inventory..."
    local state
    state=$(grpc_neighbor_state || echo '{}')

    if printf '%s' "$state" | grep -Eq \
        'interop-(old|next)-secret-m43|wrong-(next|successor)-secret-m43'; then
        fail "Dynamic neighbor state leaked TCP-AO secret material"
        return 1
    fi

    if ! jq -e '
        .isDynamic == true and
        .acceptedDynamicRange.prefix == "10.0.43.0/24" and
        .acceptedDynamicRange.peerGroup == "bird3-dynamic" and
        .authentication == "AUTHENTICATION_MODE_TCP_AO" and
        .tcpAoHealth == "TCP_AO_HEALTH_HEALTHY" and
        .tcpAo.currentKeyId == 2 and
        .tcpAo.rnextKeyId == 12 and
        ((.tcpAo.packetsBad // 0) | tonumber) == 0 and
        ((.tcpAo.packetsKeyNotFound // 0) | tonumber) == 0 and
        ((.tcpAo.packetsAoRequired // 0) | tonumber) == 0 and
        (.tcpAo.keys | length == 2) and
        any(.tcpAo.keys[];
          .peerAddress == "10.0.43.0" and .prefixLength == 24 and
          .sendId == 1 and .recvId == 11 and
          .algorithm == "hmac(sha256)" and .deprecated == true and
          .preferred != true and .isCurrent != true and .isRnext != true) and
        any(.tcpAo.keys[];
          .peerAddress == "10.0.43.0" and .prefixLength == 24 and
          .sendId == 2 and .recvId == 12 and
          .algorithm == "hmac(sha256)" and .preferred == true and
          .deprecated != true and .isCurrent == true and .isRnext == true)
    ' >/dev/null <<<"$state"; then
        fail "Dynamic TCP-AO state did not report exact range provenance and MKT inventory"
        printf '%s\n' "$state" >&2
        return 1
    fi

    ok "Dynamic /24 provenance, Current/RNext, and exact prefix MKT inventory are observable"
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
    local desired_generation=${1:-3}
    local applied_generation=${2:-2}
    log "Waiting for the one-shot selection pass to report awaiting_peer..."
    local state='{}'
    for i in $(seq 1 20); do
        state=$(grpc_neighbor_state || echo '{}')
        if jq -e \
            --argjson desired "$desired_generation" \
            --argjson applied "$applied_generation" '
            (.tcpAoDesiredGeneration | tonumber) == $desired and
            (.tcpAoAppliedGeneration | tonumber) == $applied and
            .tcpAoRotationPhase == "awaiting_peer" and
            .tcpAo.rnextKeyId == 13 and
            any(.tcpAo.keys[];
              .sendId == 2 and .recvId == 12 and .deprecated != true) and
            any(.tcpAo.keys[];
              .sendId == 3 and .recvId == 13 and
              .preferred == true and .deprecated != true)
        ' >/dev/null <<<"$state"; then
            ok "Generation $desired_generation is awaiting peer successor use (attempt $i)"
            return 0
        fi
        sleep 1
    done
    fail "selection generation did not expose desired=$desired_generation/applied=$applied_generation awaiting_peer"
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
    local expected_generation=${1:-4}
    log "Waiting for TCP-AO deletion generation $expected_generation to converge..."
    local state='{}'
    for i in $(seq 1 20); do
        state=$(grpc_neighbor_state || echo '{}')
        if printf '%s' "$state" | grep -Eq \
            'interop-(old|next|successor)-secret-m43|wrong-(next|successor)-secret-m43'; then
            fail "Neighbor state leaked TCP-AO secret material after deletion"
            return 1
        fi
        if jq -e --argjson generation "$expected_generation" '
            (.tcpAoDesiredGeneration | tonumber) == $generation and
            (.tcpAoAppliedGeneration | tonumber) == $generation and
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
            ok "Generation $expected_generation deleted both predecessors and preserved the exact selected successor (attempt $i)"
            return 0
        fi
        sleep 1
    done
    fail "TCP-AO deletion generation did not converge within 20s"
    printf '%s\n' "$state" >&2
    dump_diagnostics
    return 1
}

rust_pid() {
    docker exec "$RUSTBGPD" sh -lc '
        pids=$(pidof rustbgpd 2>/dev/null || true)
        set -- $pids
        if [ "$#" -ne 1 ]; then
            exit 1
        fi
        printf "%s\n" "$1"
    '
}

signal_rustbgpd_pid() {
    local signal=${1-}
    local pid=${2-}

    case "$signal" in
        TERM | KILL) ;;
        *) return 2 ;;
    esac
    case "$pid" in
        '' | *[!0-9]*) return 2 ;;
    esac
    if ! [ "$pid" -gt 0 ] 2>/dev/null; then
        return 2
    fi

    docker exec "$RUSTBGPD" sh -lc 'kill "-$1" "$2"' sh "$signal" "$pid"
}

self_test_pid_signal() {
    local kill_calls=0
    local census_output=""
    local expected_command="kill \"-\$1\" \"\$2\""
    local expected_signal="TERM"
    local expected_pid="42"
    pidof() { printf '%s\n' "${PIDOF_FIXTURE-}"; }
    export -f pidof
    docker() {
        if [ "$#" -eq 5 ] \
            && [ "$1" = "exec" ] \
            && [ "$2" = "fixture-rustbgpd" ] \
            && [ "$3" = "sh" ] \
            && [ "$4" = "-lc" ] \
            && [[ "$5" == *"pidof rustbgpd"* ]]; then
            PIDOF_FIXTURE="$census_output" bash -c "$5"
            return
        fi

        kill_calls=$((kill_calls + 1))
        if [ "$#" -ne 8 ] \
            || [ "$1" != "exec" ] \
            || [ "$2" != "fixture-rustbgpd" ] \
            || [ "$3" != "sh" ] \
            || [ "$4" != "-lc" ] \
            || [ "$5" != "$expected_command" ] \
            || [ "$6" != "sh" ] \
            || [ "$7" != "$expected_signal" ] \
            || [ "$8" != "$expected_pid" ]; then
            printf 'PID signal self-test observed unsafe argument boundaries:' >&2
            printf ' <%q>' "$@" >&2
            printf '\n' >&2
            return 1
        fi
    }
    fail() { :; }
    dump_diagnostics() { :; }

    local observed_pid
    census_output=""
    if observed_pid=$(rust_pid); then
        printf 'PID census self-test accepted zero processes as %q\n' \
            "$observed_pid" >&2
        return 1
    fi
    if restart_rustbgpd_with_dynamic_range || [ "$kill_calls" -ne 0 ]; then
        printf 'PID census self-test signaled after a zero-process census\n' >&2
        return 1
    fi

    census_output="42 43"
    if observed_pid=$(rust_pid); then
        printf 'PID census self-test accepted multiple processes as %q\n' \
            "$observed_pid" >&2
        return 1
    fi
    if restart_rustbgpd_with_dynamic_range || [ "$kill_calls" -ne 0 ]; then
        printf 'PID census self-test signaled after a multiple-process census\n' >&2
        return 1
    fi

    census_output="42"
    if ! observed_pid=$(rust_pid) || [ "$observed_pid" != "42" ]; then
        printf 'PID census self-test rejected exact-one output %q\n' \
            "$observed_pid" >&2
        return 1
    fi

    if ! signal_rustbgpd_pid TERM "42"; then
        printf 'PID signal self-test rejected valid PID 42\n' >&2
        return 1
    fi
    expected_signal="KILL"
    expected_pid="43"
    if ! signal_rustbgpd_pid KILL "43"; then
        printf 'PID signal self-test rejected valid PID 43\n' >&2
        return 1
    fi
    if [ "$kill_calls" -ne 2 ]; then
        printf 'PID signal self-test expected two valid kills, observed %s\n' \
            "$kill_calls" >&2
        return 1
    fi

    local invalid
    local -a invalid_pids=(
        ""
        "0"
        "-1"
        "not-a-pid"
        "17 18"
        '23; touch /tmp/m43-pid-injection'
        "\$(touch /tmp/m43-pid-substitution)"
    )
    for invalid in "${invalid_pids[@]}"; do
        if signal_rustbgpd_pid TERM "$invalid"; then
            printf 'PID signal self-test accepted invalid PID %q\n' "$invalid" >&2
            return 1
        fi
        if [ "$kill_calls" -ne 2 ]; then
            printf 'PID signal self-test invoked kill for invalid PID %q\n' \
                "$invalid" >&2
            return 1
        fi
    done

    printf 'M43 PID census and signal self-test passed\n'
}

rust_pid_gone_or_zombie() {
    local pid=${1:?}
    docker exec "$RUSTBGPD" sh -lc '
        pid=$1
        [ ! -d "/proc/$pid" ] && exit 0
        while read -r name state _; do
            if [ "$name" = "State:" ]; then
                [ "$state" = "Z" ]
                exit
            fi
        done < "/proc/$pid/status"
        exit 1
    ' sh "$pid"
}

restart_rustbgpd_with_dynamic_range() {
    local old_pid
    if ! old_pid=$(rust_pid); then
        fail "dynamic-range proof expected exactly one live rustbgpd process"
        dump_diagnostics
        return 1
    fi

    log "Restarting rustbgpd with the direct dynamic-prefix TCP-AO owner..."
    if ! signal_rustbgpd_pid TERM "$old_pid"; then
        fail "could not stop rustbgpd PID $old_pid for the dynamic-range proof"
        return 1
    fi
    local process_gone=false
    for _ in $(seq 1 100); do
        if rust_pid_gone_or_zombie "$old_pid"; then
            process_gone=true
            break
        fi
        sleep 0.1
    done
    if [ "$process_gone" != true ]; then
        fail "rustbgpd PID $old_pid did not stop for the dynamic-range proof"
        dump_diagnostics
        return 1
    fi

    start_rustbgpd "exec /usr/local/bin/rustbgpd $DYNAMIC_CONFIG"
    local new_pid
    if ! new_pid=$(rust_pid); then
        fail "dynamic-range proof expected exactly one restarted rustbgpd process"
        dump_diagnostics
        return 1
    fi
    if [ "$new_pid" = "$old_pid" ]; then
        fail "dynamic-range proof restart reused rustbgpd PID $old_pid"
        return 1
    fi
    ok "rustbgpd restarted on the direct dynamic-prefix config (PID $old_pid -> $new_pid)"
}

crash_rustbgpd_and_prove_disconnect() {
    local proof=${1:?}
    local pid
    if ! pid=$(rust_pid); then
        fail "$proof: expected exactly one live rustbgpd process before SIGKILL"
        dump_diagnostics
        return 1
    fi

    log "$proof: SIGKILL rustbgpd PID $pid"
    if ! signal_rustbgpd_pid KILL "$pid"; then
        fail "$proof: could not SIGKILL rustbgpd PID $pid"
        return 1
    fi

    local process_gone=false
    for _ in $(seq 1 20); do
        if rust_pid_gone_or_zombie "$pid"; then
            process_gone=true
            break
        fi
        sleep 0.1
    done
    if [ "$process_gone" != true ]; then
        fail "$proof: rustbgpd PID $pid remained after SIGKILL"
        dump_diagnostics
        return 1
    fi

    local disconnected=false
    local state=''
    for _ in $(seq 1 30); do
        if state=$(bird_state_strict) && awk '
            $1 == "rustbgpd" { found = 1; established = ($0 ~ /Established/) }
            END { exit (found && !established) ? 0 : 1 }
        ' <<<"$state"; then
            disconnected=true
            break
        fi
        sleep 0.1
    done
    if [ "$disconnected" != true ]; then
        fail "$proof: BIRD did not observe the crashed rustbgpd disconnect"
        dump_diagnostics
        return 1
    fi

    CRASHED_RUST_PID=$pid
    ok "$proof: SIGKILL removed rustbgpd PID $pid and BIRD left Established"
}

restart_rustbgpd_from_durable_config() {
    local proof=${1:?}
    if [ -z "$CRASHED_RUST_PID" ]; then
        fail "$proof: no crashed rustbgpd PID was recorded"
        return 1
    fi

    log "$proof: restarting from the durable /tmp/m43-config.toml"
    start_rustbgpd "exec /usr/local/bin/rustbgpd /tmp/m43-config.toml"

    local restarted_pid
    if ! restarted_pid=$(rust_pid); then
        fail "$proof: expected exactly one rustbgpd process after restart"
        dump_diagnostics
        return 1
    fi
    if [ "$restarted_pid" = "$CRASHED_RUST_PID" ]; then
        fail "$proof: restart reused crashed PID $CRASHED_RUST_PID"
        dump_diagnostics
        return 1
    fi

    ok "$proof: rustbgpd restarted with new PID $restarted_pid (was $CRASHED_RUST_PID)"
    CRASHED_RUST_PID=""
}

wait_fresh_restart_recovery() {
    local proof=${1:?}
    local inventory=${2:?}
    local expected_current=${3:?}
    local expected_rnext=${4:?}
    local expected_health=${5:-TCP_AO_HEALTH_HEALTHY}
    log "$proof: waiting for authenticated fresh-start recovery"

    local state='{}'
    local routes='{}'
    for i in $(seq 1 45); do
        state=$(grpc_neighbor_state || echo '{}')
        routes=$(grpc_list_received || echo '{}')
        if printf '%s' "$state" | grep -Eq \
            'interop-(old|next|successor)-secret-m43|wrong-(next|successor)-secret-m43'; then
            fail "$proof: neighbor state leaked TCP-AO secret material"
            return 1
        fi

        if bird_state | grep -q 'Established' &&
            printf '%s' "$routes" | grep -q "\"prefix\": \"$TEST_PREFIX\"" &&
            jq -e \
                --arg inventory "$inventory" \
                --arg health "$expected_health" \
                --argjson current "$expected_current" \
                --argjson rnext "$expected_rnext" '
                def mkt($send; $recv):
                  .peerAddress == "10.0.43.2" and .prefixLength == 32 and
                  .sendId == $send and .recvId == $recv and
                  .algorithm == "hmac(sha256)";
                (.tcpAoDesiredGeneration | tonumber) == 1 and
                (.tcpAoAppliedGeneration | tonumber) == 1 and
                .tcpAoRotationPhase == "idle" and
                (.tcpAoRotationError // "") == "" and
                .authentication == "AUTHENTICATION_MODE_TCP_AO" and
                .tcpAoHealth == $health and
                .tcpAo.currentKeyId == $current and
                .tcpAo.rnextKeyId == $rnext and
                ((.tcpAo.packetsBad // 0) | tonumber) == 0 and
                ((.tcpAo.packetsKeyNotFound // 0) | tonumber) == 0 and
                ((.tcpAo.packetsAoRequired // 0) | tonumber) == 0 and
                (if $inventory == "add-only" then
                    (.tcpAo.keys | length) == 3 and
                    any(.tcpAo.keys[];
                      mkt(1; 11) and .deprecated == true and
                      .preferred != true and .isCurrent != true and
                      .isRnext != true) and
                    any(.tcpAo.keys[];
                      mkt(2; 12) and .deprecated != true and
                      .preferred == true and .isCurrent == true and
                      .isRnext == true) and
                    any(.tcpAo.keys[];
                      mkt(3; 13) and .deprecated != true and
                      .preferred != true and .isCurrent != true and
                      .isRnext != true)
                 elif $inventory == "selection" then
                    (.tcpAo.keys | length) == 3 and
                    any(.tcpAo.keys[];
                      mkt(1; 11) and .deprecated == true and
                      .preferred != true and .isCurrent != true and
                      .isRnext != true) and
                    any(.tcpAo.keys[];
                      mkt(2; 12) and .deprecated == true and
                      .preferred != true and
                      ((.isCurrent == true) == ($current == 2)) and
                      ((.isRnext == true) == ($rnext == 12))) and
                    any(.tcpAo.keys[];
                      mkt(3; 13) and .deprecated != true and
                      .preferred == true and
                      ((.isCurrent == true) == ($current == 3)) and
                      ((.isRnext == true) == ($rnext == 13))) and
                    (($current == 2 and $rnext == 13) or
                     ($current == 3 and $rnext == 13))
                 elif $inventory == "delete" then
                    (.tcpAo.keys | length) == 1 and
                    (.tcpAo.keys[0] |
                      mkt(3; 13) and
                      .deprecated != true and .preferred == true and
                      .isCurrent == true and .isRnext == true)
                 else false
                 end)
            ' >/dev/null <<<"$state"; then
            ok "$proof: fresh 1/1 idle, exact $inventory inventory, mandatory TCP-AO ($expected_health), route/session recovery, Current/RNext=$expected_current/$expected_rnext (attempt $i)"
            return 0
        fi
        sleep 2
    done

    fail "$proof: fresh authenticated recovery did not converge"
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

prove_dynamic_range_accept_boundary() {
    log "BEGIN: direct dynamic-prefix TCP-AO accept and rejection proof"
    restart_rustbgpd_with_dynamic_range
    start_bird "$GOOD_CONF"
    wait_bird_established
    wait_route_present
    assert_dynamic_two_key_inventory

    prove_unsigned_peer_requires_ao \
        "dynamic-prefix MKT-covered address" "$GOOD_CONF"
    assert_dynamic_two_key_inventory
    ok "direct dynamic-prefix TCP-AO accepted, rejected unsigned traffic, and recovered"
}

main_uninterrupted() {
    log "M43 interop test: TCP-AO full live key rotation with BIRD $BIRD_VERSION"
    log "Topology: $TOPO"

    resolve_grpc_addr
    preflight_bird_container
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

    prove_unsigned_peer_requires_ao \
        "static MKT-covered address" "/etc/bird/bird-successor.conf"

    log "Restarting BIRD with a mismatched preferred TCP-AO secret"
    start_bird "$BAD_CONF"
    wait_route_absent
    assert_bad_key_does_not_establish

    prove_dynamic_range_accept_boundary

    print_summary
}

main_crash_restart() {
    log "M43 crash-restart proof: durable TCP-AO rotation recovery with BIRD $BIRD_VERSION"
    log "Topology: $TOPO"

    # Load-bearing mutation receipts:
    # - restarting add-only from the initial two-key config fails its exact
    #   inventory assertion;
    # - restarting selection from the add-only config fails its preferred /
    #   deprecated metadata assertion;
    # - restarting delete from the selection config fails its sole-key
    #   inventory assertion; and
    # - making strict BIRD inspection fail cannot satisfy the disconnect
    #   assertion because the named protocol row must remain observable.

    resolve_grpc_addr
    preflight_bird_container
    start_bird "$GOOD_CONF"
    docker exec "$RUSTBGPD" cp /etc/rustbgpd/config.toml /tmp/m43-config.toml
    start_rustbgpd "exec /usr/local/bin/rustbgpd /tmp/m43-config.toml"

    wait_bird_established
    wait_route_present
    assert_two_key_inventory

    local proof="add-only crash-restart proof"
    log "BEGIN: $proof"
    apply_successor_generation
    wait_successor_generation
    crash_rustbgpd_and_prove_disconnect "$proof"
    restart_rustbgpd_from_durable_config "$proof"
    wait_fresh_restart_recovery "$proof" add-only 2 12

    proof="selection/deprecation awaiting-peer crash-restart proof"
    log "BEGIN: $proof"
    begin_selection_generation
    wait_selection_awaiting 2 1
    crash_rustbgpd_and_prove_disconnect "$proof"
    restart_rustbgpd_from_durable_config "$proof"
    wait_fresh_restart_recovery \
        "$proof before peer switch" selection 2 13 TCP_AO_HEALTH_DEGRADED
    select_bird_successor
    wait_fresh_restart_recovery \
        "$proof after peer switch" selection 3 13 TCP_AO_HEALTH_HEALTHY

    proof="delete crash-restart proof"
    log "BEGIN: $proof"
    apply_deletion_generation
    wait_deletion_generation 2
    crash_rustbgpd_and_prove_disconnect "$proof"
    restart_rustbgpd_from_durable_config "$proof"
    wait_fresh_restart_recovery "$proof" delete 3 13

    print_summary
}

if [ "${1:-}" = "--self-test-pid-signal" ]; then
    self_test_pid_signal
else
    case "${M43_MODE:-uninterrupted}" in
        uninterrupted)
            main_uninterrupted "$@"
            ;;
        crash-restart)
            main_crash_restart "$@"
            ;;
        *)
            echo "ERROR: M43_MODE must be 'uninterrupted' or 'crash-restart'" >&2
            exit 2
            ;;
    esac
fi
