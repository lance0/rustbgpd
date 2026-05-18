#!/usr/bin/env bash
# M43 interop test — TCP-AO with BIRD 3.x
#
# Validates:
#   1. BGP session establishes with TCP-AO configured on both peers.
#   2. BIRD advertises a route over the protected session.
#   3. Mismatched key material fails closed and does not re-establish.
#
# Prerequisites:
#   - BIRD image built:
#       docker build -t bird:3.2.1-tcpao -f tests/interop/Dockerfile.bird3 tests/interop
#   - rustbgpd image built:
#       docker build -t rustbgpd:dev .
#   - containerlab deployed:
#       containerlab deploy -t tests/interop/m43-tcp-ao-bird.clab.yml
#
# Usage:
#   bash tests/interop/scripts/test-m43-tcp-ao-bird.sh

TOPO="m43-tcp-ao-bird"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"
BIRD="clab-${TOPO}-bird"
GOOD_CONF="/etc/bird/bird.conf"
BAD_CONF="/etc/bird/bird-bad.conf"
TEST_PREFIX="203.0.113.43"

grpc_list_received() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d '{"neighbor_address": "10.0.43.2"}' \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

bird_state() {
    docker exec "$BIRD" birdc show protocols rustbgpd 2>/dev/null || true
}

dump_diagnostics() {
    echo "--- rustbgpd logs ---" >&2
    docker logs --tail 120 "$RUSTBGPD" >&2 || true
    echo "--- BIRD logs ---" >&2
    docker logs --tail 120 "$BIRD" >&2 || true
    echo "--- BIRD protocol state ---" >&2
    docker exec "$BIRD" birdc show protocols all rustbgpd >&2 || true
    echo "--- rustbgpd TCP-AO support ---" >&2
    grpcurl -plaintext -import-path . -proto "$PROTO" \
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
    log "M43 interop test: TCP-AO with BIRD 3.x"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_bird "$GOOD_CONF"
    # start_rustbgpd intentionally uses its default daemon wrapper here.
    # shellcheck disable=SC2119
    start_rustbgpd

    wait_bird_established
    wait_route_present

    log "Restarting BIRD with mismatched TCP-AO secret"
    start_bird "$BAD_CONF"
    wait_route_absent
    assert_bad_key_does_not_establish

    print_summary
}

main "$@"
