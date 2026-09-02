#!/usr/bin/env bash
# RTR transport authentication receipt — local loopback, no containers.
#
# Runs the in-repo RTR v2 server with TCP MD5 (RFC 2385) required on its
# listener and proves the `[[rpki.cache_servers]] md5_password` path end to
# end through the rustbgpd binary:
#   1. matching key   -> the cache syncs (end_of_data_ready = 1, vrp_count > 0)
#   2. wrong key      -> no session; "RTR connection failed" with the key hint
#   3. unsigned cache -> a keyed client stays down (no plaintext fallback)
#
# Usage: bash tests/interop/scripts/test-rtr-tcp-md5.sh
#   RUSTBGPD_BIN   daemon binary (default target/debug/rustbgpd)
#   RTR_PORT, METRICS_PORT, BGP_PORT   loopback ports (defaults 13323/19179/11179)
set -euo pipefail

RUSTBGPD_BIN="${RUSTBGPD_BIN:-target/debug/rustbgpd}"
RTR_PORT="${RTR_PORT:-13323}"
METRICS_PORT="${METRICS_PORT:-19179}"
BGP_PORT="${BGP_PORT:-11179}"
KEY="rtr-md5-receipt-key"
SERVER_PY="$(dirname "$0")/rtr-v2-server.py"
WORK="$(mktemp -d)"
SERVER_PID=""
DAEMON_PID=""

cleanup() {
    [[ -n "$DAEMON_PID" ]] && kill "$DAEMON_PID" 2>/dev/null || true
    [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; echo "--- daemon log"; cat "$WORK/daemon.log"; exit 1; }

start_server() { # $1 = listener MD5 key ("" = plain TCP)
    RTR_LISTEN_PORT="$RTR_PORT" RTR_TCP_MD5_KEY="$1" \
        python3 "$SERVER_PY" > "$WORK/server.log" 2>&1 &
    SERVER_PID=$!
    sleep 0.5
    kill -0 "$SERVER_PID" 2>/dev/null || { cat "$WORK/server.log"; fail "RTR server did not start"; }
}

stop_server() { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; SERVER_PID=""; }

write_config() { # $1 = daemon md5_password
    cat > "$WORK/rustbgpd.toml" <<EOF
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = $BGP_PORT

[global.telemetry]
prometheus_addr = "127.0.0.1:$METRICS_PORT"
log_format = "json"

[global.telemetry.grpc_uds]
path = "$WORK/grpc.sock"
principal = "rustbgpd://operator/test-only"

[rpki]
[[rpki.cache_servers]]
address = "127.0.0.1:$RTR_PORT"
md5_password = "$1"
refresh_interval = 5
retry_interval = 2
expire_interval = 60

[security.grpc]
enforcement = "tier"

[security.grpc.roles]
"rustbgpd://operator/test-only" = "operator"
EOF
}

start_daemon() {
    "$RUSTBGPD_BIN" --check "$WORK/rustbgpd.toml" > "$WORK/check.log" 2>&1 || { cat "$WORK/check.log"; fail "config check"; }
    "$RUSTBGPD_BIN" "$WORK/rustbgpd.toml" > "$WORK/daemon.log" 2>&1 &
    DAEMON_PID=$!
}

stop_daemon() { kill "$DAEMON_PID" 2>/dev/null || true; wait "$DAEMON_PID" 2>/dev/null || true; DAEMON_PID=""; }

# Prints the sample value, or 0 when the family has not been emitted yet
# (gauges appear on first set).
metric() {
    curl -sf "http://127.0.0.1:$METRICS_PORT/metrics" 2>/dev/null \
        | awk -v m="$1" '$1 ~ "^"m"([{ ]|$)" {print $2; found=1; exit} END {if (!found) print 0}'
}

wait_for_sync() {
    for _ in $(seq 1 40); do
        if [[ "$(metric 'bgp_rpki_cache_end_of_data_ready')" == "1" ]] \
            && [[ "$(metric 'bgp_rpki_vrp_count')" =~ ^[1-9] ]]; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

assert_down() { # waits past the 10 s handshake bound for the logged diagnostic
    for _ in $(seq 1 60); do
        grep -q 'RTR connection failed' "$WORK/daemon.log" && break
        sleep 0.5
    done
    grep -q 'RTR connection failed' "$WORK/daemon.log" || fail "no 'RTR connection failed' diagnostic"
    grep -q 'TCP MD5 / TCP-AO key' "$WORK/daemon.log" || fail "diagnostic lacks the key-mismatch hint"
    [[ "$(metric 'bgp_rpki_cache_end_of_data_ready')" == "0" ]] || fail "cache reported ready"
    [[ "$(metric 'bgp_rpki_vrp_count')" == "0" ]] || fail "VRPs loaded without the key"
}

echo "case 1: matching key syncs"
start_server "$KEY"; write_config "$KEY"; start_daemon
wait_for_sync || fail "cache did not sync with the matching key"
grep -q 'RTR transport authentication configured' "$WORK/daemon.log" || fail "auth not logged"
grep -q "$KEY" "$WORK/daemon.log" && fail "key leaked into the daemon log"
stop_daemon; stop_server
echo "  PASS"

echo "case 2: wrong key never completes the handshake"
start_server "$KEY"; write_config "not-$KEY"; start_daemon
assert_down
stop_daemon; stop_server
echo "  PASS"

echo "case 3: keyed client against an unsigned cache stays down"
start_server ""; write_config "$KEY"; start_daemon
assert_down
stop_daemon; stop_server
echo "  PASS"

echo "RTR TCP MD5 receipt: all cases passed"
