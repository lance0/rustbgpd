#!/usr/bin/env bash
# Shared test library for interop test scripts.
#
# Source this at the top of each test script after setting TOPO:
#   TOPO="m1-frr"
#   SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
#   source "$SCRIPT_DIR/test-lib.sh"
#
# Provides:
#   - Pre-flight checks (docker, grpcurl, containerlab topology running)
#   - Timestamped log/ok/fail helpers
#   - resolve_grpc_addr, resolve_ip
#   - start_rustbgpd with gRPC health wait
#   - wait_established (FRR vtysh polling)
#   - Trap-based cleanup: auto-destroy containerlab on EXIT if CLEANUP=1

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (set TOPO before sourcing)
# ---------------------------------------------------------------------------

: "${TOPO:?TOPO must be set before sourcing test-lib.sh}"
PROTO="proto/rustbgpd.proto"
GRPC_ADDR=""
# Drivers with a non-default container name (e.g. M38 / M39 use
# `pe1` / `pe2` rather than the single-rustbgpd `rustbgpd` shape)
# can set RUSTBGPD before sourcing this lib.
RUSTBGPD="${RUSTBGPD:-clab-${TOPO}-rustbgpd}"

pass=0
fail=0

# ---------------------------------------------------------------------------
# Timestamped output helpers
# ---------------------------------------------------------------------------

_ts() { date +%H:%M:%S 2>/dev/null || true; }

log()  { printf "\033[1;34m[%s TEST]\033[0m %s\n" "$(_ts)" "$*"; }
ok()   { pass=$((pass + 1)); printf "\033[1;32m  [%s] PASS\033[0m %s\n" "$(_ts)" "$*"; }
fail() { fail=$((fail + 1)); printf "\033[1;31m  [%s] FAIL\033[0m %s\n" "$(_ts)" "$*"; }

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

preflight() {
    local errors=0

    if ! command -v docker &>/dev/null; then
        echo "ERROR: docker not found in PATH" >&2
        errors=$((errors + 1))
    fi

    if ! command -v grpcurl &>/dev/null; then
        echo "ERROR: grpcurl not found in PATH" >&2
        errors=$((errors + 1))
    fi

    # jq parses every grpcurl JSON response in the shared helpers; without it the
    # failures are opaque (empty fields, polls timing out) rather than a clear
    # missing-dependency error.
    if ! command -v jq &>/dev/null; then
        echo "ERROR: jq not found in PATH" >&2
        errors=$((errors + 1))
    fi

    if ! docker inspect "$RUSTBGPD" &>/dev/null; then
        echo "ERROR: container $RUSTBGPD not running — deploy topology first:" >&2
        echo "  containerlab deploy -t tests/interop/${TOPO}.clab.yml" >&2
        errors=$((errors + 1))
    fi

    if [ ! -f "$PROTO" ]; then
        echo "ERROR: proto file not found at $PROTO — run from repo root" >&2
        errors=$((errors + 1))
    fi

    if [ "$errors" -gt 0 ]; then
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Common helpers
# ---------------------------------------------------------------------------

resolve_ip() {
    docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1" 2>/dev/null
}

resolve_grpc_addr() {
    local ip
    ip=$(resolve_ip "$RUSTBGPD")
    if [ -z "$ip" ]; then
        echo "ERROR: cannot resolve management IP for $RUSTBGPD" >&2
        exit 1
    fi
    GRPC_ADDR="${ip}:50051"
    log "gRPC endpoint: $GRPC_ADDR"
}

grpc_health() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.ControlService/GetHealth 2>/dev/null
}

# Standardized rustbgpd start, used by every interop script. Pass a
# custom command string to run a non-default daemon invocation
# (e.g. M21/M24 launch the binary directly against `/tmp/config.toml`
# after rewriting placeholders at runtime); omit the argument to use
# the wrapper at `/usr/local/bin/start-rustbgpd.sh`.
start_rustbgpd() {
    local start_cmd="${1:-/usr/local/bin/start-rustbgpd.sh}"
    log "Starting rustbgpd daemon..."
    docker exec -d "$RUSTBGPD" sh -c "$start_cmd"

    # Poll /proc for rustbgpd up to 10 s. The previous 3 s fixed sleep
    # was tight under heavy CI load (parallel containerlab deploys);
    # the loop keeps the local fast path quick while giving slow
    # environments room to land the fork.
    local found=0
    for i in $(seq 1 10); do
        if docker exec "$RUSTBGPD" sh -c 'cat /proc/*/comm 2>/dev/null' | grep -q rustbgpd; then
            log "rustbgpd is running (after ${i}s)"
            found=1
            break
        fi
        sleep 1
    done

    if [ "$found" -ne 1 ]; then
        echo "ERROR: rustbgpd failed to start within 10s" >&2
        echo "--- docker top $RUSTBGPD ---" >&2
        docker top "$RUSTBGPD" 2>&1 >&2 || true
        echo "--- container /proc comm names ---" >&2
        docker exec "$RUSTBGPD" sh -c 'cat /proc/[0-9]*/comm 2>/dev/null' >&2 || true
        echo "--- foreground rustbgpd (2 s capture) ---" >&2
        # Run the binary in the foreground briefly to capture any
        # immediate-exit output (config error, panic, etc.). If it
        # does start cleanly here, the 2 s timeout terminates it.
        docker exec "$RUSTBGPD" sh -c 'timeout 2 /usr/local/bin/rustbgpd /etc/rustbgpd/config.toml 2>&1 || true' >&2 || true
        exit 1
    fi

    log "Waiting for gRPC to become available..."
    for i in $(seq 1 15); do
        if grpc_health >/dev/null 2>&1; then
            ok "gRPC endpoint ready (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "gRPC endpoint not reachable within 30s"
    return 1
}

# Wait for a FRR neighbor to reach Established state.
# Usage: wait_frr_established <frr_container> <peer_addr> [label]
wait_frr_established() {
    local frr_container=${1:?}
    local peer_addr=${2:?}
    local label=${3:-BGP}

    log "Waiting for $label session to reach Established..."
    for i in $(seq 1 45); do
        local state
        state=$(docker exec "$frr_container" vtysh -c "show bgp neighbors $peer_addr json" 2>/dev/null \
            | grep -o '"bgpState":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
        if [ "$state" = "Established" ]; then
            ok "$label session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label session did not reach Established within 90s"
    return 1
}

# ---------------------------------------------------------------------------
# Shared rustbgpd EVPN multi-homing helpers
# ---------------------------------------------------------------------------
# M66/M67 share a rustbgpd-on-both-sides shape: a VTEP/RR container, two
# segment PEs, a CE, and a remote host. Keep the helpers here low-level and
# transparent; phase-specific assertions stay in the individual M scripts.

# rbgp as the OPERATOR principal against a PE's bearer-token TCP
# listener. $1 = container, rest = CLI args.
pe_ctl() {
    local pe=${1:?}
    local token_file="${OPERATOR_TOKEN_FILE:-/etc/rustbgpd/grpc-operator.token}"
    shift
    docker exec "$pe" rbgp -s http://127.0.0.1:50051 \
        --token-file "$token_file" "$@"
}

# rbgp as the OBSERVER principal against a PE's UDS listener.
pe_ctl_observer() {
    local pe=${1:?}
    local observer_sock="${OBSERVER_SOCK:-unix:///var/lib/rustbgpd/grpc-observer.sock}"
    shift
    docker exec "$pe" rbgp -s "$observer_sock" "$@"
}

# rbgp against the VTEP/RR (legacy enforcement, plaintext TCP).
vtep_ctl() {
    docker exec "$VTEP" rbgp -s http://127.0.0.1:50051 "$@"
}

# JSON array of the VTEP's EVPN routes of one type from one peer.
vtep_routes() {
    local route_type=${1:?}
    local peer=${2:?}
    vtep_ctl evpn --route-type "$route_type" --peer "$peer" -j 2>/dev/null || echo "[]"
}

# Count routes of a type from a peer, optionally filtered by a jq row predicate.
vtep_route_count() {
    local route_type=${1:?}
    local peer=${2:?}
    local predicate=${3:-true}
    vtep_routes "$route_type" "$peer" \
        | jq "[.[] | select(${predicate})] | length" 2>/dev/null || echo 0
}

# Poll until at least $4 routes of a type/peer/predicate are present. Echoes
# the final count; exit 0 on success. 1s grain, optional $5 attempts.
wait_vtep_routes_at_least() {
    local route_type=${1:?} peer=${2:?} predicate=${3:?} want=${4:?}
    local attempts=${5:-${VTEP_ROUTE_WAIT_ATTEMPTS:-60}}
    local got=0
    for _ in $(seq 1 "$attempts"); do
        got=$(vtep_route_count "$route_type" "$peer" "$predicate")
        if [ "${got:-0}" -ge "$want" ] 2>/dev/null; then
            echo "$got"
            return 0
        fi
        sleep 1
    done
    echo "${got:-0}"
    return 1
}

# Poll until no routes of a type/peer/predicate remain. Echoes the final count;
# exit 0 on success. 1s grain, optional $4 attempts.
wait_vtep_routes_gone() {
    local route_type=${1:?} peer=${2:?} predicate=${3:?}
    local attempts=${4:-${VTEP_ROUTE_WAIT_ATTEMPTS:-60}}
    local got=1
    for _ in $(seq 1 "$attempts"); do
        got=$(vtep_route_count "$route_type" "$peer" "$predicate")
        if [ "${got:-1}" -eq 0 ] 2>/dev/null; then
            echo 0
            return 0
        fi
        sleep 1
    done
    echo "${got:-1}"
    return 1
}

rb_fdb() {
    docker exec "$VTEP" bridge fdb show dev "$VXLAN" 2>/dev/null || true
}

rb_nh() {
    docker exec "$VTEP" ip nexthop show 2>/dev/null || true
}

ce_mac_row() {
    rb_fdb | grep -i "$CE_MAC" || true
}

# Per-VTEP fdb nexthop id for a gateway IP (`id <nid> via <ip> fdb`).
nh_id_for_via() {
    local ip=${1:?}
    rb_nh | awk -v ip="$ip" '
        $1 == "id" && $3 == "via" && $4 == ip {
            for (i = 1; i <= NF; i++) {
                if ($i == "fdb") {
                    print $2
                    exit
                }
            }
        }
    ' || true
}

# Member ids of a group line (`id <gid> group <mid>[/<mid>...] ... fdb`).
group_members_of() {
    local gid=${1:?}
    rb_nh | awk -v gid="$gid" '
        $1 == "id" && $2 == gid && $3 == "group" {
            print $4
            exit
        }
    ' | tr '/' ' ' || true
}

# Resolve the CE MAC row's egress VTEP IP(s): either a plain `dst <ip>` row or
# an `nhid <gid>` row whose group members' `via` IPs are the egress set.
ce_mac_egress_ips() {
    local row gid dst members mid via
    row=$(ce_mac_row)
    [ -z "$row" ] && return 0
    dst=$(echo "$row" | grep -oE ' dst [0-9.]+' | awk '{print $2}' | head -1 || true)
    if [ -n "$dst" ]; then
        echo "$dst"
        return 0
    fi
    gid=$(echo "$row" | grep -oE ' nhid [0-9]+' | awk '{print $2}' | head -1 || true)
    [ -z "$gid" ] && return 0
    members=$(group_members_of "$gid")
    for mid in $members; do
        via=$(rb_nh | grep -E "^id ${mid} via " | awk '{print $4}' || true)
        [ -n "$via" ] && echo "$via"
    done
}

# Scrape Prometheus via a container's management IP (M38/M49/M66/M67 pattern).
prom_scrape() {
    local container=${1:?}
    local ip
    ip=$(resolve_ip "$container")
    [ -z "$ip" ] && return 0
    curl -sfm 5 "http://${ip}:9179/metrics" 2>/dev/null \
        || wget -qO- -T 5 "http://${ip}:9179/metrics" 2>/dev/null \
        || true
}

prom_value() {
    local container=${1:?}
    local name=${2:?}
    prom_scrape "$container" | awk -v n="$name" '$1 == n { print $2; exit }'
}

# evpn_df_role{esi=...,vni=...,role=$2} value on $1 (empty if absent).
prom_df_role() {
    local container=${1:?}
    local role=${2:?}
    prom_scrape "$container" \
        | awk -v role="$role" -v vni="$VNI" -v esi="$ESI" '
            function label_value(line, key, pattern, raw) {
                pattern = key "=\"[^\"]*\""
                if (match(line, pattern)) {
                    raw = substr(line, RSTART + length(key) + 2, RLENGTH - length(key) - 3)
                    return raw
                }
                return ""
            }
            $0 ~ /^evpn_df_role\{/ &&
                label_value($0, "role") == role &&
                label_value($0, "vni") == vni &&
                label_value($0, "esi") == esi {
                    print $2
                    exit
                }
        '
}

wait_for_role() {
    local container=${1:?} role=${2:?} want=${3:?}
    local attempts=${4:-${ROLE_WAIT_ATTEMPTS:-60}}
    for _ in $(seq 1 "$attempts"); do
        [ "$(prom_df_role "$container" "$role")" = "$want" ] && return 0
        sleep 1
    done
    return 1
}

# Single-active whole-port AC gate helpers for bound Ethernet Segments.
ac_port_state() {
    docker exec "$1" bridge -d link show dev "$AC_IF" 2>/dev/null \
        | grep -o 'state [a-z]*' | head -1 | cut -d' ' -f2
}

wait_ac_gate_state() {
    local container=${1:?} want=${2:?} attempts=${3:-60}
    for _ in $(seq 1 "$attempts"); do
        [ "$(ac_port_state "$container")" = "$want" ] && return 0
        sleep 1
    done
    return 1
}

assert_ac_gate() {
    local container=${1:?} want=${2:?} label=${3:?}
    if wait_ac_gate_state "$container" "$want"; then
        ok "$label (state $want)"
    else
        fail "$label (want state $want, got '$(ac_port_state "$container")')"
        docker exec "$container" bridge -d link show dev "$AC_IF" >&2 || true
    fi
}

# evpn_es_drained{esi=...,reason=$2} on $1, normalized: absent series reads 0.
drain_gauge() {
    local container=${1:?}
    local reason=${2:?}
    local value
    value=$(prom_scrape "$container" \
        | awk -v r="reason=\"${reason}\"" -v e="esi=\"${ESI}\"" \
            '$0 ~ /^evpn_es_drained\{/ && index($0, r) && index($0, e) { print $2; exit }')
    echo "${value:-0}"
}

wait_drain_gauge() {
    local container=${1:?} reason=${2:?} want=${3:?} attempts=${4:-15}
    for _ in $(seq 1 "$attempts"); do
        [ "$(drain_gauge "$container" "$reason")" = "$want" ] && return 0
        sleep 1
    done
    return 1
}

assert_drain_gauge() {
    local container=${1:?} reason=${2:?} want=${3:?} label=${4:?}
    local got
    got=$(drain_gauge "$container" "$reason")
    if [ "$got" = "$want" ]; then
        ok "$label (evpn_es_drained{reason=\"$reason\"}=$got)"
    else
        fail "$label (evpn_es_drained{reason=\"$reason\"}=$got, want $want)"
        prom_scrape "$container" | grep '^evpn_es_drained' >&2 || true
    fi
}

now_ms() {
    date +%s%3N
}

pe1_ac_down() {
    docker exec "$PE1" ip link set "$AC_IF" down
}

pe1_ac_up() {
    docker exec "$PE1" ip link set "$AC_IF" up
}

ce_recovery_broadcast() {
    local target="${CE_RECOVERY_BROADCAST_IP:-192.168.67.99}"
    docker exec "$CE" ping -c 1 -W 1 "$target" >/dev/null 2>&1 || true
}

# Wait until a PE's gRPC surface answers an operator rbgp call.
wait_pe_grpc() {
    local pe=${1:?}
    local label=${2:?}
    local attempts=${PE_GRPC_ATTEMPTS:-30}
    local timeout=$((attempts * 2))
    for i in $(seq 1 "$attempts"); do
        if pe_ctl "$pe" global >/dev/null 2>&1; then
            ok "$label gRPC ready (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label gRPC not reachable within ${timeout}s"
    docker exec "$pe" tail -40 /var/log/rustbgpd.log >&2 || true
    return 1
}

# Wait for the VTEP's session to a peer to reach Established.
wait_vtep_established() {
    local peer=${1:?}
    local label=${2:-BGP}
    local attempts=${VTEP_ESTABLISHED_ATTEMPTS:-45}
    local timeout=$((attempts * 2))
    log "Waiting for $label session to reach Established..."
    for i in $(seq 1 "$attempts"); do
        if vtep_ctl neighbor "$peer" 2>/dev/null | grep -qi "establ"; then
            ok "$label session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label session did not reach Established within ${timeout}s"
    return 1
}

ping_burst_ok() {
    local label=${1:?}
    local out received
    out=$(docker exec "$HR" ping -c 10 -i 0.2 -W 1 "$CE_HOST_IP" 2>/dev/null || true)
    received=$(echo "$out" | grep -oE '[0-9]+ received' | awk '{print $1}' || true)
    if [ "${received:-0}" -ge 9 ] 2>/dev/null; then
        ok "$label (${received:-0}/10 replies)"
        return 0
    fi
    fail "$label (${received:-0}/10 replies)"
    echo "$out" | tail -5 >&2
    return 1
}

wait_ping() {
    local label=${1:?}
    local attempts=${2:-${WAIT_PING_ATTEMPTS:-60}}
    for i in $(seq 1 "$attempts"); do
        if docker exec "$HR" ping -c 1 -W 1 "$CE_HOST_IP" >/dev/null 2>&1; then
            ok "$label (attempt $i)"
            return 0
        fi
        sleep 1
    done
    fail "$label not reached within ${attempts}s"
    return 1
}

prober_prefix() {
    printf '%s' "${PROBER_PREFIX:-${TOPO}}"
}

start_prober() {
    local tag=${1:?}
    local prefix interval_sec
    prefix=$(prober_prefix)
    interval_sec=$(awk -v ms="$PROBE_INTERVAL_MS" 'BEGIN { printf "%.3f", ms / 1000 }')
    docker exec "$HR" sh -c 'rm -f "/tmp/$1-prober-$2.log" "/tmp/$1-prober-$2.pid"' _ "$prefix" "$tag" || true
    docker exec -d "$HR" sh -c 'ping -i "$1" -O "$2" >"/tmp/$3-prober-$4.log" 2>&1 & echo $! >"/tmp/$3-prober-$4.pid"' _ "$interval_sec" "$CE_HOST_IP" "$prefix" "$tag"
}

stop_prober() {
    local tag=${1:?}
    local prefix
    prefix=$(prober_prefix)
    docker exec "$HR" sh -c 'kill -TERM "$(cat "/tmp/$1-prober-$2.pid")" 2>/dev/null' _ "$prefix" "$tag" || true
    sleep 1
}

prober_max_gap_ms() {
    local tag=${1:?}
    local max_gap prefix
    prefix=$(prober_prefix)
    max_gap=$(docker exec "$HR" cat "/tmp/${prefix}-prober-${tag}.log" 2>/dev/null \
        | grep 'bytes from' \
        | grep -oE 'icmp_seq=[0-9]+' | cut -d= -f2 \
        | awk 'NR>1 && $1>prev+1 { g=$1-prev-1; if (g>max) max=g } { prev=$1 } END { print max+0 }' || true)
    echo $(( ${max_gap:-0} * PROBE_INTERVAL_MS ))
}

# ---------------------------------------------------------------------------
# Test summary
# ---------------------------------------------------------------------------

print_summary() {
    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Trap-based cleanup
# ---------------------------------------------------------------------------
# Auto-destroy the containerlab topology on script exit (success, fail,
# CTRL-C, hup) when CLEANUP=1. Default off so a developer iterating on a
# failing script can poke at the live containers; flip on for CI.
#
# `_clab_topology_file` is resolved against the standard tests/interop
# layout — sourced scripts live in tests/interop/scripts/, the .clab.yml
# is in tests/interop/${TOPO}.clab.yml.

_clab_topology_file() {
    printf "%s/../%s.clab.yml" "$SCRIPT_DIR" "$TOPO"
}

_cleanup_on_exit() {
    local exit_code=$?
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

trap _cleanup_on_exit EXIT INT TERM HUP

# ---------------------------------------------------------------------------
# Run pre-flight on source
# ---------------------------------------------------------------------------

preflight
