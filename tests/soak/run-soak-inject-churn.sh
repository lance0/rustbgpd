#!/usr/bin/env bash
# Soak: gRPC route-injection churn (automation-controller beachhead).
#
# Drives `InjectionService.AddPath` / `DeletePath` over gRPC at a
# sustained add/delete rate, proving the controller-injection path
# (the automation-controller beachhead) does not leak under
# steady-state churn. Uses `rbgp rib add` / `rbgp rib delete` from
# inside the rustbgpd container.
#
# Prerequisites:
#   docker build -t rustbgpd:dev .
#   containerlab deploy -t tests/soak/soak-inject-churn.clab.yml
#
# Usage:
#   SOAK_SECONDS=600 bash tests/soak/run-soak-inject-churn.sh   # 10-min smoke
#   SOAK_HOURS=24  bash tests/soak/run-soak-inject-churn.sh     # 24h
#   bash tests/soak/run-soak-inject-churn.sh                    # 24h default
#
# Lease mode (LEASE_MODE=1, off by default) adds ADR-0141 owner leases
# beside the unowned churn. LEASE_OWNERS controllers each hold
# LEASE_KEYS_PER_OWNER leased /32s (owner k uses 172.(15+k).0.0/16) under a
# LEASE_SECONDS lease and renew every LEASE_RENEW_SEC. The last owner
# flaps: every LEASE_FLAP_INTERVAL_SEC it stops renewing, waits for FRR to
# lose its keys and re-adds under a new generation; a renewal at the old
# generation must be refused both before and after the re-add. The controllers call AddLeasedPath,
# RenewLease and ListInjectionLeases with grpcurl over the lab's gRPC TCP
# listener, using the shared public test-only token, and a 1 Hz prober
# records /readyz. Requires grpcurl and jq on the host.
#
# Output: tests/soak/runs/soak-inject-churn-<UTC>/
#   - samples.csv      one row per sample interval
#   - soak.log         harness stdout/stderr
#   - churn.log        per-cycle add/delete log
#   - rustbgpd.log     rustbgpd daemon log copied from inside the container
#   - run.json         run metadata
#   - lease-events.log     (lease mode) controller adds, renewals and flap cycles
#   - lease-samples.jsonl  (lease mode) per-sample FRR counts per owner + lease table
#   - readyz.csv           (lease mode) 1 Hz /readyz status and latency

set -euo pipefail

SOAK_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SOAK_SCRIPT_DIR/../.." && pwd)"
TOPOLOGY="${TOPOLOGY:-$REPO_ROOT/tests/soak/soak-inject-churn.clab.yml}"

SOAK_HOURS="${SOAK_HOURS:-24}"
SOAK_SECONDS="${SOAK_SECONDS:-$((SOAK_HOURS * 3600))}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-60}"
CHURN_INTERVAL_SEC="${CHURN_INTERVAL_SEC:-5}"
CHURN_BATCH="${CHURN_BATCH:-25}"
PREFIX_POOL_SIZE="${PREFIX_POOL_SIZE:-4096}"
LIVE_TARGET_PREFIXES="${LIVE_TARGET_PREFIXES:-1024}"
WARMUP_SEC="${WARMUP_SEC:-120}"
CLEANUP="${CLEANUP:-0}"

TOPO="${TOPO:-soak-inject-churn}"
RUSTBGPD="${RUSTBGPD:-clab-${TOPO}-rustbgpd}"
FRR="${FRR:-clab-${TOPO}-frr}"
RUSTBGPD_IP="${RUSTBGPD_IP:-10.0.0.1}"
FRR_IP="${FRR_IP:-10.0.0.2}"
# Default UDS socket: owner-only, so the in-container rbgp calls
# authorize as the implicit local-operator under tier enforcement.
GRPC_ADDR="${GRPC_ADDR:-unix:///var/lib/rustbgpd/grpc.sock}"
NEXTHOP="${NEXTHOP:-10.0.0.1}"

LEASE_MODE="${LEASE_MODE:-0}"
LEASE_OWNERS="${LEASE_OWNERS:-4}"
LEASE_KEYS_PER_OWNER="${LEASE_KEYS_PER_OWNER:-512}"
LEASE_SECONDS="${LEASE_SECONDS:-30}"
LEASE_RENEW_SEC="${LEASE_RENEW_SEC:-10}"
LEASE_FLAP_INTERVAL_SEC="${LEASE_FLAP_INTERVAL_SEC:-600}"
LEASE_TOKEN_FILE="${LEASE_TOKEN_FILE:-$REPO_ROOT/tests/fixtures/grpc-test-only-operator.token}"
LEASE_GRPC_ADDR=""
LEASE_PIDS=()

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${RUN_DIR_OVERRIDE:-$SOAK_SCRIPT_DIR/runs/soak-inject-churn-$RUN_ID}"

SAMPLES_CSV="$RUN_DIR/samples.csv"
SOAK_LOG="$RUN_DIR/soak.log"
CHURN_LOG="$RUN_DIR/churn.log"
RUN_JSON="$RUN_DIR/run.json"
RUSTBGPD_LOG="$RUN_DIR/rustbgpd.log"
LIVE_SET_FILE="$RUN_DIR/live-prefix-indexes.txt"
LEASE_EVENTS="$RUN_DIR/lease-events.log"
LEASE_SAMPLES="$RUN_DIR/lease-samples.jsonl"
READYZ_CSV="$RUN_DIR/readyz.csv"
LEASE_STOP_FILE="$RUN_DIR/lease-stop"

# shellcheck source=tests/soak/host-lock.sh
source "$SOAK_SCRIPT_DIR/host-lock.sh"
# shellcheck source=tests/interop/scripts/source-id-guard.sh
source "$REPO_ROOT/tests/interop/scripts/source-id-guard.sh"

log() {
    printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

churn_log() {
    printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$CHURN_LOG"
}

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log "ERROR: required tool '$1' not in PATH"
        exit 2
    fi
}

require_container() {
    if ! docker inspect "$1" >/dev/null 2>&1; then
        log "ERROR: container '$1' not found; deploy $TOPOLOGY first"
        exit 2
    fi
}

daemon_running() {
    docker exec "$RUSTBGPD" sh -c 'cat /proc/[0-9]*/comm 2>/dev/null' \
        | grep -qx rustbgpd
}

# The soak topology launches the container with `cmd: sleep infinity`;
# start the daemon explicitly. Idempotent so a re-run against a live
# topology does not double-start it.
ensure_daemon_running() {
    if daemon_running; then
        return 0
    fi
    log "rustbgpd not running in $RUSTBGPD; starting"
    # Redirect into the file the log stream tails: a detached exec's
    # stdout is otherwise discarded and rustbgpd.log stays empty.
    docker exec -d "$RUSTBGPD" sh -c \
        '/usr/local/bin/start-rustbgpd.sh >>/var/log/rustbgpd.log 2>&1'
    for _ in $(seq 1 10); do
        if daemon_running; then
            return 0
        fi
        sleep 1
    done
    log "ERROR: rustbgpd failed to start within 10s"
    return 1
}

format_prefix() {
    local n=${1:?}
    # 10.<high>.<low>.0/24 — unique /24s from the pool index.
    printf '10.%d.%d.0/24' $(((n >> 8) & 255)) $((n & 255))
}

wrap_index() {
    local value=${1:?}
    if [ "$value" -gt "$PREFIX_POOL_SIZE" ]; then
        value=1
    fi
    printf '%s\n' "$value"
}

rb_inject_add() {
    local prefix=${1:?}
    docker exec "$RUSTBGPD" rbgp -s "$GRPC_ADDR" rib add "$prefix" \
        --nexthop "$NEXTHOP" >/dev/null
}

rb_inject_del() {
    local prefix=${1:?}
    docker exec "$RUSTBGPD" rbgp -s "$GRPC_ADDR" rib delete "$prefix" \
        >/dev/null
}

frr_vtysh() {
    docker exec "$FRR" vtysh -c "$1"
}

frr_established_seen() {
    frr_vtysh "show bgp neighbors $RUSTBGPD_IP json" \
        | grep -q '"bgpState":"Established"'
}

wait_established() {
    log "Waiting for BGP session to reach Established..."
    for i in $(seq 1 90); do
        if frr_established_seen; then
            log "BGP session established after ${i}s"
            return 0
        fi
        sleep 1
    done
    log "ERROR: BGP session did not reach Established within 90s"
    return 1
}

prom_scrape() {
    local ip
    ip=$(docker inspect --format \
        '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' \
        "$RUSTBGPD" 2>/dev/null | awk '{print $1}')
    [ -z "$ip" ] && return 0
    curl -sfm 5 "http://${ip}:9179/metrics" 2>/dev/null || true
}

prom_extract_required() {
    local text="$1" metric="$2"
    printf '%s' "$text" | awk -v m="$metric" '
        $0 ~ "^"m"( |\\{)" { print $NF; found=1; exit }
        END { if (!found) { print "nan" } }
    '
}

# Sum all per-peer series of a labeled gauge from a scraped /metrics blob.
prom_extract_sum() {
    local prom="$1" name="$2"
    awk -v n="$name" '
        $0 ~ "^"n"[{ ]" { s += $NF; found=1 }
        END { if (!found) print "nan"; else printf "%d", s }
    ' <<<"$prom"
}

container_rss_mb() {
    docker exec "$RUSTBGPD" sh -c '
        pid=$(pidof rustbgpd 2>/dev/null || true)
        if [ -n "$pid" ] && [ -r "/proc/$pid/status" ]; then
            awk "/^VmRSS:/ { printf \"%.3f\", \$2 / 1024.0 }" "/proc/$pid/status"
        fi
    ' 2>/dev/null || true
}

# Unowned churn routes only: the lease-mode pool (172.16.0.0/12) is
# counted per owner by lease_frr_count.
frr_route_count() {
    frr_vtysh "show bgp ipv4 unicast json" |
        python3 -c 'import ipaddress,json,sys
d=json.load(sys.stdin)
r=d.get("routes")
if not isinstance(r, dict): raise SystemExit(2)
pool=ipaddress.ip_network("172.16.0.0/12")
print(sum(1 for p in r if not ipaddress.ip_network(p).subnet_of(pool)))'
}

run_analyzer() {
    python3 "$SOAK_SCRIPT_DIR/analyze-soak-inject-churn.py" "$RUN_DIR" --output "$RUN_DIR/verdict.json"
}

neighbor_state() {
    docker exec "$RUSTBGPD" rbgp -s "$GRPC_ADDR" neighbor -j |
        python3 -c 'import json,sys; n=json.load(sys.stdin)[0]; print(n["flap_count"], n["uptime_seconds"])'
}

wait_final_routes() {
    local count
    for _ in $(seq 1 30); do
        count=$(frr_route_count)
        [ "$count" -eq "$LIVE_TARGET_PREFIXES" ] && return 0
        sleep 1
    done
    log "ERROR: FRR route count ${count:-unknown}, expected $LIVE_TARGET_PREFIXES"
    return 1
}

write_run_json() {
    {
        echo "{"
        printf '  "run_id": "%s",\n' "$RUN_ID"
        printf '  "git_head": "%s",\n' "$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
        printf '  "soak_seconds": %d,\n' "$SOAK_SECONDS"
        printf '  "sample_interval_sec": %d,\n' "$SAMPLE_INTERVAL"
        printf '  "churn_interval_sec": %d,\n' "$CHURN_INTERVAL_SEC"
        printf '  "churn_batch": %d,\n' "$CHURN_BATCH"
        printf '  "prefix_pool_size": %d,\n' "$PREFIX_POOL_SIZE"
        printf '  "live_target_prefixes": %d,\n' "$LIVE_TARGET_PREFIXES"
        printf '  "warmup_sec": %d,\n' "$WARMUP_SEC"
        printf '  "lease_mode": %d,\n' "$LEASE_MODE"
        printf '  "lease_owners": %d,\n' "$LEASE_OWNERS"
        printf '  "lease_keys_per_owner": %d,\n' "$LEASE_KEYS_PER_OWNER"
        printf '  "lease_seconds": %d,\n' "$LEASE_SECONDS"
        printf '  "lease_renew_sec": %d,\n' "$LEASE_RENEW_SEC"
        printf '  "lease_flap_interval_sec": %d,\n' "$LEASE_FLAP_INTERVAL_SEC"
        printf '  "rustbgpd_container": "%s",\n' "$RUSTBGPD"
        printf '  "frr_container": "%s",\n' "$FRR"
        printf '  "topology": "%s"\n' "$TOPOLOGY"
        echo "}"
    } >"$RUN_JSON"
}

start_log_stream() {
    docker exec "$RUSTBGPD" sh -c \
        'touch /var/log/rustbgpd.log; tail -n +1 -F /var/log/rustbgpd.log' \
        >"$RUSTBGPD_LOG" 2>&1 &
    RUST_LOG_PID=$!
}

stop_log_stream() {
    if [ "${RUST_LOG_PID:-}" ]; then
        kill "$RUST_LOG_PID" 2>/dev/null || true
        wait "$RUST_LOG_PID" 2>/dev/null || true
    fi
}

drain_live_prefixes() {
    if [ ! -s "$LIVE_SET_FILE" ]; then
        return 0
    fi
    log "Draining remaining injected prefixes"
    while IFS= read -r idx; do
        [ -z "$idx" ] && continue
        rb_inject_del "$(format_prefix "$idx")"
    done <"$LIVE_SET_FILE"
    : >"$LIVE_SET_FILE"
}

cleanup() {
    local exit_code=$?
    set +e
    stop_lease_controllers
    drain_live_prefixes
    stop_log_stream
    if [ "$CLEANUP" = "1" ]; then
        log "Destroying containerlab topology"
        containerlab destroy -t "$TOPOLOGY" --cleanup >/dev/null 2>&1 || true
    fi
    exit "$exit_code"
}

validate_config() {
    if [ "$PREFIX_POOL_SIZE" -le "$LIVE_TARGET_PREFIXES" ]; then
        log "ERROR: PREFIX_POOL_SIZE must be greater than LIVE_TARGET_PREFIXES"
        exit 2
    fi
    if [ "$CHURN_BATCH" -le 0 ] || [ "$LIVE_TARGET_PREFIXES" -le 0 ]; then
        log "ERROR: CHURN_BATCH and LIVE_TARGET_PREFIXES must be positive"
        exit 2
    fi
    if [ "$CHURN_BATCH" -gt "$LIVE_TARGET_PREFIXES" ]; then
        log "ERROR: CHURN_BATCH must not exceed LIVE_TARGET_PREFIXES"
        exit 2
    fi
    local pool_headroom=$((PREFIX_POOL_SIZE - LIVE_TARGET_PREFIXES))
    if [ "$pool_headroom" -lt "$CHURN_BATCH" ]; then
        log "ERROR: PREFIX_POOL_SIZE - LIVE_TARGET_PREFIXES must be at least CHURN_BATCH"
        exit 2
    fi
    case "$LEASE_MODE" in
        0) return 0 ;;
        1) ;;
        *) log "ERROR: LEASE_MODE must be 0 or 1"; exit 2 ;;
    esac
    # Owners map to 172.16-31.x.x (disjoint from the 10.x churn pool); the
    # daemon allows 16,384 keys per owner and leases of 5..=3600 s.
    if [ "$LEASE_OWNERS" -lt 2 ] || [ "$LEASE_OWNERS" -gt 16 ] \
        || [ "$LEASE_KEYS_PER_OWNER" -lt 1 ] || [ "$LEASE_KEYS_PER_OWNER" -gt 16384 ] \
        || [ "$LEASE_SECONDS" -lt 5 ] || [ "$LEASE_SECONDS" -gt 3600 ] \
        || [ "$LEASE_RENEW_SEC" -lt 1 ] || [ $((2 * LEASE_RENEW_SEC)) -ge "$LEASE_SECONDS" ] \
        || [ "$LEASE_FLAP_INTERVAL_SEC" -le "$LEASE_SECONDS" ]; then
        log "ERROR: lease mode needs 2-16 owners, 1-16384 keys each, a 5-3600 s lease," \
            "renewal under half the lease and a flap interval above the lease"
        exit 2
    fi
}

lease_owner() {
    printf 'soak-lease-%d' "${1:?}"
}

lease_prefix_addr() {
    local k=${1:?} i=${2:?}
    printf '172.%d.%d.%d' $((15 + k)) $(((i >> 8) & 255)) $((i & 255))
}

lease_event() {
    printf '%s %s\n' "$(date +%s.%N)" "$*" >>"$LEASE_EVENTS"
}

# grpcurl against the lab's TCP listener with the shared test-only token,
# the same controller shape as tests/interop/scripts/test-m22-lease-expiry.sh.
lease_grpc() {
    local method=${1:?} token=""
    shift
    IFS= read -r token <"$LEASE_TOKEN_FILE"
    [ -n "$token" ] || return 1
    grpcurl -plaintext -import-path "$REPO_ROOT" -proto proto/rustbgpd.proto \
        -H "authorization: Bearer $token" "$@" "$LEASE_GRPC_ADDR" \
        "rustbgpd.v1.InjectionService/$method"
}

# "<incarnation>:<sequence>" of the generation in a response on stdin.
lease_gen_of() {
    jq -er '.generation | "\(.incarnation // "0"):\(.sequence // "0")"'
}

# Add every key of owner $1 under its lease. Sets LEASE_GEN from the last
# add and LEASE_OK_T0/T1 to the bracket around it; any failure fails.
lease_add_all() {
    local k=${1:?} owner i out t0
    owner=$(lease_owner "$k")
    for ((i = 0; i < LEASE_KEYS_PER_OWNER; i++)); do
        t0=$(date +%s.%N)
        if ! out=$(lease_grpc AddLeasedPath -d "{\"path\": {\"prefix\": \"$(lease_prefix_addr "$k" "$i")\", \"prefixLength\": 32, \"nextHop\": \"$NEXTHOP\"}, \"lease\": {\"owner\": \"$owner\", \"leaseSeconds\": $LEASE_SECONDS}}" 2>&1); then
            lease_event "$owner add_failed $(tr '\n' ' ' <<<"$out")"
            return 1
        fi
    done
    LEASE_OK_T1=$(date +%s.%N)
    LEASE_OK_T0=$t0
    if ! LEASE_GEN=$(lease_gen_of <<<"$out"); then
        lease_event "$owner add_failed unparsable generation"
        return 1
    fi
    lease_event "$owner added gen=$LEASE_GEN"
}

# One RenewLease for owner $1 at generation $2 ("inc:seq"); prints
# renewed, refused (FAILED_PRECONDITION) or error.
lease_renew() {
    local owner=${1:?} gen=${2:?} out
    if out=$(lease_grpc RenewLease -d "{\"owner\": \"$owner\", \"generation\": {\"incarnation\": \"${gen%%:*}\", \"sequence\": \"${gen##*:}\"}, \"leaseSeconds\": $LEASE_SECONDS}" 2>&1); then
        echo renewed
    elif grep -q FailedPrecondition <<<"$out"; then
        echo refused
    else
        echo "error $(tr '\n' ' ' <<<"$out")"
    fi
}

# FRR's count of owner $1's /32s.
lease_frr_count() {
    frr_vtysh "show bgp ipv4 unicast 172.$((15 + ${1:?})).0.0/16 longer-prefixes json" 2>/dev/null |
        python3 -c 'import json,sys
d=json.load(sys.stdin)
r=d.get("routes", {})
if not isinstance(r, dict): raise SystemExit(2)
print(len(r))'
}

# Wait (polling twice a second) until FRR holds exactly $2 of owner $1's
# keys or $3 epoch seconds pass; prints the first observation time of each
# fewer-than-full count as "drop=<t>" and of the target as "at=<t>".
lease_wait_frr() {
    local k=${1:?} want=${2:?} limit=${3:?} count drop=""
    while [ "$(date +%s)" -le "$limit" ]; do
        count=$(lease_frr_count "$k") || count=""
        if [ -n "$count" ]; then
            if [ -z "$drop" ] && [ "$count" -lt "$LEASE_KEYS_PER_OWNER" ]; then
                drop=$(date +%s.%N)
            fi
            if [ "$count" -eq "$want" ]; then
                printf 'drop=%s at=%s\n' "${drop:-none}" "$(date +%s.%N)"
                return 0
            fi
        fi
        sleep 0.5
    done
    printf 'drop=%s timeout\n' "${drop:-none}"
    return 1
}

# Stop renewing owner $1 (generation $2) and observe its expiry at FRR.
# Renewing the old generation must be refused both once it has expired
# (no resurrection) and once the re-add has superseded it (the generation
# check itself).
lease_flap_cycle() {
    local k=${1:?} gen=${2:?} owner seen
    owner=$(lease_owner "$k")
    lease_event "$owner flap_stop gen=$gen t0=$LEASE_OK_T0 t1=$LEASE_OK_T1"
    seen=$(lease_wait_frr "$k" 0 $((${LEASE_OK_T1%.*} + LEASE_SECONDS + 30))) || true
    lease_event "$owner frr_gone $seen"
    lease_event "$owner stale_renew $(lease_renew "$owner" "$gen") phase=expired"
    lease_add_all "$k" || return 1
    lease_event "$owner stale_renew $(lease_renew "$owner" "$gen") phase=superseded"
    seen=$(lease_wait_frr "$k" "$LEASE_KEYS_PER_OWNER" $(($(date +%s) + 60))) || true
    lease_event "$owner frr_back $seen"
}

# One owner's controller. The last owner flaps; every owner re-adds its
# full state when a renewal is refused, as a real controller must.
lease_owner_loop() {
    local k=${1:?} owner gen t0 result next_flap=""
    owner=$(lease_owner "$k")
    lease_add_all "$k" || return 1
    gen=$LEASE_GEN
    if [ "$k" -eq "$LEASE_OWNERS" ]; then
        next_flap=$(($(date +%s) + LEASE_FLAP_INTERVAL_SEC))
    fi
    while [ ! -e "$LEASE_STOP_FILE" ]; do
        if [ -n "$next_flap" ] && [ "$(date +%s)" -ge "$next_flap" ]; then
            lease_flap_cycle "$k" "$gen" || return 1
            gen=$LEASE_GEN
            next_flap=$(($(date +%s) + LEASE_FLAP_INTERVAL_SEC))
            continue
        fi
        t0=$(date +%s.%N)
        result=$(lease_renew "$owner" "$gen")
        lease_event "$owner renew $result"
        case "$result" in
            renewed) LEASE_OK_T0=$t0; LEASE_OK_T1=$(date +%s.%N) ;;
            refused) lease_add_all "$k" || return 1; gen=$LEASE_GEN ;;
        esac
        sleep "$LEASE_RENEW_SEC"
    done
}

readyz_probe_loop() {
    local url="http://${1:?}:9179/readyz"
    while [ ! -e "$LEASE_STOP_FILE" ]; do
        printf '%s,%s\n' "$(date +%s)" \
            "$(curl -s -o /dev/null -m 5 -w '%{http_code},%{time_total}' "$url" || true)" \
            >>"$READYZ_CSV"
        sleep 1
    done
}

start_lease_controllers() {
    local ip k
    ip=$(docker inspect --format \
        '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' \
        "$RUSTBGPD" | awk '{print $1}')
    [ -n "$ip" ] || { log "ERROR: no management IP for $RUSTBGPD"; return 1; }
    LEASE_GRPC_ADDR="$ip:50051"
    rm -f "$LEASE_STOP_FILE"
    : >"$LEASE_EVENTS"
    echo "epoch,code,seconds" >"$READYZ_CSV"
    readyz_probe_loop "$ip" &
    LEASE_PIDS+=("$!")
    for ((k = 1; k <= LEASE_OWNERS; k++)); do
        lease_owner_loop "$k" &
        LEASE_PIDS+=("$!")
        lease_event "$(lease_owner "$k") controller_start pid=$!"
    done
    log "Lease controllers started: $LEASE_OWNERS owners x $LEASE_KEYS_PER_OWNER keys via $LEASE_GRPC_ADDR"
}

wait_lease_adds() {
    local added
    for _ in $(seq 1 600); do
        added=$(grep -c ' added gen=' "$LEASE_EVENTS" || true)
        [ "$added" -ge "$LEASE_OWNERS" ] && return 0
        if grep -q ' add_failed ' "$LEASE_EVENTS"; then
            break
        fi
        sleep 1
    done
    log "ERROR: lease owners did not finish their initial adds"
    return 1
}

# Stop the controllers between cycles and record each exit status; the
# analyzer requires every controller to exit 0.
stop_lease_controllers() {
    local pid rc k=0
    [ "${#LEASE_PIDS[@]}" -gt 0 ] || return 0
    touch "$LEASE_STOP_FILE"
    for pid in "${LEASE_PIDS[@]}"; do
        rc=0
        wait "$pid" || rc=$?
        if [ "$k" -gt 0 ]; then
            lease_event "$(lease_owner "$k") controller_exit rc=$rc"
        fi
        k=$((k + 1))
    done
    LEASE_PIDS=()
}

lease_sample_row() {
    local elapsed=${1:?} k count leases counts=()
    for ((k = 1; k <= LEASE_OWNERS; k++)); do
        count=$(lease_frr_count "$k")
        counts+=("$count")
    done
    leases=$(lease_grpc ListInjectionLeases -d '{}')
    python3 -c 'import json,sys
print(json.dumps({"elapsed_sec": int(sys.argv[1]),
                  "frr_counts": [int(c) for c in sys.argv[2:]],
                  "leases": json.load(sys.stdin).get("leases", [])}))' \
        "$elapsed" "${counts[@]}" <<<"$leases" >>"$LEASE_SAMPLES"
}

prefill_live_set() {
    : >"$LIVE_SET_FILE"
    log "Prefilling $LIVE_TARGET_PREFIXES injected prefixes"
    local idx
    for idx in $(seq 1 "$LIVE_TARGET_PREFIXES"); do
        rb_inject_add "$(format_prefix "$idx")"
        printf '%s\n' "$idx" >>"$LIVE_SET_FILE"
    done
}

sample_row() {
    local elapsed=${1:?}
    local cycles=${2:?}
    local add_total=${3:?}
    local del_total=${4:?}
    local prom rss frr_count established intern_size flap_count uptime_seconds
    prom=$(prom_scrape) || prom=""
    rss=$(container_rss_mb)
    frr_count=$(frr_route_count)
    if frr_established_seen; then
        established=1
    else
        established=0
    fi
    intern_size=$(prom_extract_sum "$prom" bgp_rib_attr_intern_global_size)
    local neighbor
    neighbor=$(neighbor_state)
    read -r flap_count uptime_seconds <<<"$neighbor"
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        "$elapsed" \
        "${rss:-nan}" \
        "$intern_size" \
        "$LIVE_TARGET_PREFIXES" \
        "$frr_count" \
        "$established" \
        "$cycles" \
        "$add_total" \
        "$del_total" \
        "$flap_count" \
        "$uptime_seconds" \
        >>"$SAMPLES_CSV"
}

run_churn_cycle() {
    local del_idx_ref=${1:?}
    local add_idx_ref=${2:?}
    local del_idx add_idx prefix i
    del_idx=$(cat "$del_idx_ref")
    add_idx=$(cat "$add_idx_ref")

    for i in $(seq 1 "$CHURN_BATCH"); do
        prefix=$(format_prefix "$del_idx")
        rb_inject_del "$prefix"
        sed -i "/^${del_idx}$/d" "$LIVE_SET_FILE"
        churn_log "del $prefix"
        del_idx=$(wrap_index $((del_idx + 1)))
    done

    for i in $(seq 1 "$CHURN_BATCH"); do
        prefix=$(format_prefix "$add_idx")
        rb_inject_add "$prefix"
        printf '%s\n' "$add_idx" >>"$LIVE_SET_FILE"
        churn_log "add $prefix"
        add_idx=$(wrap_index $((add_idx + 1)))
    done

    printf '%s\n' "$del_idx" >"$del_idx_ref"
    printf '%s\n' "$add_idx" >"$add_idx_ref"
}

main() {
    mkdir -p "$RUN_DIR"
    exec > >(tee -a "$SOAK_LOG") 2>&1
    acquire_rustbgpd_host_lock
    trap cleanup EXIT INT TERM HUP
    require_tool docker
    require_tool curl
    require_tool awk
    require_tool python3
    require_container "$RUSTBGPD"
    require_container "$FRR"
    check_lab_source_ids "$TOPO" "$RUSTBGPD" "$FRR" || exit 2
    ensure_daemon_running
    validate_config
    if [ "$LEASE_MODE" = 1 ]; then
        require_tool grpcurl
        require_tool jq
    fi

    write_run_json
    start_log_stream

    log "gRPC inject-churn soak starting"
    log "  duration: ${SOAK_SECONDS}s"
    log "  sample:   ${SAMPLE_INTERVAL}s"
    log "  churn:    ${CHURN_BATCH} del + ${CHURN_BATCH} add every ${CHURN_INTERVAL_SEC}s"
    log "  pool:     ${PREFIX_POOL_SIZE}, live target: ${LIVE_TARGET_PREFIXES}"
    log "  lease:    mode $LEASE_MODE"
    log "  output:   $RUN_DIR"

    wait_established
    if [ "$LEASE_MODE" = 1 ]; then
        start_lease_controllers
    fi
    prefill_live_set
    if [ "$LEASE_MODE" = 1 ]; then
        wait_lease_adds
    fi

    echo "timestamp,elapsed_sec,rss_mb,intern_size,live_target,frr_route_count,bgp_established,churn_cycles,add_total,del_total,flap_count,uptime_seconds" >"$SAMPLES_CSV"

    local start_epoch end_epoch next_sample next_churn cycles add_total del_total
    local del_idx_file add_idx_file now
    start_epoch=$(date +%s)
    end_epoch=$((start_epoch + SOAK_SECONDS))
    next_sample=$start_epoch
    next_churn=$((start_epoch + WARMUP_SEC))
    cycles=0
    add_total=$LIVE_TARGET_PREFIXES
    del_total=0
    del_idx_file="$RUN_DIR/next-delete-index"
    add_idx_file="$RUN_DIR/next-add-index"
    printf '1\n' >"$del_idx_file"
    printf '%s\n' "$((LIVE_TARGET_PREFIXES + 1))" >"$add_idx_file"

    sample_row 0 "$cycles" "$add_total" "$del_total"

    while [ "$(date +%s)" -lt "$end_epoch" ]; do
        now=$(date +%s)
        if [ "$now" -ge "$next_churn" ]; then
            run_churn_cycle "$del_idx_file" "$add_idx_file"
            cycles=$((cycles + 1))
            add_total=$((add_total + CHURN_BATCH))
            del_total=$((del_total + CHURN_BATCH))
            next_churn=$((now + CHURN_INTERVAL_SEC))
        fi
        if [ "$now" -ge "$next_sample" ]; then
            local elapsed=$((now - start_epoch))
            sample_row "$elapsed" "$cycles" "$add_total" "$del_total"
            if [ "$LEASE_MODE" = 1 ]; then
                lease_sample_row "$elapsed"
            fi
            next_sample=$((now + SAMPLE_INTERVAL))
        fi
        sleep 1
    done

    stop_lease_controllers
    local final_elapsed=$(( $(date +%s) - start_epoch ))
    wait_final_routes
    sample_row "$final_elapsed" "$cycles" "$add_total" "$del_total"
    log "soak loop completed; $cycles churn cycles; final samples in $SAMPLES_CSV"
    run_analyzer
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
