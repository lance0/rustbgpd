#!/usr/bin/env bash
# Two fresh, sequential IRR-scale runs of the RFC 9069 Loc-RIB dump/live
# buffer receipt. This is a correctness/capacity-boundary receipt, not a
# throughput benchmark or a general capacity claim.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
GEN="$REPO/bench/scale/reloadstall/gen-irr-scenario.py"
HARNESS="$REPO/bench/scale/reloadstall/target/release/reloadstall"
SINK="$REPO/bench/scale/irrreload/bmp-loc-rib-sink.py"
VERIFY="$REPO/bench/scale/irrreload/verify-bmp-buffer-receipt.py"
DAEMON="$REPO/target/release/rustbgpd"
RENDER="$REPO/target/release/rs-config-render"
ART="${ARTIFACTS_DIR:-/tmp/bmp-buffer-receipt}"

N_MEMBERS=320
TOTAL_PREFIXES=183040
SEED=61
EXPECTED_FILTER_ENTRIES=3218965
CHURN_PEERS=8
CHURN_PREFIXES=16
CHURN_INTERVAL_MS=125
BGP_PORT=1790
BMP_COLLECTOR=127.0.0.1:11019
METRICS_PORT=9179
METRICS_URL=http://127.0.0.1:$METRICS_PORT/metrics
TIMEOUT_SECONDS=600

if [ "${DRY_RUN_PROTOCOL:-}" = 1 ]; then
    echo "members=$N_MEMBERS prefixes=$TOTAL_PREFIXES seed=$SEED filter_entries=$EXPECTED_FILTER_ENTRIES"
    echo "churn=${CHURN_PEERS}x${CHURN_PREFIXES}/${CHURN_INTERVAL_MS}ms collector=$BMP_COLLECTOR runs=2 timeout=${TIMEOUT_SECONDS}s"
    echo "frame_max=1048576 capture_max=1073741824 live_buffer_cap=8192"
    exit 0
fi

for tool in cargo curl flock git grep jq python3 setsid sha256sum ss timeout; do
    command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done

cd "$REPO"
if [ -n "$(git status --porcelain)" ]; then
    echo "full receipt requires a clean worktree" >&2
    exit 2
fi
HEAD=$(git rev-parse HEAD)
[ "$HEAD" = "$(git rev-parse origin/main)" ] || {
    echo "full receipt requires HEAD exactly at origin/main" >&2
    exit 2
}
[ ! -e "$ART" ] || { echo "artifact root already exists: $ART" >&2; exit 2; }

CONFIRM_BENCH_CRON_PAUSED="${CONFIRM_BENCH_CRON_PAUSED:-}" \
CONFIRM_NO_MAIN_PUSHES="${CONFIRM_NO_MAIN_PUSHES:-}" \
SKIP_BUILD_CHECK=1 tests/soak/preflight.sh
HOST_LOCK="${RUSTBGPD_HOST_LOCK:-$HOME/.local/state/rustbgpd-host.lock}"
mkdir -p "$(dirname "$HOST_LOCK")" "$ART"
exec 9>"$HOST_LOCK"
flock -n 9 || { echo "bench/soak host lock is held" >&2; exit 2; }

cargo build --release -p rustbgpd --bin rustbgpd -p rs-config-render --bin rs-config-render
cargo build --release --manifest-path bench/scale/reloadstall/Cargo.toml --locked

ACTIVE_DAEMON="" ACTIVE_HARNESS="" ACTIVE_SINK="" ACTIVE_TMP=""
terminate_group() {
    local pid=${1:-}
    [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null || kill -TERM -- "-$pid" 2>/dev/null || true
}
cleanup() {
    terminate_group "$ACTIVE_SINK"
    terminate_group "$ACTIVE_HARNESS"
    terminate_group "$ACTIVE_DAEMON"
    [ -z "$ACTIVE_TMP" ] || rm -rf "$ACTIVE_TMP"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_file() {
    local file=$1 owner=$2 deadline=$((SECONDS + TIMEOUT_SECONDS))
    while [ ! -f "$file" ]; do
        kill -0 "$owner" 2>/dev/null || return 1
        [ "$SECONDS" -lt "$deadline" ] || return 1
        sleep 1
    done
}

require_ports_free() {
    local port
    for port in "$BGP_PORT" "${BMP_COLLECTOR##*:}" "$METRICS_PORT"; do
        if ss -H -ltn "sport = :$port" | grep -q .; then
            echo "required TCP port is already listening: $port" >&2
            return 1
        fi
    done
}

run_once() {
    local out="$ART/run-$1" run="/tmp/bmpbuf-$1-$$"
    local pre="$run/pre-churn" final="$run/final" sink_start="$run/sink-start" sink_stop="$run/sink-stop"
    ACTIVE_TMP=$run
    require_ports_free
    rm -rf -- "$run" || return 1
    mkdir -p "$out" || return 1
    mkdir -m 0700 -- "$run" || return 1
    python3 "$GEN" rustbgpd "$N_MEMBERS" "$TOTAL_PREFIXES" "$run" \
        --seed "$SEED" --min-list 1000 --max-list 40000 \
        --changed-fraction 0.1 --port "$BGP_PORT" --render-bin "$RENDER" \
        --path-hiding true --admit-churn true --bmp-collector "$BMP_COLLECTOR"
    jq -e --argjson entries "$EXPECTED_FILTER_ENTRIES" --arg collector "$BMP_COLLECTOR" \
        '.n_members == 320 and .total_prefixes == 183040 and .seed == 61
         and .total_filter_entries == $entries and .bmp_collector == $collector
         and .bmp_version == 3 and .bmp_view == "loc_rib"' \
        "$run/manifest.json" >/dev/null
    (cd "$run" && { jq -r '.runtime_files[]' manifest.json; echo manifest.json; } | sort | xargs sha256sum) >"$out/scenario.sha256"

    setsid "$DAEMON" "$run/config.toml" >"$out/daemon.log" 2>&1 &
    local daemon_pid=$!
    ACTIVE_DAEMON=$daemon_pid
    local deadline=$((SECONDS + TIMEOUT_SECONDS))
    until curl -fsS --max-time 2 "$METRICS_URL" >/dev/null 2>&1; do
        kill -0 "$daemon_pid" 2>/dev/null || return 1
        [ "$SECONDS" -lt "$deadline" ] || return 1
        sleep 1
    done
    local daemon_start
    daemon_start=$(awk '{print $22}' "/proc/$daemon_pid/stat")

    setsid env RELOADSTALL_PRE_CHURN_EVIDENCE_DIR="$pre" RELOADSTALL_EVIDENCE_DIR="$final" \
        timeout "$TIMEOUT_SECONDS" "$HARNESS" "$N_MEMBERS" "$TOTAL_PREFIXES" "$BGP_PORT" \
        "$daemon_pid" "$run/member.rpol" "$run/gen-a.rpol" "$run/gen-b.rpol" 0 1 \
        >"$out/reloadstall.log" 2>&1 &
    local harness_pid=$!
    ACTIVE_HARNESS=$harness_pid
    wait_file "$pre/ready" "$harness_pid" || return 1

    setsid python3 "$SINK" --listen "$BMP_COLLECTOR" --output-dir "$run/sink" \
        --start-file "$sink_start" --stop-file "$sink_stop" \
        --total-prefixes "$TOTAL_PREFIXES" --timeout "$TIMEOUT_SECONDS" \
        >"$out/sink.log" 2>&1 &
    local sink_pid=$!
    ACTIVE_SINK=$sink_pid
    wait_file "$run/sink/listening" "$sink_pid" || return 1
    wait_file "$run/sink/accepted" "$sink_pid" || return 1
    printf 'ack\n' >"$pre/ack"
    sleep 0.2
    printf 'start\n' >"$sink_start"

    wait_file "$final/ready" "$harness_pid" || return 1
    wait_file "$run/sink/ready" "$sink_pid" || return 1
    local outcome generation_open=false
    outcome=$(cat "$run/sink/ready")
    if [ "$outcome" = complete ]; then
        kill -0 "$sink_pid"
        [ -f "$run/sink/generation-open" ]
        generation_open=true
    elif [ "$outcome" = overflow ]; then
        [ ! -f "$run/sink/generation-open" ]
    else
        echo "unknown sink outcome: $outcome" >&2
        return 1
    fi
    curl -fsS --max-time 5 "$METRICS_URL" >"$out/metrics.prom"
    cp "$run/manifest.json" "$out/manifest.json"
    cp "$run/sink/summary.json" "$out/summary.json"
    jq -n --arg outcome "$outcome" --arg collector "$BMP_COLLECTOR" \
        --arg commit "$HEAD" --argjson pid "$daemon_pid" --argjson start "$daemon_start" \
        --argjson open "$generation_open" --argjson timeout "$TIMEOUT_SECONDS" \
        '{outcome:$outcome,collector:$collector,commit:$commit,daemon_pid:$pid,
          daemon_start_ticks:$start,generation_open_at_scrape:$open,timeout_seconds:$timeout}' \
        >"$out/receipt.json"

    [ "$outcome" != complete ] || printf 'stop\n' >"$sink_stop"
    wait "$sink_pid"
    ACTIVE_SINK=""
    printf 'ack\n' >"$final/ack"
    wait "$harness_pid"
    ACTIVE_HARNESS=""
    terminate_group "$daemon_pid"
    wait "$daemon_pid" || true
    ACTIVE_DAEMON=""
    rm -rf "$run"
    ACTIVE_TMP=""
}

jq -n --arg commit "$HEAD" \
    '{schema:1,commit:$commit,runs:["run-a","run-b"],order:"fresh-sequential"}' \
    >"$ART/provenance.json"
run_once a
run_once b
python3 "$VERIFY" verify --allow-unsealed "$ART" >"$ART/verification.json"
printf 'pass\n' >"$ART/COMPLETED"
(cd "$ART" && find . -type f ! -name SHA256SUMS -printf '%P\0' | sort -z | xargs -0 sha256sum) >"$ART/SHA256SUMS"
chmod -R a-w "$ART"
python3 "$VERIFY" verify "$ART" >/dev/null
echo "sealed BMP buffer receipt: $ART"
