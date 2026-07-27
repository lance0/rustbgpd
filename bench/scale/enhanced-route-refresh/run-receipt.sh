#!/usr/bin/env bash
# Real-session one-peer x 100,000-prefix RFC 7313 inventory receipt.
set -euo pipefail

pid_running() {
    local state
    [[ -n ${1:-} ]] || return 1
    state=$(awk '{print $3}' "/proc/$1/stat" 2>/dev/null) || return 1
    [[ -n $state && $state != Z ]]
}

terminate_pid() {
    local -n slot=$1
    local pid=${slot:-}
    [[ -n $pid ]] || return 0
    if pid_running "$pid"; then
        kill -TERM "$pid" 2>/dev/null || true
        for _ in {1..30}; do
            pid_running "$pid" || break
            sleep 0.1
        done
        if pid_running "$pid"; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
    fi
    wait "$pid" 2>/dev/null || true
    slot=''
}

cleanup() {
    local rc=$?
    trap - EXIT
    terminate_pid SAMPLE_PID
    terminate_pid HARNESS_PID
    terminate_pid DAEMON_PID
    if ((SUCCESS == 0)) && [[ -d ${OUT:-} ]]; then
        printf 'status=failed\nexit_status=%s\n' "$rc" >"$OUT/result.env"
    fi
    [[ -z ${RUN:-} ]] || rm -rf "$RUN"
    exit "$rc"
}

[[ ${BASH_SOURCE[0]} == "$0" ]] || return 0
[[ $# -eq 0 ]] || { echo "usage: $0" >&2; exit 2; }
for command in awk cargo curl date find flock git grep mktemp nproc python3 \
    rustc sha256sum sort ss timeout uname xargs; do
    command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 1
    }
done

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
readonly REPO
readonly RECEIPT_DIR="$REPO/bench/scale/enhanced-route-refresh"
readonly PORT=1793 METRICS_PORT=9183 PREFIXES=100000
readonly PEER=127.1.0.1 FAMILY=ipv4_unicast
readonly LOCK="${RUSTBGPD_HOST_LOCK:-${HOME}/.local/state/rustbgpd-host.lock}"
readonly OVERALL_TIMEOUT=480
[[ -z $(git -C "$REPO" status --porcelain --untracked-files=normal) ]] || {
    echo "refusing dirty worktree (tracked or untracked files present)" >&2
    exit 2
}
mkdir -p "$(dirname "$LOCK")"
touch "$LOCK"
exec {LOCK_FD}>"$LOCK"
flock -n "$LOCK_FD" || { echo "host lock busy: $LOCK" >&2; exit 75; }

COMMIT="$(git -C "$REPO" rev-parse HEAD)"
TREE="$(git -C "$REPO" rev-parse 'HEAD^{tree}')"
OUT="$REPO/target/enhanced-route-refresh/$(date -u +%Y%m%dT%H%M%SZ)-${COMMIT:0:12}"
readonly COMMIT TREE OUT
[[ ! -e $OUT ]] || { echo "output already exists: $OUT" >&2; exit 2; }
mkdir -p "$OUT/build" "$OUT/metrics" "$OUT/memory-samples" "$OUT/phase" "$OUT/scenario"
chmod 700 "$OUT"
RUN="$(mktemp -d /tmp/rustbgpd-err.XXXXXX)"
DAEMON_PID='' HARNESS_PID='' SAMPLE_PID='' SUCCESS=0 SAMPLE_STOP=''
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

{
    printf 'commit=%s\n' "$COMMIT"
    printf 'tree=%s\n' "$TREE"
    printf 'peers=1\nprefixes_per_peer=%s\ntotal_prefixes=%s\n' "$PREFIXES" "$PREFIXES"
    printf 'peer_address=%s\nfamilies=%s\n' "$PEER" "$FAMILY"
    printf 'allocator=jemalloc\nprofile=release\n'
    printf 'rss_sample_interval_ms=25\njemalloc_sample_interval_ms=25\n'
} >"$OUT/provenance.env"
{
    rustc -vV
    cargo -V
} >"$OUT/toolchain.txt"
{
    printf 'kernel='
    uname -srvmo
    printf 'online_cpus=%s\n' "$(nproc)"
    awk -F: '/^model name/{gsub(/^[ \t]+/,"",$2); print "cpu_model=" $2; exit}' /proc/cpuinfo
    awk '/^(MemTotal|MemAvailable):/{print tolower(substr($1,1,length($1)-1)) "_kib=" $2}' /proc/meminfo
} >"$OUT/host.txt"
cat >"$OUT/commands.txt" <<'EOF'
env -u CARGO_TARGET_DIR -u RUSTFLAGS cargo build --release --locked -p rustbgpd -p rustbgpctl
env -u CARGO_TARGET_DIR -u RUSTFLAGS cargo build --release --locked --manifest-path bench/scale/enhanced-route-refresh/Cargo.toml
python3 bench/scale/enhanced-route-refresh/gen-scenario.py <runtime> 1793 9183
rustbgpd <runtime>/config.toml
enhanced-route-refresh-receipt 1793 <runtime>/evidence 100000
EOF

listeners=$(ss -H -ltn)
if awk -v a=":$PORT" -v b=":$METRICS_PORT" '
    {if (substr($4,length($4)-length(a)+1)==a ||
         substr($4,length($4)-length(b)+1)==b) used=1}
    END{exit !used}' <<<"$listeners"; then
    echo "receipt ports $PORT or $METRICS_PORT are already in use" >&2
    exit 75
fi

(cd "$REPO" && env -u CARGO_TARGET_DIR -u RUSTFLAGS \
    cargo build --release --locked -p rustbgpd -p rustbgpctl) >"$OUT/build/workspace.log" 2>&1
(cd "$REPO" && env -u CARGO_TARGET_DIR -u RUSTFLAGS \
    cargo build --release --locked --manifest-path \
    bench/scale/enhanced-route-refresh/Cargo.toml) >"$OUT/build/harness.log" 2>&1
readonly DAEMON="$REPO/target/release/rustbgpd"
readonly RBGP="$REPO/target/release/rbgp"
readonly HARNESS="$RECEIPT_DIR/target/release/enhanced-route-refresh-receipt"
sha256sum "$DAEMON" "$RBGP" "$HARNESS" >"$OUT/build/binaries.sha256"

python3 "$RECEIPT_DIR/gen-scenario.py" "$RUN" "$PORT" "$METRICS_PORT" \
    >"$OUT/scenario/generator.log"
cp "$RUN/config.toml" "$OUT/scenario/config.toml"
"$DAEMON" --check "$RUN/config.toml" >"$OUT/scenario/daemon-check.log" 2>&1
"$DAEMON" "$RUN/config.toml" >"$OUT/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in {1..200}; do
    curl -fsS --max-time 0.25 "http://127.0.0.1:${METRICS_PORT}/readyz" >/dev/null && break
    pid_running "$DAEMON_PID" || { echo "daemon exited during startup" >&2; exit 1; }
    sleep 0.05
done
curl -fsS --max-time 0.25 "http://127.0.0.1:${METRICS_PORT}/readyz" >/dev/null || {
    echo "daemon did not become ready" >&2
    exit 1
}

monotonic_now() { awk '{print $1}' /proc/uptime; }

scrape() {
    local output=$1
    curl -fsS --max-time 2 "http://127.0.0.1:${METRICS_PORT}/metrics" >"$output"
}

proc_status() {
    grep -E '^(VmRSS|VmHWM|VmPeak|VmSize)' "/proc/$DAEMON_PID/status"
}

memory_values() {
    local metrics=$1 status=$2
    python3 - "$metrics" "$status" <<'PY'
import pathlib
import re
import sys

metrics = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
status = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
names = (
    "jemalloc_allocated_bytes",
    "jemalloc_active_bytes",
    "jemalloc_resident_bytes",
    "jemalloc_mapped_bytes",
)
values = []
for name in names:
    found = re.findall(rf"^{name}\s+([0-9.eE+-]+)$", metrics, re.MULTILINE)
    if len(found) != 1 or float(found[0]) <= 0:
        raise SystemExit(f"{name}: expected one positive sample, got {found}")
    values.append(str(int(float(found[0]))))
for name in ("VmRSS", "VmHWM", "VmPeak", "VmSize"):
    found = re.findall(rf"^{name}:\s+([0-9]+)\s+kB$", status, re.MULTILINE)
    if len(found) != 1:
        raise SystemExit(f"{name}: expected one kB sample, got {found}")
    values.append(found[0])
print("\t".join(values))
PY
}

capture_boundary() {
    local phase=$1 boundary=$2
    local metrics="$OUT/metrics/${phase}-${boundary}.prom"
    local status="$OUT/phase/${phase}-${boundary}.status"
    scrape "$metrics"
    proc_status >"$status"
    printf '%s\t%s\t%s\t%s\n' "$phase" "$boundary" "$(monotonic_now)" \
        "$(memory_values "$metrics" "$status")" >>"$OUT/memory-boundaries.tsv"
}

sample_memory() {
    local phase=$1 stop=$2
    local output="$OUT/memory-samples/${phase}.tsv"
    local metrics="$RUN/${phase}.sample.prom" status="$RUN/${phase}.sample.status"
    printf 'monotonic_seconds\tjemalloc_allocated_bytes\tjemalloc_active_bytes\tjemalloc_resident_bytes\tjemalloc_mapped_bytes\tvmrss_kib\tvmhwm_kib\tvmpeak_kib\tvmsize_kib\n' \
        >"$output"
    while [[ ! -e $stop ]]; do
        if scrape "$metrics" 2>/dev/null && proc_status >"$status" 2>/dev/null; then
            printf '%s\t%s\n' "$(monotonic_now)" "$(memory_values "$metrics" "$status")" \
                >>"$output"
        fi
        sleep 0.025
    done
}

start_sampler() {
    local phase=$1
    SAMPLE_STOP="$RUN/${phase}.sample.stop"
    rm -f "$SAMPLE_STOP"
    sample_memory "$phase" "$SAMPLE_STOP" &
    SAMPLE_PID=$!
}

stop_sampler() {
    [[ -n $SAMPLE_PID ]] || return 0
    touch "$SAMPLE_STOP"
    wait "$SAMPLE_PID"
    SAMPLE_PID='' SAMPLE_STOP=''
}

wait_ready() {
    local phase=$1 timeout_seconds=$2
    local deadline=$((SECONDS + timeout_seconds))
    until [[ -e "$RUN/evidence/${phase}.ready" ]]; do
        pid_running "$HARNESS_PID" || {
            echo "harness exited before phase $phase" >&2
            exit 1
        }
        ((SECONDS < deadline)) || { echo "phase $phase ready timeout" >&2; exit 1; }
        sleep 0.025
    done
}

ack() {
    local phase=$1
    touch "$RUN/evidence/${phase}.ack"
}

validate_phase() {
    local phase=$1 timeout_seconds=$2
    local deadline=$((SECONDS + timeout_seconds))
    local candidate="$RUN/${phase}.candidate.prom"
    local error="$RUN/${phase}.error"
    local baseline="$OUT/metrics/baseline.prom"
    until ((SECONDS >= deadline)); do
        if [[ $phase == baseline ]]; then
            baseline=$candidate
        fi
        if scrape "$candidate" &&
            python3 "$RECEIPT_DIR/validate_phase.py" "$phase" "$candidate" \
                "$baseline" --output "$OUT/phase/${phase}.json" \
                >"$OUT/phase/${phase}.validation.log" 2>"$error"; then
            mv "$candidate" "$OUT/metrics/${phase}.prom"
            validate_route_sentinels "$phase"
            return
        fi
        pid_running "$HARNESS_PID" || {
            echo "harness exited while waiting for phase $phase metrics" >&2
            exit 1
        }
        sleep 0.05
    done
    [[ ! -s $error ]] || cat "$error" >&2
    echo "phase $phase never reached its exact metric state" >&2
    exit 1
}

validate_route_sentinels() {
    local phase=$1 expected=1 prefix safe output
    case "$phase" in
        eorr|timeout-complete) expected=0 ;;
    esac
    for prefix in 20.0.0.0/24 20.195.80.0/24 21.134.159.0/24; do
        safe=${prefix//\//-}
        safe=${safe//./_}
        output="$OUT/phase/${phase}-route-${safe}.json"
        timeout -k 1 10 "$RBGP" -s "unix://$RUN/grpc.sock" -j \
            rib --prefix "$prefix" received "$PEER" >"$output"
        python3 - "$output" "$prefix" "$expected" <<'PY'
import json
import pathlib
import sys

path, prefix, expected = pathlib.Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])
routes = json.loads(path.read_text(encoding="utf-8"))
if not isinstance(routes, list):
    raise SystemExit(f"{path.name}: expected a JSON route list")
if len(routes) != expected:
    raise SystemExit(
        f"{path.name}: expected {expected} exact {prefix} route(s), got {len(routes)}"
    )
if expected == 1 and routes[0].get("prefix") != prefix:
    raise SystemExit(
        f"{path.name}: expected exact prefix {prefix}, got {routes[0].get('prefix')}"
    )
PY
    done
}

run_action_phase() {
    local phase=$1 timeout_seconds=${2:-30}
    wait_ready "${phase}-arm" 30
    capture_boundary "$phase" pre
    printf '5' >"/proc/$DAEMON_PID/clear_refs"
    start_sampler "$phase"
    ack "${phase}-arm"
    wait_ready "$phase" "$timeout_seconds"
    validate_phase "$phase" "$timeout_seconds"
    capture_boundary "$phase" post
    stop_sampler
    ack "$phase"
}

printf 'phase\tboundary\tmonotonic_seconds\tjemalloc_allocated_bytes\tjemalloc_active_bytes\tjemalloc_resident_bytes\tjemalloc_mapped_bytes\tvmrss_kib\tvmhwm_kib\tvmpeak_kib\tvmsize_kib\n' \
    >"$OUT/memory-boundaries.tsv"

timeout -k 10 "$OVERALL_TIMEOUT" "$HARNESS" "$PORT" "$RUN/evidence" "$PREFIXES" \
    >"$OUT/harness.log" 2>&1 &
HARNESS_PID=$!

wait_ready baseline 45
validate_phase baseline 45
capture_boundary baseline settled
ack baseline

run_action_phase first-borr
run_action_phase replay-one
run_action_phase duplicate-borr
run_action_phase eorr
run_action_phase restored 45
run_action_phase timeout-borr

wait_ready timeout-complete 30
capture_boundary timeout-complete pre
printf '5' >"/proc/$DAEMON_PID/clear_refs"
# The production bound is five minutes. Avoid perturbing the daemon with
# high-rate allocator scrapes during the intentionally idle retained window;
# begin sampled peak capture shortly before the timer is due.
timeout_sample_start=$((SECONDS + 270))
while ((SECONDS < timeout_sample_start)); do
    pid_running "$HARNESS_PID" || {
        echo "harness exited before timeout completion" >&2
        exit 1
    }
    sleep 1
done
start_sampler timeout-complete
validate_phase timeout-complete 60
capture_boundary timeout-complete post
stop_sampler
ack timeout-complete

if wait "$HARNESS_PID"; then harness_rc=0; else harness_rc=$?; fi
HARNESS_PID=''
((harness_rc == 0)) || { echo "harness failed: $harness_rc" >&2; exit 1; }
grep -q '^receipt_complete,prefixes=100000$' "$OUT/harness.log" || {
    echo "harness completion marker missing" >&2
    exit 1
}

python3 - "$OUT" <<'PY'
import csv
import json
import pathlib
import statistics
import sys

out = pathlib.Path(sys.argv[1])
summary = {
    "fleet": {"peers": 1, "prefixes_per_peer": 100000, "families": ["ipv4_unicast"]},
    "phases": [],
    "memory": {},
}
for path in sorted((out / "phase").glob("*.json")):
    summary["phases"].append(json.loads(path.read_text(encoding="utf-8")))
with (out / "memory-boundaries.tsv").open(encoding="utf-8") as stream:
    rows = list(csv.DictReader(stream, delimiter="\t"))
for row in rows:
    summary["memory"][f"{row['phase']}:{row['boundary']}"] = {
        key: int(row[key])
        for key in (
            "jemalloc_allocated_bytes",
            "jemalloc_active_bytes",
            "jemalloc_resident_bytes",
            "jemalloc_mapped_bytes",
            "vmrss_kib",
            "vmhwm_kib",
            "vmpeak_kib",
            "vmsize_kib",
        )
    }
sampled = {}
for path in sorted((out / "memory-samples").glob("*.tsv")):
    with path.open(encoding="utf-8") as stream:
        samples = list(csv.DictReader(stream, delimiter="\t"))
    if not samples:
        raise SystemExit(f"{path.name}: no memory samples")
    sampled[path.stem] = {
        "samples": len(samples),
        "max_jemalloc_allocated_bytes": max(int(row["jemalloc_allocated_bytes"]) for row in samples),
        "max_jemalloc_active_bytes": max(int(row["jemalloc_active_bytes"]) for row in samples),
        "max_jemalloc_resident_bytes": max(int(row["jemalloc_resident_bytes"]) for row in samples),
        "max_vmrss_kib": max(int(row["vmrss_kib"]) for row in samples),
        "median_vmrss_kib": int(statistics.median(int(row["vmrss_kib"]) for row in samples)),
    }
summary["sampled_peaks"] = sampled
(out / "summary.json").write_text(
    json.dumps(summary, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

[[ $(git -C "$REPO" rev-parse HEAD) == "$COMMIT" ]] || {
    echo "HEAD changed during receipt" >&2
    exit 1
}
[[ $(git -C "$REPO" rev-parse 'HEAD^{tree}') == "$TREE" ]] || {
    echo "tree changed during receipt" >&2
    exit 1
}
[[ -z $(git -C "$REPO" status --porcelain --untracked-files=normal) ]] || {
    echo "worktree changed during receipt" >&2
    exit 1
}

terminate_pid DAEMON_PID
printf 'status=pass\nexit_status=0\n' >"$OUT/result.env"
(cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | sort -z |
    xargs -0 sha256sum >"$RUN/SHA256SUMS")
mv "$RUN/SHA256SUMS" "$OUT/SHA256SUMS"
SUCCESS=1
echo "private receipt complete: $OUT"
