#!/usr/bin/env bash
# Fixed-shape retained receipt: 1,000 eBGP RS clients x 400 routes.
set -euo pipefail

pid_running() {
    local state
    [[ -n $1 ]] || return 1
    state=$(awk '{print $3}' "/proc/$1/stat" 2>/dev/null) || return 1
    [[ -n $state && $state != Z ]]
}

check_run_outcome() {
    local hrc=$1 samplers_ok=$2 failures_ok=1 failure
    for failure in readyz metrics rss; do
        if [[ -e "$OUT/${failure}-failure" ]]; then
            cat "$OUT/${failure}-failure" >&2
            failures_ok=0
        fi
    done
    [[ $hrc -eq 0 ]] || { echo "harness failed: $hrc" >&2; return 1; }
    ((samplers_ok == 1)) || { echo "sampler completion/coverage failed" >&2; return 1; }
    ((failures_ok == 1))
}

terminate_pid() {
    local -n slot=$1
    local pid=${slot:-}
    [[ -n $pid ]] || return 0
    if pid_running "$pid"; then
        kill -TERM "$pid" 2>/dev/null || true
        for _ in {1..20}; do pid_running "$pid" || break; sleep 0.1; done
        if pid_running "$pid"; then kill -KILL "$pid" 2>/dev/null || true; fi
    fi
    wait "$pid" 2>/dev/null || true
    slot=''
}

cleanup() {
    local rc=$?
    trap - EXIT
    for slot in GUARD_PID READY_PID METRICS_PID RSS_PID H_PID DAEMON_PID; do terminate_pid "$slot"; done
    if ((SUCCESS == 0)) && [[ -d $OUT ]]; then
        printf 'status=failed\nexit_status=%s\n' "$rc" >"$OUT/exit-status.env"
    fi
    [[ -z $RUN ]] || rm -rf "$RUN"
    exit "$rc"
}

# The focused mechanics test sources these exact production helpers.
[[ ${BASH_SOURCE[0]} == "$0" ]] || return 0

[[ $# -eq 0 ]] || { echo "usage: $0" >&2; exit 2; }
for command in awk cargo curl find flock git grep mktemp nproc paste ps python3 rustc \
    sha256sum sort ss timeout tr uname xargs; do
    command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 1; }
done

readonly PEERS=1000 TOTAL=400000 CHANGED=1000 RELOADS=4 CONTROL_SECS=30
readonly PORT=1790 METRICS_PORT=9179 EXPECTED_PER_OBSERVER=399600
readonly COLD_CAP=60 OVERALL_CAP=600 RSS_LIMIT_KIB=$((2 * 1024 * 1024))
REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
readonly REPO
readonly LOCK="${RUSTBGPD_HOST_LOCK:-${HOME}/.local/state/rustbgpd-host.lock}"
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
OUT="$REPO/target/route-server-1000/$(date -u +%Y%m%dT%H%M%SZ)-${COMMIT:0:12}"
readonly COMMIT TREE OUT
[[ ! -e "$OUT" ]] || { echo "output already exists: $OUT" >&2; exit 2; }
mkdir -p "$OUT/build" "$OUT/scenario"
chmod 700 "$OUT"
SUCCESS=0 RUN='' DAEMON_PID='' H_PID='' READY_PID='' METRICS_PID='' RSS_PID='' GUARD_PID=''
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
printf 'commit=%s\ntree=%s\npeers=%s\nroutes_per_peer=400\ntotal=%s\n' \
    "$COMMIT" "$TREE" "$PEERS" "$TOTAL" >"$OUT/provenance.env"
{
    rustc -vV
    cargo -V
} >"$OUT/toolchain.txt"
{
    printf 'kernel='; uname -srvmo
    printf 'online_cpus=%s\n' "$(nproc)"
    awk -F: '/^model name/{gsub(/^[ \t]+/,"",$2); print "cpu_model=" $2; exit}' /proc/cpuinfo
    awk '/^(MemTotal|MemAvailable):/{print tolower(substr($1,1,length($1)-1)) "_kib=" $2}' /proc/meminfo
} >"$OUT/host.txt"
printf 'working_directory=%q\n' "$REPO" >"$OUT/commands.txt"
cat >>"$OUT/commands.txt" <<'EOF'
env -u CARGO_TARGET_DIR -u RUSTFLAGS cargo build --release --locked -p rustbgpd -p rustbgpctl
env -u CARGO_TARGET_DIR -u RUSTFLAGS cargo build --release --locked --manifest-path bench/scale/reloadstall/Cargo.toml
EOF
record_command() { printf '%q ' "$@" >>"$OUT/commands.txt"; printf '\n' >>"$OUT/commands.txt"; }
printf 'status=running\nexit_status=unset\n' >"$OUT/exit-status.env"
printf 'phase\tmonotonic_seconds\tutc\tload_1m\tgovernors\tcompetitors\tmem_available_kib\tfd_limit\tpswpin_delta\tpswpout_delta\tports_free\n' \
    >"$OUT/preflight.tsv"

competitors() {
    ps -eo pid=,comm= --no-headers | awk -v self="$$" '
      $1 != self && ($2 == "cargo" || $2 == "rustc" || $2 == "rustbgpd" ||
      $2 == "reloadstall" || $2 == "perf" || $2 ~ /^rrharness/ ||
      $2 ~ /^route_paging/ || $2 ~ /^rib_nlri_build/ || $2 ~ /^nlri_build/ ||
      $2 ~ /^event_history_/ || $2 ~ /^codec/ || $2 ~ /^fanout/ ||
      $2 ~ /^inbound_attrs/ || $2 ~ /^rib_ops/ || $2 ~ /^policy_eval/ ||
      $2 ~ /^explain_snapsho/ || $2 ~ /^bgperf/) { print $2 }'
}

host_snapshot() {
    local phase=$1 load mem fd pin0 pout0 pin1 pout1 procs listeners gov_count=0 gov_bad=0
    load=$(awk '{print $1}' /proc/loadavg)
    mem=$(awk '$1 == "MemAvailable:" {print $2}' /proc/meminfo)
    fd=$(ulimit -n)
    procs=$(competitors | sort -u | paste -sd, -); procs=${procs:-none}
    shopt -s nullglob
    local governors=(/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor)
    shopt -u nullglob
    gov_count=${#governors[@]}
    local path
    for path in "${governors[@]}"; do
        [[ $(tr -d '\n' <"$path") == performance ]] || ((gov_bad += 1))
    done
    read -r pin0 pout0 < <(awk '$1=="pswpin"{i=$2} $1=="pswpout"{o=$2} END{print i+0,o+0}' /proc/vmstat)
    sleep 2
    read -r pin1 pout1 < <(awk '$1=="pswpin"{i=$2} $1=="pswpout"{o=$2} END{print i+0,o+0}' /proc/vmstat)
    local ports_free=1
    if ! listeners=$(ss -H -ltn); then
        ports_free=0
    elif awk -v a=":${PORT}" -v b=":${METRICS_PORT}" '
        {if (substr($4,length($4)-length(a)+1)==a || substr($4,length($4)-length(b)+1)==b) used=1}
        END{exit !used}' <<<"$listeners"; then
        ports_free=0
    fi
    printf '%s\t%s\t%s\t%s\t%s/%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$phase" \
        "$(awk '{print $1}' /proc/uptime)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$load" \
        "$((gov_count-gov_bad))" "$gov_count" \
        "$procs" "$mem" "$fd" "$((pin1-pin0))" "$((pout1-pout0))" "$ports_free" \
        >>"$OUT/preflight.tsv"
    awk -v value="$load" 'BEGIN {exit !(value < 2.0)}' && ((gov_count > 0 && gov_bad == 0)) &&
        [[ $procs == none ]] && ((mem >= 16 * 1024 * 1024)) && ((fd >= 4096)) &&
        ((pin1 == pin0 && pout1 == pout0 && ports_free == 1))
}

wait_for_idle() {
    local phase=$1 deadline=$((SECONDS + 118))
    while ((SECONDS < deadline)); do
        host_snapshot "$phase" && return
        sleep 1
    done
    echo "$phase host preflight did not pass within 120s" >&2
    exit 75
}

wait_for_idle prebuild
(cd "$REPO" && env -u CARGO_TARGET_DIR -u RUSTFLAGS \
    cargo build --release --locked -p rustbgpd -p rustbgpctl) >"$OUT/build/root.log" 2>&1
(cd "$REPO" && env -u CARGO_TARGET_DIR -u RUSTFLAGS cargo build --release --locked \
    --manifest-path bench/scale/reloadstall/Cargo.toml) >"$OUT/build/reloadstall.log" 2>&1
readonly DAEMON="$REPO/target/release/rustbgpd" RBGP="$REPO/target/release/rbgp"
readonly HARNESS="$REPO/bench/scale/reloadstall/target/release/reloadstall"
sha256sum "$DAEMON" "$RBGP" "$HARNESS" >"$OUT/build/binaries.sha256"
wait_for_idle postbuild

RUN="$(mktemp -d /tmp/rustbgpd-rs1000.XXXXXX)"

record_command python3 "$REPO/bench/scale/reloadstall/gen-scenario.py" "$PEERS" "$RUN" "$PORT" "$CHANGED"
python3 "$REPO/bench/scale/reloadstall/gen-scenario.py" \
    "$PEERS" "$RUN" "$PORT" "$CHANGED" >"$OUT/generator.log"
cp "$RUN/config.toml" "$RUN"/*.rpol "$OUT/scenario/"
record_command "$DAEMON" --check "$RUN/config.toml"
"$DAEMON" --check "$RUN/config.toml" >"$OUT/daemon-check.log" 2>&1
record_command "$DAEMON" "$RUN/config.toml"
"$DAEMON" "$RUN/config.toml" >"$OUT/daemon.log" 2>&1 & DAEMON_PID=$!
for _ in {1..100}; do
    curl -fsS --max-time 0.25 "http://127.0.0.1:${METRICS_PORT}/readyz" >/dev/null && break
    kill -0 "$DAEMON_PID" 2>/dev/null || { echo "daemon exited during startup" >&2; exit 1; }
    sleep 0.1
done
curl -fsS --max-time 0.25 "http://127.0.0.1:${METRICS_PORT}/readyz" >/dev/null || {
    echo "daemon did not become ready" >&2; exit 1;
}

tree_rss_kib() {
    ps -eo pid=,ppid=,rss= --no-headers | awk -v root="$DAEMON_PID" '
      {parent[$1]=$2; rss[$1]=$3} END {for (pid in parent) {p=pid
      while (p in parent && p != root && parent[p] != p) p=parent[p]
      if (p == root) total+=rss[pid]} print total+0}'
}
monotonic_now() { awk '{print $1}' /proc/uptime; }
ready_sampler() {
    local count=0
    printf 'monotonic_seconds\tutc\thttp_code\ttime_seconds\n' >"$OUT/readyz.tsv"
    while pid_running "$H_PID"; do
        local sample code seconds; ((count += 1))
        sample=$(curl -sS -o /dev/null --max-time 0.250 -w '%{http_code}\t%{time_total}' \
            "http://127.0.0.1:${METRICS_PORT}/readyz" || true)
        printf '%s\t%s\t%s\n' "$(monotonic_now)" "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" "$sample" >>"$OUT/readyz.tsv"
        IFS=$'\t' read -r code seconds <<<"$sample"
        if [[ $code != 200 ]] || ! awk -v t="${seconds:-9}" 'BEGIN {exit !(t <= 0.250)}'; then
            echo "readyz exceeded 200/250ms contract: ${sample:-no response}" >"$OUT/readyz-failure"
            kill -TERM "$H_PID" 2>/dev/null || true; return 1
        fi
        sleep 0.1
    done
    printf 'samples=%s\n' "$count" >"$OUT/readyz.complete"
}
metrics_sampler() {
    local count=0 body="$RUN/metrics.$$"
    : >"$OUT/metrics-selected.prom"
    while pid_running "$H_PID"; do
        ((count += 1))
        if ! curl -fsS --max-time 1 "http://127.0.0.1:${METRICS_PORT}/metrics" >"$body"; then
            echo "metrics scrape failed" >"$OUT/metrics-failure"
            kill -TERM "$H_PID" 2>/dev/null || true; return 1
        fi
        printf '# sample monotonic_seconds=%s utc=%s\n' "$(monotonic_now)" \
            "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" >>"$OUT/metrics-selected.prom"
        grep -E '^bgp_(update_groups|update_group_members|update_group_fallback_peers|rib_policy_transition_actor_poll_duration_seconds)' \
            "$body" >>"$OUT/metrics-selected.prom" || true
        sleep 0.25
    done
    printf 'samples=%s\n' "$count" >"$OUT/metrics.complete"
}
rss_sampler() {
    local count=0
    printf 'monotonic_seconds\tutc\ttree_rss_kib\n' >"$OUT/rss.tsv"
    while pid_running "$H_PID"; do
        local rss; ((count += 1)); rss=$(tree_rss_kib)
        printf '%s\t%s\t%s\n' "$(monotonic_now)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$rss" >>"$OUT/rss.tsv"
        if ((rss > RSS_LIMIT_KIB)); then
            echo "daemon tree RSS ${rss}KiB exceeded ${RSS_LIMIT_KIB}KiB" >"$OUT/rss-failure"
            kill -TERM "$H_PID" 2>/dev/null || true; return 1
        fi
        sleep 1
    done
    printf 'samples=%s\n' "$count" >"$OUT/rss.complete"
}
wait_sampler() {
    local label=$1 variable=$2 minimum=$3 deadline=$((SECONDS + 5)) rc samples
    local -n slot=$variable
    while pid_running "$slot"; do
        if ((SECONDS >= deadline)); then
            terminate_pid "$variable"
            printf '%s\t124\n' "$label" >>"$OUT/sampler-status.tsv"
            return 1
        fi
        sleep 0.1
    done
    if wait "$slot"; then rc=0; else rc=$?; fi
    slot=''
    printf '%s\t%s\n' "$label" "$rc" >>"$OUT/sampler-status.tsv"
    [[ $rc -eq 0 && -s "$OUT/${label}.complete" ]] || return 1
    samples=$(awk -F= '$1=="samples"{print $2}' "$OUT/${label}.complete")
    ((samples >= minimum))
}
runtime_guard() {
    exec python3 - "$OVERALL_CAP" "$OUT/runtime-failure" "$$" <<'PY'
import os
import signal
import sys
import time

delay, failure_path, parent_pid = sys.argv[1:]
time.sleep(int(delay))
with open(failure_path, "w", encoding="utf-8") as stream:
    stream.write(f"full runtime phase exceeded {delay}s\n")
os.kill(int(parent_pid), signal.SIGTERM)
PY
}

cold_deadline=$((SECONDS + COLD_CAP))
printf 'sampler\texit_status\n' >"$OUT/sampler-status.tsv"
runtime_guard & GUARD_PID=$!
record_command timeout -k 10 "$OVERALL_CAP" "$HARNESS" "$PEERS" "$TOTAL" "$PORT" "$DAEMON_PID" "$RUN/member.rpol" \
    "$RUN/gen-a.rpol" "$RUN/gen-b.rpol" "$RELOADS" "$CONTROL_SECS" "$CHANGED"
timeout -k 10 "$OVERALL_CAP" "$HARNESS" "$PEERS" "$TOTAL" "$PORT" "$DAEMON_PID" \
    "$RUN/member.rpol" "$RUN/gen-a.rpol" "$RUN/gen-b.rpol" "$RELOADS" \
    "$CONTROL_SECS" "$CHANGED" >"$OUT/reloadstall.log" 2>&1 & H_PID=$!
ready_sampler & READY_PID=$!
metrics_sampler & METRICS_PID=$!
rss_sampler & RSS_PID=$!
: "$GUARD_PID" "$READY_PID" "$METRICS_PID" "$RSS_PID" # consumed later through namerefs

until grep -q "^converged (>= ${EXPECTED_PER_OBSERVER}/observer)" "$OUT/reloadstall.log"; do
    pid_running "$H_PID" || { echo "harness exited before cold convergence" >&2; exit 1; }
    ((SECONDS < cold_deadline)) || { echo "cold convergence exceeded ${COLD_CAP}s" >&2; exit 1; }
    sleep 0.1
done
curl -fsS --max-time 1 "http://127.0.0.1:${METRICS_PORT}/metrics" >"$OUT/metrics-before.prom"

while pid_running "$H_PID"; do
    if grep -q '^reloadstall_csv,4,' "$OUT/reloadstall.log"; then
        curl -fsS --max-time 1 "http://127.0.0.1:${METRICS_PORT}/metrics" >"$OUT/metrics-after.prom"
        record_command timeout -k 1 5 "$RBGP" -s "unix://$RUN/grpc.sock" -j rib \
            --prefix 20.0.0.0/24 advertised 127.1.0.2 --explain
        timeout -k 1 5 "$RBGP" -s "unix://$RUN/grpc.sock" -j rib --prefix 20.0.0.0/24 \
            advertised 127.1.0.2 --explain >"$OUT/advertised-explain.json"
        break
    fi
    sleep 0.1
done
if wait "$H_PID"; then hrc=0; else hrc=$?; fi
H_PID=''
samplers_ok=1
wait_sampler readyz READY_PID 10 || samplers_ok=0
wait_sampler metrics METRICS_PID 4 || samplers_ok=0
wait_sampler rss RSS_PID 2 || samplers_ok=0
check_run_outcome "$hrc" "$samplers_ok" || exit 1
[[ -s "$OUT/metrics-after.prom" && -s "$OUT/advertised-explain.json" ]] || { echo "final evidence missing" >&2; exit 1; }

awk -F, '$1=="reloadstall_csv" {n++; if ($3!=1000||$4!=1000||$5!=0||$6!=400000||$21!=0||$22!=1000||$23!=0) bad=1} END{exit bad || n!=4}' \
    "$OUT/reloadstall.log" || { echo "reload CSV contract failed" >&2; exit 1; }
comm_a=$((65400 * 65536 + 1000)); comm_b=$((65400 * 65536 + 2000))
for reload in 1 2 3 4; do
    expected=$comm_a; ((reload % 2 == 1)) && expected=$comm_b
    grep -Eq "^reload ${reload} rss_mib .*comms_sample=.*${expected}" "$OUT/reloadstall.log" || {
        echo "reload $reload lacks expected generation community $expected" >&2; exit 1;
    }
done
metric() { awk -v name="$1" '$1==name {sum+=$2} END{print sum+0}' "$2"; }
[[ $(metric bgp_update_groups "$OUT/metrics-after.prom") == 1 ]] || { echo "final update-group count is not 1" >&2; exit 1; }
[[ $(awk '/^bgp_update_group_members[{ ]/{sum+=$2} END{print sum+0}' "$OUT/metrics-after.prom") == 1000 ]] || {
    echo "final grouped member count is not 1000" >&2; exit 1;
}
[[ $(metric bgp_update_group_fallback_peers "$OUT/metrics-after.prom") == 0 ]] || { echo "fallback peers are nonzero" >&2; exit 1; }
before=$(metric 'bgp_rib_policy_transition_actor_poll_duration_seconds_count{poll_kind="finalize"}' "$OUT/metrics-before.prom")
after=$(metric 'bgp_rib_policy_transition_actor_poll_duration_seconds_count{poll_kind="finalize"}' "$OUT/metrics-after.prom")
((after - before >= 4)) || { echo "fewer than four finalize polls observed" >&2; exit 1; }
python3 - "$OUT/advertised-explain.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    value = json.load(stream)
assert value["decision"] == "advertise", value
assert value.get("update_group_id") is not None, value
assert any(g["verdict"] == "pass" for g in value["gates"]), value
assert any(g["gate"] == "export_policy" and g["verdict"] == "pass" for g in value["gates"]), value
PY
[[ $(git -C "$REPO" rev-parse HEAD) == "$COMMIT" ]] || { echo "HEAD changed during run" >&2; exit 1; }
[[ $(git -C "$REPO" rev-parse 'HEAD^{tree}') == "$TREE" ]] || { echo "tree changed during run" >&2; exit 1; }
[[ -z $(git -C "$REPO" status --porcelain --untracked-files=normal) ]] || {
    echo "worktree changed during run" >&2; exit 1;
}
terminate_pid DAEMON_PID
terminate_pid GUARD_PID
printf 'status=pass\nexit_status=0\n' >"$OUT/result.env"
printf 'status=success\nexit_status=0\n' >"$OUT/exit-status.env"
(cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum >"$RUN/SHA256SUMS")
mv "$RUN/SHA256SUMS" "$OUT/SHA256SUMS"
SUCCESS=1
echo "private receipt complete: $OUT"
