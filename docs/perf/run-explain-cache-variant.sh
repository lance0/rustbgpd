#!/usr/bin/env bash
# Explain-cache memory receipt runner.
#
# Derived from bench/scale/route-server-1000/run-receipt.sh (same preflight
# gating, same host lock, same clean-tree refusal, same process-tree RSS
# sampler, same reloadstall driver). Parameterised on the three axes this
# campaign needs and which the shipped no-argument driver fixes:
#   REPO    - which clean worktree/commit is measured
#   PEERS / TOTAL - fleet shape
#   EXPLAIN - omit | true | false   ([policy.explain] enabled, injected
#             into the generated config after the [policy] block)
#
# The clean-tree refusal is preserved verbatim: a run still names the exact
# tree it measured and aborts if that tree moves under it.
set -euo pipefail

: "${REPO:?}" "${LABEL:?}" "${OUTBASE:?}"
PEERS=${PEERS:-1000}
TOTAL=${TOTAL:-400000}
EXPLAIN=${EXPLAIN:-omit}
DHAT=${DHAT:-0}
PROFILE=${PROFILE:-release}
RELOADS=${RELOADS:-4}
CONTROL_SECS=${CONTROL_SECS:-30}
COLD_CAP=${COLD_CAP:-120}
OVERALL_CAP=${OVERALL_CAP:-900}
# Raised from the shipped 2 GiB gate so an unexpectedly large shape reports a
# number instead of aborting mid-run. Disclosed in the receipt.
RSS_LIMIT_KIB=${RSS_LIMIT_KIB:-$((4 * 1024 * 1024))}
PORT=${PORT:-1790}
METRICS_PORT=${METRICS_PORT:-9179}
CHANGED=$PEERS
EXPECTED_PER_OBSERVER=$((TOTAL - TOTAL / PEERS))

pid_running() {
    local state
    [[ -n $1 ]] || return 1
    state=$(awk '{print $3}' "/proc/$1/stat" 2>/dev/null) || return 1
    [[ -n $state && $state != Z ]]
}
terminate_pid() {
    local -n slot=$1
    local pid=${slot:-}
    [[ -n $pid ]] || return 0
    if pid_running "$pid"; then
        kill -TERM "$pid" 2>/dev/null || true
        for _ in {1..900}; do pid_running "$pid" || break; sleep 0.1; done
        if pid_running "$pid"; then kill -KILL "$pid" 2>/dev/null || true; fi
    fi
    wait "$pid" 2>/dev/null || true
    slot=''
}
cleanup() {
    local rc=$?
    trap - EXIT
    for slot in GUARD_PID RSS_PID H_PID DAEMON_PID; do terminate_pid "$slot"; done
    [[ -d $OUT ]] && printf 'exit_status=%s\n' "$rc" >>"$OUT/exit-status.env"
    [[ -z $RUN ]] || rm -rf "$RUN"
    exit "$rc"
}

[[ -z $(git -C "$REPO" status --porcelain --untracked-files=normal) ]] || {
    echo "refusing dirty worktree (tracked or untracked files present)" >&2
    exit 2
}
LOCK="${RUSTBGPD_HOST_LOCK:-${HOME}/.local/state/rustbgpd-host.lock}"
mkdir -p "$(dirname "$LOCK")"
touch "$LOCK"
exec {LOCK_FD}>"$LOCK"
flock -n "$LOCK_FD" || { echo "host lock busy: $LOCK" >&2; exit 75; }

COMMIT="$(git -C "$REPO" rev-parse HEAD)"
TREE="$(git -C "$REPO" rev-parse 'HEAD^{tree}')"
OUT="$OUTBASE/$(date -u +%Y%m%dT%H%M%SZ)-${LABEL}"
readonly COMMIT TREE OUT
[[ ! -e "$OUT" ]] || { echo "output already exists: $OUT" >&2; exit 2; }
mkdir -p "$OUT/build" "$OUT/scenario"
SUCCESS=0 RUN='' DAEMON_PID='' H_PID='' RSS_PID='' GUARD_PID=''
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf 'label=%s\ncommit=%s\ntree=%s\npeers=%s\nroutes_per_peer=%s\ntotal=%s\nexplain=%s\ndhat=%s\nprofile=%s\nreloads=%s\ncontrol_secs=%s\nexpected_per_observer=%s\n' \
    "$LABEL" "$COMMIT" "$TREE" "$PEERS" "$((TOTAL / PEERS))" "$TOTAL" "$EXPLAIN" "$DHAT" "$PROFILE" \
    "$RELOADS" "$CONTROL_SECS" "$EXPECTED_PER_OBSERVER" >"$OUT/provenance.env"
{ rustc -vV; cargo -V; } >"$OUT/toolchain.txt"
{
    printf 'kernel='; uname -srvmo
    printf 'online_cpus=%s\n' "$(nproc)"
    awk -F: '/^model name/{gsub(/^[ \t]+/,"",$2); print "cpu_model=" $2; exit}' /proc/cpuinfo
    awk '/^(MemTotal|MemAvailable):/{print tolower(substr($1,1,length($1)-1)) "_kib=" $2}' /proc/meminfo
} >"$OUT/host.txt"
printf 'phase\tmonotonic_seconds\tutc\tload_1m\tgovernors\tcompetitors\tmem_available_kib\tfd_limit\tpswpin_delta\tpswpout_delta\tports_free\n' \
    >"$OUT/preflight.tsv"

competitors() {
    ps -eo pid=,comm= --no-headers | awk -v self="$$" '
      $1 != self && ($2 == "cargo" || $2 == "rustc" || $2 == "rustbgpd" ||
      $2 == "reloadstall" || $2 == "perf" || $2 ~ /^rrharness/ ||
      $2 ~ /^bgperf/) { print $2 }'
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
    local phase=$1 deadline=$((SECONDS + 178))
    while ((SECONDS < deadline)); do
        host_snapshot "$phase" && return
        sleep 1
    done
    echo "$phase host preflight did not pass within 180s" >&2
    exit 75
}

wait_for_idle prebuild
BUILD_FEATURES=()
((DHAT == 0)) || BUILD_FEATURES=(--features dhat-heap)
(cd "$REPO" && env -u CARGO_TARGET_DIR -u RUSTFLAGS \
    cargo build --profile "$PROFILE" --locked -p rustbgpd -p rustbgpctl "${BUILD_FEATURES[@]}") \
    >"$OUT/build/root.log" 2>&1
(cd "$REPO" && env -u CARGO_TARGET_DIR -u RUSTFLAGS cargo build --release --locked \
    --manifest-path bench/scale/reloadstall/Cargo.toml) >"$OUT/build/reloadstall.log" 2>&1
DAEMON="$REPO/target/$PROFILE/rustbgpd"
HARNESS="$REPO/bench/scale/reloadstall/target/release/reloadstall"
sha256sum "$DAEMON" "$HARNESS" >"$OUT/build/binaries.sha256"
wait_for_idle postbuild

RUN="$(mktemp -d /tmp/rls-ex.XXXXXX)"
python3 "$REPO/bench/scale/reloadstall/gen-scenario.py" \
    "$PEERS" "$RUN" "$PORT" "$CHANGED" >"$OUT/generator.log"
if [[ $EXPLAIN != omit ]]; then
    python3 - "$RUN/config.toml" "$EXPLAIN" <<'PY'
import sys
path, enabled = sys.argv[1], sys.argv[2]
lines = open(path, encoding="utf-8").read().split("\n")
anchor = lines.index('export_chain = ["member-out"]')
lines[anchor + 1:anchor + 1] = ["", "[policy.explain]", f"enabled = {enabled}"]
open(path, "w", encoding="utf-8").write("\n".join(lines))
PY
fi
cp "$RUN/config.toml" "$RUN"/*.rpol "$OUT/scenario/"
grep -n -A7 '^\[policy\]' "$OUT/scenario/config.toml" >"$OUT/scenario/policy-section.txt"
"$DAEMON" --check "$RUN/config.toml" >"$OUT/daemon-check.log" 2>&1

(cd "$OUT" && "$DAEMON" "$RUN/config.toml") >"$OUT/daemon.log" 2>&1 & DAEMON_PID=$!
for _ in {1..200}; do
    curl -fsS --max-time 0.25 "http://127.0.0.1:${METRICS_PORT}/readyz" >/dev/null && break
    kill -0 "$DAEMON_PID" 2>/dev/null || { echo "daemon exited during startup" >&2; exit 1; }
    sleep 0.1
done
curl -fsS --max-time 0.25 "http://127.0.0.1:${METRICS_PORT}/readyz" >/dev/null || {
    echo "daemon did not become ready" >&2; exit 1; }

tree_rss_kib() {
    ps -eo pid=,ppid=,rss= --no-headers | awk -v root="$DAEMON_PID" '
      {parent[$1]=$2; rss[$1]=$3} END {for (pid in parent) {p=pid
      while (p in parent && p != root && parent[p] != p) p=parent[p]
      if (p == root) total+=rss[pid]} print total+0}'
}
monotonic_now() { awk '{print $1}' /proc/uptime; }
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
runtime_guard() {
    exec python3 - "$OVERALL_CAP" "$OUT/runtime-failure" "$$" <<'PY'
import os, signal, sys, time
delay, failure_path, parent_pid = sys.argv[1:]
time.sleep(int(delay))
with open(failure_path, "w", encoding="utf-8") as stream:
    stream.write(f"full runtime phase exceeded {delay}s\n")
os.kill(int(parent_pid), signal.SIGTERM)
PY
}

printf 'daemon_start_monotonic=%s\n' "$(monotonic_now)" >>"$OUT/provenance.env"
cold_deadline=$((SECONDS + COLD_CAP))
runtime_guard & GUARD_PID=$!
timeout -k 10 "$OVERALL_CAP" "$HARNESS" "$PEERS" "$TOTAL" "$PORT" "$DAEMON_PID" \
    "$RUN/member.rpol" "$RUN/gen-a.rpol" "$RUN/gen-b.rpol" "$RELOADS" \
    "$CONTROL_SECS" "$CHANGED" >"$OUT/reloadstall.log" 2>&1 & H_PID=$!
rss_sampler & RSS_PID=$!

until grep -q "^converged (>= ${EXPECTED_PER_OBSERVER}/observer)" "$OUT/reloadstall.log"; do
    pid_running "$H_PID" || { echo "harness exited before cold convergence" >&2; exit 1; }
    ((SECONDS < cold_deadline)) || { echo "cold convergence exceeded ${COLD_CAP}s" >&2; exit 1; }
    sleep 0.1
done
printf 'converged_monotonic=%s\n' "$(monotonic_now)" >>"$OUT/provenance.env"
curl -fsS --max-time 2 "http://127.0.0.1:${METRICS_PORT}/metrics" >"$OUT/metrics-converged.prom"
grep -E '^(VmRSS|VmHWM|VmPeak|VmSize)' "/proc/$DAEMON_PID/status" >"$OUT/proc-status-converged.txt"

while pid_running "$H_PID"; do
    if grep -q "^reloadstall_csv,${RELOADS}," "$OUT/reloadstall.log"; then
        curl -fsS --max-time 2 "http://127.0.0.1:${METRICS_PORT}/metrics" >"$OUT/metrics-after.prom"
        grep -E '^(VmRSS|VmHWM|VmPeak|VmSize)' "/proc/$DAEMON_PID/status" >"$OUT/proc-status-after.txt"
        break
    fi
    sleep 0.1
done
if wait "$H_PID"; then hrc=0; else hrc=$?; fi
H_PID=''
if wait "$RSS_PID"; then rrc=0; else rrc=$?; fi
RSS_PID=''
printf 'harness_rc=%s\nrss_sampler_rc=%s\n' "$hrc" "$rrc" >>"$OUT/provenance.env"
grep -E '^(VmRSS|VmHWM|VmPeak|VmSize)' "/proc/$DAEMON_PID/status" >"$OUT/proc-status-final.txt" || true
terminate_pid DAEMON_PID
terminate_pid GUARD_PID
((DHAT == 0)) || [[ -f "$OUT/dhat-heap.json" ]] || echo "warning: no dhat-heap.json produced" >&2

# Summary: steady = median of post-convergence samples; peak = max over run.
python3 - "$OUT" <<'PY'
import pathlib, statistics, sys
out = pathlib.Path(sys.argv[1])
prov = dict(line.split("=", 1) for line in
            out.joinpath("provenance.env").read_text().strip().split("\n"))
conv = float(prov["converged_monotonic"])
rows = [line.split("\t") for line in
        out.joinpath("rss.tsv").read_text().strip().split("\n")[1:]]
samples = [(float(t), int(r)) for t, _, r in rows]
post = [r for t, r in samples if t >= conv]
allr = [r for _, r in samples]
summary = {
    "rss_samples_total": len(allr),
    "rss_samples_post_convergence": len(post),
    "steady_rss_kib_median_post_convergence": int(statistics.median(post)) if post else 0,
    "steady_rss_mib_median_post_convergence": round(statistics.median(post) / 1024, 1) if post else 0,
    "peak_rss_kib": max(allr) if allr else 0,
    "peak_rss_mib": round(max(allr) / 1024, 1) if allr else 0,
    "min_rss_kib": min(allr) if allr else 0,
    "post_convergence_min_kib": min(post) if post else 0,
    "post_convergence_max_kib": max(post) if post else 0,
}
out.joinpath("summary.env").write_text(
    "".join(f"{k}={v}\n" for k, v in summary.items()))
print("\n".join(f"{k}={v}" for k, v in summary.items()))
PY

[[ $(git -C "$REPO" rev-parse HEAD) == "$COMMIT" ]] || { echo "HEAD changed during run" >&2; exit 1; }
[[ $(git -C "$REPO" rev-parse 'HEAD^{tree}') == "$TREE" ]] || { echo "tree changed during run" >&2; exit 1; }
[[ -z $(git -C "$REPO" status --porcelain --untracked-files=normal) ]] || {
    echo "worktree changed during run" >&2; exit 1; }
((hrc == 0 && rrc == 0)) || { echo "run failed: harness=$hrc rss_sampler=$rrc" >&2; exit 1; }
printf 'status=success\n' >"$OUT/exit-status.env"
SUCCESS=1
echo "variant complete: $OUT"
