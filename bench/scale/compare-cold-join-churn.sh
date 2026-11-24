#!/usr/bin/env bash
# Cold first-member join with concurrent churn: build rrharness at two refs and
# run the `cold-join-churn` cells parent/candidate ABBA. Recipe and frozen bars:
# bench/scale/rrharness/README.md, "Cold join with churn".
#
#   compare-cold-join-churn.sh PARENT_REF CANDIDATE_REF OUT_DIR [ROWS]
#
# Both refs must contain this harness. Equal refs give an A/A run from one
# binary. Each timed run holds the host lock exclusively, passes the quiet-host
# gate, runs in a zero-swap 64 GiB scope and is INVALID if a compiler appears.
# `--verdict TIMELINE` regrades an existing timeline.
set -euo pipefail
# Verdict per arm. Each of the 8 controls and the 24 scheduled runs must appear
# exactly once, exit 0 and see no compiler sample, or the arm is INVALID. Then
# each clean/mixed run waits <= 200 ms, clean completes paced, mixed reports its
# fallback count (bar: 0), and burst is report-only but must fall back.
verdict() {
    awk '
        BEGIN {
            split("parent cand", arms, " "); split("clean mixed burst budget-control", ctl_cells, " ")
            split("plain policy", profiles, " "); split("clean mixed burst", cells, " ")
            split("parent cand cand parent", order, " ")
            for (a in arms) for (c in ctl_cells) control["ctl-" arms[a] "-" ctl_cells[c]] = 1
            n = 0
            for (p = 1; p <= 2; p++) for (c = 1; c <= 3; c++) for (o = 1; o <= 4; o++)
                scheduled[sprintf("%02d-%s-%s-%s", ++n, order[o], profiles[p], cells[c])] = order[o]
        }
        / end / {
            name = $3; split(name, id, "-"); cell = id[4]; delete kv
            for (i = 4; i <= NF; i++) { split($i, f, "="); kv[f[1]] = f[2] }
            if (name in control) {
                if (++control_seen[name] > 1 || kv["rc"] != 0 || kv["compiler_samples"] != 0) ctl_bad++
                next
            }
            if (!(name in scheduled)) { stray++; next }
            arm = scheduled[name]; runs[arm]++
            if (++seen[name] > 1 || kv["rc"] != 0 || kv["compiler_samples"] != 0 || kv["worst_wait_us"] == "") {
                bad[arm]++; next
            }
            if (cell != "burst" && kv["worst_wait_us"] > 200000) wait_fail[arm]++
            if (cell == "clean" && kv["fallback"] != 0) clean_fail[arm]++
            if (cell == "mixed") { mixed[arm]++; fell[arm] += kv["fallback"] }
            if (cell == "burst" && kv["fallback"] != 1) bad[arm]++
        }
        END {
            for (name in control) if (!(name in control_seen)) ctl_bad++
            for (name in scheduled) if (!(name in seen)) bad[scheduled[name]]++
            for (a = 1; a <= 2; a++) {
                arm = arms[a]
                invalid = ctl_bad || stray || bad[arm]
                v = invalid ? "INVALID" : (wait_fail[arm] || clean_fail[arm] || fell[arm]) ? "FAIL" : "PASS"
                printf "verdict arm=%s %s runs=%d invalid_runs=%d failed_controls=%d unexpected_runs=%d wait_over_200ms=%d clean_fallbacks=%d mixed_fallbacks=%d/%d\n",
                    arm, v, runs[arm], bad[arm], ctl_bad, stray, wait_fail[arm], clean_fail[arm], fell[arm], mixed[arm]
            }
        }' "$1"
}
if [[ ${1:-} == --verdict ]]; then
    [[ $# == 2 ]] || { echo "usage: $0 --verdict TIMELINE" >&2; exit 2; }
    verdict "$2"; exit 0
fi
[[ $# == 3 || $# == 4 ]] || { echo "usage: $0 PARENT_REF CANDIDATE_REF OUT_DIR [ROWS]" >&2; exit 2; }
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(git -C "$script_dir" rev-parse --show-toplevel)
parent=$(git -C "$repo" rev-parse --verify "$1^{commit}")
cand=$(git -C "$repo" rev-parse --verify "$2^{commit}")
out=$(realpath -m "$3")
rows=${4:-1000000}
lock=${RUSTBGPD_HOST_LOCK:-$HOME/.local/state/rustbgpd-host.lock}
mkdir -p "$out/bin" "$out/r"
log() { echo "$(date -u +%FT%TZ) $* load=$(cut -d' ' -f1 /proc/loadavg)" | tee -a "$out/timeline.txt"; }

build() { # build ARM REV
    local tree=$out/src-$1
    [[ -d $tree ]] || git -C "$repo" worktree add --detach "$tree" "$2" >/dev/null
    [[ $(git -C "$tree" rev-parse HEAD) == "$2" && -z $(git -C "$tree" status --porcelain) ]] ||
        { log "STOP: $tree is not a clean checkout of $2"; exit 3; }
    (cd "$tree" && CARGO_INCREMENTAL=0 flock -s "$lock" \
        cargo build --locked --profile scale -j "${JOBS:-6}" -p rrharness) > "$out/build-$1.log" 2>&1 ||
        { log "STOP: $1 build failed"; exit 3; }
    install -m 755 "$tree/target/scale/rrharness" "$out/bin/rrharness-$1"
}
test "$(df --output=pcent / | tr -dc '0-9')" -lt 85 || { echo "disk above 85%" >&2; exit 4; }
log "start parent=$parent candidate=$cand rows=$rows $(rustc -V)"
build parent "$parent"
if [[ $cand == "$parent" ]]; then
    cp "$out/bin/rrharness-parent" "$out/bin/rrharness-cand"; log "A/A: one binary"
else
    build cand "$cand"
    (cd "$out/bin" && sha256sum rrharness-parent rrharness-cand > SHA256SUMS)
    [[ $(cut -d' ' -f1 "$out/bin/SHA256SUMS" | sort -u | wc -l) == 2 ]] || { log "STOP: binaries identical"; exit 3; }
fi

( while :; do
    echo "$(date +%s) compilers=$(pgrep -x 'cargo|rustc|rustdoc|clippy-driver' | wc -l)"; sleep 1
  done >> "$out/intruders.log" ) & sampler=$!
trap 'kill $sampler 2>/dev/null' EXIT

one() { # one NAME ARM PROFILE CELL ROWS (caller holds the lock)
    local name=$1 t0 t1 rc=0 bad
    t0=$(date +%s)
    # shellcheck disable=SC2016 # The inner script expands its own arguments.
    systemd-run --user --scope --quiet --unit="cold-join-churn-$(cut -c1-8 /proc/sys/kernel/random/uuid)" \
        -p MemoryMax=64G -p MemorySwapMax=0 -- bash -c \
        'timeout -k 10s 600s "$1" cold-join-churn "$2" "$3" "$4"; rc=$?
         echo "cgroup_memory_peak_bytes=$(cat "/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)/memory.peak")"; exit $rc' \
        _ "$out/bin/rrharness-$2" "$5" "$3" "$4" > "$out/r/$name.log" 2>&1 || rc=$?
    t1=$(date +%s)
    bad=$(awk -v s="$t0" -v e="$t1" -F'[ =]' '$1>=s && $1<=e && $3>0 {b++} END {print b+0}' "$out/intruders.log")
    [[ $bad == 0 ]] || echo "INVALID: $bad compiler samples" > "$out/r/$name.INVALID"
    log "end $name rc=$rc compiler_samples=$bad $(grep -h '^cold_join_churn_summary ' "$out/r/$name.log" | cut -d' ' -f2-)"
}
locked() { # locked TAG CMD... : exclusive lock plus quiet gate around CMD
    local tag=$1; shift
    exec 9> "$lock"; flock -x 9
    # shellcheck source=/dev/null
    if ! (cd "$repo" && source "$script_dir/host-quiet.sh" &&
          RUSTBGPD_HOST_QUIET_TIMEOUT_SECS=1200 wait_for_rustbgpd_quiet_host "$out/r/$tag.quiet.tsv" \
          > "$out/r/$tag.quiet.log" 2>&1 9>&-); then
        log "$tag quiet gate failed"; exec 9>&-; return 0
    fi
    "$@" 9>&-; exec 9>&-
}
controls() { # untimed 16,384-row detector checks: every cell, both arms
    local arm cell
    for arm in parent cand; do for cell in clean mixed burst budget-control; do
        one "ctl-$arm-$cell" "$arm" plain "$cell" 16384
    done; done
}
locked controls controls
n=0
for profile in plain policy; do for cell in clean mixed burst; do for arm in parent cand cand parent; do
    n=$((n + 1)); name=$(printf '%02d-%s-%s-%s' "$n" "$arm" "$profile" "$cell")
    locked "$name" one "$name" "$arm" "$profile" "$cell" "$rows"
done; done; done

verdict "$out/timeline.txt" | tee -a "$out/timeline.txt"
log DONE
