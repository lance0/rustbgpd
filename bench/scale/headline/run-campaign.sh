#!/usr/bin/env bash
# Headline performance campaign: the IXP matrix S2 and S3 legs (S1 is read
# from their convergence phase), the IRR reload roots, and the RR1000
# campaigns, across two or more arms built from this repository. Strictly
# sequential; the arm order rotates every run.
#
# Usage: run-campaign.sh OUT_DIR LABEL=REF LABEL=REF [LABEL=REF ...]
#
# A campaign compares at least two arms.
#
#   LABEL=REF          an arm: REF's tree, built and run with its own runners
#                      and harnesses. LABEL is letters, digits, '.' and '_'.
#   LABEL=HREF:DREF    a cross-harness arm: the DREF daemon under HREF's matrix
#                      runner and harness. It runs matrix legs only.
#
# Each arm runs from OUT_DIR/trees/LABEL, a detached worktree at a local,
# never-pushed commit whose tree is REF's tree and whose parent is
# origin/main, so the IRR runner's source gate accepts it. The tree hash is
# the arm's identity. Before the first leg, each arm's daemon is rebuilt at
# REF itself in the same directory and must hash identically, so no commit
# identity enters the build. When origin/main moves, an arm's commit is
# re-parented before its next IRR root; its tree never changes.
#
# Legs land in OUT_DIR as matrix-LABEL-rN-s{2,3}, irr-ovF-LABEL-rN and
# rr1000-LABEL-cN. OUT_DIR/manifest.txt records the campaign's shape on first
# start: each arm's resolved commits, CELLS, RUNS, OVERLAPS, IRR_CELLS,
# MATRIX_SCENARIOS, the MATRIX_* shape and SMOKE. A rerun with the same shape
# resumes: finished legs are skipped and a failed IRR or RR1000 leg is moved
# aside and run again. A rerun with any other shape, or a non-empty OUT_DIR
# without a manifest, is refused before anything is written, so one output
# directory never mixes legs from two shapes.
# progress.txt logs every leg boundary with the load average, the swap-in and
# swap-out counters, and the CPUs the leg may run on; placement.txt records
# the campaign's CPU affinity, which every runner, harness and daemon inherits
# (none of the runners sets its own). The campaign ends by writing
# summary.csv, establishment-span.csv and report.md with summarize.py, and
# exits non-zero if any setup step, leg or the extraction failed. Each leg
# keeps the daemon.log its runner wrote: the daemon's own reload intervals in
# summary.csv are read from them, and summarize.py refuses a campaign
# directory whose finished S2 or IRR leg has lost its log. To drop a
# leg another workload disturbed, list its ID in OUT_DIR/EXCLUDED
# and rerun `just bench-headline-summary OUT_DIR`; report.md names every
# excluded leg.
#
# Knobs (env):
#   CELLS=matrix,irr,rr    phases to run, always in this order
#   RUNS=3                 runs per cell per arm
#   OVERLAPS=0             IRR overlap fractions; above 0 the IRR runner
#                          requires a comparator cell in IRR_CELLS
#   IRR_CELLS=rustbgpd-sighup
#   MATRIX_PEERS=700 MATRIX_PREFIXES=400400 MATRIX_RELOADS=4
#   MATRIX_CONTROL_SECS=30 MATRIX_FLAPSTORM=50 (S3 only)
#   MATRIX_SCENARIOS=s2,s3 matrix legs per run and arm
#   SMOKE=1                pipeline check, not a measurement: the matrix runs
#                          at 20 peers x 11,440 prefixes, one reload and five
#                          flapping members; the IRR runner runs its SMOKE
#                          shape; RR1000 runs the tiny rrtransport fixture
#   DRY_RUN=1              print the arms and the leg schedule, then exit
#   CONFIRM_NO_MAIN_PUSHES passed to the IRR runner's preflight unchanged
#   RUSTBGPD_HOST_QUIET_TIMEOUT_SECS=1800  the runners' quiet-gate wait
#   HEADLINE_LOCKS         space-separated lock files held, nonblocking, for
#                          the whole window (for example a local build lock);
#                          contention exits 75
#   HEADLINE_MARKER        a file that exists only while the window is open
#
# The runners take the shared host lock per leg themselves, so the campaign
# does not hold it across the window. The arm worktrees stay registered after
# the campaign; remove them with `git worktree remove OUT_DIR/trees/LABEL`.
set -euo pipefail

usage() {
    echo "usage: $0 OUT_DIR ARM ARM [ARM ...]  (ARM is LABEL=REF or LABEL=HARNESS_REF:DAEMON_REF)" >&2
    exit 2
}
die() {
    log "STOP: $*"
    exit 1
}
log() { echo "[$(date -Is)] $*" | tee -a "$OUT/progress.txt"; }

[[ $# -ge 3 ]] || usage
REPO=$(cd "$(dirname "$0")/../../.." && pwd)
OUT=$(realpath -m "$1")
shift

CELLS=${CELLS:-matrix,irr,rr}
RUNS=${RUNS:-3}
OVERLAPS=${OVERLAPS:-0}
IRR_CELLS=${IRR_CELLS:-rustbgpd-sighup}
SMOKE=${SMOKE:-}
if [[ -n $SMOKE ]]; then
    MATRIX_PEERS=${MATRIX_PEERS:-20} MATRIX_PREFIXES=${MATRIX_PREFIXES:-11440}
    MATRIX_RELOADS=${MATRIX_RELOADS:-1} MATRIX_CONTROL_SECS=${MATRIX_CONTROL_SECS:-5}
    MATRIX_FLAPSTORM=${MATRIX_FLAPSTORM:-5}
else
    MATRIX_PEERS=${MATRIX_PEERS:-700} MATRIX_PREFIXES=${MATRIX_PREFIXES:-400400}
    MATRIX_RELOADS=${MATRIX_RELOADS:-4} MATRIX_CONTROL_SECS=${MATRIX_CONTROL_SECS:-30}
    MATRIX_FLAPSTORM=${MATRIX_FLAPSTORM:-50}
fi
export RUSTBGPD_HOST_QUIET_TIMEOUT_SECS=${RUSTBGPD_HOST_QUIET_TIMEOUT_SECS:-1800}
# The runners read these generic names; each leg sets the ones it needs, so an
# operator's matrix shape never leaks into an IRR root. One build environment
# serves the prebuilds and the IRR runner's own build.
unset N_PEERS TOTAL_PREFIXES RELOADS CONTROL_SECS FLAPSTORM ARTIFACTS_DIR
unset CARGO_TARGET_DIR RUSTFLAGS

IFS=', ' read -r -a PHASES <<<"$CELLS"
for phase in "${PHASES[@]}"; do
    case $phase in matrix | irr | rr) ;; *) echo "unknown cell: $phase (want matrix, irr, rr)" >&2; exit 2 ;; esac
done
IFS=', ' read -r -a OVERLAP_LIST <<<"$OVERLAPS"
IFS=', ' read -r -a SCENARIOS <<<"${MATRIX_SCENARIOS:-s2,s3}"
for s in "${SCENARIOS[@]}"; do
    case $s in s2 | s3) ;; *) echo "unknown matrix scenario: $s (want s2, s3)" >&2; exit 2 ;; esac
done
[[ $RUNS =~ ^[1-9][0-9]*$ ]] || { echo "RUNS must be a positive integer" >&2; exit 2; }
wants() { [[ " ${PHASES[*]} " == *" $1 "* ]]; }

declare -a ARMS=()
declare -A HARNESS_REF=() DAEMON_REF=() HARNESS_SHA=() DAEMON_SHA=()
resolve() {
    git -C "$REPO" rev-parse --verify -q "$1^{commit}" || { echo "unknown ref: $1" >&2; exit 2; }
}
for spec in "$@"; do
    [[ $spec =~ ^([A-Za-z0-9._]+)=([^:]+)(:(.+))?$ ]] || usage
    label=${BASH_REMATCH[1]}
    [[ -z ${HARNESS_REF[$label]:-} ]] || { echo "duplicate arm label: $label" >&2; exit 2; }
    ARMS+=("$label")
    HARNESS_REF[$label]=${BASH_REMATCH[2]}
    DAEMON_REF[$label]=${BASH_REMATCH[4]:-${BASH_REMATCH[2]}}
    HARNESS_SHA[$label]=$(resolve "${HARNESS_REF[$label]}")
    DAEMON_SHA[$label]=$(resolve "${DAEMON_REF[$label]}")
done
is_cross() { [[ ${DAEMON_REF[$1]} != "${HARNESS_REF[$1]}" ]]; }

# Arm order for run R (1-based): the arm list rotated by R-1 (a Latin square
# when RUNS equals the number of arms).
order() {
    local r=$1 n=${#ARMS[@]} i
    for ((i = 0; i < n; i++)); do echo "${ARMS[$(((i + r - 1) % n))]}"; done
}

schedule() {
    local r arm s ov
    if wants matrix; then
        for ((r = 1; r <= RUNS; r++)); do for arm in $(order "$r"); do for s in "${SCENARIOS[@]}"; do
            echo "matrix $arm $r $s"
        done; done; done
    fi
    if wants irr; then
        for ov in "${OVERLAP_LIST[@]}"; do for ((r = 1; r <= RUNS; r++)); do for arm in $(order "$r"); do
            is_cross "$arm" || echo "irr $arm $r $ov"
        done; done; done
    fi
    if wants rr; then
        for ((r = 1; r <= RUNS; r++)); do for arm in $(order "$r"); do
            is_cross "$arm" || echo "rr $arm $r"
        done; done
    fi
}

if [[ -n ${DRY_RUN:-} ]]; then
    for arm in "${ARMS[@]}"; do echo "arm $arm=${HARNESS_REF[$arm]}:${DAEMON_REF[$arm]}"; done
    schedule
    exit 0
fi

for lock in ${HEADLINE_LOCKS:-}; do
    exec {fd}>>"$lock"
    flock -n "$fd" || { echo "lock busy: $lock" >&2; exit 75; }
done
if [[ -n ${HEADLINE_MARKER:-} ]]; then
    touch "$HEADLINE_MARKER"
    trap 'rm -f "$HEADLINE_MARKER"' EXIT
fi

# OUT_DIR is either fresh (missing or empty) or a campaign whose manifest
# matches this run's shape exactly; anything else is refused before any file
# is written, so one directory never mixes legs from two shapes.
manifest() {
    local arm
    for arm in "${ARMS[@]}"; do echo "arm $arm=${HARNESS_SHA[$arm]}:${DAEMON_SHA[$arm]}"; done
    echo "cells=${PHASES[*]}"
    echo "runs=$RUNS"
    echo "overlaps=${OVERLAP_LIST[*]}"
    echo "irr_cells=$IRR_CELLS"
    echo "matrix_scenarios=${SCENARIOS[*]}"
    echo "matrix_peers=$MATRIX_PEERS matrix_prefixes=$MATRIX_PREFIXES matrix_reloads=$MATRIX_RELOADS"
    echo "matrix_control_secs=$MATRIX_CONTROL_SECS matrix_flapstorm=$MATRIX_FLAPSTORM"
    echo "smoke=${SMOKE:+1}"
}
fresh=1
if [[ -e $OUT ]]; then
    [[ -d $OUT ]] || { echo "OUT_DIR is not a directory: $OUT" >&2; exit 2; }
    [[ -z $(find "$OUT" -mindepth 1 -maxdepth 1 -print -quit) ]] || fresh=0
fi
if ((!fresh)); then
    if [[ ! -e $OUT/manifest.txt ]]; then
        echo "OUT_DIR is not empty and has no campaign manifest; use a fresh OUT_DIR" >&2
        exit 2
    fi
    if ! mismatch=$(diff "$OUT/manifest.txt" <(manifest)); then
        echo "OUT_DIR holds a campaign with another shape; use a fresh OUT_DIR (< recorded, > requested):" >&2
        echo "$mismatch" >&2
        exit 2
    fi
fi

mkdir -p "$OUT/trees"
if ((fresh)); then
    manifest >"$OUT/manifest.txt"
    for arm in "${ARMS[@]}"; do echo "$arm=${HARNESS_REF[$arm]}:${DAEMON_REF[$arm]}"; done >"$OUT/arms.txt"
fi
[[ -z $SMOKE ]] || echo "pipeline check at a reduced shape; not a measurement" >"$OUT/SMOKE"
cpus() { awk '/^Cpus_allowed_list:/ {print $2}' /proc/self/status; }
{
    echo "cpus_allowed=$(cpus) online_cpus=$(getconf _NPROCESSORS_ONLN)"
    echo "Every runner, harness and daemon inherits this affinity; none sets its own."
} >"$OUT/placement.txt"
log "campaign start arms=${ARMS[*]} cells=$CELLS runs=$RUNS smoke=${SMOKE:-0} cpus=$(cpus)"

git -C "$REPO" fetch -q origin main
MAIN=$(git -C "$REPO" rev-parse origin/main)
sha() { sha256sum "$1" | cut -c1-64; }
build_product() { # TREE LOG
    (cd "$1" && cargo build --release --locked -p rustbgpd -p rustbgpctl -p rs-config-render) >>"$2" 2>&1
}

setup_arm() {
    local arm=$1 tree=$OUT/trees/$1 log=$OUT/build-$1.log harness daemon ctl dtree before after
    harness=${HARNESS_SHA[$arm]}
    daemon=${DAEMON_SHA[$arm]}
    if [[ ! -d $tree ]]; then
        ctl=$(git -C "$REPO" commit-tree "$harness^{tree}" -p "$MAIN" \
            -m "local measurement control: $arm, tree of ${HARNESS_REF[$arm]} (never pushed)")
        git -C "$REPO" worktree add -q --detach "$tree" "$ctl"
    fi
    log "build $arm start"
    build_product "$tree" "$log"
    (cd "$tree" && cargo build --release --locked --manifest-path bench/scale/reloadstall/Cargo.toml) >>"$log" 2>&1
    if wants rr && ! is_cross "$arm" && [[ -z $SMOKE ]]; then
        (cd "$tree" && cargo build --release --locked --manifest-path bench/scale/rrtransport/Cargo.toml) >>"$log" 2>&1
    fi
    if is_cross "$arm"; then
        dtree=$OUT/trees/$arm.daemon
        [[ -d $dtree ]] || git -C "$REPO" worktree add -q --detach "$dtree" "$daemon"
        build_product "$dtree" "$log"
        cp "$dtree/target/release/rustbgpd" "$tree/target/release/rustbgpd"
    else
        # The same directory at REF itself must give the same daemon.
        ctl=$(git -C "$tree" rev-parse HEAD)
        before=$(sha "$tree/target/release/rustbgpd")
        git -C "$tree" checkout -q --detach "$harness"
        build_product "$tree" "$log" || {
            git -C "$tree" checkout -q --detach "$ctl"
            die "$arm: build at ${HARNESS_REF[$arm]} failed (see $log)"
        }
        after=$(sha "$tree/target/release/rustbgpd")
        git -C "$tree" checkout -q --detach "$ctl"
        [[ $before == "$after" ]] || die "$arm: daemon at ${HARNESS_REF[$arm]} hashes $after, control commit $before"
    fi
    [[ -z $(git -C "$tree" status --porcelain) ]] || die "$arm: tree dirty after build"
    printf '%s\ttree=%s\tdaemon=%s\tdaemon_sha256=%s\treloadstall_sha256=%s\n' "$arm" \
        "$(git -C "$tree" rev-parse 'HEAD^{tree}')" "$daemon" "$(sha "$tree/target/release/rustbgpd")" \
        "$(sha "$tree/bench/scale/target/release/reloadstall")" >>"$OUT/identity.tsv"
    log "build $arm done daemon_sha256=$(sha "$tree/target/release/rustbgpd")"
}

# Keep an arm's commit a direct child of origin/main for the IRR source gate.
reparent() {
    local arm=$1 tree=$OUT/trees/$1 main next
    git -C "$REPO" fetch -q origin main
    main=$(git -C "$REPO" rev-parse origin/main)
    [[ $(git -C "$tree" rev-parse HEAD^) != "$main" ]] || return 0
    next=$(git -C "$REPO" commit-tree "$(git -C "$tree" rev-parse 'HEAD^{tree}')" -p "$main" \
        -m "local measurement control: $arm, tree of ${HARNESS_REF[$arm]} (never pushed)")
    git -C "$tree" checkout -q --detach "$next"
    log "reparented $arm onto origin/main $main"
}

state() {
    printf 'load=%s %s cpus=%s' "$(cut -d' ' -f1-3 /proc/loadavg)" \
        "$(awk '/^pswp(in|out) / {printf "%s=%s ", $1, $2}' /proc/vmstat)" "$(cpus)"
}
FAILED=()
set_aside() { # a runner that refuses an existing output directory
    local stamp
    stamp=$(date +%s)
    [[ ! -e $1 ]] || mv "$1" "$1.failed.$stamp"
    [[ ! -e $1.log ]] || mv "$1.log" "$1.log.failed.$stamp"
}

leg_matrix() {
    local arm=$1 r=$2 s=$3 name art rc=0 flap='' status
    name=matrix-$arm-r$r-$s
    art=$OUT/$name
    if [[ $(cat "$art/rustbgpd/status" 2>/dev/null) == pass ]]; then log "$name already pass, skip"; return; fi
    [[ $s == s2 ]] || flap=$MATRIX_FLAPSTORM
    log "$name start $(state)"
    (cd "$OUT/trees/$arm" && env FLAPSTORM="$flap" N_PEERS="$MATRIX_PEERS" \
        TOTAL_PREFIXES="$MATRIX_PREFIXES" RELOADS="$MATRIX_RELOADS" \
        CONTROL_SECS="$MATRIX_CONTROL_SECS" ARTIFACTS_DIR="$art" \
        bash bench/scale/matrix/run-matrix.sh rustbgpd) >>"$art.log" 2>&1 || rc=$?
    status=$(cat "$art/rustbgpd/status" 2>/dev/null || echo missing)
    log "$name rc=$rc status=$status $(state)"
    [[ $rc -eq 0 && $status == pass ]] || FAILED+=("$name")
}

leg_irr() {
    local arm=$1 r=$2 ov=$3 name art rc=0 tree=$OUT/trees/$1 status
    name=irr-ov$ov-$arm-r$r
    art=$OUT/$name
    if jq -e '.status == "pass"' "$art/COMPLETED" >/dev/null 2>&1; then log "$name already completed, skip"; return; fi
    set_aside "$art"
    reparent "$arm"
    log "$name start $(state)"
    # shellcheck disable=SC2086 # IRR_CELLS is a list of runner cells
    (cd "$tree" && env SMOKE="$SMOKE" CONFIRM_NO_MAIN_PUSHES="${CONFIRM_NO_MAIN_PUSHES:-}" \
        MEASUREMENT_CANDIDATE_SHA="$(git -C "$tree" rev-parse HEAD)" OVERLAP_FRACTION="$ov" \
        ARTIFACTS_DIR="$art" bash bench/scale/irrreload/run-irr-reload.sh $IRR_CELLS) \
        >"$art.log" 2>&1 || rc=$?
    status=$(jq -r .status "$art/COMPLETED" 2>/dev/null || echo missing)
    log "$name rc=$rc completed=$status $(state)"
    [[ $rc -eq 0 && $status == pass ]] || FAILED+=("$name")
}

leg_rr() {
    local arm=$1 r=$2 name art rc=0 status
    name=rr1000-$arm-c$r
    art=$OUT/$name
    if [[ $(head -n1 "$art/COMPLETED" 2>/dev/null) == pass ]]; then log "$name already completed, skip"; return; fi
    set_aside "$art"
    log "$name start $(state)"
    if [[ -n $SMOKE ]]; then
        # The tiny real-TCP fixture writes one run through the same verifier.
        (cd "$OUT/trees/$arm" && bash bench/scale/rrtransport/run-receipt.sh --real-smoke "$art/run-1") \
            >"$art.log" 2>&1 || rc=$?
        [[ $rc -ne 0 ]] || echo pass >"$art/COMPLETED"
    else
        (cd "$OUT/trees/$arm" && bash bench/scale/rrtransport/run-receipt.sh "$art") >"$art.log" 2>&1 || rc=$?
    fi
    status=$(head -n1 "$art/COMPLETED" 2>/dev/null || echo missing)
    log "$name rc=$rc completed=$status $(state)"
    [[ $rc -eq 0 && $status == pass ]] || FAILED+=("$name")
}

: >"$OUT/identity.tsv"
for arm in "${ARMS[@]}"; do setup_arm "$arm"; done
mapfile -t LEGS < <(schedule)
for leg in "${LEGS[@]}"; do
    read -r kind arm r extra <<<"$leg"
    case $kind in
        matrix) leg_matrix "$arm" "$r" "$extra" </dev/null ;;
        irr) leg_irr "$arm" "$r" "$extra" </dev/null ;;
        rr) leg_rr "$arm" "$r" </dev/null ;;
    esac
done

rc=0
python3 "$REPO/bench/scale/headline/summarize.py" "$OUT" >"$OUT/summarize.log" 2>&1 || rc=$?
[[ $rc -eq 0 ]] || log "summarize.py failed rc=$rc (see summarize.log)"
((${#FAILED[@]} == 0)) || rc=1
log "campaign done rc=$rc failed=${FAILED[*]:-none}"
exit "$rc"
