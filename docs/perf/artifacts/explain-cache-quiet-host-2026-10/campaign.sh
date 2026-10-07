#!/usr/bin/env bash
# Run under: flock "$HOME/.local/state/rustbgpd-host.lock" campaign.sh
# The canonical host lock is held by that outer flock for the whole campaign;
# the runner's own per-cell exclusive lock points at a campaign-private file
# because a second open of the canonical file would conflict with the holder.
set -u
BASE=${BASE:?output directory}
WT=${WT:?clean worktree at the measured commit}
LOG=$BASE/campaign.log
log() { echo "$(date -u +%FT%TZ) $*" >>"$LOG"; }
log "campaign start pid=$$ head=$(git -C "$WT" rev-parse HEAD)"

log "prebuild start"
(cd "$WT" && env -u CARGO_TARGET_DIR -u RUSTFLAGS cargo build --profile release --locked -p rustbgpd -p rustbgpctl) \
    >"$BASE/prebuild-root.log" 2>&1; r1=$?
(cd "$WT" && env -u CARGO_TARGET_DIR -u RUSTFLAGS cargo build --profile scale --locked \
    --manifest-path bench/scale/reloadstall/Cargo.toml) >"$BASE/prebuild-harness.log" 2>&1; r2=$?
log "prebuild root_rc=$r1 harness_rc=$r2"
((r1 == 0 && r2 == 0)) || { log "prebuild failed"; echo 1 >"$BASE/campaign.exit"; exit 1; }

wait_quiet() {   # scheduling only; the runner's own preflight still gates
    local end=$((SECONDS + 3600)) procs load
    while ((SECONDS < end)); do
        procs=$(ps -eo comm= | awk '$1=="cargo"||$1=="rustc"||$1=="rustbgpd"||$1=="reloadstall"||$1=="perf"||$1~/^rrharness/||$1~/^bgperf/' | sort -u | paste -sd, -)
        load=$(cut -d' ' -f1 /proc/loadavg)
        if [[ -z $procs ]] && awk -v l="$load" 'BEGIN{exit !(l < 1.8)}'; then
            log "quiet load=$load"; return 0; fi
        sleep 5
    done
    log "quiet wait expired (procs=${procs:-none} load=$load); launching anyway"
}

COMMON=(REPO="$WT" OUTBASE="$BASE/cells" RUSTBGPD_HOST_LOCK="$BASE/cell.lock"
        RELOADS=0 CONTROL_SECS=10 COLD_CAP=600 OVERALL_CAP=1500 RSS_LIMIT_KIB=16777216)
CELLS=(
  "a-off-r1 PEERS=2 TOTAL=2000000 EXPLAIN=false"
  "b-4096-r1 PEERS=2 TOTAL=2000000 EXPLAIN=true CACHE_SIZE=4096"
  "c-262144-r1 PEERS=2 TOTAL=2000000 EXPLAIN=true CACHE_SIZE=262144"
  "d-1048576-r1 PEERS=2 TOTAL=2000000 EXPLAIN=true CACHE_SIZE=1048576"
  "e-1000x400-4096 PEERS=1000 TOTAL=400000 EXPLAIN=true CACHE_SIZE=4096"
  "f-1000x400-1048576 PEERS=1000 TOTAL=400000 EXPLAIN=true CACHE_SIZE=1048576"
  "a-off-r2 PEERS=2 TOTAL=2000000 EXPLAIN=false"
  "b-4096-r2 PEERS=2 TOTAL=2000000 EXPLAIN=true CACHE_SIZE=4096"
  "c-262144-r2 PEERS=2 TOTAL=2000000 EXPLAIN=true CACHE_SIZE=262144"
  "d-1048576-r2 PEERS=2 TOTAL=2000000 EXPLAIN=true CACHE_SIZE=1048576"
)
mkdir -p "$BASE/cells"
worst=0
for spec in "${CELLS[@]}"; do
    read -r label vars <<<"$spec"
    wait_quiet
    log "cell $label start ($vars)"
    # shellcheck disable=SC2086
    systemd-run --user --scope --quiet --unit="explain-cache-$label" -p MemorySwapMax=0 -p Delegate=yes -- \
        env "${COMMON[@]}" LABEL="$label" CGOUT="$BASE/cgroup/$label" $vars \
        bash "$(dirname "$0")/cgroup-cell-wrapper.sh"
    rc=$?
    log "cell $label rc=$rc"
    ((rc == 0)) || worst=1
done
log "campaign end worst=$worst"
echo "$worst" >"$BASE/campaign.exit"
exit "$worst"
