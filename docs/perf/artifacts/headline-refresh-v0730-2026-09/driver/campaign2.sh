#!/usr/bin/env bash
# Adapted for publication: absolute scratch, checkout, repository and home paths
# are replaced with SCRATCH, WORKTREES, REPO, BGPERF2 and HOME. Otherwise as run.
# Headline refresh campaign, three arms (v0.73.0 / v0.72.0 / v0.68.0 trees),
# derived from the 2026-09-26 driver. Strictly sequential; arm order rotates
# per run (Latin square). Each arm runs its own tree's runners and harnesses.
# Phases: matrix | irr | rr | irrov | all.
set -u
L=${SCRATCH:?}/headline-v0730
C=$L/campaign
ARMS=(v0730 v0720 v0680 xh)
log() { echo "[$(date -Is)] $*" | tee -a $C/progress.txt; }
tree_of() { echo ${WORKTREES:?}/headline-v0730-$1; }
swap() { awk '/^pswpin|^pswpout/{printf "%s=%s ", $1, $2}' /proc/vmstat; }
# Rotated arm order for run r (1-based).
order() { local r=$1 i; for i in 0 1 2; do echo ${ARMS[$(( (i + r - 1) % 3 ))]}; done; }
# Cross-harness block: v0.68.0 daemon under the v0.72.0 harness (xh), interleaved
# with the v0.68.0 own-harness arm.
xh() {
  for r in 4 5 6; do
    local pair="xh v0680"; [ $r = 5 ] && pair="v0680 xh"
    for arm in $pair; do for s in s2 s3; do
      check_trees
      local extra=""; [ $s = s3 ] && extra="FLAPSTORM=50"
      local art=$C/matrix-$arm-r$r-$s
      [ -f $art/rustbgpd/status ] && grep -q pass $art/rustbgpd/status && { log "matrix $arm r$r $s already pass, skip"; continue; }
      log "matrix $arm r$r $s start load=$(cut -d' ' -f1-3 /proc/loadavg) $(swap)"
      (cd $(tree_of $arm) && env $extra RUSTBGPD_HOST_QUIET_TIMEOUT_SECS=1800 N_PEERS=700 TOTAL_PREFIXES=400400 \
          RELOADS=4 CONTROL_SECS=30 PORT=1790 ARTIFACTS_DIR=$art \
          bash bench/scale/matrix/run-matrix.sh rustbgpd) > $art.log 2>&1
      log "matrix $arm r$r $s rc=$? status=$(cat $art/rustbgpd/status 2>/dev/null) $(swap)"
    done; done
  done
}
# Keep each measured tree a direct child of origin/main (IRR source gate).
# The tree never changes; only the local, never-pushed commit is re-parented.
check_trees() {
  local a t head parent main tree
  git -C $(tree_of v0730) fetch -q origin main
  main=$(git -C $(tree_of v0730) rev-parse origin/main)
  for a in "${ARMS[@]}"; do
    t=$(tree_of $a)
    [ -z "$(git -C $t status --porcelain --untracked-files=no)" ] || { log "STOP: $a tree dirty"; exit 1; }
    head=$(git -C $t rev-parse HEAD); parent=$(git -C $t rev-parse HEAD^)
    if [ "$parent" != "$main" ]; then
      tree=$(git -C $t rev-parse HEAD^{tree})
      new=$(git -C $t commit-tree $tree -p $main -m "local measurement control: $a tree (never pushed)")
      git -C $t checkout -q --detach $new || { log "STOP: reparent $a failed"; exit 1; }
      log "reparented $a $head -> $new (tree $tree, origin/main $main)"
    fi
  done
}
matrix() {
  for r in 1 2 3; do for arm in $(order $r); do for s in s2 s3; do
    check_trees
    local extra=""; [ $s = s3 ] && extra="FLAPSTORM=50"
    local art=$C/matrix-$arm-r$r-$s
    [ -f $art/rustbgpd/status ] && grep -q pass $art/rustbgpd/status && { log "matrix $arm r$r $s already pass, skip"; continue; }
    log "matrix $arm r$r $s start load=$(cut -d' ' -f1-3 /proc/loadavg) $(swap)"
    (cd $(tree_of $arm) && env $extra RUSTBGPD_HOST_QUIET_TIMEOUT_SECS=1800 N_PEERS=700 TOTAL_PREFIXES=400400 \
        RELOADS=4 CONTROL_SECS=30 PORT=1790 ARTIFACTS_DIR=$art \
        bash bench/scale/matrix/run-matrix.sh rustbgpd) > $art.log 2>&1
    log "matrix $arm r$r $s rc=$? status=$(cat $art/rustbgpd/status 2>/dev/null) $(swap)"
  done; done; done
}
irr() {
  local ov=${1:-0} cells=${2:-rustbgpd-sighup}
  for r in 1 2 3; do for arm in $(order $r); do
    check_trees
    local t=$(tree_of $arm)
    local art=$C/irr-ov$ov-$arm-r$r
    [ -f $art/COMPLETED ] && { log "irr ov=$ov $arm r$r already completed, skip"; continue; }
    log "irr ov=$ov $arm r$r cells=$cells start load=$(cut -d' ' -f1-3 /proc/loadavg) $(swap)"
    (cd $t && CONFIRM_NO_MAIN_PUSHES=1 MEASUREMENT_CANDIDATE_SHA=$(git -C $t rev-parse HEAD) \
        OVERLAP_FRACTION=$ov ARTIFACTS_DIR=$art RUSTBGPD_HOST_QUIET_TIMEOUT_SECS=1800 \
        bash bench/scale/irrreload/run-irr-reload.sh $cells) > $art.log 2>&1
    log "irr ov=$ov $arm r$r rc=$? completed=$(cat $art/COMPLETED 2>/dev/null | tr -d '\n ') $(swap)"
  done; done
}
rr() {
  for r in 1 2 3; do for arm in $(order $r); do
    check_trees
    local art=$C/rr1000-$arm-c$r
    [ -f $art/COMPLETED ] && { log "rr1000 $arm c$r already completed, skip"; continue; }
    log "rr1000 $arm c$r start load=$(cut -d' ' -f1-3 /proc/loadavg) $(swap)"
    (cd $(tree_of $arm) && bash bench/scale/rrtransport/run-receipt.sh $art) > $art.log 2>&1
    log "rr1000 $arm c$r rc=$? completed=$(cat $art/COMPLETED 2>/dev/null) $(swap)"
  done; done
}
case "${1:-all}" in
  matrix) matrix ;; irr) irr 0 ;; rr) rr ;; xh) xh ;;
  irrov) irr 0.1 "rustbgpd-sighup bird"; irr 0.5 "rustbgpd-sighup bird" ;;
  all) matrix; irr 0; rr ;;
esac
log "phase ${1:-all} done"
