#!/bin/sh
# Adapted for publication: absolute scratch, checkout, repository and home paths
# are replaced with SCRATCH, WORKTREES, REPO, BGPERF2 and HOME. Otherwise as run.
# Run inline before the window (recorded here as a script): local, never-pushed
# control commits (tag tree, parent origin/main) for the IRR source gate, arm
# checkouts, and the cross-harness checkout (v0.72.0 tree, v0.68.0 daemon,
# v0.72.0 reloadstall). Binaries are copied, not rebuilt.
cd ${REPO:?} && M=$(git rev-parse origin/main)
for a in v0.73.0:v0730 v0.72.0:v0720 v0.68.0:v0680; do
  tag=${a%%:*}; arm=${a#*:}
  c=$(git commit-tree "$tag^{tree}" -p $M -m "local measurement control: $tag tree (never pushed)")
  git worktree add --detach ${WORKTREES:?}/headline-v0730-$arm $c
done
git worktree add --detach ${WORKTREES:?}/headline-v0730-xh $(git -C ${WORKTREES:?}/headline-v0730-v0720 rev-parse HEAD)
X=${WORKTREES:?}/headline-v0730-xh; mkdir -p $X/target/release $X/bench/scale/target/release
cp ${WORKTREES:?}/headline-v0730-v0680/target/release/rustbgpd $X/target/release/rustbgpd
cp ${WORKTREES:?}/headline-v0730-v0720/bench/scale/target/release/reloadstall $X/bench/scale/target/release/reloadstall
# Untimed dry runs: IRR smoke on the v0.68.0 arm, rrtiny on every arm.
L=${SCRATCH:?}/headline-v0730
cd ${WORKTREES:?}/headline-v0730-v0680 && SMOKE=1 CONFIRM_NO_MAIN_PUSHES=1 MEASUREMENT_CANDIDATE_SHA=$(git rev-parse HEAD) ARTIFACTS_DIR=$L/dryrun-irr-v0680 timeout 1800 bash bench/scale/irrreload/run-irr-reload.sh rustbgpd-sighup > $L/dryrun-irr-v0680.log 2>&1; echo "irr-smoke-v0680=$?"
for w in v0730 v0720 v0680; do cd ${WORKTREES:?}/headline-v0730-$w && rm -rf $L/dryrun-rrtiny-$w && timeout 600 ./bench/scale/target/release/rrtransport rrtiny $L/dryrun-rrtiny-$w > $L/dryrun-rrtiny-$w.log 2>&1; echo "rrtiny-$w=$?"; done
