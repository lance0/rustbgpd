#!/bin/sh
# Adapted for publication: absolute scratch, checkout, repository and home paths
# are replaced with SCRATCH, WORKTREES, REPO, BGPERF2 and HOME. Otherwise as run.
# Run inline before the window (recorded here as a script): in each arm's own
# build directory, check out the real tag commit, re-run the three-package
# build, and compare the daemon hash; then return to the local control commit.
L=${SCRATCH:?}/headline-v0730
for a in v0730:v0.73.0 v0720:v0.72.0 v0680:v0.68.0; do arm=${a%%:*}; tag=${a#*:}; W=${WORKTREES:?}/headline-v0730-$arm; cd $W; ctl=$(git rev-parse HEAD); before=$(sha256sum target/release/rustbgpd | cut -c1-64); git checkout -q --detach $tag; taskset -c 40-63 cargo build --release -p rustbgpd -p rustbgpctl -p rs-config-render > $L/$arm-tagcheck-build.log 2>&1; rc=$?; after=$(sha256sum target/release/rustbgpd | cut -c1-64); git checkout -q --detach $ctl; echo "$arm tag=$tag ctl=$ctl rc=$rc compiled=$(grep -c Compiling $L/$arm-tagcheck-build.log) before=$before after=$after same=$([ $before = $after ] && echo yes || echo no)"; done | tee $L/tagcheck.txt
