#!/bin/sh
# Adapted for publication: absolute scratch, checkout, repository and home paths
# are replaced with SCRATCH, WORKTREES, REPO, BGPERF2 and HOME. Otherwise as run.
# Detached campaign wrapper: quiet-window file + bench and gate locks for the whole run.
L=${SCRATCH:?}
PHASE=${1:-all}
touch $L/quiet-window
date -Is >> $L/headline-v0730/window-start
trap 'rm -f $L/quiet-window; date -Is >> $L/headline-v0730/window-end' EXIT INT TERM
flock $L/bench.lock flock $L/gate.lock $L/headline-v0730/campaign3.sh $PHASE
echo "campaign $PHASE rc=$?" >> $L/headline-v0730/campaign/progress.txt
