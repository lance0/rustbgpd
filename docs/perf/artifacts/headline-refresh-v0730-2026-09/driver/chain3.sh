#!/bin/sh
# Adapted for publication: absolute scratch, checkout, repository and home paths
# are replaced with SCRATCH, WORKTREES, REPO, BGPERF2 and HOME. Otherwise as run.
L=${SCRATCH:?}
until grep -q 'campaign xh rc=' $L/headline-v0730/campaign/progress.txt; do sleep 30; done
$L/headline-v0730/run-window3.sh irrx
