#!/usr/bin/env bash
# Usage: run-leg.sh ARM LEGNAME  (ARM = main|fix)
# One S2 rustbgpd-only matrix leg under a blocking outer flock on the shared host lock, held for this
# one leg only (as the 2026-10-04 stall scout's run-leg2.sh). The runner's inner lock is redirected to
# a private file; the 300 s post-cell cool-down is cut (runner + its children killed by exact PID).
set -u
O=<bench-dir>
ARM=$1; LEG=$2; WT=<worktree>-$ARM
[ "$(date -u +%H%M)" -ge 0222 ] && [ "$(date -u +%H%M)" -lt 1200 ] && { echo "past 02:22Z, not starting"; exit 3; }
rm -rf $O/$LEG; mkdir -p $O/$LEG
echo "leg $LEG ($ARM) waiting for host lock $(date -Is)"
exec 9><host-lock>
flock 9
echo "leg $LEG ($ARM) acquired host lock $(date -Is) head=$(git -C $WT rev-parse HEAD) daemon=$(sha256sum $WT/target/release/rustbgpd | cut -c1-16) harness=$(sha256sum $WT/target/scale/reloadstall | cut -c1-16)"
[ "$(date -u +%H%M)" -ge 0222 ] && [ "$(date -u +%H%M)" -lt 1200 ] && { echo "past 02:22Z, not starting"; exit 3; }
(cd $WT && exec env RUSTBGPD_HOST_LOCK=$O/inner-runner.lock ARTIFACTS_DIR=$O/$LEG bash bench/scale/matrix/run-matrix.sh rustbgpd) > $O/$LEG.log 2>&1 &
rpid=$!
rc=""
while kill -0 $rpid 2>/dev/null; do
  if grep -q "^cool-down 300s" $O/$LEG.log; then
    for c in $(pgrep -P $rpid); do kill $c; done; kill $rpid; wait $rpid; rc=0; echo "cut cool-down"; break
  fi
  sleep 1
done
[ -z "$rc" ] && { wait $rpid; rc=$?; }
st=$(cat $O/$LEG/rustbgpd/status 2>/dev/null)
echo "leg $LEG ($ARM) runner rc=$rc status=$st $(date -Is)"
[ "$st" = pass ]
