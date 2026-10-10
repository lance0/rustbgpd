#!/usr/bin/env bash
# Usage: build-arm.sh ARM  -- release daemon (+ scale harness for main) into the arm's OWN target dir, under the host lock.
set -u
ARM=$1; W=<worktree>-$ARM
echo "build $ARM start $(date -Is) head=$(git -C $W rev-parse HEAD) diff=$(git -C $W diff | sha256sum | cut -c1-12)"
cd $W || exit 1
flock <host-lock> taskset -c 40-63 env CARGO_TARGET_DIR=$W/target cargo build --release --locked -q -p rustbgpd --bin rustbgpd
rc=$?; echo "daemon $ARM rc=$rc $(date -Is)"; [ $rc = 0 ] || exit $rc
if [ "$ARM" = main ]; then
  flock <host-lock> taskset -c 40-63 env CARGO_TARGET_DIR=$W/target cargo build --profile scale --locked -q -p reloadstall
  rc=$?; echo "harness rc=$rc $(date -Is)"; [ $rc = 0 ] || exit $rc
fi
sha256sum $W/target/release/rustbgpd
echo build-done
