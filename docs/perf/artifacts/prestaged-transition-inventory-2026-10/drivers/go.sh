#!/usr/bin/env bash
set -u
B=<bench-dir>
until grep -qE "build-done|rc=[1-9]" $B/build-main.log; do sleep 10; done
grep -q build-done $B/build-main.log || { echo "main build failed"; exit 1; }
mkdir -p <worktree>-fix/target/scale
cp <worktree>-main/target/scale/reloadstall <worktree>-fix/target/scale/reloadstall
sha256sum <worktree>-*/target/release/rustbgpd <worktree>-*/target/scale/reloadstall
m=$(sha256sum <worktree>-main/target/release/rustbgpd | cut -d' ' -f1); f=$(sha256sum <worktree>-fix/target/release/rustbgpd | cut -d' ' -f1)
[ "$m" != "$f" ] || { echo "IDENTICAL DAEMONS, refusing"; exit 2; }
echo "daemons differ; starting A/B $(date -Is)"
exec $B/run-ab.sh
