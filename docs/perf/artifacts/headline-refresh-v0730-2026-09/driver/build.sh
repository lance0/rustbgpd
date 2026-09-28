#!/bin/sh
# Adapted for publication: absolute scratch, checkout, repository and home paths
# are replaced with SCRATCH, WORKTREES, REPO, BGPERF2 and HOME. Otherwise as run.
# build.sh: runner three-package product build + scale harnesses, per arm tree,
# then tag-checkout daemon builds for hash comparison. Pinned to cores 40-63.
L=${SCRATCH:?}/headline-v0730
for a in v0730 v0720 v0680; do
  W=${WORKTREES:?}/headline-v0730-$a
  (cd $W && taskset -c 40-63 cargo build --release -p rustbgpd -p rustbgpctl -p rs-config-render > $L/$a-build-product.log 2>&1); echo "$a product=$?"
  (cd $W/bench/scale/reloadstall && taskset -c 40-63 cargo build --release > $L/$a-build-reloadstall.log 2>&1); echo "$a reloadstall=$?"
  (cd $W && taskset -c 40-63 cargo build --manifest-path bench/scale/Cargo.toml --locked --release -p rrtransport > $L/$a-build-rrtransport.log 2>&1); echo "$a rrtransport=$?"
done
for a in v0730 v0680; do
  W=${WORKTREES:?}/headline-v0730-tag-$a
  (cd $W && taskset -c 40-63 cargo build --release -p rustbgpd -p rustbgpctl -p rs-config-render > $L/tag-$a-build.log 2>&1); echo "tag-$a product=$?"
done
sha256sum ${WORKTREES:?}/headline-v0730-*/target/release/rustbgpd ${WORKTREES:?}/headline-v0730-*/bench/scale/target/release/reloadstall ${WORKTREES:?}/headline-v0730-v*/bench/scale/target/release/rrtransport ${WORKTREES:?}/headline-v0730-v*/target/release/rbgp ${WORKTREES:?}/headline-v0730-v*/target/release/rs-config-render
echo BUILD_DONE
