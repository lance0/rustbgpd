#!/usr/bin/env bash
# Usage: build.sh NEW_ABSOLUTE_BUILD_RECEIPT [diagnostic]
# Run sequentially after gates/commit, with no concurrent Cargo builds or labs.
# Normal:     build.sh /tmp/readiness-build-UNIQUE
# Diagnostic: build.sh /tmp/readiness-diagnostic-build-UNIQUE diagnostic
# Pristine binaries live in RECEIPT.MODE.binary-store beside the receipt.
# This script builds and stages binaries; it never launches a fixture.
set -euo pipefail
umask 022
ulimit -n 65536
repo=/tmp/readiness-source
primary=/tmp/readiness-build-cache
prep=/tmp/readiness-acceptance-prep
[[ $# == 1 || ( $# == 2 && $2 == diagnostic ) ]] || {
    echo 'usage: build.sh NEW_ABSOLUTE_BUILD_RECEIPT [diagnostic]' >&2
    exit 2
}
[[ $1 == /* ]] || { echo 'build receipt must be absolute' >&2; exit 2; }
build=$(realpath -m -- "$1")
mode=${2:-normal}
store="$build.$mode.binary-store"
case "$build/" in
    "$repo/"* | "$primary/"*)
        echo 'build receipt must be outside both repositories and Cargo caches' >&2
        exit 2 ;;
esac
[[ ! -e $build && ! -L $build && ! -e $store && ! -L $store ]] || {
    echo 'build receipt and sibling binary store must both be new' >&2
    exit 2
}

# Accept only the exact owned cache symlinks, or a complete previous private
# stage containing precisely release/{rustbgpd,rbgp} and release/reloadstall.
# Refuse partial stages, extra cache files, unexpected links, or other layouts.
verify_staging() {
    python3 - "$repo" "$primary" <<'PY'
from pathlib import Path
import sys
repo, primary = map(Path, sys.argv[1:])
for relative, binaries in [('target', {'rustbgpd', 'rbgp'}),
                           ('bench/scale/target', {'reloadstall'})]:
    stage, cache = repo / relative, primary / relative
    if stage.is_symlink():
        if str(stage.readlink()) != str(cache):
            raise SystemExit(f'unexpected target symlink: {stage} -> {stage.readlink()}')
        if not cache.is_dir():
            raise SystemExit(f'missing primary Cargo cache: {cache}')
        continue
    release = stage / 'release'
    if (not stage.is_dir() or stage.resolve() != stage
            or {p.name for p in stage.iterdir()} != {'release'}
            or not release.is_dir() or release.is_symlink()
            or {p.name for p in release.iterdir()} != binaries
            or any(not p.is_file() or p.is_symlink() for p in release.iterdir())):
        raise SystemExit(f'refusing unexpected private stage layout: {stage}')
PY
}
verify_staging
mkdir "$build"
trap 'build_rc=$?; printf "%s\n" "$build_rc" >"$build/build.exit"' EXIT
printf '%s\n' "$mode" >"$build/build-mode"
printf '%s\n' "$store" >"$build/binary-store-path"
cp "$prep/build.sh" "$prep/snapshot.py" "$build/"
cd "$repo"
python3 "$build/snapshot.py" "$build/before"
date -u +%FT%TZ >"$build/started-at"
env -i "PATH=$PATH" "HOME=$HOME" rustc -Vv >"$build/rustc.txt"
env -i "PATH=$PATH" "HOME=$HOME" cargo -V >"$build/cargo.txt"
daemon=(env -i "PATH=$PATH" "HOME=$HOME" CARGO_BUILD_JOBS=8
    cargo build --locked --release -p rustbgpd -p rustbgpctl
    --target-dir "$primary/target")
if [[ $mode == diagnostic ]]; then
    daemon+=(--features rustbgpd-rib/bench-internals)
fi
harness=(env -i "PATH=$PATH" "HOME=$HOME" CARGO_BUILD_JOBS=8
    cargo build --locked --release
    --manifest-path bench/scale/reloadstall/Cargo.toml
    --target-dir "$primary/bench/scale/target")
printf '%q ' "${daemon[@]}" >"$build/commands.txt"
printf '\n' >>"$build/commands.txt"
printf '%q ' "${harness[@]}" >>"$build/commands.txt"
printf '\n' >>"$build/commands.txt"
rc=0
"${daemon[@]}" >"$build/daemon.log" 2>&1 || rc=$?
printf '%s\n' "$rc" >"$build/daemon.exit"
[[ $rc == 0 ]] || exit "$rc"
rc=0
"${harness[@]}" >"$build/harness.log" 2>&1 || rc=$?
printf '%s\n' "$rc" >"$build/harness.exit"
[[ $rc == 0 ]] || exit "$rc"

# Retain the full post-build source identity before touching owned symlinks.
python3 "$build/snapshot.py" "$build/after"
cmp "$build/before/source.json" "$build/after/source.json"
cmp "$build/before/git-head" "$build/after/git-head"
for binary in "$primary/target/release/rustbgpd" "$primary/target/release/rbgp" \
    "$primary/bench/scale/target/release/reloadstall"; do
    [[ -f $binary && -x $binary && ! -L $binary ]] || {
        echo "expected regular executable from the primary build: $binary" >&2
        exit 1
    }
done
sha256sum "$primary/target/release/rustbgpd" "$primary/target/release/rbgp" \
    "$primary/bench/scale/target/release/reloadstall" >"$build/cache-binaries.sha256"
mkdir "$store"
cp --reflink=auto --preserve=mode "$primary/target/release/rustbgpd" "$store/rustbgpd"
cp --reflink=auto --preserve=mode "$primary/target/release/rbgp" "$store/rbgp"
cp --reflink=auto --preserve=mode "$primary/bench/scale/target/release/reloadstall" "$store/reloadstall"
chmod a-w "$store/rustbgpd" "$store/rbgp" "$store/reloadstall"
sha256sum -c "$build/cache-binaries.sha256" >"$build/cache-copy-check.log"
for binary in rustbgpd rbgp; do cmp "$primary/target/release/$binary" "$store/$binary"; done
cmp "$primary/bench/scale/target/release/reloadstall" "$store/reloadstall"
(cd "$store" && sha256sum rustbgpd rbgp reloadstall >binaries.sha256)

# Validate both roots together immediately before detaching either one.
verify_staging
for relative in target bench/scale/target; do
    stage="$repo/$relative"
    if [[ -L $stage ]]; then
        [[ $(readlink -- "$stage") == "$primary/$relative" ]]
        unlink -- "$stage"  # Unlink only this verified symlink, never its target.
        mkdir "$stage" "$stage/release"
    fi
    [[ $(realpath -- "$stage") == "$stage" && ! -L $stage/release ]]
done
# Remove a previous private destination before copying, so even a hardlinked
# stage file cannot cause writes through to an existing cache/store inode.
cp --reflink=auto --remove-destination --preserve=mode "$store/rustbgpd" "$repo/target/release/rustbgpd"
cp --reflink=auto --remove-destination --preserve=mode "$store/rbgp" "$repo/target/release/rbgp"
cp --reflink=auto --remove-destination --preserve=mode "$store/reloadstall" "$repo/bench/scale/target/release/reloadstall"
verify_staging
for binary in rustbgpd rbgp; do cmp "$store/$binary" "target/release/$binary"; done
cmp "$store/reloadstall" bench/scale/target/release/reloadstall
sha256sum target/release/rustbgpd target/release/rbgp \
    bench/scale/target/release/reloadstall >"$build/binaries.sha256"
sha256sum -c "$build/binaries.sha256" >"$build/staged-binary-check.log"
sha256sum -c "$build/cache-binaries.sha256" >"$build/cache-check-after-stage.log"
date -u +%FT%TZ >"$build/finished-at"
printf 'Prepared %s build receipt: %s\nPristine binary store: %s\n' "$mode" "$build" "$store"
