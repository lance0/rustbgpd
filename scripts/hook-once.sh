#!/usr/bin/env bash
# Run a hook command once per clean source tree.
#
#     bash scripts/hook-once.sh <check-name> -- <command> [args...]
#
# The pre-push hooks run workspace clippy, library tests and rustdoc. A
# re-push, a second worktree at the same commit, or a merge whose tree was
# just checked would otherwise rebuild and rerun all of them. This wrapper
# records a pass and skips the command when the same check already passed for
# the same inputs:
#
#   - Key: the check name, the exact command, `git rev-parse HEAD^{tree}`,
#     `rustc -V`, `cargo clippy -V`, and RUSTFLAGS / RUSTDOCFLAGS. The tree
#     hash covers Cargo.lock, `.cargo/config.toml` and every tracked source.
#   - The hooks check the working tree, not the pushed commit, so the cache is
#     read and written only when `git status --porcelain` is empty: no
#     modified, staged or untracked (non-ignored) files. Otherwise the command
#     runs and nothing is recorded.
#   - A pass is recorded only after the command exits 0.
#   - Stamps live under `<git common dir>/hook-pass-cache/`, shared by every
#     worktree of the clone, one file per key; stamps unused for 14 days are
#     pruned on each run.
#   - HOOK_ONCE_DISABLE=1 forces the command to run; a pass is still recorded.
#
# prek shows a passing hook's output only when the hook sets `verbose: true`.
# The hooks set it so this script's one-line verdict is always visible, and the
# script prints the command's own output only when the command fails.
#
# The command keeps its own locking: hooks pass `bash scripts/build-lock.sh
# cargo ...`, so the build lock is taken only when the command really runs.

set -euo pipefail

if [ "$#" -lt 3 ] || [ "$2" != "--" ]; then
    echo "usage: bash scripts/hook-once.sh <check-name> -- <command> [args...]" >&2
    exit 2
fi
name=$1
shift 2

log=$(mktemp)
trap 'rm -f "$log"' EXIT
run() {
    local status=0
    "$@" >"$log" 2>&1 || status=$?
    if [ "$status" -ne 0 ]; then
        cat "$log"
        echo "hook-once: $name failed (exit $status)"
        exit "$status"
    fi
}

if [ -n "$(git status --porcelain)" ]; then
    echo "hook-once: working tree has uncommitted or untracked files; running $name without the pass cache"
    run "$@"
    exit 0
fi

tree=$(git rev-parse 'HEAD^{tree}')
cache="$(git rev-parse --git-common-dir)/hook-pass-cache"
mkdir -p "$cache"
find "$cache" -type f -mtime +14 -delete

key=$(printf '%s\n' "check=$name" "command=$*" "tree=$tree" \
    "rustc=$(rustc -V)" "clippy=$(cargo clippy -V 2>/dev/null || true)" \
    "RUSTFLAGS=${RUSTFLAGS-}" "RUSTDOCFLAGS=${RUSTDOCFLAGS-}")
stamp="$cache/$(printf '%s' "$key" | sha256sum | cut -d' ' -f1)"

if [ "${HOOK_ONCE_DISABLE:-0}" != 1 ] && [ -f "$stamp" ]; then
    touch "$stamp"
    echo "hook-once: $name already passed for tree ${tree:0:12}; skipping (HOOK_ONCE_DISABLE=1 forces a run)"
    exit 0
fi

run "$@"
tmp=$(mktemp "$cache/.tmp.XXXXXX")
printf '%s\n' "$key" >"$tmp"
mv "$tmp" "$stamp"
echo "hook-once: $name passed for tree ${tree:0:12}; recorded"
