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
#     `rustc -V`, `cargo clippy -V`, and the environment variables listed in
#     KEYED_ENV / KEYED_ENV_PREFIXES below. The tree hash covers Cargo.lock,
#     `.cargo/config.toml` and every tracked source.
#   - The hooks check the working tree, not the pushed commit, so the cache is
#     read and written only when `git status --porcelain` is empty: no
#     modified, staged or untracked (non-ignored) files. Otherwise the command
#     runs and nothing is recorded.
#   - A pass is recorded only after the command exits 0 and only if the working
#     tree is still clean at the same tree afterward: a fixture-blessing run can
#     rewrite tracked files, and HEAD can move during a minute-long run.
#   - When a variable in BYPASS_ENV is set (fixture-blessing modes), the command
#     runs and the cache is neither read nor written.
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

# Extend these when a test, build script or Cargo setting reads a new variable:
# key it when its value changes what a check validates, bypass it when the run
# rewrites tracked files.
KEYED_ENV=(
    RUSTFLAGS RUSTDOCFLAGS CARGO_BUILD_RUSTFLAGS CARGO_BUILD_RUSTDOCFLAGS
    CARGO_ENCODED_RUSTFLAGS CARGO_ENCODED_RUSTDOCFLAGS CARGO_BUILD_TARGET
    RUSTC RUSTDOC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTC_BOOTSTRAP
    ORACLE_STRICT
    RUSTBGPD_TEST_FLUSH_BUDGET_US RUSTBGPD_TEST_OUTBOUND_ROW_CREDIT
    RUSTBGPD_TEST_RIB_INGEST_STALL_MS RUSTBGPD_TEST_RIB_PANIC_ON_PEER_UP
)
KEYED_ENV_PREFIXES='^(PROPTEST_|RUST_TEST_|CARGO_PROFILE_)'
BYPASS_ENV=(BLESS RPOL_LEX_GOLDEN_BLESS RPOL_DECISION_GOLDEN_BLESS REGENERATE_BGPKIT_FIXTURES)

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
uncached() {
    echo "hook-once: $1; running $name without the pass cache"
    shift
    run "$@"
    exit 0
}

for var in "${BYPASS_ENV[@]}"; do
    if [ -n "${!var+set}" ]; then
        uncached "$var is set" "$@"
    fi
done
if [ -n "$(git status --porcelain)" ]; then
    uncached "working tree has uncommitted or untracked files" "$@"
fi

tree=$(git rev-parse 'HEAD^{tree}')
cache="$(git rev-parse --git-common-dir)/hook-pass-cache"
mkdir -p "$cache"
find "$cache" -type f -mtime +14 -delete

env_key=()
for var in "${KEYED_ENV[@]}"; do
    if [ -n "${!var+set}" ]; then
        env_key+=("$var=${!var}")
    fi
done
while read -r var; do
    env_key+=("$var=${!var}")
done < <(compgen -e | grep -E "$KEYED_ENV_PREFIXES" | sort || true)

key=$(printf '%s\n' "check=$name" "command=$*" "tree=$tree" \
    "rustc=$(rustc -V)" "clippy=$(cargo clippy -V 2>/dev/null || true)" \
    ${env_key[@]+"${env_key[@]}"})
stamp="$cache/$(printf '%s' "$key" | sha256sum | cut -d' ' -f1)"

if [ "${HOOK_ONCE_DISABLE:-0}" != 1 ] && [ -f "$stamp" ]; then
    touch "$stamp"
    echo "hook-once: $name already passed for tree ${tree:0:12}; skipping (HOOK_ONCE_DISABLE=1 forces a run)"
    exit 0
fi

run "$@"
if [ -n "$(git status --porcelain)" ] || [ "$(git rev-parse 'HEAD^{tree}')" != "$tree" ]; then
    echo "hook-once: working tree or HEAD changed during the run; $name ran without the pass cache"
    exit 0
fi
tmp=$(mktemp "$cache/.tmp.XXXXXX")
printf '%s\n' "$key" >"$tmp"
mv "$tmp" "$stamp"
echo "hook-once: $name passed for tree ${tree:0:12}; recorded"
