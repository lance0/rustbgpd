#!/usr/bin/env bash
# Repository build mutex for the local check loop.
#
# `just gate` and the pre-commit / pre-push hooks each compile the whole
# workspace into the same target directory. Running two of them at once
# doubles peak CPU and memory for no extra coverage, and the contention has
# already stalled an interactive session mid-release. Every heavy local check
# takes an exclusive `flock` on one file first, so the second caller waits for
# the first instead of racing it.
#
#   - Path: ${RUSTBGPD_BUILD_LOCK:-${CARGO_TARGET_DIR:-target}/build.lock}.
#     The lock lives beside the artifacts it protects, so two worktrees with
#     separate target directories still build in parallel while a gate and a
#     push in one tree serialize. Worktrees that share a target directory
#     share the lock, which is the intended behavior: they share the
#     contention too.
#   - Wait rather than fail. `tests/soak/host-lock.sh` guards measurement
#     runs, where a concurrent workload corrupts the reading and failing fast
#     is correct. Here the second caller wants its checks to run, so the wait
#     is unbounded and announced once on stderr.
#   - A crashed holder cannot wedge the repository. `flock` is a property of
#     the open file description, so the kernel drops it when the holder exits
#     for any reason. There is no stale lock file to clean up, and the file
#     itself is disposable.
#   - The fd is allocated to the caller's shell (`exec {fd}>...`), so the lock
#     lives for the rest of the caller's process and is released on exit. The
#     caller does not unlock explicitly.
#
# Source it to hold the lock across several commands:
#
#     source scripts/build-lock.sh
#     acquire_rustbgpd_build_lock
#
# Or execute it to hold the lock around one command:
#
#     bash scripts/build-lock.sh cargo doc --locked --workspace --lib

acquire_rustbgpd_build_lock() {
    local build_lock="${RUSTBGPD_BUILD_LOCK:-${CARGO_TARGET_DIR:-target}/build.lock}"
    mkdir -p "$(dirname "$build_lock")"
    # shellcheck disable=SC1083  # bash {fd} redirection is intentional
    exec {RUSTBGPD_BUILD_LOCK_FD}>"$build_lock"
    if ! flock -n "$RUSTBGPD_BUILD_LOCK_FD"; then
        echo "waiting for ${build_lock}: another gate, commit, or push is building" >&2
        flock "$RUSTBGPD_BUILD_LOCK_FD"
    fi
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    set -euo pipefail
    if [ "$#" -eq 0 ]; then
        echo "usage: bash scripts/build-lock.sh <command> [args...]" >&2
        exit 2
    fi
    acquire_rustbgpd_build_lock
    exec "$@"
fi
