#!/usr/bin/env bash
# Canonical host mutex for soak and production benchmark receipt runners.
#
# When soak and benchmark runners share a host, letting them touch CPU / memory
# / FIB at the same time would corrupt every reading. Each workload acquires an
# exclusive `flock` on the same path before doing real work.
#
# Source this file from a production benchmark or soak entrypoint and call
# `acquire_rustbgpd_host_lock` after log redirection is set up (so the
# success/failure line is retained) but before any container, daemon, or churn
# driver starts.
#
# The Criterion comparison runner inlines equivalent semantics; keep its block
# behaviorally aligned with this helper.
#
#   - Path: ${RUSTBGPD_HOST_LOCK:-${HOME}/.local/state/rustbgpd-host.lock}.
#   - Always lock; create the lock dir if missing. (An earlier
#     "skip when ${HOME}/.local/state is absent" escape hatch silently
#     disabled the mutex on the shared soak/bench box, where that dir
#     did not exist — soak and nightly bench then ran unprotected. An
#     uncontended lock is free, so always taking it is harmless on a
#     local dev box and correct on the shared host.) The soak runner
#     and the GitHub Actions bench runner both run as the same user, so
#     the per-user default path resolves to one shared file.
#   - Use `flock -n` so the wait is the operator's problem to resolve,
#     not the script's. A held lock fails fast (return 75 — "host
#     busy") with a clear message.
#   - The fd is allocated to the caller's shell (`exec {fd}>...`),
#     so the lock lives for the rest of the caller's process and is
#     released automatically on exit. The caller does not need to
#     unlock explicitly.
#
# sudo / $HOME trap:
#
#   When the soak runs under sudo, $HOME flips to /root (or whatever
#   sudo configures), so the default lock path moves to
#   /root/.local/state/rustbgpd-host.lock — a DIFFERENT file from the
#   bench runner's lock under $HOME/.local/state. The two
#   workloads would not see each other. The convention on the
#   shared host is: run containerlab deploy/destroy with sudo where
#   required, but invoke the soak harness as the normal user.
#   If sudo is unavoidable, export RUSTBGPD_HOST_LOCK explicitly:
#
#       sudo RUSTBGPD_HOST_LOCK=/home/<bench-user>/.local/state/rustbgpd-host.lock \
#           bash tests/soak/run-<gate>-soak.sh
#
#   See tests/soak/README.md ("Host mutex") for the full rationale.

acquire_rustbgpd_host_lock() {
    local host_lock="${RUSTBGPD_HOST_LOCK:-${HOME}/.local/state/rustbgpd-host.lock}"
    mkdir -p "$(dirname "$host_lock")"
    touch "$host_lock"
    # shellcheck disable=SC1083  # bash {fd} redirection is intentional
    exec {RUSTBGPD_HOST_LOCK_FD}>"$host_lock"
    if ! flock -n "$RUSTBGPD_HOST_LOCK_FD"; then
        echo "error: ${host_lock} is held by another process (soak or bench)" >&2
        echo "       wait for it to finish or remove the lock if stale" >&2
        return 75 # EX_TEMPFAIL — host busy, retry later
    fi
    echo "acquired host lock: ${host_lock}"
}
