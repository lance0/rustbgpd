#!/usr/bin/env bash
# Canonical file-descriptor headroom guard for the bare-host flagship soaks.
#
# A scaled daemon holds one socket per peer plus the gRPC/metrics listeners,
# their accepted connections, the event-history store, and the MRT/journal
# files. Launched from a bare shell it inherits the caller's `RLIMIT_NOFILE`
# soft limit, which on a stock login session is 1024 — under the 1000-peer
# flagship shape the last few descriptors are consumed by peer sockets and
# every subsequent `accept()` on the metrics listener fails with EMFILE. That
# state is invisible to a client-side gate: the scrapes that do get served
# still return 200, so the run reports green while measuring a crippled
# daemon.
#
# Source this file from a soak entrypoint and call `require_fd_headroom`
# from the runner's own shell (never a subshell — `ulimit` applies to the
# calling process and is inherited by the daemon it forks) before the daemon
# is started. It is fail-closed: a soak that cannot get descriptor headroom
# must not run.
#
#   - Target: ${SOAK_NOFILE_SOFT:-65536}, matching the soft limit the
#     shipped systemd and container units pin
#     (examples/systemd/rustbgpd-container.service,
#     scripts/check_release_install_contract.py). The soak measures the
#     configuration the project ships, not whatever the invoking shell had.
#   - Raising the soft limit needs no privilege while it stays at or below
#     the inherited hard limit; only a host whose hard limit is itself too
#     low needs operator action.
#   - `RUSTBGPD_NOFILE_SOFT_JSON` is exported as a ready JSON scalar for the
#     caller's `run.json`, so the receipt carries the limit the run actually
#     achieved rather than the one it asked for.
#
# `rbgp doctor` reports the same condition from the live daemon
# (`daemon.rlimit.nofile.<pid>`); the route-server flagship's
# management-plane load asserts it periodically for the whole window.

# `null` until the guard has actually measured a limit, so a `run.json`
# written without it says so instead of asserting a number nobody checked.
export RUSTBGPD_NOFILE_SOFT_JSON=null

require_fd_headroom() {
    local target="${SOAK_NOFILE_SOFT:-65536}" hard achieved
    if [[ ! $target =~ ^[1-9][0-9]*$ ]]; then
        echo "error: SOAK_NOFILE_SOFT must be a positive decimal integer" >&2
        return 2
    fi
    hard=$(ulimit -Hn)
    # `ulimit` failing here is not fatal on its own; the achieved-limit
    # check below is what decides, so one message covers both causes.
    ulimit -Sn "$target" 2>/dev/null || true
    achieved=$(ulimit -n)
    if [[ $achieved != unlimited ]] && ((achieved < target)); then
        echo "error: file-descriptor headroom too low: soft limit is ${achieved}," >&2
        echo "       need ${target} (hard limit ${hard})" >&2
        echo "       a scaled daemon exhausts descriptors at this limit and its" >&2
        echo "       metrics listener starts failing accept() with EMFILE while" >&2
        echo "       client-side gates still read green — refusing to soak" >&2
        echo "       raise the hard limit (e.g. a LimitNOFILE= drop-in for the" >&2
        echo "       login session, or /etc/security/limits.d) and re-run" >&2
        return 2
    fi
    if [[ $achieved =~ ^[0-9]+$ ]]; then
        export RUSTBGPD_NOFILE_SOFT_JSON="$achieved"
    else
        export RUSTBGPD_NOFILE_SOFT_JSON="\"$achieved\""
    fi
    echo "file-descriptor headroom: nofile soft ${achieved} (hard ${hard})"
}
