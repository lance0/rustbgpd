#!/usr/bin/env bash
# Shared lifecycle ownership for the two bare-host flagship runners.

flagship_proc_start_ticks() {
    local stat
    [[ ${1:-} =~ ^[1-9][0-9]*$ ]] || return 1
    [[ -r /proc/$1/stat ]] || return 1
    IFS= read -r stat <"/proc/$1/stat" || return 1
    stat=${stat##*) }
    # shellcheck disable=SC2086 # /proc fields are deliberately split here.
    set -- $stat
    [[ ${20:-} =~ ^[0-9]+$ ]] || return 1
    printf '%s\n' "${20}"
}

flagship_identity_matches() {
    local run_dir=$1 identity pid boot start extra current_boot current_start
    identity="$run_dir/runner.identity"
    [[ -r $identity ]] || return 1
    IFS=' ' read -r pid boot start extra <"$identity" || return 1
    [[ -z $extra && $pid =~ ^[1-9][0-9]*$ && $start =~ ^[0-9]+$ ]] || return 1
    IFS= read -r current_boot </proc/sys/kernel/random/boot_id || return 1
    [[ $boot == "$current_boot" ]] || return 1
    current_start=$(flagship_proc_start_ticks "$pid") || return 1
    [[ $start == "$current_start" ]] && kill -0 "$pid" 2>/dev/null
}

start_flagship_lifecycle() {
    local boot start identity_tmp coproc_input runner_pid=$BASHPID
    # shellcheck disable=SC2153 # both flagship runners assign RUN_DIR.
    FLAGSHIP_IDENTITY_FILE="$RUN_DIR/runner.identity"
    FLAGSHIP_CLEANUP_MARKER="$RUN_DIR/cleanup.complete"
    rm -f "$FLAGSHIP_CLEANUP_MARKER"
    exec {FLAGSHIP_STDOUT_FD}>&1
    exec {FLAGSHIP_STDERR_FD}>&2
    # Keep the file writer alive if a launch wrapper closes its output pipe.
    coproc FLAGSHIP_LOG_WRITER { exec tee -p -a "$SOAK_LOG" >&"$FLAGSHIP_STDOUT_FD"; }
    FLAGSHIP_TEE_PID=$!
    coproc_input=${FLAGSHIP_LOG_WRITER[1]}
    exec {FLAGSHIP_TEE_INPUT_FD}>&"$coproc_input"
    exec {coproc_input}>&-
    exec 1>&"$FLAGSHIP_TEE_INPUT_FD"
    exec 2>&"$FLAGSHIP_TEE_INPUT_FD"
    IFS= read -r boot </proc/sys/kernel/random/boot_id
    start=$(flagship_proc_start_ticks "$runner_pid") || return 1
    identity_tmp="${FLAGSHIP_IDENTITY_FILE}.tmp"
    printf '%s %s %s\n' "$runner_pid" "$boot" "$start" >"$identity_tmp"
    mv "$identity_tmp" "$FLAGSHIP_IDENTITY_FILE"
}

finish_flagship_cleanup() {
    local rc=$1 interrupted=${2:-0} status tee_rc fd_path fd
    [[ -n ${FLAGSHIP_TEE_PID:-} ]] || return 0
    if ((interrupted != 0)); then
        status=interrupted
    elif ((rc == 0)); then
        status=normal
    else
        status=failed
    fi
    exec 1>&"$FLAGSHIP_STDOUT_FD"
    exec 2>&"$FLAGSHIP_STDERR_FD"
    # An EXIT trap inside a redirected command can retain Bash's saved
    # stdout on an internal descriptor. We are exiting, so close every
    # remaining descriptor for this owned writer's input pipe as well.
    for fd_path in /proc/"$BASHPID"/fd/*; do
        fd=${fd_path##*/}
        [[ $fd == "$FLAGSHIP_TEE_INPUT_FD" ]] && continue
        [[ $fd_path -ef /proc/$BASHPID/fd/$FLAGSHIP_TEE_INPUT_FD ]] || continue
        exec {fd}>&-
    done
    exec {FLAGSHIP_TEE_INPUT_FD}>&-
    # Always collect the exit status, even if Bash has already reaped the
    # process. The callers ignore INT/TERM throughout cleanup so this wait
    # cannot return early because of a repeated stop request.
    wait "$FLAGSHIP_TEE_PID" || tee_rc=$?
    if [[ -n ${tee_rc:-} ]]; then
        status=log_write_failed
        ((rc == 0)) && rc=1
    fi
    printf 'status=%s\nexit_status=%s\n' "$status" "$rc" >"${FLAGSHIP_CLEANUP_MARKER}.tmp" || return 1
    mv "${FLAGSHIP_CLEANUP_MARKER}.tmp" "$FLAGSHIP_CLEANUP_MARKER" || return 1
    exec {FLAGSHIP_STDOUT_FD}>&-
    exec {FLAGSHIP_STDERR_FD}>&-
    [[ -z ${tee_rc:-} ]]
}

flagship_send_term() {
    local run_dir=$1 pid boot start
    read -r pid boot start <"$run_dir/runner.identity"
    python3 - "$pid" "$boot" "$start" <<'PY'
import os
import signal
import sys

pid, boot, start = sys.argv[1:]
try:
    fd = os.pidfd_open(int(pid))
except OSError as error:
    raise SystemExit(f"cannot open runner pidfd: {error}")
try:
    if open("/proc/sys/kernel/random/boot_id", encoding="utf-8").read().strip() != boot:
        raise SystemExit("runner boot identity changed")
    stat = open(f"/proc/{pid}/stat", encoding="utf-8").read().rsplit(") ", 1)[1].split()
    if len(stat) < 20 or stat[19] != start:
        raise SystemExit("runner start identity changed")
    signal.pidfd_send_signal(fd, signal.SIGTERM)
finally:
    os.close(fd)
PY
}

flagship_cleanup_drained() {
    [[ -r $1/cleanup.complete ]] && grep -qx 'status=normal\|status=interrupted\|status=failed' "$1/cleanup.complete"
}

stop_flagship_runner() {
    local run_dir=$1 marker="$1/cleanup.complete" i
    if ! flagship_identity_matches "$run_dir"; then
        echo "error: runner identity is stale or does not match: $run_dir" >&2
        return 1
    fi
    if ! flagship_send_term "$run_dir"; then
        echo "error: could not signal the verified runner: $run_dir" >&2
        return 1
    fi
    for ((i = 0; i < 600; i++)); do
        if flagship_cleanup_drained "$run_dir" && ! flagship_identity_matches "$run_dir"; then
            echo "runner cleanup completed: $run_dir"
            return 0
        fi
        if [[ -f $marker ]] && ! flagship_identity_matches "$run_dir"; then
            echo "error: runner log writer did not drain: $run_dir" >&2
            return 1
        fi
        sleep 0.1
    done
    echo "error: runner cleanup did not complete within 60 seconds: $run_dir" >&2
    return 1
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    if [[ ${1:-} != stop || $# != 2 ]]; then
        echo "usage: $0 stop <run-dir>" >&2
        exit 2
    fi
    stop_flagship_runner "$2"
fi
