#!/usr/bin/env bash
# Recover PE2 when needed, then append exactly one terminal evidence row.
# The sample callback still runs after a failed recovery so the receipt records
# the failure state before the runner returns nonzero.
gate8b_terminal_recovery() {
    local pe2_running="$1" recover_callback="$2" sample_callback="$3" recovery_rc=0
    if [ "$pe2_running" != "1" ]; then
        "$recover_callback" || recovery_rc=$?
    fi
    "$sample_callback" || return
    return "$recovery_rc"
}
