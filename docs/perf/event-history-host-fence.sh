#!/usr/bin/env bash
# Shared host-isolation helpers for retained event-history producer measurements.
#
# Source this file from a `set -euo pipefail` driver. The acquired descriptor
# intentionally remains open in the caller until that shell exits.

# Retained event-history producer receipts use one fixed noise gate. An environment override
# would make two otherwise identical receipts incomparable and could turn a
# noisy run into a publishable-looking success.
readonly EVENT_HISTORY_PERF_REQUIRED_LOAD_ONE_MAX=2.0

event_history_acquire_host_lock() {
    command -v flock >/dev/null 2>&1 || {
        printf '%s\n' 'required command not found: flock' >&2
        return 1
    }

    EVENT_HISTORY_PERF_HOST_LOCK_PATH=${RUSTBGPD_HOST_LOCK:-${HOME}/.local/state/rustbgpd-host.lock}
    mkdir -p "$(dirname "$EVENT_HISTORY_PERF_HOST_LOCK_PATH")"
    touch "$EVENT_HISTORY_PERF_HOST_LOCK_PATH"
    # shellcheck disable=SC1083 # bash dynamic descriptor syntax is intentional.
    exec {EVENT_HISTORY_PERF_HOST_LOCK_FD}>"$EVENT_HISTORY_PERF_HOST_LOCK_PATH"
    if ! flock -n "$EVENT_HISTORY_PERF_HOST_LOCK_FD"; then
        printf 'error: %s is held by another retained soak or benchmark\n' \
            "$EVENT_HISTORY_PERF_HOST_LOCK_PATH" >&2
        printf '%s\n' '       no event-history producer build or measurement was started' >&2
        return 75
    fi
    printf 'acquired host lock: %s\n' "$EVENT_HISTORY_PERF_HOST_LOCK_PATH"
}

event_history_init_host_preflight_log() {
    local log=$1
    [[ ! -e "$log" ]] || {
        printf 'refusing existing event-history producer preflight log: %s\n' "$log" >&2
        return 1
    }
    printf 'phase\tattempt\tutc\tload_1m\tload_1m_max\tgovernor\trequired_governor\tcompeting_process_count\tcompeting_processes\tstatus\n' \
        >"$log"
}

event_history_governor_snapshot() {
    local -a paths
    local path value first='' mixed=0
    shopt -s nullglob
    paths=(/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor)
    shopt -u nullglob
    ((${#paths[@]} > 0)) || {
        printf '%s\n' unavailable
        return
    }
    for path in "${paths[@]}"; do
        [[ -r "$path" ]] || {
            printf '%s\n' unavailable
            return
        }
        value=$(tr -d '\n' <"$path")
        if [[ -z "$first" ]]; then
            first=$value
        elif [[ "$value" != "$first" ]]; then
            mixed=1
        fi
    done
    if ((mixed)); then
        printf '%s\n' mixed
    else
        printf '%s\n' "$first"
    fi
}

event_history_competing_process_snapshot() {
    ps -eo pid=,comm=,args= --no-headers \
        | awk -v self="$$" '
            $1 != self &&
            ($2 == "cargo" || $2 == "rustc" || $2 == "perf" ||
             $2 == "rustbgpd" ||
             $2 ~ /^rrharness($|-)/ || $2 ~ /^reloadstall($|-)/ ||
             $2 ~ /^route_paging($|-)/ || $2 ~ /^rib_nlri_build/ ||
             $2 ~ /^vpn_query_timi/ || $2 ~ /^vpn_query_allo/ ||
             $2 ~ /^nlri_build($|-)/ || $2 ~ /^event_history_/ ||
             $2 ~ /^codec($|-)/ || $2 ~ /^fanout($|-)/ ||
             $2 ~ /^inbound_attrs/ || $2 ~ /^rib_ops($|-)/ ||
             $2 ~ /^policy_eval($|-)/ || $2 ~ /^explain_snapsho/ ||
             $2 ~ /^validate($|-)/ || $2 ~ /^evpn-tester($|-)/ ||
             $2 ~ /^evpn-monitor($|-)/ || $2 ~ /^rustbgpd-evpn-/ ||
             $0 ~ /[[:space:]]bgperf2\.py[[:space:]]/) {
                # Retain only the bounded executable name. PIDs and argv can
                # contain usernames, checkout paths, tokens, or unrelated
                # command-line data and are not required to prove the fence.
                print $2
            }
        '
}

event_history_wait_for_idle() {
    local phase=$1 log=$2
    local load_one_max=$EVENT_HISTORY_PERF_REQUIRED_LOAD_ONE_MAX
    local wait_seconds=${EVENT_HISTORY_PERF_PREFLIGHT_WAIT_SECONDS:-120}
    local poll_seconds=${EVENT_HISTORY_PERF_PREFLIGHT_POLL_SECONDS:-1}
    local required_governor=performance
    local deadline=$((SECONDS + wait_seconds)) attempt=0
    local utc load_one governor process_lines process_count process_summary status

    [[ "$wait_seconds" =~ ^[1-9][0-9]*$ ]] || {
        printf 'EVENT_HISTORY_PERF_PREFLIGHT_WAIT_SECONDS must be positive, got %s\n' \
            "$wait_seconds" >&2
        return 2
    }
    [[ "$poll_seconds" =~ ^[1-9][0-9]*$ ]] || {
        printf 'EVENT_HISTORY_PERF_PREFLIGHT_POLL_SECONDS must be positive, got %s\n' \
            "$poll_seconds" >&2
        return 2
    }
    [[ -f "$log" ]] || {
        printf 'event-history producer preflight log is not initialized: %s\n' "$log" >&2
        return 1
    }

    while true; do
        ((attempt += 1))
        utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
        load_one=$(awk '{print $1}' /proc/loadavg)
        governor=$(event_history_governor_snapshot)
        process_lines=$(event_history_competing_process_snapshot)
        if [[ -n "$process_lines" ]]; then
            process_count=$(wc -l <<<"$process_lines")
            process_summary=$(printf '%s' "$process_lines" | tr '\t\n' '  ' | tr -s ' ')
        else
            process_count=0
            process_summary=none
        fi

        status=pass
        if ! awk -v observed="$load_one" -v maximum="$load_one_max" \
            'BEGIN { exit !(observed + 0 < maximum + 0) }'; then
            status=wait-load
        elif [[ "$governor" != "$required_governor" ]]; then
            status=wait-governor
        elif ((process_count != 0)); then
            status=wait-processes
        fi

        if [[ "$status" != pass ]] && ((SECONDS >= deadline)); then
            status=${status/wait-/timeout-}
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$phase" "$attempt" "$utc" "$load_one" "$load_one_max" \
            "$governor" "$required_governor" "$process_count" \
            "$process_summary" "$status" >>"$log"

        if [[ "$status" == pass ]]; then
            return
        fi
        if [[ "$status" == timeout-* ]]; then
            printf 'event-history producer idle preflight timed out after %ss: %s (load=%s governor=%s processes=%s)\n' \
                "$wait_seconds" "$phase" "$load_one" "$governor" \
                "$process_summary" >&2
            return 75
        fi
        sleep "$poll_seconds"
    done
}

# VPN query campaigns deliberately share the same machine-wide lock and idle
# policy as other retained performance work.
vpn_query_acquire_host_lock() {
    event_history_acquire_host_lock
}

vpn_query_init_host_preflight_log() {
    event_history_init_host_preflight_log "$@"
}

vpn_query_wait_for_idle() {
    event_history_wait_for_idle "$@"
}
