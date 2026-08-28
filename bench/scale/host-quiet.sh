#!/usr/bin/env bash
# Canonical quiet-host gate for measured scale and performance receipts.
#
# Source this file and call `wait_for_rustbgpd_quiet_host QUIET_TSV` after the
# shared host lock is held, but before starting a measured cell.  A successful
# call retains two consecutive samples that prove:
#
#   - one-minute load average is below 2.0;
#   - at least one CPU frequency governor exists and every governor is
#     `performance`;
#   - no compiler, benchmark, rustbgpd, or other BGP daemon is running; and
#   - pswpin / pswpout did not move between the two accepted samples.
#
# The gate retries until RUSTBGPD_HOST_QUIET_TIMEOUT_SECS (default 300) and
# returns EX_TEMPFAIL (75) with the last failed dimensions when the host does
# not settle.  RUSTBGPD_HOST_QUIET_SAMPLE_INTERVAL_SECS defaults to 30.

rustbgpd_host_quiet_competitors() {
    local processes
    processes=$(ps -eo pid=,comm= --no-headers) || return 1
    awk -v self="$$" '
        function competing(name) {
            return name == "cargo" || name == "rustc" || name == "rustdoc" ||
                name == "cc" || name == "c++" || name == "gcc" ||
                name == "g++" || name == "clang" || name == "clang++" ||
                name == "cc1" || name == "cc1plus" || name == "ld" ||
                name == "ld.lld" || name == "mold" ||
                name == "perf" || name == "rustbgpd" || name == "rrtransport" ||
                name == "reloadstall" || name ~ /^rrharness/ ||
                name ~ /^route_paging/ || name ~ /^rib_nlri_build/ ||
                name ~ /^nlri_build/ || name ~ /^event_history_/ ||
                name ~ /^codec/ || name ~ /^fanout/ || name ~ /^inbound_attrs/ ||
                name ~ /^rib_ops/ || name ~ /^policy_eval/ ||
                name ~ /^explain_snapsho/ || name ~ /^bgperf/ ||
                name ~ /^enhanced-route-/ ||
                name == "bird" || name == "bird6" || name == "bgpd" ||
                name == "openbgpd" || name == "gobgpd" || name == "zebra" ||
                name == "frr" || name == "ospfd" || name == "staticd"
        }
        BEGIN {separator = ""}
        $1 != self && competing($2) {
            printf "%s%s:%s", separator, $1, $2
            separator = ","
        }
        END {print ""}
    ' <<<"$processes"
}

rustbgpd_host_quiet_snapshot() {
    local proc_root=${RUSTBGPD_HOST_QUIET_PROC_ROOT:-/proc}
    local cpu_root=${RUSTBGPD_HOST_QUIET_CPU_ROOT:-/sys/devices/system/cpu}
    local path value
    local -a paths=() governors=()

    RUSTBGPD_HOST_QUIET_LOAD=$(awk '{print $1; exit}' "$proc_root/loadavg") || return 1
    read -r RUSTBGPD_HOST_QUIET_PSWPIN RUSTBGPD_HOST_QUIET_PSWPOUT < <(
        awk '$1 == "pswpin" {pin=$2} $1 == "pswpout" {pout=$2}
             END {print pin+0, pout+0}' "$proc_root/vmstat"
    ) || return 1
    RUSTBGPD_HOST_QUIET_COMPETITORS=$(rustbgpd_host_quiet_competitors) || return 1

    shopt -s nullglob
    paths=("$cpu_root"/cpu[0-9]*/cpufreq/scaling_governor)
    shopt -u nullglob
    for path in "${paths[@]}"; do
        value=''
        if ! IFS= read -r value <"$path" || [ -z "$value" ]; then
            return 1
        fi
        governors+=("$value")
    done
    RUSTBGPD_HOST_QUIET_GOVERNORS=$(IFS=,; printf '%s' "${governors[*]}")
    RUSTBGPD_HOST_QUIET_GOVERNOR_COUNT=${#governors[@]}
    RUSTBGPD_HOST_QUIET_PERFORMANCE_COUNT=0
    for value in "${governors[@]}"; do
        if [ "$value" = performance ]; then
            RUSTBGPD_HOST_QUIET_PERFORMANCE_COUNT=$((RUSTBGPD_HOST_QUIET_PERFORMANCE_COUNT + 1))
        fi
    done
}

rustbgpd_host_quiet_dimensions() {
    local -a failed=()

    awk -v load1="$RUSTBGPD_HOST_QUIET_LOAD" \
        'BEGIN {exit !(load1 ~ /^[0-9]+([.][0-9]+)?$/ && load1 < 2.0)}' ||
        failed+=(load1)
    if [ "$RUSTBGPD_HOST_QUIET_GOVERNOR_COUNT" -eq 0 ]; then
        failed+=(governors_missing)
    elif [ "$RUSTBGPD_HOST_QUIET_PERFORMANCE_COUNT" -ne \
        "$RUSTBGPD_HOST_QUIET_GOVERNOR_COUNT" ]; then
        failed+=(governors_not_performance)
    fi
    [ -z "$RUSTBGPD_HOST_QUIET_COMPETITORS" ] || failed+=(competitors)

    RUSTBGPD_HOST_QUIET_FAILED=$(IFS=,; printf '%s' "${failed[*]}")
    [ ${#failed[@]} -eq 0 ]
}

wait_for_rustbgpd_quiet_host() {
    if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
        echo "usage: wait_for_rustbgpd_quiet_host QUIET_TSV [EXTRA_SAMPLE_FUNCTION [EXTRA_HEADER]]" >&2
        return 2
    fi
    local output=$1
    local extra_sample=${2:-} extra_header=${3:-}
    local timeout=${RUSTBGPD_HOST_QUIET_TIMEOUT_SECS:-300}
    local interval=${RUSTBGPD_HOST_QUIET_SAMPLE_INTERVAL_SECS:-30}
    local min_spacing=${RUSTBGPD_HOST_QUIET_MIN_SPACING_SECS:-30}
    local deadline
    local attempt=0 accepted=0 first_epoch='' first_pswpin='' first_pswpout=''
    local epoch failed generic_ok extra_ok last_failed=second_sample

    if [ -n "$extra_sample" ] && ! declare -F "$extra_sample" >/dev/null; then
        echo "unknown host-quiet extra sample function: $extra_sample" >&2
        return 2
    fi

    case $timeout in '' | *[!0-9]*)
        echo "RUSTBGPD_HOST_QUIET_TIMEOUT_SECS must be a non-negative integer" >&2
        return 2
        ;;
    esac
    case $min_spacing in '' | *[!0-9]*)
        echo "RUSTBGPD_HOST_QUIET_MIN_SPACING_SECS must be a non-negative integer" >&2
        return 2
        ;;
    esac
    if ! awk -v interval="$interval" \
        'BEGIN {exit !(interval ~ /^[0-9]+([.][0-9]+)?$/)}'; then
        echo "RUSTBGPD_HOST_QUIET_SAMPLE_INTERVAL_SECS must be non-negative" >&2
        return 2
    fi
    deadline=$((SECONDS + timeout))
    mkdir -p "$(dirname "$output")" || return 1

    rustbgpd_host_quiet_header() {
        printf 'sample\tepoch_s\tload1\tpswpin\tpswpout'
        [ -z "$extra_header" ] || printf '\t%s' "$extra_header"
        printf '\tgovernors\tperformance_governors\tgovernor_count\tcompetitors\tquiet\tfailed_dimensions\toriginal_attempt\n'
    }
    rustbgpd_host_quiet_row() {
        local sample=$1 row_failed=${2:-none}
        printf '%s\t%s\t%s\t%s\t%s' "$sample" "$epoch" \
            "$RUSTBGPD_HOST_QUIET_LOAD" "$RUSTBGPD_HOST_QUIET_PSWPIN" \
            "$RUSTBGPD_HOST_QUIET_PSWPOUT"
        [ -z "$extra_header" ] || printf '\t%s' "$RUSTBGPD_HOST_QUIET_EXTRA_FIELDS"
        printf '\t%s\t%s\t%s\t%s\ttrue\t%s\t%s\n' \
            "${RUSTBGPD_HOST_QUIET_GOVERNORS:-none}" \
            "$RUSTBGPD_HOST_QUIET_PERFORMANCE_COUNT" \
            "$RUSTBGPD_HOST_QUIET_GOVERNOR_COUNT" \
            "${RUSTBGPD_HOST_QUIET_COMPETITORS:-none}" "$row_failed" "$attempt"
    }
    rustbgpd_host_quiet_header >"$output" || return 1

    while :; do
        attempt=$((attempt + 1))
        generic_ok=true
        if ! rustbgpd_host_quiet_snapshot; then
            RUSTBGPD_HOST_QUIET_LOAD=unreadable
            RUSTBGPD_HOST_QUIET_GOVERNORS=unreadable
            RUSTBGPD_HOST_QUIET_PERFORMANCE_COUNT=0
            RUSTBGPD_HOST_QUIET_GOVERNOR_COUNT=0
            RUSTBGPD_HOST_QUIET_COMPETITORS=unreadable
            RUSTBGPD_HOST_QUIET_PSWPIN=unreadable
            RUSTBGPD_HOST_QUIET_PSWPOUT=unreadable
            RUSTBGPD_HOST_QUIET_FAILED=snapshot
            generic_ok=false
        elif ! rustbgpd_host_quiet_dimensions; then
            generic_ok=false
        fi

        RUSTBGPD_HOST_QUIET_EXTRA_FIELDS=''
        RUSTBGPD_HOST_QUIET_EXTRA_FAILED=''
        extra_ok=true
        if [ -n "$extra_sample" ] && ! "$extra_sample"; then
            extra_ok=false
            [ -n "$RUSTBGPD_HOST_QUIET_EXTRA_FAILED" ] ||
                RUSTBGPD_HOST_QUIET_EXTRA_FAILED=extra_snapshot
        fi
        [ -z "$RUSTBGPD_HOST_QUIET_EXTRA_FAILED" ] || extra_ok=false
        failed=$RUSTBGPD_HOST_QUIET_FAILED
        if [ -n "$RUSTBGPD_HOST_QUIET_EXTRA_FAILED" ]; then
            [ -z "$failed" ] || failed+=,
            failed+=$RUSTBGPD_HOST_QUIET_EXTRA_FAILED
        fi
        epoch=$(date +%s)

        if [ "$generic_ok" != true ] || [ "$extra_ok" != true ]; then
            last_failed=${failed:-snapshot}
            accepted=0
            first_epoch=''
            first_pswpin=''
            first_pswpout=''
            rustbgpd_host_quiet_header >"$output" || return 1
        elif [ "$accepted" -eq 0 ]; then
            first_epoch=$epoch
            first_pswpin=$RUSTBGPD_HOST_QUIET_PSWPIN
            first_pswpout=$RUSTBGPD_HOST_QUIET_PSWPOUT
            accepted=1
            rustbgpd_host_quiet_header >"$output" || return 1
            rustbgpd_host_quiet_row 1 >>"$output" || return 1
            last_failed=second_sample
        elif [ "$RUSTBGPD_HOST_QUIET_PSWPIN" != "$first_pswpin" ] ||
            [ "$RUSTBGPD_HOST_QUIET_PSWPOUT" != "$first_pswpout" ]; then
            first_epoch=$epoch
            first_pswpin=$RUSTBGPD_HOST_QUIET_PSWPIN
            first_pswpout=$RUSTBGPD_HOST_QUIET_PSWPOUT
            accepted=1
            rustbgpd_host_quiet_header >"$output" || return 1
            rustbgpd_host_quiet_row 1 >>"$output" || return 1
            last_failed=swap_activity
        elif [ $((epoch - first_epoch)) -lt "$min_spacing" ]; then
            last_failed=sample_spacing
        else
            rustbgpd_host_quiet_row 2 >>"$output" || return 1
            echo "host quiet: retained two accepted samples in $output"
            return 0
        fi
        if [ "$SECONDS" -ge "$deadline" ]; then
            echo "host quiet timeout: failed dimensions: $last_failed" >&2
            return 75
        fi
        sleep "$interval"
    done
}
