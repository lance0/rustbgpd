#!/bin/sh
# Profiling-only bgperf2 entrypoint for the event-history producer proceed gate.
set -eu

case "${1:-}" in
    -* | "")
        exec /usr/local/bin/rustbgpd.real "$@"
        ;;
esac

config=$1
mode=${EVENT_HISTORY_PERF_MODE:-}
case "$mode" in
    enabled)
        if grep -q '^\[event_history\]$' "$config"; then
            printf '%s\n' 'event_history block unexpectedly supplied by bgperf2' >&2
            exit 1
        fi
        cat >>"$config" <<'EOF'

[event_history]
enabled = true
required = true
path = "/var/lib/rustbgpd/events.db"
synchronous = "full"
queue_capacity = 262144
EOF
        ;;
    disabled)
        if grep -q '^\[event_history\]$' "$config"; then
            printf '%s\n' 'disabled profile contains an event_history block' >&2
            exit 1
        fi
        ;;
    *)
        printf 'EVENT_HISTORY_PERF_MODE must be enabled or disabled, got %s\n' "$mode" >&2
        exit 2
        ;;
esac

# bgperf2 launches this entrypoint through `docker exec`, so the container init
# PID is not the daemon PID. Stop this exec process at a host-visible barrier;
# the receipt attaches perf to it and sends SIGCONT. The subsequent exec keeps
# the same host PID while replacing this shell with the real daemon.
printf '%s\n' "$$" >"$(dirname "$config")/event-history-profile-ready"
kill -STOP "$$"
exec /usr/local/bin/rustbgpd.real "$@"
