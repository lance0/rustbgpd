#!/bin/bash
# Bench quiet gate. Exits 0 only when the box has been verifiably idle
# across a 30s confirmation window with no BENCH_HOLD lock present.
# Usage: quiet-gate.sh <label>
LOCK=<scratch>/BENCH_HOLD.lock
LABEL="${1:-gate}"

quiet() {
    [ ! -e "$LOCK" ] || { echo "  hold-lock present"; return 1; }
    local c r
    c=$(pgrep -c cargo 2>/dev/null)
    r=$(pgrep -c rustc 2>/dev/null)
    [ "$c" -eq 0 ] || { echo "  cargo=$c"; return 1; }
    [ "$r" -eq 0 ] || { echo "  rustc=$r"; return 1; }
    [ "$(awk '{print ($1<1.0)}' /proc/loadavg)" -eq 1 ] || { echo "  load=$(cut -d' ' -f1 /proc/loadavg)"; return 1; }
    return 0
}

echo "[$LABEL] gate start $(date -u +%H:%M:%S)"
while true; do
    until quiet; do sleep 5; done
    echo "[$LABEL] quiet-1 $(date -u +%H:%M:%S) load=$(cut -d' ' -f1-3 /proc/loadavg)"
    sleep 30
    if quiet; then
        echo "[$LABEL] CONFIRMED $(date -u +%H:%M:%S) load=$(cut -d' ' -f1-3 /proc/loadavg)"
        break
    fi
    echo "[$LABEL] regressed during confirm window - re-waiting"
done
