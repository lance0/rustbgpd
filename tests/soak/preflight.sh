#!/usr/bin/env bash
# Soak-window pre-flight. Run once before starting any long soak.
#
# Checks, in order:
#   1. Required tools present.
#   2. No competing workload: the shared bench/soak host lock is free,
#      no containerlab process is live, no clab-managed containers are
#      up, and no rustbgpd process is running on the host itself.
#   3. Disk headroom on the partition holding tests/soak/runs/.
#   4. The rustbgpd:dev image exists and the daemon compiles at HEAD.
#   5. Two manual mutexes confirmed by the operator:
#        - the nightly bench cron is paused for the soak window
#        - no pushes to main will land during the soak window
#      Confirm via CONFIRM_BENCH_CRON_PAUSED=1 and
#      CONFIRM_NO_MAIN_PUSHES=1, or interactively when run on a TTY.
#
# Exit code: 0 = ready. 1 = one or more named failures (each printed
# as "FAIL: ..."). Failures are collected, not fail-fast, so one run
# reports everything that needs fixing.
#
# Tunables:
#   SOAK_MIN_DISK_GB   minimum free space required (default 50)
#   RUSTBGPD_HOST_LOCK lock path (same default as host-lock.sh)
#   SKIP_BUILD_CHECK=1 skip the cargo compile check (image check stays)

set -uo pipefail

SOAK_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SOAK_SCRIPT_DIR/../.." && pwd)"

SOAK_MIN_DISK_GB="${SOAK_MIN_DISK_GB:-50}"
HOST_LOCK="${RUSTBGPD_HOST_LOCK:-$HOME/.local/state/rustbgpd-host.lock}"

FAILURES=0

log() {
    printf '[preflight] %s\n' "$*"
}

fail() {
    printf 'FAIL: %s\n' "$*"
    FAILURES=$((FAILURES + 1))
}

ok() {
    printf '  ok: %s\n' "$*"
}

# --- 1. Required tools ------------------------------------------------
log "checking required tools"
for tool in docker containerlab curl jq awk python3 flock git cargo; do
    if command -v "$tool" >/dev/null 2>&1; then
        ok "$tool"
    else
        fail "required tool '$tool' not in PATH"
    fi
done

# --- 2. No competing workload ----------------------------------------
log "checking for competing workloads"

# The bench/soak host mutex: if held, a bench or another soak is live.
mkdir -p "$(dirname "$HOST_LOCK")" 2>/dev/null || true
if exec 9>"$HOST_LOCK" 2>/dev/null; then
    if flock -n 9; then
        ok "host lock free ($HOST_LOCK)"
        flock -u 9
    else
        fail "host lock held ($HOST_LOCK) — a bench or soak is already running"
    fi
    exec 9>&-
else
    fail "cannot open host lock path $HOST_LOCK"
fi

# PID checks by exact comm — never pgrep -f | head.
for comm in containerlab rustbgpd; do
    if pids=$(pgrep -x "$comm"); then
        fail "live '$comm' process on host (pid(s): ${pids//$'\n'/ })"
    else
        ok "no live '$comm' process"
    fi
done

# clab-managed containers left over from a previous lab.
clab_up=$(docker ps --format '{{.Names}}' 2>/dev/null | grep '^clab-' || true)
if [ -n "$clab_up" ]; then
    fail "clab containers already running: ${clab_up//$'\n'/ }"
else
    ok "no clab containers running"
fi

# --- 3. Disk headroom -------------------------------------------------
log "checking disk headroom (need >= ${SOAK_MIN_DISK_GB} GB)"
avail_gb=$(df -BG --output=avail "$SOAK_SCRIPT_DIR" | tail -1 | tr -dc '0-9')
if [ -z "$avail_gb" ]; then
    fail "could not determine free disk space for $SOAK_SCRIPT_DIR"
elif [ "$avail_gb" -lt "$SOAK_MIN_DISK_GB" ]; then
    fail "only ${avail_gb} GB free; a multi-day soak writes multi-GB daemon logs"
else
    ok "${avail_gb} GB free"
fi

# --- 4. Daemon builds -------------------------------------------------
log "checking daemon image and build"
if docker image inspect rustbgpd:dev >/dev/null 2>&1; then
    created=$(docker image inspect rustbgpd:dev --format '{{.Created}}')
    ok "rustbgpd:dev image present (created $created)"
    head_commit=$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)
    log "  note: verify the image was built from the tip under soak (HEAD is $head_commit)"
else
    fail "rustbgpd:dev image missing — run: docker build --target dev -t rustbgpd:dev ."
fi

if [ "${SKIP_BUILD_CHECK:-0}" = "1" ]; then
    log "  skipping cargo compile check (SKIP_BUILD_CHECK=1)"
elif (cd "$REPO_ROOT" && cargo check -q --bin rustbgpd >/dev/null 2>&1); then
    ok "cargo check --bin rustbgpd"
else
    fail "cargo check --bin rustbgpd failed — daemon does not compile at HEAD"
fi

# --- 5. Manual mutexes (operator confirmations) ----------------------
log "manual mutexes — these cannot be verified mechanically:"
log "  (a) the nightly bench cron on this host MUST be paused for the window"
log "  (b) no pushes to main during the soak window (CI topology collision)"

confirm() {
    local var_name=$1 prompt=$2 value
    value="${!var_name:-}"
    if [ "$value" = "1" ]; then
        ok "$prompt (confirmed via $var_name=1)"
        return 0
    fi
    if [ -t 0 ]; then
        printf 'Confirm: %s [y/N] ' "$prompt"
        read -r reply
        case "$reply" in
            y | Y | yes | YES)
                ok "$prompt (confirmed interactively)"
                return 0
                ;;
        esac
    fi
    fail "$prompt — not confirmed (set $var_name=1 or answer y on a TTY)"
}

confirm CONFIRM_BENCH_CRON_PAUSED "bench-nightly cron is paused for the soak window"
confirm CONFIRM_NO_MAIN_PUSHES "no pushes to main during the soak window"

# --- verdict ----------------------------------------------------------
if [ "$FAILURES" -eq 0 ]; then
    log "READY — all pre-flight checks passed"
    exit 0
fi
log "NOT READY — $FAILURES check(s) failed (listed above as FAIL:)"
exit 1
