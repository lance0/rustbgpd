#!/usr/bin/env bash
set -euo pipefail

repo=$(git rev-parse --show-toplevel)
driver="$repo/bench/scale/route-server-1000/run-receipt.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/route-server-1000-mechanics.XXXXXX")
cleanup_tmp() { rm -rf "$tmp"; }
trap cleanup_tmp EXIT INT TERM

# shellcheck disable=SC1090 # The repository root is resolved dynamically.
source "$driver"

# Keep the production post-sampler path wired through the ordering helper. A
# direct helper test alone would stay green if that call site were reverted.
# shellcheck disable=SC2016 # Match the literal production shell variables.
grep -Fxq 'check_run_outcome "$hrc" "$samplers_ok" || exit 1' "$driver" || {
    echo 'production outcome path bypassed retained sampler diagnostics' >&2
    exit 1
}

# Make awk lose the /proc state read for a live PID. The helper must classify
# the process as gone without leaking the expected race to stderr.
mkdir "$tmp/bin"
cat >"$tmp/bin/awk" <<'EOF'
#!/usr/bin/env bash
if [[ ${FAKE_AWK_EMPTY:-0} == 1 ]]; then
    exit 0
fi
echo 'simulated /proc stat race' >&2
exit 2
EOF
chmod +x "$tmp/bin/awk"
if PATH="$tmp/bin:$PATH" pid_running "$$" 2>"$tmp/pid.stderr"; then
    echo 'pid_running accepted an unreadable process state' >&2
    exit 1
fi
[[ ! -s "$tmp/pid.stderr" ]] || {
    echo 'pid_running leaked a benign /proc disappearance to stderr' >&2
    exit 1
}
if FAKE_AWK_EMPTY=1 PATH="$tmp/bin:$PATH" pid_running "$$"; then
    echo 'pid_running accepted an empty process state' >&2
    exit 1
fi

# A sampler intentionally terminates the harness after retaining its detailed
# failure. Keep that root cause ahead of the consequential exit 143.
OUT="$tmp/out"
mkdir "$OUT"
printf 'readyz exceeded 200/250ms contract: 503\t0.251\n' >"$OUT/readyz-failure"
set +e
(
    set -e
    # shellcheck disable=SC2034 # Consumed by the sourced cleanup helper.
    SUCCESS=0 RUN=''
    # shellcheck disable=SC2034 # Consumed by the sourced cleanup helper.
    DAEMON_PID='' H_PID='' READY_PID='' METRICS_PID='' RSS_PID='' GUARD_PID=''
    trap cleanup EXIT
    check_run_outcome 143 0
) >"$tmp/outcome.stdout" 2>"$tmp/outcome.stderr"
outcome_rc=$?
set -e
if ((outcome_rc == 0)); then
    echo 'failed harness and sampler outcome was accepted' >&2
    exit 1
fi
root_line=$(grep -n -F 'readyz exceeded 200/250ms contract' "$tmp/outcome.stderr" | cut -d: -f1 || true)
harness_line=$(grep -n -F 'harness failed: 143' "$tmp/outcome.stderr" | cut -d: -f1 || true)
[[ -n $root_line && -n $harness_line && $root_line -lt $harness_line ]] || {
    echo 'retained sampler root cause was not reported before harness termination' >&2
    exit 1
}
[[ $(<"$OUT/exit-status.env") == $'status=failed\nexit_status=1' ]] || {
    echo 'failed sampler outcome did not retain its nonzero exit status' >&2
    exit 1
}

printf 'route-server-1000 receipt mechanics passed\n'
