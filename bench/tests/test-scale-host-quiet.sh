#!/usr/bin/env bash
# shellcheck disable=SC2016 # single-quoted strings below are literal production seams
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
helper="$repo/bench/scale/host-quiet.sh"
matrix="$repo/bench/scale/matrix/run-matrix.sh"
irrreload="$repo/bench/scale/irrreload/run-irr-reload.sh"
enhanced="$repo/bench/scale/enhanced-route-refresh/run-receipt.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/scale-host-quiet.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

make_fixture() {
    local root=$1 load=${2:-0.50}
    mkdir -p "$root/proc" "$root/sys/cpu0/cpufreq" "$root/bin"
    printf '%s 0.40 0.30 1/100 1\n' "$load" >"$root/proc/loadavg"
    printf 'pswpin 10\npswpout 20\n' >"$root/proc/vmstat"
    printf 'performance\n' >"$root/sys/cpu0/cpufreq/scaling_governor"
    cat >"$root/bin/ps" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    chmod +x "$root/bin/ps"
}

run_gate() {
    local root=$1 output=$2 timeout=${3:-2} interval=${4:-0}
    PATH="$root/bin:$PATH" \
        RUSTBGPD_HOST_QUIET_PROC_ROOT="$root/proc" \
        RUSTBGPD_HOST_QUIET_CPU_ROOT="$root/sys" \
        RUSTBGPD_HOST_QUIET_TIMEOUT_SECS="$timeout" \
        RUSTBGPD_HOST_QUIET_SAMPLE_INTERVAL_SECS="$interval" \
        RUSTBGPD_HOST_QUIET_MIN_SPACING_SECS=0 \
        bash -c 'source "$1"; wait_for_rustbgpd_quiet_host "$2"' \
        bash "$helper" "$output"
}

success="$tmp/success"
make_fixture "$success"
run_gate "$success" "$success/quiet.tsv"
[[ $(wc -l <"$success/quiet.tsv") -eq 3 ]] || fail 'success did not retain exactly two samples'
awk -F '\t' '
    NR == 1 {
        expected="sample\tepoch_s\tload1\tpswpin\tpswpout\tgovernors\tperformance_governors\tgovernor_count\tcompetitors\tquiet\tfailed_dimensions\toriginal_attempt"
        if ($0 != expected) exit 1
        next
    }
    $1 != NR - 1 || $3 >= 2.0 || $4 != 10 || $5 != 20 ||
        $6 != "performance" || $7 != 1 || $8 != 1 || $9 != "none" ||
        $10 != "true" || $11 != "none" || $12 != NR - 1 {exit 1}
    END {if (NR != 3) exit 1}
' "$success/quiet.tsv" || fail 'success quiet.tsv does not prove every dimension'

assert_rejected() {
    local name=$1 expected=$2
    shift 2
    local root="$tmp/$name" status=0
    make_fixture "$root"
    "$@" "$root"
    run_gate "$root" "$root/quiet.tsv" 0 0 >"$root/stdout" 2>"$root/stderr" || status=$?
    [[ $status -eq 75 ]] || fail "$name returned $status instead of 75"
    grep -Fq "host quiet timeout: failed dimensions: $expected" "$root/stderr" ||
        fail "$name missing $expected timeout diagnostic"
}

remove_governors() { rm -rf "$1/sys/cpu0"; }
mix_governors() {
    mkdir -p "$1/sys/cpu1/cpufreq"
    printf 'powersave\n' >"$1/sys/cpu1/cpufreq/scaling_governor"
}
break_later_governor_read() {
    mkdir -p "$1/sys/cpu1/cpufreq/scaling_governor"
}
raise_load() { printf '2.00 0.40 0.30 1/100 1\n' >"$1/proc/loadavg"; }
write_competitor() {
    local root=$1 process=$2
    cat >"$root/bin/ps" <<EOF
#!/usr/bin/env bash
printf '4242 $process\n'
EOF
    chmod +x "$root/bin/ps"
}
add_compiler() { write_competitor "$1" rustc; }
add_benchmark() { write_competitor "$1" rrharness-fixt; }
add_rustbgpd() { write_competitor "$1" rustbgpd; }
add_bgp_daemon() { write_competitor "$1" bird; }

assert_rejected missing-governor governors_missing remove_governors
assert_rejected mixed-governor governors_not_performance mix_governors
assert_rejected unreadable-governor snapshot break_later_governor_read
assert_rejected high-load load1 raise_load
assert_rejected compiler competitors add_compiler
assert_rejected benchmark competitors add_benchmark
assert_rejected rustbgpd competitors add_rustbgpd
assert_rejected bgp-daemon competitors add_bgp_daemon

swap="$tmp/swap"
make_fixture "$swap"
cat >"$swap/bin/ps" <<'EOF'
#!/usr/bin/env bash
read -r _ pin <"$FAKE_VMSTAT"
read -r _ pout < <(sed -n '2p' "$FAKE_VMSTAT")
printf 'pswpin %s\npswpout %s\n' "$((pin + 1))" "$((pout + 1))" >"$FAKE_VMSTAT"
EOF
chmod +x "$swap/bin/ps"
swap_status=0
FAKE_VMSTAT="$swap/proc/vmstat" PATH="$swap/bin:$PATH" \
    RUSTBGPD_HOST_QUIET_PROC_ROOT="$swap/proc" \
    RUSTBGPD_HOST_QUIET_CPU_ROOT="$swap/sys" \
    RUSTBGPD_HOST_QUIET_TIMEOUT_SECS=2 \
    RUSTBGPD_HOST_QUIET_SAMPLE_INTERVAL_SECS=0.05 \
    RUSTBGPD_HOST_QUIET_MIN_SPACING_SECS=0 \
    bash -c 'source "$1"; wait_for_rustbgpd_quiet_host "$2"' \
    bash "$helper" "$swap/quiet.tsv" >"$swap/stdout" 2>"$swap/stderr" || swap_status=$?
[[ $swap_status -eq 75 ]] || fail "swap activity returned $swap_status instead of 75"
grep -Fq 'failed dimensions: swap_activity' "$swap/stderr" || fail 'swap timeout omitted failed dimension'

irr="$tmp/irr-compatibility"
make_fixture "$irr"
cat >"$irr/bin/ss" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"$irr/bin/df" <<'EOF'
#!/usr/bin/env bash
printf 'Filesystem 1024-blocks Used Available Capacity Mounted\n'
printf 'fixture 100000000 1 50000000 1%% /fixture\n'
EOF
cat >"$irr/bin/date" <<'EOF'
#!/usr/bin/env bash
count=$(cat "$FAKE_DATE_COUNTER" 2>/dev/null || printf '0')
printf '%s\n' "$((1 + 30 * count))"
printf '%s\n' "$((count + 1))" >"$FAKE_DATE_COUNTER"
EOF
chmod +x "$irr/bin/ss" "$irr/bin/df" "$irr/bin/date"
FAKE_DATE_COUNTER="$irr/date-counter" PATH="$irr/bin:$PATH" \
    RUSTBGPD_HOST_QUIET_PROC_ROOT="$irr/proc" \
    RUSTBGPD_HOST_QUIET_CPU_ROOT="$irr/sys" \
    RUSTBGPD_HOST_QUIET_TIMEOUT_SECS=2 \
    RUSTBGPD_HOST_QUIET_SAMPLE_INTERVAL_SECS=0 \
    bash "$irrreload" --self-test-host-quiet "$irr/quiet.tsv"
python3 - "$repo/bench/scale/irrreload/verify-receipt.py" "$irr/quiet.tsv" <<'PY'
import csv
import importlib.util
import pathlib
import sys

verifier_path, quiet_path = map(pathlib.Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location("irr_verify_receipt", verifier_path)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
module.validate_quiet(quiet_path)

with quiet_path.open(newline="") as stream:
    reader = csv.DictReader(stream, delimiter="\t")
    fieldnames = reader.fieldnames
    rows = list(reader)
assert fieldnames is not None

def rejected(name, mutate):
    candidate = quiet_path.with_name(f"quiet-{name}.tsv")
    changed = [dict(row) for row in rows]
    mutate(changed)
    with candidate.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, delimiter="\t")
        writer.writeheader()
        writer.writerows(changed)
    try:
        module.validate_quiet(candidate)
    except module.InvalidReceipt:
        return
    raise SystemExit(f"{name} mutation stayed green")

rejected("port", lambda data: data[0].update(port1790_free="false"))
rejected("disk", lambda data: data[0].update(disk_available_kib="41943039"))
rejected("swap", lambda data: data[1].update(pswpin="11"))
rejected("governor", lambda data: data[0].update(governors="powersave"))
rejected("competitor", lambda data: data[0].update(competitors="4242:rustc"))
PY

check_driver_seam() {
    local driver=$1 name=$2 acquire_line quiet_line quiet_call workload workload_line
    grep -Fxq 'source "$REPO/tests/soak/host-lock.sh"' "$driver" || return 1
    grep -Fxq 'source "$REPO/bench/scale/host-quiet.sh"' "$driver" || return 1
    grep -Fxq 'acquire_rustbgpd_host_lock || exit $?' "$driver" || return 1
    case $name in
        matrix)
            quiet_call='wait_for_rustbgpd_quiet_host "$ART/$cell/quiet.tsv" || exit $?'
            workload_line='if run_cell "$cell"; then'
            ;;
        irrreload)
            grep -Fq 'wait_for_rustbgpd_quiet_host "$quiet"' "$driver" || return 1
            quiet_call='load_gate "$cell" || exit $?'
            workload_line='if run_cell "$cell"; then'
            ;;
        enhanced)
            quiet_call='wait_for_rustbgpd_quiet_host "$OUT/quiet.tsv" || exit $?'
            workload_line='"$DAEMON" "$RUN/config.toml" >"$OUT/daemon.log" 2>&1 &'
            ;;
        *) return 1 ;;
    esac
    grep -Fq "$quiet_call" "$driver" || return 1
    acquire_line=$(grep -nF 'acquire_rustbgpd_host_lock || exit $?' "$driver" | cut -d: -f1)
    quiet_line=$(grep -nF "$quiet_call" "$driver" | cut -d: -f1)
    workload=$(grep -nF "$workload_line" "$driver" | head -n1 | cut -d: -f1)
    [[ -n $acquire_line && -n $quiet_line && -n $workload ]] || return 1
    ((acquire_line < workload && quiet_line < workload))
}

for spec in "$matrix:matrix" "$irrreload:irrreload" "$enhanced:enhanced"; do
    driver=${spec%:*}
    name=${spec##*:}
    check_driver_seam "$driver" "$name" || fail "$name production seam rejected"
    for mutation in host-source quiet-source acquire quiet-call; do
        candidate="$tmp/${name}-${mutation}"
        cp "$driver" "$candidate"
        case $mutation in
            host-source) sed -i '\|source "$REPO/tests/soak/host-lock.sh"|d' "$candidate" ;;
            quiet-source) sed -i '\|source "$REPO/bench/scale/host-quiet.sh"|d' "$candidate" ;;
            acquire) sed -i '/acquire_rustbgpd_host_lock || exit \$?/d' "$candidate" ;;
            quiet-call)
                if [[ $name == irrreload ]]; then
                    sed -i '/load_gate "$cell" || exit \$?/d' "$candidate"
                else
                    sed -i '/wait_for_rustbgpd_quiet_host .* || exit \$?/d' "$candidate"
                fi
                ;;
        esac
        ! check_driver_seam "$candidate" "$name" ||
            fail "$name $mutation mutation stayed green"
    done
done

lock="$tmp/matrix.lock"
artifacts="$tmp/matrix-artifacts"
exec {lock_fd}>"$lock"
flock -n "$lock_fd"
matrix_status=0
RUSTBGPD_HOST_LOCK="$lock" ARTIFACTS_DIR="$artifacts" \
    bash "$matrix" rustbgpd >"$tmp/matrix.stdout" 2>"$tmp/matrix.stderr" || matrix_status=$?
[[ $matrix_status -eq 75 ]] || fail "held matrix lock returned $matrix_status instead of 75"
grep -Fq 'is held by another process (soak or bench)' "$tmp/matrix.stderr" ||
    fail 'held matrix lock omitted canonical diagnostic'
[[ ! -e $artifacts ]] || fail 'matrix created artifacts before rejecting held host lock'

printf 'PASS: shared scale host-quiet gate and destructive production seams\n'
