#!/usr/bin/env bash
# Fixed-shape real-daemon scale campaign for ADR-0113 grouped outbound
# prefix-limit admission sets. Measurement only: no optimized variant exists.

set -euo pipefail

readonly BGP_PORT=17910
readonly METRICS_PORT=19180
readonly TABLE_ROUTES=400000
readonly WITHHELD_ROUTES=64
readonly DAEMON_START_TIMEOUT=60
readonly SCENARIO_TIMEOUT=7200
readonly PREFLIGHT_TIMEOUT=300
readonly MIN_AVAILABLE_KIB=$((16 * 1024 * 1024))

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "${HERE}/../../.." && pwd)"
readonly HERE REPO
readonly LOCK="${RUSTBGPD_HOST_LOCK:-${HOME}/.local/state/rustbgpd-host.lock}"

fail() {
    echo "outbound-prefix-limit-scale: $*" >&2
    exit 1
}

cd "${REPO}"
[[ -z $(git status --porcelain --untracked-files=normal) ]] ||
    fail "working tree is dirty; commit the immutable campaign before measuring"

mkdir -p "$(dirname -- "${LOCK}")"
touch "${LOCK}"
exec {LOCK_FD}>"${LOCK}"
flock -n "${LOCK_FD}" || {
    echo "outbound-prefix-limit-scale: host lock busy: ${LOCK}" >&2
    exit 75
}

COMMIT="$(git rev-parse HEAD)"
TREE="$(git rev-parse 'HEAD^{tree}')"
OUT="${REPO}/target/outbound-prefix-limit-scale/$(date -u +%Y%m%dT%H%M%SZ)-${COMMIT:0:12}"
readonly COMMIT TREE OUT
[[ ! -e "${OUT}" ]] || fail "output already exists: ${OUT}"
mkdir -p "${OUT}/build"
chmod 700 "${OUT}"

{
    printf 'commit=%s\n' "${COMMIT}"
    printf 'tree=%s\n' "${TREE}"
    printf 'table_routes=%s\n' "${TABLE_ROUTES}"
    printf 'withheld_routes=%s\n' "${WITHHELD_ROUTES}"
    printf 'members=1,10,100\n'
    printf 'variants=control,candidate\n'
    printf 'started=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"${OUT}/provenance.env"
{
    rustc -vV
    cargo -V
} >"${OUT}/toolchain.txt"
{
    printf 'kernel='
    uname -srvmo
    printf 'online_cpus=%s\n' "$(nproc)"
    awk -F: '/^model name/{gsub(/^[ \t]+/,"",$2); print "cpu_model=" $2; exit}' /proc/cpuinfo
    awk '/^(MemTotal|MemAvailable):/{print tolower(substr($1,1,length($1)-1)) "_kib=" $2}' /proc/meminfo
} >"${OUT}/host.txt"
cat >"${OUT}/commands.txt" <<'EOF'
env -u CARGO_TARGET_DIR -u RUSTFLAGS cargo build --release --locked -p rustbgpd
env -u CARGO_TARGET_DIR -u RUSTFLAGS cargo build --release --locked --manifest-path bench/scale/outbound-prefix-limit-scale/Cargo.toml
EOF
record_command() {
    printf '%q ' "$@" >>"${OUT}/commands.txt"
    printf '\n' >>"${OUT}/commands.txt"
}

env -u CARGO_TARGET_DIR -u RUSTFLAGS cargo build --release --locked -p rustbgpd \
    >"${OUT}/build/daemon.log" 2>&1 ||
    fail "daemon build failed (see ${OUT}/build/daemon.log)"
env -u CARGO_TARGET_DIR -u RUSTFLAGS cargo build --release --locked \
    --manifest-path "${HERE}/Cargo.toml" >"${OUT}/build/harness.log" 2>&1 ||
    fail "harness build failed (see ${OUT}/build/harness.log)"

readonly DAEMON="${REPO}/target/release/rustbgpd"
readonly HARNESS="${HERE}/target/release/outbound-prefix-limit-scale"
sha256sum "${DAEMON}" "${HARNESS}" |
    sed "s#${REPO}/##; s#${HERE}/##" >"${OUT}/binaries.sha256"

competitors() {
    ps -eo pid=,comm= --no-headers | awk -v self="$$" '
        $1 != self && ($2 == "cargo" || $2 == "rustc" ||
        $2 == "rustbgpd" || $2 == "perf" || $2 ~ /^bgperf/ ||
        $2 ~ /^rrharness/ || $2 ~ /^reloadstall/ ||
        $2 ~ /^route_paging/ || $2 ~ /^criterion/ ||
        $2 ~ /^outbound-prefix/) { print $2 }'
}

ports_free() {
    local listeners
    listeners="$(ss -H -ltn)" || return 1
    ! awk -v bgp=":${BGP_PORT}" -v metrics=":${METRICS_PORT}" '
        {
            if (substr($4, length($4)-length(bgp)+1) == bgp ||
                substr($4, length($4)-length(metrics)+1) == metrics) {
                used=1
            }
        }
        END { exit !used }
    ' <<<"${listeners}"
}

host_preflight() {
    local label="$1" deadline=$((SECONDS + PREFLIGHT_TIMEOUT)) consecutive=0
    local file="${OUT}/preflight-${label}.tsv"
    printf 'monotonic_seconds\tutc\tload_1m\tgovernors_performance\tgovernors_total\tcompetitors\tmem_available_kib\tfd_limit\tpswpin_delta\tpswpout_delta\tports_free\taccepted\n' >"${file}"
    while ((SECONDS < deadline)); do
        local load mem fd procs pin0 pout0 pin1 pout1 ports=0 accepted=0
        local governor_total=0 governor_good=0
        load="$(awk '{print $1}' /proc/loadavg)"
        mem="$(awk '$1=="MemAvailable:"{print $2}' /proc/meminfo)"
        fd="$(ulimit -n)"
        procs="$(competitors | sort -u | paste -sd, -)"
        procs="${procs:-none}"
        shopt -s nullglob
        local governors=(/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor)
        shopt -u nullglob
        governor_total=${#governors[@]}
        local governor
        for governor in "${governors[@]}"; do
            [[ $(tr -d '\n' <"${governor}") == performance ]] &&
                ((governor_good += 1))
        done
        read -r pin0 pout0 < <(
            awk '$1=="pswpin"{i=$2} $1=="pswpout"{o=$2} END{print i+0,o+0}' /proc/vmstat
        )
        sleep 2
        read -r pin1 pout1 < <(
            awk '$1=="pswpin"{i=$2} $1=="pswpout"{o=$2} END{print i+0,o+0}' /proc/vmstat
        )
        ports_free && ports=1
        if awk -v value="${load}" 'BEGIN{exit !(value < 2.0)}' &&
            ((governor_total > 0 && governor_good == governor_total)) &&
            [[ "${procs}" == none ]] &&
            ((mem >= MIN_AVAILABLE_KIB && fd >= 4096)) &&
            ((pin1 == pin0 && pout1 == pout0 && ports == 1)); then
            accepted=1
            ((consecutive += 1))
        else
            consecutive=0
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$(awk '{print $1}' /proc/uptime)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            "${load}" "${governor_good}" "${governor_total}" "${procs}" "${mem}" "${fd}" \
            "$((pin1-pin0))" "$((pout1-pout0))" "${ports}" "${accepted}" >>"${file}"
        ((consecutive >= 3)) && return 0
    done
    return 1
}

emit_config() {
    local path="$1" rundir="$2" members="$3" limit="$4"
    {
        cat <<EOF
# Generated by outbound-prefix-limit-scale/run-receipt.sh.
[global]
asn = 65500
router_id = "10.255.0.1"
listen_port = ${BGP_PORT}
runtime_state_dir = "${rundir}"

[global.telemetry]
prometheus_addr = "127.0.0.1:${METRICS_PORT}"
log_format = "json"

[global.telemetry.grpc_uds]
path = "${rundir}/grpc.sock"
principal = "operator"

[security.grpc]
enforcement = "tier"

[security.grpc.roles]
operator = "operator"

[peer_groups.members]
hold_time = 180
families = ["ipv4_unicast"]
EOF
        if [[ "${limit}" != unlimited ]]; then
            printf 'max_prefixes_out_ipv4 = %s\n' "${limit}"
        fi
        cat <<'EOF'

# The source is deliberately private so the one shared update group contains
# exactly the measured members and nothing else.
[[neighbors]]
address = "127.10.0.1"
remote_asn = 64512
description = "route-source"
hold_time = 180
families = ["ipv4_unicast"]
route_server_client = true
per_client_best = true
EOF
        local member address asn
        for ((member=1; member<=members; member++)); do
            address="127.10.0.$((member + 1))"
            asn=$((64512 + member))
            cat <<EOF

[[neighbors]]
address = "${address}"
remote_asn = ${asn}
description = "grouped-member-${member}"
peer_group = "members"
route_server_client = true
EOF
        done
    } >"${path}"
}

DAEMON_PID=''
SAMPLER_PID=''
RUNDIR=''
cleanup_scenario() {
    if [[ -n "${DAEMON_PID}" ]] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
        kill "${DAEMON_PID}" 2>/dev/null || true
        wait "${DAEMON_PID}" 2>/dev/null || true
    fi
    DAEMON_PID=''
    if [[ -n "${SAMPLER_PID}" ]]; then
        wait "${SAMPLER_PID}" 2>/dev/null || true
    fi
    SAMPLER_PID=''
    [[ -z "${RUNDIR}" ]] || rm -rf "${RUNDIR}"
    RUNDIR=''
}
trap cleanup_scenario EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

rss_sampler() {
    local pid="$1" output="$2"
    printf 'monotonic_seconds\tutc\tvm_rss_kib\tvm_hwm_kib\n' >"${output}"
    while kill -0 "${pid}" 2>/dev/null; do
        local rss hwm
        rss="$(awk '$1=="VmRSS:"{print $2}' "/proc/${pid}/status" 2>/dev/null || true)"
        hwm="$(awk '$1=="VmHWM:"{print $2}' "/proc/${pid}/status" 2>/dev/null || true)"
        [[ -n "${rss}" && -n "${hwm}" ]] &&
            printf '%s\t%s\t%s\t%s\n' "$(awk '{print $1}' /proc/uptime)" \
                "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${rss}" "${hwm}" >>"${output}"
        sleep 1
    done
}

run_scenario() {
    local members="$1" variant="$2"
    local scenario="${members}-${variant}"
    local scenario_out="${OUT}/${scenario}"
    RUNDIR="/tmp/rustbgpd-opscale-$$-${members}-${variant}"
    mkdir -p "${scenario_out}" "${RUNDIR}"
    chmod 700 "${scenario_out}" "${RUNDIR}"

    local start_limit=unlimited apply_limit=unlimited recover_limit=unlimited
    if [[ "${variant}" == candidate ]]; then
        apply_limit="${TABLE_ROUTES}"
    fi
    emit_config "${scenario_out}/config.start.toml" "${RUNDIR}" "${members}" "${start_limit}"
    emit_config "${scenario_out}/config.apply.toml" "${RUNDIR}" "${members}" "${apply_limit}"
    emit_config "${scenario_out}/config.recover.toml" "${RUNDIR}" "${members}" "${recover_limit}"
    cp "${scenario_out}/config.start.toml" "${scenario_out}/config.live.toml"

    local generation
    for generation in start apply recover; do
        record_command "${DAEMON}" --check "${scenario_out}/config.${generation}.toml"
        "${DAEMON}" --check "${scenario_out}/config.${generation}.toml" \
            >"${scenario_out}/check-${generation}.log" 2>&1 ||
            fail "${scenario} generated ${generation} config failed --check"
    done

    host_preflight "${scenario}" ||
        fail "${scenario} host preflight did not become valid; shape was not reduced"

    record_command env RUST_LOG=info "${DAEMON}" "${scenario_out}/config.live.toml"
    RUST_LOG=info "${DAEMON}" "${scenario_out}/config.live.toml" \
        >"${scenario_out}/daemon.log" 2>&1 &
    DAEMON_PID=$!
    rss_sampler "${DAEMON_PID}" "${scenario_out}/rss.tsv" &
    SAMPLER_PID=$!

    local deadline=$((SECONDS + DAEMON_START_TIMEOUT))
    until curl -fsS --max-time 1 "http://127.0.0.1:${METRICS_PORT}/metrics" \
        >"${scenario_out}/metrics-startup.prom" 2>/dev/null; do
        kill -0 "${DAEMON_PID}" 2>/dev/null ||
            fail "${scenario} daemon exited during startup"
        ((SECONDS < deadline)) ||
            fail "${scenario} daemon did not expose metrics within ${DAEMON_START_TIMEOUT}s"
        sleep 0.2
    done

    local harness_status=0
    record_command timeout --kill-after=30 "${SCENARIO_TIMEOUT}" "${HARNESS}" \
        "${variant}" "${members}" "${BGP_PORT}" "${DAEMON_PID}" \
        "127.0.0.1:${METRICS_PORT}" \
        "${scenario_out}/config.live.toml" \
        "${scenario_out}/config.apply.toml" \
        "${scenario_out}/config.recover.toml" \
        "${scenario_out}"
    timeout --kill-after=30 "${SCENARIO_TIMEOUT}" "${HARNESS}" \
        "${variant}" "${members}" "${BGP_PORT}" "${DAEMON_PID}" \
        "127.0.0.1:${METRICS_PORT}" \
        "${scenario_out}/config.live.toml" \
        "${scenario_out}/config.apply.toml" \
        "${scenario_out}/config.recover.toml" \
        "${scenario_out}" >"${scenario_out}/harness.log" 2>&1 ||
        harness_status=$?
    cat "${scenario_out}/harness.log"

    local opened recovered
    opened="$(grep -c 'outbound prefix limit reached' "${scenario_out}/daemon.log" || true)"
    recovered="$(grep -c 'outbound prefix limit recovered' "${scenario_out}/daemon.log" || true)"
    if [[ "${variant}" == candidate ]]; then
        [[ "${opened}" -eq "${members}" ]] ||
            fail "${scenario} blocking episode count ${opened}, expected ${members}"
        [[ "${recovered}" -eq "${members}" ]] ||
            fail "${scenario} recovery episode count ${recovered}, expected ${members}"
    else
        [[ "${opened}" -eq 0 && "${recovered}" -eq 0 ]] ||
            fail "${scenario} unlimited control opened a blocking/recovery episode"
    fi
    [[ "${harness_status}" -eq 0 ]] ||
        fail "${scenario} harness failed with status ${harness_status}"
    [[ $(grep -c '"message":"peer deleted"' "${scenario_out}/daemon.log" || true) -eq 0 ]] ||
        fail "${scenario} limit-only reload rebuilt a peer"

    printf 'status=pass\nmembers=%s\nvariant=%s\n' "${members}" "${variant}" \
        >"${scenario_out}/result.env"
    cleanup_scenario
    (
        cd "${scenario_out}"
        find . -type f ! -name SHA256SUMS -print0 | sort -z |
            xargs -0 sha256sum >"${OUT}/.SHA256SUMS.$$"
        mv "${OUT}/.SHA256SUMS.$$" SHA256SUMS
    )

    [[ $(git -C "${REPO}" rev-parse HEAD) == "${COMMIT}" ]] ||
        fail "HEAD changed during campaign"
    [[ $(git -C "${REPO}" rev-parse 'HEAD^{tree}') == "${TREE}" ]] ||
        fail "tree changed during campaign"
    [[ -z $(git -C "${REPO}" status --porcelain --untracked-files=normal) ]] ||
        fail "worktree changed during campaign"
}

# Adjacent same-SHA pairs with alternating order cancel fixed ordering bias.
run_scenario 1 control
run_scenario 1 candidate
run_scenario 10 candidate
run_scenario 10 control
run_scenario 100 control
run_scenario 100 candidate

python3 - "${OUT}" <<'PY'
import csv
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
rows = []
for summary_path in sorted(root.glob("*-*/summary.json")):
    value = json.loads(summary_path.read_text(encoding="utf-8"))
    with (summary_path.parent / "rss.tsv").open(
        newline="", encoding="utf-8"
    ) as stream:
        rss_rows = list(csv.DictReader(stream, delimiter="\t"))
    if not rss_rows:
        raise SystemExit(f"{summary_path.parent.name} has no RSS sampler rows")
    baseline = value["snapshots"]["baseline"]
    applied = value["snapshots"]["applied"]
    blocked = value["snapshots"]["blocked"]
    recovered = value["snapshots"]["recovered"]
    rows.append({
        "members": value["members"],
        "variant": value["variant"],
        "table_routes": value["table_routes"],
        "withheld_routes": value["withheld_routes"],
        "cold_convergence_seconds": value["cold_convergence_seconds"],
        "apply_seconds": value["apply_seconds"],
        "apply_allocated_delta_bytes":
            applied["jemalloc_allocated_bytes"] - baseline["jemalloc_allocated_bytes"],
        "apply_rss_delta_kib": applied["vm_rss_kib"] - baseline["vm_rss_kib"],
        "blocked_allocated_bytes": blocked["jemalloc_allocated_bytes"],
        "recovery_apply_seconds": value["recovery_apply_seconds"],
        "recovery_seconds": value["recovery_seconds"],
        "recovery_wall_seconds": value["recovery_wall_seconds"],
        "recovery_max_slice_bucket_lower_seconds":
            value["recovery_max_slice_bucket_lower_seconds"],
        "recovery_max_slice_bucket_upper_seconds":
            value["recovery_max_slice_bucket_upper_seconds"],
        "recovered_allocated_bytes": recovered["jemalloc_allocated_bytes"],
        "recovered_vm_rss_kib": recovered["vm_rss_kib"],
        "recovered_vm_hwm_kib": recovered["vm_hwm_kib"],
        "rss_samples": len(rss_rows),
        "sampled_max_vm_rss_kib":
            max(int(row["vm_rss_kib"]) for row in rss_rows),
        "sampled_max_vm_hwm_kib":
            max(int(row["vm_hwm_kib"]) for row in rss_rows),
        "checks_total": value["checks_total"],
        "checks_failed": value["checks_failed"],
    })

if len(rows) != 6:
    raise SystemExit(f"expected six summaries, found {len(rows)}")
if any(row["checks_failed"] for row in rows):
    raise SystemExit("a scenario summary contains failed checks")

fieldnames = list(rows[0])
with (root / "campaign.csv").open("w", newline="", encoding="utf-8") as stream:
    writer = csv.DictWriter(stream, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
PY

{
    printf 'finished=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'status=pass\n'
} >>"${OUT}/provenance.env"
(
    cd "${OUT}"
    find . -type f ! -name SHA256SUMS -print0 | sort -z |
        xargs -0 sha256sum >"${OUT}/../SHA256SUMS.$$"
    mv "${OUT}/../SHA256SUMS.$$" SHA256SUMS
)
echo "RECEIPT PASS; private raw output in ${OUT}"
