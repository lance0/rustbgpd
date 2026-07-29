#!/usr/bin/env bash
# Retained VPN query campaign driver. CI may invoke only --smoke.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source-path=SCRIPTDIR/..
# shellcheck source=docs/perf/event-history-host-fence.sh
# shellcheck disable=SC1091 # Exact CI invocation does not pass the sourced file as an input.
source "$root/docs/perf/event-history-host-fence.sh"

smoke=0
attempts=1
declared_cpu=
[[ ${1:-} != --smoke ]] || { smoke=1; shift; }
[[ ${1:-} != --retry ]] || { attempts=2; shift; }
if [[ ${1:-} == --cpu && $# -ge 2 ]]; then
    declared_cpu=$2
    shift 2
fi
[[ $# -eq 1 ]] || {
    echo "usage: $0 [--smoke] [--retry] --cpu LOGICAL_CPU OUTPUT_DIRECTORY" >&2
    exit 2
}
[[ $declared_cpu =~ ^[0-9]+$ ]] ||
    { echo "a numeric --cpu is required for every campaign" >&2; exit 2; }
command -v taskset >/dev/null 2>&1 ||
    { echo "taskset is required for the declared CPU pin" >&2; exit 2; }
taskset -c "$declared_cpu" true >/dev/null 2>&1 ||
    { echo "declared CPU is unavailable: $declared_cpu" >&2; exit 2; }
linux_affinity=$(taskset -c "$declared_cpu" \
    grep '^Cpus_allowed_list:' /proc/self/status | cut -f2)
[[ $linux_affinity == "$declared_cpu" ]] ||
    { echo "declared CPU and Linux affinity differ" >&2; exit 2; }
output=$1
if ((!smoke)) && [[ -v RUSTBGPD_VPN_QUERY_FORCE_CENSOR ]]; then
    echo "RUSTBGPD_VPN_QUERY_FORCE_CENSOR is forbidden for retained campaigns" >&2
    exit 2
fi
[[ ! -e "$output" ]] || {
    echo "refusing existing output: $output" >&2
    exit 1
}
mkdir -p "$output/bin"
[[ -z $(git -C "$root" status --porcelain) ]] || {
    echo "refusing campaign from a dirty source tree" >&2
    exit 1
}

vpn_query_acquire_host_lock
vpn_query_init_host_preflight_log "$output/host-preflight.tsv"
vpn_query_wait_for_idle build "$output/host-preflight.tsv"
source_commit=$(git -C "$root" rev-parse HEAD)
source_tree=$(git -C "$root" rev-parse 'HEAD^{tree}')
source_status=$(git -C "$root" status --porcelain=v1)
toolchain=$(rustc --version --verbose | tr '\n' ';')
[[ -z $source_status ]]

target_dir="$output/target"
export CARGO_TARGET_DIR=$target_dir
cargo build --locked --manifest-path "$root/Cargo.toml" --release -p rustbgpd-api \
    --bench vpn_query_timing --features bench-internals
cargo build --locked --manifest-path "$root/Cargo.toml" --release -p rustbgpd-api \
    --bench vpn_query_allocation --features bench-internals,vpn-query-allocation

find_binary() {
    local name=$1
    mapfile -t matches < <(find "$target_dir/release/deps" -maxdepth 1 -type f \
        -perm -0100 -name "$name-*" | sort)
    ((${#matches[@]} == 1)) || {
        printf 'expected one %s binary, found %s\n' "$name" "${#matches[@]}" >&2
        return 1
    }
    printf '%s\n' "${matches[0]}"
}
cp "$(find_binary vpn_query_timing)" "$output/bin/vpn_query_timing"
cp "$(find_binary vpn_query_allocation)" "$output/bin/vpn_query_allocation"
timing_hash=$(sha256sum "$output/bin/vpn_query_timing" | awk '{print $1}')
allocation_hash=$(sha256sum "$output/bin/vpn_query_allocation" | awk '{print $1}')

python3 - "$output/manifest.json" "$timing_hash" "$allocation_hash" \
    "$source_commit" "$source_tree" "$toolchain" "$attempts" \
    "$declared_cpu" "$linux_affinity" <<'PY'
import json, sys
path, timing, allocation, commit, tree, rustc, attempts, cpu, affinity = sys.argv[1:]
fixed = [f"{case}{i}" for i in range(1, 9) for case in ("U", "F")]
json.dump({"schema": 3, "base_commit": commit, "rustc": rustc,
           "host_fence": "pass", "source_tree_clean": True, "fixed_order": fixed,
           "source_tree": tree, "attempts": int(attempts),
           "declared_cpu": int(cpu), "linux_affinity": affinity,
           "timing_binary_sha256": timing,
           "allocation_binary_sha256": allocation}, open(path, "w"), indent=2)
PY

decorate() {
    local raw=$1 output_path=$2 binary_hash=$3 ordinal=$4 repetition=$5 timeout=$6 attempt=$7
    python3 - "$raw" "$output_path" "$binary_hash" "$ordinal" "$repetition" \
        "$timeout" "$(git -C "$root" rev-parse HEAD)" "$attempt" <<'PY'
import json, sys
raw, output, binary_hash, ordinal, repetition, timeout, commit, attempt = sys.argv[1:]
doc = json.load(open(raw))
doc.update(schema=3, binary_sha256=binary_hash, ordinal=int(ordinal),
           repetition=int(repetition), timeout_seconds=int(timeout),
           source_commit=commit, attempt=int(attempt))
json.dump(doc, open(output, "w"), indent=2)
PY
}

check_provenance() {
    [[ $(git -C "$root" rev-parse HEAD) == "$source_commit" ]]
    [[ $(git -C "$root" rev-parse 'HEAD^{tree}') == "$source_tree" ]]
    [[ -z $(git -C "$root" status --porcelain=v1) ]]
    [[ $(rustc --version --verbose | tr '\n' ';') == "$toolchain" ]]
    [[ $(sha256sum "$output/bin/vpn_query_timing" | awk '{print $1}') == "$timing_hash" ]]
    [[ $(sha256sum "$output/bin/vpn_query_allocation" | awk '{print $1}') == "$allocation_hash" ]]
    [[ $(taskset -c "$declared_cpu" grep '^Cpus_allowed_list:' \
        /proc/self/status | cut -f2) == "$linux_affinity" ]]
}

if ((smoke)); then
    vpn_query_wait_for_idle smoke "$output/host-preflight.tsv"
    for target in timing allocation; do
        raw="$output/$target-raw.json"
        taskset -c "$declared_cpu" "$output/bin/vpn_query_$target" \
            smoke U "$raw" "$declared_cpu"
        decorate "$raw" "$output/$target-smoke.json" \
            "$([[ $target == timing ]] && echo "$timing_hash" || echo "$allocation_hash")" \
            1 1 10 0
        rm "$raw"
    done
    echo "VPN query 256-route smoke passed"
    exit
fi
for attempt in $(seq 1 "$attempts"); do
    mkdir -p "$output/attempt-$attempt/timing"
    ordinal=0
    for size in 10000 100000 1000000; do
        for repetition in 1 2 3 4 5 6 7 8; do
            for case in U F; do
                ((ordinal += 1))
                check_provenance
                vpn_query_wait_for_idle "attempt-$attempt-timing-$ordinal" \
                    "$output/host-preflight.tsv"
                raw="$output/attempt-$attempt/timing/raw.json"
                set +e
                taskset -c "$declared_cpu" "$output/bin/vpn_query_timing" \
                    cell "$size" "$case" "$raw" "$declared_cpu"
                rc=$?
                set -e
                if ((rc == 75)); then
                    decorate "$raw" "$output/censor.json" "$timing_hash" \
                        "$ordinal" "$repetition" 120 "$attempt"
                    rm "$raw"
                    check_provenance
                    python3 "$root/bench/verify-vpn-query-campaign.py" "$output" \
                        --output "$output/classification.json"
                    check_provenance
                    exit
                elif ((rc != 0)); then
                    exit "$rc"
                fi
                decorate "$raw" "$output/attempt-$attempt/timing/$(printf '%02d' "$ordinal").json" \
                    "$timing_hash" "$ordinal" "$repetition" 120 "$attempt"
                rm "$raw"
            done
        done
    done
done
check_provenance
vpn_query_wait_for_idle allocation "$output/host-preflight.tsv"
set +e
taskset -c "$declared_cpu" "$output/bin/vpn_query_allocation" \
    cell 1000000 U "$output/allocation-raw.json" "$declared_cpu"
rc=$?
set -e
if ((rc == 75)); then
    decorate "$output/allocation-raw.json" "$output/censor.json" \
        "$allocation_hash" 49 1 120 "$attempts"
    rm "$output/allocation-raw.json"
    check_provenance
    python3 "$root/bench/verify-vpn-query-campaign.py" "$output" \
        --output "$output/classification.json"
    check_provenance
    exit
elif ((rc != 0)); then
    exit "$rc"
fi
decorate "$output/allocation-raw.json" "$output/allocation.json" \
    "$allocation_hash" 49 1 120 "$attempts"
rm "$output/allocation-raw.json"
python3 "$root/bench/verify-vpn-query-campaign.py" "$output" \
    --output "$output/classification.json"
check_provenance
