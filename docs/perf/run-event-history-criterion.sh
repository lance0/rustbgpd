#!/usr/bin/env bash
# Exact-ref, privacy-safe Criterion receipt driver for event-history producer.
set -euo pipefail

usage() {
    printf 'usage: %s baseline|candidate\n' "$0" >&2
    exit 2
}

[[ $# -eq 1 ]] || usage
PHASE=$1
case "$PHASE" in baseline | candidate) ;; *) usage ;; esac

ROOT=$(git rev-parse --show-toplevel)
ARTIFACT_DIR=${ARTIFACT_DIR:-$ROOT/docs/perf/artifacts/event-history-producer-2026-07}
STATE_DIR=${EVENT_HISTORY_PERF_STATE_DIR:-$ROOT/target/event-history-criterion-state}
BASELINE_REF=refs/remotes/origin/main
BASELINE_NAME=event-history-exact-baseline
FENCE=$ROOT/docs/perf/event-history-host-fence.sh
VALIDATOR_REL=docs/perf/validate-event-history-criterion.py
PERF_VALIDATOR_REL=docs/perf/validate-event-history-perf.py
FULL_COMPARISON_REL=docs/perf/validate-event-history-full-comparison.py
RECEIPT_VALIDATOR_REL=docs/perf/validate-event-history-receipt.py
BENCH_REL=crates/api/benches/event_history_producer.rs
BENCH_SUPPORT_REL=crates/rib/src/manager/bench_support.rs
DRIVER_REL=docs/perf/run-event-history-criterion.sh
FULL_DRIVER_REL=docs/perf/run-event-history-full-daemon.sh
FENCE_REL=docs/perf/event-history-host-fence.sh
WRAPPER_REL=docs/perf/bgperf-rustbgpd-ehm-wrapper.sh
WORK_ROOT=''

cleanup() {
    if [[ -n "$WORK_ROOT" ]]; then
        for directory in "$WORK_ROOT/base" "$WORK_ROOT/candidate"; do
            if [[ -d "$directory" ]]; then
                git -C "$ROOT" worktree remove --force "$directory" >/dev/null 2>&1 || true
            fi
        done
        rm -rf -- "$WORK_ROOT"
    fi
}
trap cleanup EXIT

fail() {
    printf 'event-history producer Criterion error: %s\n' "$*" >&2
    exit 1
}

read_value() {
    local file=$1 key=$2
    awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; found=1 } END { if (!found) exit 1 }' "$file"
}

require_safe_build_environment() {
    local name
    for name in RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER; do
        [[ -z "${!name:-}" ]] || fail "$name must be unset for retained measurements"
    done
    while IFS='=' read -r name _; do
        case "$name" in
            CARGO_PROFILE_* | CARGO_TARGET_*_RUSTFLAGS)
                fail "$name must be unset for retained measurements"
                ;;
        esac
    done < <(env)
    export CARGO_INCREMENTAL=0
}

repo_slug() {
    local remote
    remote=$(git -C "$ROOT" remote get-url origin)
    case "$remote" in
        git@github.com:lance0/rustbgpd.git | https://github.com/lance0/rustbgpd.git | https://github.com/lance0/rustbgpd)
            printf '%s\n' lance0/rustbgpd
            ;;
        *) fail 'origin is not the canonical lance0/rustbgpd repository' ;;
    esac
}

write_host_fingerprint() {
    local output=$1 cpu_model physical_cores logical_cpus memory_bytes
    cpu_model=$(awk -F: '/model name/ { sub(/^[[:space:]]+/, "", $2); print $2; exit }' /proc/cpuinfo)
    logical_cpus=$(getconf _NPROCESSORS_ONLN)
    physical_cores=$(lscpu -p=CORE,SOCKET | awk '
        !/^#/ { seen[$1 FS $2]=1 }
        END { for (key in seen) count++; print count + 0 }
    ')
    memory_bytes=$(awk '/MemTotal:/ { print $2 * 1024 }' /proc/meminfo)
    {
        printf 'schema=1\n'
        printf 'kernel=%s\n' "$(uname -srm)"
        printf 'architecture=%s\n' "$(uname -m)"
        printf 'cpu_model=%s\n' "$cpu_model"
        printf 'physical_cores=%s\n' "$physical_cores"
        printf 'logical_cpus=%s\n' "$logical_cpus"
        printf 'memory_bytes=%.0f\n' "$memory_bytes"
        printf 'repo_fs=%s\n' "$(findmnt -n -T "$ROOT" -o FSTYPE)"
        printf 'tmp_fs=%s\n' "$(findmnt -n -T /tmp -o FSTYPE)"
    } >"$output"
}

write_toolchain() {
    local output=$1
    {
        rustc -Vv
        cargo -Vv
        protoc --version
        perf --version
    } >"$output"
}

config_hash() {
    local cargo_home=${CARGO_HOME:-$HOME/.cargo}
    local legacy=$cargo_home/config modern=$cargo_home/config.toml
    for config in "$legacy" "$modern"; do
        if [[ -e "$config" || -L "$config" ]]; then
            [[ -f "$config" && ! -L "$config" ]] || \
                fail "Cargo home configuration is not a regular file: $(basename "$config")"
        fi
    done
    if [[ -f "$legacy" && -f "$modern" ]]; then
        fail 'both Cargo home config and config.toml exist; measurement input is ambiguous'
    elif [[ -f "$legacy" ]]; then
        sha256sum "$legacy" | awk '{print $1}'
    elif [[ -f "$modern" ]]; then
        sha256sum "$modern" | awk '{print $1}'
    else
        printf '%s\n' absent
    fi
}

build_environment_hash() {
    python3 <<'PY'
import hashlib
import json
import os

exact = {
    "AR", "CC", "CFLAGS", "CPATH", "CXX", "CXXFLAGS", "LD", "LDFLAGS",
    "LIBRARY_PATH", "PATH", "PROTOC", "RUSTUP_TOOLCHAIN", "SOURCE_DATE_EPOCH",
}
prefixes = ("CARGO_", "PKG_CONFIG_", "RUST")
relevant = {
    name: value
    for name, value in os.environ.items()
    if name in exact or name.startswith(prefixes)
}
payload = json.dumps(relevant, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
print(hashlib.sha256(payload.encode()).hexdigest())
PY
}

harness_hashes() {
    local source=$1 output=$2
    (
        cd "$source"
        sha256sum "$BENCH_REL" "$BENCH_SUPPORT_REL" \
            "$DRIVER_REL" "$FULL_DRIVER_REL" \
            "$FENCE_REL" "$WRAPPER_REL" "$VALIDATOR_REL" \
            "$PERF_VALIDATOR_REL" "$FULL_COMPARISON_REL" \
            "$RECEIPT_VALIDATOR_REL"
    ) >"$output"
}

sanitize_build_receipt() {
    local raw=$1 output=$2 target_dir=$3 binary_file=$4
    python3 - "$raw" "$output" "$target_dir" "$binary_file" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

raw, output, target_root, binary_output = map(Path, sys.argv[1:])
target_root = target_root.resolve()
executables = set()
receipt = []
with raw.open(encoding="utf-8") as source:
    for line in source:
        message = json.loads(line)
        if message.get("reason") != "compiler-artifact":
            continue
        target = message.get("target", {})
        executable = message.get("executable")
        if (
            target.get("name") == "event_history_producer"
            and "bench" in target.get("kind", [])
            and executable
        ):
            path = Path(executable).resolve()
            try:
                path.relative_to(target_root)
            except ValueError:
                raise SystemExit("benchmark executable escaped its exact target directory")
            executables.add(path)
            receipt.append(
                {
                    "target_name": target.get("name"),
                    "target_kind": target.get("kind"),
                    "features": sorted(message.get("features", [])),
                    "executable_basename": path.name,
                    "executable_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
if len(executables) != 1 or len(receipt) != 1:
    raise SystemExit(f"expected one benchmark executable, got {sorted(map(str, executables))!r}")
output.write_text(json.dumps(receipt[0], indent=2, sort_keys=True) + "\n", encoding="utf-8")
binary_output.write_text(str(executables.pop()) + "\n", encoding="utf-8")
PY
}

copy_criterion_json() {
    local source=$1 destination=$2
    rm -rf "$destination"
    mkdir -p "$destination"
    while IFS= read -r -d '' file; do
        local relative=${file#"$source"/}
        mkdir -p "$destination/$(dirname "$relative")"
        cp -- "$file" "$destination/$relative"
    done < <(
        find "$source" -type f \
            \( -path "*/$BASELINE_NAME/*.json" -o -path '*/new/*.json' -o -path '*/change/*.json' \) \
            -print0
    )
}

write_manifest() {
    local phase=$1 source_archive=$2
    local manifest=$ARTIFACT_DIR/microbench-$phase-SHA256SUMS
    local temporary
    temporary=$(mktemp "$ARTIFACT_DIR/.microbench-$phase-SHA256SUMS.XXXXXX")
    (
        cd "$ARTIFACT_DIR"
        {
            find . -type f \
                \( -name "microbench-$phase-*" -o -path "./criterion-$phase/*" \) \
                ! -name "microbench-$phase-SHA256SUMS" -print0
            printf './%s\0' "$(basename "$source_archive")"
        } | sort -zu | xargs -0 sha256sum
    ) >"$temporary"
    mv "$temporary" "$manifest"
    (cd "$ARTIFACT_DIR" && sha256sum --check "$(basename "$manifest")" >/dev/null)
}

privacy_check() {
    local phase=$1
    python3 - "$ARTIFACT_DIR" "$phase" <<'PY'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
phase = sys.argv[2]
private = re.compile(r"(?:/home/[^/\s]+|/Users/[^/\s]+|https?://[^/\s:@]+:[^/\s@]+@|git@)")
for path in root.rglob("*"):
    if not path.is_file() or path.is_symlink():
        continue
    if not (path.name.startswith(f"microbench-{phase}-") or f"criterion-{phase}" in path.parts):
        continue
    if path.suffix not in {".txt", ".tsv", ".json", ".csv", ".jsonl"} and "SHA256SUMS" not in path.name:
        continue
    text = path.read_text(encoding="utf-8", errors="strict")
    match = private.search(text)
    if match:
        raise SystemExit(f"private host material in {path.name}: {match.group(0)!r}")
PY
}

require_safe_build_environment
[[ -x "$FENCE" ]] || fail "missing executable host fence: $FENCE"
[[ -x "$ROOT/$VALIDATOR_REL" ]] || fail "missing executable Criterion validator"
if [[ -L "$ARTIFACT_DIR" || -L "$STATE_DIR" ]]; then
    fail 'artifact and state directories must not be symlinks'
fi
mkdir -p "$ARTIFACT_DIR" "$STATE_DIR/targets" "$STATE_DIR/criterion"
if [[ "$PHASE" == baseline ]]; then
    unexpected=$(find "$ARTIFACT_DIR" -mindepth 1 -maxdepth 1 ! -name README.md -print -quit)
else
    unexpected=$(find "$ARTIFACT_DIR" -mindepth 1 -maxdepth 1 \
        \( -name 'microbench-candidate-*' -o -name 'criterion-candidate' \
           -o -name 'rustbgpd-candidate-source.tar.gz' \) -print -quit)
fi
[[ -z "$unexpected" ]] || fail "refusing preexisting phase artifact: $unexpected"
ROOT_STATUS=$(git -C "$ROOT" status --porcelain=v1 --untracked-files=all -- . \
    ':(exclude)docs/perf/artifacts/event-history-producer-2026-07')
[[ -z "$ROOT_STATUS" ]] || fail 'invoking source checkout is dirty outside the receipt directory'
REPO_SLUG=$(repo_slug)

BASELINE_ENV=$ARTIFACT_DIR/microbench-baseline-environment.txt
if [[ "$PHASE" == baseline ]]; then
    BASELINE_COMMIT=$(git -C "$ROOT" rev-parse "$BASELINE_REF^{commit}")
    [[ "$(git -C "$ROOT" rev-parse HEAD)" == "$BASELINE_COMMIT" ]] || \
        fail "baseline must run from exact current $BASELINE_REF"
    [[ ! -e "$BASELINE_ENV" ]] || fail "baseline receipt already exists: $BASELINE_ENV"
    if find "$STATE_DIR/criterion" -mindepth 1 -print -quit | grep -q .; then
        fail 'baseline requires an empty event-history producer Criterion state directory'
    fi
    SOURCE_COMMIT=$BASELINE_COMMIT
else
    [[ -f "$BASELINE_ENV" && ! -L "$BASELINE_ENV" ]] || fail 'missing regular baseline environment receipt'
    (cd "$ARTIFACT_DIR" && sha256sum --check microbench-baseline-SHA256SUMS >/dev/null) || \
        fail 'baseline publication manifest no longer verifies'
    BASELINE_COMMIT=$(read_value "$BASELINE_ENV" baseline_commit)
    [[ "$BASELINE_COMMIT" =~ ^[0-9a-f]{40}$ ]] || fail 'invalid recorded baseline commit'
    SOURCE_COMMIT=$(git -C "$ROOT" rev-parse HEAD)
    [[ "$SOURCE_COMMIT" != "$BASELINE_COMMIT" ]] || fail 'candidate equals recorded baseline'
    git -C "$ROOT" merge-base --is-ancestor "$BASELINE_COMMIT" "$SOURCE_COMMIT" || \
        fail 'recorded baseline is not an ancestor of candidate'
    [[ ! -e "$ARTIFACT_DIR/microbench-candidate-environment.txt" ]] || \
        fail 'candidate receipt already exists'
fi

WORK_ROOT=$(mktemp -d /tmp/event-history-criterion-worktrees.XXXXXX)
git -C "$ROOT" worktree add --detach "$WORK_ROOT/base" "$BASELINE_COMMIT" >/dev/null
if [[ "$PHASE" == candidate ]]; then
    git -C "$ROOT" worktree add --detach "$WORK_ROOT/candidate" "$SOURCE_COMMIT" >/dev/null
    SOURCE_DIR=$WORK_ROOT/candidate
else
    SOURCE_DIR=$WORK_ROOT/base
fi
[[ -z "$(git -C "$WORK_ROOT/base" status --porcelain=v1 --untracked-files=all)" ]]
[[ -z "$(git -C "$SOURCE_DIR" status --porcelain=v1 --untracked-files=all)" ]]

HOST_FINGERPRINT=$ARTIFACT_DIR/microbench-$PHASE-host-fingerprint.txt
TOOLCHAIN=$ARTIFACT_DIR/microbench-$PHASE-toolchain.txt
HARNESS_HASHES=$ARTIFACT_DIR/microbench-$PHASE-harness-SHA256SUMS
write_host_fingerprint "$HOST_FINGERPRINT"
write_toolchain "$TOOLCHAIN"
harness_hashes "$SOURCE_DIR" "$HARNESS_HASHES"
if [[ "$PHASE" == candidate ]]; then
    cmp --silent "$ARTIFACT_DIR/microbench-baseline-host-fingerprint.txt" "$HOST_FINGERPRINT" || \
        fail 'candidate host fingerprint differs from baseline'
    cmp --silent "$ARTIFACT_DIR/microbench-baseline-toolchain.txt" "$TOOLCHAIN" || \
        fail 'candidate toolchain differs from baseline'
    cmp --silent "$ARTIFACT_DIR/microbench-baseline-harness-SHA256SUMS" "$HARNESS_HASHES" || \
        fail 'measurement harness differs from baseline'
fi
CARGO_CONFIG_SHA256=$(config_hash)
BUILD_ENVIRONMENT_SHA256=$(build_environment_hash)
if [[ "$PHASE" == candidate ]]; then
    [[ "$(read_value "$BASELINE_ENV" cargo_home_config_sha256)" == \
        "$CARGO_CONFIG_SHA256" ]] || \
        fail 'candidate Cargo home configuration differs from baseline'
    [[ "$(read_value "$BASELINE_ENV" build_environment_sha256)" == \
        "$BUILD_ENVIRONMENT_SHA256" ]] || \
        fail 'candidate build environment differs from baseline'
fi

# shellcheck source=docs/perf/event-history-host-fence.sh
source "$FENCE"
event_history_acquire_host_lock
PREFLIGHT=$ARTIFACT_DIR/microbench-$PHASE-host-preflight.tsv
event_history_init_host_preflight_log "$PREFLIGHT"

TARGET_DIR=$STATE_DIR/targets/$PHASE-$SOURCE_COMMIT
BUILD_RAW=$(mktemp /tmp/event-history-build.XXXXXX.jsonl)
BUILD_RECEIPT=$ARTIFACT_DIR/microbench-$PHASE-bench-build.json
BINARY_FILE=$(mktemp /tmp/event-history-binary.XXXXXX)
(
    cd "$SOURCE_DIR"
    CARGO_TARGET_DIR=$TARGET_DIR cargo bench -p rustbgpd-api \
        --features bench-internals --bench event_history_producer \
        --locked --no-run --message-format=json >"$BUILD_RAW"
)
sanitize_build_receipt "$BUILD_RAW" "$BUILD_RECEIPT" "$TARGET_DIR" "$BINARY_FILE"
rm -f "$BUILD_RAW"
BENCH_BIN=$(<"$BINARY_FILE")
rm -f "$BINARY_FILE"
[[ -x "$BENCH_BIN" ]] || fail 'resolved benchmark executable is not executable'
BENCH_SHA=$(sha256sum "$BENCH_BIN" | awk '{print $1}')

STATE_MANIFEST=$STATE_DIR/baseline-state-SHA256SUMS
if [[ "$PHASE" == candidate ]]; then
    [[ -f "$STATE_MANIFEST" && ! -L "$STATE_MANIFEST" ]] || fail 'missing baseline Criterion state manifest'
    [[ "$(sha256sum "$STATE_MANIFEST" | awk '{print $1}')" == \
        "$(read_value "$BASELINE_ENV" live_baseline_state_manifest_sha256)" ]] || \
        fail 'live baseline state manifest does not match the published baseline receipt'
    (cd "$STATE_DIR" && sha256sum --check "$(basename "$STATE_MANIFEST")" >/dev/null) || \
        fail 'baseline Criterion state changed before candidate run'
fi

for group in event_history_manager_self_time event_history_sqlite_end_to_end; do
    event_history_wait_for_idle "$PHASE-$group" "$PREFLIGHT"
    if [[ "$PHASE" == baseline ]]; then
        CRITERION_HOME=$STATE_DIR/criterion "$BENCH_BIN" --bench "$group" \
            --save-baseline "$BASELINE_NAME" --noplot
    else
        CRITERION_HOME=$STATE_DIR/criterion "$BENCH_BIN" --bench "$group" \
            --baseline "$BASELINE_NAME" --noplot
    fi
done
[[ "$(sha256sum "$BENCH_BIN" | awk '{print $1}')" == "$BENCH_SHA" ]] || \
    fail 'benchmark executable changed during measurement'
[[ "$(config_hash)" == "$CARGO_CONFIG_SHA256" ]] || \
    fail 'Cargo home configuration changed during measurement'
[[ "$(build_environment_hash)" == "$BUILD_ENVIRONMENT_SHA256" ]] || \
    fail 'build environment changed during measurement'
if [[ "$PHASE" == candidate ]]; then
    (cd "$STATE_DIR" && sha256sum --check "$(basename "$STATE_MANIFEST")" >/dev/null) || \
        fail 'candidate measurement changed the saved baseline state'
fi

if [[ "$PHASE" == baseline ]]; then
    STATE_MANIFEST_TMP=$(mktemp "$STATE_DIR/.baseline-state.XXXXXX")
    (
        cd "$STATE_DIR"
        find criterion -type f -path "*/$BASELINE_NAME/*.json" -print0 \
            | sort -z | xargs -0 -r sha256sum
    ) >"$STATE_MANIFEST_TMP"
    [[ -s "$STATE_MANIFEST_TMP" ]] || fail 'Criterion emitted no named baseline state'
    mv "$STATE_MANIFEST_TMP" "$STATE_MANIFEST"
    (cd "$STATE_DIR" && sha256sum --check "$(basename "$STATE_MANIFEST")" >/dev/null)
fi

CRITERION_ARTIFACT=$ARTIFACT_DIR/criterion-$PHASE
copy_criterion_json "$STATE_DIR/criterion" "$CRITERION_ARTIFACT"
ARTIFACT_STATE_MANIFEST=$ARTIFACT_DIR/microbench-$PHASE-baseline-state-SHA256SUMS
(
    cd "$ARTIFACT_DIR"
    find "criterion-$PHASE" -type f -path "*/$BASELINE_NAME/*.json" -print0 \
        | sort -z | xargs -0 -r sha256sum
) >"$ARTIFACT_STATE_MANIFEST"
[[ -s "$ARTIFACT_STATE_MANIFEST" ]] || fail 'retained artifact omitted named baseline state'
RESULTS=$ARTIFACT_DIR/microbench-$PHASE-results.csv
VERDICT=$ARTIFACT_DIR/microbench-$PHASE-verdict.json
python3 "$SOURCE_DIR/$VALIDATOR_REL" \
    --phase "$PHASE" \
    --criterion-dir "$CRITERION_ARTIFACT" \
    --baseline-name "$BASELINE_NAME" \
    --results "$RESULTS" \
    --verdict "$VERDICT"

SOURCE_ARCHIVE=$ARTIFACT_DIR/rustbgpd-$PHASE-source.tar.gz
git -C "$ROOT" archive --format=tar.gz --output "$SOURCE_ARCHIVE" "$SOURCE_COMMIT"
ENVIRONMENT=$ARTIFACT_DIR/microbench-$PHASE-environment.txt
{
    printf 'receipt_schema=2\n'
    printf 'phase=%s\n' "$PHASE"
    printf 'repository=%s\n' "$REPO_SLUG"
    printf 'source_commit=%s\n' "$SOURCE_COMMIT"
    printf 'baseline_commit=%s\n' "$BASELINE_COMMIT"
    printf 'baseline_ref=%s\n' "$BASELINE_REF"
    printf 'baseline_name=%s\n' "$BASELINE_NAME"
    printf 'live_baseline_state_manifest_sha256=%s\n' "$(sha256sum "$STATE_MANIFEST" | awk '{print $1}')"
    printf 'detached_worktree=1\n'
    printf 'separate_target_dir=1\n'
    printf 'shared_criterion_dir=1\n'
    printf 'cargo_incremental=0\n'
    printf 'cargo_home_config_sha256=%s\n' "$CARGO_CONFIG_SHA256"
    printf 'build_environment_sha256=%s\n' "$BUILD_ENVIRONMENT_SHA256"
    printf 'benchmark_binary_basename=%s\n' "$(basename "$BENCH_BIN")"
    printf 'benchmark_binary_sha256=%s\n' "$BENCH_SHA"
    printf 'host_lock_policy=rustbgpd-shared-user-lock\n'
    printf 'load_one_max=%s\n' "$EVENT_HISTORY_PERF_REQUIRED_LOAD_ONE_MAX"
    printf 'required_governor=performance\n'
} >"$ENVIRONMENT"
if [[ "$PHASE" == candidate ]]; then
    [[ "$(read_value "$ARTIFACT_DIR/microbench-baseline-environment.txt" live_baseline_state_manifest_sha256)" == \
        "$(read_value "$ENVIRONMENT" live_baseline_state_manifest_sha256)" ]] || \
        fail 'candidate consumed a different named baseline state'
fi

COMPLETION=$ARTIFACT_DIR/microbench-$PHASE-completion.txt
privacy_check "$PHASE"
{
    printf 'phase=%s\n' "$PHASE"
    printf 'source_commit=%s\n' "$SOURCE_COMMIT"
    printf 'matrix_complete=1\n'
    printf 'privacy_check=pass\n'
    printf 'run_utc_complete=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$COMPLETION"
privacy_check "$PHASE"
write_manifest "$PHASE" "$SOURCE_ARCHIVE"
printf 'event-history producer %s Criterion receipt complete: %s\n' "$PHASE" "$VERDICT"
