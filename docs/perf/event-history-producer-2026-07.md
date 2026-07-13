# LAN-393 event-history producer measurement gate

Status: **harness implemented; measurements pending**. Do not begin the
offload implementation until the baseline below is captured on an otherwise
idle host and the proceed gate passes.

This receipt separates the two costs that the existing bgperf2 comparison
combines:

- `lan393_manager_self_time` times only the synchronous
  `RibManager::publish_*` call. `noop` is the default-disabled sink; `ehm` is
  the production EHM sink, including route/EVPN proto conversion, prost
  encoding, index-string construction, and non-blocking queue enqueue. Every
  noop case finishes before EHM is started. For enabled cases, committed-cursor
  fences and health checks are Criterion setup and are not timed.
- `lan393_sqlite_end_to_end` starts at the same manager helper and stops after
  all 256 events arrive on EHM's post-commit broadcast. It therefore includes
  the manager phase, EHM queue, SQLite `synchronous=FULL` batch commit, durable
  cursor allocation, and committed-event delivery.

Both modes cover route-added, route-policy-filtered, and realistic EVPN
best-change events. Every timed iteration uses 256 owned events. Criterion uses
`BatchSize::PerIteration`, and the 4096-entry EHM queue is fenced empty before
every enabled iteration. The manager benchmark also waits for the previous
iteration's last cursor to be committed before starting another sample; queue
capacity alone is not treated as proof of a SQLite commit. Any
queue-full/closed/database drop exposed by the outbox metrics, degraded-state
transition, timeout, broadcast lag, or non-contiguous cursor fails the
benchmark rather than producing a deceptively fast result. After shutdown, the
benchmark re-reads the exposed degraded/drop/cursor signals. The production
shutdown API is best-effort and returns no storage result, so this harness does
not claim to prove that an otherwise-unreported final sidecar flush or WAL
checkpoint succeeded.

## Reproduce

Run from the repository root. Keep the target directory explicit so the exact
Criterion JSON copied below cannot be confused with another worktree's build.

```bash
set -euo pipefail

export CARGO_TARGET_DIR="$PWD/target/lan393"
export ARTIFACT_DIR="$PWD/docs/perf/artifacts/event-history-producer-2026-07"
HOST_FENCE="$PWD/docs/perf/lan393-host-fence.sh"
# shellcheck source=docs/perf/lan393-host-fence.sh
source "$HOST_FENCE"
lan393_acquire_host_lock
BASELINE_REF=${BASELINE_REF:-origin/main}
BASELINE_COMMIT=$(git rev-parse HEAD)
BASELINE_REF_COMMIT=$(git rev-parse "$BASELINE_REF^{commit}")
if [ "$BASELINE_COMMIT" != "$BASELINE_REF_COMMIT" ]; then
  printf 'baseline HEAD %s does not match %s at %s\n' \
    "$BASELINE_COMMIT" "$BASELINE_REF" "$BASELINE_REF_COMMIT" >&2
  exit 1
fi
BASELINE_STATUS=$(git status --porcelain=v1 --untracked-files=all)
if [ -n "$BASELINE_STATUS" ]; then
  printf '%s\n' "refusing dirty baseline source tree:" >&2
  printf '%s\n' "$BASELINE_STATUS" >&2
  exit 1
fi
if [ -d "$ARTIFACT_DIR" ]; then
  EXISTING_ARTIFACT=$(find "$ARTIFACT_DIR" -mindepth 1 \
    ! -name README.md -print -quit)
  if [ -n "$EXISTING_ARTIFACT" ]; then
    printf 'refusing nonempty artifact directory: %s\n' \
      "$EXISTING_ARTIFACT" >&2
    exit 1
  fi
fi
rm -rf "$ARTIFACT_DIR/criterion"
mkdir -p "$ARTIFACT_DIR/criterion"
HOST_PREFLIGHT="$ARTIFACT_DIR/microbench-baseline-host-preflight.tsv"
lan393_init_host_preflight_log "$HOST_PREFLIGHT"
BASELINE_TOOLCHAIN="$ARTIFACT_DIR/microbench-baseline-toolchain.txt"
{
  rustc -Vv
  cargo -Vv
  protoc --version
} > "$BASELINE_TOOLCHAIN"
BASELINE_TOOLCHAIN_SHA256=$(sha256sum "$BASELINE_TOOLCHAIN" | awk '{print $1}')

{
  printf 'baseline_commit=%s\n' "$BASELINE_COMMIT"
  printf 'baseline_ref=%s\n' "$BASELINE_REF"
  printf 'baseline_ref_commit=%s\n' "$BASELINE_REF_COMMIT"
  printf 'baseline_remote=%s\n' "$(git remote get-url origin)"
  printf 'baseline_status=%s\n' "$BASELINE_STATUS"
  printf 'toolchain_receipt=%s\n' "$(basename "$BASELINE_TOOLCHAIN")"
  printf 'toolchain_sha256=%s\n' "$BASELINE_TOOLCHAIN_SHA256"
  uname -a
  lscpu
  findmnt -T "$PWD" -o TARGET,SOURCE,FSTYPE,OPTIONS
  findmnt -T /tmp -o TARGET,SOURCE,FSTYPE,OPTIONS
  printf 'host_lock=%s\n' "$LAN393_HOST_LOCK_PATH"
  printf 'host_lock_acquired=1\n'
  printf 'host_preflight=%s\n' "$(basename "$HOST_PREFLIGHT")"
  printf 'load_one_max=%s\n' "$LAN393_REQUIRED_LOAD_ONE_MAX"
  printf 'preflight_wait_seconds=%s\n' "${LAN393_PREFLIGHT_WAIT_SECONDS:-120}"
  printf 'required_governor=performance\n'
} > "$ARTIFACT_DIR/environment.txt"

git archive --format=tar.gz \
  --output "$ARTIFACT_DIR/rustbgpd-baseline-source.tar.gz" \
  "$BASELINE_COMMIT"
( cd "$ARTIFACT_DIR" && \
  sha256sum rustbgpd-baseline-source.tar.gz > source-sha256.txt )

cargo bench -p rustbgpd-api \
  --features bench-internals \
  --bench event_history_producer \
  --locked \
  --no-run

lan393_wait_for_idle baseline-manager "$HOST_PREFLIGHT"
cargo bench -p rustbgpd-api \
  --features bench-internals \
  --bench event_history_producer \
  --locked \
  -- lan393_manager_self_time \
  --save-baseline origin-main

lan393_wait_for_idle baseline-sqlite "$HOST_PREFLIGHT"
cargo bench -p rustbgpd-api \
  --features bench-internals \
  --bench event_history_producer \
  --locked \
  -- lan393_sqlite_end_to_end \
  --save-baseline origin-main

cp -a \
  "$CARGO_TARGET_DIR/criterion/lan393_manager_self_time" \
  "$CARGO_TARGET_DIR/criterion/lan393_sqlite_end_to_end" \
  "$ARTIFACT_DIR/criterion/"
```

Those commands are the pre-offload harness run, whose production behavior must
still match current main. Preserve that target directory: the named
`origin-main` samples under it are what Criterion compares against.
The sourced host fence holds the same nonblocking
`${RUSTBGPD_HOST_LOCK:-$HOME/.local/state/rustbgpd-host.lock}` used by the other
retained rustbgpd performance drivers. After the locked warm build and before
each Criterion group, it records every poll and requires one-minute load below
the fixed 2.0 ceiling, no competing Cargo/rustc/rustbgpd benchmark/perf
process, and
`performance` on every available CPU governor. A timeout exits 75 instead of
emitting a publishable-looking noisy sample.
The baseline retains exact `rustc -Vv`, `cargo -Vv`, and `protoc --version`
output. The candidate captures the same receipt and byte-compares it before
building, so a compiler/toolchain change cannot masquerade as an offload gain.

On the candidate commit, use `--baseline origin-main` (not
`--save-baseline lan393-offload`) so Criterion actually performs the
before/after comparison:

```bash
set -euo pipefail

export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"$PWD/target/lan393"}
export ARTIFACT_DIR=${ARTIFACT_DIR:-"$PWD/docs/perf/artifacts/event-history-producer-2026-07"}
HOST_FENCE="$PWD/docs/perf/lan393-host-fence.sh"
# shellcheck source=docs/perf/lan393-host-fence.sh
source "$HOST_FENCE"
lan393_acquire_host_lock
CANDIDATE_COMMIT=$(git rev-parse HEAD)
RECORDED_BASELINE_COMMIT=$(awk -F= \
  '$1 == "baseline_commit" { print $2 }' \
  "$ARTIFACT_DIR/environment.txt")
test -n "$RECORDED_BASELINE_COMMIT"
if [ "$CANDIDATE_COMMIT" = "$RECORDED_BASELINE_COMMIT" ]; then
  printf '%s\n' "candidate commit matches recorded baseline" >&2
  exit 1
fi
if ! git merge-base --is-ancestor \
  "$RECORDED_BASELINE_COMMIT" "$CANDIDATE_COMMIT"; then
  printf 'recorded baseline is not an ancestor of candidate: %s !<= %s\n' \
    "$RECORDED_BASELINE_COMMIT" "$CANDIDATE_COMMIT" >&2
  exit 1
fi
CANDIDATE_STATUS=$(git status --porcelain=v1 --untracked-files=all \
  -- . \
  ':(exclude)docs/perf/artifacts/event-history-producer-2026-07')
CANDIDATE_ARTIFACT_STATUS=$(git status --porcelain=v1 --untracked-files=all \
  -- docs/perf/artifacts/event-history-producer-2026-07)
if [ -n "$CANDIDATE_STATUS" ]; then
  printf '%s\n' "refusing dirty candidate source tree:" >&2
  printf '%s\n' "$CANDIDATE_STATUS" >&2
  exit 1
fi
HOST_PREFLIGHT="$ARTIFACT_DIR/microbench-candidate-host-preflight.tsv"
lan393_init_host_preflight_log "$HOST_PREFLIGHT"
BASELINE_TOOLCHAIN="$ARTIFACT_DIR/microbench-baseline-toolchain.txt"
if [ ! -f "$BASELINE_TOOLCHAIN" ] || [ -L "$BASELINE_TOOLCHAIN" ]; then
  printf 'missing regular baseline toolchain receipt: %s\n' \
    "$BASELINE_TOOLCHAIN" >&2
  exit 1
fi
CANDIDATE_TOOLCHAIN="$ARTIFACT_DIR/microbench-candidate-toolchain.txt"
CANDIDATE_TOOLCHAIN_TMP=$(mktemp "$ARTIFACT_DIR/.candidate-toolchain.XXXXXX")
{
  rustc -Vv
  cargo -Vv
  protoc --version
} > "$CANDIDATE_TOOLCHAIN_TMP"
if ! cmp --silent "$BASELINE_TOOLCHAIN" "$CANDIDATE_TOOLCHAIN_TMP"; then
  printf '%s\n' 'candidate toolchain differs from retained baseline' >&2
  diff -u "$BASELINE_TOOLCHAIN" "$CANDIDATE_TOOLCHAIN_TMP" >&2 || true
  rm -f "$CANDIDATE_TOOLCHAIN_TMP"
  exit 1
fi
mv "$CANDIDATE_TOOLCHAIN_TMP" "$CANDIDATE_TOOLCHAIN"
CANDIDATE_TOOLCHAIN_SHA256=$(sha256sum "$CANDIDATE_TOOLCHAIN" | awk '{print $1}')
{
  printf 'candidate_commit=%s\n' "$CANDIDATE_COMMIT"
  printf 'recorded_baseline_commit=%s\n' "$RECORDED_BASELINE_COMMIT"
  printf 'candidate_baseline_ancestor=true\n'
  printf 'candidate_remote=%s\n' "$(git remote get-url origin)"
  printf 'candidate_status=%s\n' "$CANDIDATE_STATUS"
  printf 'preexisting_artifact_status=%s\n' "$CANDIDATE_ARTIFACT_STATUS"
  printf 'toolchain_receipt=%s\n' "$(basename "$CANDIDATE_TOOLCHAIN")"
  printf 'toolchain_sha256=%s\n' "$CANDIDATE_TOOLCHAIN_SHA256"
  printf 'baseline_toolchain_match=1\n'
  printf 'host_lock=%s\n' "$LAN393_HOST_LOCK_PATH"
  printf 'host_lock_acquired=1\n'
  printf 'host_preflight=%s\n' "$(basename "$HOST_PREFLIGHT")"
  printf 'load_one_max=%s\n' "$LAN393_REQUIRED_LOAD_ONE_MAX"
  printf 'preflight_wait_seconds=%s\n' "${LAN393_PREFLIGHT_WAIT_SECONDS:-120}"
  printf 'required_governor=performance\n'
} > "$ARTIFACT_DIR/candidate-environment.txt"
git archive --format=tar.gz \
  --output "$ARTIFACT_DIR/rustbgpd-candidate-source.tar.gz" \
  "$CANDIDATE_COMMIT"
( cd "$ARTIFACT_DIR" && \
  sha256sum rustbgpd-baseline-source.tar.gz \
    rustbgpd-candidate-source.tar.gz > source-sha256.txt )

cargo bench -p rustbgpd-api \
  --features bench-internals \
  --bench event_history_producer \
  --locked \
  --no-run

lan393_wait_for_idle candidate-manager "$HOST_PREFLIGHT"
cargo bench -p rustbgpd-api \
  --features bench-internals \
  --bench event_history_producer \
  --locked \
  -- lan393_manager_self_time \
  --baseline origin-main

lan393_wait_for_idle candidate-sqlite "$HOST_PREFLIGHT"
cargo bench -p rustbgpd-api \
  --features bench-internals \
  --bench event_history_producer \
  --locked \
  -- lan393_sqlite_end_to_end \
  --baseline origin-main

rm -rf "$ARTIFACT_DIR/criterion-comparison"
mkdir -p "$ARTIFACT_DIR/criterion-comparison"
cp -a \
  "$CARGO_TARGET_DIR/criterion/lan393_manager_self_time" \
  "$CARGO_TARGET_DIR/criterion/lan393_sqlite_end_to_end" \
  "$ARTIFACT_DIR/criterion-comparison/"

find "$ARTIFACT_DIR/criterion-comparison" \
  -path '*/change/estimates.json' -print | sort
```

The candidate estimates are retained in each case's `new/estimates.json`; the
comparison against `origin-main` is in `change/estimates.json`. Copy those
directories before any optional later `--save-baseline` run can replace
Criterion's `new` sample. Candidate cleanliness excludes only the receipt
directory itself, so the retained baseline artifacts can remain present while
any source or harness change still fails closed.

Capture CPU counters after the benchmark executable is warm-built. Set
`PERF_PHASE=baseline` for the proceed-gate evidence or `candidate` for the
later implementation comparison. The recipe binds every output to that
phase's exact clean commit, source archive, and byte-identical toolchain before
building. The manager command deliberately filters to one enabled case so the
counter and profile receipts are not blended with the no-op baseline.

```bash
set -euo pipefail

export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"$PWD/target/lan393"}
export ARTIFACT_DIR=${ARTIFACT_DIR:-"$PWD/docs/perf/artifacts/event-history-producer-2026-07"}
: "${PERF_PHASE:?set PERF_PHASE to baseline or candidate}"
case "$PERF_PHASE" in
  baseline)
    IDENTITY_FILE="$ARTIFACT_DIR/environment.txt"
    IDENTITY_KEY=baseline_commit
    PERF_SOURCE_ARCHIVE="$ARTIFACT_DIR/rustbgpd-baseline-source.tar.gz"
    ;;
  candidate)
    IDENTITY_FILE="$ARTIFACT_DIR/candidate-environment.txt"
    IDENTITY_KEY=candidate_commit
    PERF_SOURCE_ARCHIVE="$ARTIFACT_DIR/rustbgpd-candidate-source.tar.gz"
    ;;
  *)
    printf 'PERF_PHASE must be baseline or candidate, got %s\n' \
      "$PERF_PHASE" >&2
    exit 2
    ;;
esac

read_receipt_value() {
  awk -F= -v key="$2" \
    '$1 == key { sub(/^[^=]*=/, ""); print; found = 1 }
     END { if (!found) exit 1 }' "$1"
}

test -f "$IDENTITY_FILE" && test ! -L "$IDENTITY_FILE"
EXPECTED_COMMIT=$(read_receipt_value "$IDENTITY_FILE" "$IDENTITY_KEY")
if [[ ! "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'invalid %s in %s: %s\n' \
    "$IDENTITY_KEY" "$IDENTITY_FILE" "$EXPECTED_COMMIT" >&2
  exit 1
fi
test "$(git rev-parse "$EXPECTED_COMMIT^{commit}")" = "$EXPECTED_COMMIT"
test "$(git rev-parse HEAD)" = "$EXPECTED_COMMIT"

if [ "$PERF_PHASE" = candidate ]; then
  RECORDED_BASELINE_COMMIT=$(read_receipt_value \
    "$IDENTITY_FILE" recorded_baseline_commit)
  test "$RECORDED_BASELINE_COMMIT" = \
    "$(read_receipt_value "$ARTIFACT_DIR/environment.txt" baseline_commit)"
  git merge-base --is-ancestor \
    "$RECORDED_BASELINE_COMMIT" "$EXPECTED_COMMIT"
fi

PERF_SOURCE_STATUS=$(git status --porcelain=v1 --untracked-files=all \
  -- . \
  ':(exclude)docs/perf/artifacts/event-history-producer-2026-07')
if [ -n "$PERF_SOURCE_STATUS" ]; then
  printf '%s\n' "refusing dirty $PERF_PHASE perf source tree:" >&2
  printf '%s\n' "$PERF_SOURCE_STATUS" >&2
  exit 1
fi
test -f "$PERF_SOURCE_ARCHIVE" && test ! -L "$PERF_SOURCE_ARCHIVE"
ARCHIVE_CHECK=$(mktemp /tmp/lan393-perf-source.XXXXXX.tar.gz)
git archive --format=tar.gz --output "$ARCHIVE_CHECK" "$EXPECTED_COMMIT"
if ! cmp --silent "$ARCHIVE_CHECK" "$PERF_SOURCE_ARCHIVE"; then
  rm -f "$ARCHIVE_CHECK"
  printf 'retained %s source archive does not match %s\n' \
    "$PERF_PHASE" "$EXPECTED_COMMIT" >&2
  exit 1
fi
rm -f "$ARCHIVE_CHECK"

HOST_FENCE="$PWD/docs/perf/lan393-host-fence.sh"
# shellcheck source=docs/perf/lan393-host-fence.sh
source "$HOST_FENCE"
lan393_acquire_host_lock
PHASE_TOOLCHAIN="$ARTIFACT_DIR/microbench-$PERF_PHASE-toolchain.txt"
test -f "$PHASE_TOOLCHAIN" && test ! -L "$PHASE_TOOLCHAIN"
CURRENT_TOOLCHAIN=$(mktemp /tmp/lan393-perf-toolchain.XXXXXX)
{
  rustc -Vv
  cargo -Vv
  protoc --version
} > "$CURRENT_TOOLCHAIN"
if ! cmp --silent "$PHASE_TOOLCHAIN" "$CURRENT_TOOLCHAIN"; then
  diff -u "$PHASE_TOOLCHAIN" "$CURRENT_TOOLCHAIN" >&2 || true
  rm -f "$CURRENT_TOOLCHAIN"
  printf '%s\n' "current toolchain differs from $PERF_PHASE receipt" >&2
  exit 1
fi
rm -f "$CURRENT_TOOLCHAIN"

PERF_PREFIX="$ARTIFACT_DIR/microbench-$PERF_PHASE-perf"
PERF_ENVIRONMENT="$PERF_PREFIX-environment.txt"
PERF_HOST_PREFLIGHT="$PERF_PREFIX-host-preflight.tsv"
BENCH_BUILD="$PERF_PREFIX-bench-build.jsonl"
PERF_STAT="$PERF_PREFIX-stat.csv"
PERF_DATA="$PERF_PREFIX.data"
PERF_REPORT="$PERF_PREFIX-report.txt"
PERF_COMPLETION="$PERF_PREFIX-completion.txt"
PERF_MANIFEST="$PERF_PREFIX-SHA256SUMS"
for OUTPUT in \
  "$PERF_ENVIRONMENT" "$PERF_HOST_PREFLIGHT" "$BENCH_BUILD" \
  "$PERF_STAT" "$PERF_DATA" "$PERF_REPORT" "$PERF_COMPLETION" \
  "$PERF_MANIFEST"; do
  if [ -e "$OUTPUT" ]; then
    printf 'refusing existing %s perf receipt: %s\n' \
      "$PERF_PHASE" "$OUTPUT" >&2
    exit 1
  fi
done
lan393_init_host_preflight_log "$PERF_HOST_PREFLIGHT"

cargo bench -p rustbgpd-api \
  --features bench-internals \
  --bench event_history_producer \
  --locked \
  --no-run \
  --message-format=json \
  > "$BENCH_BUILD"

BENCH_BIN=$(
  python3 - "$BENCH_BUILD" <<'PY'
import json
import sys

executables = set()
with open(sys.argv[1], encoding="utf-8") as messages:
    for line in messages:
        message = json.loads(line)
        target = message.get("target", {})
        executable = message.get("executable")
        if (
            message.get("reason") == "compiler-artifact"
            and target.get("name") == "event_history_producer"
            and "bench" in target.get("kind", [])
            and executable
        ):
            executables.add(executable)

if len(executables) != 1:
    raise SystemExit(
        f"expected exactly one event_history_producer bench executable, got {sorted(executables)!r}"
    )
print(executables.pop())
PY
)
test -x "$BENCH_BIN"

{
  printf 'profile_phase=%s\n' "$PERF_PHASE"
  printf 'expected_commit=%s\n' "$EXPECTED_COMMIT"
  printf 'source_head=%s\n' "$(git rev-parse HEAD)"
  printf 'source_status=%s\n' "$PERF_SOURCE_STATUS"
  printf 'identity_receipt=%s\n' "$(basename "$IDENTITY_FILE")"
  printf 'source_archive=%s\n' "$(basename "$PERF_SOURCE_ARCHIVE")"
  printf 'source_archive_sha256=%s\n' \
    "$(sha256sum "$PERF_SOURCE_ARCHIVE" | awk '{print $1}')"
  printf 'toolchain_receipt=%s\n' "$(basename "$PHASE_TOOLCHAIN")"
  printf 'toolchain_sha256=%s\n' \
    "$(sha256sum "$PHASE_TOOLCHAIN" | awk '{print $1}')"
  printf 'bench_binary=%s\n' "$BENCH_BIN"
  printf 'bench_binary_sha256=%s\n' \
    "$(sha256sum "$BENCH_BIN" | awk '{print $1}')"
  printf 'host_lock=%s\n' "$LAN393_HOST_LOCK_PATH"
  printf 'host_lock_acquired=1\n'
  printf 'host_preflight=%s\n' "$(basename "$PERF_HOST_PREFLIGHT")"
  printf 'load_one_max=%s\n' "$LAN393_REQUIRED_LOAD_ONE_MAX"
  printf 'required_governor=performance\n'
} > "$PERF_ENVIRONMENT"

lan393_wait_for_idle "$PERF_PHASE-perf-stat" "$PERF_HOST_PREFLIGHT"
perf stat -x, \
  -e task-clock,cycles,instructions,branches,branch-misses,cache-misses \
  -o "$PERF_STAT" \
  "$BENCH_BIN" --bench --exact \
  'lan393_manager_self_time/route_added/ehm' --profile-time 30

lan393_wait_for_idle "$PERF_PHASE-perf-record" "$PERF_HOST_PREFLIGHT"
perf record --call-graph dwarf \
  -o "$PERF_DATA" \
  "$BENCH_BIN" --bench --exact \
  'lan393_manager_self_time/route_added/ehm' --profile-time 30

perf report --stdio \
  -i "$PERF_DATA" \
  > "$PERF_REPORT"

test -s "$PERF_STAT"
test -s "$PERF_DATA"
test -s "$PERF_REPORT"
{
  printf 'profile_phase=%s\n' "$PERF_PHASE"
  printf 'expected_commit=%s\n' "$EXPECTED_COMMIT"
  printf 'run_utc_complete=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'phase_complete=1\n'
} > "$PERF_COMPLETION"
(
  cd "$ARTIFACT_DIR"
  sha256sum \
    "$(basename "$PERF_ENVIRONMENT")" \
    "$(basename "$PERF_HOST_PREFLIGHT")" \
    "$(basename "$BENCH_BUILD")" \
    "$(basename "$PERF_STAT")" \
    "$(basename "$PERF_DATA")" \
    "$(basename "$PERF_REPORT")" \
    "$(basename "$PERF_COMPLETION")" \
    "$(basename "$PHASE_TOOLCHAIN")" \
    "$(basename "$PERF_SOURCE_ARCHIVE")" \
    > "$(basename "$PERF_MANIFEST")"
  sha256sum --check "$(basename "$PERF_MANIFEST")" >/dev/null
)
```

The Cargo JSON selection is intentional: hashed bench filenames are not ordered
by freshness, so sorting `target/release/deps` can silently profile a stale
executable. A phase receipt is complete only when its `completion.txt` and
relative-path `SHA256SUMS` both exist and the latter verifies.

## Full-daemon proceed profile

The proceed gate also requires a real daemon processing a full table with EHM
enabled. The pinned bgperf2 adapter correctly treats event history as
opt-in/default-off and omits the block when no mode is selected. For this
profile, the profiling-only wrapper in
`docs/perf/bgperf-rustbgpd-ehm-wrapper.sh` is the sole authority: both adapter
environment controls are unset, and the wrapper appends an explicit
`[event_history]` block to bgperf2's generated config. It stops its own process
before `exec`-ing the daemon. The host attaches `perf`, then resumes that same
PID so recording begins before the peers can converge. It does not change the
rustbgpd binary.

The checked-in driver has two deliberately separate modes:

- `baseline` is the only mode that satisfies the proceed gate. It reads the
  exact `baseline_commit` and `baseline_ref_commit` captured in
  `environment.txt`, requires both to agree with the clean source `HEAD`, and
  regenerates and hashes the archive from that commit before building.
- `candidate` is only for evaluating a later offload implementation. It reads
  `candidate_commit` from `candidate-environment.txt`, requires the clean
  source `HEAD` to match, and fails if the candidate equals the recorded
  baseline. Candidate artifacts have a separate filename prefix and cannot
  overwrite the baseline profile.

Both modes clone the fork into a disposable directory at the reviewed bgperf2
commit. The custom profiling image reproduces the adapter's digest-pinned Rust
1.95 and Debian bases, uses `cargo --locked`, and retains the image inspection,
content digest, binary hashes, compiler/Cargo/protoc versions, complete builder
and runtime package inventories, and OCI revision/base labels. Before profiling,
the driver verifies those labels against the exact rustbgpd and bgperf2 commits;
after bgperf starts, it also verifies that the running container uses that same
image digest. Docker's build context is an extraction of the retained
phase-specific rustbgpd commit archive, never the mutable checkout that invoked
the driver, so the image bytes and revision label have the same source of truth.
Both modes also hold the shared rustbgpd host lock from before the image build
through receipt completion. A retained TSV records the idle/load,
all-CPU-governor, and competing-process fence before the build and again after
the build, immediately before bgperf starts. The driver writes its completion
sentinel only after convergence, outbox-health, resource, and perf validation;
the final phase-specific `SHA256SUMS` binds that sentinel, every other
phase-prefixed file, and the exact rustbgpd/bgperf2 source archives.

Run the current-main proceed profile from the clean recorded baseline checkout:

```bash
set -euo pipefail

export RUSTBGPD_SOURCE="$PWD"
export ARTIFACT_DIR="$PWD/docs/perf/artifacts/event-history-producer-2026-07"
docs/perf/run-lan393-full-daemon.sh baseline
```

Do not use `candidate` until the current-main gate has passed and an offload
candidate has been implemented and measured with the preceding Criterion
comparison:

```bash
set -euo pipefail

export RUSTBGPD_SOURCE="$PWD"
export ARTIFACT_DIR="$PWD/docs/perf/artifacts/event-history-producer-2026-07"
docs/perf/run-lan393-full-daemon.sh candidate
```

The driver does not trust bgperf2's exit status alone. It parses the retained
scenario and final result, rejects any `FAILED` marker, and requires exactly
two BIRD peers with 100,000 prefixes each, `required=received=200000`, no
policy/filter input, and the expected rustbgpd scenario identity. It also
copies the two BIRD logs from this exact phase's custom run directory and makes
those copies authoritative for tester errors. The pinned adapter intends an
error to mean a case-sensitive line containing `RMT`, except lines containing
`NEXT_HOP`; its helper accidentally reads `/tmp/bgperf2/tester` regardless of
`--dir` and `--bench-name`, so the driver applies that rule itself to the
run-scoped copies and records their hashes. It inventories every source
`*.log` entry, requires exactly the two scenario peer names as regular,
non-symlink files, and verifies the retained copies remain byte-identical;
the run receipt, tester directories, and source/retained scenario paths reject
symlink components, and the two scenario copies must be byte-identical. Non-log
BIRD configuration and control-socket entries remain permitted. The
raw bgperf log retains the adapter's tester-error field for forensic context,
while the validator records that ignored value separately and writes the
authoritative run-scoped verdict to the normalized CSV. A stale default
directory therefore cannot create either a false pass or a false failure.

The pinned BIRD adapter does not implement timeout detection:
`find_timeouts()` is the base-class constant zero. The normalized CSV must
still carry zero in that compatibility field, but the receipt labels timeout
evidence as unsupported and makes no independent "zero BIRD timeouts" claim.
Remote-state diagnostics that BIRD labels `RMT` are covered by the authoritative
error rule above; timeout diagnostics without that label are not independently
classified. The normalized result, run-scoped tester logs, their hashes, and
validator output are retained beside the raw bgperf log and time series.

Use the inclusive call stacks rooted in RIB-manager processing as the proceed
gate denominator. The numerator is samples in `EhmRibSink`, route/EVPN proto
conversion, prost encoding, or allocation directly owned by those frames. The
raw `perf.data` and `perf-script.txt` make that classification reviewable; do
not use the isolated microbenchmark profile to satisfy the full-daemon gate.

## Proceed gate

Implement the offload only when both conditions are true on the current-main
baseline:

1. The EHM manager phase is at least 25% slower than noop in at least two of
   the three event shapes, with non-overlapping Criterion confidence intervals.
2. The enabled 2-peer, 100k-prefix full-table profile above (or an equally
   retained churn profile) attributes at least 5% of RIB-actor samples to
   `EhmRibSink`, route/EVPN proto conversion, prost encoding, or their
   directly-owned allocation work.

If either condition fails, LAN-393 is a no-proceed: SQLite or another stage is
the material cost and an encoder queue would add complexity without moving the
bound.

The implementation is accepted only if the candidate then demonstrates:

- at least 50% lower EHM-enabled manager producer time in this harness;
- noop/default-disabled time within 3% of baseline and overlapping confidence
  intervals;
- no regression in SQLite end-to-end throughput beyond the run-to-run noise
  recorded here;
- zero outbox drops/degraded transitions and contiguous committed cursors;
- full-daemon enabled/disabled CPU, RSS, queue-depth, drop, and cursor-integrity
  receipts retained alongside these microbench artifacts.

## Baseline results

Pending host clearance. Fill this table from Criterion's `estimates.json`; do
not transcribe terminal-only numbers without retaining the JSON.

| Mode | Event shape | Estimate | 95% CI | Events/s | Verdict |
|---|---|---:|---:|---:|---|
| manager/noop | route added | pending | pending | pending | pending |
| manager/ehm | route added | pending | pending | pending | pending |
| manager/noop | policy filtered | pending | pending | pending | pending |
| manager/ehm | policy filtered | pending | pending | pending | pending |
| manager/noop | EVPN best changed | pending | pending | pending | pending |
| manager/ehm | EVPN best changed | pending | pending | pending | pending |
| SQLite end-to-end | route added | pending | pending | pending | pending |
| SQLite end-to-end | policy filtered | pending | pending | pending | pending |
| SQLite end-to-end | EVPN best changed | pending | pending | pending | pending |
