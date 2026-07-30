# MRT snapshot allocation control protocol (July 2026)

## Status and decision boundary

Status: **bounded ordinary-output growth is GO and implemented**. The
immediate-parent comparison cleared every predeclared gate. Bounded
warm-checkpoint encoding is unchanged.

This receipt answers one narrow question: does bounded geometric growth reduce
ordinary MRT full-snapshot allocation churn without changing encoded output or
the warm-checkpoint budget contract? It does not measure actor cloning,
checkpoint admission, filesystem writes, compression, or restore, and it does
not authorize preallocation, streaming, or a RIB/actor redesign.

Any later optimization is held unless **both** fleet shapes clear every
predeclared GO threshold. A failure or an inconclusive/noisy result is a HOLD;
it is still useful evidence and must not be rewritten into a win.

## Bounded growth result

The candidate grows only ordinary full-snapshot top-level output geometrically
by 25%, from a 4 KiB floor. Standalone public encoders remain exact, and
budgeted warm-checkpoint buffers retain their separate capped doubling
strategy. Four complete A-B-B-A blocks compared control
`6e1c11edce2d8cd6e12036e7e4cc937f4e943dd4` with candidate
`f4a5a521a82b3bc7c8a99442d0f8964b596c323b`; both used the same locked harness
and fresh, isolated timing and diagnostic binaries.

| Shape | Time reduction, all blocks | Allocation-call reduction | Growth misses, control -> candidate | Final slack | Candidate peak overhead |
|-------|----------------------------:|--------------------------:|------------------------------------:|------------:|------------------------:|
| IXP many-source | 68.34%..69.61% | 53.13% | 6,809,607 -> 41 | 14.48% | 8,135,463 B |
| Two full feeds | 61.86%..63.29% | 46.43% | 10,410,415 -> 43 | 3.66% | 8,528,915 B |

Cumulative requested allocator bytes fell by more than 99.999% on both shapes.
All 32 retained comparison rows passed the closed validator; maximum timing CV
was 2.29%, all fixed-time bytes and decoded counts were identical, every
preflight used CPU 0 with the `performance` governor and no competing work, and
admitted one-minute load stayed in 1.03..1.87. These results apply to the two
disclosed ordinary MRT fleet shapes, not warm snapshots or filesystem
publication. The sanitized evidence is retained in
[`artifacts/mrt-output-growth-2026-07/`](artifacts/mrt-output-growth-2026-07/).

## Standalone control result

The quiet-host control at
`d2872d0cf9648ffe0be764eab712f5d8933d021e` passed the complete 16-row matrix,
schema, semantic-reader, allocator-equation, deterministic-diagnostic-byte,
privacy, and 5% CV gates. Both phase preflights held the shared host lock, found
no competing work, observed the `performance` governor, and recorded one-minute
loads of 0.97 at 2026-07-23T02:57:22Z before timing and 0.97 at
2026-07-23T02:57:38Z before diagnostics. CPU affinity was fixed to logical CPU
0. The reported CV is population standard deviation divided by the mean.

| Shape | Timing median | CV | Output bytes | Allocation calls | Requested bytes | Output growth misses | Peak overhead bytes |
|-------|--------------:|---:|-------------:|-----------------:|----------------:|---------------------:|--------------------:|
| IXP many-source | 458,231,764 ns | 0.359% | 33,642,720 | 12,815,613 | 114,530,702,750,252 | 6,809,607 | 3,262,777 |
| Two full feeds | 749,038,496 ns | 0.367% | 58,058,046 | 22,422,420 | 302,204,009,708,208 | 10,410,415 | 6,406,665 |

`Allocation calls` is `alloc + alloc_zeroed + realloc`. `Requested bytes` is
the cumulative size submitted across those calls, not resident memory or bytes
simultaneously live; the very large totals expose repeated realloc requests.
The timing ranges were 457,056,262..462,023,035 ns and
747,046,999..754,241,036 ns respectively.

Decision: **GO to measure a bounded preallocation candidate in a new PR**, using
the immediate-parent A/B protocol below. Millions of output-growth misses and
allocator calls on both representative shapes make that experiment worth
running. This control alone is not a speedup claim and cannot serve as the
future candidate's timing comparator.

The control host used Linux 6.17.0-35-generic, rustc 1.97.0, Cargo 1.97.0,
an AMD Ryzen Threadripper 7970X with 32 physical/64 logical CPUs, and
134,532,804,608 bytes of memory. No hostname, username, path, PID, or command
line is retained in the artifact.

## Real path and fleet shapes

Timing calls the public production `rustbgpd_mrt::encode_snapshot` entry point
with prebuilt routes. Diagnostics call a feature-gated wrapper around the same
internal encoder, adding allocator accounting, a top-level growth probe, and a
deterministic final-originated-time override. Diagnostic elapsed time is never
performance evidence. In both modes, `SnapshotReader` streams and validates
every encoded entry without collecting the decoded entries into another table.

The two fixed shapes represent different route-reflector and route-server
pressures:

| Shape | Paths | Sources | Intent |
|-------|------:|--------:|--------|
| IXP many-source | 400,400 | 700 | Many contributing peers sharing a route-server-sized table |
| Two full feeds | 800,800 | 2 | Two source peers each contributing a full-feed-sized table |

The benchmark fixtures contain IPv4 unicast routes only. The path and source
counts are assertions, not labels supplied after the run. Changing either
fixture count, bypassing the public encoder in timing mode, or failing to read
back every entry invalidates the sample. Each route carries ORIGIN, a four-AS
AS_PATH, synthesized NEXT_HOP, LOCAL_PREF, MED, and a community. Codec unit
tests separately prove the diagnostic originated-time override at both unicast
and EVPN write sites and prove that child and bounded warm buffers are excluded
from the growth probe.

## Two intentionally separate modes

The benchmark source compiles into two mutually exclusive measurement modes:

- **Timing** is the default build. It uses the daemon's shipped jemalloc
  directly and contains no tracking allocator or growth-probe atomics. It
  rejects the `timing` mode if the diagnostics feature was compiled in.
- **Diagnostic** requires the sole off-by-default
  `snapshot-allocation-diagnostics` feature. It enables allocation accounting,
  the top-level growth probe, and a deterministic originated-time override. It
  rejects the `diagnostic` mode if the feature is absent. Diagnostic elapsed
  time is never used as performance evidence.

The bounded CI versions are:

```bash
cargo test -p rustbgpd-mrt --bench snapshot_allocation -- timing --candidate --smoke
cargo test -p rustbgpd-mrt --features snapshot-allocation-diagnostics \
  --bench snapshot_allocation -- diagnostic --candidate --smoke
```

Full retained runs use the same source and mode guards:

```bash
set -euo pipefail
source tests/soak/host-lock.sh
source docs/perf/event-history-host-fence.sh
acquire_rustbgpd_host_lock

CONTROL_SHA="$(git rev-parse HEAD)"
CONTROL_JSONL="$(pwd)/docs/perf/artifacts/mrt-snapshot-allocation-2026-07/control.jsonl"
CONTROL_CPU=0
TIMING_TARGET=/tmp/rustbgpd-mrt-allocation-timing
DIAGNOSTIC_TARGET=/tmp/rustbgpd-mrt-allocation-diagnostic
test "$(printf %s "$CONTROL_SHA" | wc -c)" -eq 40
test -z "$(git status --porcelain)"
test ! -e "$CONTROL_JSONL"

CARGO_TARGET_DIR="$TIMING_TARGET" \
  cargo bench --locked -p rustbgpd-mrt --bench snapshot_allocation --no-run
CARGO_TARGET_DIR="$DIAGNOSTIC_TARGET" \
  cargo bench --locked -p rustbgpd-mrt --features snapshot-allocation-diagnostics \
    --bench snapshot_allocation --no-run

preflight() {
  for _ in $(seq 1 300); do
    governor="$(cat "/sys/devices/system/cpu/cpu${CONTROL_CPU}/cpufreq/scaling_governor")"
    competing="$(
      event_history_competing_process_snapshot
      ps -eo comm= | awk '$1 ~ /^snapshot_alloc/ { print }'
    )"
    if [[ $governor == performance && -z $competing ]] &&
      awk 'BEGIN { ok = 0 } { ok = ($1 < 1.0) } END { exit !ok }' /proc/loadavg; then
      printf 'preflight pass: load_1m=%s governor=%s competing=none\n' \
        "$(awk '{print $1}' /proc/loadavg)" "$governor"
      return 0
    fi
    sleep 1
  done
  return 75
}

preflight
CARGO_TARGET_DIR="$TIMING_TARGET" taskset -c "$CONTROL_CPU" \
  cargo bench --locked -p rustbgpd-mrt --bench snapshot_allocation -- \
  timing --commit "$CONTROL_SHA" --output "$CONTROL_JSONL"
preflight
CARGO_TARGET_DIR="$DIAGNOSTIC_TARGET" taskset -c "$CONTROL_CPU" \
  cargo bench --locked -p rustbgpd-mrt --features snapshot-allocation-diagnostics \
    --bench snapshot_allocation -- \
  diagnostic --commit "$CONTROL_SHA" --output "$CONTROL_JSONL"
```

The output path must be absent before the timing command. The timing run creates
and appends 14 rows; the diagnostic run appends two. Validate the exact 16-row
mode/shape/sample matrix before creating `SHA256SUMS`. Full runs reject missing
output paths and revisions that are not 40 lowercase hexadecimal characters.

The smoke commands are compile-and-path gates, not benchmark results. The
implementation review records the isolated mutations that make these gates go
red. Codec unit tests, rather than the IPv4-only benchmark fixtures, guard the
EVPN override and child/bounded-buffer probe exclusions. Removing either CI
command would remove that mode's only per-commit execution and is therefore not
an acceptable "fix."

## Timed boundary and allocator semantics

The elapsed interval contains only the call to the real snapshot encoder,
including creation and growth of its returned top-level output. Fixture
construction, warmups, allocator-counter reset, growth-counter reset,
`SnapshotReader` validation, hashing, JSON serialization, and dropping the
output buffer are outside the interval.

Diagnostic tracking wraps the same shipped jemalloc allocator. Its
`alloc`, `alloc_zeroed`, `realloc`, and `dealloc` methods delegate directly to
jemalloc; especially, `realloc` retains jemalloc's native semantics rather than
using `GlobalAlloc`'s allocate-copy-free default. Counters are enabled only
around the encode call. Requested-byte totals count the sizes submitted to the
allocator. `baseline_live_requested_bytes` captures tracked live requested
capacity at the start of that window; `peak_live_delta_bytes` is the peak
tracked live requested capacity minus that baseline, and
`peak_live_overhead_bytes` subtracts the retained output length from that
delta. The absolute final and peak live values are retained for accounting
checks. These values are diagnostic estimates, not process RSS. For the future
candidate gate, "total allocator calls" means `alloc_calls +
alloc_zeroed_calls + realloc_calls`; `dealloc_calls` is a lifecycle/accounting
check and is not included in that total.

The allocation window is deliberately single-threaded. The harness starts no
other Rust thread while counters are enabled, and it fails if the final tracked
live delta is not exactly the returned output capacity; the relaxed counter
reset/read sequence is not a general concurrent profiler contract.

The `EncodeBuffer` diagnostic probe counts a capacity miss only for the
top-level, unbounded ordinary snapshot output. Its aggregate count must be at
least `path_count`; it does not assert that every individual route caused a
miss. Codec unit tests prove that ordinary child buffers and bounded
warm-checkpoint buffers do not increment this counter. Together, those
assertions show that a later growth experiment targets ordinary output without
weakening warm-budget enforcement.

In diagnostic mode, fixed caller record timestamps plus a diagnostics-only
final originated-time override make the complete MRT byte stream stable. The
wrapper shares the production encoder implementation and substitutes the value
at the final unicast and EVPN write sites. Production, timing mode, and the
public warm-encoding signatures retain their normal `SystemTime`/`Instant`
behavior. Only the timing build is used for elapsed-time claims.

## Standalone control and future ABBA protocol

This tranche retains a standalone control only. Run it from the exact first
commit of this tranche: the measurement harness applied directly to the chosen
current-main parent, before adding result artifacts. Record that 40-character
revision in every retained row and never substitute a moving branch name. For
each shape, timing mode performs two untimed warmups and emits seven retained samples;
diagnostic mode emits one retained row. The warmups are executed and disclosed
but are not publication rows. The resulting control matrix is exactly 14
timing rows plus two diagnostic rows. There is no metadata row.

A future growth candidate must not compare against this older standalone
control across days or environments. It must rerun its immediate-parent control
(A) and candidate (B), using identical harness source, in four complete
**A-B-B-A** blocks. Build A and B from clean detached worktrees with separate
Cargo target directories, the same locked dependency graph, and the same Rust
toolchain. Keep the order and rejected attempts; do not pool a partial block or
silently replace one side. Compute the paired median within each block before
the four-block decision, and retain that campaign in its own comparison
artifact/schema extension.

```bash
python3 bench/tests/test_verify_mrt_growth_campaign.py
python3 bench/verify-mrt-growth-campaign.py comparison.jsonl
```

The closed 32-row contract pins both shapes in four ABBA blocks, source/tree, binaries, one harness, seven timings, decoded byte identity, allocations, growth, slack, and peak overhead.
Control and `--candidate` diagnostics assert their declared path before emitting it; any drift or threshold miss is red. Attested raw rows use schema 2; the retained control remains schema 1.

Acquire the repository's shared benchmark/soak host lock before building or
running the control or either future revision. For every retained phase, record
UTC time, logical CPU affinity, CPU governor, one-minute load, toolchain, kernel,
memory, and competing benchmark/build processes. Use the `performance` governor
and the same pinned logical CPU throughout a block. Reject a phase if a
competing workload appears, the host fingerprint changes within a block, or
either shape's seven timing samples have coefficient of variation above 5%.
Noise rejection is not an invitation to select favorable samples: retain the
rejection reason and rerun the whole ABBA block.

## Predeclared GO/HOLD gates

A future growth candidate is GO only if **both** fleet shapes satisfy all of
these conditions against the immediate-parent control:

- at least 99% fewer top-level output reservations, with no more than 64 in the
  candidate;
- at least 20% fewer total allocator calls;
- at least 50% fewer requested allocator bytes;
- at least 5% faster paired timing median, with the candidate favorable in all
  four ABBA blocks;
- byte-identical complete MRT output, the same decoded entry count, and all
  reader semantic assertions passing; byte identity compares the control and
  candidate fixed-time diagnostic `raw_sha256` values, because production
  timing rows retain real route age;
- candidate `peak_live_overhead_bytes` no more than
  `min(control output_len_bytes / 4, 32 MiB)`; and
- final candidate output-capacity slack no more than 25% of
  `output_len_bytes`.

If either memory bound fails, the candidate is NO-GO or must use a smaller
growth factor and repeat the entire protocol. A threshold miss, inconsistent
pair direction, CV rejection, changed bytes, reader failure, wrong path count,
or absent path-probe evidence is HOLD. No subset of passing metrics overrides a
failed gate.

## Artifact schema and retention

The retained `control.jsonl` is newline-delimited JSON with one object per
retained sample and no hostnames, usernames, absolute paths, PIDs, process
arguments, credentials, or environment dump. Every row contains
`schema_version`, `variant`, `commit`, `mode`, `shape`, `smoke`,
`warmup_count`, `sample_index`, `path_count`, `prefix_count`, `source_count`,
`output_len_bytes`, `output_capacity_bytes`, `decoded_entry_count`,
`elapsed_ns`, `raw_sha256`, `semantic_sha256`, `allocator`, and `growth`.
Timing rows have numeric `elapsed_ns` and null `allocator`/`growth` values.
Diagnostic rows have null `elapsed_ns`, a populated allocator object, and a
populated growth object. Both modes retain raw and semantic SHA-256 digests.
The artifact README defines the nested fields.

The standalone control JSONL contains exactly seven timing rows and one
diagnostic row per shape, with no metadata row. Rejected attempts are logged
separately and never substituted into the retained matrix without rerunning the
whole affected phase. Every
numeric field must be a finite non-negative integer, every exact revision must
be a 40-character lowercase hexadecimal commit, and the retained file must
contain the complete expected mode/shape/sample matrix. The artifact README
defines the concrete field inventory. `SHA256SUMS` is created only after the
final sanitized JSONL passes its schema, matrix, privacy, and control-validity
gates.

The retained artifact location is
[`artifacts/mrt-snapshot-allocation-2026-07/`](artifacts/mrt-snapshot-allocation-2026-07/).
It contains the 16-row `control.jsonl`, its closed schema and result summary,
the sanitized `validation.txt` preflight and mutation receipt, and a
relative-path `SHA256SUMS` manifest covering both retained files.

Documentation statements in this protocol are not executable gates (mutation
proof N/A). The retained control was checked against the schema, matrix,
semantic, allocator, growth, CV, and privacy rules before checksumming. Seven
isolated validation mutations—missing row, extra field, fleet drift, broken
peak delta, absent growth signal, noisy timing, and a hostname injection—each
made that validation red. The two CI smoke commands and the benchmark's
internal assertions carry their own isolated revert-red proofs.
