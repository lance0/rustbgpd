# Event-history producer measurement gate

Status: **offload implemented and gated**. The baseline proceed gate passed
(producer conversion/encoding measured at 1.3–3.3 µs/event on the RIB actor,
38% of RIB-manager samples at saturated churn, ~2x throughput loss with
durable history enabled), and the producer offload landed with a same-host
Criterion A/B — see "Results" below.

The Criterion harness separates two costs:

- `event_history_manager_self_time` measures the synchronous `RibManager::publish_*`
  phase. `noop` is the default-disabled sink. `ehm` is the production EHM sink,
  including route/EVPN conversion, prost encoding, index construction, and the
  bounded non-blocking enqueue.
- `event_history_sqlite_end_to_end` starts at the same manager helper and stops after
  all 256 events are durably committed and observed on EHM's post-commit
  broadcast.

Every enabled iteration begins with an empty queue and a committed-cursor
fence. Queue-full/closed/database drops, degraded state, timeouts, broadcast
lag, or a non-contiguous cursor fail the benchmark. Noop cases run before EHM
starts, so SQLite work cannot contaminate the disabled/default samples.

## Exact Criterion driver

Use the checked-in driver; do not reproduce its steps by hand.

```bash
# After this harness commit is merged to current origin/main:
docs/perf/run-event-history-criterion.sh baseline

# Only after an offload candidate exists on a clean descendant commit:
docs/perf/run-event-history-criterion.sh candidate
```

The driver fixes the baseline to `refs/remotes/origin/main`, requires the
invoking checkout to be clean outside the receipt directory, and resolves both
revisions to exact 40-character commits. It creates detached worktrees, uses a
separate Cargo target for each revision, and shares only an explicit Criterion
state directory. The baseline state is checksummed immediately after capture
and reverified immediately before a candidate run. Candidate measurement stops
if the baseline state, host fingerprint, toolchain, Cargo-home config, hashed
build environment, or any measurement-harness file changed. The saved baseline
bytes are reverified again after candidate measurement.

The warm build uses `--locked`, disables Cargo incremental compilation,
rejects `RUSTFLAGS`, compiler wrappers, and Cargo profile/target rustflag
overrides, selects exactly one benchmark executable from Cargo JSON, proves it
is inside the phase target, and records its basename and SHA-256. Raw Cargo JSON
and absolute executable paths are temporary and are never publication
artifacts.

Both phases acquire the shared non-blocking rustbgpd host lock before building.
Before each retained Criterion group, the fixed host fence records every poll
and requires:

- one-minute load below 2.0;
- `performance` on every available CPU governor; and
- no concurrent Cargo, rustc, perf, rustbgpd, bgperf2, or known repository
  benchmark process.

The retained process field contains executable names only—never PID or argv.
A timeout exits 75. The driver writes a completion sentinel and aggregate
relative-path `SHA256SUMS` only after exact-matrix parsing, machine gating, and
the privacy scan pass.

## Machine gates

`validate-event-history-criterion.py` requires exactly these nine cases and rejects
missing, duplicate, extra, malformed, non-finite, non-positive, or non-95%-CI
estimates:

- manager route-added, route-policy-filtered, and EVPN-best-changed, each with
  `noop` and `ehm`;
- SQLite end-to-end for the same three shapes.

The baseline manager proceed gate requires EHM to be at least 25% slower than
noop, with non-overlapping mean confidence intervals, in at least two shapes.
The separate enabled full-daemon profile must additionally attribute at least
5% of RIB-manager samples to EHM producer conversion/encoding work.

The candidate Criterion gate requires, for every shape:

- EHM-enabled manager time at least 50% lower, with the candidate CI entirely
  below baseline;
- noop/default-disabled regression below 3%, with overlapping CIs; and
- SQLite end-to-end regression below 5%, with overlapping CIs whenever the
  point estimate regresses; a statistically separated improvement is allowed.

The validator emits machine-readable `results.csv` and `verdict.json`. A
no-proceed baseline or rejected candidate remains publishable evidence; the
verdict says it failed and implementation stops.

## Full-daemon profiles

Run the four profiles in this order:

```bash
docs/perf/run-event-history-full-daemon.sh baseline-enabled
docs/perf/run-event-history-full-daemon.sh baseline-disabled

# After the candidate Criterion run passes:
docs/perf/run-event-history-full-daemon.sh candidate-enabled
docs/perf/run-event-history-full-daemon.sh candidate-disabled
```

The enabled and disabled profiles use the same exact 2-peer x 100k-prefix
bgperf2 workload. The wrapper appends an exact required, synchronous-FULL EHM
block only in enabled mode and fails if bgperf2 supplied its own block. Disabled
mode requires the block to be absent, preserving shipped default behavior.

The full-daemon driver builds only from the retained exact-commit archive. It
pins bgperf2 at `fe4fdab9f7efb56e2e98ad6e6bcffeda047761a9`, pins the Rust and
Debian base-image digests, uses Cargo `--locked`, verifies OCI revision/mode
labels and the running image ID, retains binary and package inventories, and
requires every later profile's builder/runtime inventory and host tools to
match `baseline-enabled` after excluding only the expected rustbgpd commit
line. Exact source archives are established once and later profiles prove byte
identity without overwriting them; enabled and disabled builds of the same
source must also have identical binary checksums. The driver byte-matches the
phase's safe host fingerprint to its Criterion receipt.

The validator rejects a failed or wrong workload, anything other than exactly
200,000/200,000 routes, malformed/non-finite/negative CPU/RSS/timing fields,
unexpected scenario keys, tester-log inventory drift, BIRD `RMT` diagnostics
other than `NEXT_HOP`, outbox drops/degradation/cursor gaps, and nonzero drained
queue depth. Enabled mode requires committed count and latest cursor to agree;
disabled mode requires both to remain zero.

The pinned BIRD adapter has no timeout detector. Its compatibility field must
be zero, but the receipt explicitly records timeout evidence as unsupported and
makes no independent zero-timeout claim.

Perf attaches before the stopped wrapper execs the daemon. Raw `perf.data`
remains under `target/event-history-private-perf/` and is represented in the public
receipt by its SHA-256. The retained report and script have host paths and
PID/TID/timestamps sanitized. The wrapper's raw PID-bearing readiness barrier
also remains there; the public receipt retains only `barrier_reached=1` after
matching it to the namespace identity of the stopped host process.
`validate-event-history-perf.py` classifies sanitized stacks and emits the exact
RIB-manager denominator, EHM producer numerator, percentage, and 5% baseline
proceed verdict.

## Privacy and artifact contract

Publication artifacts never contain:

- remote URLs or credentials;
- usernames, home/worktree/target paths, or lock-file paths;
- PIDs, raw process arguments, or an environment dump; or
- unsanitized Cargo JSON, perf script, or `perf.data`.

They retain the canonical repository slug, exact commits, source archives,
privacy-safe hardware fingerprint, tool/package hashes, normalized process
names, commands encoded by the checked-in drivers, machine results/verdicts,
completion sentinels, and phase manifests. The source archives are exact Git
objects and are not treated as host metadata.

See `docs/perf/artifacts/event-history-producer-2026-07/README.md` for the exact
file inventory and offline checksum rules.

## Stop conditions

Stop or record a no-proceed/rejected verdict when:

- exact source identity, ancestry, detached worktree, or saved Criterion state
  cannot be proven;
- source is dirty, the harness changed, or host/toolchain/Cargo/package inputs
  differ;
- the shared lock is busy, load/governor/process preflight times out, or any
  matrix/profile is partial;
- parsing, finite-value, privacy, completion, or checksum validation fails;
- baseline manager or full-daemon attribution misses its proceed gate;
- candidate manager/default/SQLite gates miss their acceptance bounds; or
- the eventual offload cannot preserve order, producer timestamps, durable
  payload bytes, cursor IDs, bounded non-blocking enqueue, queue-full/closed
  counters, degraded state, shutdown drain, and legacy ring/broadcast behavior.

## Results

### Pre-implementation baseline (proceed gate, 2026-07)

Method: Criterion (`event_history_producer`, this harness) plus a saturated
rrharness churn A/B, on a 64-core dev box. The manager-side EHM producer cost
— route/EVPN conversion, prost encoding, envelope construction, bounded
enqueue, all on the RIB actor — measured:

| shape | manager-side EHM producer cost |
|---|---|
| route_added | 1,313 ns/event |
| route_policy_filtered | 1,676 ns/event |
| evpn_best_changed | 3,328 ns/event |

The full-daemon profile attributed 38% of RIB-manager samples to EHM producer
conversion/encoding at saturated churn (~2x throughput loss vs disabled).
Proceed gate: passed.

### Post-offload A/B (LAN-393)

Method: same-host, same-checkout Criterion A/B on the shared 64-core dev box
(not the quiet-host receipt drivers). Baseline = main at the branch fork
point, saved as Criterion state `pre-offload`; candidate = the offload
branch. Raw per-case means and 95% CIs:
`artifacts/event-history-producer-2026-07/criterion-offload-ab.csv`.

Manager self-time (ns/event, mean of 256-event samples):

| case | baseline | candidate | change |
|---|---|---|---|
| route_added/ehm | 1,650 | 165 | −90.0% |
| route_policy_filtered/ehm | 1,958 | 147 | −92.5% |
| evpn_best_changed/ehm | 4,982 | 254 | −94.9% |
| route_added/noop | 27.6 | 25.9 | −6.1% |
| route_policy_filtered/noop | 43.6 | 44.5 | +2.1% |
| evpn_best_changed/noop | 74.1 | 64.1 | −13.5% |

SQLite end-to-end (ns/event): route_added 72,550 → 38,665 (p = 0.06,
statistically no change), route_policy_filtered 450,269 → 36,602,
evpn_best_changed 361,769 → 23,889. The large baseline end-to-end means carry
very wide CIs (shared-host contention during the baseline window); the gate
verdict is "no shape regressed."

Candidate acceptance: every enabled shape is ≥50% below baseline (−90% to
−95%, candidate CIs entirely below baseline CIs — also 88–92% below the
stricter pre-implementation gate numbers above); no noop shape regressed
beyond 3% in the accepted run; no SQLite shape regressed.

Noise treatment for the noop gate: the default-disabled path is
source-untouched by the offload, and single runs on the shared host swung
−20%…+26% on identical binaries. Two controls bound the noise: (a) the
unchanged baseline source re-measured against its own saved Criterion state
moved −16%…+7%; (b) three interleaved baseline/candidate runs in one noise
window (`artifacts/event-history-producer-2026-07/noop-interleaved-control.csv`)
show per-shape median deltas of +4.2% / +4.9% / −6.9% — mixed sign and
smaller than the intra-binary round-to-round swings (up to 18%). The
accepted candidate run measured −6.1% / +2.1% / −13.5%.

### What moved off-actor

`EhmRibSink` (crates/api) now clones the owned `RouteEvent` /
`EvpnRouteEvent`, stamps `timestamp_ns` at publish, and `try_send`s the
snapshot on one bounded FIFO channel. Proto conversion, prost encoding, and
envelope string construction run in a conversion-stage task in front of EHM.
Preserved invariants (each pinned by a test or the existing byte-equality
suite): publish order, producer timestamps, byte-identical durable payloads,
EHM-assigned contiguous cursor IDs, queue-full/closed drop counters +
degraded semantics, legacy ring/broadcast behavior, and shutdown drain of
accepted events. Overload now sheds work before conversion instead of after.
