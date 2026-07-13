# Event-history producer measurement gate

Status: **harness implemented; measurements pending**. Do not implement the
producer offload until the baseline proceed gate below is captured on an idle
host and passes.

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

Pending host clearance. Summaries must be generated from the retained CSV/JSON
and full-daemon normalized receipts; terminal-only transcription is not valid.
