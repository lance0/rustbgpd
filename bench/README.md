# Benchmark tooling

This directory contains local tooling for repeatable performance checks.

**Development tooling only.** Nothing in this directory is production
surface: it is excluded from the default `cargo build`, the release
binary tarballs, and the default (runtime) container image. The
`evpn-load` crate's `evpn-tester` / `evpn-monitor` binaries are built
only with `--workspace` and ship only in the `dev` image target used
by the interop/soak labs.

## evpn-load

`evpn-load/` is the EVPN scale load generator — a deliberately minimal
iBGP tester (`evpn-tester`) + convergence monitor (`evpn-monitor`) for
RR benchmarking and the soak gates. It is not a BGP implementation and
not an operator tool; see the crate docs in `evpn-load/src/lib.rs` for
scope.

The tester validates the workload before listening for BGP. `--batch` must
be non-zero, and an enabled churn phase requires both a non-zero `--count`
and `--churn-rate`. A zero count remains useful for a session-only peer, and
`--rate 0` retains its historical meaning of unlimited initial injection.
`--hold-time 0` disables both the hold timer and periodic keepalives; non-zero
values must be at least 3 seconds so the hold/3 keepalive cadence is valid. The
VNI must fit its 24-bit wire field, and MAC/IP workloads are limited to the
16,777,216 unique synthetic MAC addresses. EAD-per-EVI workloads do not have
that MAC-space limit. The largest initial advertisement and active-churn
withdrawal chunks are encoded before bind and rejected if they exceed the
standard 4096-byte BGP message limit.

Both injection and churn pacing use a cumulative route-event budget rather
than rounding to whole batches per second. Each chunk waits for its cumulative
budget before it is sent, and the effective chunk size is capped by the rate so
a low configured rate cannot escape as an initial batch burst. Churn counts
each withdrawal and re-advertisement as one event, so `--churn-rate 1000` means
1000 total route events per second regardless of `--batch` and partial chunks
at the end of the route set. A pair scheduled after the churn-duration deadline
is not emitted. The M32b/M33 route-type, count, rate, batch, and churn arguments
are otherwise unchanged.

## Criterion compare

`compare-criterion.sh` runs the same Criterion bench target at two git refs,
with both runs pinned to one CPU core through `taskset`. It writes a Markdown
summary, command logs, environment metadata, and raw Criterion artifacts under
`target/bench-compare/`. Use `--features LIST` when the selected benchmark is
feature-gated; the same Cargo feature set is applied to both refs.

LAN-395 retained comparisons additionally use `--lan395-gate-out PATH`. That
mode rejects any missing or unexpected fanout row, requires the exact pinned
two-attempt transport matrix on a performance-governor CPU, applies every
acceptance threshold, and writes only a checksummed sanitized receipt. Generic
metadata, logs, absolute paths, and Criterion reports are local diagnostics and
must not be published.

`route_paging` is a manager-level custom harness for the long-running LAN-391
complete-traversal shape. One harness process runs exactly one scope/route/page
cell and reports one CSV row plus per-page synchronous handler-boundary
p50/p99/max. Those page timings include oneshot setup/retrieval around the
direct handler call: they are a conservative proxy for manager-task occupancy,
not an observation of actor scheduling or end-to-end gRPC latency. Unlike
Criterion, the harness does not multiply the 400k route/page-size 100
repeated-scan baseline by a minimum sample count.

Use the paired driver for retained comparisons:

```bash
bench/compare-route-paging.sh \
  --base 50399dac696507a827480be4a9dcfef49e1682b3 \
  --head d12cbaae37a9779ccc58617189253450b57c8fa4 \
  --routes 100000,400000 \
  --page-sizes 100,1000 \
  --repetitions 4 \
  --core 5
```

The driver requires the exact full commit IDs shown above, creates detached
worktrees for them, and overlays the invoking checkout's benchmark plus
bench-support source byte-for-byte into both. It records and verifies their
combined SHA-256, runs every traversal in a fresh process, and alternates
baseline-first/optimized-first order for paired repetitions. The harness
validates row totals, strict cursor order, page bounds, complete traversal, and
a deterministic ordered-route-key checksum. The
grouped fixture is intentionally distinct from the best control: two RR-client
members share a group while every sixteenth route is sourced by the queried
member and removed by member-specific split horizon. The driver rejects any
baseline/optimized row, page-count, or checksum disagreement and any grouped
fixture that collapses back to the best control. Both refs are required, must
resolve to the pinned distinct commits, and executable-line plus iterator-body
guards require the materialized call only at the baseline and the borrowed
grouped view only at the optimized ref. The normalized production diff must
match its pinned SHA-256, so extra edits inside an otherwise allowed
implementation file are rejected. After the shared overlays, all tracked Cargo
manifests and lockfiles, build scripts, Cargo config, and optional Rust
toolchain selector files must be byte-identical; dirty production files are
never measured. Retained comparisons also require a clean invoking checkout
and an exclusive, nonblocking lock on
`${RUSTBGPD_HOST_LOCK:-$HOME/.local/state/rustbgpd-host.lock}`; lock contention
exits 75 before either pinned tree is built. The driver prebuilds both trees
with `cargo bench --locked --no-run` into separate target directories and
retains one build log per side. Prebuilds use one Cargo job so the driver's own
compile phase does not manufacture a high one-minute load immediately before
the first sample. Each cell launches its side's resolved prebuilt executable
directly, so Cargo cannot rebuild between the idle preflight and the sample;
metadata retains both executable hashes.

Immediately before every fresh-process cell, the driver polls for at most 30
seconds and requires all of the following at the same point-in-time check: the
one-minute load average is below 2.0, no other `cargo`, `rustc`, `rrharness`, or
`route_paging` process is running, and the selected CPU reports the
`performance` governor. Every polling attempt, including a timeout, is retained
with UTC, load, governor, and matching process snapshot in
`cell-preflight.tsv`. The lock excludes only cooperating rustbgpd bench/soak
runners, and the process/load checks are a noise fence rather than a claim that
the whole host is isolated.
Retained metadata records the lock's default/override policy and a path digest,
not the host username or absolute home directory.

Each per-process CSV is retained under the comparison artifact's `raw/`
directory. The exact overlaid harness, bench-support module, comparison driver,
baseline/optimized production paging sources, and common Cargo/build inputs are
retained under `measurement-sources/` with verified manifests, and an
explicitly selected output directory must be empty.
On successful validation, a top-level `SHA256SUMS` covers the combined/raw
CSVs, logs, preflight evidence, metadata, and nested measurement-source
manifest.

`--no-taskset` marks the output `mechanics-only` and is never retained as
comparison evidence. A dirty checkout is rejected by default; the explicit
`--allow-dirty-mechanics --no-taskset` combination exists only to exercise the
driver while editing it. Metadata records the invoking HEAD, dirty flag and
status hash, evidence class, lock policy/digest, preflight thresholds, and exact driver,
harness, bench-support, compile-input-manifest, and measurement-source-manifest
hashes.

For a quick single-process mechanics check, invoke the bench target directly
with one `--routes`, `--page-size`, and `--scope` value. Do not retain or publish
that output as comparison evidence.

Requirements: `bash`, `git`, `cargo`, `python3`, `flock`, and `taskset` from
util-linux, plus Linux `/proc/loadavg` and per-CPU cpufreq governor reporting.
Use `--no-taskset` only for a quick mechanics check; its output is not
performance evidence.

The no-build driver guard test covers dirty-source rejection, the
mechanics-only override, host-lock contention/exit 75, and lock/prebuild/
preflight ordering:

```bash
bench/tests/test-route-paging-driver.sh
```

Example:

```bash
bench/compare-criterion.sh \
  --base origin/main \
  --head HEAD^^ \
  --core 5 \
  --features bench-internals \
  --package rustbgpd-transport \
  --bench fanout \
  --filter distribute_fanout \
  --attempts 2 \
  --require-performance \
  --lan395-gate-out target/lan395-criterion-receipt
```

For the default RIB benchmark surface:

```bash
bench/compare-criterion.sh \
  --base origin/main \
  --head HEAD \
  --core 8 \
  --package rustbgpd-rib \
  --bench rib_ops \
  --filter adj_rib_in_insert
```

For wire-codec benches:

```bash
bench/compare-criterion.sh \
  --base origin/main \
  --head HEAD \
  --core 8 \
  --package rustbgpd-wire \
  --bench codec
```

## RIB memory compare

`compare-rib-memory.sh` runs the ignored high-N RIB structural memory profile
at two git refs and writes a Markdown summary, CSV, logs, and metadata under
`target/rib-memory-compare/`. It measures allocator-tracked live heap for three
RIB shapes: one-peer Adj-RIB-In, two-peer Adj-RIB-In + Loc-RIB, and a
route-server / route-reflector fanout shape with two Adj-RIB-Out peers.

Requirements: `bash`, `git`, `cargo`, and `python3`. The compared refs must
already include the structured `memory_profile_high_n` harness.

```bash
bench/compare-rib-memory.sh \
  --base origin/main \
  --head HEAD \
  --profile quick
```

Profiles:

| Profile | Prefix counts | Use |
|---|---:|---|
| `quick` | 10k, 100k | Mechanics check / small PR review |
| `full` | 100k, 500k, 900k | Full-table memory review on a large host |

The summary flags a row for review only when head grows by at least **+5%**
and **+32 MiB** for the same shape/size. Smaller movement is recorded but
treated as allocator/map-capacity noise unless the PR is explicitly
memory-targeted.

## Multiple attempts (recommended on noisy hosts)

`--attempts N` runs the full base+head comparison N times. Odd attempts run
**base first**, even attempts run **head first**. Cache and codegen state
warm during whichever ref runs first; alternating ordering lets the
across-attempt mean cancel that bias. Even N (4, 6, ...) cancels it fully;
odd N still leaves a half-attempt of residual bias.

```bash
bench/compare-criterion.sh \
  --base origin/main \
  --head perf/my-branch \
  --core 8 \
  --attempts 4 \
  --filter adj_rib_in_insert/10000
```

With `--attempts ≥ 2` the summary table reports an aggregate row per
benchmark:

| Benchmark | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI | verdict |

The mean delta uses the head-vs-base sign convention (positive = head
slower = regression) computed from each attempt's saved baseline medians,
so it is independent of which ref ran first. The last-run 95% CI is
conservatively propagated from the last attempt's saved median CIs:
`(head_lo - base_hi)/base_hi .. (head_hi - base_lo)/base_lo`. It is wider
than Criterion's own `change/estimates.json` mean CI would be, but
computing the latter requires `--baseline` which conflicts with
`--save-baseline` — Criterion rejects the two flags combined. The
across-attempt stddev + min..max columns are the better signals on noisy
hosts anyway.

`--attempts 1` (the default) keeps the simpler single-row table used by
earlier versions.

## Regression verdict mode

`--fail-on-regression` turns the summary classifier into a tripwire. It exits
non-zero only when a row is a confident regression:

- completed attempts are at least `--verdict-min-attempts` (default: 3)
- `min..max` is entirely above zero
- `stddev` is below `--regression-max-stddev-pct` (default: 10)
- `mean delta` is at least `--regression-threshold-pct` (default: 3)
- the last run's propagated 95% CI is entirely above zero (all-positive
  across-attempt deltas whose last-run CI straddles zero stay advisory)

Verdict labels are:

- `regression`: confident regression; `--fail-on-regression` exits non-zero.
- `ci-straddles-zero`: all-positive deltas clearing the mean-delta threshold,
  but the last run's own 95% CI straddles zero — advisory, does **not** fail
  `--fail-on-regression`.
- `noise`: `min..max` brackets zero, so the sign is not reliable.
- `improvement`: the completed attempts are consistently faster.
- `positive-under-threshold`: consistently slower, but below the configured
  mean-delta threshold.
- `inconclusive-noisy`: consistently slower, but stddev is above the configured
  ceiling.
- `insufficient-attempts`: not enough completed attempts, or no stddev/min..max
  signal.
- `missing`: no usable baseline pair was found for that row.

The nightly workflow uses this mode against the latest release tag so real
accumulated regressions go red without failing on noisy single-row movement.

## Tuning + safety

Before taking numbers seriously, put the selected CPU into the
`performance` governor where the host allows it:

```bash
sudo cpupower frequency-set -g performance
```

The script reports the observed governor and warns when it is not
`performance`. Add `--require-performance` when a run should fail instead of
warning.

`--allow-dirty` only bypasses the local worktree cleanliness guard. Benchmark
runs still happen in detached worktrees at the resolved base/head commits, so
uncommitted changes never leak into either measurement.

`--keep-worktrees` leaves the detached worktrees under the run directory for
debugging failed or suspicious runs. Normal runs remove them after the summary
is written.

## Host coexistence (bench vs. soak)

When the bench runner shares a host with the soak runner, both
workloads acquire an exclusive `flock` on
`${RUSTBGPD_HOST_LOCK:-$HOME/.local/state/rustbgpd-host.lock}` before
doing real work — the Criterion and RIB-memory compare scripts directly,
the soak harnesses via the shared `tests/soak/host-lock.sh` helper. If
the lock is already held the script exits with a clear error rather than
producing useless numbers next to a busy soak (and vice versa). See
`tests/soak/README.md` ("Host mutex") for the sudo / `$HOME` trap —
running soak as root moves the lock under `/root/...` and bypasses
the guard.

The output summaries are designed to be pasted into PR comments. Keep the raw
artifact directory when reviewing regressions; Criterion's HTML report remains
the source for distribution details on timing benches, and the RIB-memory CSV is
the source for structural memory rows.

The same entrypoint is exposed through the manual `Criterion Bench Compare`
GitHub Actions workflow. That workflow expects a self-hosted runner labeled
`rustbgpd-bench` and defaults to `--attempts 3` for a usable signal on the
current runner shape.
