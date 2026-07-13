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
`target/bench-compare/`.

`route_paging` is a manager-level custom harness for the long-running LAN-391
complete-traversal shape. It reports one CSV row per traversal plus per-page
actor-occupancy p50/p99/max; unlike Criterion it does not multiply the 400k
route/page-size 100 repeated-scan baseline by a minimum sample count:

```bash
RUSTBGPD_ROUTE_PAGING_VARIANT=baseline \
RUSTBGPD_ROUTE_PAGING_COMMIT="$(git rev-parse HEAD)" \
taskset -c 5 cargo bench -p rustbgpd-rib --features bench-internals \
  --bench route_paging -- \
  --routes 100000,400000 --page-sizes 100,1000 \
  --repetitions 1 --output /tmp/route-paging.csv
```

Run the identical command at each pinned comparison commit with different
`VARIANT`/`COMMIT` values. The harness validates row totals, strict cursor
order, page bounds, and complete traversal while it measures.

Requirements: `bash`, `git`, `cargo`, `python3`, and `taskset` from
util-linux. Use `--no-taskset` only for a quick mechanics check; results from
an unpinned run should be treated as directional.

Example:

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
