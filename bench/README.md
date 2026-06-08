# Benchmark tooling

This directory contains local tooling for repeatable performance checks.

## Criterion compare

`compare-criterion.sh` runs the same Criterion bench target at two git refs,
with both runs pinned to one CPU core through `taskset`. It writes a Markdown
summary, command logs, environment metadata, and raw Criterion artifacts under
`target/bench-compare/`.

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

| Benchmark | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI |

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
