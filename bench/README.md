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

When the bench runner shares a host with the soak runner, both workloads
acquire a shared `flock` on `${RUSTBGPD_HOST_LOCK:-$HOME/.local/state/rustbgpd-host.lock}`
before doing real work. If the lock is already held the script exits with a
clear error rather than producing useless numbers next to a busy soak. The
soak harness uses the same path. Local dev boxes without that XDG state
directory skip the locking entirely.

The output summary is designed to be pasted into a PR comment. Keep the raw
artifact directory when reviewing regressions; Criterion's HTML report remains
the source for distribution details.

The same entrypoint is exposed through the manual `Criterion Bench Compare`
GitHub Actions workflow. That workflow expects a self-hosted runner labeled
`rustbgpd-bench` and defaults to `--attempts 3` for a usable signal on the
current runner shape.
