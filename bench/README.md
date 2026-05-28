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

The output summary is designed to be pasted into a PR comment. Keep the raw
artifact directory when reviewing regressions; Criterion's HTML report remains
the source for distribution details.

The same entrypoint is exposed through the manual `Criterion Bench Compare`
GitHub Actions workflow. That workflow expects a self-hosted runner labeled
`rustbgpd-bench`; normal pull-request triggering should stay disabled until
that runner's noise floor has been measured.
