# Explain-cache opt-in memory receipt artifacts

These are the bounded retained artifacts for
[`explain-cache-opt-in-2026-07.md`](../../explain-cache-opt-in-2026-07.md). The
campaign ran from two clean worktrees — `515659b191b7fde91a1a1c9f973e7c8ae3731086`
(explain cache opt-in) and `530badfef268bed9821f5a363a415b77bed6c47f` (explain
cache on by default) — with the real release daemon, CLI, and `reloadstall` BGP
client harness.

Paths were sanitized to `$REPO` (the measured worktree), `$RUN` (the ephemeral
generated-scenario directory), and `$OUT` (the campaign output root); host
identifiers were removed. Large streams were deterministically gzip-compressed.
The two per-run Prometheus snapshots and the full daemon logs are **not**
retained — together they exceed 400 MiB and nothing in the receipt rests on
them. `SHA256SUMS` covers the retained, sanitized bytes.

## Contents

- `runs.tsv` indexes every accepted run: label, commit, fleet shape, explain
  setting, build profile, steady and peak resident memory, the 1 Hz sampled
  peak, the harness control-window figure, the jemalloc allocated/resident
  gauges, convergence time, and sample count. Its `retained_dir` column points
  at that run's directory here; the original timestamped run-directory names are
  preserved in `commands.txt` ordering and each `provenance.env`.
- `commands.txt` retains the exact driver invocation of every run in execution
  order. Regenerate rather than executing the sanitized placeholders verbatim.
- `toolchain.txt`, and each `runs/<label>/host.txt`, pin the build environment
  and hardware shape. `runs/<label>/preflight.tsv` retains the two quiet-host
  admission rows (pre-build and post-build) that gated the run.
- `runs/<label>/` holds that run's `provenance.env` (commit, tree, shape,
  explain setting, convergence timestamps, harness exit codes), `summary.env`
  (the derived steady/peak values), `exit-status.env`, `binaries.sha256`,
  `config.toml.gz`, `policy-section.txt` (the `[policy]` block as the daemon
  actually received it), `daemon-check.log`, `generator.log`,
  `reloadstall.log`, the three `proc-status-*.txt` `/proc` high-water snapshots,
  and `rss.tsv.gz` — the 1 Hz process-tree resident-memory stream every steady
  and sampled-peak figure is derived from.
- `member.rpol`, `gen-a.rpol`, and `gen-b.rpol` are retained once at the top
  level: the generator emits byte-identical policy files for every run.
- `dhat/` holds the two DHAT captures' component tables (`*.memory.tsv`), their
  full sanitized derivatives (`*.dhat-derivative.tsv.gz`), and
  `explain-bucket-netting.tsv` — the derived per-row table that separates the
  real explain-cache allocations from the `RejectedRouteStore` rows the
  classifier misattributes into the same bucket. DHAT bytes are *allocated*
  bytes from a non-jemalloc `release-prof` build and are not comparable to the
  resident-memory streams.

## Disclosures

The `smoke` run is a 20-session shakeout of the driver taken before the
campaign proper. It is retained for completeness and contributes to no result
in the receipt.

`runs/D1-dhat-true-20x5000` and `runs/D2-dhat-false-20x5000` are DHAT runs built
on the plain `release` profile. Their captures could not be classified — the
profile strips symbols, so DHAT emitted points with empty frame stacks — which
is why the receipt's DHAT attribution uses the `release-prof` D3/D4 pair
instead. The runs themselves succeeded and their resident-memory streams are
retained; only the heap profiles are unusable. That defect is recorded in
[`KNOWN_ISSUES.md`](../../../../KNOWN_ISSUES.md).

The retained driver,
[`run-explain-cache-variant.sh`](../../run-explain-cache-variant.sh), is its
final form. Its `PROFILE` knob was added ahead of the D3/D4 runs; every earlier
run used the same default (`release`) that the knob now names, so no earlier
run's behavior differs from what the retained script reproduces. Runs recorded
before that point have no `profile=` line in `provenance.env`.
