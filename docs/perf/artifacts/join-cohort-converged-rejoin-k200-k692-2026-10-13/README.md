# Join-cohort converged rejoin at K = 200 and 692: evidence

Compact evidence for the
[October 2026 K = 200 and 692 converged-rejoin receipt](../../join-cohort-converged-rejoin-k200-k692-2026-10-13.md).
All 12 cells are retained, including the two invalid ones. No cell was rerun
and no round was excluded beyond the driver's own validity rules.

- `manifest.txt`: base and head commits, trees and daemon sha256, the
  base-to-head diffstat, the driver state (`dirty=1`, see below), harness,
  scenario-generator, analyzer and `campaign.json` sha256, toolchain, kernel,
  shape and CPU placement. The local results path is replaced with
  `<queue-dir>`.
- `campaign.json`: the shape, schedule parameters and bars, fixed before the
  first cell.
- `schedule.txt`: the declared cell order (arm, K, repetition).
- `runs.tsv`: harness and daemon exit codes for every cell.
- `job.log`: per-cell start and finish times with load average, in run order.
- `quiet/<cell>.tsv`: the two accepted quiet-host samples before each cell.
- `raw/<cell>/reloadstall.log`: the complete harness output for each cell.
  It includes per-joiner `rejoin_complete_s` and the `converged_rejoin_csv`
  rows the analyzer reads. Both invalid cells end with the harness's `FAIL:`
  line.
- `raw/<cell>/vmhwm`: the daemon's `VmHWM` and `VmRSS` at the end of the cell.
- `readiness-misses.tsv`: the count of `readiness probe deadline exceeded`
  warnings in each cell's daemon log.
- `readiness-miss-events.txt`: those two warnings, verbatim.
- `samples.tsv`, `verdict.json`, `verdict.txt`: the analyzer's per-round
  samples, verdict and printed table.
- `driver-prebuilt.patch`: the one local change to the driver at head. With
  `PREBUILT_DIR` set, it checks the prebuilt binaries against
  `prebuilt-SHA256SUMS` and `prebuilt-refs.txt` and copies them in instead of
  building in the window.
- `prebuilt-SHA256SUMS`, `prebuilt-refs.txt`: the prebuilt daemons' and
  harness's hashes and the commits they were built from.

The analyzer is `bench/scale/reloadstall/converged_rejoin.py` in the
repository, unchanged since head; its sha256 matches `analyzer_sha256` in
the manifest. Daemon logs, metrics dumps, scenario configurations and
binaries are not published.

To recompute `samples.tsv`, `verdict.json` and `verdict.txt` from the harness
logs, run the analyzer on a copy, since it writes into the directory it reads:

```bash
tmp=$(mktemp -d)
cp -r docs/perf/artifacts/join-cohort-converged-rejoin-k200-k692-2026-10-13/. "$tmp"
python3 bench/scale/reloadstall/converged_rejoin.py analyze "$tmp" > "$tmp/verdict.recomputed"
echo "rc=$?"
diff docs/perf/artifacts/join-cohort-converged-rejoin-k200-k692-2026-10-13/verdict.txt "$tmp/verdict.recomputed"
diff docs/perf/artifacts/join-cohort-converged-rejoin-k200-k692-2026-10-13/samples.tsv "$tmp/samples.tsv"
diff docs/perf/artifacts/join-cohort-converged-rejoin-k200-k692-2026-10-13/verdict.json "$tmp/verdict.json"
```

The analyzer exits 4 (INVALID), and all three diffs are empty.
