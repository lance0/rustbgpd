# Join-cohort converged-rejoin evidence

Compact evidence for the [October 2026 converged-rejoin qualification](../../join-cohort-converged-rejoin-2026-10.md).
All 12 cells and 36 rounds are retained. No measured round was excluded.

- `identity.txt`: control and candidate commits and trees, the candidate's
  merge parents, the control-to-candidate diffstat, toolchain, daemon and
  harness sha256, input-script hashes, CPU pinning and the run shape.
- `schedule.txt`: the declared cell order (arm, K, repetition).
- `runs.tsv`: harness and daemon exit codes for every cell.
- `job.log`: per-cell start and finish times, load average and quiet-gate
  results, in run order.
- `quiet/<cell>.tsv`: the two accepted quiet-host samples before each cell.
- `raw/<cell>/reloadstall.log`: the complete harness output for each cell,
  including per-joiner `rejoin_complete_s` for every round and the
  `converged_rejoin_csv` rows the analyzer reads.
- `samples.tsv`: the 36 parsed rounds.
- `analyze_j1.py`: the analyzer with the predeclared bars B1–B4.
- `verdict.txt`: the analyzer's table and verdict.

The published analyzer differs from the one that ran only in its module
docstring, one comment and the title line it prints, where internal tracker
references were removed; the bars and logic are unchanged. `identity.txt`
records the hash of the analyzer as run. Daemon logs, metrics dumps, scenario
configurations and binaries are not published.

To recompute `samples.tsv` and `verdict.txt` from the harness logs, run the
analyzer on a copy, since it writes `samples.tsv` and `verdict.json` into the
directory it reads:

```bash
tmp=$(mktemp -d)
cp -r docs/perf/artifacts/join-cohort-converged-rejoin-2026-10/. "$tmp"
python3 "$tmp/analyze_j1.py" "$tmp" > "$tmp/verdict.recomputed"
diff docs/perf/artifacts/join-cohort-converged-rejoin-2026-10/verdict.txt "$tmp/verdict.recomputed"
diff docs/perf/artifacts/join-cohort-converged-rejoin-2026-10/samples.tsv "$tmp/samples.tsv"
```

Both diffs are empty and the analyzer exits 0 (PASS).
