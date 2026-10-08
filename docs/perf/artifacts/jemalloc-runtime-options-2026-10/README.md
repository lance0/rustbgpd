# jemalloc run-time options compact artifacts (2026-10-08)

These files are the evidence for the
[jemalloc background_thread A/B](../../jemalloc-runtime-options-2026-10.md).
The two arms are `main` (jemalloc defaults) and `bgth`
(`_RJEM_MALLOC_CONF=background_thread:true` on the daemon only).

| Path | Contents |
|---|---|
| `acceptance.md` | The bars predeclared before the first measured leg |
| `analyze.py` | The analyzer that applied them, as run |
| `verdict.json`, `verdict.md` | Its output: per-leg values, bar results, allocator verification and the INVALID reason |
| `watch-daemons.py` | The `/proc` watcher that recorded each daemon's `_RJEM_MALLOC_CONF` and `jemalloc_bg_thd` thread count |
| `allocator-watch.tsv` | Its rows: one per daemon process, 15 in all |
| `opt-readback.txt` | `stats_print` read-back of `opt.background_thread` and `opt.metadata_thp` with the prefixed variable, and the ignored plain `MALLOC_CONF` |
| `arm.diff` | The `bgth` arm's only change from the base: the daemon launch lines |
| `matrix/matrix-{main,bgth}-r{1,2,3}-s2/` | Matrix cells: `reloadstall.log`, `status`, 5-second process-tree and cgroup `rss.csv`, daemon `vmhwm`, the swap-fenced `cgroup-memory` readout, and runner `provenance.json` |
| `irr/irr-ov0-{main,bgth}-r{1,2,3}/` | IRR root `COMPLETED`, `rows.csv`, `provenance.json` and dataset digest; under `rustbgpd-sighup/`, the cell's `reloadstall.log`, `rss.csv`, `status`, `vmhwm`, `cgroup-memory`, `memory-window` and dataset-refresh summary |
| `policy-stats/{main,bgth}-r1/` | The two completed operator-read runs: `summary.json`, `environment.json` and `cell.exit` |
| `summary.csv`, `establishment-span.csv` | Every headline value, one row per run, round and metric, from [`summarize.py`](../../../../bench/scale/headline/summarize.py) |
| `manifest.txt`, `identity.tsv`, `placement.txt` | Campaign shape, each arm's resolved commit and binary hashes, and CPU affinity |
| `progress.txt` | Headline leg boundaries with load average, swap counters and allowed CPUs |
| `stage-progress.txt` | The stage wrapper's log, including the policy-stats runs and the deliberate stop |

## Notes

- **Local commits.** Both arms ran from local, never-published commits
  parented on origin/main for the IRR runner's source gate. The `main` arm's
  tree is origin/main `f15804bc408273095c963a64f92e500b93af7d5c`; the `bgth`
  tree differs only by `arm.diff`.
- **Build-directory hashes.** `identity.tsv` records different daemon hashes
  for identical sources, because each build embeds its own directory. The
  receipt's "Same binaries" paragraph describes the section-level comparison
  that `analyze.py` applies instead.
- **Daemon rows** in `summary.csv` and `establishment-span.csv` come from the
  daemon logs, which are not in the bundle. On this bundle,
  `just bench-headline-summary <bundle> --out <dir>` reproduces every
  non-daemon row of `summary.csv` byte for byte.
- **Edits.** Files are copied unchanged except for the removal of local paths
  and branch names: `allocator-watch.tsv` lists executables relative to the
  campaign directory, and `stage-progress.txt` names the arm's local commit
  generically. The titles of `acceptance.md`, `analyze.py` and `verdict.md`
  drop internal tracker names. Full daemon logs, scenario configurations and
  metrics scrapes remain outside the repository.
