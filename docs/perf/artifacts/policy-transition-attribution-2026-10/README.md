# Policy-transition attribution compact artifacts (2026-10-10)

These files are the evidence for the
[policy-transition attribution receipt](../../policy-transition-attribution-2026-10.md).
The layout mirrors the job's output directory, so the as-run analyzer reads
this bundle directly.

| Path | Contents |
|---|---|
| `acceptance.md` | The bars, predeclared on 2026-10-08 before any measured cell |
| `analyze.py` | The analyzer that applied them, as run |
| `verdict-q1-q3.txt`, `verdict-q1-q3.json` | Its output for the first window: Q1 PASS, Q2 INVALID, Q3 PASS, Q4 SKIPPED by the cutoff |
| `verdict-q4-as-run.txt`, `verdict-q4-as-run.json` | Its output after the Q4 rerun: SKIPPED, read from the stale `q4 skipped` line in the progress log |
| `verdict-q4-reanalysis.txt` | The same analyzer on a copy without that line: Q4 PASS |
| `progress.txt` | The job's progress log for both windows, including the stale line |
| `recompute.py` | Re-runs `analyze.py` on a scratch copy of this bundle, checks all three verdict files byte for byte, and checks the Q1 clock comparison the receipt quotes |
| `provenance.json` | Arms (commits, trees, daemon and `rbgp` SHA-256), instruments, build and run commands, host class and time window |
| `q1/{pre2952,post2952}-r{1,2}/` | Q1 policy-stats runs: `summary.json` (per-reload clocks and the cell's own verdict), `summary.txt`, `environment.json` (binary hashes, shape, placement) and the cell, engine and daemon exit codes; `*.quiet.tsv` is each run's quiet-host gate |
| `q4/v073-r1/` | The Q4 run, laid out as Q1 |
| `q3/{pre2952,post2952}/rustbgpd/` | Q3 matrix legs: `status`, `daemon.exit`, `provenance.json`, `quiet.tsv`, `cgroup-memory` and `vmhwm`. `daemon.log` holds only the `RIB export-policy transition completed` and `reload generation phase timing` lines, the two the analyzer reads |
| `q3/*.exit`, `q2.exit` | Runner and campaign exit codes |
| `q2/` | The `just bench-headline` campaign: `summary.csv`, `establishment-span.csv` and `report.md` from `summarize.py`; `manifest.txt`, `arms.txt`, `identity.tsv` and `placement.txt`; `progress.txt` with every leg boundary; per-leg `reloadstall.log`, `status`, `rss.csv`, `vmhwm`, `cgroup-memory` (where recorded) and runner `provenance.json` |

## Notes

- **Edits.** Files are copied unchanged, except for these title edits:
  - the first line of `acceptance.md` and the docstring title of `analyze.py`
    drop internal tracker names;
  - the publication-rule sentence in `acceptance.md` drops a tracker
    reference.

  The job script itself is not included, because it embeds local paths. Its
  commands are recorded in `provenance.json`. `reloadstall.log` keeps the
  runners' fixed scenario paths under `/tmp`, as other headline bundles do.
- **Q2 IRR cgroup peak.** `q2/irr-ov0-v075-r*/rustbgpd-sighup/` has no
  `cgroup-memory` or `memory-window` file, because v0.75.0's own IRR runner
  predates the cgroup peak measurement (#2942). That missing value is the
  only reason for Q2's INVALID.
- **Q2 local commits.** The headline campaign runs each arm from a local,
  never-published commit whose tree is the arm's tree. `identity.tsv` records
  each tree and daemon commit.
- **Daemon rows.** The daemon rows in `q2/summary.csv` come from the daemon
  logs, which are not in the bundle. Full daemon logs, scenario
  configurations and metrics scrapes remain outside the repository.
- **Reproduce.** `python3 recompute.py` exits 0 when every check passes.
