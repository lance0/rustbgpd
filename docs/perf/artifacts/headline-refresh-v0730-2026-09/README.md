# Headline refresh compact artifacts (2026-09-28)

These files retain the evidence behind the
[v0.73.0 headline refresh](../../headline-refresh-v0730-2026-09.md), with its
v0.72.0 and v0.68.0 controls.

| Path | Contents |
|---|---|
| `matrix/matrix-{v0730,v0720,v0680}-r{1,2,3}-{s2,s3}/` | Main-block matrix cells: `reloadstall.log`, `status`, 5-second process-tree `rss.csv`, daemon `vmhwm` (v0.72.0 and v0.73.0 runners only), and runner `provenance.json` |
| `matrix/matrix-{xh,v0680}-r{4,5,6}-{s2,s3}/` | Cross-harness block: `xh` is the v0.68.0 daemon under the v0.72.0 matrix runner and harness, interleaved with the v0.68.0 own-harness arm. `matrix-v0680-r6-s2` is retained but excluded from the receipt: other build work overlapped it briefly |
| `irr/irr-ov0-{v0730,v0720}-r{1..5}/`, `irr/irr-ov0-v0680-r{1,2,3}/` | IRR root `COMPLETED`, `rows.csv`, `provenance.json`, dataset digest, and the rustbgpd cell's `reloadstall.log`, `rss.csv`, `status` and dataset-refresh summary |
| `rr1000/rr1000-{v0730,v0720,v0680}-c{1,2,3}/` | Campaign `COMPLETED` plus each attempt's `phase.json`, `provenance.json` and `rss.json` |
| `progress.txt` | Campaign driver log, with the load average and kernel swap counters at every run boundary |
| `summary.csv` | Every value the receipt reports, one row per run, round and metric |
| `establishment-span.csv` | Per-leg span from the first to the 700th `session established` daemon log record |
| `daemon-reload.csv` | Per-reload daemon-log intervals: SIGHUP received to config source loaded and to config reload complete, with the logged `validate_ms` and RIB transition time |
| `bgperf2-spot-check.csv` | The three single-run bgperf2 rows for the v0.73.0 spot-check |
| `driver/` | The campaign driver as run (see below) |

## Arms and identities

Each arm ran from a local, never-published commit whose tree is identical to
its release. The commits exist only to satisfy the IRR runner's source gate,
which accepts `origin/main` or a descendant. Matrix and IRR provenance files
name those local commits; the tree hashes are the verifiable identity.

| Arm | Release tree | Daemon SHA-256 (this build directory) |
|---|---|---|
| `v0730` | `8a15d254039aa680371702c9deb5bf87bacedfb7` | `22cf7d4bf3c09bea4c30f402df5820c3b0f0e5f98f848b56b8b0aee5e3cab90f` |
| `v0720` | `4ff22f7e882d5ade6057eacbe1e7da5613955838` | `b7757f088462865ead3d26b8e108fb61aa02dafaa24db34132e7098b51b66613` |
| `v0680` | `77600eafd878c19cccea0cca02efc42d94b4358a` | `82fe1b791c8b5f62ead6431cc675dbe7e47de0fd53e44327c57f283d8a841125` |
| `xh` | `4ff22f7e882d5ade6057eacbe1e7da5613955838` (runner and harness) | `82fe1b791c8b5f62ead6431cc675dbe7e47de0fd53e44327c57f283d8a841125` (the v0.68.0 daemon) |

- **Daemon hashes depend on the build directory.** Cargo's per-package
  metadata includes the location of a path dependency. In each arm's
  directory, rebuilding at the real tag commit recompiled nothing and left
  the hash unchanged.
- **`reloadstall` hashes** are in each matrix `provenance.json`.
- **`rbgp` and `rs-config-render`** are recorded in the IRR `provenance.json`
  files. They are not on a timed path of a `rustbgpd-sighup` root.

## The driver

`driver/` holds the scripts that ran the campaign, adapted for publication.
Absolute scratch, checkout, repository and home paths are replaced with
`SCRATCH`, `WORKTREES`, `REPO`, `BGPERF2` and `HOME`; the logic is unchanged.

| File | Role |
|---|---|
| `setup.sh` | Local control commits, arm checkouts, the cross-harness checkout, and the untimed dry runs (run inline; recorded as a script) |
| `build.sh` | Three-package product build, `reloadstall` and `rrtransport` per arm, and the tag-checkout daemon builds |
| `tagcheck.sh` | Same-directory tag-commit rebuild and daemon hash comparison (run inline; recorded as a script) |
| `campaign.sh` | Main block: matrix, IRR 0% and RR1000, with arm order rotated per run |
| `campaign2.sh` | `campaign.sh` plus the cross-harness block (`xh`) |
| `campaign3.sh` | `campaign2.sh` plus the extra v0.73.0/v0.72.0 IRR 0% roots (`irrx`) |
| `run-window*.sh` | Hold the benchmark and gate locks and the quiet-window marker around one phase |
| `chain.sh`, `chain3.sh` | Start the next phase once the previous one logs its exit status |
| `bgperf2-spot.sh` | The bgperf2 single-run spot-check |
| `summary.py`, `report.py`, `daemon_reload.py` | Extraction into `summary.csv`, `establishment-span.csv` and `daemon-reload.csv`, and the per-arm range report |
| `bundle.py` | Sanitized copy of the evidence into this directory |

Local paths in the evidence files are replaced with `<run-root>`, `<scratch>`
and `<v0.73.0-tree>`-style placeholders. Full daemon logs, scenario
configurations and metrics scrapes remain outside the repository.

Verify the bundle with `sha256sum -c SHA256SUMS`.
