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
| `build/` | `build.out` (per-arm build exit codes and binary hashes) and `tagcheck.txt` (same-directory tag-commit rebuild check), with paths replaced by placeholders |

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

### Known defects in this driver as run

The scripts are published unchanged, so these defects remain in them. None of
them affected the evidence, for the reasons given after the list.

1. **`build.sh` depends on checkouts that `setup.sh` does not create.** Its
   second loop builds in `headline-v0730-tag-v0730` and
   `headline-v0730-tag-v0680`, but `setup.sh` never creates them. The script
   has no `set -e`, so a failed `cd` would not stop it: it would build in the
   wrong directory and still print `BUILD_DONE`.
2. **`run-window.sh` exits with the status of its final `echo`,** not the
   campaign's exit status.
3. **`run-window2.sh` has the same defect.**
4. **`run-window3.sh` has the same defect.**
5. **`tagcheck.sh` does not fail when a build fails.** It prints each rebuild's
   exit code into its output line, and the trailing `tee` masks the loop's
   status.
6. **`report.py` does not apply the contaminated-leg exclusion,** and it
   pools v0.68.0's main-block and cross-harness runs.
   - **How the leg was removed.** The published values came from a separate
     inline filter that split the blocks (runs 1–3 and 4–6) and dropped
     `matrix-v0680-r6-s2` by hand:
     `if r['arm'] == 'v0.68.0' and run == 6 and r['phase'] == 'matrix-s2': continue`.
   - **What the leg recorded.** It converged in 3.6 s, and its reload p50s
     were 1.32 / 1.48 / 1.40 / 1.31 s, inside v0.68.0's main-block range of
     1.20–1.52 s.
   - **What including it would change.** The cross-harness column's range and
     median would move, with no reading changed:
     - S2 completion from 1.19–1.44 s to 1.19–1.48 s, median 1.33 s in both;
     - stall median from 562 to 554 ms;
     - daemon SIGHUP-to-complete from 901–995 ms (median 943) to
       901–1,093 ms (median 956).
   - **Unaffected.** The main-table v0.68.0 values use runs 1–3 only, and no
     other published value involves the leg.

**Why the evidence is unaffected:**

- **The tag checkouts existed during the run.** Before `build.sh` ran, they
  were created inline with `git worktree add --detach
  <worktrees>/headline-v0730-tag-v0730 v0.73.0`, and likewise for `v0.68.0`.
  `build/build.out` records `tag-v0730 product=0` and `tag-v0680 product=0`
  and hashes daemons at both tag paths.
  - Those tag-path hashes are not used as an identity anywhere. A daemon
    built in a different directory hashes differently.
- **Every recorded leg exited 0.** `progress.txt` holds 52 per-leg exit codes:
  - 30 matrix cells, each also recording `status=pass`;
  - 13 IRR roots, each recording `"status":"pass"`;
  - 9 RR1000 campaigns, each recording `completed=pass`.
- **The phase exit codes were recorded despite defects 2–4.** Each wrapper
  wrote its phase's exit code before exiting: `campaign all rc=0`,
  `campaign xh rc=0` and `campaign irrx rc=0`. The chain scripts start a phase
  by reading that line, not the wrapper's exit status.
- **Every tag rebuild passed.** `build/tagcheck.txt` shows `rc=0`,
  `compiled=0` and `same=yes` for all three arms, and the three hashes match
  the daemon hashes above and in the matrix and IRR provenance files.

Local paths in the evidence files are replaced with `<run-root>`, `<scratch>`
and `<v0.73.0-tree>`-style placeholders. Full daemon logs, scenario
configurations and metrics scrapes remain outside the repository.

Verify the bundle with `sha256sum -c SHA256SUMS`.
