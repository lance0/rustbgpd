# Headline refresh compact artifacts (2026-10-03)

These files are the evidence for the
[headline refresh on the jemalloc harness](../../headline-refresh-jemalloc-2026-10.md).
It compares main with a same-night harness-fix control.

| Path | Contents |
|---|---|
| `matrix/matrix-{base,main}-r{1,2,3}-{s2,s3}/` | Matrix cells: `reloadstall.log`, `status`, 5-second process-tree and cgroup `rss.csv`, daemon `vmhwm`, the swap-fenced `cgroup-memory` readout, and runner `provenance.json` |
| `irr/irr-ov0-{base,main}-r{1,2,3}/` | IRR root `COMPLETED`, `rows.csv`, `provenance.json` and dataset digest. The rustbgpd cell's `reloadstall.log`, `rss.csv`, `status` and dataset-refresh summary sit under `rustbgpd-sighup/` |
| `progress.txt` | Campaign log, with the load average, kernel swap counters and allowed CPUs at every leg boundary |
| `manifest.txt` | The campaign's shape and each arm's resolved commits |
| `placement.txt` | The campaign's CPU affinity, inherited by every runner, harness and daemon |
| `identity.tsv` | Each arm's tree, daemon commit, daemon SHA-256 and `reloadstall` SHA-256 |
| `summary.csv` | Every value the receipt reports, one row per run, round and metric |
| `establishment-span.csv` | Per-leg span from the first to the 700th `session established` daemon log record |
| `daemon-reload.csv` | Per-reload daemon-log intervals: SIGHUP received to config source loaded and to config reload complete, with the logged `validate_ms` and RIB transition time |
| `generation-phase.csv` | Per-reload fields of the daemon's "reload generation phase timing" record: pre-stage session apply, RIB transition, deferred refresh dispatch and the generation total, in ms |

## Arms and identities

`base` is the harness-fix control and `main` is main. Both are named in the
receipt by their contents.

| Arm | Commit | Tree | Daemon SHA-256 (this build directory) |
|---|---|---|---|
| `base` | `370e211b95ec3e4a7b07556146e31dd02f391ea6` | `cae43a47f9d597342c3ec0599a1ddbbfe23fbe36` | `f7b540cb49dd62ecab48f2462c6f773e65fab0e47f71ddecfb85208169e85d8e` |
| `main` | `481e0187d873dd8e7715033224be0fe90cb7d4e2` | `dc90a0c052af909f56a2625515fcd22e72fa658b` | `7ef213c92b7c9b1a6fc6551ec76e18cb4dbc552422c68ef7044b93d445322e8b` |

- **Local commits.** Each arm ran from a local, never-published commit with
  the arm's tree, parented on `origin/main` for the IRR runner's source gate.
  The provenance files name those commits; the tree hashes are the identity.
- **Daemon hashes depend on the build directory.** Before the first leg, the
  campaign rebuilt each arm's daemon at the arm's real commit in the same
  directory, and the hash matched.

## How the files were produced

- **The driver** is the in-repository
  [`run-campaign.sh`](../../../../bench/scale/headline/run-campaign.sh), run
  as `just bench-headline` with `CELLS=matrix,irr` and `RUNS=3`.
- **`summary.csv` and `establishment-span.csv`** are the campaign's own output
  from [`summarize.py`](../../../../bench/scale/headline/summarize.py).
  - **On this bundle,** `just bench-headline-summary <bundle> --out <dir>`
    reproduces every non-daemon row of `summary.csv` byte for byte.
  - **The daemon rows** need the daemon logs, which are not in the bundle.
- **`daemon-reload.csv`** was extracted from the daemon logs with the
  2026-09-28 receipt's extractor. Its 192 values match the daemon rows in
  `summary.csv`.
- **`generation-phase.csv`** comes from the same logs. Its RIB transition
  column matches `daemon-reload.csv`.

The bundle copies files without editing them. They contain no home or
checkout paths; the only absolute paths are the runners' fixed `/tmp`
scenario directories inside `reloadstall.log`. Full daemon logs, scenario
configurations and metrics scrapes remain outside the repository.

Verify the bundle with `sha256sum -c SHA256SUMS`.
