# Cross-daemon v0.74.0 compact artifacts (2026-10-03 to 2026-10-04)

These files are the evidence for the
[cross-daemon refresh at v0.74.0](../../cross-daemon-v0740-2026-10.md):
rustbgpd v0.74.0, BIRD 3.3.2 and OpenBGPD 9.2 on one host in one night.

| Path | Contents |
|---|---|
| `matrix/matrix-{rustbgpd,bird,openbgpd}-r{1,2,3}-{s2,s3}/` | Matrix cells: `reloadstall.log`, `status`, 5-second process-tree `rss.csv` and runner `provenance.json`. The rustbgpd cells also hold daemon `vmhwm` and the swap-fenced `cgroup-memory` readout |
| `irr/irr-ov{0,10,50}-rustbgpd-r{1,2,3}/` | IRR roots: `COMPLETED`, `rows.csv`, `provenance.json` and dataset digest. Each daemon's `reloadstall.log`, `rss.csv` and `status` sit under `rustbgpd-sighup/`, `bird/` and `openbgpd/`, with rustbgpd's dataset-refresh summary |
| `progress.txt` | The queue log: leg order, exit codes, load average at every leg boundary and host-lock waits. The campaign directory is written as `<campaign>` |
| `identity.txt` | Measured commit and tree, daemon and harness SHA-256, toolchain, competitor images and kernel |
| `summary.csv` | [`summarize.py`](../../../../bench/scale/headline/summarize.py) output: one row per run, round and metric |
| `establishment-span.csv` | Per-leg span from the first to the 700th `session established` record in rustbgpd's log |
| `matrix-tails.csv` | Per leg: p50, p95 and maximum from each labelled reload and flap line, plus the settled and peak RSS sample |
| `irr-cells.csv` | Per root, daemon and reload: completion p50 and maximum, changed-observer gap p50, sessions, parse errors and peak RSS sample |
| `extract-tails.py` | The script that wrote `matrix-tails.csv` and `irr-cells.csv` |

## Naming

The leg directories use the names `summarize.py` reads. In a matrix leg, the
arm is the daemon. Each IRR root holds all three daemons. It is named with
the arm `rustbgpd` because `summarize.py` extracts only that cell's rows;
`irr-cells.csv` carries all three.

## How the files were produced

- **`summary.csv` and `establishment-span.csv`** came from `summarize.py`
  run on the campaign's legs, with each rustbgpd daemon log present.
  - **On this bundle,** `just bench-headline-summary <bundle> --out <dir>`
    reproduces every row of `summary.csv` byte for byte, except the 192
    daemon-log rows (`daemon_sighup_to_loaded`, `daemon_sighup_to_complete`,
    `daemon_validate`, `daemon_rib_transition`).
  - **Those rows need the daemon logs,** which are not in the bundle.
- **`matrix-tails.csv` and `irr-cells.csv`** came from
  `python3 extract-tails.py <legs> <out>`. It reads the campaign's leg
  layout (`matrix-s2-r1-bird/bird/`, `irr-ov0-r1/`), not this bundle's, and
  takes the same values that the bundle's files hold.

The bundle copies files without editing them, apart from `progress.txt`,
where the campaign directory is replaced by `<campaign>` and the queue PID
is removed, and `identity.txt`, where a free-text upstream note is dropped
(the receipt states it). Full daemon logs, scenario configurations and
metrics scrapes remain outside the repository.

Verify the bundle with `sha256sum -c SHA256SUMS`.
