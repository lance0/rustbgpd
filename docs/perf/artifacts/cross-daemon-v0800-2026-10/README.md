# Cross-daemon v0.80.0 compact artifacts (2026-10-25)

These files are the evidence for the
[cross-daemon refresh at v0.80.0](../../cross-daemon-v0800-2026-10.md): the v0.80.0 tree
(`871d9d269`), OpenBGPD 9.3 and, in the IRR roots, BIRD 3.3.3, on one host in one night, plus
the same queue's Criterion A/B, rrharness rungs and bgperf2 spot-check.

| Path | Contents |
|---|---|
| `matrix/matrix-{rustbgpd,openbgpd}-r{1,2,3}-{s2,s3}/` | Matrix cells: `reloadstall.log`, `status`, 5-second process-tree `rss.csv` and runner `provenance.json`. The rustbgpd cells also hold `vmhwm`, the swap-fenced `cgroup-memory` readout and the gzipped daemon log; the OpenBGPD cells hold the container's `container-memory` readout |
| `irr/irr-ov{0,10,50}-rustbgpd-r{1,2,3}/` | IRR roots: `COMPLETED`, `rows.csv`, `provenance.json` and dataset digest. Each daemon's `reloadstall.log`, `rss.csv`, `status`, cgroup or container memory readout and `memory-window` sit under `rustbgpd-sighup/`, `bird/` and `openbgpd/`, with rustbgpd's `vmhwm`, dataset-refresh summary and gzipped daemon log |
| `rr/` | `rrharness flood` output for runs A and B at 256, 512 and 1000 clients, and the run A 1000-client folded CPU profile (gzipped) |
| `bgperf2/` | The three single-run bgperf2 logs and each run's image and harness versions |
| `criterion/` | The Criterion A/B summarizer output (`analysis.txt`) and its rollup line (`summary.txt`), unedited |
| `progress.txt` | The queue log: leg order, exit codes and load average at every leg boundary. The campaign directory is written as `<campaign>` |
| `identity.txt` | Measured commit and tree, binary SHA-256s, toolchain, competitor and bgperf2 images, and kernel |
| `interference.log.gz` | The queue's 10-second host sampler: load, build processes, container count and rustbgpd process count |
| `summary.csv`, `report.md`, `establishment-span.csv` | [`summarize.py`](../../../../bench/scale/headline/summarize.py) output on the raw queue directory |
| `matrix-tails.csv`, `irr-cells.csv` | p95, maximum and RSS extraction by `extract-tails.py`, copied unchanged from the v0.74.0 bundle |

## How the files were produced

- **On this bundle,** `summarize.py <bundle> --out <dir>` reproduces every row of
  `summary.csv` (in a different row order), except the 192 daemon-log rows, which need the
  daemon logs uncompressed. `establishment-span.csv` needs them too.
- **`matrix-tails.csv` and `irr-cells.csv`** came from `python3 extract-tails.py <legs> <out>`
  on the campaign's leg layout (`matrix-s2-r1-openbgpd/openbgpd/`, `irr-ov0-r1/`).
- **Edits.** Files are copied unedited, except: `progress.txt` replaces the campaign
  directory with `<campaign>` and drops queue PIDs; `identity.txt` drops a free-text upstream
  note and a local checkout path; the `rr/*.stdout` files drop two shell `getcwd` warnings;
  the `bgperf2/*.log` contention lines keep their CPU totals but omit host process names; and
  `criterion/analysis.txt` drops private tracker references from three header lines. Its
  rollup line and every result row are unedited, and `criterion/summary.txt` is unedited.
- **Not included:** scenario configurations, metrics scrapes, competitor daemon logs, the
  other five folded profiles and the raw Criterion sample data.

Verify the bundle with `sha256sum -c SHA256SUMS`.
