# IXP matrix v0.84.0 compact artifacts (2026-11-22)

These files are the evidence for the
[cross-daemon IXP matrix at v0.84.0](../../../cross-daemon-v0840-2026-11.md): the v0.84.0 release
commit (`5f5ca6a31`), BIRD 3.3.3 and OpenBGPD 9.3 on one host, two runs per daemon.

| Path | Contents |
|---|---|
| `matrix/matrix-{rustbgpd,bird,openbgpd}-r{1,2}-{s2,s3}/` | Matrix cells (run 1 = A, run 2 = B): `reloadstall.log`, `status`, 5-second process-tree `rss.csv` and runner `provenance.json`. The rustbgpd cells also hold `vmhwm`, the swap-fenced `cgroup-memory` readout and the gzipped daemon log; the competitor cells hold the container's `container-memory` readout |
| `progress.txt` | The campaign log: leg order, exit codes, status, duration and load average at every leg boundary |
| `identity.txt` | Measured commit and tree, binary SHA-256s, toolchain, competitor images and kernel |
| `interference.log.gz` | The campaign's 10-second host sampler: load, compiler and docker-build processes, rustbgpd and harness process counts, and containers beyond the constant baseline and the matrix's own |
| `summary.csv`, `report.md`, `establishment-span.csv` | [`summarize.py`](../../../../../bench/scale/headline/summarize.py) output on the raw campaign directory |
| `matrix-tails.csv` | p95, maximum and RSS extraction by `extract-tails.py`, copied unchanged from the v0.74.0 bundle |
| `MANIFEST`, `verify.sh` | SHA-256 of every other file, and its re-checker |

## How the files were produced

- **On this bundle,** `summarize.py <bundle> --out <dir>` reproduces every row of `summary.csv`
  (in a different row order) except the 32 daemon-log rows, which need the daemon logs
  uncompressed. `establishment-span.csv` needs them too.
- **`matrix-tails.csv`** came from `python3 extract-tails.py <legs> <out>` on the campaign's leg
  layout (`matrix-s2-r1-openbgpd/openbgpd/`).
- **Edits.** Files are copied unedited, except that `progress.txt` drops the campaign PID.
- **Not included:** scenario configurations, quiet-gate samples and competitor daemon logs.

Verify the bundle with `sh verify.sh`.
