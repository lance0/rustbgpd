# Flap-storm (S3) v0.80.1 addendum artifacts (2026-10-25)

These files are the evidence for the
[v0.80.1 flap-storm addendum](../../cross-daemon-v0801-s3-2026-10.md): three rustbgpd S3 legs
at 700 members × 400,400 prefixes with 50 flapping, on v0.80.1's daemon source, on the host
and inputs of the [v0.80.0 bundle](../cross-daemon-v0800-2026-10/README.md).

| Path | Contents |
|---|---|
| `matrix/matrix-rustbgpd-r{1,2,3}-s3/` | One leg per run: `reloadstall.log`, `status`, 5-second process-tree `rss.csv`, `vmhwm`, the swap-fenced `cgroup-memory` readout, runner `provenance.json` and the gzipped daemon log |
| `identity.txt` | Measured HEAD and its uncommitted change, the release commit compared, binary SHA-256s, toolchain and kernel |
| `summary.csv`, `report.md`, `establishment-span.csv` | [`summarize.py`](../../../../bench/scale/headline/summarize.py) output on the raw run directories |

## How the files were produced

- **On this bundle,** `summarize.py <bundle> --out <dir>` reproduces every row of
  `summary.csv` (in a different row order). `establishment-span.csv` needs the daemon logs
  uncompressed. The raw directories were named `r{1,2,3}/rustbgpd/`; the files are placed in
  the v0.80.0 bundle's `matrix/` layout. The start-up rows (`matrix-s1` in `report.md`) come
  from these S3 legs and are not cited by the addendum.
- **Edits.** Every file in `matrix/`, and the summarizer output, is copied unedited. The daemon
  logs are compressed with no stored file name or timestamp. `identity.txt` is assembled from
  the runner's records and drops the local checkout path from the binary digest line. The run
  logs and host-quiet samples are not included, because they carry local scratch paths; their
  load and swap readings are quoted in the addendum.
- **Identifier scan.** Every file, including the decompressed daemon logs, was searched for
  host names, home directories and user names before publication; none occur. The only paths
  are the harness's `/tmp/ixp-rustbgpd/` scenario directory, as in the v0.80.0 bundle.
- **Not included:** scenario configurations, metrics scrapes and competitor runs. OpenBGPD's S3
  legs are in the v0.80.0 bundle.

Verify the bundle with `sha256sum -c SHA256SUMS`.
