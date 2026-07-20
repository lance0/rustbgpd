# 1,000-peer route-server receipt artifacts

These are the bounded retained artifacts for
[`route-server-1000-2026-07.md`](../../route-server-1000-2026-07.md). The
campaign ran from clean commit
`cb2c924f117fe264991f12b24ea44c2b15b132e2` (tree
`6e02804e7a233aebcdf50b01e0e3c3d1911156c6`) with the real release daemon,
CLI, and `reloadstall` BGP client harness.

The raw private directory passed its original `SHA256SUMS` before this subset
was copied. Paths were then sanitized to `$REPO` and `$RUN`; logs and full
Prometheus snapshots were deterministically gzip-compressed. The manifest in
this directory covers the retained, sanitized bytes.

## Contents

- `provenance.env`, `toolchain.txt`, `host.txt`, and `preflight.tsv` pin the
  source, build environment, hardware shape, and quiet-host admission checks.
- `commands.txt`, `binaries.sha256`, the three generated policies, and
  `config.toml` retain the exact run inputs. Regenerate rather than executing
  the sanitized `$RUN` paths verbatim.
- `build-*.log.gz`, `daemon-check.log`, and `daemon.log.gz` retain the real
  encoder/daemon build and execution evidence.
- `reloadstall.log`, `readyz.tsv`, `rss.tsv`, and the three compressed metrics
  files retain the measurement streams. `advertised-explain.json` proves a
  representative route was exported through policy and assigned to a group.
- `validation.env` records the derived acceptance values. The four
  `reloadstall_csv` rows remain authoritative for per-cycle results.

As the measured harness completed, one sampler observed its timeout-wrapper
PID disappear between `/proc` probes and printed a harmless diagnostic. The
samplers then completed cleanly and every post-run acceptance gate passed.
This does not alter the measured window or its result; it is disclosed so a
future harness cleanup does not mistake the diagnostic for measurement
failure.
