# LAN-393 machine-artifact manifest

This directory is receipt-only. Measurements are intentionally absent until
the exact drivers in `docs/perf/event-history-producer-2026-07.md` complete on a
quiet host.

## Criterion phases

Each `baseline` or `candidate` phase produces:

- `microbench-<phase>-environment.txt`: exact source/base identities, canonical
  repository slug, detached-worktree/separate-target/shared-state proof,
  Cargo-config and build-environment hashes, executable basename/hash, and
  normalized lock/fence policy;
- `microbench-<phase>-{host-fingerprint,toolchain}.txt` and
  `microbench-<phase>-harness-SHA256SUMS`;
- `microbench-<phase>-host-preflight.tsv`, whose process column contains only
  executable names;
- `microbench-<phase>-bench-build.json`, sanitized to the selected target,
  enabled features, executable basename, and executable hash;
- `microbench-<phase>-baseline-state-SHA256SUMS`, binding the exact named
  Criterion baseline state consumed by candidate;
- `criterion-<phase>/**/{benchmark,estimates,sample,tukey}.json` for the exact
  nine-case matrix; candidate also retains `change/` JSON;
- `microbench-<phase>-results.csv` and `microbench-<phase>-verdict.json`;
- `rustbgpd-<phase>-source.tar.gz`; and
- `microbench-<phase>-completion.txt` plus
  `microbench-<phase>-SHA256SUMS`.

A phase is complete only when `matrix_complete=1` is present and its manifest
verifies from this directory:

```bash
sha256sum --check microbench-baseline-SHA256SUMS
sha256sum --check microbench-candidate-SHA256SUMS
```

## Full-daemon profiles

Each of `baseline-enabled`, `baseline-disabled`, `candidate-enabled`, and
`candidate-disabled` has a `full-daemon-<profile>-` prefix and retains:

- exact source and pinned bgperf2 archive hashes;
- safe host fingerprint/toolchain, load/governor/process preflight, OCI image
  inspection, binary hashes, and builder/runtime package provenance;
- exact generated scenario/config and explicit enabled/disabled EHM verdict;
- raw bgperf log/time series, normalized finite-value result CSV, two exact
  run-scoped BIRD logs, and validator output;
- post-drain metrics, resource snapshot, daemon log, and cursor/drop/degraded
  checks;
- sanitized perf report/script, machine attribution JSON/validation, and the
  private raw perf capture's SHA-256;
- after each disabled profile, an overall baseline-proceed or
  candidate-acceptance verdict combining Criterion, attribution, and disabled
  CPU/RSS; and
- completion sentinel plus aggregate phase `SHA256SUMS`.

The baseline/candidate source archives and pinned bgperf2 archive are created
once. Later profiles regenerate them only into temporary files and must prove
byte identity, so no file already bound by an earlier manifest is replaced.

Raw `perf.data` is intentionally not publication material. It remains under
`target/lan393-private-perf/`; the public receipt binds its digest and retains
the sanitized, classifiable derivatives.

Verify a profile from this directory, for example:

```bash
sha256sum --check full-daemon-baseline-enabled-SHA256SUMS
```

## Privacy

Do not add hand-written result JSON or unsanitized raw data. Public artifacts
must not contain remote URLs/credentials, usernames, host paths, lock paths,
PIDs, argv, environment dumps, raw Cargo JSON, raw perf script, or `perf.data`.
The drivers run a final privacy scan before writing a checksummed completion.
