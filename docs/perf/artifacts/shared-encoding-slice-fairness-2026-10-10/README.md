# Shared encoding slice fairness artifacts — 2026-10-10

Both measured campaigns are VALID and complete. Initial one-slice and final
two-slice results remain separate; their baseline distributions differ. The
INVALID aborted build-confounded attempt supplies no timing rows to either.
Historical receipts are unchanged.

[Read the dated receipt](../../shared-encoding-slice-fairness-2026-10-10.md)
for the measured clocks, workload and scoped release decision.

| File | Retained evidence |
|---|---|
| `initial-records.json`, `final-records.json` | All 64 reloads: selected original daemon boundary/phase/trace events, all 192 raw RPC starts/ends/durations/reply shapes and selected audit events, and exact engine CSV fields |
| `initial-correlation.csv`, `final-correlation.csv` | Derived per-reload daemon/phase/RPC/wire clocks; no reload excluded |
| `initial-summary.json`, `final-summary.json` | Process/arm median, mean and ranges for all, first two and remaining reloads |
| `provenance.json` | Exact source/tree/build/input-refresh/toolchain/binary/instrument/driver identities, native verdicts, quiet samples, exits, finished window and original-file hashes |
| `feature-audit.json`, `final-feature-audit.json` | Binary-bound dependency signatures and configuration/edge records for 227 artifact units per arm (226 library fingerprints plus the daemon binary); resolved graph and historical missing API build-script scope; six original feature differences |
| `normal-build-graph.txt.gz` | One copy of the identical normalized 17,893-line normal/build graph, excluding dev edges; only source worktree roots are replaced with `<SOURCE>` |
| `invalid-build-confound.json` | Original aborted comparison: actual exit 143 versus retained trap 0, closing baseline absent, no finish and all timing observations excluded |
| `recompute.py`, `test_recompute.py` | Standard-library reproduction and plausible broken-input controls |
| `SHA256SUMS` | Checksums of all other artifact files and the accompanying receipt |

Run from this directory:

```bash
python3 recompute.py
python3 test_recompute.py
sha256sum -c SHA256SUMS
```

The first command requires matching actual library configurations and
runtime dependency identities, verifies each stored measured campaign's
extracted controls, and reproduces its summary and CSV. Both measured
source/binary sets are independently identified; cross-window baselines are
not substituted. The test companion rejects missing
rows, incomplete/failing probes or audits, wrong boundaries/outcomes,
non-additive phase data, package/source/binary/feature mismatches, missing
finish, failed native/outer stages, wire quantile inversion and treating the
aborted raw zero as success.

The extracted selected events are authoritative for these recomputed clocks.
Full native audit/reply/integrity/load/settlement checks remain their original
verdicts and hashes; the script does not independently reconstruct omitted
compressed full replies, metrics or CPU sample streams. No checksum alone
converts an invalid campaign into a valid one. Original full-file hashes
identify retained bytes without publishing private machine paths.

Medians use `statistics.median`, including the midpoint for even counts.
Native summary `p50` uses nearest rank; the two vocabularies are distinct.
Wire per-reload p50/p95/max are the harness's observer quantiles. Medians of
those rows do not combine every observer into a new distribution. All units
are milliseconds except explicit wire completion seconds. Phase medians are
not additive; per-row means are. Two process launches per arm provide the
replication view; pooled 16 reloads are correlated.
