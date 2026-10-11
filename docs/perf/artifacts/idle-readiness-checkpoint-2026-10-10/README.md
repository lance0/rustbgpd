# Idle readiness checkpoint artifacts — 2026-10-10

The [dated receipt](../../idle-readiness-checkpoint-2026-10-10.md) reports one
VALID four-process A/B/B/A: a modest replay inter-handler proxy improvement
and mixed OPEN-to-table rejoin clocks. Two process launches per arm provide
the replication view; the six rounds and twelve pairs per arm are correlated.
Every requested pair and every native row is retained without a duration cutoff.

| File | Evidence |
|---|---|
| `records.json` | Four complete native harness logs, 48 selected observer handler events, peer-0 rejoin/GR phase events with original line numbers, quiet samples, exits and end integrity metadata |
| `observer-replay-pairs.json` | All 24 derived timestamp pairs at disconnected and settled checkpoints |
| `rejoin-phase-clocks.json` | All 12 native rejoin clocks paired with established-to-EoR-enqueued daemon log spans and their unallocated difference |
| `summary.json` | Per-process and descriptive pooled means, medians and ranges; first versus later rounds and each checkpoint phase |
| `inputs/` | Actual generated configuration and three policies; all cells differ only in scenario-directory strings, normalized to `<SCENARIO>` |
| `provenance.json` | Acceptance declared before the first cell; source/tree/binary/toolchain/build/input-refresh identities; native window, lock order, full exits, integrity and original-file hashes |
| `feature-audit.json` | Both binary-bound 227-unit normal and 343-unit including-build fingerprint closures, signatures, complete capture inventories and normalized build-script output metadata |
| `normal-build-graph.txt.gz` | One copy of the identical normalized normal/build resolution graph; actual-unit audit remains primary |
| `as-run.json`, `compare_features.py` | Retained build, capture, comparator, ABBA, cell and extraction scripts, with private absolute paths normalized; comparator module preserves unit multiplicity |
| `recompute.py`, `test_recompute.py` | Standard-library reproduction and plausible broken-input controls using this bundle's own data |
| `SHA256SUMS` | Public-normalized checksums of all other artifact files and the accompanying receipt |

Run from this directory:

```bash
python3 recompute.py
python3 test_recompute.py
sha256sum -c SHA256SUMS
```

Recomputation requires matching actual normal and including-build unit
configuration/features/dependency identities and multiplicity, independently
rejects daemon/RIB `bench-internals`, follows captured dependency signatures,
and checks source/binary/build/native/quiet/input identities. It extracts the
same 12 rows and 24 complete pairs directly from retained native logs and
selected authoritative daemon events, then compares them with every stored
clock and distribution. The companion controls reject incomplete/failing
native input, missing replay pairs/checkpoints, incorrect family/clocks,
missing or changed actual units, both arms instrumented identically, and
failed integrity/window completion. A positive long-gap control confirms
that a gap above 500 ms remains in the result.

The selected events and complete native harness logs are authoritative for
the recomputed clocks. The full original daemon scan found no ERROR or
readiness-failure events; those scan results are retained alongside the
original daemon-log hashes. Full omitted daemon/metrics streams and native
GR/survivor checks are not independently reconstructed by the checker.
The sampled readiness count does not prove continuous readiness or that
a probe overlapped every replay. RSS CSV fields remain native single-process
values, not a whole-cgroup measurement or resource improvement claim.

The as-run scripts retain their original preparation comments as historical
source. They are evidence, not authorization to run another campaign.
Public data was normalized only after all measured commands were reaped:
private path prefixes become stable `<SOURCE>`, `<CANDIDATE_SOURCE>`,
`<CACHE>`, `<ARTIFACTS>`, `<INSTRUMENTS>` and lock/home placeholders. The
per-cell temporary directory becomes `<SCENARIO>`. Timings, numeric values,
configuration/feature inputs, dependency identities and exits are unchanged.
Local original hashes and sizes are listed separately from public checksums.
As-run source and byte-level outputs retain source identity through the
frozen revisions. Normalized public bytes are not the original files or
immutable binary fingerprints.

All time distributions use `statistics.median`; for an even count this is
the midpoint. The native K=1 p50/max values both describe its one reconnecting
peer. No distributions are added together and no statistical significance
or CPU mechanism is inferred from wall times.
