# Final prestaged-inventory attribution artifacts — 2026-10-11

These are public projections of one completed, VALID parent/merged-child
four-process ABBA. All 32 reloads remain in the primary population: two
processes and 16 correlated reloads per arm. Historical receipts are unchanged.

[Read the receipt](../../policy-transition-final-inventory-attribution-2026-10-11.md).

| File | Evidence |
| --- | --- |
| `records.json` | 128 selected original daemon boundary objects, full phase/commit dictionaries, all 96 raw RPC records, 64 stats audits, 32 exact embedded engine CSV records and selected native summary controls |
| `rpc-responses.json` | All 96 original compressed RPC stdout bodies as base64, with original compressed digests; reply bodies are independently parsed and hashed |
| `feature-audit.json` | Both actual binary-bound closures: 227 normal artifact units (226 library fingerprints plus daemon binary), 342 including-build units, configuration/features/cfg/build environment/dependency identities and multiplicity |
| `normal-build-graph.txt.gz` | One identical 17,891-line normalized resolution graph, a separate resolution proxy |
| `provenance.json` | Native exits, exact source/tree/toolchain/input-refresh/binary/instrument identities, quiet samples, original native hashes and public normalization provenance |
| `driver.normalized.sh`, `build-arm.normalized.sh`, `timing-launcher.normalized.sh` | Post-run projections of the actual executed local scripts, with private roots replaced by stable placeholders; **not the executed bytes or a runnable launch recipe** |
| `source-diff.patch` | Exact parent-to-merged-child source diff |
| `summary.json`, `reloads.tsv`, `timing.md` | Derived process/arm distributions, first reload versus later rows, wire clocks and additive means; no censoring |
| `recompute.py`, `feature_compare.py`, `test_recompute.py` | Standard-library reproduction, native stage/reply grammar and duplicate-preserving actual-unit comparison, with broken-input controls |
| `quiet-preparation.md`, `quiet-source-preparation.json`, `quiet-irr-prebuilt-adapter.patch` | Separate, source-only future S2/IRR preparation; no adapter/config smoke/build/campaign executed |
| `SHA256SUMS` | Public file and receipt checksums, distinct from native original hashes |

Run from this directory:

```bash
python3 recompute.py
python3 test_recompute.py
sha256sum -c SHA256SUMS
```

The complete positive is established before any negative control counts.
Broken controls cover full phase binding, non-additive components, each
selected boundary clock, fallback, missing reload/pair, failed/slow paired
policy-stats, corrupted or incomplete reply, malformed audit, incorrect flat
criterion, native failure/missing finish, quiet failure, wire inversion/parser
error, missing normal/build closure, changed feature/dependency/environment,
and both equal arms accidentally enabling `bench-internals`.

The checker links the selected native summaries to their event/RPC/audit/wire
projections and regenerates summary/table/TSV bytes. Native full CPU streams,
metrics, omitted integrity/settlement logs and their acceptance remain
original verdicts and original hashes; the checker does not recreate those
omitted full checks. The retained compressed responses are unmodified; only
selected audit listener socket directories and private source/cache/runner/
artifact roots are replaced in public projections. No normalization occurs
inside the measurement window. Original files remain untouched, and public
script hashes must not be confused with executed-script hashes.

Medians use `statistics.median`, including the even-count midpoint. Native
summary p50 uses nearest rank. Wire p50/p95/max are per-reload observer
quantiles, not pooled observers. Phase fields use microseconds divided by
1,000; additive accounting uses per-row means rather than sums of medians.
Daemon SIGHUP/complete, cohort, actor and engine wire clocks have the distinct
boundaries stated in the receipt. No CPU or exact scheduling attribution is
derived from wall time alone.
