# Initial-table reconciliation extracts

Compact evidence for the [October 2026 qualification](../../initial-table-reconciliation-2026-10.md).
All six processes, 18 rounds, 900 returning-peer records and 11,700 survivor
records are retained. No measured round was excluded.

- `rounds.csv`: original six-decimal per-round p50/p95/max endpoint summaries.
- `catchup.csv`: OPEN, EoR, latched completion and current-full timestamps,
  with exact current bitmap counts for all 50 returning peers per round.
- `survivors.csv`: trigger, published first-any, first-affected and full
  reannouncement timestamps for all 650 survivors per round.
- `legs.json`: compact native exits/HTTP results, canonical inputs, binary
  identities, freeze equality, quiet samples, stage chronology, hashed process
  identities, initial coverage, session/parse results and readiness records.
  Stage order is leg start, quiet start/end, daemon launch, harness launch/exit,
  cleanup end, cooldown start/end, leg finish. Hashes retain distinct process
  identity without publishing raw process/boot metadata.
- `provenance.json`: source/build identities, common helper changes, raw archive
  identity and cleanup observations. Raw audit requires the unpublished archive.
- `common-qualification.patch`: identical non-runtime harness/runner changes
  used by both arms, relative to the measured control commit.
- `recompute.py`: validates coverage, quantiles, clock ordering and compact
  native receipts, then recomputes all endpoints, process pairs and frozen
  acceptance bars. Withdrawal quantiles come from native summary rows; their
  full bitmap validation remains in the raw harness logs.
- `comparison.json`: exact original campaign comparison, including all 150
  returning-peer process-pair medians and the first-arrival identity counts.
- `test_recompute.py`: valid-receipt, coverage, current-table/EoR ordering,
  quantile, nonfinite-input, native-check and inclusive acceptance-boundary tests.
- `SHA256SUMS`: hashes of every other published artifact in this directory.

From the repository root:

```bash
(cd docs/perf/artifacts/initial-table-reconciliation-2026-10 && sha256sum -c SHA256SUMS)
python3 docs/perf/artifacts/initial-table-reconciliation-2026-10/recompute.py > /tmp/initial-table-comparison.json
diff -u docs/perf/artifacts/initial-table-reconciliation-2026-10/comparison.json /tmp/initial-table-comparison.json
python3 docs/perf/artifacts/initial-table-reconciliation-2026-10/test_recompute.py
```

Per-peer CSV timestamps are harness-process elapsed microseconds. Leg stage
witnesses use same-boot monotonic nanoseconds; quiet samples retain wall-clock
epoch seconds. Returning completion uses `complete_us - open_us`; survivor
endpoints use their recorded trigger. The native quantile index rounds
`(n - 1) × q` to the nearest integer,
with halves upward. Reported arm values are medians of nine correlated round
quantiles; each arm has three independent processes. The unusually fast control
04 round 2 is retained. Pair order is AB/BA/AB.

The first-any acceptance endpoint is preserved and separately checked against
first-affected coverage. No GR-retained or aborted earlier-cohort sample enters
these files. The original CSVs and comparison are byte-identical to the audited
campaign outputs. Compact assertions and hashes are audit pointers, not a
substitute for the original private logs.
