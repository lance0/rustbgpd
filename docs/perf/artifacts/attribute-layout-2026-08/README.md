# Interned attribute-container layout artifacts

Status: **migration rejected; evidence-only harness retained**.

These are the durable artifacts for the
[attribute-container layout receipt](../../attribute-layout-2026-08.md). The
structural campaign compares baseline
`f822fd2ba407117dcf8a6d7faa32018b77dae250` with harness revision
`73380e1cdc0519a4af5b4c3559bb4922b14582f7`; neither revision changes the
production attribute representation.

## Result

At the calibrated ratio of one unique interned set per seven prefixes, the
900,000-prefix full-RIB model makes `Arc<[PathAttribute]>` 17.7 MiB larger and
the route-reflector fanout model makes it 31.4 MiB larger. The slice pointer is
eight bytes wider for every Route copy, while eliminating the 24-byte Vec
header saves bytes only once per unique set. The production migration is
therefore rejected before a prototype or throughput campaign.

The two representative rows exist only in the harness revision, so their
baseline live-byte fields are empty and their review value is `missing-row`.
They are structural model rows, not a live-byte A/B. All older shared rows are
exactly unchanged.

## Contents

- `structural-results.csv` is the complete 100k/500k/900k full campaign,
  including pointer growth, Vec-header savings, exact set/Route counts, and
  break-even counts.
- `2p-100k.csv` is the bounded bgperf2 result: 200,000/200,000 routes, zero
  tester errors, and zero tester timeouts.
- `2p-100k.memory.tsv` is the DHAT owner summary.
- `2p-100k.dhat-derivative.tsv` is the sanitized bounded derivative from which
  the owner summary can be regenerated. Raw DHAT JSON is intentionally absent.
- `provenance.txt` pins source, baseline, adapter, image digest, host/toolchain,
  load, and the exact campaign commands without retaining host paths or PIDs.
- `SHA256SUMS` covers every retained file other than itself.

The 2-peer x 100k fixture is deliberately low-diversity. Its zero-byte outer
attribute-backing row is ownership attribution, not evidence that the proposed
layout would save memory on a real table.

## Verification

```bash
sha256sum -c SHA256SUMS
python3 ../../../../bench/scale/rebaseline/classify_dhat.py \
  --from-derivative 2p-100k.dhat-derivative.tsv \
  --check 2p-100k.memory.tsv
python3 ../../../../bench/scale/rebaseline/sanitize_bgperf_csv.py \
  --from-sanitized 2p-100k.csv --check 2p-100k.csv
```
