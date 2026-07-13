# Grouped exact-precommit artifacts — 2026-07

These are the durable machine-readable artifacts for Campaign 3 of the
[exact-export fanout receipt](../../exact-export-fanout-2026-07.md). They
compare baseline `b2ec55f21364978f26662b1ec35fd47ddcfce9a6` with production
revision `ea579bea4ad6602dc719a1664441f04330c5ef64`. The reviewed measurement
tooling is `e6c6ea75819869cb2cd188711891459f8991d51d`, pinned by
`deb52f7b92f7f633714573a86f0eaeb22bb94bad`.

## Contents

- `rrharness-receipt.tar.gz` is the complete sealed 16-cell flood/churn
  receipt. It includes the exact source snapshot, production patch and hash,
  binary/input hashes, raw rows, folded profiles, classifier output,
  preflights, execution order, manifest, checksum envelope, and `COMPLETED`
  marker.
- `rrharness-comparison.csv` duplicates the compact eight-row comparison from
  that archive for easy review.
- `criterion/` is the complete sanitized two-attempt Criterion receipt. Its
  five-file whitelist retains the 16 result rows, 32 exact Criterion input
  hashes, gate decisions, checksum envelope, and `COMPLETED` marker without
  retaining host-private raw paths.
- `SHA256SUMS` covers every retained file other than itself.

The two earlier rrharness attempts are intentionally absent. The first passed
the throughput matrix but failed before sealing when a source-vocabulary
privacy rule was too broad. The second sealed but an independent review found
an ignored Python bytecode file containing a private path. The final driver
disables bytecode, requires an exact NUL-safe source inventory, scans ignored
and binary files after final reconciliation, and fails closed on scanner
errors. Only the clean third run is retained here.

## Verification

```bash
sha256sum -c SHA256SUMS

tmp=$(mktemp -d)
tar -xzf rrharness-receipt.tar.gz -C "$tmp"
(cd "$tmp" && sha256sum -c SHA256SUMS)

(cd criterion && sha256sum -c SHA256SUMS)
```

Both nested `COMPLETED` files bind the SHA-256 of their corresponding
`SHA256SUMS` envelope and assert that the required matrix and acceptance gates
passed.
