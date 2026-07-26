# Fanout source-stack benchmark artifacts

This directory retains the fresh evidence for the two adjacent LAN-623
optimizations:

- [`../../fanout-metrics-handle-2026-07.md`](../../fanout-metrics-handle-2026-07.md)
- [`../../otc-pristine-reconcile-2026-07.md`](../../otc-pristine-reconcile-2026-07.md)

The campaign ran after the source stack was rebased onto the settled
post-#1167 main tip. The four source commits are preserved separately so each
optimization still has an immediate control.

## Browsable evidence

- `metrics-same-sha-summary.md` and `metrics-before-after-summary.md`: generated
  six-pair summaries for the metrics-handle change.
- `otc-same-sha-summary.md` and `otc-before-after-summary.md`: generated
  six-pair summaries for the pristine-OTC change.
- `attempt-medians.tsv`: all 120 exact paired medians and confidence bounds.
- `aggregate.tsv`: exact across-attempt statistics for all four campaigns and
  five peer counts.
- `metrics-red-proof.txt` and `otc-red-proof.txt`: fresh destructive
  load-bearing test receipts.
- `PROVENANCE.txt`: revisions, fleet, boundary, toolchain, binary hashes, raw
  key hashes, sanitation, and archive provenance.
- `commands.txt`: exact benchmark and verification commands.

## Compressed evidence

`criterion-evidence.tar.gz` is a deterministic sanitized archive containing:

- the complete campaign log;
- four generated metadata files and four generated summaries;
- 48 complete per-side benchmark logs;
- 240 immutable Criterion `estimates.json` attempt baselines; and
- 240 matching Criterion `sample.json` attempt baselines.

Criterion's 20 mutable `new/` copies are not retained: each is only the last
run duplicated outside its named immutable baseline. The archive therefore
preserves exactly the 240 estimates and 240 samples used by the four
six-attempt, five-shape comparisons.

The archive has 538 files: 537 evidence files plus its internal `SHA256SUMS`.
Directory entries are not counted. `SANITIZED-EVIDENCE-SHA256SUMS` is the
same 537-entry manifest kept outside the archive for review.
`RAW-EVIDENCE-SHA256SUMS` binds every sanitized relative file name to the
corresponding pre-sanitation source hash. `SHA256SUMS` covers every checked-in
file in this directory except itself.

The package replaces the local hostname, checkout, host-lock path, campaign
root, and user identity with explicit angle-bracket tokens. A post-package
scan rejects those values, other local absolute paths, and all obsolete
pre-rebase receipt revisions.

## Verify

```bash
sha256sum -c SHA256SUMS
mkdir receipt-extract
tar -xzf criterion-evidence.tar.gz -C receipt-extract
(
  cd receipt-extract/criterion-evidence
  sha256sum -c SHA256SUMS
)
```

The archive was generated twice with sorted names, epoch mtimes, numeric
owner/group zero, and `gzip -n -9`; both byte streams had the same SHA-256.
