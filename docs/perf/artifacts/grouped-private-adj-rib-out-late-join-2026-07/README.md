# Grouped private Adj-RIB-Out late-join artifacts

These files retain the complete same-host A/B/B/A evidence for
[`../../grouped-private-adj-rib-out-late-join-2026-07.md`](../../grouped-private-adj-rib-out-late-join-2026-07.md).

## Contents

- `raw/` contains the eight exact `rrharness` stdout records.
- `summary.tsv` adds within-process memory deltas to those raw values.
- `provenance.txt` pins product and harness revisions plus safe host/tool
  characteristics.
- `commands.txt` records the build, preflight, and run sequence without
  retaining local paths.
- `SHA256SUMS` covers every other retained file in this directory.

The control and candidate harness directories were byte-identical. Each row
asserts a real encoder, exact Loc-RIB convergence, a single homogeneous update
group, exact per-member staged counts, and exact aggregate drained counts
before the post-join snapshot.

`VmSize` is the process virtual address-space size. `VmRSS` is resident memory,
and `VmHWM` is the process resident high-water mark. The receipt reports the
virtual allocation result and explicitly declines an RSS or latency claim.

Verify from this directory:

```bash
sha256sum -c SHA256SUMS
```

