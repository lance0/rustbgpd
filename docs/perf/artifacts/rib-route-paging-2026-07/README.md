# RIB route-paging retained matrix

This directory retains the four-repetition LAN-391 matrix measured on
2026-07-13. The review-sized files are unpacked:

- `route-paging.csv`: all 64 baseline/candidate traversal rows;
- `cell-preflight.tsv`: the immediate host fence for every fresh process;
- `metadata.txt`: exact commits, source hashes, binaries, toolchain, and host
  policy.

`route-paging-receipt.tar.gz` contains the exact successful driver output,
including every one-row raw CSV, build and execution logs, exact benchmark and
production sources, compile inputs, nested manifests, and the original
top-level `SHA256SUMS`. The archive is deterministic: sorted names, numeric
owner/group 0, and mtime pinned to the recorded matrix completion time.

Verify the checked-in bundle, then the extracted original receipt:

```bash
sha256sum -c SHA256SUMS
mkdir /tmp/rustbgpd-route-paging-receipt
tar -xzf route-paging-receipt.tar.gz \
  -C /tmp/rustbgpd-route-paging-receipt
(cd /tmp/rustbgpd-route-paging-receipt && sha256sum -c SHA256SUMS)
```

The result interpretation and continuation decision are in
[`../../rib-route-paging-2026-07.md`](../../rib-route-paging-2026-07.md).
