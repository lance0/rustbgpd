# Boxed MP real-table memory artifacts (October 2026)

This is the compact public evidence for the [dated receipt](../../boxed-mp-real-table-2026-10.md).
All pair deltas are parent minus boxed. The release rows came from five
serial, counterbalanced pairs with exact route and attribute-inventory guards;
the DHAT rows are a separate two-profile source-attribution check.

| File | Contents |
| --- | --- |
| [`release-runs.csv`](release-runs.csv) | Ten release cells with exact cgroup, process-tree, and diagnostic-scan readings |
| [`release-pairs.csv`](release-pairs.csv) | Five signed parent-minus-boxed differences |
| [`dhat-classes.tsv`](dhat-classes.tsv) | Original, frozen classifier labels and live bytes at each profile's own `t_gmax` |
| [`dhat-outer-stacks.tsv`](dhat-outer-stacks.tsv) | Four dominant outer-vector source-site stack summaries; the original classifier label is retained |
| [`provenance.json`](provenance.json) | Input hashes, source commits, image identities, build, runner, diagnostic and correctness inventory |
| [`SHA256SUMS`](SHA256SUMS) | Checksums of the five data files above |

From this directory, `sha256sum -c SHA256SUMS` checks the published data
files. The archived MRT can be independently fetched from the Route Views URL
in `provenance.json` and checked against its compressed and decompressed
hashes. The full DHAT profiles and raw run logs are retained outside this
repository; this directory does not contain them or reconstruct every
allocation stack.
