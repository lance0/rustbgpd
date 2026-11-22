# Competitive bgperf2 v0.84.0 compact artifacts

`results.csv` concatenates the two batch tests' CSV rows, 60 in all, and adds
a `test` column. `provenance.json` records the source commit, the bgperf2 fork
revision, the shuffle seeds, each image's tag, immutable ID and reported
version, and for every run its convergence status and target-read pairing
counts. `campaign.yaml` is the batch configuration that ran.

The rustbgpd image was built with no cache from commit
`5f5ca6a312d1bdf7094440ae363495574a6ddecc`, which reports itself as 0.84.0.
BIRD 2.19.2, FRR 10.7.0 and GoBGP 4.8.0 were rebuilt with no cache from their
release tags on the same day. The BIRD 2.19.2 image is also the tester image,
and the GoBGP 4.8.0 image is also the monitor.

The five fixed shapes are 10 peers × 1,000 prefixes, 2 × 10,000,
2 × 100,000, 30 × 1,000, and 100 × 1,000. This is not a full-table campaign.
The per-run events and graph files are retained in the local campaign directory
and are not published. `SHA256SUMS` hashes each file here.
