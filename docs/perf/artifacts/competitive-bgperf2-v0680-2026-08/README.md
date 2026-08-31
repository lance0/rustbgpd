# Competitive bgperf2 v0.68.0 compact artifacts

`results.csv` concatenates the 80 successful single-row cell outputs in stable
filename order and adds `source_file` for reconstruction. `images.json` is the
Docker image inspection record. The rustbgpd image is exact v0.68.0 commit
`d3e6c3571116261c47039b603ec64db14100ea0e` with digest
`sha256:73550c1e040d127d83a555c1a5d38fd28e39c28146a9a69c45ae0f7044e6c7fa`.

The five fixed shapes are 10 peers × 1,000 prefixes, 2 × 10,000,
2 × 100,000, 30 × 1,000, and 100 × 1,000. This is not a full-table campaign.
