# IRR reload v0.68.0 compact artifacts

These files retain every verifier-approved row from the 2026-08-30 IRR reload
campaign. Each overlap point has 24 comparison rows and eight grouped-control
rows. The verifier JSON records the frozen source, dataset, execution order,
input shape, and received-view delta check.

`rss-peaks.csv` is mechanically derived from the raw five-second process-tree
RSS streams. It retains the maximum `total_rss_kib` for every root/cell pair;
the full streams and logs remain outside the repository.

The campaign used commit
`451e3685d676bcc0b4294276a6989891378819d8`. The release-built product inputs
and IRR runner inputs are identical to v0.68.0 commit
`d3e6c3571116261c47039b603ec64db14100ea0e`; the intervening reloadstall change
only extends AS_TRANS handling above 1,023 peers and is outside this 320-member
shape. This is source-equivalent release evidence, not an exact-tag run.

Verify the compact bundle with `sha256sum -c SHA256SUMS` and
`jq -e . ov*-verification.json`.
