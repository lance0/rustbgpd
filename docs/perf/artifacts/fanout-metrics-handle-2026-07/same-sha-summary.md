# Criterion same-SHA control summary

- Base/head: `a91394e8d7c5781aa3a7da12808053ec5f6e83d6`
- Attempts: 6, alternating nominal base/head order
- Benchmark: `adj_rib_out_family_gauge/homogeneous_route_server_second_pass`
- Metadata: `metadata.txt`
- Exact estimates: `attempt-medians.tsv`

| Benchmark peers | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI | verdict |
|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 1 | 6/6 | 32.13 us | 30.87 us | -3.84% | 3.11% | -6.11%..+1.74% | -2.84%..-1.42% | noise |
| 8 | 6/6 | 65.46 us | 63.88 us | -2.40% | 1.67% | -4.65%..+0.41% | -5.61%..-2.36% | noise |
| 64 | 6/6 | 334.31 us | 332.87 us | -0.43% | 0.51% | -1.19%..+0.21% | -2.85%..-0.53% | noise |
| 256 | 6/6 | 1.28 ms | 1.27 ms | -0.35% | 0.75% | -1.57%..+0.65% | -2.69%..-0.36% | noise |
| 1,000 | 6/6 | 5.00 ms | 5.00 ms | -0.03% | 0.92% | -1.77%..+0.70% | -2.63%..-0.51% | noise |

The nominal base/head binaries are byte-identical. Every row is noise by the
configured across-attempt verdict.
