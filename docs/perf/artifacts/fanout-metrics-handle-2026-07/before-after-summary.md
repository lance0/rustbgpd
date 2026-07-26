# Criterion control/target summary

- Control: `a91394e8d7c5781aa3a7da12808053ec5f6e83d6`
- Target: `6e1cf047ed406572614e65a828b584478c740cf4`
- Attempts: 6, alternating control/target order
- Benchmark: `adj_rib_out_family_gauge/homogeneous_route_server_second_pass`
- Metadata: `metadata.txt`
- Exact estimates: `attempt-medians.tsv`

| Benchmark peers | attempts | control median (mean) | target median (mean) | mean delta | stddev | min..max | last-run 95% CI | verdict |
|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 1 | 6/6 | 30.71 us | 30.91 us | +0.65% | 1.52% | -1.11%..+3.18% | -1.43%..+1.56% | noise |
| 8 | 6/6 | 63.80 us | 58.59 us | -8.16% | 1.01% | -8.97%..-6.32% | -9.84%..-6.87% | improvement |
| 64 | 6/6 | 332.36 us | 281.11 us | -15.42% | 0.50% | -15.97%..-14.67% | -16.87%..-14.81% | improvement |
| 256 | 6/6 | 1.27 ms | 1.06 ms | -16.32% | 0.37% | -16.93%..-15.87% | -16.85%..-15.27% | improvement |
| 1,000 | 6/6 | 4.99 ms | 4.19 ms | -15.93% | 0.55% | -16.52%..-15.01% | -16.27%..-14.64% | improvement |

No confident regression was found by the configured verdict rule.
