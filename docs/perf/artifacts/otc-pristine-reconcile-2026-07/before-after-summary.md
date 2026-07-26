# Criterion control/target summary

- Control: `ff055f75233f5fcbfa2dd12c7976c87489ee55fa`
- Target: `8526b27e839bf1eb3974f2df2d7a7745a8b00f70`
- Attempts: 6, alternating control/target order
- Benchmark: `adj_rib_out_family_gauge/homogeneous_route_server_second_pass`
- Metadata: `metadata.txt`
- Exact estimates: `attempt-medians.tsv`

| Peers | attempts | control median (mean) | target median (mean) | mean delta | stddev | min..max | last-run 95% CI | script verdict |
|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 1 | 6/6 | 30.94 us | 28.98 us | -6.32% | 1.14% | -7.54%..-4.59% | -5.68%..-3.11% | improvement |
| 8 | 6/6 | 58.27 us | 43.47 us | -25.41% | 0.24% | -25.61%..-25.00% | -26.60%..-23.59% | improvement |
| 64 | 6/6 | 281.77 us | 164.15 us | -41.74% | 0.16% | -41.99%..-41.58% | -42.50%..-41.03% | improvement |
| 256 | 6/6 | 1.07 ms | 595.46 us | -44.12% | 0.18% | -44.42%..-43.85% | -44.68%..-43.26% | improvement |
| 1,000 | 6/6 | 4.21 ms | 2.40 ms | -42.95% | 0.30% | -43.23%..-42.36% | -44.09%..-42.06% | improvement |

All six attempts at every shape favor the target, and every A/B range clears
the corresponding same-SHA range.
