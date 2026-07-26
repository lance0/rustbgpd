# Criterion same-SHA control summary

- Base/head: `ff055f75233f5fcbfa2dd12c7976c87489ee55fa`
- Attempts: 6, alternating nominal base/head order
- Benchmark: `adj_rib_out_family_gauge/homogeneous_route_server_second_pass`
- Metadata: `metadata.txt`
- Exact estimates: `attempt-medians.tsv`

| Peers | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI | script verdict |
|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 1 | 6/6 | 31.04 us | 30.98 us | -0.17% | 0.63% | -1.28%..+0.46% | -2.47%..+1.73% | noise |
| 8 | 6/6 | 58.66 us | 58.50 us | -0.27% | 0.76% | -1.31%..+0.92% | -1.63%..+1.24% | noise |
| 64 | 6/6 | 285.49 us | 282.81 us | -0.93% | 1.40% | -2.86%..+0.78% | -2.30%..-0.31% | noise |
| 256 | 6/6 | 1.08 ms | 1.07 ms | -1.38% | 1.57% | -2.97%..+0.73% | -2.86%..-1.55% | noise |
| 1,000 | 6/6 | 4.28 ms | 4.22 ms | -1.33% | 1.82% | -3.52%..+0.90% | -4.26%..-1.15% | noise |

The nominal base/head binaries are byte-identical. Every across-attempt range
crosses zero and the script classifies every row as noise.
