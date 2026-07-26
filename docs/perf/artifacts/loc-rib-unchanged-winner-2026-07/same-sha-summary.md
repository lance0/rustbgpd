# Same-SHA control

- Base: `35b33a5d0ca901e15e995aaff5aff1e31038e88b`
- Head: `35b33a5d0ca901e15e995aaff5aff1e31038e88b`
- Attempts: 6, alternating order

| Benchmark | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `loc_rib_recompute/no_change/1000` | 6/6 | 37.72 us | 37.49 us | -0.62% | 1.37% | -2.34%..+1.10% | -1.96%..-1.44% | noise |
| `loc_rib_recompute/no_change/10000` | 6/6 | 422.55 us | 421.58 us | -0.23% | 0.44% | -0.84%..+0.28% | -0.60%..-0.31% | noise |
| `loc_rib_recompute/no_change/50000` | 6/6 | 3.98 ms | 3.99 ms | +0.21% | 0.38% | -0.22%..+0.76% | -0.23%..+2.03% | noise |

No confident regressions. Because both refs are identical, all movement is
measurement noise.

