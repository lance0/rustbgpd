# Immediate-parent A/B

- Base: `35b33a5d0ca901e15e995aaff5aff1e31038e88b`
- Head: `80b34f3af806a4cca378e570e436adaa261b3211`
- Attempts: 6, alternating order

| Benchmark | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `loc_rib_recompute/no_change/1000` | 6/6 | 37.85 us | 33.87 us | -10.50% | 0.88% | -11.83%..-9.32% | -9.46%..-9.07% | improvement |
| `loc_rib_recompute/no_change/10000` | 6/6 | 421.88 us | 392.67 us | -6.93% | 0.29% | -7.29%..-6.64% | -6.86%..-6.46% | improvement |
| `loc_rib_recompute/no_change/50000` | 6/6 | 4.01 ms | 4.17 ms | +3.88% | 0.91% | +2.34%..+4.79% | +3.79%..+5.93% | regression |

The confident 50,000-route regression rejects the proposed optimization.

