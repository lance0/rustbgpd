# Criterion Compare Summary

- Run: `20260725T211102Z-12c63b7cd637-vs-5e2ae925157a-rustbgpd-rib-rib_ops`
- Base: `12c63b7cd637` (`12c63b7cd637699cb692a22d5e447cf65962a89a`)
- Head: `5e2ae925157a` (`5e2ae925157ae6237babaabdaf17b2802094d0c7`)
- Attempts: 6 (alternating order: odd = base-first, even = head-first)
- Verdict mode: summary only
- Regression threshold: mean delta >= 3% with min..max and the last-run 95% CI both entirely above zero, stddev < 10%, with >= 3 completed attempts (delta-only rows whose 95% CI straddles zero stay advisory)
- Metadata: `$OUT/metadata.txt`
- Criterion artifacts: `$OUT/criterion`

| Benchmark | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `adj_rib_in_insert/10000` | 6/6 | 622.08 us | 607.46 us | -2.35% | 0.61% | -3.35%..-1.50% | -3.54%..-2.75% | improvement |
| `adj_rib_in_insert/100000` | 6/6 | 10.71 ms | 9.79 ms | -7.96% | 10.39% | -21.22%..+3.28% | -7.63%..-6.20% | noise |
| `adj_rib_in_insert/500000` | 6/6 | 46.72 ms | 39.95 ms | -14.24% | 4.87% | -18.85%..-5.03% | -16.05%..-15.28% | improvement |
| `rib_pipeline/1000` | 6/6 | 288.25 us | 286.27 us | -0.69% | 0.80% | -1.70%..+0.48% | -2.34%..-1.45% | noise |
| `rib_pipeline/10000` | 6/6 | 3.44 ms | 3.44 ms | -0.01% | 1.48% | -1.74%..+1.62% | -2.27%..-0.55% | noise |
| `rib_pipeline/50000` | 6/6 | 25.24 ms | 25.21 ms | -0.06% | 3.04% | -4.03%..+3.78% | -4.99%..-3.22% | noise |

## Verdict

No confident regressions by the configured verdict rule.
