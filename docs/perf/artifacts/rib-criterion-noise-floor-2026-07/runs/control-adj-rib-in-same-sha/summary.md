# Criterion Compare Summary

- Run: `20260725T202034Z-515659b191b7-vs-515659b191b7-rustbgpd-rib-rib_ops`
- Base: `515659b191b7` (`515659b191b7fde91a1a1c9f973e7c8ae3731086`)
- Head: `515659b191b7` (`515659b191b7fde91a1a1c9f973e7c8ae3731086`)
- Attempts: 6 (alternating order: odd = base-first, even = head-first)
- Verdict mode: summary only
- Regression threshold: mean delta >= 3% with min..max and the last-run 95% CI both entirely above zero, stddev < 10%, with >= 3 completed attempts (delta-only rows whose 95% CI straddles zero stay advisory)
- Metadata: `$OUT/metadata.txt`
- Criterion artifacts: `$OUT/criterion`

| Benchmark | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `adj_rib_in_insert/10000` | 6/6 | 613.64 us | 617.79 us | +0.68% | 1.44% | -0.30%..+3.50% | -0.57%..+0.42% | noise |
| `adj_rib_in_insert/100000` | 6/6 | 9.66 ms | 10.31 ms | +7.69% | 16.76% | -17.20%..+25.44% | -17.77%..-16.55% | noise |
| `adj_rib_in_insert/500000` | 6/6 | 38.88 ms | 39.22 ms | +1.10% | 6.62% | -8.78%..+8.22% | +4.25%..+5.50% | noise |

## Verdict

No confident regressions by the configured verdict rule.
