# Criterion Compare Summary

- Run: `20260725T203213Z-7d9313e94639-vs-515659b191b7-rustbgpd-rib-rib_ops`
- Base: `7d9313e94639` (`7d9313e946395c61dfdc67744e2985f29422ed90`)
- Head: `515659b191b7` (`515659b191b7fde91a1a1c9f973e7c8ae3731086`)
- Attempts: 6 (alternating order: odd = base-first, even = head-first)
- Verdict mode: summary only
- Regression threshold: mean delta >= 3% with min..max and the last-run 95% CI both entirely above zero, stddev < 10%, with >= 3 completed attempts (delta-only rows whose 95% CI straddles zero stay advisory)
- Metadata: `$OUT/metadata.txt`
- Criterion artifacts: `$OUT/criterion`

| Benchmark | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `adj_rib_in_insert/10000` | 6/6 | 636.05 us | 618.49 us | -2.76% | 1.84% | -4.24%..+0.83% | -3.82%..-2.76% | noise |
| `adj_rib_in_insert/100000` | 6/6 | 11.17 ms | 10.17 ms | -8.17% | 12.62% | -25.48%..+13.24% | -7.78%..-5.98% | noise |
| `adj_rib_in_insert/500000` | 6/6 | 45.94 ms | 39.93 ms | -12.51% | 8.13% | -22.02%..-2.67% | -22.66%..-21.40% | improvement |
| `bulk_initial_load/10000` | 6/6 | 1.64 ms | 1.64 ms | -0.18% | 2.47% | -2.02%..+4.75% | -0.64%..+0.05% | noise |
| `bulk_initial_load/100000` | 6/6 | 27.69 ms | 27.32 ms | -0.88% | 9.97% | -18.23%..+12.30% | +0.26%..+2.13% | noise |
| `rib_pipeline/1000` | 6/6 | 291.26 us | 286.69 us | -1.57% | 0.75% | -2.54%..-0.96% | -1.76%..-0.43% | improvement |
| `rib_pipeline/10000` | 6/6 | 3.56 ms | 3.48 ms | -2.34% | 1.07% | -3.73%..-0.68% | -3.61%..-0.29% | improvement |
| `rib_pipeline/50000` | 6/6 | 26.01 ms | 25.22 ms | -3.05% | 1.28% | -4.62%..-1.16% | -2.47%..-0.87% | improvement |

## Verdict

No confident regressions by the configured verdict rule.
