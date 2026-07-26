# Criterion Compare Summary

- Run: `20260725T205533Z-515659b191b7-vs-515659b191b7-rustbgpd-rib-rib_ops`
- Base: `515659b191b7` (`515659b191b7fde91a1a1c9f973e7c8ae3731086`)
- Head: `515659b191b7` (`515659b191b7fde91a1a1c9f973e7c8ae3731086`)
- Attempts: 6 (alternating order: odd = base-first, even = head-first)
- Verdict mode: summary only
- Regression threshold: mean delta >= 3% with min..max and the last-run 95% CI both entirely above zero, stddev < 10%, with >= 3 completed attempts (delta-only rows whose 95% CI straddles zero stay advisory)
- Metadata: `$OUT/metadata.txt`
- Criterion artifacts: `$OUT/criterion`

| Benchmark | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `bulk_initial_load/10000` | 6/6 | 1.63 ms | 1.62 ms | -0.94% | 1.67% | -2.83%..+1.72% | -1.08%..-0.54% | noise |
| `bulk_initial_load/100000` | 6/6 | 26.58 ms | 26.19 ms | -1.43% | 4.05% | -9.04%..+1.24% | +0.72%..+4.24% | noise |
| `rib_pipeline/1000` | 6/6 | 285.16 us | 285.68 us | +0.18% | 0.55% | -0.63%..+0.77% | +0.39%..+1.10% | noise |
| `rib_pipeline/10000` | 6/6 | 3.44 ms | 3.45 ms | +0.21% | 1.40% | -1.05%..+2.21% | -0.85%..-0.23% | noise |
| `rib_pipeline/50000` | 6/6 | 25.17 ms | 25.05 ms | -0.43% | 2.52% | -2.95%..+3.56% | +1.04%..+1.70% | noise |

## Verdict

No confident regressions by the configured verdict rule.
