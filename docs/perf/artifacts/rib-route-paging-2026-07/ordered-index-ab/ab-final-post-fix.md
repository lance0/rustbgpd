# Ordered-index ingest A/B — final post-fix three-group run

v0.51.0 base vs the deferred-maintenance fix across the recompute
microbenchmark and the long-lived pipeline and bulk-load shapes.

- Run: `20260718T180749Z-8711571252da-vs-451e48297b33-rustbgpd-rib-rib_ops`
- Base: `8711571252da` (`8711571252daa499a604208b891a6589057d36fc`)
- Head: `451e48297b33` (`451e48297b3361ce7795814a6f275d4abd06ed7b`)
- Attempts: 3 (alternating order: odd = base-first, even = head-first)
- Verdict mode: summary only
- Regression threshold: mean delta >= 3% with min..max and the last-run 95% CI both entirely above zero, stddev < 10%, with >= 3 completed attempts (delta-only rows whose 95% CI straddles zero stay advisory)

| Benchmark | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `bulk_initial_load/10000` | 3/3 | 1.60 ms | 1.59 ms | -0.68% | 1.02% | -1.83%..+0.13% | -0.36%..+0.86% | noise |
| `bulk_initial_load/100000` | 3/3 | 25.65 ms | 27.45 ms | +6.99% | 9.64% | -1.21%..+17.61% | +0.92%..+5.44% | noise |
| `loc_rib_recompute/1` | 3/3 | 63.0 ns | 93.3 ns | +48.52% | 8.51% | +38.72%..+54.01% | +46.15%..+62.05% | regression |
| `loc_rib_recompute/2` | 3/3 | 75.4 ns | 111.6 ns | +48.00% | 1.27% | +47.20%..+49.46% | +40.88%..+63.83% | regression |
| `loc_rib_recompute/4` | 3/3 | 109.4 ns | 146.1 ns | +33.56% | 3.27% | +29.92%..+36.25% | +25.75%..+36.29% | regression |
| `loc_rib_recompute/8` | 3/3 | 179.4 ns | 217.2 ns | +21.08% | 0.69% | +20.30%..+21.59% | +20.35%..+24.12% | regression |
| `rib_pipeline/1000` | 3/3 | 279.36 us | 278.75 us | -0.22% | 0.06% | -0.28%..-0.16% | -0.53%..+0.08% | improvement |
| `rib_pipeline/10000` | 3/3 | 3.51 ms | 3.45 ms | -1.52% | 0.47% | -2.00%..-1.06% | -3.91%..+3.89% | improvement |
| `rib_pipeline/50000` | 3/3 | 26.14 ms | 25.86 ms | -1.08% | 2.09% | -3.40%..+0.65% | -1.02%..+1.88% | noise |

## Verdict

Confident regression rows: `loc_rib_recompute/1`, `loc_rib_recompute/2`, `loc_rib_recompute/4`, `loc_rib_recompute/8`
