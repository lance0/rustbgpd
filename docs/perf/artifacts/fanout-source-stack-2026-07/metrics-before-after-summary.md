# Criterion Compare Summary

- Run: `20260726T144439Z-c933a0da8156-vs-067663e53219-rustbgpd-transport-fanout`
- Base: `c933a0da8156` (`c933a0da8156af5e56da4e9544141170e40c7e8f`)
- Head: `067663e53219` (`067663e532191bc5b3f8828e7ad659633e37f2bd`)
- Attempts: 6 (alternating order: odd = base-first, even = head-first)
- Verdict mode: summary only
- Regression threshold: mean delta >= 3% with min..max and the last-run 95% CI both entirely above zero, stddev < 10%, with >= 3 completed attempts (delta-only rows whose 95% CI straddles zero stay advisory)
- Metadata: `<CAMPAIGN_ROOT>/02-metrics-target/20260726T144439Z-c933a0da8156-vs-067663e53219-rustbgpd-transport-fanout/metadata.txt`
- Criterion artifacts: `<CAMPAIGN_ROOT>/02-metrics-target/20260726T144439Z-c933a0da8156-vs-067663e53219-rustbgpd-transport-fanout/criterion`

| Benchmark | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `adj_rib_out_family_gauge/homogeneous_route_server_second_pass/1` | 6/6 | 30.64 us | 30.80 us | +0.52% | 1.19% | -1.37%..+2.01% | -1.56%..+1.64% | noise |
| `adj_rib_out_family_gauge/homogeneous_route_server_second_pass/1000` | 6/6 | 5.01 ms | 4.28 ms | -14.51% | 0.32% | -14.84%..-13.93% | -15.61%..-13.87% | improvement |
| `adj_rib_out_family_gauge/homogeneous_route_server_second_pass/256` | 6/6 | 1.27 ms | 1.08 ms | -15.04% | 0.33% | -15.54%..-14.50% | -15.86%..-14.35% | improvement |
| `adj_rib_out_family_gauge/homogeneous_route_server_second_pass/64` | 6/6 | 332.39 us | 285.51 us | -14.10% | 0.50% | -14.76%..-13.32% | -15.28%..-13.90% | improvement |
| `adj_rib_out_family_gauge/homogeneous_route_server_second_pass/8` | 6/6 | 63.63 us | 58.44 us | -8.16% | 0.21% | -8.53%..-8.00% | -10.14%..-7.14% | improvement |

## Verdict

No confident regressions by the configured verdict rule.
