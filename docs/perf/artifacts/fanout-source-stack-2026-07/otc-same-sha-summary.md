# Criterion Compare Summary

- Run: `20260726T150130Z-6a5d19b854c9-vs-6a5d19b854c9-rustbgpd-transport-fanout`
- Base: `6a5d19b854c9` (`6a5d19b854c9f16cbde7b0cc5956ba4182f05e2c`)
- Head: `6a5d19b854c9` (`6a5d19b854c9f16cbde7b0cc5956ba4182f05e2c`)
- Attempts: 6 (alternating order: odd = base-first, even = head-first)
- Verdict mode: summary only
- Regression threshold: mean delta >= 3% with min..max and the last-run 95% CI both entirely above zero, stddev < 10%, with >= 3 completed attempts (delta-only rows whose 95% CI straddles zero stay advisory)
- Metadata: `<CAMPAIGN_ROOT>/03-otc-control/20260726T150130Z-6a5d19b854c9-vs-6a5d19b854c9-rustbgpd-transport-fanout/metadata.txt`
- Criterion artifacts: `<CAMPAIGN_ROOT>/03-otc-control/20260726T150130Z-6a5d19b854c9-vs-6a5d19b854c9-rustbgpd-transport-fanout/criterion`

| Benchmark | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `adj_rib_out_family_gauge/homogeneous_route_server_second_pass/1` | 6/6 | 31.00 us | 31.00 us | -0.00% | 0.85% | -1.08%..+1.07% | -0.82%..+3.18% | noise |
| `adj_rib_out_family_gauge/homogeneous_route_server_second_pass/1000` | 6/6 | 4.24 ms | 4.25 ms | +0.38% | 0.97% | -0.99%..+2.00% | -0.96%..+1.50% | noise |
| `adj_rib_out_family_gauge/homogeneous_route_server_second_pass/256` | 6/6 | 1.08 ms | 1.08 ms | +0.15% | 1.57% | -1.75%..+2.95% | -0.44%..+1.00% | noise |
| `adj_rib_out_family_gauge/homogeneous_route_server_second_pass/64` | 6/6 | 285.09 us | 285.27 us | +0.07% | 1.19% | -1.19%..+2.31% | -1.30%..+0.36% | noise |
| `adj_rib_out_family_gauge/homogeneous_route_server_second_pass/8` | 6/6 | 58.69 us | 58.70 us | +0.04% | 1.67% | -1.93%..+2.54% | -1.42%..+1.03% | noise |

## Verdict

No confident regressions by the configured verdict rule.
