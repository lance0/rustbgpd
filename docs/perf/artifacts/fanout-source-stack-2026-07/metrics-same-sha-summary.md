# Criterion Compare Summary

- Run: `20260726T142738Z-c933a0da8156-vs-c933a0da8156-rustbgpd-transport-fanout`
- Base: `c933a0da8156` (`c933a0da8156af5e56da4e9544141170e40c7e8f`)
- Head: `c933a0da8156` (`c933a0da8156af5e56da4e9544141170e40c7e8f`)
- Attempts: 6 (alternating order: odd = base-first, even = head-first)
- Verdict mode: summary only
- Regression threshold: mean delta >= 3% with min..max and the last-run 95% CI both entirely above zero, stddev < 10%, with >= 3 completed attempts (delta-only rows whose 95% CI straddles zero stay advisory)
- Metadata: `<CAMPAIGN_ROOT>/01-metrics-control/20260726T142738Z-c933a0da8156-vs-c933a0da8156-rustbgpd-transport-fanout/metadata.txt`
- Criterion artifacts: `<CAMPAIGN_ROOT>/01-metrics-control/20260726T142738Z-c933a0da8156-vs-c933a0da8156-rustbgpd-transport-fanout/criterion`

| Benchmark | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `adj_rib_out_family_gauge/homogeneous_route_server_second_pass/1` | 6/6 | 30.66 us | 30.66 us | -0.00% | 0.47% | -0.65%..+0.60% | -1.45%..+1.08% | noise |
| `adj_rib_out_family_gauge/homogeneous_route_server_second_pass/1000` | 6/6 | 5.04 ms | 5.01 ms | -0.45% | 0.85% | -1.82%..+0.48% | -0.54%..+1.22% | noise |
| `adj_rib_out_family_gauge/homogeneous_route_server_second_pass/256` | 6/6 | 1.27 ms | 1.27 ms | +0.11% | 0.43% | -0.54%..+0.79% | -0.85%..+1.16% | noise |
| `adj_rib_out_family_gauge/homogeneous_route_server_second_pass/64` | 6/6 | 332.00 us | 332.20 us | +0.06% | 0.40% | -0.66%..+0.53% | -0.89%..+1.11% | noise |
| `adj_rib_out_family_gauge/homogeneous_route_server_second_pass/8` | 6/6 | 63.94 us | 63.86 us | -0.12% | 0.84% | -1.04%..+1.18% | -0.71%..+1.58% | noise |

## Verdict

No confident regressions by the configured verdict rule.
