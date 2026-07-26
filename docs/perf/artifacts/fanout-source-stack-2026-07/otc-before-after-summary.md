# Criterion Compare Summary

- Run: `20260726T151813Z-6a5d19b854c9-vs-bf14cdd64c8a-rustbgpd-transport-fanout`
- Base: `6a5d19b854c9` (`6a5d19b854c9f16cbde7b0cc5956ba4182f05e2c`)
- Head: `bf14cdd64c8a` (`bf14cdd64c8a99f85a959c755120bd10df947025`)
- Attempts: 6 (alternating order: odd = base-first, even = head-first)
- Verdict mode: summary only
- Regression threshold: mean delta >= 3% with min..max and the last-run 95% CI both entirely above zero, stddev < 10%, with >= 3 completed attempts (delta-only rows whose 95% CI straddles zero stay advisory)
- Metadata: `<CAMPAIGN_ROOT>/04-otc-target/20260726T151813Z-6a5d19b854c9-vs-bf14cdd64c8a-rustbgpd-transport-fanout/metadata.txt`
- Criterion artifacts: `<CAMPAIGN_ROOT>/04-otc-target/20260726T151813Z-6a5d19b854c9-vs-bf14cdd64c8a-rustbgpd-transport-fanout/criterion`

| Benchmark | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `adj_rib_out_family_gauge/homogeneous_route_server_second_pass/1` | 6/6 | 31.14 us | 28.90 us | -7.17% | 0.65% | -7.86%..-6.15% | -8.00%..-6.47% | improvement |
| `adj_rib_out_family_gauge/homogeneous_route_server_second_pass/1000` | 6/6 | 4.21 ms | 2.38 ms | -43.57% | 0.54% | -44.53%..-42.96% | -44.29%..-42.83% | improvement |
| `adj_rib_out_family_gauge/homogeneous_route_server_second_pass/256` | 6/6 | 1.07 ms | 592.96 us | -44.61% | 0.54% | -45.60%..-44.11% | -45.02%..-43.70% | improvement |
| `adj_rib_out_family_gauge/homogeneous_route_server_second_pass/64` | 6/6 | 282.85 us | 163.77 us | -42.09% | 0.58% | -43.06%..-41.61% | -42.22%..-40.81% | improvement |
| `adj_rib_out_family_gauge/homogeneous_route_server_second_pass/8` | 6/6 | 58.65 us | 43.47 us | -25.88% | 0.44% | -26.34%..-25.15% | -27.61%..-25.20% | improvement |

## Verdict

No confident regressions by the configured verdict rule.
