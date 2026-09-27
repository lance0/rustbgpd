# Criterion Compare Summary

- Run: `20260927T155105Z-82700ff0dfe1-vs-aea6e2c77ee5-rustbgpd-transport-fanout`
- Base: `82700ff0dfe1` (`82700ff0dfe1b37d4e5a32ec1557e19a10abedab`)
- Head: `aea6e2c77ee5` (`aea6e2c77ee5581ff399fc27d6a8ebb816d2ea4d`)
- Attempts: 6 (alternating order: odd = base-first, even = head-first)
- Verdict mode: fail on confident regression
- Regression threshold: mean delta >= 3% with min..max and the last-run 95% CI both entirely above zero, stddev < 10%, with >= 3 completed attempts (delta-only rows whose 95% CI straddles zero stay advisory)

| Benchmark | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `mp_exact_export_probe/distinct_shape_64` | 6/6 | 44.21 us | 42.60 us | +1.78% | 40.28% | -50.06%..+62.48% | +14.15%..+42.76% | noise |
| `mp_exact_export_probe/rich_scalar_50` | 6/6 | 49.66 us | 38.83 us | -19.11% | 14.11% | -47.67%..-10.89% | -12.45%..-10.46% | improvement |
| `mp_exact_export_probe/same_shape_1` | 6/6 | 516.8 ns | 444.8 ns | -13.82% | 4.03% | -19.82%..-7.93% | -13.43%..-12.47% | improvement |
| `mp_exact_export_probe/same_shape_64` | 6/6 | 3.45 us | 3.10 us | -8.53% | 12.66% | -24.92%..+1.62% | -30.54%..-7.72% | noise |

## Verdict

No confident regressions by the configured verdict rule.
Row verdicts: improvement=2, noise=2
Noise: read stddev and min..max before mean delta; a row whose min..max brackets zero is noise whatever its mean, and a same-SHA control on this host at this shape is the only honest floor.
