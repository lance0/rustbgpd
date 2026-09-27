# Criterion Compare Summary

- Run: `20260927T161057Z-82700ff0dfe1-vs-aea6e2c77ee5-rustbgpd-wire-codec`
- Base: `82700ff0dfe1` (`82700ff0dfe1b37d4e5a32ec1557e19a10abedab`)
- Head: `aea6e2c77ee5` (`aea6e2c77ee5581ff399fc27d6a8ebb816d2ea4d`)
- Attempts: 6 (alternating order: odd = base-first, even = head-first)
- Verdict mode: fail on confident regression
- Regression threshold: mean delta >= 3% with min..max and the last-run 95% CI both entirely above zero, stddev < 10%, with >= 3 completed attempts (delta-only rows whose 95% CI straddles zero stay advisory)

| Benchmark | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `update_parse_revised/1` | 6/6 | 282.7 ns | 235.2 ns | -16.79% | 1.27% | -18.54%..-14.98% | -17.60%..-16.04% | improvement |
| `update_parse_revised/10` | 6/6 | 368.1 ns | 316.0 ns | -14.18% | 1.41% | -15.69%..-11.75% | -16.29%..-15.20% | improvement |
| `update_parse_revised/100` | 6/6 | 973.6 ns | 935.7 ns | -3.89% | 1.44% | -5.52%..-1.87% | -6.51%..-2.65% | improvement |
| `update_parse_revised/500` | 6/6 | 3.41 us | 3.37 us | -0.99% | 1.84% | -2.27%..+2.16% | -4.76%..+0.35% | noise |
| `update_parse_revised/ipv6_mp_add_path` | 6/6 | 213.4 ns | 217.4 ns | +1.90% | 1.32% | +0.72%..+3.81% | +3.40%..+4.24% | positive-under-threshold |
| `update_parse_revised/ipv6_typical/1` | 6/6 | 296.5 ns | 286.8 ns | -3.25% | 1.35% | -5.53%..-2.17% | -4.55%..-3.64% | improvement |
| `update_parse_revised/ipv6_typical/100` | 6/6 | 1.08 us | 1.04 us | -3.74% | 3.31% | -8.36%..+0.57% | -1.15%..-0.77% | noise |

## Verdict

No confident regressions by the configured verdict rule.
Row verdicts: improvement=4, noise=2, positive-under-threshold=1
Noise: read stddev and min..max before mean delta; a row whose min..max brackets zero is noise whatever its mean, and a same-SHA control on this host at this shape is the only honest floor.
