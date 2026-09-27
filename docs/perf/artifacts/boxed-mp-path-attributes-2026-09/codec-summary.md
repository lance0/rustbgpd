# Criterion Compare Summary

- Run: `20260927T143722Z-82700ff0dfe1-vs-aea6e2c77ee5-rustbgpd-wire-codec`
- Base: `82700ff0dfe1` (`82700ff0dfe1b37d4e5a32ec1557e19a10abedab`)
- Head: `aea6e2c77ee5` (`aea6e2c77ee5581ff399fc27d6a8ebb816d2ea4d`)
- Attempts: 6 (alternating order: odd = base-first, even = head-first)
- Verdict mode: fail on confident regression
- Regression threshold: mean delta >= 3% with min..max and the last-run 95% CI both entirely above zero, stddev < 10%, with >= 3 completed attempts (delta-only rows whose 95% CI straddles zero stay advisory)

| Benchmark | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `attr_decode/as_set_revised/1` | 6/6 | 98.8 ns | 100.5 ns | +1.72% | 5.97% | -6.37%..+11.74% | -0.07%..+1.02% | noise |
| `attr_decode/rich/11` | 6/6 | 503.5 ns | 405.1 ns | -19.40% | 4.50% | -26.41%..-15.31% | -17.35%..-11.66% | improvement |
| `attr_decode/typical/6` | 6/6 | 231.9 ns | 184.6 ns | -20.29% | 4.33% | -27.35%..-15.24% | -18.68%..-17.72% | improvement |
| `attr_decode_revised/rich/11` | 6/6 | 420.3 ns | 388.0 ns | -7.62% | 3.68% | -13.05%..-1.84% | -14.10%..-12.58% | improvement |
| `attr_decode_revised/typical/6` | 6/6 | 215.0 ns | 190.8 ns | -11.20% | 3.92% | -15.69%..-6.35% | -9.62%..-8.11% | improvement |
| `attr_encode/rich/11` | 6/6 | 368.3 ns | 384.2 ns | +4.53% | 12.19% | -9.66%..+22.96% | -10.43%..-8.32% | noise |
| `attr_encode/typical/6` | 6/6 | 59.7 ns | 62.9 ns | +5.37% | 20.06% | -5.01%..+46.08% | -5.64%..-4.56% | noise |
| `nlri_decode/1` | 6/6 | 23.6 ns | 22.5 ns | -4.02% | 8.54% | -20.95%..+1.17% | -0.48%..+0.78% | noise |
| `nlri_decode/10` | 6/6 | 98.8 ns | 106.3 ns | +7.65% | 18.82% | -3.73%..+45.76% | -0.88%..+4.33% | noise |
| `nlri_decode/100` | 6/6 | 709.1 ns | 693.2 ns | -1.85% | 3.86% | -8.50%..+2.98% | +2.06%..+5.28% | noise |
| `nlri_decode/500` | 6/6 | 2.97 us | 3.02 us | +1.54% | 4.77% | -6.72%..+5.62% | +2.96%..+7.09% | noise |
| `nlri_encode/1` | 6/6 | 13.4 ns | 13.1 ns | -1.71% | 1.93% | -3.93%..+1.37% | -2.92%..-0.91% | noise |
| `nlri_encode/10` | 6/6 | 33.3 ns | 36.5 ns | +9.94% | 12.64% | -0.98%..+34.60% | +3.09%..+4.77% | noise |
| `nlri_encode/100` | 6/6 | 270.1 ns | 329.5 ns | +22.47% | 44.05% | -0.26%..+112.09% | +6.31%..+12.72% | noise |
| `nlri_encode/500` | 6/6 | 1.33 us | 1.38 us | +4.13% | 22.90% | -19.14%..+44.62% | -0.73%..-0.02% | noise |
| `update_build/1` | 6/6 | 152.9 ns | 133.5 ns | -8.68% | 18.21% | -44.78%..+6.77% | -5.07%..-3.91% | noise |
| `update_build/10` | 6/6 | 195.5 ns | 191.0 ns | -2.31% | 2.36% | -4.36%..+1.72% | -4.16%..-3.46% | noise |
| `update_build/100` | 6/6 | 568.6 ns | 517.1 ns | -5.95% | 16.07% | -38.51%..+2.51% | +0.04%..+1.02% | noise |
| `update_build/500` | 6/6 | 1.89 us | 1.82 us | -1.96% | 12.29% | -25.21%..+11.53% | +1.95%..+2.28% | noise |
| `update_build/ipv6_mp_add_path` | 6/6 | 138.7 ns | 121.5 ns | -8.61% | 17.30% | -43.80%..+0.93% | -2.61%..-2.08% | noise |
| `update_parse/1` | 6/6 | 261.4 ns | 235.7 ns | -9.72% | 6.00% | -19.14%..-1.85% | -6.88%..-5.79% | improvement |
| `update_parse/10` | 6/6 | 369.0 ns | 295.4 ns | -18.73% | 11.02% | -40.60%..-9.94% | -15.69%..-14.87% | improvement |
| `update_parse/100` | 6/6 | 980.3 ns | 928.6 ns | -5.24% | 2.36% | -7.70%..-1.61% | -8.23%..-6.36% | improvement |
| `update_parse/500` | 6/6 | 3.46 us | 3.39 us | -2.26% | 1.45% | -4.39%..-0.69% | -6.67%..-4.19% | improvement |
| `update_parse_revised/1` | 6/6 | 320.4 ns | 236.7 ns | -23.23% | 15.92% | -48.94%..-6.66% | -9.74%..-7.67% | improvement |
| `update_parse_revised/10` | 6/6 | 362.5 ns | 313.2 ns | -13.57% | 3.10% | -15.97%..-7.36% | -8.62%..-6.69% | improvement |
| `update_parse_revised/100` | 6/6 | 989.3 ns | 928.9 ns | -6.09% | 1.69% | -7.62%..-3.40% | -5.76%..-2.51% | improvement |
| `update_parse_revised/500` | 6/6 | 3.41 us | 3.36 us | -1.67% | 0.78% | -2.47%..-0.38% | -4.27%..-1.44% | improvement |
| `update_parse_revised/ipv6_mp_add_path` | 6/6 | 215.4 ns | 228.8 ns | +6.22% | 1.65% | +3.54%..+8.14% | +5.35%..+7.30% | regression |

## Verdict

Confident regression rows: `update_parse_revised/ipv6_mp_add_path`
Row verdicts: improvement=12, noise=16, regression=1
Noise: read stddev and min..max before mean delta; a row whose min..max brackets zero is noise whatever its mean, and a same-SHA control on this host at this shape is the only honest floor.
