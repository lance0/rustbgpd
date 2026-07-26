# Criterion Compare Summary

- Run: `20260726T211516Z-b874b847554a-vs-0bae2ba31ebb-rustbgpd-wire-codec`
- Base: `b874b847554a` (`b874b847554a758563ce7f09e8d7b36a35d1ea8c`)
- Head: `0bae2ba31ebb` (`0bae2ba31ebb6d99bbbeb1cfb07fe98dcdd32eb6`)
- Attempts: 6 (alternating order: odd = base-first, even = head-first)
- Verdict mode: fail on confident regression
- Regression threshold: mean delta >= 3% with min..max and the last-run 95% CI both entirely above zero, stddev < 10%, with >= 6 completed attempts (delta-only rows whose 95% CI straddles zero stay advisory)
- Metadata: `<RUN_ROOT>/metadata.txt`
- Criterion artifacts: `<RUN_ROOT>/criterion`

| Benchmark | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `update_parse_revised/1` | 6/6 | 271.7 ns | 212.6 ns | -21.73% | 1.71% | -24.34%..-19.26% | -22.09%..-21.24% | improvement |

## Verdict

No confident regressions by the configured verdict rule.
