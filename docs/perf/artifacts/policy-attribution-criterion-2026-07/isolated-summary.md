# Criterion Compare Summary

- Run: `20260728T164015Z-9a7b64615fd0-vs-e49d1c87d64c-rustbgpd-policy-policy_eval`
- Base: `9a7b64615fd0` (`9a7b64615fd0a81572fc75e938dd2084890fecbe`)
- Head: `e49d1c87d64c` (`e49d1c87d64cd1e9ca5e8c9d4f2be021be8ecf14`)
- Attempts: 6 (alternating order: odd = base-first, even = head-first)
- Verdict mode: summary only
- Regression threshold: mean delta >= 3% with min..max and the last-run 95% CI both entirely above zero, stddev < 10%, with >= 3 completed attempts (delta-only rows whose 95% CI straddles zero stay advisory)
- Metadata: `metadata.txt` (sanitized shared metadata)
- Criterion artifacts: raw tree retained outside repository

| Benchmark | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `policy_chain_eval/1` | 6/6 | 43.6 ns | 40.3 ns | -6.24% | 10.21% | -26.84%..-0.36% | -3.05%..+0.30% | improvement |
| `policy_chain_eval/32` | 6/6 | 392.3 ns | 390.8 ns | -0.23% | 7.17% | -7.73%..+9.46% | +5.35%..+7.50% | noise |
| `policy_chain_eval/8` | 6/6 | 119.1 ns | 116.7 ns | -1.84% | 4.63% | -10.62%..+3.24% | +2.06%..+4.39% | noise |
| `policy_chain_eval_early_deny` | 6/6 | 40.9 ns | 34.7 ns | -14.82% | 6.34% | -25.94%..-7.73% | -27.44%..-10.87% | improvement |

## Verdict

No confident regressions by the configured verdict rule.
