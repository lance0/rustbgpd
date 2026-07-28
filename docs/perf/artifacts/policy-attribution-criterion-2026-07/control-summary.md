# Criterion Compare Summary

- Run: `20260728T162822Z-e49d1c87d64c-vs-e49d1c87d64c-rustbgpd-policy-policy_eval`
- Base: `e49d1c87d64c` (`e49d1c87d64cd1e9ca5e8c9d4f2be021be8ecf14`)
- Head: `e49d1c87d64c` (`e49d1c87d64cd1e9ca5e8c9d4f2be021be8ecf14`)
- Attempts: 6 (alternating order: odd = base-first, even = head-first)
- Verdict mode: summary only
- Regression threshold: mean delta >= 3% with min..max and the last-run 95% CI both entirely above zero, stddev < 10%, with >= 3 completed attempts (delta-only rows whose 95% CI straddles zero stay advisory)
- Metadata: `metadata.txt` (sanitized shared metadata)
- Criterion artifacts: raw tree retained outside repository

| Benchmark | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `policy_chain_eval/1` | 6/6 | 44.7 ns | 42.3 ns | -3.95% | 12.80% | -23.65%..+13.14% | -1.92%..+3.82% | noise |
| `policy_chain_eval/32` | 6/6 | 399.7 ns | 402.3 ns | +0.78% | 6.10% | -7.58%..+9.68% | +5.33%..+8.48% | noise |
| `policy_chain_eval/8` | 6/6 | 123.0 ns | 119.2 ns | -2.84% | 5.46% | -11.97%..+3.26% | -1.08%..+0.31% | noise |
| `policy_chain_eval_early_deny` | 6/6 | 35.7 ns | 35.4 ns | -0.40% | 7.72% | -13.49%..+10.09% | -15.34%..-12.02% | noise |

## Verdict

No confident regressions by the configured verdict rule.
