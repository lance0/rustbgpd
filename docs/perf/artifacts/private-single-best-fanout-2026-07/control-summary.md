# Criterion Compare Summary

- Run: `20260730T055513Z-454a83b0f700-vs-454a83b0f700-rustbgpd-transport-fanout`
- Base: `454a83b0f700` (`454a83b0f700a5d2488d9aefd684678d34fe54ad`)
- Head: `454a83b0f700` (`454a83b0f700a5d2488d9aefd684678d34fe54ad`)
- Attempts: 6 (alternating order: odd = base-first, even = head-first)
- Verdict mode: summary only
- Regression threshold: mean delta >= 3% with min..max and the last-run 95% CI both entirely above zero, stddev < 10%, with >= 3 completed attempts (delta-only rows whose 95% CI straddles zero stay advisory)
- Metadata: `<RUN_ROOT>/metadata.txt`
- Criterion artifacts: `<RUN_ROOT>/criterion`

| Benchmark | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `private_single_best_fanout/policy_peer_context/1` | 6/6 | 26.33 us | 26.20 us | -0.46% | 1.05% | -2.55%..+0.18% | -1.42%..-0.04% | noise |
| `private_single_best_fanout/policy_peer_context/256` | 6/6 | 5.00 ms | 4.99 ms | -0.18% | 1.89% | -3.54%..+1.82% | -1.84%..+0.11% | noise |
| `private_single_best_fanout/policy_peer_context/64` | 6/6 | 1.24 ms | 1.24 ms | +0.01% | 1.84% | -3.51%..+1.57% | -0.98%..+1.04% | noise |
| `private_single_best_fanout/policy_peer_context/8` | 6/6 | 159.98 us | 159.66 us | -0.16% | 1.98% | -3.95%..+1.37% | -1.49%..+0.30% | noise |

## Verdict

No confident regressions by the configured verdict rule.
