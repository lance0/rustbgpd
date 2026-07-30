# Criterion Compare Summary

- Run: `20260730T061022Z-454a83b0f700-vs-b9f805a0abe6-rustbgpd-transport-fanout`
- Base: `454a83b0f700` (`454a83b0f700a5d2488d9aefd684678d34fe54ad`)
- Head: `b9f805a0abe6` (`b9f805a0abe6c0cac79b55af89ed866c7ffa10fb`)
- Attempts: 6 (alternating order: odd = base-first, even = head-first)
- Verdict mode: summary only
- Regression threshold: mean delta >= 3% with min..max and the last-run 95% CI both entirely above zero, stddev < 10%, with >= 3 completed attempts (delta-only rows whose 95% CI straddles zero stay advisory)
- Metadata: `<RUN_ROOT>/metadata.txt`
- Criterion artifacts: `<RUN_ROOT>/criterion`

| Benchmark | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `private_single_best_fanout/policy_peer_context/1` | 6/6 | 26.29 us | 25.26 us | -3.93% | 1.26% | -6.26%..-2.51% | -6.78%..-5.82% | improvement |
| `private_single_best_fanout/policy_peer_context/256` | 6/6 | 4.97 ms | 4.74 ms | -4.47% | 1.36% | -7.20%..-3.45% | -7.69%..-6.41% | improvement |
| `private_single_best_fanout/policy_peer_context/64` | 6/6 | 1.24 ms | 1.18 ms | -4.56% | 1.33% | -7.17%..-3.47% | -7.91%..-6.51% | improvement |
| `private_single_best_fanout/policy_peer_context/8` | 6/6 | 159.62 us | 152.21 us | -4.63% | 1.26% | -7.15%..-3.69% | -7.40%..-6.56% | improvement |

## Verdict

No confident regressions by the configured verdict rule.
