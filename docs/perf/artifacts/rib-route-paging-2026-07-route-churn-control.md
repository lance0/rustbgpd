# LAN-391 route-churn control — 2026-07-13

This control compares the same pinned commits as the retained route-paging
matrix and is intentionally separate from the matrix artifact. It checks that
the borrowed grouped paging iterator did not regress the existing RIB
route-churn benchmark.

| Field | Value |
|---|---|
| Baseline | `50399dac696507a827480be4a9dcfef49e1682b3` |
| Candidate | `d12cbaae37a9779ccc58617189253450b57c8fa4` |
| Benchmark | `route_churn/10k_base_1k_churn` |
| Attempts | 4, alternating baseline-first and candidate-first |
| Baseline median mean | 275.25 us |
| Candidate median mean | 271.98 us |
| Mean delta | -1.17% |
| Across-attempt stddev | 1.58% |
| Across-attempt range | -3.48%..+0.02% |
| Last-run 95% CI | -1.76%..+1.30% |
| Verdict | `noise`; no confident regression |

The command used the shared host lock, CPU 5 under the `performance`
governor, four counterbalanced attempts, and the fail-on-regression rule with a
3% threshold and three-attempt minimum:

```bash
bench/compare-criterion.sh \
  --base 50399dac696507a827480be4a9dcfef49e1682b3 \
  --head d12cbaae37a9779ccc58617189253450b57c8fa4 \
  --core 5 \
  --package rustbgpd-rib \
  --bench rib_ops \
  --filter route_churn \
  --attempts 4 \
  --require-performance \
  --fail-on-regression \
  --regression-threshold-pct 3 \
  --verdict-min-attempts 3
```
