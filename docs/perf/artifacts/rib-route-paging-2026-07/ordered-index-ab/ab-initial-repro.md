# Ordered-index ingest A/B — initial regression reproduction

Two-attempt pinned-harness reproduction of the nightly tripwire: v0.51.0
base vs the eagerly maintained ordered index inside `LocRib::recompute`.

- Run: `20260718T161700Z-8711571252da-vs-46fa89e8cafb-rustbgpd-rib-rib_ops`
- Base: `8711571252da` (`8711571252daa499a604208b891a6589057d36fc`)
- Head: `46fa89e8cafb` (`46fa89e8cafb8d520bb806d9c6048fe07d3ce6fa`)
- Attempts: 2 (alternating order: odd = base-first, even = head-first)
- Verdict mode: summary only
- Regression threshold: mean delta >= 3% with min..max and the last-run 95% CI both entirely above zero, stddev < 10%, with >= 3 completed attempts (delta-only rows whose 95% CI straddles zero stay advisory)

| Benchmark | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `loc_rib_recompute/1` | 2/2 | 71.0 ns | 134.9 ns | +90.27% | 11.08% | +82.43%..+98.11% | +88.92%..+107.94% | insufficient-attempts |
| `loc_rib_recompute/2` | 2/2 | 80.2 ns | 153.4 ns | +91.78% | 11.31% | +83.78%..+99.78% | +90.95%..+107.14% | insufficient-attempts |
| `loc_rib_recompute/4` | 2/2 | 117.2 ns | 188.4 ns | +60.77% | 0.88% | +60.15%..+61.39% | +58.72%..+66.36% | insufficient-attempts |
| `loc_rib_recompute/8` | 2/2 | 185.0 ns | 268.5 ns | +45.14% | 0.14% | +45.05%..+45.24% | +42.38%..+49.04% | insufficient-attempts |

## Verdict

No confident regressions by the configured verdict rule.
