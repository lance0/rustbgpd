# Ordered-index ingest A/B — no-op-body discriminator

Discriminator build: the deferred-maintenance head with the journal note
stubbed to a no-op, isolating the cost of carrying the index feature
itself from the cost of the deferred maintenance.

- Run: `20260718T173007Z-8711571252da-vs-6f79c4da4c9a-rustbgpd-rib-rib_ops`
- Base: `8711571252da` (`8711571252daa499a604208b891a6589057d36fc`)
- Head: `6f79c4da4c9a` (`6f79c4da4c9ad8112dda0890e49865f32d9f013c`)
- Attempts: 3 (alternating order: odd = base-first, even = head-first)
- Verdict mode: summary only
- Regression threshold: mean delta >= 3% with min..max and the last-run 95% CI both entirely above zero, stddev < 10%, with >= 3 completed attempts (delta-only rows whose 95% CI straddles zero stay advisory)

| Benchmark | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI | verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `loc_rib_recompute/1` | 3/3 | 69.5 ns | 90.1 ns | +29.91% | 6.25% | +22.96%..+35.06% | +14.47%..+35.93% | regression |
| `loc_rib_recompute/2` | 3/3 | 79.1 ns | 107.8 ns | +37.04% | 14.74% | +20.69%..+49.31% | +16.06%..+26.78% | inconclusive-noisy |
| `loc_rib_recompute/4` | 3/3 | 114.0 ns | 143.3 ns | +25.86% | 6.08% | +18.86%..+29.88% | +15.58%..+22.26% | regression |
| `loc_rib_recompute/8` | 3/3 | 187.1 ns | 220.0 ns | +17.62% | 3.96% | +14.71%..+22.13% | +13.00%..+16.70% | regression |

## Verdict

Confident regression rows: `loc_rib_recompute/1`, `loc_rib_recompute/4`, `loc_rib_recompute/8`
