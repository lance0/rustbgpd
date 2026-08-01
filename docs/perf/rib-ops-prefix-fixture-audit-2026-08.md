# RIB operations prefix-fixture audit — 2026-08

This audit bounds the historical evidence affected by the pre-#1374
`crates/rib/benches/rib_ops.rs` prefix generator. Before commit `13d542c3`,
the generator varied only two IPv4 octets and repeated after 65,536 `/24`s.
Benchmark rows above that count therefore timed all requested loop iterations,
but they did not contain the advertised number of unique route keys.

This is an interpretation correction, not a rerun. Retained output, manifests,
and checksums remain immutable. Historical absolute timings and A/B deltas are
still byte-truthful for the duplicate-shaped workload that ran: both sides of
each A/B used the same fixture. They are not evidence for a unique table above
65,536 routes.

## Complete affected roster

| Historical row | Evidence packages | What ran | Current interpretation |
|---|---|---|---|
| `adj_rib_in_insert/100000` | RIB Criterion noise-floor package and current benchmark summary | 100,000 insert iterations over 65,536 unique `(prefix, path_id)` keys | Same-SHA variance and historical A/B remain valid for this duplicate-key shape; not unique-100k insert evidence |
| `adj_rib_in_insert/500000` | RIB Criterion noise-floor package and current benchmark summary | 500,000 insert iterations over 65,536 unique keys | The published suggestive delta remains an observation for this duplicate-key shape; not unique-500k insert evidence |
| `bulk_initial_load/100000` | v0.61.0 Criterion archive, RIB Criterion noise-floor package, and route-paging ordered-index A/B control | 100,000 inserts plus 100,000 recompute attempts; 65,536 unique prefixes and final output keys | Absolute and A/B rows remain exact duplicate-shaped regression anchors; not unique-100k cold-load evidence |

Those are the complete affected rows in the named July packages. Within those
packages, no affected comparison was graded confident or causal:

- the 100k and 500k insert rows in the noise-floor receipt were respectively
  uninterpretable and explicitly suggestive, not claims;
- the route-paging 100k bulk-load comparison straddled zero and was graded
  non-confident; and
- the v0.61.0 archive is a single-revision absolute baseline, not a causal
  performance comparison.

The published 2.35% `AdjRibIn::insert` improvement is unaffected: it was
measured at 10,000 unique routes, below the old generator's wrap point.

## Source boundary and unaffected evidence

| Generator or source | Source evidence | Disposition |
|---|---|---|
| Historical `rib_ops.rs::generate_prefixes` at counts no greater than 65,536 | The old expression mapped the low 16 bits of the index into the second and third address octets | `adj_rib_in_insert/10000`, `bulk_initial_load/10000`, `rib_pipeline/1000`, `/10000`, and `/50000` retain their unique-prefix interpretation. `route_churn/10k_base_1k_churn` retains a unique 10k base and intentionally updates 1k of those keys. |
| Current [`rib_ops.rs::generate_prefixes`](../../crates/rib/benches/rib_ops.rs) | Commit `13d542c3` advances to a new first-octet block every 65,536 prefixes and asserts that the collected `HashSet` length equals the request | New runs support unique-route interpretation through the asserted fixture limit; they do not retroactively change archived rows. |
| Route-paging retained `measurement-sources/route_paging.rs::make_routes` | The checksummed [route-paging archive](artifacts/rib-route-paging-2026-07/route-paging-receipt.tar.gz) adds each index to a `u32` IPv4 base, emits `/32`s, and collects the changed keys into a `HashSet` | The 100k/400k core route-paging matrix is independent and remains unique-route evidence. Only its separate 100k `bulk_initial_load` Criterion control is affected. |
| [`memory_profile.rs::generate_prefixes`](../../crates/rib/tests/memory_profile.rs) | The high-N memory harness maps 24 index bits into three IPv4 octets | The 100k/500k/900k RIB-memory rows are independent and remain unique-prefix evidence. |
| [`route_data_sharing_profile.rs::prefixes`](../../crates/rib/tests/route_data_sharing_profile.rs) | The shared-`RouteData` gate independently maps 24 index bits into three IPv4 octets | Its 50k shape is unique-prefix evidence and unaffected. |
| Real-daemon, transport, and bgperf2 harnesses | These receipts do not call the `rib_ops.rs` generator | Their route-count claims are outside this audit and unchanged. |
| Wire, policy, and non-RIB Criterion suites in the v0.61.0 archive | Separate benchmark targets and fixtures | Unaffected. |

## Corrected reading

Use the retained affected rows only for exact-shape regression comparisons.
Do not derive unique-table throughput, cold-load scaling, or a 900k-route
extrapolation from them. Current unique high-N evidence must come from a run of
the corrected generator or from one of the independent sources above.

No rerun is required to correct these packages: their affected evidence
was non-confident or absolute-only. A future claim about unique RIB insert or
cold-load performance above 65,536 routes must use the corrected fixture and
retain its uniqueness preflight.

## Load-bearing proof

Docs-only red proof: N/A; this change adds no executable gate. The corrected
benchmark carries the destructive preflight: restoring the old two-octet
generator makes its 100,000-prefix uniqueness assertion fail with 65,536
unique entries. That is the structural fence for future collections.
