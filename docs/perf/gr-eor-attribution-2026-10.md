# Graceful Restart End-of-RIB attribution (October 2026)

## Result

One in-process RIB-manager sample per mode on 2026-10-02 attributed the cost
of a zero-change Graceful Restart End-of-RIB (EoR). With 1,000,000 IPv4 and
200,000 IPv6 routes, the final-binary dual-stack control took 11.763 ms for
IPv4 EoR and 11.386 ms for IPv6 EoR with one live interned attribute set.
The exact retained-stale count walk took 2.868 and 2.836 ms. Attribute GC took
less than 0.001 ms. The 8.893 and 8.548 ms residuals include work outside the
four component timers and remain unassigned.

The same binary with 148,667 synthetic MED-distinct live attribute sets took
13.404 and 12.851 ms for those unicast EoRs. Attribute GC, including its
gauge sync, took 1.319 and 1.375 ms; exact stale counting remained about
2.8 ms. Both full-table unicast totals exceed the approximately 10 ms total
EoR stop threshold for this investigation. The measured components alone do
not support changing GC scheduling or adding incremental stale counters.

| Final-binary EoR | Live attribute sets | Total ms | Attribute GC ms | Exact stale count ms | Other ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| Empty VPNv4 | 1 | 3.177 | <0.001 | 2.936 | 0.239 |
| IPv4 unicast | 1 | 11.763 | <0.001 | 2.868 | 8.893 |
| IPv6 unicast | 1 | 11.386 | <0.001 | 2.836 | 8.548 |
| Empty VPNv4 | 148,667 | 4.391 | 1.329 | 2.814 | 0.246 |
| IPv4 unicast | 148,667 | 13.404 | 1.319 | 2.840 | 9.244 |
| IPv6 unicast | 148,667 | 12.851 | 1.375 | 2.826 | 8.649 |

`Other` is total minus recompute, distribution, attribute GC, and stale count.
The first two components were at most 0.002 ms per EoR in these rows. The
empty VPNv4 EoR has no VPN routes but still invokes the full-peer stale count
and global attribute GC.

## Fixture and limits

The bench seeds one source through the production `RoutesReceived` path,
marks its GR families stale, re-advertises the identical table, then times
each production `EndOfRib` dispatch. Fixture construction, restart, and
re-advertisement are outside the timed interval. All EoRs reported zero
affected and changed routes, zero retained-stale routes and outbound
envelopes. Final Loc-RIB counts matched the fixture, and GR completed after
the final family.
The default remains one shared attribute set. `--attribute-sets N` reuses a
deterministic pool of MED-distinct sets for both advertisements and asserts
the actual interned cardinality.

The attribute pool keeps its `Arc` references alive, so this result measures
a live-set scan, not reclamation after withdrawal. MED diversity is a
synthetic control, not an MRT or DFZ attribute distribution. This daytime,
one-sample run shared a host with an active model scheduler. It supports
component attribution in these fixtures, not a speedup, a latency bound, or
a general route-server result.

An earlier one-set four-mode sample used a different instrumentation binary.
Its dual, two per-client-best, and IPv4-only rows remain in the
[raw artifact](artifacts/gr-eor-attribution-2026-10/README.md) as historical
observations. They are not same-binary comparisons with the diversity control.

## Reproduce and inspect

Build with Rust/Cargo 1.99.0, locked dependencies, and the `bench-internals`
feature:

```sh
cargo bench --locked -p rustbgpd-rib --features bench-internals \
  --bench gr_end_of_rib --no-run
```

Run the resulting optimized `gr_end_of_rib` executable on an otherwise quiet
core. The recorded final-binary cells used core 36, in this order:

```sh
taskset -c 36 <gr_end_of_rib-executable> --mode dual --attribute-sets 1
taskset -c 36 <gr_end_of_rib-executable> --mode dual --attribute-sets 148667
```

The [artifact inventory](artifacts/gr-eor-attribution-2026-10/README.md)
provides raw JSON, source/diff and binary hashes, run context, and checks.
