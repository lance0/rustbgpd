# Graceful Restart EoR stale-resolution attribution (October 2026)

## Result

A follow-up to the [original EoR attribution](gr-eor-attribution-2026-10.md)
timed both unicast stale-resolution steps in the same zero-change fixture:
1,000,000 IPv4 plus 200,000 IPv6 routes from one restarting source, followed
by identical re-advertisement and End-of-RIB (EoR) markers. One final-binary
sample per attribute shape on 2026-10-02 measured 5.6–5.7 ms for the combined
GR and LLGR stale sweeps and 3.0–3.5 ms for the subsequent stale clear per
unicast EoR. The exact retained-stale count took about 2.8 ms. The remaining
unmeasured work was 0.008–0.009 ms in the unicast rows after subtracting these
and the existing attribute-GC, recompute and distribution timers.

| EoR | Live attribute sets | Total ms | Stale sweeps ms | Stale clear ms | Exact count ms | Attribute GC ms | Other ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Empty VPNv4 | 1 | 3.077 | <0.001 | 0.225 | 2.839 | <0.001 | 0.010 |
| IPv4 unicast | 1 | 12.074 | 5.695 | 3.532 | 2.838 | <0.001 | 0.008 |
| IPv6 unicast | 1 | 11.413 | 5.609 | 2.958 | 2.836 | <0.001 | 0.009 |
| Empty VPNv4 | 148,667 | 4.378 | <0.001 | 0.225 | 2.818 | 1.318 | 0.015 |
| IPv4 unicast | 148,667 | 13.337 | 5.665 | 3.518 | 2.834 | 1.311 | 0.008 |
| IPv6 unicast | 148,667 | 12.751 | 5.615 | 2.962 | 2.841 | 1.323 | 0.009 |

`Other` is total minus stale sweeps, stale clear, exact count, attribute GC,
unicast recompute and distribution. The latter two together took at most
0.002 ms per EoR. These numbers
identify the cost of the existing zero-change path, not a proposed shortcut.
The two sweep helpers each traverse the unicast route slab to find still-stale
routes. The clear helper visits matching-family routes, checks for locally
added LLGR tags and clears stale flags even after identical re-advertisement.
Both full-table unicast EoR totals remain above the approximately 10 ms total
stop threshold. This receipt does not establish a safe way to skip any scan
or to defer reclamation or exact gauge publication.

## Fixture and limits

The bench times the production `EndOfRib` dispatch after fixture construction,
restart and re-advertisement. The new timers bracket only the two consecutive
unicast sweep calls together and the following `clear_stale()` call in the GR
arm; they do not time the LLGR branch. All six EoRs reported zero affected,
changed and retained-stale routes and zero outbound envelopes, with GR
complete only after the final family. Requested and actual interned set counts
matched at 1 and 148,667. The optional MED pool retains its attribute `Arc`s,
so the diverse cell measures a live-set scan, not reclamation. It is
synthetic, not an MRT/DFZ distribution.

Each cell ran once, in daytime on a host with an active model scheduler. The
result is component attribution for this fixture, not a speedup, latency
bound, or broad route-server claim. A preliminary clear-only run used a
different instrumentation binary; its rows remain private intermediate
evidence and are not compared with the final same-binary pair below. The
original dated receipt and its raw rows are unchanged.

## Reproduce and inspect

Build with Rust/Cargo 1.99.0, locked dependencies, the `bench-internals`
feature and the optimized bench profile:

```sh
cargo bench --locked -p rustbgpd-rib --features bench-internals \
  --bench gr_end_of_rib --no-run
```

The recorded final-binary cells ran consecutively on core 36 under the
repository host lock and a separate benchmark lock, with no competing build,
profiler, benchmark or daemon process found before either cell:

```sh
taskset -c 36 <gr_end_of_rib-executable> --mode dual --attribute-sets 1
taskset -c 36 <gr_end_of_rib-executable> --mode dual --attribute-sets 148667
```

The [artifact inventory](artifacts/gr-eor-stale-resolution-2026-10/README.md)
retains the raw JSON, source and binary identities, and checks.
