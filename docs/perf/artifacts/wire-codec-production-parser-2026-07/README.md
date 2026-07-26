# Production wire-codec benchmark receipt

This artifact records the LAN-621 benchmark repair at benchmark-code commit
`ab518890`. It does not claim an optimization or a before/after performance
gain. It establishes current production-path coverage and proves that each new
row is sensitive to the path named by the row.

## Environment

- AMD Ryzen Threadripper 7970X, 32 cores / 64 threads
- Linux 6.17.0-35-generic
- rustc 1.97.0 (2d8144b78 2026-07-07)
- Criterion 0.8.2
- `performance` governor
- Published measurements pinned to CPU 8
- No concurrent rustbgpd build, benchmark, bgperf2, rrharness, or daemon
  process

## Published measurements

```console
taskset -c 8 cargo bench -p rustbgpd-wire --bench codec -- \
  'update_parse_revised'
taskset -c 8 cargo bench -p rustbgpd-wire --bench codec -- \
  '^update_build/ipv6_mp_add_path$'
taskset -c 8 cargo bench -p rustbgpd-wire --bench codec -- \
  'attr_(decode|encode)'
```

`measurements.tsv` contains the Criterion estimate interval transcribed from
those runs. The benchmark asserts the decoded fixture exactly before entering
each timed loop.

## Sensitivity proof

The proof-only mutations were:

1. A nominal 25 µs sleep at the entry to
   `UpdateMessage::parse_revised`.
2. One nominal 25 µs sleep in each exact `(Afi::Ipv6, true)` decoder arm
   for `MP_REACH_NLRI` and `MP_UNREACH_NLRI`.
3. One nominal 25 µs sleep at the entry to each MP reach/unreach encoder.

The first two campaigns ran unpinned on the otherwise quiet host. The encoder
campaign was pinned to CPU 8. They are qualitative path-sensitivity proofs,
not calibrated delay measurements; short sleeps overshot to roughly 77 µs
each on this kernel.

`sensitivity.tsv` records every affected row and its unaffected control. The
first campaign's legacy control showed 11.6% same-code run-to-run drift, but
remained hundreds of nanoseconds and did not inherit the injected
76.9–80.2 µs cost.

All proof-only product mutations were removed. This command passed before the
final verification:

```console
git diff --exit-code -- \
  crates/wire/src/update.rs \
  crates/wire/src/attribute.rs
```

## Load-bearing breaks

- Removing the `parse_revised` call from the numeric group erases all four
  production-ingress rows and the entry-delay sensitivity signal.
- Dropping the negotiated `(Ipv6, Unicast)` family, encoding without Add-Path,
  or changing either path ID makes the exact MP fixture assertions fail.
- Bypassing either MP decoder arm removes half the MP decoder delay.
- Bypassing either MP encoder removes half the MP build delay.

Verify the retained artifacts with:

```console
cd docs/perf/artifacts/wire-codec-production-parser-2026-07
sha256sum -c SHA256SUMS
```
