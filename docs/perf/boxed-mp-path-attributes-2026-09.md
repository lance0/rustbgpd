# Boxed MP path-attribute payloads (September 2026)

> **Document class: HISTORICAL.** This dated receipt measures one source change
> on one host; it is not a throughput or memory guarantee for another
> deployment.

Status: **accepted**. Every stored `PathAttribute` shrinks from 208 to
48 bytes. The calibrated 900,000-prefix RIB rows fall by 117.7 MiB each. On
the codec fixtures, parsing gets faster, except an UPDATE that carries both MP
attributes, which gains two small allocations.

## Question

`PathAttribute` was as large as its largest variant, the inline
`MpReachNlri` payload at 208 bytes. The RIB never stores that variant: the
inbound path removes `MP_REACH_NLRI` and `MP_UNREACH_NLRI` before interning an
attribute set, and `crates/rib/tests/memory_profile.rs` pins that behavior.
Every stored attribute nevertheless paid 208 bytes. Boxing both MP payloads
moves those bytes behind a pointer. The trade is one heap allocation for each
decoded or constructed MP attribute.

The acceptance rule was set before measurement. The change had to save more
than both 5% and 50 MiB on the calibrated RIB rows, with no meaningful codec,
inbound, or fanout regression.

## Arms

| Arm | Commit | Tree |
| --- | --- | --- |
| base | `82700ff0dfe1b37d4e5a32ec1557e19a10abedab` | `main`, the immediate parent |
| head | `aea6e2c77ee5581ff399fc27d6a8ebb816d2ea4d` | base plus the boxed variants and their call-site updates |

Two later commits change only the codec benchmark:

- `814cd995e69bcbad7982eb5feb433b13cfe7df46` updates the revised-decode
  allocation assertion to the new layout. The allocation diagnostic ran at
  this commit.
- `b6f96a2ea2fdff25a729f7d0b57b731e3eb3c7f8` adds the
  `update_parse_revised/ipv6_typical/{1,100}` rows. The follow-up parse A/B
  installed this commit's benchmark file into both arms.

No production source differs from `aea6e2c77` in either commit.

These are the measured pre-rebase commits. After rebasing onto a later `main`,
the same changes are the commits titled `perf(wire): box mp_reach and
mp_unreach path attribute payloads`, `bench(wire): pin revised-decode
requested bytes to the boxed layout`, and `bench(wire): add ipv6 typical
revised-parse rows`. The rebase changed no source in those commits.

Host: AMD Ryzen Threadripper 7970X (64 logical CPUs), Linux 7.0, rustc
1.98.1. Criterion timing ran pinned to one core under the performance
governor while a benchmark mutex was held.

## Layout

`cargo test -p rustbgpd-wire --test path_attribute_layout -- --nocapture`:

| Arm | `PathAttribute` | `MpReachNlri` | `MpUnreachNlri` | Largest remaining payload |
| --- | ---: | ---: | ---: | --- |
| base | 208 | 208 | 176 | `MpReachNlri` (inline) |
| head | **48** | 208 (boxed) | 176 (boxed) | `Unknown` (`RawAttribute`), 40 B |

The test now checks the real enum rather than a private mirror. It fails
unless `RawAttribute` is among the largest payloads and the enum fits in that
payload plus one tag word. Against the base source it fails
(`208 B grew past its largest listed payload (40 B) plus a tag word`); on
head it passes.

## Structural memory

`bench/compare-rib-memory.sh --base 82700ff0d --head aea6e2c77 --profile full`
counts allocator-live bytes with the RIB memory-profile harness. It does not
measure process RSS.

| Shape | Prefixes | Base live bytes | Head live bytes | Change |
| --- | ---: | ---: | ---: | ---: |
| `full_rib_representative` | 900,000 | 661,076,400 | 537,647,280 | **−117.7 MiB (−18.67%)** |
| `rr_fanout_representative` | 900,000 | 958,305,648 | 834,876,528 | **−117.7 MiB (−12.88%)** |
| `full_rib_representative` | 500,000 | 446,710,728 | 378,138,888 | −65.4 MiB (−15.35%) |
| `rr_fanout_representative` | 500,000 | 608,925,576 | 540,353,736 | −65.4 MiB (−11.26%) |
| `full_rib_diverse` | 900,000 | 1,723,467,792 | 859,467,792 | −824.0 MiB (−50.13%) |
| `adj_rib_in`, `full_rib`, `rr_fanout`, `loc_rib_only` | every size | — | — | at most −1.9 KiB |

Both 900,000-prefix rows save exactly 123,429,120 bytes. That matches the
model of 128,572 interned sets × 6 attributes × 160 bytes. The low-diversity
shapes hold one or two attribute sets, so they barely move. No row crossed the
harness's growth-review threshold. Every row is in
[`structural-results.csv`](artifacts/boxed-mp-path-attributes-2026-09/structural-results.csv).

## Codec and export throughput

`bench/compare-criterion.sh` ran 6 attempts in alternating order, and each
attempt measured both arms. A row is a confident regression only if all of
these hold:

- the mean delta is at least 3%;
- the min..max range and the last run's 95% interval are both above zero;
- the standard deviation is below 10%.

Full codec filter (`update_parse_revised`, `update_parse`, `update_build`,
`attr_decode_revised`, `attr_decode`, `attr_encode`, `nlri_decode`,
`nlri_encode`): 12 rows improved, 16 were noise, and 1 regressed.

| Row | Base median | Head median | Mean delta | Verdict |
| --- | ---: | ---: | ---: | --- |
| `attr_decode/typical/6` | 231.9 ns | 184.6 ns | −20.29% | improvement |
| `attr_decode/rich/11` | 503.5 ns | 405.1 ns | −19.40% | improvement |
| `attr_decode_revised/typical/6` | 215.0 ns | 190.8 ns | −11.20% | improvement |
| `update_parse_revised/1` | 320.4 ns | 236.7 ns | −23.23% | improvement |
| `update_parse_revised/100` | 989.3 ns | 928.9 ns | −6.09% | improvement |
| `update_parse_revised/500` | 3.41 µs | 3.36 µs | −1.67% | improvement |
| `update_parse_revised/ipv6_mp_add_path` | 215.4 ns | 228.8 ns | **+6.22%** | regression |
| `update_build/ipv6_mp_add_path` | 138.7 ns | 121.5 ns | −8.61% | noise |

`ipv6_mp_add_path` puts `MP_REACH_NLRI` and `MP_UNREACH_NLRI` in one UPDATE,
so each parse makes two extra allocations. It carries only four attributes, so
the smaller attribute vector never saves a reallocation. That fixture was the
only one with no realistic IPv6 counterpart, so a follow-up A/B added one.
The new `ipv6_typical/{1,100}` rows parse the five non-next-hop `typical/6`
attributes plus one `MP_REACH_NLRI` carrying 1 or 100 IPv6 prefixes. The
follow-up used the same benchmark source on both arms
(`--harness-ref b6f96a2ea --harness-path crates/wire/benches/codec.rs`,
filter `^update_parse_revised/`):

| Row | Base median | Head median | Mean delta | Verdict |
| --- | ---: | ---: | ---: | --- |
| `update_parse_revised/1` | 282.7 ns | 235.2 ns | −16.79% | improvement |
| `update_parse_revised/10` | 368.1 ns | 316.0 ns | −14.18% | improvement |
| `update_parse_revised/100` | 973.6 ns | 935.7 ns | −3.89% | improvement |
| `update_parse_revised/500` | 3.41 µs | 3.37 µs | −0.99% | noise |
| `update_parse_revised/ipv6_mp_add_path` | 213.4 ns | 217.4 ns | +1.90% | positive, under threshold |
| `update_parse_revised/ipv6_typical/1` | 296.5 ns | 286.8 ns | −3.25% | improvement |
| `update_parse_revised/ipv6_typical/100` | 1.08 µs | 1.04 µs | −3.74% | noise |

The quieter follow-up run had standard deviations of 1.3–3.3%. It puts the
combined reach-and-unreach shape at +1.9%, or +0.7% to +3.8% per attempt,
against +6.2% in the first run. Both runs agree on the direction: that shape
costs 4–13 ns more per UPDATE. A single-MP IPv6 announcement parses faster.
This receipt records the combined-shape cost; it does not treat it as a
regression of inbound processing.

Export probe (`--package rustbgpd-transport --bench fanout --features
bench-internals --filter '^mp_exact_export_probe/'`) had no confident
regression:

| Row | Base median | Head median | Mean delta | Verdict |
| --- | ---: | ---: | ---: | --- |
| `mp_exact_export_probe/same_shape_1` | 516.8 ns | 444.8 ns | −13.82% | improvement |
| `mp_exact_export_probe/rich_scalar_50` | 49.66 µs | 38.83 µs | −19.11% | improvement |
| `mp_exact_export_probe/same_shape_64` | 3.45 µs | 3.10 µs | −8.53% | noise |
| `mp_exact_export_probe/distinct_shape_64` | 44.21 µs | 42.60 µs | +1.78% | noise (40% stddev) |

Each summary is retained as `*-summary.md`. The per-attempt Criterion mean,
median, and standard deviation for every row are in the matching
`*-estimates.csv`.

## Allocation counts

`cargo bench -p rustbgpd-wire --bench codec --features
codec-allocation-diagnostics` ran once per arm, with 10,000 operations per row:

| Row | Base calls | Head calls | Base requested bytes | Head requested bytes |
| --- | ---: | ---: | ---: | ---: |
| `attr_decode_revised/typical/6` | 50,000 | 50,000 | 26,440,000 | **7,240,000** |
| `attr_decode_revised/ipv6_mp_reach/1` | 30,000 | **40,000** | 9,240,000 | 4,920,000 |
| `attr_encode/rich/11` | 80,000 | 80,000 | 10,840,000 | 10,840,000 |
| `validate_update` | 0 | 0 | 0 | 0 |

`update_build/rich_mp/50` (50 builds):

| Path | Base calls | Head calls | Base requested bytes | Head requested bytes |
| --- | ---: | ---: | ---: | ---: |
| legacy owned-attribute build | 1,200 | 1,250 | 524,050 | 270,450 |
| borrowed-iterator build | 750 | 800 | 149,250 | 159,650 |

Each decoded or cloned MP attribute now makes one extra allocation of 208 or
176 bytes. Every attribute vector in turn requests 160 bytes less per slot of
capacity. The only row that requests more bytes is the borrowed-iterator
build: its single cloned MP_REACH adds 208 bytes per build. Every row is in
[`allocation.jsonl`](artifacts/boxed-mp-path-attributes-2026-09/allocation.jsonl).

## Daemon DHAT attribution and release control

These whole-daemon runs use the bgperf2 2 peers × 100,000 prefixes shape,
driven by the adapter pinned at `fe4fdab9`. BIRD announces every route from a
peer with the same attributes, so the daemon stores about two attribute sets.
The change can therefore save only a few kilobytes on this shape. These runs
test ownership and whether the daemon regressed; they cannot show the memory
gain.

The pinned adapter needed one local change. It rendered
`[security.grpc] enforcement = "legacy"`, which the daemon has rejected at
boot since v0.63.0, together with an unauthenticated TCP gRPC listener. The
changed adapter renders neither and queries neighbor state over the default
owner-only socket. Images were built with the unmodified pinned adapter; the
changed adapter only ran the benchmarks.

The daemon runs under `docker exec`, so `docker stop` would kill it before
DHAT writes its profile. Each DHAT run therefore sent SIGTERM to the
`rustbgpd` process itself. The daemon exited within 2 s, and the profile was
classified with `bench/scale/rebaseline/classify_dhat.py`.

| DHAT run | Converged | Tester errors | Tracked live bytes at t-gmax | Interned attribute-set backing |
| --- | ---: | ---: | ---: | ---: |
| base | 200,000 / 200,000 | 0 | 198,361,174 | 0 |
| head | 200,000 / 200,000 | 0 | 198,244,621 | 0 |

The head run tracked 116,553 fewer live bytes (−0.06%). Most of the
difference is in session buffers, the group-table trie index, the API layer,
and telemetry, not in any attribute component. As expected, this shape does
not exercise the change.

The release-image control ran in the fixed order B1, C1, C2, B2:

| Run | Arm | Converged | Convergence (s) | Total (s) | bgperf2 max memory (GB) |
| --- | --- | ---: | ---: | ---: | ---: |
| B1 | base | 200,000 / 200,000 | 3 | 12.46 | 0.246 |
| C1 | head | 200,000 / 200,000 | 3 | 12.54 | 0.198 |
| C2 | head | 200,000 / 200,000 | 3 | 12.54 | 0.204 |
| B2 | base | 200,000 / 200,000 | 3 | 12.56 | 0.194 |

Every run converged with zero tester errors. Convergence was identical, and
mean total time was 12.51 s on base and 12.54 s on head (+0.2%). bgperf2
samples container memory and spreads by 52 MB between the two base runs, so
this table supports no memory claim. The sealed-image cgroup `memory.peak`
protocol of the
[August 2026 attribution campaign](memory-attribution-2026-08.md) was not run.
On a shape with two attribute sets it would measure a difference far below its
±30–50 MiB noise floor. A real-table or high-diversity daemon measurement
remains open.

## Limits

- The structural rows count allocator-live bytes inside the RIB harness. They
  exclude allocator size classes, fragmentation, and whole-process RSS. The
  saving depends on how many distinct attribute sets are stored: shapes with
  one or two sets save almost nothing, and a one-set-per-prefix table saves
  half its bytes.
- Each Criterion result is a fixture measurement of one codec or export-probe
  operation. None covers RIB distribution, policy, sockets, or daemon
  convergence.
- The allocation counts use the benchmark's system allocator. The daemon uses
  jemalloc by default, where allocation costs differ.
- The 2026-09-23 ticket analysis projected roughly 126–252 MiB of saving for a
  1.3M-prefix full table. That figure is modeled from the set count of one
  live table; no real-table measurement was taken for this receipt.

Artifacts, checksums, and verification commands are listed in the
[artifact README](artifacts/boxed-mp-path-attributes-2026-09/README.md).
