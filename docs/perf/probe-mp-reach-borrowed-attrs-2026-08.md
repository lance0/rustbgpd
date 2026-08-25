# MP_REACH borrowed-attribute exact-export receipt (August 2026)

## Result

The production IPv6 MP_REACH exact-export probe no longer clones its prepared
path-attribute slice into a temporary vector just to append the locally built
MP_REACH attribute. It passes the prepared attributes and that final attribute
to the wire encoder as one ordered iterator of borrowed values.

All four fixed-harness production-probe shapes improved across six alternating
A/B attempts:

| Shape | Base median mean | Candidate median mean | Mean delta | Six-attempt range | Last-attempt 95% CI |
|---|---:|---:|---:|---:|---:|
| `distinct_shape/64` | 50.52 us | 36.66 us | **-27.45%** | -32.29%..-22.69% | -32.41%..-32.12% |
| `rich_scalar/50` | 53.49 us | 41.39 us | **-22.52%** | -27.15%..-11.16% | -25.45%..-24.98% |
| `same_shape/1` | 541.4 ns | 426.3 ns | **-21.17%** | -26.74%..-18.14% | -23.76%..-23.04% |
| `same_shape/64` | 2.17 us | 2.01 us | **-7.35%** | -9.75%..-5.90% | -6.27%..-5.13% |

The deterministic rich-MP diagnostic also recorded 50 builds with identical
687-byte output (`fnv1a64:b2a66b877515c858`). The iterator path requested 750
allocations and 149,250 bytes, down from 1,200 requests and 524,050 bytes for
the legacy temporary-vector path. That is 9 fewer requests and 7,496 fewer
requested bytes per measured build for this fixture.

Machine-readable timing rows, including the control, are in
[`results.csv`](artifacts/probe-mp-reach-borrowed-attrs-2026-08/results.csv).
The exact allocation row is in
[`allocation.json`](artifacts/probe-mp-reach-borrowed-attrs-2026-08/allocation.json),
and revision, harness, environment, parameter, hash, and claim-limit evidence
is in
[`metadata.txt`](artifacts/probe-mp-reach-borrowed-attrs-2026-08/metadata.txt).

## Additive API and behavior contract

`rustbgpd-wire` adds
`UpdateMessage::try_build_from_attribute_iter`. The existing
`UpdateMessage::try_build` slice API remains available and delegates to the
same implementation; there is no version bump in this change.

The new entry point consumes its `IntoIterator<Item = &PathAttribute>` once
and encodes values in yielded order. It does not require cloning, a known
length, a double-ended iterator, or a rewind. Existing encoder rules still
apply while visiting that sequence: attributes intentionally omitted by the
encoder remain omitted, derived AS4 compatibility attributes remain in their
canonical positions, and errors stop the build with the same `EncodeError` as
the slice path. Tests compare the slice and iterator results, component buffers,
complete wire bytes, decoded semantic order, 2-octet and 4-octet ASN modes,
Add-Path modes, an empty iterator, and representative error paths.

The production caller uses
`base_attrs.iter().chain(std::iter::once(&mp_reach))`, so the transient
MP_REACH value follows the prepared attributes exactly as it did after the
legacy vector `push`. The optimization does not alter NLRI, next-hop selection,
message ceilings, Add-Path negotiation, or export-policy decisions.

## Timing method and control

Both campaigns compare baseline
`388793c12639dec17f151df2a4191ff0fc6f2b17` under one fixed benchmark file from
`4f6f45095e6e5a1690861409c7c99b99b02616c0`. The selected
`crates/transport/benches/fanout.rs` blob has SHA-256
`f048167833f87ec66358479b613d0a08d4013233509ca53b41199622cd730aa4`.
The driver verified that exact blob on both sides of every comparison.

The harness-only commit changes no production file. Comparing baseline with
that commit is therefore a same-production control. Its six-attempt envelopes
were -3.81%..+5.19% for `distinct_shape/64`, -4.69%..+2.93% for
`rich_scalar/50`, -11.00%..+1.07% for `same_shape/1`, and
-1.05%..-0.41% for `same_shape/64`. The first three rows were classified as
noise; the last was a small improvement. Candidate ranges are reported rather
than subtracting a single global noise number because each shape has its own
control distribution.

The candidate is `5673e776f6e5729b940dbfcc3f7ec0d83b7bc139`. Each campaign
used six attempts in alternating order (odd base-first, even head-first), CPU
5 pinned with `taskset`, and the `performance` governor. Criterion used its
3-second warm-up, 5-second measurement, and 100 samples for every row. The
table's base/head values are means of the six per-attempt medians. The
comparison driver was in summary-only mode (`fail_on_regression=0`); its
recorded reviewer rule used a 3% regression threshold, less than 10% across-
attempt delta standard deviation, at least three attempts, and positive
min..max plus last-attempt confidence bounds before calling a regression.

The four probe shapes cover one route with one shared ordinary attribute
shape; 64 routes sharing one attribute allocation; 64 routes with distinct
but equal ordinary attribute allocations; and 50 scalar probes with richer,
route-varying attributes. Setup assertions require exact result cardinality,
successful encodes, nonempty UPDATE bodies, and encoded lengths within each
message ceiling before Criterion starts timing.

## Allocation method

With `codec-allocation-diagnostics`, the wire benchmark uses a counting
`System` allocator. A rich IPv6 MP fixture is first built through both APIs and
required to produce an identical `UpdateMessage`, 687 encoded bytes, and the
same FNV-1a digest. Counters are then reset before 50 legacy builds and before
50 iterator builds. Each measured operation constructs the same local MP_REACH
tail; the legacy arm additionally clones and pushes into the prepared
attribute vector, while the iterator arm chains borrowed prepared attributes
with the borrowed tail. Result equality is checked after each measurement
window.

The diagnostic counts successful `alloc` / `alloc_zeroed` requests plus
successful `realloc` requests and their requested layout sizes. It does not
measure RSS, retained/live/peak heap, allocator metadata, deallocation volume,
jemalloc behavior, a session writer, or whole-daemon memory. Neither path is
allocation-free, and this receipt makes no zero-allocation claim.

## Broad IPv4-body non-regression (S3)

A separate sealed S3 campaign compared exact v0.66.0 control
`5873768daaeb197d7b5a7f531efd7feb5535e258`, current base
`388793c12639dec17f151df2a4191ff0fc6f2b17`, and candidate
`5673e776f6e5729b940dbfcc3f7ec0d83b7bc139` in the order control-A,
base-A, candidate-A, candidate-B, base-B, control-B. Every leg used 700
peers, 400,400 injected routes, 50 simultaneous flaps, three rounds, the
load-average gate, exclusive host mutex, and five-minute cooldown.

| Run | Re-announce p50 range | Mean p50 | Worst observer |
|---|---:|---:|---:|
| v0.66.0 control A | 0.453007–0.472263 s | 0.465325 s | 0.511032 s |
| current base A | 0.448660–0.465595 s | 0.457410 s | 0.498355 s |
| candidate A | 0.439626–0.453897 s | 0.446953 s | 0.492540 s |
| candidate B | 0.433906–0.451715 s | 0.445361 s | 0.491177 s |
| current base B | 0.447870–0.455176 s | 0.451997 s | 0.487639 s |
| v0.66.0 control B | 0.439917–0.459093 s | 0.448417 s | 0.495977 s |

The candidate's six-round mean was 0.446157 s versus the current base's
0.454703 s, a 1.88% decrease. Its largest round p50 was 0.453897 s and its
worst observer was 0.492540 s, below the frozen 0.55 s and 0.58 s ceilings.
Every cell established 700/700 sessions, delivered exactly 399,828 unique
routes per observer (400,400 minus that observer's own 572), returned to
700/700 sessions after each round, observed all 28,600 affected routes at all
650 survivors, and recorded zero decode errors.

Both exact-tag controls ran below the historical 0.49–0.55 s published band;
the bracketed second control reproduced that lower-side drift. An independent
rejudge accepted the current-base comparison and retired the historical lower
bound as a current-host acceptance floor. Matrix runner, sampler, generator,
reloadstall source/binary, generated scenarios, and the isolated
`bench/scale/Cargo.lock` were hash-pinned; this does not claim that the
repository-root lock was identical at the historical tag. This sweep is broad
IPv4-unicast non-regression evidence only, not evidence for the MP_REACH speedup.

## Reproduction and limits

The original shell argv was not retained. The campaign metadata retained all
comparison parameters, so the following are reconstructed reproducible
invocations, not quoted captured commands:

```bash
bench/compare-criterion.sh \
  --base 388793c12639dec17f151df2a4191ff0fc6f2b17 \
  --head 4f6f45095e6e5a1690861409c7c99b99b02616c0 \
  --package rustbgpd-transport --bench fanout \
  --features bench-internals --filter '^mp_exact_export_probe/' \
  --harness-ref 4f6f4509 \
  --harness-path crates/transport/benches/fanout.rs \
  --core 5 --attempts 6 \
  --out-dir /tmp/lan1030-baseline-control-20260825 \
  --require-performance

bench/compare-criterion.sh \
  --base 388793c12639dec17f151df2a4191ff0fc6f2b17 \
  --head 5673e776f6e5729b940dbfcc3f7ec0d83b7bc139 \
  --package rustbgpd-transport --bench fanout \
  --features bench-internals --filter '^mp_exact_export_probe/' \
  --harness-ref 4f6f4509 \
  --harness-path crates/transport/benches/fanout.rs \
  --core 5 --attempts 6 \
  --out-dir /tmp/lan1030-candidate-compare-20260825 \
  --require-performance

cargo bench -p rustbgpd-wire --bench codec \
  --features codec-allocation-diagnostics
```

The timing result covers exact UPDATE construction inside production export
probes. It excludes RIB or manager distribution, policy evaluation, session
writer scheduling, sockets, network I/O, and whole-daemon convergence. It is
an IPv6 MP_REACH result on one host, CPU, kernel, and toolchain; it is not a
fleet-wide throughput or latency guarantee.
