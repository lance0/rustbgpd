# Paced first-group build during registration — November 2026

> **Document class: HISTORICAL.** Measurements from 2026-11-19 within the scope below.

This receipt records how long an unrelated UPDATE waits while the first member of a plain unicast update group registers against a table of 400,000 or 1,000,000 routes, before and after the group table is built in paced turns.

**PASS.** At 1M routes, during the first policy-free plain-unicast group build, unrelated UPDATE latency fell from 2,209 ms to 0.60 ms. Sessions with export policy, a configured role, per-client-best, or mixed families can still take the synchronous build path.

The [campaign record](artifacts/first-group-build-registration-2026-11/README.md) links the [curated comparison](artifacts/first-group-build-registration-2026-11/comparison.json), with all 16 scale cells and the six control cells, and the two harness patches.

## Shape

- **Harness.** The in-process route-reflector harness (`bench/scale/rrharness`) with a `first-registration` mode that exists only in the harness patches published with this receipt. It drives the production RIB actor directly. There is no daemon process, no TCP session, no transport and no wire encoding.
- **Table.** N IPv4 /24 best routes from four iBGP sources, N = 400,000 and 1,000,000, loaded and settled before the timed registration. The update group has no table yet.
- **Registering session.** One iBGP session marked as a route-reflector client, IPv4 unicast only, no export policy, no configured role, no route-server control, no per-client best, no Add-Path, no ORF.
- **Unrelated UPDATE.** One UPDATE carrying one /32 route from a fifth source. It is admitted on the RIB's primary queue as soon as the registration has started its first unit of work. The measured interval runs from that admission to the route's installation as the Loc-RIB winner.
- **Each cell** is one fresh process in its own memory scope with swap disabled.

## Commits and builds

The parent is `d3998cdb700431146828b31cc47a3dca44c4e07d`. The candidate is `9cda5d37222f197839db1731273da51bacf5a021`, the reviewed head of the change, which merged to main as `be3d4404a424aeb933b4d18b14ab1472d7e4cb60`. Later changes to main are in neither arm.

Both arms were built with `cargo build --locked --profile scale -p rrharness`: optimization level 3, no debug assertions, not a test build. The test-only checkpoint tally in the RIB is therefore compiled out of both arms. `rustbgpd-rib` and `rustbgpd-transport` carry the `bench-internals` feature the harness needs. The parent was built twice in separate target directories and produced the same executable hash; the candidate hash differs.

Both arms carry measurement-only instrumentation that is not in the repository: the harness mode, monotonic timestamps at registration, build, replay and installation, and per-poll work counters. The candidate patch adds counters for the paced build. The instrumentation is in the measured path of both arms.

The host ran Linux 7.0.0-30-generic on a 32-core AMD Ryzen Threadripper 7970X with 125 GiB visible memory, Rust 1.100.0.

## Bars

Written before the measurement:

- Each candidate build-only actor poll is at most 50 ms.
- The unrelated UPDATE's admission-to-installation interval is at most 50 ms on the candidate, at each scale.
- Each build poll visits at most 1,024 Loc-RIB slots or repairs at most 1,024 keys; at most one provisional table; at most 4,096 changed keys held.
- The candidate delivers all N routes and the unrelated route exactly once before one End-of-RIB.
- Peak RSS and memory-scope peak relative to the parent are at most `max(1.02, A/A + 0.01)`, in ABBA and in the confirmation.

Each scale ran eight cells in order: two parent cells from the two independent builds (A/A), then parent, candidate, candidate, parent (ABBA), then one parent and one candidate confirmation. Every cell took the host lock and two accepted quiet samples at least 30 s apart: load below 2, performance governors, no competing work and no swap activity. A kernel watcher recorded any compiler or build tool started during the campaign; none was.

## Results

ABBA means, two cells per arm:

| Routes | Interval | Parent | Candidate |
|---:|---|---:|---:|
| 400,000 | Unrelated UPDATE, admission to installation, ms | 744.012 | 0.944 |
| | Whole registration, ms | 744.346 | 602.825 |
| | Initial table replay, ms | 449.802 | 420.284 |
| | Longest actor poll, ms | 744.388 | 420.666 |
| | Peak RSS, MiB | 506.4 | 414.7 |
| 1,000,000 | Unrelated UPDATE, admission to installation, ms | 2,208.914 | 0.599 |
| | Whole registration, ms | 2,209.754 | 1,836.201 |
| | Initial table replay, ms | 1,418.116 | 1,356.233 |
| | Longest actor poll, ms | 2,209.791 | 1,356.553 |
| | Peak RSS, MiB | 1,370.1 | 1,145.9 |

All cells, unrelated UPDATE admission to installation, ms:

| Routes | Parent (five cells) | Candidate (three cells) |
|---:|---|---|
| 400,000 | 729.009–759.016 | 0.609–1.000 |
| 1,000,000 | 2,157.519–2,234.947 | 0.582–0.615 |

On the parent the build and the initial table replay run in one actor poll, so the unrelated UPDATE waits for both and reaches the registering session after its End-of-RIB. On the candidate the build took 513 polls at 400,000 routes and 2,049 at 1,000,000, the unrelated UPDATE was installed between two of them, and it reached the registering session before End-of-RIB in every cell.

| Candidate work bar | 400,000 | 1,000,000 |
|---|---:|---:|
| Longest build-only poll, ms | 6.060 | 5.440 |
| Most slots visited in one build poll | 1,024 | 1,024 |
| Most changed keys held | 1 | 1 |
| Provisional tables | 1 | 1 |

| Routes | Peak | A/A | Bar | ABBA | Confirmation |
|---:|---|---:|---:|---:|---:|
| 400,000 | RSS | 1.0113 | 1.0213 | 0.8190 | 0.8334 |
| | memory scope | 1.0091 | 1.0200 | 0.8193 | 0.8323 |
| 1,000,000 | RSS | 1.0039 | 1.0200 | 0.8364 | 0.8447 |
| | memory scope | 1.0038 | 1.0200 | 0.8356 | 0.8442 |

Six control cells at 16,384 routes passed on both arms: a cold registration, a registration into a group whose table already exists, and a receiver that expects a wrong attribute value on the unrelated route and must not record a match.

One earlier candidate build failed to compile, before any timing, because its instrumentation named an enum variant that no longer existed. The instrumentation was corrected and no measurement was discarded.

## Scope

- The result covers the group-table build of one shape: a session that negotiated only IPv4 or IPv6 unicast and has no export policy, no configured role, no route-server control and no per-client best. It was measured with IPv4 only. Every other grouped session, including any with VPN, EVPN or another family, still builds its table and replays it in one registration turn, as the parent column shows for the plain shape. Those shapes were not measured.
- The initial table replay is unchanged: one actor poll of 1.33–1.38 s at 1,000,000 routes on the candidate. An UPDATE that arrives during the replay waits for it. The unrelated UPDATE here was admitted during the build, not during the replay.
- One unrelated UPDATE was sent per cell. A build under sustained input was not measured; input that changes more than 4,096 keys before the walk can repair them restarts the build.
- A registration that also holds a pending export-policy change, a session end during the build, and a second joiner were exercised by tests, not timed here.
- The intervals are in-process, from monotonic timestamps inside an instrumented RIB. They are not wire latency, daemon convergence time or a capacity figure for any deployment.
- Two cells per arm in ABBA and one confirmation per arm at each scale. The spread is in the table above; no confidence interval is claimed.

There is no hosted Actions run for these measurements. The [RIB lifecycle page](../reference/rib-lifecycle.md#session-comes-up) describes the path and the shapes it does not cover.
