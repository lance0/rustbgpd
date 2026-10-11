# RPKI validation-refresh baseline, October 2026

At a 700-member dual-stack route server, a changed VRP table cost the daemon
at most 0.66 CPU-seconds and 0.36 s to settle (medians), whether the RTR delta
replaced 10, 100 or 1,000 VRPs. That is under the predeclared bar of 1
CPU-second and 1 s. The members carry the cost instead: every delta, even one
covering 20 routes, made the daemon send ROUTE-REFRESH for both families to all
700 members, and they re-sent all 400,400 NLRI.

Measured on 2026-10-03 on one host, against main `481e0187d` with no
refresh-targeting change. Published on 2026-10-11 from the retained data. The
[compact evidence](artifacts/rpki-validation-refresh-baseline-2026-10/README.md)
holds every cell's harness log, RTR cache log, daemon events, CPU and readiness
samples, and a script that recomputes every number below.

## Question

When the RTR cache delivers a changed VRP table, the RIB re-validates only the
routes the delta covers. The peer manager then asks every Established member
whose import policy uses an `rpki is …` match for a full inbound replay of
every negotiated family. Most of that replay cannot change a routing outcome.

How much does that full-fleet replay cost the daemon, and how much does it ask
of the members? Is the cost high enough to justify sending ROUTE-REFRESH only to
the members, or only for the address families, that a delta can affect?

## The bar

Fixed before the run: decline the targeting work if a full-fleet replay at
700 × 400,400 costs **under 1 CPU-second of daemon time and under 1 s to
settle** (median at every delta size), *and* the member-side replay is judged
acceptable. Otherwise, a targeted variant would have to send ROUTE-REFRESH to at
most 20% of the baseline's members for a 100-entry delta, with byte-identical
member views after settle compared with a full-refresh control.

## Shape

- 700 route-server members, each with its own ASN, and 400,400 disjoint
  prefixes: 200,200 IPv4 and 200,200 IPv6, 572 per member (286 per family).
  Every session negotiates IPv4 and IPv6 unicast.
- Every member's import chain rejects RPKI-invalid routes
  (`GEN_DUALSTACK=1 GEN_RPKI_CACHE=…` in `bench/scale/reloadstall/gen-scenario.py`).
- 500,000 VRPs (299,800 IPv4 and 200,200 IPv6) that make every announced route
  Valid, served over RTR v1 by StayRTR 0.6.4, pinned by digest.
- **Delta.** N maxLength replacements, half per family, for N = 10, 100 and
  1,000 (`rpki_cell.py maxlen-delta`). Each replacement is one withdrawal and
  one announcement for the same prefix and origin, so the VRP count and every
  route's validity stay unchanged. The RIB re-validates the covered routes and
  changes none; any remaining work is the refresh and replay.
- The harness holds all 700 sessions with no churn (`reloadstall --no-churn`)
  and answers each ROUTE-REFRESH with its full table for that family.

## Method

- **Source and binaries.** Main `481e0187d873dd8e7715033224be0fe90cb7d4e2`
  (workspace 0.73.0), which contains the harness prerequisites #2855
  (ROUTE-REFRESH accounting), #2857 (RPKI scenario configuration), #2858
  (dual-stack VRP fixtures) and #2859 (held sessions without churn). Built with
  Rust 1.99.0: `cargo build --release --locked --bin rustbgpd --bin rbgp` and
  `cargo build --profile scale --locked -p reloadstall`. The daemon's sha256 is
  `010a999f7ac58234a093c55f1b2ae191eb2ed0015ce3e3704de0823dd54d2ab5`; the
  other hashes are in
  [`provenance.json`](artifacts/rpki-validation-refresh-baseline-2026-10/provenance.json).
- **Cells.** One fresh RTR cache, daemon and harness per cell; two repetitions
  per N in the order 10, 100, 1,000, 1,000, 100, 10. Before every cell the
  shared host lock was held and the quiet-host gate
  (`bench/scale/host-quiet.sh`) retained two accepted samples.
- **Injection.** After the initial table loaded and both families converged
  at every member, the poller ran 10 s idle, then the delta file replaced the
  cache file by atomic rename in a directory mount.
- **Clocks.** Every interval starts at the daemon's
  `RTR incremental update received` log event. The cache's file-poll lag before
  that point (2.43–2.53 s medians) is reported separately and excluded.
  **Settle** ends at the latest of the RIB's
  `RPKI cache update re-validation complete` event, the
  `processed validation-cache import-policy refresh` event, and the last
  observed increase of the daemon's summed received-UPDATE counter. The
  counter is polled every 0.25 s, so the last-UPDATE time can be late by up
  to one poll interval.
- **CPU.** Daemon `utime + stime` from `/proc`, at 10 ms resolution, between the
  last poll before the delta and the first poll at or after settle. **Net**
  subtracts the idle rate (0.15–0.16 CPU-seconds per second with the pollers
  running) measured over the 10 s before injection.
- **Member burden.** Each harness member counts ROUTE-REFRESH requests received,
  requests suppressed by its one-outstanding-per-family latch, replays
  completed, and NLRI in replay UPDATEs it wrote.
- **Validity.** A cell counts only if: the RTR session is unchanged and its
  serial advanced by exactly one; exactly one incremental update arrived with
  N announced and N withdrawn and no full table followed; the RIB re-validated
  in `mode=delta` with zero changed routes; one refresh pass reported
  eligible = refreshed = 700 with no skips or failures; all 700 sessions stayed
  up with unchanged flap counts and zero parse errors; every member and family
  received at least one ROUTE-REFRESH; and the replay was quiet for 10 s before
  the hold ended. All six cells passed, and the job exited 0.
- **Placement.** Daemon on CPUs 12–32 and 34–39, harness on 40–63, RTR cache on
  8–11. One AMD Ryzen Threadripper 7970X host, Linux 7.0.0-30-generic.

## Results

Medians of two cells per N; per-cell values are in
[`cells.json`](artifacts/rpki-validation-refresh-baseline-2026-10/cells.json).

| N VRPs replaced | Settle | Re-validation / refresh pass / last UPDATE | Daemon CPU, net (raw) | ROUTE-REFRESH sent | Replayed NLRI | Replay UPDATEs |
|---|---|---|---|---|---|---|
| 10 | 0.36 s | 0.16 / 0.19 / 0.36 s | 0.66 s (0.74) | 1,400 | 400,400 | 1,400 |
| 100 | 0.24 s | 0.16 / 0.19 / 0.24 s | 0.48 s (0.53) | 1,400 | 400,400 | 1,400 |
| 1,000 | 0.34 s | 0.20 / 0.18 / 0.34 s | 0.62 s (0.69) | 1,400 | 400,400 | 1,400 |

- **Daemon side.** Net CPU per cell ranged from 0.46 to 0.70 s, and settle from
  0.23 to 0.37 s. The last replayed UPDATE set the settle time in every cell.
- **RIB re-validation.** The RIB re-validated 20, 200 and 2,000 routes in
  2–3, 6 and 46–47 ms, and changed none.
- **Member side.** In every cell the refresh pass covered all 700 members.
  Each member received one ROUTE-REFRESH per family, completed both replays and
  re-sent its 572 NLRI: 1,400 requests with none suppressed, 1,400 completed
  replays and 400,400 NLRI in total. The replay volume does not depend on the delta size: a delta covering
  20 routes cost the same replay as one covering 2,000.
- **Readiness.** Every `/readyz` sample inside a settle window returned 200,
  the slowest in 159.3 ms. The windows are short, so there were only 1–2
  samples per cell; this is not a readiness bound.

## Verdict

The daemon-side legs of the bar are met at every N: median net CPU at most
0.66 s and median settle at most 0.36 s. The project therefore declined both
targeting variants. Refreshing only the families present in a delta saves at
most half the replay, and only for a single-family delta. Refreshing only the
members a delta covers needs a complete record of each member's rejected
routes. Route-server members usually lack one, so most would fall back to a
full refresh.

## Limitation: the cost lands on members

The daemon side is cheap, but the full replay stays. At 700 members every
changed VRP table still sends about 1,400 ROUTE-REFRESH and asks the members to
re-send about 400,400 NLRI, however small the delta. The request count follows
the member count and the NLRI follow the members' tables; neither was measured
beyond this shape.

[RFC 9324](https://www.rfc-editor.org/rfc/rfc9324.html) describes this pattern
as a serious resource burden on peers. Section 5 requires a speaker performing
ROV to keep either the full Adj-RIB-In or at least the routes dropped by ROV,
so that new RPKI data does not trigger Route Refresh. The measured build does
neither: it recovers routes affected by new RPKI data only through Route
Refresh and replay. The follow-up, measured separately, keeps the routes
rejected because of their validation state and re-checks them locally when the
VRPs change.

## What this does not establish

- **Other shapes.** One table size, one member count and disjoint per-member
  prefixes. A real route server's transit members announce overlapping,
  larger tables.
- **Member cost.** The harness members answer refreshes from memory. The
  receipt counts the requests and NLRI, not what a real router spends to send
  them.
- **Variance.** Two cells per N on one host give medians, not a distribution.
- **ASPA and IRR.** ASPA changes trigger the same refresh pass, and IRR dataset
  swaps trigger a similar one; neither was measured.
- **Later builds.** The result applies to `481e0187d`.
