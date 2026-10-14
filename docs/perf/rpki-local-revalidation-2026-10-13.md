# RFC 9324 local re-evaluation A/B, October 2026

At a 700-member dual-stack route server, local re-evaluation removed the
ROUTE-REFRESH round trip from a VRP change. With `[rpki] local_revalidation`
enabled, no delta sent a ROUTE-REFRESH or caused any replay. With it
disabled, every delta sent 1,400 ROUTE-REFRESH and members re-sent 400,400
NLRI. The daemon settled sooner and used less CPU per delta. The cost is
memory: with the option enabled, the daemon held 52.5–69.8 MiB more at steady
state (137–183 B per retained route) and peaked 44.6–68.7 MiB higher during
a delta. The extra memory is there because the retention store keeps the
pre-policy input of every accepted unicast route, not only the rejects.

Measured on 2026-10-12 and 2026-10-13 (23:53–00:49 UTC) on one host, against
the head of pull request #3080, which was unmerged when measured. The
predeclared bars all passed. The
[compact evidence](artifacts/rpki-local-revalidation-2026-10-13/README.md)
holds every cell's harness log, RTR cache log, daemon events, CPU, memory
and readiness samples and the fixture provenance. It also has a script that
re-runs the as-run summarizer and checks every number below.

## Question

The [validation-refresh baseline](rpki-validation-refresh-baseline-2026-10.md)
found the daemon's own cost of a VRP change acceptable. The members carried
the cost instead: every delta asked all 700 members to re-send their full
tables. [RFC 9324](https://www.rfc-editor.org/rfc/rfc9324.html) Section 5
asks a speaker doing route origin validation to keep enough state to avoid
that, either the full Adj-RIB-In or at least the routes dropped by validation.

#3080 adds an opt-in `[rpki] local_revalidation` setting, false by default.
For each member whose import policy depends on validation state, the session
keeps a store of that member's routes and re-runs import locally when the
VRPs change. It falls back to ROUTE-REFRESH only when the store is incomplete.

This receipt answers four questions. How many routes does the store hold at
a realistic Invalid share? What does it cost in cgroup memory against the
refresh it replaces? How long does local re-evaluation take per delta? Does
any ROUTE-REFRESH remain on the wire?

## Shape

- 700 route-server members, each with its own ASN, and 400,400 disjoint
  prefixes: 200,200 IPv4 and 200,200 IPv6, 572 per member. Every session
  negotiates IPv4 and IPv6 unicast. Every member's import chain rejects
  RPKI-invalid routes (`GEN_DUALSTACK=1 GEN_RPKI_CACHE=…` in
  `bench/scale/reloadstall/gen-scenario.py`).
- 500,000 VRPs, served over RTR v1 by StayRTR 0.6.4, pinned by digest
  (`rpki/stayrtr@sha256:cdb93c0b661d97179a5525e00caf7d9e693a04da3b9002f7e24bebb194d9a77b`).
- **Invalid share from a real snapshot.** The baseline's table made every
  route Valid. This run assigns real shares instead:
  - Every distinct prefix and origin pair was validated against a pinned
    VRP snapshot. The pairs come from the RouteViews `route-views2` (IPv4)
    and `route-views6` (IPv6) RIBs of 2026-08-08. The VRPs are the RIPE NCC
    RPKI archive's validated `roas.csv.xz` for the five RIR trust anchors on
    the same date, 988,293 unique VRPs. The file hashes match the
    publisher's.
  - 0.248% of IPv4 pairs were Invalid (2,781 of 1,121,489), and 0.538% of
    IPv6 pairs (1,429 of 265,422).
  - Those shares, and the measured NotFound shares, were assigned to the
    synthetic routes per family. 496 IPv4 and 1,078 IPv6 routes are Invalid,
    **1,574 routes or 0.39%** of the table. Each one is covered by an exact
    VRP for a non-member ASN. Another 62,108 IPv4 and 37,278 IPv6 routes are
    NotFound. The rest stay Valid.
  - The pairwise share is the high end: no individual full-feed RouteViews
    peer exceeded 0.197% Invalid for IPv4 or 0.403% for IPv6.
- **Delta.** N maxLength increases on covering VRPs, half per family, for
  N = 10, 100 and 1,000. Of the changed VRPs, 0, 2 and 7 respectively cover
  an Invalid route. No route changes validation state, and the cell is
  invalid unless the RIB reports zero changed routes. Whatever work remains
  is the refresh and replay (arm A) or the local re-evaluation (arm B).
- The harness holds all 700 sessions with no churn (`reloadstall --no-churn`)
  and answers each ROUTE-REFRESH with its full table for that family.

## Arms and binaries

Both arms ran the same binaries, built from #3080's head
`7dc289613dc680d4328806870da2701c59779c0e` (tree `e2b781200f5d`, based on
main `6bb6be4a8`, workspace 0.76.0) with Rust 1.99.0. The arms differ in one
generated configuration line in the `[rpki]` table:

| Arm | Configuration |
|---|---|
| A, refresh | `local_revalidation = false`: the existing ROUTE-REFRESH path |
| B, local re-evaluation | `local_revalidation = true` |

| Binary | Command | sha256 |
|---|---|---|
| `rustbgpd` | `cargo build --release --locked --bin rustbgpd --bin rbgp` | `be6ad48a72c7e9b2b1607c3e5938ae1e18346a586c0e950528748899ab8b78b0` |
| `rbgp` | same command | `c8937a192df76d7316eb0f1e9b28fd52842a4536e4eeee54849f3075c0043680` |
| `reloadstall` | `cargo build --profile scale --locked -p reloadstall`, same commit plus one local patch | `cccbd239eaf4952405c15750aab04e6116064def03eb6ad5af39e606a9431f67` |

The harness patch,
[`reloadstall-import-rejected.patch`](artifacts/rpki-local-revalidation-2026-10-13/reloadstall-import-rejected.patch),
lowers each observer's exact-convergence target by the Invalid routes outside
its own slice. Without it, initial convergence would wait for routes that
reject-invalid import never delivers.

## Method

- **Cells.** One fresh RTR cache, daemon and harness per cell, giving 2 arms
  × 3 delta sizes × 2 repetitions = 12 cells. Arm order alternates within
  each N pair
  ([`schedule.txt`](artifacts/rpki-local-revalidation-2026-10-13/schedule.txt)).
  Before every cell the shared host lock was held, and the quiet-host gate
  (`bench/scale/host-quiet.sh`) kept two accepted samples.
- **Memory fence.** The daemon ran in a systemd user scope with swap
  disabled for it (`memory.swap.max` = 0, checked in every cell).
- **Sequence.** The job waits until both families have converged at every
  member, then records the scope's `memory.current` as **steady**. The poller
  then resets its own `memory.peak` handle and the daemon idles for 10 s.
  The delta file replaces the cache file by atomic rename. At +60 s the job
  reads the **delta peak**, which spans the 10 s idle window through +60 s,
  before it captures member views. The hold ends at 240 s.
- **Clocks.** Every interval starts at the daemon's
  `RTR incremental update received` event. The cache's file-poll lag before
  that point (2.0–2.6 s) is excluded. **Settle** ends at the latest of these
  events:
  - the RIB's re-validation;
  - the session pass log (refresh in A, local re-evaluation in B), and in B
    the per-session `RFC 9324 local import re-evaluation queued` events;
  - the last increase of the summed received-UPDATE counter, polled every
    0.25 s.
- **CPU.** Daemon `utime + stime` at 10 ms resolution, from the last poll
  before the update to the first poll at or after settle. **Net** subtracts
  the idle rate measured over the 10 s before injection.
- **Member burden.** Each harness member counts the ROUTE-REFRESH requests it
  received and the NLRI it re-sent in replays.
- **Retention size.** In B, each session logs the identities it retains and
  how many of them are rejects. There is no store-size gauge. The memory
  attributed to the store is the B−A difference in median steady memory,
  divided by the retained identities.
- **Validity, failing closed.** A cell counts only if:
  - the RTR session is unchanged, with its serial advanced by exactly one
    and the VRP counts unchanged;
  - exactly one incremental update arrived with N announced and N withdrawn,
    and no full table followed;
  - the RIB re-validated in `mode=delta` with zero changed routes;
  - all 700 sessions stayed up with unchanged flap counts and zero parse
    errors;
  - the steady and delta-peak readings exist.
  
  Arm A also needs one refresh pass with 700 eligible and 700 refreshed, a
  ROUTE-REFRESH at every member and family, and a replay quiet for 10 s
  before the hold ended. Arm B needs exactly one local re-evaluation pass.
  All 12 cells passed.
- **Placement.** The daemon ran on CPUs 12–32 and 34–39, the harness on
  40–63 and the RTR cache on 8–11. The host is one AMD Ryzen Threadripper
  7970X with Linux 7.0.0-30-generic.

## Predeclared bars

Fixed before the run; a missing or invalid cell makes the result INVALID.

- **B1:** in every B cell, members receive zero ROUTE-REFRESH and replay zero
  NLRI.
- **B2:** in every B cell, the `revalidated_locally` outcome counter rises by
  700 and `fallback_refresh` by zero.
- **B3:** in every cell of both arms, every `/readyz` sample from the RTR
  update to 50 s after it returns 200 within 250 ms.
- **B4:** for each N, member views are equal between A and B. A view is the
  digest of `rbgp rib advertised` for two fixed members in both families,
  plus every member's received and sent prefix counts.

## Results

Medians of two cells per arm and N; per-cell rows are in
[`cells.json`](artifacts/rpki-local-revalidation-2026-10-13/cells.json).

| N | Arm | ROUTE-REFRESH sent | Replayed NLRI | Settle | Net CPU | Steady memory | Delta peak |
|---:|---|---:|---:|---:|---:|---:|---:|
| 10 | A | 1,400 | 400,400 | 0.38 s | 0.87 s | 456.4 MiB | 512.4 MiB |
| 10 | B | 0 | 0 | 0.16 s | 0.17 s | 508.9 MiB | 572.7 MiB |
| 100 | A | 1,400 | 400,400 | 0.28 s | 0.77 s | 458.1 MiB | 512.9 MiB |
| 100 | B | 0 | 0 | 0.16 s | 0.18 s | 528.0 MiB | 581.5 MiB |
| 1,000 | A | 1,400 | 400,400 | 0.34 s | 0.82 s | 456.0 MiB | 542.5 MiB |
| 1,000 | B | 0 | 0 | 0.22 s | 0.29 s | 513.2 MiB | 587.1 MiB |

The four measurements:

1. **Retention size.** Every B cell retained 400,400 route identities, all
   572 routes of each of the 700 members. 1,574 of them (0.39%) are
   rejects, the Invalid routes the fixture assigns. The store holds every
   accepted route as well as the rejects.
2. **Memory against the refresh baseline.**
   - Steady memory was higher in B by 52.5, 69.8 and 57.1 MiB at N = 10, 100
     and 1,000. That is 137, 183 and 150 B per retained identity.
   - The delta peak was higher by 60.2, 68.7 and 44.6 MiB.
   - The separation holds cell by cell. Every B cell's steady memory
     (506.2–534.2 MiB) is above every A cell's (450.5–461.6 MiB), and every
     B delta peak (564.1–598.2 MiB) is above every A delta peak
     (504.7–545.4 MiB).
   - The rise from steady to delta peak was of the same order in both arms:
     the refresh replay in A did not drive the peak above B's.
3. **Re-evaluation time per delta.**
   - Settle fell from 0.28–0.38 s in A to 0.16–0.22 s in B, and net CPU from
     0.77–0.87 s to 0.17–0.29 s.
   - In B the RIB's re-validation finished 0.15–0.21 s after the RTR update,
     as in A. The local re-evaluation pass finished 4–7 ms after it at
     N = 10 and 100 and 24–27 ms after it at N = 1,000.
   - The 700 per-session re-evaluations queued a total of N retained
     identities, matching the delta size.
4. **ROUTE-REFRESH on the wire.** Zero in every B cell, with zero replayed
   NLRI. Arm A sent 1,400 per delta, one per member and family, and members
   re-sent all 400,400 NLRI, as in the baseline.

**Bars.** B1, B2, B3 and B4 passed. B3 covered 2,400 readiness samples, all
200; the slowest took 178.2 ms, in an A cell. **Verdict: PASS.**

## What the memory buys and costs

The store keeps the pre-policy input of every accepted unicast route, not
only the routes rejected by validation. A VRP removal can turn an accepted
route Invalid, and re-running import needs that route's pre-policy
attributes. That is why the retained count equals the whole table rather
than the 1,574 rejects. The modeled cost is about 135 B per route, one
B-tree entry. At 700 × 572 routes that is 51.5 MiB, close to the measured
137–183 B per identity. The model was not checked with a profiler.

On daemon memory alone, local re-evaluation costs more than the refresh it
replaces. Arm A's refresh replay added no peak above B's, so B pays 44.6–68.7
MiB more at peak and 52.5–69.8 MiB more at steady state. The refresh's own
cost lands on the members and the wire instead: 1,400 requests and 400,400
re-sent NLRI for every delta, whatever its size. The two costs are not in the
same unit. The project accepted local re-evaluation as an opt-in, false by
default, so only operators who enable it pay the memory.

## What this does not establish

- **The store's own footprint.** The per-identity figure is an arm
  difference in cgroup memory. It includes anything else the setting
  changes. Two cells per arm and N cannot separate it from run-to-run
  variation: the within-arm steady spread was up to 12.5 MiB.
- **Real Invalid distribution.** The fixture spreads Invalid routes evenly
  across members by a hash order. Real Invalid routes cluster by origin AS,
  so real members would carry very uneven numbers of rejects.
- **A state change.** Every delta was validity-neutral. No retained reject
  became Valid and no accepted route became Invalid, so the re-evaluation
  measured here re-checked routes without changing an outcome. B4 shows only
  that the outcomes stayed the same.
- **Other shapes.** One table size, one member count and disjoint
  per-member prefixes. Transit members announce overlapping, larger tables,
  and the store grows with every retained route.
- **ASPA and IRR.** StayRTR serves RTR v1 with no ASPA records, so no ASPA
  change was measured. IRR dataset swaps were not measured either.
- **Member cost.** The harness members answer refreshes from memory. The
  receipt counts the refresh requests and NLRI avoided, not what a real
  router saves.
- **The merged code.** The measured commit is #3080's head before it was
  integrated with later main. The absolute settle and CPU figures differ from
  the baseline receipt's, which used another build and an all-Valid table,
  and should not be compared across the two receipts.
