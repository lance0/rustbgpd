# Join-cohort converged rejoin at K = 200 and 692, October 2026

The campaign's verdict is **INVALID**. Two of the three control processes at
K=200 stopped after their first round on a readiness failure, leaving that
arm with 3 of the 9 rounds it needs. Every other cell is valid, and every
performance bar passed on the valid rounds by a wide margin. With 692 of 700
route-server members rejoining a converged table at once, the slowest joiner
finished in 1.257 s on current main against 80.313 s on the control (medians
of nine rounds, disjoint ranges). At K=200 the figures were 0.573 s against
23.644 s, with the control figure from three rounds only.

Measured on 2026-10-13 between 00:49 and 01:34 UTC on one host. This follows
the [K = 1 and 50 qualification](join-cohort-converged-rejoin-2026-10.md),
which deferred these two points. The
[compact evidence](artifacts/join-cohort-converged-rejoin-k200-k692-2026-10-13/README.md)
keeps every cell's harness log, the quiet-host samples, the readiness-miss
extract and the driver's outputs. The in-repository analyzer recomputes the
table and the INVALID verdict from them.

## Question

The K=50 receipt showed that completing queued same-group joiners from one
shared replay removes the K-fold serialization of initial-table exports. Does
the result hold at K=200 and at the harness maximum of K=692? Do survivors and
readiness stay within their limits when most of the fleet rejoins at once?

## Shape

The shape matches the K=50 receipt except for K:

- 700 identically configured IPv4 route-server members, each with its own
  ASN, and 400,400 disjoint prefixes (572 per member). The last eight members
  churn a dedicated 16-prefix block throughout and never flap, so 692 is the
  largest K.
- **Converged rejoin with GR helper retention.** Each round hard-closes K
  members, waits 10 s, verifies through metrics that their routes are still
  retained, then reconnects them. The Loc-RIB and every survivor's table stay
  unchanged.
- **Observers refreshing.** Two surviving members send an IPv4 ROUTE-REFRESH
  at two checkpoints per round, outside the measured rejoin window.
- K = 200 and K = 692, three rounds per process.

## Arms

| Arm | Source | Daemon sha256 |
|---|---|---|
| Base | main `1d0e4e155d0cf8e42ab007c399067540855c02df` (workspace 0.75.0), the commit immediately before the shared replay (#2999); the K=50 receipt's control | `3c72e77d0287f2856ae3ae81a2a10ef1ef9ea2dc5cec34b4d5112d940c3c77d3` |
| Head | main `9951192c3579869c1fcedcba4d5f3b2922453b0e` (workspace 0.76.0), main when the run was prepared | `a0b0d85eef29332b1c39c175dd39d854351d4d9176286c9fff1fc4b2ede48ea1` |

**The arms differ by 57 commits, not by one change.** Head contains the
shared joiner replay (#2999), the shared replay across queued
ROUTE-REFRESH requests, and #3086. #3086 makes the RIB actor and the peer
manager yield after answering a readiness probe, so `/readyz` keeps its
deadline during a mass graceful-restart entry. Under `crates/` and `src/`
the two trees differ in 176 files. This A/B compares the rejoin path of two
mains; it does not attribute the difference to any single change.

Both daemons were built before the window with the driver's own command,
`cargo build --release --locked -p rustbgpd --bin rustbgpd`, Rust 1.99.0.
They are separate builds, so the base hash differs from the K=50 receipt's
control build of the same commit. One harness binary served both arms:
`reloadstall`, built at head with `--profile scale`, sha256
`62240fd68ee053cefbd2d1755583b620df4a37ebc2a73b2f3459e0ef2b2186fb`.

## Method

- **Driver.** `just bench-converged-rejoin` from a clone of head with one
  local patch,
  [`driver-prebuilt.patch`](artifacts/join-cohort-converged-rejoin-k200-k692-2026-10-13/driver-prebuilt.patch).
  It sets `PREBUILT_DIR`, so the driver checks the binaries' hashes and refs
  and copies them in instead of building inside the window. The cells, bars,
  INVALID rules and analyzer are unchanged. The manifest records the driver
  as `dirty=1`. The driver checked the prebuilt hashes before the first
  cell, and after the last cell the daemons it had used still matched them.
- **Cells.** One fresh daemon per cell and three repetitions. Repetitions 1
  and 3 ran base K=200, head K=200, head K=692, base K=692; repetition 2 ran
  the reverse. That gives twelve cells and nine scheduled rounds per arm and
  K. No cell was rerun.
- **Quiet host.** Before every cell the shared host lock was held, and the
  quiet-host gate (`bench/scale/host-quiet.sh`) kept two accepted samples
  30 s apart. Each sample had load below 2.0, every CPU on the `performance`
  governor, no competing compiler, benchmark or BGP daemon, and no swap
  movement.
- **Placement.** The daemon ran on 27 CPUs (12–32 and 34–39) and the harness
  on CPUs 40–63. The host is an AMD Ryzen Threadripper 7970X (32 cores, 64
  threads) with no swap configured, running Linux 7.0.0-30-generic.
- **Clocks.** These match the K=50 receipt. `rejoin_max` is the slowest
  joiner in a round, timed from its OPEN write to the later of its End-of-RIB
  and its full 399,828-prefix table. `survivor_maxgap` is the longest interval
  during the rejoin window in which some surviving member received no UPDATE.
- **Readiness.** The harness polls `/readyz` once per second through every
  round. It fails the cell on any response that is not 200 within 250 ms.

## Predeclared bars and validity

The bars are the driver's defaults, fixed in
[`campaign.json`](artifacts/join-cohort-converged-rejoin-k200-k692-2026-10-13/campaign.json)
before the first cell; its sha256 is recorded in the manifest.

- **B1 (primary, K=692):** the head median `rejoin_max` is below the base
  median, and the ranges are disjoint (head max < base min).
- **B2 (K=200):** the head median `rejoin_max` is at most the base median
  × 1.10 + 30 ms.
- **B3 (each K):** the head median survivor gap is at most the base median
  × 1.10 + 50 ms, and the head maximum at most the base maximum × 1.10 +
  100 ms.

A cell is valid only if the harness and the daemon exit 0 after an accepted
quiet sample, and if the cell reports exactly three rounds with 700 sessions
up, K flapped peers, zero parse errors, readiness samples taken and finite
timings. Any invalid cell, or fewer than nine rounds for an arm and K, makes
the verdict INVALID whatever the bars say.

## Results

Medians over the valid rounds, with the observed range in brackets.
"Readiness samples" counts `/readyz` polls in those rounds; every one returned
200 within 250 ms. RSS is the daemon's `VmRSS` at the end of each round, not
a peak.

| Arm | K | Valid rounds | `rejoin_max` median [range] | `rejoin_p50` median | Survivor gap median / max | Readiness samples | RSS median |
|---|---:|---:|---:|---:|---:|---:|---:|
| Base | 200 | **3 of 9** | 23.644 s [23.524–23.949] | 12.017 s | 131.2 / 139.2 ms | 114 | 422 MiB |
| Head | 200 | 9 of 9 | 0.573 s [0.529–0.609] | 0.345 s | 123.1 / 132.1 ms | 126 | 437 MiB |
| Base | 692 | 9 of 9 | 80.313 s [79.823–80.886] | 39.745 s | 135.6 / 150.9 ms | 901 | 404 MiB |
| Head | 692 | 9 of 9 | 1.257 s [1.185–1.352] | 0.757 s | 121.7 / 130.1 ms | 181 | 421 MiB |

The driver's bar results are as follows:

- **B1 passed.** At K=692 the head's slowest joiner finished in 1.257 s
  against 80.313 s, and the worst head round (1.352 s) beat the best base
  round (79.823 s).
- **B2 passed.** At K=200 the head median of 0.573 s is under the 26.038 s
  limit. That limit comes from the three valid base rounds only.
- **B3 passed** at both K. The K=200 limits likewise come from the three
  valid base rounds.

**Verdict: INVALID (3 validity problems)**, exactly as the driver printed it
in [`verdict.txt`](artifacts/join-cohort-converged-rejoin-k200-k692-2026-10-13/verdict.txt):

- `base-k200-rep1: harness_rc=1 daemon_rc=0`
- `base-k200-rep2: harness_rc=1 daemon_rc=0`
- `base K=200: 3 valid rounds, need 9`

## Why base K=200 is incomplete

Both failed cells ran their first round to the settled checkpoint. The
harness then stopped with
`FAIL: converged rejoin: /readyz HTTP status is not 200: HTTP/1.1 503 Service Unavailable`,
so neither cell wrote a round sample. In each of the two cells the base
daemon logged exactly one `readiness probe deadline exceeded` warning. None
of the other ten cells logged one, and that includes all six head cells.

This is the readiness defect #3086 fixes, and the base predates it. An
earlier run of this campaign on 2026-10-12, with a head that also predated
#3086, located the miss in the burst of 200 sessions entering graceful
restart. In that run three K=200 rounds failed across both arms. The run was
INVALID, and this receipt does not use it. A fresh run of base K=200 would
meet the same defect, so the INVALID stands as recorded. No cell was rerun,
and the readiness rule was not relaxed.

## What the valid data show

- **The serialization is gone at scale.** On the base, the slowest joiner
  grows roughly linearly with K: 23.6 s at K=200 and 80.3 s at K=692, about
  0.12 s per joiner. That matches the staircase the K=50 receipt describes.
  On head, the slowest joiner takes 0.57 s at K=200 and 1.26 s at K=692.
  The K=692 to K=200 ratio of the medians is 3.40 on base and 2.20 on head.
- **Survivors were not starved.** Head survivor gaps (121.7–123.1 ms median,
  132.1 ms worst) are at or below the base's at both K.
- **Readiness held on head.** Head served 307 `/readyz` samples across its
  18 rounds, all 200 within 250 ms, with no deadline miss in the daemon log.

## Limitations

- **INVALID is the result.** The bar outcomes above are reported for
  completeness. The K=200 comparison rests on one base process and three
  correlated rounds.
- **Two mains, not one change.** The arms differ by 57 commits. The
  improvement belongs to the head's rejoin path as a whole.
- **One host, one shape.** These are same-host A/B results for one
  homogeneous IPv4 route-server fleet with 400,400 prefixes and a converged,
  GR-retained table. They are not a scale bound or a cross-daemon comparison.
  They do not cover mixed wire profiles, Add-Path members or other address
  families.
- **Correlated rounds.** Nine rounds come from three processes; they are not
  nine independent samples.
- **Not a forwarding claim.** The clocks end when the harness has decoded the
  full table. Nothing here measures forwarding or FIB state.
- **Not comparable across receipts.** The K=50 receipt measured a different
  head build (`8e1430e49`'s tree). Its absolute timings are not a point on
  the same curve as these.
