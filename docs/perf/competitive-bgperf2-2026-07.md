# Cross-stack bgperf2 receipt — rustbgpd vs BIRD, GoBGP, and FRR — 2026-07

This receipt answers one bounded question: on one host, through one harness,
how does rustbgpd compare to three incumbent BGP daemons across five fleet
shapes? The short version is that rustbgpd is the fastest of the four on total
time at every shape measured, wins convergence decisively at the route-server
shape, and **is the largest of the four in resident memory at 100 peers ×
1,000 prefixes — the route-server shape rustbgpd is built for.**

Both halves of that are the result. A comparison table that only gets
published when it flatters the author is worth nothing, so the losses below
are stated with the same precision as the wins, and the noisiest figure in the
campaign is rustbgpd's own memory.

Every figure is labelled *measured*, *computed*, or *extrapolated* at the point
of use.

## Provenance

**Measured commit:** `515659b191b7fde91a1a1c9f973e7c8ae3731086`. That was the
candidate tip when this campaign ran. `main` has since moved through routing
and memory changes, so these remain pinned historical results rather than a
current-tip measurement.

**The target reports `rustbgpd 0.60.0` in every raw row, and that is expected.**
The v0.61.0 version bump had not happened when the campaign ran. The binary is
the v0.61.0 candidate; only the version string is behind.

**Image:** built `nocache` from a git-archive export of the measured commit,
digest `sha256:c60bed5e9ec8…`. The retained build transcript contains zero
`Using cache` lines, which is what makes the no-cache claim checkable rather
than asserted.

**Peers:**

| Daemon | Version as reported by the target |
|---|---|
| rustbgpd | `rustbgpd 0.60.0` (the v0.61.0 candidate, pre-bump) |
| BIRD | `2.18+branch.master.0ee9f93bd076` |
| GoBGP | `4.3.0` |
| FRR | `FRRouting 10.7.0-dev` (see the FRR caveat below) |

**Host:** AMD Ryzen Threadripper 7970X (32 cores / 64 threads), 125 GiB RAM,
Linux 6.17, Docker. All four daemons, the BIRD tester fleet, and the GoBGP
monitor ran in containers on this one host. **Same-host caveat:** every daemon
therefore competes for the same cores, memory bandwidth, and Docker bridge as
the load generators. This is a comparison under identical conditions, not an
absolute performance figure for any of the four, and it does not forecast a
different machine.

**Campaign window:** 2026-07-26 00:22–01:57 UTC. The harness `date` column
records the host's local date, 2026-07-25.

**Statistics:** three runs per cell, six for 10p × 1k (it appears in both
phases). Every table below reports the *measured* median, with the per-run
values printed underneath so a reader can see the spread rather than trust the
midpoint.

**Units:** bgperf2 prints memory labelled "MB" but computes it 1024-based. Its
`max mem (GB)` column times 1024 is the figure this receipt calls **MiB**, and
it is the maximum resident set of the *target container* over the run.
"Convergence" is the harness `elapsed` column: monitor start to all expected
prefixes received, which therefore includes the wait for the first prefix.
"Total" additionally includes session establishment and harness setup.

## Result

### 10 peers × 1,000 prefixes — 10,000 routes

| Daemon | Convergence | Total (s) | Max CPU | Max RSS (MiB) |
|---|---:|---:|---:|---:|
| **rustbgpd** | **2 s** | **8.23** | 7% | 37.9 |
| BIRD 2.18 | 2 s | 9.20 | 2% | **8.2** |
| GoBGP 4.3.0 | 3 s | 10.32 | 126% | 38.9 |
| FRR 10.7.0-dev | 3 s | 10.27 | 4% | 27.6 |

Six runs each. rustbgpd total: 8.19 / 8.20 / 8.22 / 8.23 / 8.24 / 8.26.
rustbgpd RSS: 36.9 / 36.9 / 37.9 / 37.9 / 38.9 / 42.0.
BIRD RSS: 8.2 five times and 9.2 once. GoBGP RSS: 36.9 / 37.9 / 38.9 / 38.9 /
39.9 / 39.9. FRR RSS: 26.6 / 27.6 / 27.6 / 27.6 / 27.6 / 28.7.

### 2 peers × 10,000 prefixes — 20,000 routes

| Daemon | Convergence | Total (s) | Max CPU | Max RSS (MiB) |
|---|---:|---:|---:|---:|
| **rustbgpd** | **2 s** | **8.26** | 7% | 48.1 |
| BIRD 2.18 | 2 s | 9.24 | 1% | **9.2** |
| GoBGP 4.3.0 | 3 s | 10.34 | 88% | 44.0 |
| FRR 10.7.0-dev | 3 s | 9.31 | 5% | 36.9 |

rustbgpd RSS: 47.1 / 48.1 / 48.1. BIRD RSS: 8.2 / 9.2 / 10.2. GoBGP RSS:
44.0 / 44.0 / 45.1. FRR RSS: 36.9 / 36.9 / 36.9.

### 2 peers × 100,000 prefixes — 200,000 routes

| Daemon | Convergence | Total (s) | Max CPU | Max RSS (MiB) |
|---|---:|---:|---:|---:|
| **rustbgpd** | **3 s** | **12.32** | 41% | 212.0 |
| BIRD 2.18 | 3 s | 13.22 | 6% | **27.6** |
| GoBGP 4.3.0 | 6 s | 16.49 | 565% | 202.8 |
| FRR 10.7.0-dev | 4 s | 13.39 | 94% | 228.4 |

rustbgpd RSS: 205.8 / 212.0 / 214.0. BIRD RSS: 26.6 / 27.6 / 28.7. GoBGP RSS:
200.7 / 202.8 / 202.8. FRR RSS: 226.3 / 228.4 / 229.4. This is the one shape
where rustbgpd is not last on memory — FRR is 7.7% larger.

### 30 peers × 1,000 prefixes — 30,000 routes (new)

| Daemon | Convergence | Total (s) | Max CPU | Max RSS (MiB) |
|---|---:|---:|---:|---:|
| **rustbgpd** | **3 s** | **9.83** | 22% | 108.5 |
| BIRD 2.18 | 3 s | 10.87 | 14% | **11.3** |
| GoBGP 4.3.0 | 4 s | 11.84 | 897% | 68.6 |
| FRR 10.7.0-dev | 4 s | 10.85 | 11% | 51.2 |

**rustbgpd RSS: 86.0 / 108.5 / 131.1** — see the spread section. BIRD RSS:
11.3 / 11.3 / 14.3. GoBGP RSS: 67.6 / 68.6 / 69.6. FRR RSS: 51.2 / 51.2 / 52.2.

### 100 peers × 1,000 prefixes — 100,000 routes (new)

| Daemon | Convergence | Total (s) | Max CPU | Max RSS (MiB) |
|---|---:|---:|---:|---:|
| **rustbgpd** | **3 s** | **11.79** | 122% | 212.0 |
| BIRD 2.18 | 5 s | 15.22 | 101% | **32.8** |
| GoBGP 4.3.0 | 20 s | 28.50 | 1281% | 193.5 |
| FRR 10.7.0-dev | 7 s | 16.01 | 68% | 134.1 |

**rustbgpd RSS: 180.2 / 212.0 / 230.4.** BIRD RSS: 32.8 / 32.8 / 33.8. GoBGP
RSS: 183.3 / 193.5 / 198.7. FRR RSS: 134.1 / 134.1 / 135.2.

## What rustbgpd wins

**Total time, at all five shapes.** *Computed* margins against the next-fastest
daemon at each shape: 0.97 s at 10p × 1k (vs BIRD), 1.05 s at 2p × 10k (vs
FRR), 0.90 s at 2p × 100k (vs BIRD), 1.02 s at 30p × 1k (vs FRR), and 3.43 s at
100p × 1k (vs BIRD). Four of those five margins are around a second and sit on
a per-cell spread of a few hundredths of a second, so the ordering is stable;
the fifth is not close.

**Convergence at the route-server shape.** At 100 peers rustbgpd converges in a
*measured* 3 s against FRR's 7 s, BIRD's 5 s, and GoBGP's 20 s. That is the
largest separation in the campaign and it is the shape rustbgpd is designed
for. At every other shape rustbgpd ties the leader.

**CPU at the shapes where peer count drives cost.** 22% at 30p × 1k and 122% at
100p × 1k against GoBGP's 897% and 1281%. BIRD is materially cheaper than
rustbgpd at every shape below 100 peers, and at 100 peers the two are close
(101% vs 122%).

## What rustbgpd loses

### Memory at 100 peers × 1,000 prefixes — last of four, at our own target shape

At 100 peers rustbgpd's *measured* 212.0 MiB is the largest of the four
daemons. *Computed* ratios: **1.10× GoBGP's 193.5 MiB, 1.58× FRR's 134.1 MiB,
and 6.46× BIRD's 32.8 MiB.** This is the route-server shape, so it is the loss
that matters most.

### Memory against BIRD, at every shape

*Computed* rustbgpd-to-BIRD RSS ratio:

| Shape | rustbgpd (MiB) | BIRD (MiB) | Ratio |
|---|---:|---:|---:|
| 10p × 1k | 37.9 | 8.2 | 4.62× |
| 2p × 10k | 48.1 | 9.2 | 5.23× |
| 2p × 100k | 212.0 | 27.6 | 7.68× |
| 30p × 1k | 108.5 | 11.3 | **9.60×** |
| 100p × 1k | 212.0 | 32.8 | 6.46× |

The range is **4.6×–9.6×** and the worst cell is 30 peers × 1,000 prefixes.
BIRD's radix-tree RIB with global attribute deduplication is a structurally
leaner design on this data, and nothing in this campaign narrows that.

### rustbgpd's RSS is the noisiest figure in the campaign

**Do not read rustbgpd's memory numbers as single values.** They have the
widest run-to-run spread of anything measured:

| Shape | rustbgpd runs (MiB) | Spread as % of median |
|---|---|---:|
| 30p × 1k | 86.0 / 108.5 / 131.1 | **42%** (*computed*) |
| 100p × 1k | 180.2 / 212.0 / 230.4 | **24%** (*computed*) |

For contrast, at those same two shapes GoBGP spans a *computed* 2.9% and 7.9%
and FRR spans 2.0% and 0.8%. BIRD's relative spread at 30p × 1k is a *computed*
26.5%, but that is ±1.5 MiB in absolute terms against rustbgpd's ±22.6 MiB.

A reader who reproduces 30p × 1k and measures 131 MiB has not found a
regression and has not caught this receipt understating the number — that value
is inside the range we measured. Quote rustbgpd's memory at these shapes as a
range, not a point.

We have not root-caused the spread. It is a finding this receipt publishes, not
one it explains.

## Historical structural hypothesis: memory tracks peers, not routes

> **2026-07-26 controlled follow-up:** this heading was too strong. The two
> cells below changed both dimensions and had 24% RSS spread at 100 peers.
> A counterbalanced 2 × 2 release-daemon matrix now holds BASE routes fixed
> while varying peers, then holds peers fixed while varying BASE routes. The
> last 8 stubs continuously flap distinct 16-prefix blocks after convergence.
> Under that workload it measures 118.200/142.844 KiB per peer and
> 825.515/850.751 B per BASE route. Both dimensions are material, so the
> 1.93 MiB/peer table remains the historical campaign's mixed-shape upper
> bound, not an isolated per-peer cost or sizing coefficient.
> The follow-up and immutable artifacts are in
> [`per-peer-rss-attribution-2026-07.md`](per-peer-rss-attribution-2026-07.md).
> The raw cross-stack tables below are retained unchanged.

Two shapes in this campaign carry very different route counts and produce
identical memory:

| Shape | Routes | rustbgpd RSS (MiB) |
|---|---:|---:|
| 100p × 1k | 100,000 | 212.0 |
| 2p × 100k | 200,000 | 212.0 |

**Half the routes, the same campaign median.** This observation motivated the
controlled follow-up; it does not by itself establish which dimension
dominates.

Across the 10 → 100 peer span the *computed* marginal cost is:

| Daemon | RSS 10p (MiB) | RSS 100p (MiB) | Marginal MiB/peer (*computed*) |
|---|---:|---:|---:|
| rustbgpd | 37.9 | 212.0 | **1.93** |
| GoBGP | 38.9 | 193.5 | 1.72 |
| FRR | 27.6 | 134.1 | 1.18 |
| BIRD | 8.2 | 32.8 | **0.27** |

Those slopes are an **upper bound** for all four daemons, not a clean per-peer
cost: prefix totals grow from 10,000 to 100,000 across the same span, so route
storage is folded into the numerator.

**Any projection past 100 peers is *extrapolated* and assumes a linearity this
campaign did not demonstrate.** Two points do not establish a line, and the 42%
spread at the midpoint says the curve itself needs measuring before anyone
sizes a 1,000-peer deployment from it. The separately measured 1,000-peer
receipts ([`scale-receipt-2026-07.md`](scale-receipt-2026-07.md),
[`route-server-1000-2026-07.md`](route-server-1000-2026-07.md)) are the
evidence at that scale; this table is not.

## Establishment versus flood at 100 peers

Splitting convergence into "time to the monitor's first prefix" and "time from
first prefix to all 100,000" separates session establishment from route
processing. The split was *measured* identically in all three runs for
rustbgpd, BIRD, and GoBGP:

| Daemon | First prefix | All 100,000 | Shape of the curve |
|---|---:|---:|---|
| **rustbgpd** | 1 s | **2 s** | One step: 24,656–29,536 prefixes at second 1, all 100,000 at second 2 in every run. |
| BIRD | 1 s | 4 s | Steady ramp: ~29k, ~53k, ~85k, 100,000 across seconds 1–4. |
| GoBGP | 1 s | 18 s | Long linear climb of roughly 4–5k prefixes per second for seventeen seconds. |
| FRR | 5–6 s | 6 s | Flat at zero, then everything at once. |

FRR is the interesting shape and the one place the three runs differ: its
monitor count stays at zero through second 4 in all three runs, then in one run
35,809 prefixes appear at second 5 before all 100,000 at second 6, and in the
other two nothing appears until second 6, when the whole table lands inside a
single sample. FRR spends its time before the flood, not during it; rustbgpd
does neither.

## Harness defects and anomalies, disclosed

### OpenBGPD could not be collected — harness defect, not a daemon result

**This is a four-way comparison. OpenBGPD is absent because bgperf2 could not
start it, not because it performed badly.** Nothing here should be read as an
OpenBGPD result.

Root cause, verified live on the stuck container: bgperf2's `openbgp.py`
launches `/usr/local/sbin/bgpd`, but the `openbgpd/openbgpd` image ships its
binaries at `/usr/sbin/` and has no `/usr/local/sbin/` at all. The harness
start script therefore fails instantly, and the harness-generated config — which
does contain correct neighbor stanzas — is never loaded. The image's own
entrypoint is meanwhile already running `bgpd` against the image default config,
which has zero neighbors, so it refuses every monitor dial as a non-peer. The
GoBGP monitor stays in Active forever, and `monitor.py`'s `wait_established()`
is an unbounded `while True:` with no timeout, so the batch hangs. The aborted
attempt ran about 11 minutes (the retained log ends mid-`Waiting 674 seconds
for monitor`) before it was killed.

It was not patched mid-campaign because a correct fix is not a one-line path
change: the image entrypoint already holds TCP/179, so a second `bgpd` started
from the harness config could not bind. Producing a number would have required
restructuring the target — suppressing the entrypoint daemon or rewriting the
image's default config in place — and an ad-hoc restructuring done mid-campaign
would have been the least defensible figure in the report. bgperf2 is a
third-party harness and was out of scope to modify. Full detail:
[`openbgpd-defect.txt`](artifacts/competitive-bgperf2-2026-07/openbgpd-defect.txt).

The separately published [IXP receipt
matrix](ixp-matrix-2026-07.md) does carry a head-to-head OpenBGPD 9.1
comparison through a different harness.

### One BIRD outlier, resolved by a third run

BIRD's 100p × 1k total time measured 24.51 s in the first run against 15.17 s
in the second. A third run returned 15.22 s and the published median is 15.22 s.

The outlier is attributable and did not touch BIRD's own performance: the
harness's `monitor` column — time spent waiting for the monitor container to
come up, before BIRD is asked to do anything — read 9 s in that run against 0 s
in the other two, and 24.51 − 15.17 = 9.34 s. BIRD's convergence column read
5 s in all three runs, and its per-second progression is the same ramp in all
three. The first run's total is a harness startup artifact, not a BIRD result.

### FRR's per-neighbor counters are unavailable

bgperf2 raises `TypeError: FRRoutingTarget.get_neighbor_received_routes() got
an unexpected keyword argument 'dckr_override'` on every FRR cell, so FRR's
`neighbors_accepted` stays 0 in the raw rows. This does not affect any
published figure: the ground truth for completion is the independent GoBGP
monitor's received count, which is collected identically for all four targets.

### FRR is an unpinned development build

Every one of the 18 FRR cells reports a **distinct** build identifier under
`FRRouting 10.7.0-dev`. The FRR target is rebuilt per cell from a moving
source; it is not a pinned release, and we did not establish whether those
identifiers correspond to distinct upstream commits. FRR's cell-to-cell
consistency was nonetheless high (2p × 10k total measured 9.31 s in all three
runs), so this is a caveat on reproducibility, not a visible source of scatter.

### The `tester errors` column is not interpreted

The raw CSVs carry a harness `tester errors` column that reads 0 for the GoBGP
and FRR targets, single digits to low tens for rustbgpd, and up to 11,048,168
for BIRD. We did not establish its semantics, no published figure depends on
it, and it is retained unexplained rather than given a meaning it may not have.

## Method and gates

bgperf2 runs the target daemon, N BIRD tester peers each advertising P
prefixes, and an independent GoBGP monitor peer. The monitor's accepted route
count is the completion oracle for every target, so no daemon reports on its
own convergence.

Each phase ran through a driver that enforced, in order: an idle interlock, a
container and network cleanup, then a bounded batch run. The interlock required
no hold lock present, zero `cargo` and zero `rustc` processes, and a one-minute
load average below 1.0 — **confirmed twice, 30 seconds apart**, so a run could
not start in a momentary dip. Every admission decision and the load average at
it are in the retained chain logs. All targets within a run executed back to
back through the same harness invocation, sequentially, never concurrently.

The measured tree was a git-archive export of the commit, built and run outside
the working repository, so a concurrently active branch could not perturb the
measurement.

## Limitations

- One host, one harness, one campaign window. Absolute figures are
  host-specific; the *ordering* between daemons under identical conditions is
  the durable result.
- Every daemon ran with the harness's default configuration for that target. No
  daemon was tuned, including rustbgpd. An operator who tunes any of the four
  will get different numbers.
- All four daemons and both load generators shared one host, so each target
  competes with the fleet that drives it.
- Five shapes, all IPv4 unicast, no policy, no churn, no session flap, no
  restart, no Add-Path. This is cold convergence and steady-state footprint
  only.
- Three runs per cell (six at one shape) is enough to expose a 42% spread but
  not enough to characterize its distribution.
- OpenBGPD is uncollected, so the comparison is four-way.
- No claim is made about behavior beyond 100 peers or beyond 200,000 routes.

## Reproduce and artifacts

With a bgperf2 checkout and Docker on an otherwise idle host:

```console
RUSTBGPD_SOURCE=<path-to-rustbgpd-checkout> \
    .venv/bin/python bgperf2.py batch -c phaseB-run1.yaml
```

The batch configs, the idle interlock, the phase driver, the raw per-run stats
CSVs, the full per-second progression logs, the aborted OpenBGPD attempt, the
quiet-gate chain logs, the `nocache` image build transcript, and checksums are
in the [retained artifact
set](artifacts/competitive-bgperf2-2026-07/README.md), which also records what
was dropped from the 2.3 GB campaign directory and why.
