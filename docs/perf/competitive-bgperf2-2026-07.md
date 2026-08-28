# Cross-stack bgperf2 receipt — rustbgpd vs BIRD, GoBGP, and FRR — 2026-07

This receipt preserves the raw output of one historical four-daemon bgperf2
campaign across five fleet shapes. It no longer supports a cross-daemon
performance ranking: a 2026-08-28 audit found execution-order and build
asymmetries that the original interpretation did not disclose. The measured
rows remain useful as historical observations, but derived wins, losses,
ratios, slopes, and ordering claims are retracted.

Rustbgpd's separately retained no-cache measurements and later rustbgpd-only
release spot checks remain valid for tracking that daemon against itself.

**Historical July harness output only; no current cross-daemon ranking is supported.**

## Provenance

> **Integrity correction — 2026-08-28:** the campaign always ran targets in
> the fixed order rustbgpd → BIRD → GoBGP → FRR. One-second resource samplers
> started for an earlier cell continued polling while later cells ran, adding
> cumulative host work. That direction favors the earlier rustbgpd cells, but
> the magnitude was not measured, so no correction factor is assigned. The
> sampler data is not subtracted from target-container memory. Rustbgpd is the
> only target with a retained fresh no-cache image-build receipt; competitor
> images were pre-existing or not pinned to reproducible image digests and
> source revisions. FRR was additionally built with gcov instrumentation.
> These asymmetries invalidate cross-daemon rankings while leaving the raw
> historical rows and rustbgpd-only repeatability checks intact.

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

**Units and memory surface:** bgperf2 prints memory labelled "MB" but computes
it 1024-based. Its `max mem (GB)` column times 1024 is the figure this receipt
calls **MiB**. The source is Docker's raw container cgroup
`memory_stats.usage` counter, so the tables report its peak over the run. This
is neither process-tree RSS nor Docker working set; depending on the cgroup it
may include anonymous memory, file/page-cache memory, kernel memory, and socket
memory. These pinned historical values are therefore labelled **peak raw
container cgroup usage** throughout.
"Convergence" is the harness `elapsed` column: monitor start to all expected
prefixes received, which therefore includes the wait for the first prefix.
"Total" additionally includes session establishment and harness setup.

## Result

### 10 peers × 1,000 prefixes — 10,000 routes

| Daemon | Convergence | Total (s) | Max CPU | Peak raw cgroup (MiB) |
|---|---:|---:|---:|---:|
| rustbgpd | 2 s | 8.23 | 7% | 37.9 |
| BIRD 2.18 | 2 s | 9.20 | 2% | 8.2 |
| GoBGP 4.3.0 | 3 s | 10.32 | 126% | 38.9 |
| FRR 10.7.0-dev | 3 s | 10.27 | 4% | 27.6 |

Six runs each. rustbgpd total: 8.19 / 8.20 / 8.22 / 8.23 / 8.24 / 8.26.
rustbgpd raw cgroup usage: 36.9 / 36.9 / 37.9 / 37.9 / 38.9 / 42.0.
BIRD raw cgroup usage: 8.2 five times and 9.2 once. GoBGP raw cgroup usage:
36.9 / 37.9 / 38.9 / 38.9 / 39.9 / 39.9. FRR raw cgroup usage: 26.6 / 27.6 /
27.6 / 27.6 / 27.6 / 28.7.

### 2 peers × 10,000 prefixes — 20,000 routes

| Daemon | Convergence | Total (s) | Max CPU | Peak raw cgroup (MiB) |
|---|---:|---:|---:|---:|
| rustbgpd | 2 s | 8.26 | 7% | 48.1 |
| BIRD 2.18 | 2 s | 9.24 | 1% | 9.2 |
| GoBGP 4.3.0 | 3 s | 10.34 | 88% | 44.0 |
| FRR 10.7.0-dev | 3 s | 9.31 | 5% | 36.9 |

rustbgpd raw cgroup usage: 47.1 / 48.1 / 48.1. BIRD raw cgroup usage: 8.2 /
9.2 / 10.2. GoBGP raw cgroup usage: 44.0 / 44.0 / 45.1. FRR raw cgroup
usage: 36.9 / 36.9 / 36.9.

### 2 peers × 100,000 prefixes — 200,000 routes

| Daemon | Convergence | Total (s) | Max CPU | Peak raw cgroup (MiB) |
|---|---:|---:|---:|---:|
| rustbgpd | 3 s | 12.32 | 41% | 212.0 |
| BIRD 2.18 | 3 s | 13.22 | 6% | 27.6 |
| GoBGP 4.3.0 | 6 s | 16.49 | 565% | 202.8 |
| FRR 10.7.0-dev | 4 s | 13.39 | 94% | 228.4 |

rustbgpd raw cgroup usage: 205.8 / 212.0 / 214.0. BIRD raw cgroup usage: 26.6 /
27.6 / 28.7. GoBGP raw cgroup usage: 200.7 / 202.8 / 202.8. FRR raw cgroup
usage: 226.3 / 228.4 / 229.4.

### 30 peers × 1,000 prefixes — 30,000 routes (new)

| Daemon | Convergence | Total (s) | Max CPU | Peak raw cgroup (MiB) |
|---|---:|---:|---:|---:|
| rustbgpd | 3 s | 9.83 | 22% | 108.5 |
| BIRD 2.18 | 3 s | 10.87 | 14% | 11.3 |
| GoBGP 4.3.0 | 4 s | 11.84 | 897% | 68.6 |
| FRR 10.7.0-dev | 4 s | 10.85 | 11% | 51.2 |

**rustbgpd raw cgroup usage: 86.0 / 108.5 / 131.1** — see the spread section.
BIRD raw cgroup usage: 11.3 / 11.3 / 14.3. GoBGP raw cgroup usage: 67.6 / 68.6 /
69.6. FRR raw cgroup usage: 51.2 / 51.2 / 52.2.

### 100 peers × 1,000 prefixes — 100,000 routes (new)

| Daemon | Convergence | Total (s) | Max CPU | Peak raw cgroup (MiB) |
|---|---:|---:|---:|---:|
| rustbgpd | 3 s | 11.79 | 122% | 212.0 |
| BIRD 2.18 | 5 s | 15.22 | 101% | 32.8 |
| GoBGP 4.3.0 | 20 s | 28.50 | 1281% | 193.5 |
| FRR 10.7.0-dev | 7 s | 16.01 | 68% | 134.1 |

**rustbgpd raw cgroup usage: 180.2 / 212.0 / 230.4.** BIRD raw cgroup usage:
32.8 / 32.8 / 33.8. GoBGP raw cgroup usage: 183.3 / 193.5 / 198.7. FRR raw
cgroup usage: 134.1 / 134.1 / 135.2.

## Cross-daemon interpretation retracted

The elapsed, total-time, CPU, and raw-cgroup columns above are retained exactly
as recorded. They must not be turned into daemon rankings or cross-daemon
ratios because the targets did not receive an order-neutral, build-equivalent
measurement envelope. A future comparison needs counterbalanced target order,
cell-scoped samplers that are stopped and reaped before the next target, and
reproducibly pinned non-instrumented builds for every daemon.

### Rustbgpd raw-cgroup spread

**Do not read rustbgpd's memory numbers as single values.** Its retained runs
have substantial within-target spread:

| Shape | rustbgpd runs (MiB) | Spread as % of median |
|---|---|---:|
| 30p × 1k | 86.0 / 108.5 / 131.1 | **42%** (*computed*) |
| 100p × 1k | 180.2 / 212.0 / 230.4 | **24%** (*computed*) |

A reader who reproduces 30p × 1k and measures 131 MiB has not found a
regression and has not caught this receipt understating the number — that value
is inside the range we measured. Quote rustbgpd's memory at these shapes as a
range, not a point.

We have not root-caused the spread. It is a finding this receipt publishes, not
one it explains.

## Historical structural hypothesis: memory tracks peers, not routes

> **2026-07-26 controlled follow-up:** this heading was too strong. The two
> cells below changed both dimensions and had 24% raw-cgroup-usage spread at
> 100 peers.
> A counterbalanced 2 × 2 release-daemon matrix now holds BASE routes fixed
> while varying peers, then holds peers fixed while varying BASE routes. The
> last 8 stubs continuously flap distinct 16-prefix blocks after convergence.
> Under that workload it measures 118.200/142.844 KiB per peer and
> 825.515/850.751 B per BASE route. Both dimensions are material, so the
> former mixed-shape slope is not an isolated per-peer cost or sizing
> coefficient.
> The follow-up and immutable artifacts are in
> [`per-peer-rss-attribution-2026-07.md`](per-peer-rss-attribution-2026-07.md).
> The numeric cross-stack rows below are retained unchanged.

Two shapes in this campaign carry very different route counts and produce
identical memory:

| Shape | Routes | rustbgpd raw cgroup usage (MiB) |
|---|---:|---:|
| 100p × 1k | 100,000 | 212.0 |
| 2p × 100k | 200,000 | 212.0 |

**Half the routes, the same campaign median.** This observation motivated the
controlled follow-up; it does not by itself establish which dimension
dominates.

The former cross-daemon marginal-cost table is removed. Its slopes mixed a
tenfold route-count change with the peer-count change and also inherited the
campaign-order confound. The controlled rustbgpd-only follow-up above is the
source for peer and route attribution.

**Any projection past 100 peers is *extrapolated* and assumes a linearity this
campaign did not demonstrate.** Two points do not establish a line, and the 42%
spread at the midpoint says the curve itself needs measuring before anyone
sizes a 1,000-peer deployment from it. The separately measured 1,000-peer
receipts ([`scale-receipt-2026-07.md`](scale-receipt-2026-07.md),
[`route-server-1000-2026-07.md`](route-server-1000-2026-07.md)) are the
evidence at that scale; this table is not.

## Establishment versus flood at 100 peers

Splitting convergence into "time to the monitor's first prefix" and "time from
first prefix to all 100,000" preserves additional raw timing observations.
They share the same campaign-order limitation and do not establish a ranking:

| Daemon | First prefix | All 100,000 | Shape of the curve |
|---|---:|---:|---|
| **rustbgpd** | 1 s | **2 s** | One step: 24,656–29,536 prefixes at second 1, all 100,000 at second 2 in every run. |
| BIRD | 1 s | 4 s | Steady ramp: ~29k, ~53k, ~85k, 100,000 across seconds 1–4. |
| GoBGP | 1 s | 18 s | Long linear climb of roughly 4–5k prefixes per second for seventeen seconds. |
| FRR | 5–6 s | 6 s | Flat at zero, then everything at once. |

FRR is the one place the three runs differ: its
monitor count stays at zero through second 4 in all three runs, then in one run
35,809 prefixes appear at second 5 before all 100,000 at second 6, and in the
other two nothing appears until second 6, when the whole table lands inside a
single sample.

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
The image was also gcov-instrumented. Its CPU and timing rows are retained as
historical harness output, not as a release-build comparison.

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
The target order was fixed as rustbgpd, BIRD, GoBGP, then FRR. One-second
sampler threads from earlier cells were not stopped before later cells, so the
host work accumulated across that sequence. This was discovered after
publication; its effect was not measured, and no numeric adjustment is made.

The measured tree was a git-archive export of the commit, built and run outside
the working repository, so a concurrently active branch could not perturb the
measurement.

## Limitations

- One host, one harness, one campaign window. Absolute figures are
  host-specific, and the fixed target order plus accumulating sampler work
  means this campaign does not support a cross-daemon ordering.
- Only the rustbgpd image has a retained fresh no-cache build receipt.
  Competitor provenance is insufficient for a current reproducible ranking,
  and FRR was gcov-instrumented.
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

## v0.61.0 exact-tag refresh (2026-07-27)

The three phase-A shapes were re-measured on the same host through the
same harness at `d1877d4b` — the `v0.61.0` tag plus five docs-only
commits, verified code-identical to the tag — closing the "pinned
historical candidate" gap above for these shapes. The target now
reports `rustbgpd 0.61.0` in every raw row. Three runs per cell, all
clean; the image was rebuilt `nocache` (digest `sha256:b0e77db8ebf7…`,
zero `Using cache` lines in the retained transcript); event-history
was **on** — the harness default, with `RUSTBGPD_EVENT_HISTORY_OFF`
explicitly unset and recorded. Campaign window: 2026-07-27
19:30–19:46 UTC.

Scope differences from the campaign above, disclosed: phase-A shapes
only (10p × 1k, 30p × 1k, and 100p × 1k route-server shapes were not
rerun, and 10p × 1k therefore has 3 runs here, not 6); the target was
built from the repository checkout at the named commit rather than a
git-archive export; OpenBGPD was excluded up front — the harness
defect documented above was verified still present, and an attempted
cell would still hang the batch. Peer versions: BIRD
`2.18+branch.master.0ee9f93bd076` and GoBGP `4.3.0` identical to the
campaign above; FRR `10.7.0-dev` remains an unpinned development
build with a distinct build identifier per cell.

Medians of 3 runs per cell:

| Shape | Daemon | Total (s) | Convergence (s) | Max CPU | Peak raw cgroup (MiB) |
|---|---|---:|---:|---:|---:|
| 10p × 1k | rustbgpd | 8.28 | 2 | 6% | 37.9 |
| | BIRD 2.18 | 9.23 | 2 | 3% | 9.2 |
| | GoBGP 4.3.0 | 10.29 | 3 | 140% | 37.9 |
| | FRR 10.7.0-dev | 10.32 | 3 | 3% | 27.6 |
| 2p × 10k | rustbgpd | 8.21 | 2 | 7% | 48.1 |
| | BIRD 2.18 | 9.22 | 2 | 1% | 9.2 |
| | GoBGP 4.3.0 | 10.35 | 3 | 82% | 45.1 |
| | FRR 10.7.0-dev | 9.28 | 3 | 6% | 36.9 |
| 2p × 100k | rustbgpd | 12.33 | 3 | 41% | 212.0 |
| | BIRD 2.18 | 13.20 | 3 | 6% | 27.6 |
| | GoBGP 4.3.0 | 16.45 | 6 | 580% | 204.8 |
| | FRR 10.7.0-dev | 13.26 | 4 | 92% | 228.4 |

Every rustbgpd median is within 0.05 s of its earlier rustbgpd value, which is
the supported repeatability conclusion. The cross-daemon rows remain subject
to the fixed-order, sampler-lifetime, image-provenance, and FRR-instrumentation
limitations above; this refresh does not establish time, CPU, or memory
rankings.

Raw per-run harness CSVs, full run transcripts, the `nocache` build
transcript, the per-run medians, the campaign timeline with quiet-gate
admissions, and a checksum `MANIFEST` with a `verify.sh` re-checker
are in
[`artifacts/competitive-bgperf2-2026-07/v0610-refresh-2026-07/`](artifacts/competitive-bgperf2-2026-07/v0610-refresh-2026-07/).

## Reproduce and artifacts

> **Archival warning:** reproduction with the historical driver reproduces its
> fixed-order and sampler-lifetime defects. Do not use it to publish a current
> cross-daemon ranking. A replacement campaign must counterbalance order, reap
> every cell's samplers, and pin equivalent non-instrumented builds.

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
