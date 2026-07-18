# IXP route-server receipt matrix — 2026-07

How do rustbgpd, BIRD, and OpenBGPD compare as IXP route servers on the
operator KPIs that actually page people — reload stall, reload
completion, member-flap propagation, convergence, and memory — when all
three are fed **identical wire inputs through the same harness on the
same host**? The [reload-stall receipt](reload-stall-2026-07.md)
established rustbgpd's own numbers against a pre-committed gate; this
receipt puts the same scenario through BIRD 3.3.1 and OpenBGPD 9.1 and
publishes every cell, the losses as plainly as the wins.

**Commit measured:** rustbgpd cells at `576c6c9b` (jemalloc-default
build plus two fixes this campaign itself surfaced: the route-server
control-communities opt-in — see the
[first anomaly](#anomaly-a-the-matrix-caught-a-fleet-scale-regression)
— and the deferred PeerUp initial-dump fix — see the
[post-publication fix note](#post-publication-fix-the-re-announce-plateau)).
The BIRD and OpenBGPD cells are from the original campaign at
`40fd0a0c`; the two commits are code-identical for those cells (the
harness, driver, and their configurations are unchanged between them),
so they were not rerun.

## Headline

700 route-server clients × 400,400 IPv4 routes, live churn throughout,
full import+export policy swap, receiver-side timestamps, two
independent campaign runs (A and B), 4 reloads each:

| Reload KPI (range over 8 reloads, both runs) | rustbgpd | BIRD 3.3.1 | OpenBGPD 9.1 |
|---|---|---|---|
| UPDATE stall, p50 across 700 observers | **0.43–0.84 s** | 1.61–2.29 s | **0.25–0.29 s** |
| UPDATE stall, worst single observer | 1.85 s | 7.73 s | **0.36 s** |
| New-policy completion, p50 | **1.5–2.2 s** | 77–86 s | 249–253 s |
| New-policy completion, worst observer | **2.9 s** | 93.8 s | 252.9 s |
| Session flaps / decode errors, all reloads | 0 / 0 | 0 / 0 | 0 / 0 |

**Verdict: three different trade-offs, honestly stated.** OpenBGPD has
the smallest stall at every scale rung — churn keeps flowing while its
RDE recomputes — but takes ~4 minutes to deliver the new policy (and
~6.5 minutes to converge at startup). BIRD completes in ~80 s but pays
the largest stalls (p50 1.6–2.3 s, single observers up to 7.7 s). rustbgpd
is the only daemon in the matrix that holds both a **sub-second median
stall and single-digit-seconds completion**: every one of the 700 members
verifiably holds the full new-policy table within 2.9 s of the reload,
worst case, in both runs. On the flapstorm leg rustbgpd now propagates
both member-down and member-up fastest (re-announce p50 0.46–0.49 s vs
BIRD's 2.8–4.2 s — a loss in the first publication of this receipt,
fixed and rerun; see the
[post-publication fix note](#post-publication-fix-the-re-announce-plateau)).
BIRD wins settled memory outright — published below.

## Method and fairness protocol

- **One harness, one instrument.** All three daemons face the same
  `bench/scale/reloadstall` harness: 700 real BGP stub sessions over
  loopback TCP, real OPEN/KEEPALIVE/UPDATE wire exchange, per-member
  572-prefix slices of a 400,400 × /24 base table, 8 members flapping
  churn blocks every 125 ms (≈64 UPDATE events/s aggregate). Every stub
  decodes every received UPDATE and timestamps arrivals; completion
  requires every expected *unique* base prefix carrying the reload's
  policy-generation community (per-observer bitmap, own slice
  excluded) — a duplicate never advances the window.
- **Semantically identical policies.** The two policy generations swap
  an export community (`65500:1000` ⇄ `65500:2000`, forcing full
  re-advertisement) and an import reject-term on an out-of-table prefix
  (content-real, output-neutral), expressed natively per daemon: `.rpol`
  chains for rustbgpd, `filter` functions for BIRD, `deny`/`match` rules
  for OpenBGPD. The delivered generation is verified per reload by
  sampling communities off decoded UPDATEs.
- **Each incumbent at its documented strongest configuration** (see
  [Configuration disclosure](#configuration-disclosure)), reloaded by
  its own operator-documented mechanism: SIGHUP (rustbgpd),
  `birdc configure` (BIRD), `bgpctl reload` (OpenBGPD).
- **Pre-committed shapes, resumable cells, published failures.** The
  scale ladder (20×20k, 200×115k) ran first and gated the full shape;
  cells abort past 100 GiB daemon-tree RSS; a failed cell is preserved
  and published with its mechanism, not silently rerun (see the two
  anomalies below). One cell at a time behind a 1-min loadavg < 2.0
  gate with a 5-minute cool-down; the box was otherwise idle.
- **Two independent campaign runs** (fresh daemon starts, same order)
  so run-to-run spread is visible in every table.

## Environment

| Field | Value |
|---|---|
| Hardware | AMD Ryzen Threadripper 7970X (32 cores / 64 threads), 125 GiB RAM |
| Kernel | Linux 6.17.0-35-generic |
| rustbgpd | `--release` at `576c6c9b`, bare binary, stock config (8 tokio workers — the capped default), jemalloc (the shipped default) |
| BIRD | 3.3.1, built from `tests/interop/Dockerfile.bird3`, `docker run --network=host` |
| OpenBGPD | 9.1, image `openbgpd/openbgpd:9.1`, `docker run --network=host` |
| RSS instrument | `bench/scale/matrix/rss-sampler.sh`: full process tree, 5 s cadence (OpenBGPD is 7 processes; the others 1) |

Both containers run with host networking, so all three daemons serve
the same loopback path; the container boundary adds no NAT or veth hop.

## S1 — cold convergence

Startup phase of every leg: time for all 700 sessions to reach
Established, then for every observer to hold the full base table
(399,828 non-self prefixes; a ~280 M-NLRI aggregate fan-out). Four
observations per daemon (S2 + S3 legs × runs A/B):

| S1 metric | rustbgpd | BIRD 3.3.1 | OpenBGPD 9.1 |
|---|---|---|---|
| 700 sessions Established | **0.6 s** (all 4 legs) | 17.3–19.7 s | 124.4–141.4 s |
| Full base-table delivery to all observers | **4.9–5.1 s** | 59.0–62.1 s | 396.1–417.3 s |

## S2 — reload stall and completion

**UPDATE stall** = the largest gap between consecutive UPDATE arrivals
at an observer in its window [reload trigger, own full-table
completion], including the leading trigger→first-UPDATE gap.
Distribution is across the 700 observers; each row gives the range over
that run's 4 reloads, so drift across consecutive reloads is visible.
The control row is the expected worst per-observer gap from churn alone
(30 s no-reload window).

| Daemon | Run | stall p50 | stall p95 | worst observer | completion p50 | completion max |
|---|---|---|---|---|---|---|
| rustbgpd | A | 0.51–0.84 s | 0.88–1.62 s | 1.85 s | 1.75–2.23 s | 2.86 s |
| rustbgpd | B | 0.43–0.68 s | 0.70–1.01 s | 1.26 s | 1.52–1.69 s | 2.71 s |
| BIRD 3.3.1 | A | 1.61–2.29 s | 3.57–5.23 s | 7.31 s | 79.1–86.1 s | 93.8 s |
| BIRD 3.3.1 | B | 1.76–1.88 s | 3.34–4.75 s | 7.73 s | 77.4–83.7 s | 92.8 s |
| OpenBGPD 9.1 | A | 0.25–0.29 s | 0.30–0.33 s | 0.36 s | 248.8–251.8 s | 251.8 s |
| OpenBGPD 9.1 | B | 0.25–0.28 s | 0.28–0.32 s | 0.35 s | 251.2–252.9 s | 252.9 s |
| *control (churn only), p50* | A / B | 19 / 19 ms | 40 / 45 ms | 13 / 15 ms | — | — |

Reading the table:

- **rustbgpd**: stall p50 drifts upward across the 4 consecutive
  reloads within a session (0.43→0.68 s in run B; run A steps
  0.51→0.75→0.84→0.82 s) and the p95 tail widens with it — published
  as observed; the per-reload progression is in the raw CSV lines.
  Completion holds at 1.5–2.2 s p50 / ≤2.9 s worst across all 8
  reloads.
- **BIRD**: completion p50 ~80 s means the median member waits over a
  minute for its new-policy table, with multi-second delivery gaps
  (single observers up to 7.7 s between UPDATEs) while filters
  re-evaluate.
- **OpenBGPD**: the stall winner — churn delivery barely hiccups
  (p50 ~0.26 s, worst 0.36 s, and its churn-only baseline is also the
  tightest at 13–15 ms) — but the new policy lands all-at-once ~250 s
  after `bgpctl reload`, for every observer (p50 ≈ max: the RDE
  recomputes the full table, then floods the result). An operator
  changing an IXP filter waits ~4 minutes for it to take effect on the
  wire.

## S3 — flapstorm (member-down / member-up propagation)

50 members hard-close simultaneously (TCP RST-style socket abort), the
650 survivors must observe all 28,600 withdrawn prefixes; after 10 s
the 50 reconnect and re-announce, and the survivors must re-hold all
28,600. Three rounds per run; ranges are over rounds. The re-announce
clock starts only after all 50 sessions have re-reached Established, so
it measures pure re-delivery fan-out (28,600 prefixes × 650 observers
≈ 18.6 M NLRI), not reconnect pacing.

| Daemon | Run | withdraw p50 | withdraw max | re-announce p50 | re-announce max |
|---|---|---|---|---|---|
| rustbgpd | A | **0.38–0.48 s** | 0.49 s | **0.46–0.49 s** | 0.53 s |
| rustbgpd | B | **0.28–0.36 s** | 0.39 s | **0.48–0.49 s** | 0.52 s |
| BIRD 3.3.1 | A | 0.45–0.56 s | 0.72 s | 3.28–3.84 s | 4.47 s |
| BIRD 3.3.1 | B | 0.52–0.61 s | 0.70 s | 2.84–4.22 s | 4.68 s |
| OpenBGPD 9.1 | A | 12.18–12.43 s | 12.43 s | 21.20–21.61 s | 21.63 s |
| OpenBGPD 9.1 | B | 10.84–10.87 s | 10.87 s | 21.30–21.67 s | 21.69 s |

- **Withdraw**: rustbgpd propagates 50 simultaneous member failures to
  all survivors fastest (p50 0.28–0.48 s vs BIRD's 0.45–0.61 s).
  OpenBGPD takes 11–12 s — a member's routes stay advertised to the
  fleet for that long after its session drops.
- **Re-announce**: rustbgpd re-delivers the 50 returning members'
  routes to all 650 survivors in under half a second (p50 0.46–0.49 s,
  worst observer 0.53 s, every round of both runs), vs BIRD's
  2.8–4.2 s and OpenBGPD's 21–22 s. The first re-announced prefix
  reaches survivors at p50 0.20–0.23 s after the last flapped session
  re-establishes (the harness's `first_reann_s` instrument, added for
  this refresh), so roughly half the completion window is
  delivery-start latency and half is fan-out. This cell was a loss in
  the first publication of this receipt — see the note below.
- No session flaps among survivors and zero decode errors in any round,
  for any daemon.

### Post-publication fix: the re-announce plateau

As first published, the re-announce column was a plain rustbgpd loss:
a flat 9.5–9.8 s p50 in every round of both runs, ~2.5× slower than
BIRD. The receipt's own tables exposed the shape of the problem — the
distribution was implausibly tight (p50 ≈ max within ~0.2 s) and
insensitive to round and run, meaning all 650 observers were waiting on
one shared completion event, not accumulating delivery jitter.

The mechanism, proven before fixing: a reconnecting peer's `PeerUp`
registration performed its initial full-table Adj-RIB-Out dump inline
on the RIB actor loop, so the 50 returning members' dumps serialized
**ahead of** the survivor-facing re-announce fan-out already queued
behind the burst — head-of-line blocking, not a timer. The evidence:
the plateau scaled with flap count × table size, survivors' first
re-announce arrivals clustered after the final dump finished, and the
daemon log timeline showed the dump sequence occupying the actor for
the width of the plateau.

The fix (`576c6c9b`, #978, same day): when the actor has queued work
and the table is at or above 10k routes, a registration (and its dump)
defers behind the queued imports, completing one per loop iteration
strictly after each queued mutation batch drains; a quiet actor or a
small table still registers inline, and graceful-restart semantics are
untouched. All four rustbgpd cells were rerun at the fixed head:
re-announce p50 went **9.5–9.8 s → 0.46–0.49 s (~20×)**, withdraw and
the S1/S2/RSS cells moved only within run-to-run spread. The pre-fix
raw artifacts remain preserved in the campaign working state alongside
the published cells.

## Memory

Settled = last sample of the leg (post-campaign); peak = max over the
leg. Process-tree RSS from the shared external sampler, so the numbers
are comparable across daemons (rustbgpd figures are the jemalloc-default
build, as shipped).

| Daemon | S2 settled (A / B) | S2 peak (A / B) | S3 settled (A / B) | S3 peak (A / B) |
|---|---|---|---|---|
| rustbgpd | 768 / 763 MiB | 1028 / 906 MiB | 856 / 753 MiB | 856 / 830 MiB |
| BIRD 3.3.1 | **408 / 416 MiB** | 408 / 416 MiB | **325 / 314 MiB** | 351 / 314 MiB |
| OpenBGPD 9.1 | 769 / 767 MiB | 974 / 975 MiB | 812 / 827 MiB | 975 / 975 MiB |

- **BIRD wins memory outright** — roughly half of either other daemon,
  consistent with its reputation. Its S2 sessions end at their peak
  (RSS never came back down within the sampled window), but the
  absolute number is still the lowest.
- rustbgpd and OpenBGPD settle within a few percent of each other at
  this shape. The highest single sample in the matrix is now a
  transient rustbgpd reload peak (~1.03 GiB, run A S2, one 5 s sample);
  OpenBGPD peaks at ~975 MiB during initial convergence. rustbgpd's S3
  tail reads higher than in the first publication (856/753 vs 734/737
  MiB settled) because the fixed re-announce finishes in ~0.5 s instead
  of ~9.8 s — the leg now ends seconds after the last churn burst, so
  the final sample lands mid-oscillation (the S3 tail swings 736–877
  MiB at 5 s cadence) rather than after a long quiet drain. The
  jemalloc default matters: the same rustbgpd scenario on a stock-glibc
  build previously ratcheted to ~1.3 GiB across reload cycles.

## Scale-ladder context

The full shape was gated by two smaller rungs (2 reloads each, same
harness and protocol; rung values are p50, single run):

| Metric | Shape | rustbgpd | BIRD 3.3.1 | OpenBGPD 9.1 |
|---|---|---|---|---|
| stall p50 | 20 × 20k | 40 ms | 102–132 ms | **26–32 ms** |
| | 200 × 115k | 109–128 ms | 984 ms (max 2.46 s) | **36–61 ms** |
| | 700 × 400,400 | 0.43–0.84 s | 1.61–2.29 s | **0.25–0.29 s** |
| completion p50 | 20 × 20k | **0.06 s** | 0.17–0.18 s | 0.26 s |
| | 200 × 115k | **0.29–0.31 s** | 7.5–7.7 s | 15.2 s |
| | 700 × 400,400 | **1.5–2.2 s** | 77–86 s | 249–253 s |
| daemon RSS (tree) | 200 × 115k | ~432 MB | **~103 MB** | ~284 MB |

The shape of each curve is the story: OpenBGPD's stall stays near its
churn baseline at every rung while its completion grows to minutes;
BIRD's stall grows fastest (26× from rung 1 to the full shape); both
incumbents' completion scales roughly with table×peers while rustbgpd's
stays in single-digit seconds.

## Configuration disclosure

- **rustbgpd**: bare release binary, stock daemon config (no tuning
  knobs set; worker threads at the capped default of 8), 700
  `route_server_client = true` neighbors, global rpol import/export
  chains, reload = overwrite the live `.rpol` + SIGHUP. The
  route-server control-communities feature is at its (post-fix) opt-in
  default, i.e. off — no member uses action communities in this
  scenario.
- **BIRD 3.3.1**: `threads 8`, `rs client` template with `passive`,
  `multihop`, `next hop keep`, `gateway recursive` plus static
  device-route NEXT_HOP glue; reload = overwrite the generation include
  + `birdc configure`. **Threads trade, disclosed:** a `threads 32`
  sweep at 200 × 115k completes ~15% faster (6.3–6.7 s vs 7.5–7.7 s
  p50) but stalls ~55% worse (1.49–1.60 s vs 0.98 s p50). The campaign
  uses `threads 8` — the better configuration on the headline stall
  KPI (the generous-to-competitor choice) and consistent with upstream
  guidance to cap threads. Raw sweep data is preserved with the
  campaign working state (`bench/scale/matrix/artifacts-bird-threads32/`
  on the bench host; see the artifacts README).
- **OpenBGPD 9.1**: as documented for route servers —
  `transparent-as yes`, `fib-update no`, passive neighbors,
  `holdtime 180`, `nexthop qualify via default` (bgpd validates next
  hops against the kernel FIB even with `fib-update no`; the synthetic
  next hops exist nowhere, so they qualify via the host default route);
  reload = overwrite the generation include + `bgpctl reload`.

Generated configs for every cell are committed alongside the raw logs
(`scenario/` per cell).

## Honesty notes

- **Single host, loopback TCP**: no NIC, no RTT, no loss. Syscall and
  PDU counts match production; receiver timestamps are taken in the
  stub after full wire framing+decode of each UPDATE.
- **Receiver-side measurement only.** Daemon-side clocks (rustbgpd's
  reload log line, BIRD's `Reconfigured`, `bgpctl`'s
  `request processed`) are advisory and never used in the tables. The
  reload trigger timestamp is taken immediately before invoking the
  daemon's reload mechanism, so BIRD's and OpenBGPD's windows include
  their control-socket round-trip (microseconds-to-milliseconds; SIGHUP
  has no round-trip).
- **Reload-semantic asymmetry.** SIGHUP + `.rpol` swap (rustbgpd)
  re-parses only the policy files; `birdc configure` (BIRD) re-parses
  the entire config and re-evaluates filters; `bgpctl reload`
  (OpenBGPD) re-parses the config and soft-reconfigures the RDE. These
  are each daemon's documented route-server reload path — the thing an
  operator actually runs — but they are not the same amount of work.
- **Scheduler contention**: the harness's 700 stub tasks and the
  measured daemon share one host. The load gate and cool-downs bound
  cross-cell interference, and the run-to-run spread (A vs B) is
  published, but sub-100 ms differences should be read loosely — the
  original campaign saw a ~3.5× swing in rustbgpd's churn-only control
  gap between runs (20 vs 71 ms) with identical configs (the refreshed
  cells measured 19 ms in both runs).
- **The stall metric counts any UPDATE delivery** (churn, resync
  announces, withdraws); completion counts only unique base-table
  prefixes carrying the expected generation community. Churn prefixes
  live in a disjoint range and are excluded from completion by prefix.
- **rustbgpd's stall drifts upward across consecutive reloads** within
  a session (run B: 0.43→0.68 s p50 over 4 reloads) — visible in the
  raw per-reload lines and published rather than averaged away.
- **The rustbgpd cells are one fix newer than the incumbents' cells.**
  The re-announce plateau in the first publication was a real loss,
  root-caused and fixed after publishing (see the
  [post-publication fix note](#post-publication-fix-the-re-announce-plateau));
  only the rustbgpd cells were rerun, at `576c6c9b`. The BIRD and
  OpenBGPD numbers stand from `40fd0a0c` — the intervening commits
  touch nothing those cells execute — and the pre-fix rustbgpd numbers
  stay quoted in the note.

### Anomaly (a): the matrix caught a fleet-scale regression

The first attempt at every rustbgpd cell aborted at the campaign's
100 GiB tree-RSS gate (the preserved failure artifact peaks at
~104 GiB): a just-shipped route-server feature — RFC 7947-style
control-communities honored at export — defaulted **on** for
route-server clients, and its per-member export context disqualified
every one of the 700 sessions from update-group sharing, collapsing the
route server into 700 independent full-table Adj-RIB-Out builds. That
is exactly the fleet shape this campaign exists to exercise and the
regression never surfaced in unit or interop tests. The default was
flipped to opt-in the same night (#976), and all rustbgpd cells in this
receipt include that fix (`40fd0a0c`, later refreshed at `576c6c9b`
per the post-publication note). The aborted first attempts
are preserved as `rustbgpd-fail-rscontrol-oom/` siblings in the
campaign working state. This is the matrix doing its job: a
pre-release, fleet-scale regression caught by the receipt harness
before any operator saw it.

### Anomaly (b): one OpenBGPD run-to-run variance event

OpenBGPD's first run-B S2 attempt established all 700 sessions (in
111.5 s, in line with its other legs) but then moved **zero prefixes to
any observer for 120 s**, tripping the harness's no-progress watchdog
— the RDE accepted sessions but never began table delivery. A fresh
attempt with a fresh container passed normally and is the run-B cell
published above; the wedged attempt did not recur in any other leg. It
is reported as run-to-run variance with the artifact preserved
(`openbgpd-fail-rde-wedge/` in the campaign working state), not as a
DNF — but at an IXP, a reload that wedges the RDE until restart would
be an incident, so it is part of the record.

## Current-tip revalidation (2026-07-18)

The published rustbgpd cells predate the control-communities feature
from anomaly (a) returning to **default-on** for route-server clients
(it came back behind an emit-time route-granular filter), so the
receipt no longer described the shipped default configuration. All
four rustbgpd cells were rerun at the current tip with that default
active; the BIRD and OpenBGPD cells stand unchanged (code-identical
for what they execute).

The rerun caught a **second fleet-scale regression** before it
shipped in any release: with every route-server client now carrying
control-community context, the shared clean policy-transition path —
the machinery behind the receipt's reload-completion numbers —
excluded all 700 members as a "rare, tiny cohort" and fell back to
serial per-member full-table resyncs. Reload completion measured
p50 **271–292 s** against the published 1.5–2.2 s band (stall,
flapstorm, and memory were unaffected). The exclusion predated this
campaign's shape and had never been visible at unit scale. It was
root-caused the same night (0.22 s vs 28.6 s policy-apply at a 200 ×
115k discriminator shape isolated the knob; the eligibility check
confirmed it in code) and fixed by admitting members whose transition
inventory carries no control-form communities — decided against the
source routes, so stripped or policy-added tags still force the
per-target path. The pre-fix S2 runs are preserved with the campaign
working state as the catch evidence.

Post-fix numbers at the revalidation tip (`f98e1297` for S2; S3 ran
at the immediately preceding docs-only commit, which the flapstorm
path does not execute):

| KPI (range over both runs) | published receipt | revalidation |
|---|---|---|
| S2 reload stall p50 | 0.43–0.84 s | 0.44–0.92 s |
| S2 completion p50 | 1.5–2.2 s | 1.50–2.12 s |
| S3 re-announce p50 | 0.46–0.49 s | 0.48–0.49 s |
| S3 first re-announce p50 | — (introduced post-publication) | 0.21–0.22 s |
| RSS settled / peak | ~0.78 GiB / 1.03 GiB transient | 0.74–0.87 GiB / 0.90 GiB |

The stall band's upper edge widened slightly (0.92 s vs 0.84 s, still
under the 1 s gate; single worst reload of eight). One reload in run A
had a single-peer completion tail of 11.2 s (p95 of that reload:
2.61 s); no other reload exceeded 2.8 s. Sessions 700/700 and zero
parse errors in every cell. Raw revalidation artifacts:
[`artifacts/ixp-matrix-2026-07/revalidation-2026-07/`](artifacts/ixp-matrix-2026-07/revalidation-2026-07/).

## Raw artifacts

Committed under
[`artifacts/ixp-matrix-2026-07/`](artifacts/ixp-matrix-2026-07/README.md):
per cell, the harness output (`reloadstall.log` with `reloadstall_csv` /
`flapstorm_csv` machine lines), the external RSS samples (`rss.csv`),
the pass status, the generated daemon configs (`scenario/`), and the
daemon's own log. The failure artifacts and the BIRD threads sweep
remain in the campaign working state (see the artifacts README).

## Reproduction

Images:

```text
docker build -t bird:3.3.1 -f tests/interop/Dockerfile.bird3 tests/interop
docker pull openbgpd/openbgpd:9.1
cd bench/scale/reloadstall && cargo build --release   # the harness
cargo build --release                                  # rustbgpd
```

One campaign leg per scenario, one cell at a time (the driver is
resumable per cell; delete a cell's `status` file to redo it, and point
`ARTIFACTS_DIR` at a distinct directory per leg):

```text
# S2 (+S1: convergence is the startup phase of every leg)
N_PEERS=700 TOTAL_PREFIXES=400400 RELOADS=4 \
  ARTIFACTS_DIR=bench/scale/matrix/artifacts-runA-s2 \
  bash bench/scale/matrix/run-matrix.sh            # or: ... run-matrix.sh bird

# S3 (flapstorm replaces the reload loop)
N_PEERS=700 TOTAL_PREFIXES=400400 FLAPSTORM=50 \
  ARTIFACTS_DIR=bench/scale/matrix/artifacts-runA-s3 \
  bash bench/scale/matrix/run-matrix.sh
```

`run-matrix.sh` regenerates every daemon's scenario from scratch per
cell (`gen-scenario.py`, `gen-bird-scenario.py`, `gen-obgpd-scenario.py`),
starts the daemon (bare binary for rustbgpd; `--network=host`
containers for BIRD/OpenBGPD), attaches the process-tree RSS sampler,
runs the harness with the daemon's native reload command, enforces the
loadavg gate, the 5-minute cool-down, and the 100 GiB abort gate, and
writes each cell's artifacts and pass/fail status. Harness internals —
stub addressing, collision-resolution details, the unique-prefix
completion bitmap, churn generation, and the flapstorm state machine —
are documented in `bench/scale/reloadstall/` and in the
[reload-stall receipt](reload-stall-2026-07.md#reproduction).
