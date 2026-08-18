# Single-commit attribution of the July 2026 memory step — 2026-08

The July 2026 performance batch made the daemon converge faster and hold
more memory at route-server scale. This campaign answers which commit
bought which. Seven sealed A/B campaigns, 25 measured arms, 134 runs at
100 peers × 1,000 routes, each one preregistered before its first build,
narrowed a 509-commit window to a single merge.

The answer is one commit — a deliberate coalescing change that replaced
fragmented per-neighbor RIB actor queries with one ordered aggregate
snapshot per API call. Holding more state per call in order to do less
work per neighbor is exactly the shape of the trade the measurement
found. Its own PR explicitly declined to claim a timing headline; the
campaign measured one anyway, and priced it.

## Headline — the decisive split

Three arms, every one built and measured fresh inside the deciding
campaign, five runs each, round-robin order:

| Arm | cg `memory.peak` median | Settled anon median | Convergence median |
|---|---:|---:|---:|
| merge #1184 `perf: remove revised UPDATE duplicate-tracking allocation` | 205.3 MiB | 152.8 MiB | 13.95 s |
| merge #1188 `perf(policy): share attribution labels through group staging` | 183.9 MiB | 129.0 MiB | 12.96 s |
| merge #1189 `perf(api): coalesce neighbor RIB snapshots` | 290.5 MiB | 230.1 MiB | 11.94 s |

| Step | cg `memory.peak` | Settled anon | Convergence | Verdict against the preregistered rule |
|---|---:|---:|---:|---|
| #1184 → #1188 — 5 commits, only #1188 touches runtime code | **−21.4 MiB** | −23.8 MiB | −0.99 s † | REDUCTION (beyond the −15 MiB flat band) |
| #1188 → #1189 — **exactly one commit** | **+106.6 MiB** | **+101.1 MiB** | **−1.02 s** | **OWNS GROWTH** (≥ +25 MiB) |

Sum check, exact: **−21.4 + 106.6 = +85.2 MiB**, which is the campaign's
own measured #1184 → #1189 endpoint step. The owning step exceeds the
endpoint delta because the step before it is negative.

**#1189 is the sole owner of the memory step, and it is also where the
speed came from.** #1188 is a memory *reducer* that owns none of the
growth. Both merged 2026-07-26 and shipped in **v0.61.0** (tag cut
2026-07-27) — not v0.62.0.

† The #1184 arm's convergence is bimodal here (12.91/12.97 fast mode vs
13.95/13.97/14.01 slow mode, 3 of 5 slow), so its 13.95 s median sits in
the slow mode and inflates that step. Read against stable levels, the
durable reference gain is −1.08 s (12.99 → 11.91 s in the preceding
campaign) and #1189 carries it: #1188's arm is tight at 12.92–12.99 s,
i.e. exactly the #1184 arm's fast mode and within 0.03 s of the
preceding campaign's #1184 level. See
[Convergence, read honestly](#convergence-read-honestly).

## The chain, and what each phase narrowed

Each campaign fixed its arms, bands, ownership thresholds, anomaly
tripwire and sum check in a manifest written **before any build**, then
measured. Every phase's manifest and full result table is in
[`artifacts/memory-attribution-2026-08/`](artifacts/memory-attribution-2026-08/README.md).

| Phase | Design | Window | Result |
|---|---|---:|---|
| 0 — endpoint A/B | 2 arms + a bridge series, 5 interleaved pairs each, 20 runs | 509 commits | Growth is **daemon-side**: paired (B−A)/A on cg peak +37.4%, 95% CI [+26.3%, +48.6%] — lower bound 2.6× the preregistered +10% threshold. Endpoint delta **+88.5 MiB** (195.1 → 283.6 MiB), convergence 14.0 → 11.9 s |
| 1 — tip tranche | 2 arms, 7 interleaved pairs, 14 runs | the 12-merge structural-reclaim tranche at the tip | **INCONCLUSIVE** by preregistration. Arm medians within ~1 MiB on every settled surface; the ±5% band was unreachable at this shape's variance |
| 2 — coarse bisect | 5 arms × 5 runs, round robin, 25 runs | 509 → **271** | +75.6 MiB already present at the authz-cut commit; everything after v0.63.0 flat |
| 3 — refinement bisect | 4 arms × 5 runs, 20 runs | 271 → **86** | +90.3 MiB and the whole −2.10 s convergence move land in the first quarter-point; the other three intervals are flat, minor, or negative |
| 4 — quartile split | 4 arms × 5 runs, 20 runs | 86 → **21** | +84.4 MiB in one 21-commit quarter, which also carries −1.07 s. The convergence gain splits almost exactly in half across the window |
| 5 — micro-bisect | 4 arms × 5 runs, candidate-targeted arm placement, 20 runs | 21 → **6** | +90.1 MiB and the entire −1.08 s in one 6-commit step. #1184 measured alone and exonerated |
| 6 — single-commit split | 3 arms × 5 runs, **every arm re-measured in-campaign**, 15 runs | 6 → **1** | the headline above |

Phase 5 stopped short of a verdict on purpose: its owning 6-commit step
contained *two* runtime-code commits (#1188 and #1189; the other four
were docs, receipt, version-bump and lint surfaces), and its report says
so — "ownership within the step is NOT attributable from this campaign's
data — it needs one further single-commit split." Phase 6 is that split.

## Shape and workload

One shape, throughout: **100 peers × 1,000 routes**, 100,000 prefixes
total, IPv4 unicast, driven by the `bgperf2` harness pinned at
`ad8a7deba21e8ffa1aed609b86e0d0236b0489cd` (`bench -t rustbgpd -n 100
-p 1000`, sequential, full cleanup between runs). The load generator and
the receiving monitor are pinned container images, identical in every
run of every phase:

| Role | Image | Digest |
|---|---|---|
| tester (load generator) | `bgperf/bird` | `sha256:1187aaa54a535659f4929b2068c3533fdf0ce97df571f1a270565c2dfb012732` |
| monitor (receiver) | `bgperf/gobgp` | `sha256:e783a1d91600f613ec9e8b7d4b23d7142696397b8ef6860c64e2cdafc1b91f99` |

Those two images are load-generation and reception apparatus held
constant across arms. **No control daemon ran in this campaign and no
competitor comparison is made or implied anywhere in this receipt.**

Every accepted run converged exactly `100000/100000` and exited zero.
Event history was disabled on every measured arm and verified
*behaviorally* per run — the rendered config carries
`[event_history] enabled = false` **and** the daemon logs its own
"event history disabled" line, with a control preflight proving the
signal discriminates (the same image with the block on logs "event
history manager started" and writes a db file).

## Method

- **Interleaved arms, never blocks.** Phases 0 and 1 alternate A/B and
  B/A pairs; phases 2–6 run strict round robin across all arms
  (`r01 = arm1, r02 = arm2, …`), so any host drift lands on every arm
  equally rather than on whichever ran last.
- **Five runs per arm, medians.** Ownership is decided on the per-arm
  **median** of cg `memory.peak` — never on a single run.
- **Primary surface: cgroup `memory.peak`** of the target container,
  read from `memory.peak` directly, sampled alongside a 1 Hz
  `/proc`-derived process-tree stream. Secondary: **settled anonymous
  RSS** (sum of `RssAnon` over the cgroup's processes at the last
  sample). Convergence time is recorded per run as a secondary
  observation with **no gate**. Peak and settled-anon are reported
  separately and never substituted for one another; the divergence
  between them is itself informative (anonymous growth vs page cache).
- **Bands fixed before measurement.** Every phase manifest states its
  attribution rule verbatim before its first build. Phases 2–6 all
  carry the same one: an interval **OWNS** growth when its median
  cg-peak step is **≥ +25 MiB**; steps within **±15 MiB** are **FLAT**;
  **+15…+25 MiB** is a **MINOR CONTRIBUTOR, no ownership claim**;
  negative steps beyond −15 MiB are reported factually as reductions.
  Phase 6 additionally preregistered the joint-ownership branch — "if
  BOTH steps exceed +25, the partition is reported as JOINT ownership
  with both magnitudes — a valid final answer, not a failure" — and
  that branch did not trigger.
- **One build per arm, sealed before measurement.** Each arm is built
  once, `nocache`, from a fresh clone detached at its exact SHA with a
  clean tree; the working checkout is never entered or built from. Image
  digests, binary SHA-256s and the daemon's own version string are
  recorded and **sealed into the manifest before the first measured
  run**.
- **Reproducible-build byte-identity between campaigns.** Every phase
  from 2 onward re-measured the previous phase's boundary arm, and every
  such rebuild came back byte-identical (see
  [Provenance](#provenance)), which is what licenses reading the phases
  as one chain — and what proves the cross-campaign level offsets below
  are run-to-run variance rather than build differences.
- **Quiet-lane gating per run.** Load average and a `ps`-by-comm check
  for build processes are recorded at the start and end of every run;
  runs overlapping foreign load are marked CONTAMINATED, excluded and
  replaced. **Across all 134 runs, zero were contaminated.**
- **Era-correct configs, disclosed.** Arms predating the 2026-08-03
  authz arc refuse to boot with an empty roles map, so they render the
  `[security.grpc] enforcement = "legacy"` block their own era's harness
  rendered, via an env-gated harness shim applied *after* every build
  sealed and reverted at campaign end. gRPC authz is control-plane only
  and not in the measured data path. The two rendered config surfaces
  are published (`config_base.toml` `sha256 3316fed0…`,
  `config_head.toml` `sha256 64fb4f7b…`) and their digests are quoted in
  the manifests that used them.

## Per-arm results

All medians, n = 5 per arm unless noted. Arms carried in from a prior
phase without re-measurement are marked *(rec.)* and named as such in
that phase's own manifest.

**Phase 2 — coarse bisect** (true first-parent order, which is *not* the
tag order: the authz legacy cut landed 34 commits **before** the v0.63.0
tag):

| Arm | cg peak | Settled anon | Convergence |
|---|---:|---:|---:|
| `515659b1` #1161 (2026-07-25 baseline) *(rec.)* | 195.1 MiB | 153.8 MiB | 14.00 s |
| `9fe58871` #1431 authz legacy cut | 270.7 MiB | 216.2 MiB | 11.91 s |
| `39ebf370` v0.63.0 | 295.1 MiB | 243.6 MiB | 11.96 s |
| `9077984b` #1512 ADR-0126 phase-3 classifier flip | 277.1 MiB | 218.3 MiB | 11.93 s |
| `295d1f37` v0.64.0 | 281.6 MiB | 225.1 MiB | 11.90 s |
| `07f6eb52` #1672 (2026-08-14 anchor) | 292.0 MiB | 239.0 MiB | 11.91 s |

| Interval | Commits | cg-peak step | Verdict |
|---|---:|---:|---|
| baseline → authz cut | 271 | +75.6 MiB | OWNS |
| authz cut → v0.63.0 | 34 | +24.4 MiB | MINOR CONTRIBUTOR |
| v0.63.0 → ADR-0126 flip | 48 | −18.0 MiB | reduction |
| ADR-0126 flip → v0.64.0 | 11 | +4.5 MiB | FLAT |
| v0.64.0 → anchor | 145 | +10.4 MiB | FLAT |

**Phase 3 — refinement bisect** inside the 271-commit interval:

| Arm | cg peak | Settled anon | Convergence |
|---|---:|---:|---:|
| baseline *(rec.)* | 195.1 MiB | 153.8 MiB | 14.00 s |
| `9b46432c` #1246 (2026-07-28) | 285.4 MiB | 217.2 MiB | 11.90 s |
| `5ef6a066` v0.62.0 | 286.6 MiB | 239.4 MiB | 11.93 s |
| `fb4b586e` merge #1377 | 302.5 MiB | 243.1 MiB | 11.93 s |
| `9fe58871` #1431 (anchor) | 287.0 MiB | 220.3 MiB | 11.94 s |

Steps: **+90.3 MiB OWNS** (86 commits, and −2.10 s of convergence with
it), then +1.2 FLAT, +15.9 MINOR, −15.5 reduction. The entire trade is
confined to the first 86 commits.

**Phase 4 — quartile split** inside those 86 commits:

| Arm | cg peak | Settled anon | Convergence |
|---|---:|---:|---:|
| baseline *(rec.)* | 195.1 MiB | 153.8 MiB | 14.00 s |
| `6294f0e5` merge #1183 | 187.7 MiB | 130.1 MiB | 12.97 s |
| `b592362b` merge #1204 | 272.1 MiB | 225.6 MiB | 11.90 s |
| `048a8293` #1225 | 294.5 MiB | 216.1 MiB | 11.90 s |
| `9b46432c` #1246 (anchor) | 294.6 MiB | 241.5 MiB | 11.92 s |

| Interval | Commits | cg-peak step | Settled anon | Convergence | Verdict |
|---|---:|---:|---:|---:|---|
| baseline → merge #1183 | 22 | −7.4 MiB | −23.7 MiB | **−1.03 s** | FLAT on peak, memory *down* |
| merge #1183 → merge #1204 | 21 | **+84.4 MiB** | +95.5 MiB | **−1.07 s** | OWNS |
| merge #1204 → #1225 | 21 | +22.4 MiB | −9.5 MiB | +0.00 s | MINOR |
| #1225 → #1246 | 22 | +0.1 MiB | +25.4 MiB | +0.02 s | FLAT |

This is where the free half of the speed-up shows up: the first 22
commits deliver **−1.03 s with peak flat and settled anon 23.7 MiB
lower**. See the limits section on what that does and does not attribute.

**Phase 5 — candidate-targeted micro-bisect** inside those 21 commits:

| Arm | cg peak | Settled anon | Convergence |
|---|---:|---:|---:|
| merge #1183 *(rec.)* | 187.7 MiB | 130.1 MiB | 12.97 s |
| `99ee74ba` merge #1184 | 178.2 MiB | 133.6 MiB | 12.99 s |
| `21aeba73` merge #1189 | 268.3 MiB | 218.2 MiB | 11.91 s |
| `870062f0` merge #1198 | 286.5 MiB | 223.7 MiB | 11.93 s |
| `b592362b` merge #1204 (anchor) | 291.0 MiB | 238.2 MiB | 11.87 s |

| Interval | Commits | cg-peak step | Convergence | Verdict |
|---|---:|---:|---:|---|
| merge #1183 → merge #1184 | **1** | −9.5 MiB | +0.02 s | FLAT — #1184 exonerated alone |
| merge #1184 → merge #1189 | 6 | **+90.1 MiB** | **−1.08 s** | OWNS |
| merge #1189 → merge #1198 | 8 | +18.2 MiB | +0.02 s | MINOR |
| merge #1198 → merge #1204 | 6 | +4.5 MiB | −0.06 s | FLAT |

**Phase 6** is the headline table above.

## Attribution

| Role | Commit(s) | Magnitude | Evidence |
|---|---|---|---|
| **Sole owner** | **#1189 `perf(api): coalesce neighbor RIB snapshots`** (merge `21aeba73`, 2026-07-26, v0.61.0) | **+106.6 MiB cg peak, +101.1 MiB settled anon, for −1.02 s convergence** | phase 6, single-commit step, n = 5/arm |
| **Reducer** | #1188 `perf(policy): share attribution labels through group staging` (merge `9c1ebb12`) | **−21.4 MiB cg peak, −23.8 MiB settled anon** | phase 6, 5-commit step of which only #1188 touches runtime code |
| **Free speed** | the 22-commit interval ending at merge #1183, whose perf-labeled landings are #1183 `perf: grow extended-message receive buffers on demand`, #1176 `perf(rib): remove peer-multiplied fanout bookkeeping`, #1177 `perf(wire): eliminate temporary codec allocation churn` | **−1.03 s with peak −7.4 MiB (flat) and settled anon −23.7 MiB** | phase 4, interval-level — **not** split per commit |
| **Exonerated (measured, flat or negative)** | #1184 alone (−9.5 MiB peak, +0.02 s); the authz arc (−15.5 MiB over its 54-commit interval); the 48-commit interval that lands listener hardening and ADR-0126 phases 1–3 (−18.0 MiB); v0.64.0 (+4.5 MiB over 11 commits); the 145 commits from v0.64.0 to the anchor (+10.4 MiB) | inside the ±15 MiB flat band, or a reduction beyond it | phases 2 and 5 |
| **Exonerated (inconclusive, reported as such)** | the #1678–#1689 structural-reclaim tranche at the tip | arm medians within ~1 MiB; CI [−7.1%, +9.0%] on peak | phase 1 — **not** a no-movement claim, see the lessons |
| **Minor, unattributed** | +24.4 MiB across the 34 commits from the authz cut to the v0.63.0 tag; +18.2 MiB across the 8 commits ending at #1198 (phase 4 saw +22.4 MiB over the overlapping 21-commit interval); +15.9 MiB across the 46 commits ending at merge #1377 | each between +15 and +25 MiB — above the flat band, below the ownership threshold | phases 2, 3, 5 |

The minor rows are published, not dropped. Each sits in the band the
preregistration reserved for "reported without ownership claim", and at
this shape's noise they are not separable from arm-median variance. They
were never bisected further because none of them is large enough to
matter against a +106.6 MiB single-commit owner.

### Sum checks

Every phase reconciled its chain of median steps against the endpoint
delta it inherited, and disclosed the residual rather than correcting
it:

| Phase | Chain sum | Reference endpoint | Residual = that phase's anchor offset |
|---|---:|---:|---:|
| 2 | +96.9 MiB | +88.5 MiB | +8.4 MiB |
| 3 | +91.9 MiB | +75.6 MiB | +16.3 MiB |
| 4 | +99.5 MiB | +90.3 MiB | +9.2 MiB |
| 5 | +103.3 MiB | +84.4 MiB | +18.9 MiB |
| 6 | +85.2 MiB | +90.1 MiB | −4.9 MiB |

The residual is the boundary arm's in-campaign level minus the level the
previous campaign measured for **the same binary**, so by construction it
equals the anchor offset. No correction was applied in any phase. Phase 6
is the one that matters, because it re-measured *all three* of its arms
in-campaign: its internal sum check is exact to the digit
(−21.4 + 106.6 = +85.2, its own measured endpoint step).

## Noise floor, and how the bands account for it

Settled memory at this shape carries a **±30–50 MiB glibc allocator-arena
residency noise floor** — the same figure the soak gates are calibrated
against, see
[`../soaks/soak-acceptance-gates.md`](../soaks/soak-acceptance-gates.md).
It is not measurement error; it is how many pages the allocator's arenas
happen to have dirtied on a given run.

The distribution is not merely noisy, it is **bimodal**. A minority of
runs land 50–120 MiB below their own arm's median with normal
convergence and a correct route count. Every phase preregistered a
tripwire for it (any run ≥ 40 MiB below its arm's running median),
captured `smaps`/`smaps_rollup` for **every** run regardless, and
preregistered that flagged runs are **KEPT** — medians absorb them.
Each phase reports its own count: 3 of 25 runs in phase 2, 2 of 20 in
phase 3, 2 of 20 in phase 4, 1 of 20 in phase 5, and **0 of 15 in the
deciding phase 6**. The rollup signature is consistent every time: the
entire delta is Anonymous/`Private_Dirty`, file-backed residency is
identical to within ~0.1 MB (~1.5–1.6 MB `Shared_Clean`), the
anonymous-VMA count is essentially unchanged (84 vs 85 in the run
examined in most detail), and every large arena is uniformly less
resident. Same allocation profile, fewer dirty pages — not a different
code path, and it appears on both arms of an A/B, so it is a property of
the daemon at this shape rather than of any commit under test.

Three design choices follow from that, all preregistered:

1. **Medians of 5, never single runs**, so a low-mode run shifts a
   verdict by at most one rank.
2. **A +25 MiB ownership threshold with a ±15 MiB flat band and an
   explicit no-claim strip between them**, so a step has to clear the
   arena's median-level influence before anyone calls it an owner. The
   winning step is +106.6 MiB — more than 4× the threshold and more than
   twice the top of the noise floor.
3. **Every figure at this shape is a band, never a point.** The medians
   in this receipt are the statistic the rule was written against; the
   per-arm min/max spreads (5%–48%) are published in full in each
   phase's `results.txt`.

## Convergence, read honestly

Convergence time was a **secondary observation with no gate** in every
phase. It is quoted here because it moves in lockstep with the memory,
which is the substance of the trade — not as a speed claim.

The window's total convergence move is 14.00 s → 11.9 s at this shape,
and it splits almost exactly in half: −1.03 s across the 22 commits
ending at merge #1183 (with memory going *down*), and −1.07 s across the
following 21 commits (with memory going sharply *up*). Phase 5 put the
whole second half inside one 6-commit step (−1.08 s), and phase 6 put it
on #1189 (−1.02 s).

The one place the medians need reading: phase 6's #1184 arm is bimodal
in *time* as well as memory (12.91/12.97 s vs 13.95/13.97/14.01 s), so
its median lands in the slow mode and the #1184 → #1188 step reads
−0.99 s. The #1188 arm is tight at 12.92–12.99 s — the #1184 arm's fast
mode, and within 0.03 s of phase 5's #1184 level of 12.99 s. Against
stable levels, #1188 leaves convergence where it found it and #1189
carries the gain. The same slow mode hit 2 of 5 #1184 runs in phase 5
on the byte-identical binary.

## Campaign-method lessons

Two are worth recording because they changed how the later phases were
designed.

**A preregistered band can be unreachable, and the answer is to say so.**
Phase 1's design asked for a ±5% no-movement interval on paired deltas.
At the observed pair-delta spread (~16.9 points of standard deviation on
settled anon, driven by the low mode), a ±5% CI needs roughly 50+ pairs
— out of reach for the campaign. The series was extended from 5 to 7
pairs and then **recorded INCONCLUSIVE, which was the terminal
preregistered verdict**, rather than renegotiating the band after seeing
the data. The honest reading of phase 1 is "arm medians within ~1 MiB and
the interval is variance-driven", not "no movement".

**Absolute levels do not travel between campaigns; steps do.** Re-running
a *byte-identical binary* in a later campaign produced level offsets of
+16.3, +9.2 and +18.9 MiB on cg peak in phases 3, 4 and 5 — each against
a rebuild verified byte-identical to the prior phase's build, so those
offsets are pure run-to-run and arena variance rather than build
differences. (Phase 2's own +8.4 MiB offset is against phase 0, whose
binary hash was never recorded because its image was deleted at campaign
end.) Those offsets are the same order as the effects a late-stage
bisect is trying to resolve. So
the deciding phase preregistered that **no prior level would be reused
for the split decision** and re-measured all three of its arms
in-campaign. That was the right call twice over: phase 6's own boundary
arms came in +27.1 and +22.2 MiB above phase 5's levels, i.e. *outside*
the +9…+19 MiB band its manifest had cited when making the rule. Had it
reused phase 5's numbers, the split would have been computed against
levels 22–27 MiB wrong.

## Limits

- **One shape.** 100 peers × 1,000 routes, IPv4 unicast, one homogeneous
  load generator, event history disabled, no policy churn, no reloads,
  no route refresh. Nothing here predicts the same commit's cost at
  route-reflector fan-out, at VPN scale, at 1,000 sessions, or under
  churn.
- **No comparison.** No control daemon ran in any phase. This receipt
  contains no competitor claim, and its figures do not license one.
- **Medians, not distributions.** Ownership is decided on per-arm
  medians of five runs. Per-arm spreads reach 48% at this shape. The
  full per-run rows are published so the spread is visible; the medians
  are not a claim about any individual run.
- **Convergence figures are same-shape observations**, ungated and
  secondary. "#1189 bought −1.02 s" means "at this shape, in this
  harness, the median moved by that much" — it is not a general
  throughput or convergence claim.
- **Levels are campaign-local.** Only in-campaign steps are comparable.
  Cross-campaign level offsets of +8 to +27 MiB were measured, mostly on
  rebuilds verified byte-identical; do not difference a number from one
  phase's table against a number from another's.
- **The reducer attribution is by code character, not by isolation.**
  The −21.4 MiB step spans five commits; four of them are docs, receipt,
  version-bump and lint surfaces carrying no daemon runtime path, and
  #1188 is the only one that touches runtime code. That is a strong
  inference, not a single-commit measurement like #1189's.
- **The free half is an interval result.** −1.03 s with memory down is
  attributed to a 22-commit interval, not to any one PR inside it. The
  three perf-labeled landings named above are the plausible carriers by
  code character; none was measured alone.
- **Modeled is not observed.** Every number here is a measured median
  of an observed surface. No figure is derived from a model of what a
  data structure "should" cost.
- **Pre-authz-arc arms ran an era-correct legacy authz config block**
  that later arms cannot render. It is control-plane only and outside
  the measured data path, but it is an asymmetry and it is disclosed
  rather than hidden.

## Provenance

Arms are identified by source SHA; every build's image digest and binary
SHA-256 were sealed into the phase manifest before its first measured
run. The chain of boundary rebuilds came back byte-identical every time:

| Boundary arm rebuilt | Source SHA | Binary SHA-256 | Matches |
|---|---|---|---|
| phase 1 → phase 2 | `07f6eb52` | `b68b1e8b…` | phase 1's build of the same SHA |
| phase 2 → phase 3 | `9fe58871` | `0a14ef6c…` | phase 2's build |
| phase 3 → phase 4 | `9b46432c` | `6690b082…` | phase 3's build |
| phase 4 → phase 5 | `b592362b` | `a02f2c6c…` | phase 4's build |
| phase 5 → phase 6 | `99ee74ba` | `d881d4df…` | phase 5's build |
| phase 5 → phase 6 | `21aeba73` | `d9c82887…` | phase 5's build |

The deciding arm, `9c1ebb12` (merge #1188), was built for the first time
in phase 6: binary `b7128cd0…`, image
`sha256:30cdb7dc7aa47dfe6cbd8eb65c43f9f4d052e280766c1dbc0046e010600feb05`,
reporting `rustbgpd 0.61.0`. Its two neighbors in that campaign are
`sha256:fb63c25a…` (`99ee74ba`, reports `0.60.0` — pre-release-prep, as
expected for its position) and `sha256:49adfe42…` (`21aeba73`, reports
`0.61.0`).

All builds used the pinned builder base
`rust:1.95-bookworm@sha256:6258907a…`, rustc 1.95.0 — identical across
every phase by construction, and confirmed empirically by the binary
byte-matches above.

## Environment

| Field | Value |
|---|---|
| Hardware | the project's standard bench host — AMD Ryzen Threadripper 7970X (32 cores / 64 threads), 125 GiB RAM; the campaign logs record 64 threads and per-run load telemetry directly |
| Kernel | Linux 6.17 |
| Harness | `bgperf2` pinned at `ad8a7de`, `bench -t rustbgpd -n 100 -p 1000`, sequential, cleanup between runs |
| Build toolchain | rustc 1.95.0 via `rust:1.95-bookworm@sha256:6258907a…`, one `nocache` build per arm |
| Lane discipline | load average + `ps`-by-comm build check at the start and end of every run; 0 of 134 runs contaminated |

One host, one governor, one allocator. These figures do not transfer to
another machine, kernel or allocator.

## Artifacts

[`artifacts/memory-attribution-2026-08/`](artifacts/memory-attribution-2026-08/README.md)
carries, for all seven phases, the **preregistered manifest**, the
complete per-run result table with every verdict, and each campaign's
own seal roster — plus the shared protocol kit (run driver, preflight,
analysis script, both rendered config surfaces, the harness shim). Every
number in this receipt traces to a line in one of those files.

Held off-repo in the campaign artifact archive, read-only: the 134
per-run bench logs, the 1 Hz sample streams, the per-run
`smaps`/`smaps_rollup` dumps behind the low-mode analysis, the `nocache`
build transcripts, the preflight boot transcripts, the lane telemetry,
and the rendered runtime manifests — bulk capture with no reviewable
prose. Each phase's `original-SHA256SUMS.txt` identifies those originals
by digest.

The published copies carry two mechanical redactions — absolute host
paths, and private tracker IDs and host process names — which is why
their bytes differ from the digests in `original-SHA256SUMS.txt`. The
files published here are sealed by this directory's own `SHA256SUMS`;
the two rendered configs are unmodified and still hash to the values
their manifests quote (`3316fed0…`, `64fb4f7b…`).

## Open follow-up

#1189's trade is worth revisiting because the machinery that would make
it unnecessary did not exist when it landed. ADR-0126's shared groups can
hold coalesced snapshot state once per update group rather than once per
neighbour, which is exactly the shape of the retention measured above.
Reworking it that way is planned and hard-gated: **no more than a 2%
convergence regression at this shape**, the shape #1189 bought its
speed-up at. The trade is only worth undoing if the speed survives.
