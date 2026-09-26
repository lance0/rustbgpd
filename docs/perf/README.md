# Performance evidence index

> **Document class: CURRENT.** This maintained index summarizes dated measurements within their published scope.

Find the measured route-server, route-reflector, and route-import results and their source receipts.

Each receipt records its workload, versions, measurement dates, limitations,
and artifacts. These results describe those workloads, not a performance
guarantee for another deployment. The [complete receipts index](../receipts.md)
also covers interop and archived soaks.

## Route-server and route-reflector results

Each result below links to its published, reproducible receipt:

- **Dual-stack filtering reload after redundant-policy work removal**:
  the 200-member cell passed with 170 changed targets and no stable-peer
  remainder; median full-generation duration was 345.378 ms across four
  reloads. The single 700-member cell removed the remainder work but failed
  health and warning acceptance; the dated receipt preserves those limits —
  [policy-reload receipt](ixp-dualstack-policy-noops-2026-09.md),
  measured 2026-09-08
- **Policy reload at IXP scale** (700 route-server clients × 400,400 routes,
  live churn, same harness / same host — the policy-file reload, not the IRR
  filter refresh below): new policy fully delivered to every member in
  **1.37–1.63 s p50** for rustbgpd v0.72.0, measured 2026-09-26; current main
  measured the same day read 1.42–1.75 s, within run-to-run spread — [v0.72.0 refresh receipt](headline-refresh-v0720-2026-09.md).
  These rows are slower than the 1.21–1.35 s v0.68.0 rows measured 2026-08-30
  on the same host; a same-day v0.68.0/v0.72.0 comparison is pending to tell
  a regression from host drift. The dated matrix retains BIRD and OpenBGPD
  context separately, [IXP receipt matrix](ixp-matrix-2026-07.md)
- **IRR-scale filter reload** (320 route-server members × 183,040 generated
  prefixes, same harness / same host): at 0% received-view overlap, v0.72.0
  completion p50 was **1.22–1.44 s** and current main 1.21–1.32 s, measured
  2026-09-26 with 320/320 sessions and zero parse errors — [v0.72.0 refresh receipt](headline-refresh-v0720-2026-09.md). That is slower
  than the 0.85–0.97 s v0.68.0 rows measured 2026-08-30 on the same host (same
  pending comparison). The 10% and 50% overlap rows were not re-measured and
  remain v0.68.0 source-equivalent observations of 0.88–1.09 s; BIRD completed
  in 11.86–15.21 s and OpenBGPD in 42.94–61.96 s at this fixed shape —
  [v0.68.0 receipt](irr-reload-v0680-2026-08.md), measured 2026-08-30
- **Member-flap propagation** (50 members flap, 650 observers): re-announce
  p50 **0.48–0.55 s** for v0.72.0 and 0.50–0.53 s for current main, measured
  2026-09-26 — [v0.72.0 refresh receipt](headline-refresh-v0720-2026-09.md). The 2026-08-30 v0.68.0 rows read 0.36–0.39 s on the same
  host (same pending comparison). The dated matrix retains BIRD and OpenBGPD
  comparison rows separately,
  [same matrix](ixp-matrix-2026-07.md#s3--flapstorm-member-down--member-up-propagation)
- **Cold start**: full 400,400-route table delivered to all 700 members in
  **3.6–4.0 s** for v0.72.0 and 3.7–3.9 s for current main, measured
  2026-09-26 — [v0.72.0 refresh receipt](headline-refresh-v0720-2026-09.md). The 2026-08-30 v0.68.0 rows read 3.4 s on the same host
  (same pending comparison). The dated matrix retains BIRD and OpenBGPD
  comparison rows, [same matrix](ixp-matrix-2026-07.md#s1--cold-convergence)
- **Route-reflector scale**: 1,000 RR clients × 100k routes converge on the
  wire in **332–351 ms** at **372,912–411,892 KiB** direct-process RSS in six
  v0.72.0 runs, and in 343–349 ms at 388,516–420,564 KiB in six current-main
  runs, measured 2026-09-26 — [v0.72.0 refresh receipt](headline-refresh-v0720-2026-09.md). The v0.68.0 rows measured 2026-08-30
  read 318–341 ms; the historical receipt was measured 2026-07-03,
  [1000-peer scale receipt](scale-receipt-2026-07.md)
- **The losses, stated plainly**: OpenBGPD 9.2 holds a smaller reload stall
  (p50 0.213–0.238 s vs rustbgpd v0.72.0's 0.457–0.646 s), and BIRD keeps the
  settled-RSS win under flap churn (337/328 MiB vs rustbgpd v0.72.0's
  401–426 MiB after each flap round, with noisier end-of-run samples of
  521–607 MiB). rustbgpd v0.72.0 withdraw p50 is 0.26–0.48 s. At S2, rustbgpd
  v0.72.0 settles at 384/385/384 MiB versus BIRD's dated 422/412 MiB. The
  rustbgpd figures are from the [v0.72.0 refresh receipt](headline-refresh-v0720-2026-09.md); the comparator rows and the fairness
  protocol are in the [same matrix](ixp-matrix-2026-07.md#memory).
  Cross-daemon memory is not ranked in the current IRR receipt because daemon
  and container defaults differ.

The rustbgpd figures above are v0.72.0 release-tree rows measured 2026-09-26,
with current main measured the same day as a no-regression check. The IRR 10%
and 50% overlap rows remain v0.68.0 source-equivalent rows measured
2026-08-30. On this host, the 2026-09-26 rows are slower than the 2026-08-30
v0.68.0 rows in every re-measured cell; until a same-day v0.68.0/v0.72.0
comparison runs, that gap is unattributed. BIRD remains the v0.64.0
same-host refresh measured 2026-08-08; OpenBGPD 9.2 is a supplemental
comparator amendment measured 2026-08-30. The mixed-date boundary and earlier
bands are preserved in the receipts.

## Earlier route-reflector measurements

**Update-group fanout** — peers with provably identical staged output share
one staging pass: ~27x faster 100k-route convergence at 256 uniform RR
clients (15.1 s to 0.56 s), measured 2026-07-03; v2 extends sharing to
VPNv4/v6 with per-member RT filtering at emit
([receipt](scale-receipt-2026-07.md), whose current 1,000-client rows were
measured 2026-08-30).

At route-reflector shapes, the
[1000-peer scale receipt](scale-receipt-2026-07.md), measured 2026-07-03
(its v0.68.0 source-equivalent rows were measured 2026-08-30), records 1,000
uniform RR clients × 100k routes converging on the wire in 1.82 s at 419 MiB
whole-process RSS, and 1,000 clients × 100k VPNv4 in 12.60 s / 625 MiB uniform
and 3.92 s / 636 MiB with heterogeneous ~10% RT memberships (vs ~73 s / ~31 GiB
and ~12.5 s / ~5.7 GiB extrapolated per-peer), with a one-RT membership flip
delivering its 1600-route delta in ~15 ms with zero policy evaluations.

## Route import comparisons

The freshest published [v0.68.0 cross-stack bgperf2
receipt](competitive-bgperf2-v0680-2026-08.md), measured 2026-08-30,
is the headline same-host IPv4 import/convergence comparison. All 80 cells
reached the exact expected route count across five fixed shapes; the largest is
two peers × 100,000 prefixes, not a full-table cell. Microbenchmarks and memory
scaling are in [Benchmarks](../benchmarks.md). That page also retains
the corrected July campaign as explicitly historical evidence; it supports no
cross-daemon ranking. Every receipt is indexed in
[the receipts index](../receipts.md); GoBGP-specific parity is in
[the GoBGP parity reference](../explanation/gobgp-parity.md).

## Reading the archive

This directory is a historical evidence archive. Each row reports only the
workload and metadata stated by its linked file; it is not a claim about every
deployment or the current tip. Follow the linked record before reusing a
result. `Unstated` means that the linked file does not state the field; this
index does not infer metadata from filenames, parent directories, or related
records.

## Primary records

| Document | Date stated | Workload or shape | Establishes | Does not establish |
|---|---|---|---|---|
| [`actor-ceiling-1m-2026-07.md`][actor-ceiling-1m-2026-07.md] | 2026-07 | 500 clients, 1M routes, 300 policy changes, three SIGHUP reloads | Transition polls stayed at or below 200 ms, but the post-commit flush blocked readiness for 1.64–2.40 s on all three reloads | A high-percentile bound from a large reload sample |
| [`adj-rib-out-family-gauge-2026-07.md`][adj-rib-out-family-gauge-2026-07.md] | July 2026 | Family-gauge refresh at 8, 64, 256, and 1,000 peers | 256-peer and 1,000-peer rows improved 11.69% and 14.98% | A sevenfold whole-daemon or every-shape gain |
| [`attr-intern-hashing-2026-08.md`][attr-intern-hashing-2026-08.md] | August 2026 | Typical and rich attributes at 10k and 100k entries | NO-GO: the isolated hash control exceeded its stability limit | A production change or speedup |
| [`attr-intern-hashing-recheck-2026-08.md`][attr-intern-hashing-recheck-2026-08.md] | August 2026 | A 35-row same-source control matrix | Not evaluated: six controls exceeded their limits | A performance or regression claim |
| [`attribute-layout-2026-08.md`][attribute-layout-2026-08.md] | August 2026 | 900k prefixes with 2.7M and 4.5M route-copy models | Slice-backed attributes increased modeled memory by 17.7 and 31.4 MiB | Allocator, locality, conversion-cost, or nested-payload effects |
| [`authoritative-policy-replacement-cursor-feasibility-2026-07.md`][authoritative-policy-replacement-cursor-feasibility-2026-07.md] | 2026-07 | Borrow-free, exact-once bounded-continuation feasibility gate | Gate 1 NO-GO | Gate 2 or a behavior change |
| [`competitive-bgperf2-2026-07.md`][competitive-bgperf2-2026-07.md] | Initial campaign 2026-07-26; latest refresh 2026-07-27 | Four daemons, five fleet shapes, three runs per shape | Historical observations whose cross-daemon ranking was later retracted | Any projection beyond 100 peers |
| [`competitive-bgperf2-v0670-2026-08.md`][competitive-bgperf2-v0670-2026-08.md] | 2026-08-29 | Four daemons, five import shapes, four repetitions | 79 of 80 cells reached the exact expected table | Export, reload, churn, IPv6, Add-Path, OpenBGPD, or another host |
| [`competitive-bgperf2-v0680-2026-08.md`][competitive-bgperf2-v0680-2026-08.md] | 2026-08-30 | Four daemons, five import shapes, four counterbalanced repetitions | All 80 cells reached the exact expected table | Universal throughput, memory, or CPU ranking |
| [`config-persistence-2026-07.md`][config-persistence-2026-07.md] | 2026-07-25 | Pinned persistence, history, rollback, and commit-confirm lifecycle harness | Behavioral assertions preserved by the workspace integration test | Timing or performance |
| [`controller-injection-2026-09.md`](controller-injection-2026-09.md) | 2026-09-20–21 | Unary inserts, replacements and deletes through 100k routes, one passive client | Scoped CPU reduction from deferred controller attribute collection; existing local-route reconciliation | Batch packing, multi-client scale or isolated-host latency |
| [`enhanced-route-refresh-2026-07.md`][enhanced-route-refresh-2026-07.md] | Initial campaign 2026-07; latest refresh 2026-08-30 | 100k-route Enhanced Route Refresh inventory lifecycle | Completion dominated snapshot creation in the all-withdraw shape | Fleet-wide convergence or generic throughput |
| [`event-history-producer-2026-07.md`][event-history-producer-2026-07.md] | 2026-07 | Three event-history producer shapes at 1.3–3.3 µs per event | The offload proceed gate passed and bounded delivery completed | Independent BIRD timeout evidence |
| [`evpn-fanout-2026-09-05.md`](evpn-fanout-2026-09-05.md) | 2026-09-05 | Synthetic EVPN Type 2 reflector workload: 10,000 selected routes at 8–480 receiving peers, plus a separate ten-second churn phase | Absolute baseline: every receiver in every accepted run reached the exact 10,000-key table and withdrawal count | An optimization comparison or throughput ceiling |
| [`exact-export-fanout-2026-07.md`][exact-export-fanout-2026-07.md] | 2026-07 | Four exact-export fanout campaigns with production probes | PASS for the measured grouped fanout optimization | Resync or full-table convergence |
| [`explain-cache-opt-in-2026-07.md`][explain-cache-opt-in-2026-07.md] | 2026-07 | Same-host route-server memory runs with explain cache on and off | Resident-memory cost of the opt-in import-decision cache | Throughput or competitor ranking |
| [`fanout-metrics-handle-2026-07.md`][fanout-metrics-handle-2026-07.md] | July 2026 | Homogeneous groups of 1–1,000 peers distributing 64 changed routes | Clone-once metrics handling reduced the measured distribution interval | Whole-daemon convergence |
| [`fib-kernel-dump-2026-08.md`][fib-kernel-dump-2026-08.md] | 2026-08-30 | 64 managed tables with 0, 1k, 5k, and 20k unrelated routes | Strict-table dump crossover and scaling on Linux 6.17 | Whole-reconcile latency, IPv6, realistic nexthops, or a shipped-code speedup |
| [`grouped-private-adj-rib-out-late-join-2026-07.md`][grouped-private-adj-rib-out-late-join-2026-07.md] | Unstated | Late join after a preloaded Loc-RIB, measured across client counts | Fresh grouped-join virtual-allocation reduction | A retained-RSS headline |
| [`grouped-withdrawal-fanout-2026-07.md`][grouped-withdrawal-fanout-2026-07.md] | July 2026 | Grouped withdrawal fanout across the disclosed member fleet | Absolute measurement-only baseline | Writer, socket, network, or end-to-end latency |
| [`grouped-withdrawal-probe-skip-2026-07.md`][grouped-withdrawal-probe-skip-2026-07.md] | July 2026 | Fixed 64-route withdrawal at 64, 256, and 1,000 members | Exact-probe skip improved measured medians by 6.80–9.33% | A result outside the fixed withdrawal shape |
| [`headline-refresh-v0720-2026-09.md`](headline-refresh-v0720-2026-09.md) | 2026-09-26 | IXP-700 S1/S2/S3, IRR reload at 0% overlap, and RR1000 on v0.72.0 and current main, alternating, three or more runs per build | Main within run-to-run spread of the same-day v0.72.0 control | IRR 10%/50% overlap, comparator daemons, or attribution of the gap to the August v0.68.0 rows |
| [`high-n-route-server-v0680-2026-08.md`][high-n-route-server-v0680-2026-08.md] | 2026-08-30 | Exact-source 2,500- and 5,000-peer route-server runs | Both high-N runs completed their session and route-count gates | A scaling law, interpolation, or extrapolation |
| [`irr-reload-comparison-2026-08.md`][irr-reload-comparison-2026-08.md] | 2026-08 | 320 members, 183,040 routes, 3.2M filter entries, eight reload roots | Same-host rustbgpd, BIRD, and OpenBGPD reload observations | A cause for later-reload growth or exact allocator comparison |
| [`irr-reload-grouped-per-client-best-2026-08.md`][irr-reload-grouped-per-client-best-2026-08.md] | 2026-08 | 320 members, 183,040 prefixes, four reloads per cell | Historical grouped per-client-best acceptance result | A speedup or the internal mechanism behind later-reload growth |
| [`irr-reload-realistic-mix-2026-08.md`][irr-reload-realistic-mix-2026-08.md] | 2026-08 | Canonical IRR scenario with controlled received-route overlap | Historical realistic-mix reload result | A same-commit A/B or the operational value of a hidden path |
| [`irr-reload-v0680-2026-08.md`][irr-reload-v0680-2026-08.md] | 2026-08-30 | 320 IPv4 members, 183,040 prefixes, three overlap levels | All 12 roots and 96 verifier rows passed exact route-count gates | IPv6, larger fleets, or other policy distributions |
| [`irr-transactional-apply-2026-08.md`][irr-transactional-apply-2026-08.md] | 2026-08 | 320-member, 183,040-route, 295.6 MB streamed candidate | Eight full transactional reload cycles completed and were confirmed | A memory optimization claim |
| [`ixp-matrix-2026-07.md`][ixp-matrix-2026-07.md] | Initial campaign 2026-07; latest refresh 2026-08-30 | 700-session route-server matrix for reload, churn, convergence, and memory | Dated same-host observations for rustbgpd, BIRD, and OpenBGPD | A universal memory win or cross-host ranking |
| [Qualified membership cell](ixp-membership-churn-qualified-2026-09.md) | 2026-09-20 | 700 unchanged announcers plus two rotating dual-stack receivers | All original gates pass after readiness service and terminal draining; earlier red evidence retained | Endurance, announcing-owner churn or a general capacity claim |
| [Initial-export readiness cell](ixp-initial-export-readiness-2026-09.md) | 2026-09-20 | Same 702-member workload with readiness service and the original Python cleanup | Zero readiness failures; full qualification remains red on a teardown reset warning | A passing scale qualification or a causal performance comparison |
| [Membership churn](ixp-membership-churn-2026-09.md) | 2026-09-20 | 700 unchanged announcers plus two rotating dual-stack receivers and dataset bindings | Preparation passes; full cell fails eight health deadlines; v0.70.0 rejects the first reload | A passing 702-member qualification or announcing-owner churn |
| [`ixp-dualstack-final-campaign-2026-09.md`](ixp-dualstack-final-campaign-2026-09.md) | 2026-09-10 | Fixed-source 90/10 and 50/50 dual-stack reloads at 200 and 700 members | All 13 cells qualify, including two four-cell 700-member campaigns; original cleanup-warning failures remain alongside supplemental assessments | Endurance qualification, another binary, or cross-daemon comparison |
| [`ixp-dualstack-2026-09-08.md`](ixp-dualstack-2026-09-08.md) | 2026-09-08 (stopped) | Dual-stack 90/10 and 50/50 operating campaign | Three accepted 200-member cells and one failed 200-member cell; planned 700-member cells not run | A completed 700-member result or cross-daemon comparison |
| [`ixp-dualstack-2026-09.md`][ixp-dualstack-2026-09.md] | 2026-09 (in progress) | Dual-stack route-server reload harness: 286 IPv4 + 286 IPv6 routes per member, permit-set-preserving and filtering policy changes, 20-member correctness rung run | Independent per-family completion with empty-family, missing, duplicate, leak, and bystander negative cases | Any 200- or 700-member result, a comparison with the IPv4-only matrix, or an IPv6 performance claim |
| [`ixp-dualstack-policy-noops-2026-09.md`](ixp-dualstack-policy-noops-2026-09.md) | 2026-09-08 | 200- and 700-member dual-stack filtering reloads after unchanged executable policies are retained | The 200-member cell passed the operating gate with a 345.378 ms median full-generation duration against 4,057.727 ms in the matched diagnostic; the 700-member cell failed operating acceptance | Independent repeated trials or a general readiness bound |
| [`ixp-dualstack-readiness-2026-09.md`](ixp-dualstack-readiness-2026-09.md) | 2026-09 | 200- and 700-member dual-stack filtering reloads with readiness service during policy replacement | The final normal 200- and 700-member runs passed the unchanged operating gate; earlier failed cells remain | A paired A/B isolating one change or a universal scheduling bound |
| [`known-path-accounting-2026-07.md`][known-path-accounting-2026-07.md] | July 2026 | Two BIRD peers, 100k prefixes each, one GoBGP monitor | Compact plain-unicast accounting reduced the measured common-case memory | An Add-Path memory win |
| [`lean-daemon-build-flavors-2026-07.md`][lean-daemon-build-flavors-2026-07.md] | July 2026 | Four release build flavors and their dependency inventories | Dependency and binary-size observations for the disclosed builds | Shipped prototype features or every production config ingress |
| [`memory-attribution-2026-08.md`][memory-attribution-2026-08.md] | 2026-08 | 100 peers × 1,000 routes, three fresh-build arms, five runs each | Attribution of the July memory step across the measured arms | Portable process-RSS or cross-host conclusions |
| [`mrt-snapshot-allocation-2026-07.md`][mrt-snapshot-allocation-2026-07.md] | July 2026 | Public snapshot encoder with ordinary and warm-checkpoint outputs | Bounded ordinary-output growth passed and was implemented | A completed warm-checkpoint preallocation result |
| [`otc-pristine-reconcile-2026-07.md`][otc-pristine-reconcile-2026-07.md] | July 2026 | Pristine OTC path, 64 routes, 1–1,000 homogeneous peers | Early return improved the exact pristine reconciliation case | Whole-daemon convergence or active OTC-blocked state |
| [`outbound-prefix-limit-admission-compaction-2026-07.md`][outbound-prefix-limit-admission-compaction-2026-07.md] | 2026-07 | Homogeneous IPv4 group, one run per revision and fleet size | Admission-compaction result for the archived harness shape | IPv6, Add-Path, heterogeneous groups, or mixed capabilities |
| [`outbound-prefix-limit-recovery-slicing-2026-07.md`][outbound-prefix-limit-recovery-slicing-2026-07.md] | 2026-07 | 400k IPv4 routes recovered across bounded member slices | Recovery became bounded actor turns at the measured fleet sizes | A short total recovery time |
| [`outbound-prefix-limit-scale-2026-07.md`][outbound-prefix-limit-scale-2026-07.md] | 2026-07 | Real daemon and TCP driver across grouped prefix-limit fleet sizes | Archived scale observations for admission, suppression, and recovery | Run-to-run variance or extrapolation past 100 members and 400k routes |
| [`outbound-prefix-limits-2026-07.md`][outbound-prefix-limits-2026-07.md] | 2026-07-24 | Pinned outbound-prefix-limit behavior harness | Limit, warning, teardown, and recovery behavior | Timing or performance |
| [`per-peer-rss-attribution-2026-07.md`][per-peer-rss-attribution-2026-07.md] | 2026-07 | 10/100 peers and 10k/100k BASE-route matrix | Both peer and route dimensions materially affect memory | “Memory tracks peers, not routes” |
| [`persisted-config-serialization-2026-08.md`][persisted-config-serialization-2026-08.md] | August 2026 | Legacy and bounded serialization over the same 342,422,071-byte config | Phase attribution and byte-identical serialization output | Portable conclusions from small `/proc` RSS movement |
| [`policy-attribution-criterion-2026-07.md`][policy-attribution-criterion-2026-07.md] | Unstated | Four Criterion policy-evaluation shapes with same-SHA and isolated controls | The measured deltas do not support CPU-gain attribution | Convergence, reload latency, throughput, or end-to-end gain |
| [`policy-fallback-per-peer-handoff-2026-07.md`][policy-fallback-per-peer-handoff-2026-07.md] | July 2026 | Clean policy transition with typed grouped and fallback outcomes | Per-member fallback work moved out of the clean actor poll | Total-work improvement or wall-clock scheduler latency |
| [`policy-regroup-shared-plan-2026-07.md`][policy-regroup-shared-plan-2026-07.md] | July 2026 | Four alternating reloads between pinned base and candidate revisions | Shared regroup-plan transition result for the disclosed fleet | General RIB-query latency during the transition |
| [`private-single-best-fanout-2026-07.md`][private-single-best-fanout-2026-07.md] | 2026-07-30 | Manager-path fanout at 1, 8, 64, and 256 peers | Improvement at 8, 64, and 256 peers with linear absolute scaling there | A one-peer improvement |
| [`probe-mp-reach-borrowed-attrs-2026-08.md`][probe-mp-reach-borrowed-attrs-2026-08.md] | August 2026 | IPv6 MP_REACH exact-export probe with paired allocation campaigns | Removed a temporary attribute-vector clone in the measured path | RSS, live heap, convergence, or whole-daemon memory |
| [`rebaseline-2026-07.md`][rebaseline-2026-07.md] | 2026-07 | Manager-direct RR fanout reconstruction and memory attribution | Post-update-group manager-phase and allocation breakdown | Transport, encode, writer, network, or backpressure cost |
| [`reload-authoritative-batch-discriminator-2026-08.md`][reload-authoritative-batch-discriminator-2026-08.md] | August 2026 | Two identical 320-member, 183,040-prefix roots on one candidate | Localized later-reload growth to registration/membership, with a negative adjudicator result | A mechanism, improvement, or authorization to optimize |
| [`reload-flush-envelope-2026-07.md`][reload-flush-envelope-2026-07.md] | 2026-07 | 100-peer fleets with 100k, 300k, and 500k tables | Reload-flush depooling tracked fleet shape more than route volume | A fitted coefficient or fully orthogonalized peer-axis result |
| [`reload-generation-phase-attribution-2026-08.md`][reload-generation-phase-attribution-2026-08.md] | August 2026 | Two 320-member, 183,040-prefix roots with four SIGHUP reloads | Localized later-reload latency inside the synchronous authoritative RIB transition | A mechanism, latency improvement, or sufficient basis for a fix |
| [`reload-stall-2026-07.md`][reload-stall-2026-07.md] | Initial campaign 2026-07-11; latest campaign 2026-07-16 | 700 clients, 400,400 routes, live churn, four reloads | Dated reload stall and completion observations | A settled RSS plateau from four cycles |
| [`revised-update-duplicate-table-2026-07.md`][revised-update-duplicate-table-2026-07.md] | 2026-07 | One clean UPDATE through the eBGP disposition branch | Fixed-table duplicate detection improved the measured parser fixture | A causal 21.73% speedup after the biased control |
| [`rib-criterion-noise-floor-2026-07.md`][rib-criterion-noise-floor-2026-07.md] | 2026-07 | Same-SHA controls plus isolated LLGR tag-lookup row | Establishes the host noise floor and one scoped CPU improvement | Convergence, pipeline, other sizes, or other hosts |
| [`rib-memory-v0680-2026-08.md`][rib-memory-v0680-2026-08.md] | 2026-08-30 | Twelve shared v0.67/v0.68 RIB memory shapes | Shared rows were byte-identical between releases | Whole-daemon RSS or live-table footprint |
| [`rib-ops-prefix-fixture-audit-2026-08.md`][rib-ops-prefix-fixture-audit-2026-08.md] | 2026-08 | Audit of the pre-fix prefix generator above 65,536 entries | Historical rows remain valid only for their duplicate-shaped workload | Unique-table throughput or high-N extrapolation |
| [`rib-rebaseline-2026-07-13.md`][rib-rebaseline-2026-07-13.md] | 2026-07-13 | Flood and churn shapes plus a two-peer 100k-route run | Production-encoder CPU attribution and a one-capture 210,338,877-byte live-heap component breakdown | Independently measured BIRD tester timeouts |
| [`rib-route-paging-2026-07.md`][rib-route-paging-2026-07.md] | Initial campaign 2026-07; ordered-index follow-up 2026-07-18 | Bounded unicast pages and grouped advertised-route materialization | Identified full-scope scans and removed grouped full-view cloning | Performance for the later ordered-index method without a receipt |
| [`route-server-1000-2026-07.md`][route-server-1000-2026-07.md] | Initial campaign 2026-07-20; latest refresh 2026-08-30 | 1,000 eBGP clients, 400k routes, uniform export policy | The real daemon completed the disclosed capacity and reload gates | Competitor comparison or universal forecast |
| [`scale-receipt-2026-07.md`][scale-receipt-2026-07.md] | Initial campaign 2026-07-03; latest refresh 2026-08-30 | 1,000 RR clients × 100k routes in the rrharness | Absolute route-reflector fanout and memory baseline | Larger-fleet scaling or real-NIC behavior |
| [`shared-source-ordering-2026-07.md`][shared-source-ordering-2026-07.md] | 2026-07 | Multi-source speedup target with retained one-source guards | NO-GO because the 400k/1-source row regressed 5.298% | A shipped performance change |
| [`unicast-prefix-announcer-index-2026-08.md`][unicast-prefix-announcer-index-2026-08.md] | 2026-08 | Three admitted campaigns and six pairs per rung | Announcer-index compaction passed the bounded no-regression gate | Universal throughput speedup |
| [`v0.61.0-final-performance-2026-07.md`][v0.61.0-final-performance-2026-07.md] | 2026-07 | Three 1,000-client, 400k-route daemon runs plus Criterion rows | Absolute v0.61.0 release-candidate baseline | An A/B optimization or CPU-delta claim |
| [`vpn-rib-query-occupancy-method.md`][vpn-rib-query-occupancy-method.md] | Unstated | Existing `ListVpnRoutes` path with a 48-cell campaign method | The required campaign and verifier protocol | A committed result or API redesign |
| [`wire-codec-allocation-2026-07.md`][wire-codec-allocation-2026-07.md] | July 2026 | Rich 11-attribute encode and six-attribute UPDATE validation fixtures | Measured fixture improvements of 28.34% and 90.57% | Framing, policy, RIB, fanout, sockets, or convergence |

[actor-ceiling-1m-2026-07.md]: actor-ceiling-1m-2026-07.md
[adj-rib-out-family-gauge-2026-07.md]: adj-rib-out-family-gauge-2026-07.md
[attr-intern-hashing-2026-08.md]: attr-intern-hashing-2026-08.md
[attr-intern-hashing-recheck-2026-08.md]: attr-intern-hashing-recheck-2026-08.md
[attribute-layout-2026-08.md]: attribute-layout-2026-08.md
[authoritative-policy-replacement-cursor-feasibility-2026-07.md]: authoritative-policy-replacement-cursor-feasibility-2026-07.md
[competitive-bgperf2-2026-07.md]: competitive-bgperf2-2026-07.md
[competitive-bgperf2-v0670-2026-08.md]: competitive-bgperf2-v0670-2026-08.md
[competitive-bgperf2-v0680-2026-08.md]: competitive-bgperf2-v0680-2026-08.md
[config-persistence-2026-07.md]: config-persistence-2026-07.md
[enhanced-route-refresh-2026-07.md]: enhanced-route-refresh-2026-07.md
[event-history-producer-2026-07.md]: event-history-producer-2026-07.md
[exact-export-fanout-2026-07.md]: exact-export-fanout-2026-07.md
[explain-cache-opt-in-2026-07.md]: explain-cache-opt-in-2026-07.md
[fanout-metrics-handle-2026-07.md]: fanout-metrics-handle-2026-07.md
[fib-kernel-dump-2026-08.md]: fib-kernel-dump-2026-08.md
[grouped-private-adj-rib-out-late-join-2026-07.md]: grouped-private-adj-rib-out-late-join-2026-07.md
[grouped-withdrawal-fanout-2026-07.md]: grouped-withdrawal-fanout-2026-07.md
[grouped-withdrawal-probe-skip-2026-07.md]: grouped-withdrawal-probe-skip-2026-07.md
[high-n-route-server-v0680-2026-08.md]: high-n-route-server-v0680-2026-08.md
[irr-reload-comparison-2026-08.md]: irr-reload-comparison-2026-08.md
[irr-reload-grouped-per-client-best-2026-08.md]: irr-reload-grouped-per-client-best-2026-08.md
[irr-reload-realistic-mix-2026-08.md]: irr-reload-realistic-mix-2026-08.md
[irr-reload-v0680-2026-08.md]: irr-reload-v0680-2026-08.md
[irr-transactional-apply-2026-08.md]: irr-transactional-apply-2026-08.md
[ixp-dualstack-2026-09.md]: ixp-dualstack-2026-09.md
[ixp-matrix-2026-07.md]: ixp-matrix-2026-07.md
[known-path-accounting-2026-07.md]: known-path-accounting-2026-07.md
[lean-daemon-build-flavors-2026-07.md]: lean-daemon-build-flavors-2026-07.md
[memory-attribution-2026-08.md]: memory-attribution-2026-08.md
[mrt-snapshot-allocation-2026-07.md]: mrt-snapshot-allocation-2026-07.md
[otc-pristine-reconcile-2026-07.md]: otc-pristine-reconcile-2026-07.md
[outbound-prefix-limit-admission-compaction-2026-07.md]: outbound-prefix-limit-admission-compaction-2026-07.md
[outbound-prefix-limit-recovery-slicing-2026-07.md]: outbound-prefix-limit-recovery-slicing-2026-07.md
[outbound-prefix-limit-scale-2026-07.md]: outbound-prefix-limit-scale-2026-07.md
[outbound-prefix-limits-2026-07.md]: outbound-prefix-limits-2026-07.md
[per-peer-rss-attribution-2026-07.md]: per-peer-rss-attribution-2026-07.md
[persisted-config-serialization-2026-08.md]: persisted-config-serialization-2026-08.md
[policy-attribution-criterion-2026-07.md]: policy-attribution-criterion-2026-07.md
[policy-fallback-per-peer-handoff-2026-07.md]: policy-fallback-per-peer-handoff-2026-07.md
[policy-regroup-shared-plan-2026-07.md]: policy-regroup-shared-plan-2026-07.md
[private-single-best-fanout-2026-07.md]: private-single-best-fanout-2026-07.md
[probe-mp-reach-borrowed-attrs-2026-08.md]: probe-mp-reach-borrowed-attrs-2026-08.md
[rebaseline-2026-07.md]: rebaseline-2026-07.md
[reload-authoritative-batch-discriminator-2026-08.md]: reload-authoritative-batch-discriminator-2026-08.md
[reload-flush-envelope-2026-07.md]: reload-flush-envelope-2026-07.md
[reload-generation-phase-attribution-2026-08.md]: reload-generation-phase-attribution-2026-08.md
[reload-stall-2026-07.md]: reload-stall-2026-07.md
[revised-update-duplicate-table-2026-07.md]: revised-update-duplicate-table-2026-07.md
[rib-criterion-noise-floor-2026-07.md]: rib-criterion-noise-floor-2026-07.md
[rib-memory-v0680-2026-08.md]: rib-memory-v0680-2026-08.md
[rib-ops-prefix-fixture-audit-2026-08.md]: rib-ops-prefix-fixture-audit-2026-08.md
[rib-rebaseline-2026-07-13.md]: rib-rebaseline-2026-07-13.md
[rib-route-paging-2026-07.md]: rib-route-paging-2026-07.md
[route-server-1000-2026-07.md]: route-server-1000-2026-07.md
[scale-receipt-2026-07.md]: scale-receipt-2026-07.md
[shared-source-ordering-2026-07.md]: shared-source-ordering-2026-07.md
[unicast-prefix-announcer-index-2026-08.md]: unicast-prefix-announcer-index-2026-08.md
[v0.61.0-final-performance-2026-07.md]: v0.61.0-final-performance-2026-07.md
[vpn-rib-query-occupancy-method.md]: vpn-rib-query-occupancy-method.md
[wire-codec-allocation-2026-07.md]: wire-codec-allocation-2026-07.md

## Supporting records

These files retain manifests, raw-output indexes, comparisons, verifier
summaries, and reproduction instructions. Their title and date are taken only
from that file; a directory name does not fill a missing date.

| Document | Date stated | Workload, shape, or role | Establishes | Does not establish |
|---|---|---|---|---|
| [`artifacts/adj-rib-out-family-gauge-2026-07/README.md`](artifacts/adj-rib-out-family-gauge-2026-07/README.md) | Unstated | Exact unrounded estimates and controls for the linked family-gauge receipt | Unstated | Unstated |
| [`artifacts/adj-rib-out-family-gauge-2026-07/rejected-attempts.md`](artifacts/adj-rib-out-family-gauge-2026-07/rejected-attempts.md) | Unstated | Preflight-invalid and threshold-crossing attempts | Why those attempts were excluded | A retained result |
| [`artifacts/attribute-layout-2026-08/README.md`](artifacts/attribute-layout-2026-08/README.md) | Unstated | 100k, 500k, and 900k structural rows plus a 200k-route bgperf2 result | The container-layout migration was rejected before a prototype | A live-byte A/B or throughput result |
| [`artifacts/competitive-bgperf2-2026-07/README.md`](artifacts/competitive-bgperf2-2026-07/README.md) | 2026-07 | Four daemons, five fleet shapes, and three runs per shape | The retained inputs can recompute the linked receipt | Unstated |
| [`artifacts/competitive-bgperf2-v0680-2026-08/README.md`](artifacts/competitive-bgperf2-v0680-2026-08/README.md) | Unstated | Eighty rows across five fixed import shapes | The retained row and image inventory | A full-table campaign |
| [`artifacts/controller-injection-2026-09/README.md`](artifacts/controller-injection-2026-09/README.md) | Unstated | Eight completed controller-injection cells with passive-receiver counts, paginated reconciliation, and metrics snapshots | The retained result and evidence inventory for the linked receipt | Unstated |
| [`artifacts/current-scale-v0680-2026-08/README.md`](artifacts/current-scale-v0680-2026-08/README.md) | Unstated | IXP-700 S2/S3, route-server-1000, and three RR1000 runs | Compact source-equivalent v0.68.0 evidence | Unstated |
| [`artifacts/enhanced-route-refresh-2026-07/README.md`](artifacts/enhanced-route-refresh-2026-07/README.md) | Unstated | One Enhanced Route Refresh peer with 100,000 IPv4 unicast routes | Retained phase, actor-duration, and memory boundaries | A 1M-route result |
| [`artifacts/enhanced-route-refresh-v0680-2026-08/README.md`](artifacts/enhanced-route-refresh-v0680-2026-08/README.md) | Unstated | Exact-release phase, correctness, actor-duration, and memory observations | The compact summary and provenance inventory | Unstated |
| [`artifacts/event-history-producer-2026-07/README.md`](artifacts/event-history-producer-2026-07/README.md) | 2026-07 | Criterion phases and four enabled/disabled full-daemon profiles | The machine-artifact and verdict inventory | Unstated |
| [`artifacts/explain-cache-opt-in-2026-07/README.md`](artifacts/explain-cache-opt-in-2026-07/README.md) | Unstated | Real-daemon explain-cache memory campaign across two source trees | The bounded retained artifact inventory | Unstated |
| [`artifacts/fanout-source-stack-2026-07/README.md`](artifacts/fanout-source-stack-2026-07/README.md) | Unstated | Four six-attempt, five-shape Criterion comparisons | Exact aggregate statistics and retained inputs | Unstated |
| [`artifacts/fanout-source-stack-2026-07/metrics-before-after-summary.md`](artifacts/fanout-source-stack-2026-07/metrics-before-after-summary.md) | Unstated | Criterion before/after comparison summary | No confident regressions under the configured rule | Unstated |
| [`artifacts/fanout-source-stack-2026-07/metrics-same-sha-summary.md`](artifacts/fanout-source-stack-2026-07/metrics-same-sha-summary.md) | Unstated | Criterion same-SHA comparison summary | No confident regressions under the configured rule | Unstated |
| [`artifacts/fanout-source-stack-2026-07/otc-before-after-summary.md`](artifacts/fanout-source-stack-2026-07/otc-before-after-summary.md) | Unstated | OTC before/after Criterion comparison summary | No confident regressions under the configured rule | Unstated |
| [`artifacts/fanout-source-stack-2026-07/otc-same-sha-summary.md`](artifacts/fanout-source-stack-2026-07/otc-same-sha-summary.md) | Unstated | OTC same-SHA Criterion comparison summary | No confident regressions under the configured rule | Unstated |
| [`artifacts/grouped-exact-precommit-2026-07/README.md`](artifacts/grouped-exact-precommit-2026-07/README.md) | 2026-07 | Campaign 3 of the grouped exact-export fanout receipt | Retained result rows, hashes, gate decisions, and completion marker | Unstated |
| [`artifacts/grouped-private-adj-rib-out-late-join-2026-07/README.md`](artifacts/grouped-private-adj-rib-out-late-join-2026-07/README.md) | Unstated | Same-host A/B/B/A late-join campaign | The complete retained inputs for the linked receipt | Unstated |
| [`artifacts/grouped-withdrawal-fanout-2026-07/README.md`](artifacts/grouped-withdrawal-fanout-2026-07/README.md) | Unstated | Exact-commit grouped-withdrawal baseline campaign | Retained estimates, workload, and claim boundary | Unstated |
| [`artifacts/grouped-withdrawal-probe-skip-2026-07/README.md`](artifacts/grouped-withdrawal-probe-skip-2026-07/README.md) | Unstated | A/B/B/A grouped-withdrawal exact-probe campaign at 8, 64, 256, and 1,000 members | A manager-path improvement at 64, 256, and 1,000 members | An 8-member, full-daemon, convergence, or network-throughput result |
| [`artifacts/headline-refresh-v0720-2026-09/README.md`](artifacts/headline-refresh-v0720-2026-09/README.md) | 2026-09-26 | Matrix, IRR 0%, and RR1000 runs for v0.72.0 and current main | Logs, status, provenance, RSS samples, and a per-value summary | Full daemon logs or scenario configurations |
| [`artifacts/high-n-route-server-v0680-2026-08/README.md`](artifacts/high-n-route-server-v0680-2026-08/README.md) | Unstated | Exact-source 2,500- and 5,000-peer runs | Status, timing, settled RSS, and provenance rows | A replayable binary package |
| [`artifacts/honor-policy-waits-2026-09-12/README.md`](artifacts/honor-policy-waits-2026-09-12/README.md) | 2026-09-12 | Two honor-only SIGHUP edits across 1,000 eBGP peers with timed CLI probes | Every call met the 2-second budget and both reloads completed at the candidate revision | Soak qualification or a general operator deadline |
| [`artifacts/installed-import-counters-2026-09-13/README.md`](artifacts/installed-import-counters-2026-09-13/README.md) | Unstated | Installed import-counter descriptor construction, publication, and release at 1,000 peers | Allocation counts, requested bytes, and elapsed ranges for the disclosed label and cache shapes | A cold/warm speedup comparison or configuration limit |
| [`artifacts/installed-import-counters-isolated-2026-09-13/README.md`](artifacts/installed-import-counters-isolated-2026-09-13/README.md) | 2026-09-13 | Isolated-generator CPU placement control of the import-counter diagnostic | A comparison under the observed phase and delivered load | A scheduler-cause proof, soak qualification, or release gate |
| [`artifacts/irr-reload-comparison-2026-08/README.md`](artifacts/irr-reload-comparison-2026-08/README.md) | 2026-08 | Four verified sealed comparison roots | Verifier output and sealed-root identity digests | Unstated |
| [`artifacts/irr-reload-grouped-per-client-best-2026-08/README.md`](artifacts/irr-reload-grouped-per-client-best-2026-08/README.md) | 2026-08 | Eight roots across announcement overlap points 0.1 and 0.5 | Verifier output, received-view identities, and root digests | Unstated |
| [`artifacts/irr-reload-realistic-mix-2026-08/README.md`](artifacts/irr-reload-realistic-mix-2026-08/README.md) | 2026-08 | Eight roots across announcement overlap points 0.1 and 0.5 | Verifier output and sealed-root identity digests | Unstated |
| [`artifacts/irr-reload-v0680-2026-08/README.md`](artifacts/irr-reload-v0680-2026-08/README.md) | 2026-08-30 | Twenty-four comparison and eight grouped-control rows per overlap point | Every verifier-approved row and derived RSS peak | An exact-tag run |
| [`artifacts/irr-transactional-apply-2026-08/README.md`](artifacts/irr-transactional-apply-2026-08/README.md) | 2026-08 | Two verified sealed transactional-apply roots | Verifier output, transaction lifecycle, and identity digests | Unstated |
| [`artifacts/ixp-exact-export-cohorts-2026-07/README.md`](artifacts/ixp-exact-export-cohorts-2026-07/README.md) | Unstated | IXP exact-export cohort summaries and production state-machine counters | Aggregate estimates and first-invocation counters | Raw samples |
| [`artifacts/ixp-dualstack-final-campaign-2026-09/README.md`](artifacts/ixp-dualstack-final-campaign-2026-09/README.md) | 2026-09-10 | Source/build binding, complete command capture, and both gate versions | All 13 measurements, complete health capture, and reproducible original/supplemental assessments | Replacing original failures or qualifying another binary |
| [`artifacts/ixp-dualstack-2026-09-08/README.md`](artifacts/ixp-dualstack-2026-09-08/README.md) | 2026-09-08 | Source/binary binding and dual-stack operating cells | Four 200-member cells, warning review, and retained failed 200- and 700-member diagnostics | Unrun acceptance cells or complete 700-member operating proof |
| [`artifacts/ixp-dualstack-2026-09/README.md`](artifacts/ixp-dualstack-2026-09/README.md) | 2026-09 | Pinned dual-stack shape (400,400 total = 200,200 per family at 700 members) and the 20-member correctness cells | The shape definition committed before measurement and the rung-1 raw cells | A 700-member result |
| [`artifacts/ixp-dualstack-policy-noops-2026-09/README.md`](artifacts/ixp-dualstack-policy-noops-2026-09/README.md) | Unstated | Inputs, instruments, gate, and build bindings for the 200- and 700-member policy-reload reduction cells | The retained evidence behind the linked receipt, including the failed 700-member cell | Rewritten earlier measurements |
| [`artifacts/ixp-dualstack-readiness-2026-09/README.md`](artifacts/ixp-dualstack-readiness-2026-09/README.md) | Unstated | Seven completed readiness cells with source and build bindings | Per-cell gate results and health-capture completeness | A qualification of another binary |
| [`artifacts/ixp-initial-export-readiness-2026-09/README.md`](artifacts/ixp-initial-export-readiness-2026-09/README.md) | Unstated | Readiness-corrected 702-member cell evidence, original qualification, and provenance | The retained evidence; the sole qualification failure is a teardown `ConnectionReset` warning | Unstated |
| [`artifacts/ixp-matrix-2026-07/README.md`](artifacts/ixp-matrix-2026-07/README.md) | 2026-07 | Seven hundred peers and 400,400 prefixes across three daemons | Raw data behind the linked route-server matrix | Unstated |
| [`artifacts/ixp-membership-churn-2026-09/README.md`](artifacts/ixp-membership-churn-2026-09/README.md) | Unstated | 20+2 preparation, 702-member qualification, and v0.70.0 first-reload rejection archives | Preparation passes; the 702-member qualification fails on eight health deadlines | Unstated |
| [`artifacts/ixp-membership-churn-qualified-2026-09/README.md`](artifacts/ixp-membership-churn-qualified-2026-09/README.md) | Unstated | Fresh 702-member cell with initial-export readiness service and the corrected terminal lifecycle | The original passing qualification and its provenance | Unstated |
| [`artifacts/known-path-accounting-2026-07/README.md`](artifacts/known-path-accounting-2026-07/README.md) | July 2026 | Eight admitted bgperf2 rows with sixteen BIRD logs | The manifest, route-count rows, and zero `RMT` log scan | Independent timeout evidence from bgperf2's structural field |
| [`artifacts/memory-attribution-2026-08/README.md`](artifacts/memory-attribution-2026-08/README.md) | 2026-08 | Seven sealed coarse-to-single-commit campaigns | Preregistered manifests, result tables, verdicts, and identity seals | Unstated |
| [`artifacts/mrt-snapshot-allocation-2026-07/README.md`](artifacts/mrt-snapshot-allocation-2026-07/README.md) | Unstated | Two-shape ordinary and warm-checkpoint allocation control | Feasibility evidence for a separately measured candidate | A future candidate's speedup or timing comparator |
| [`artifacts/operator-query-wait-2026-09-12/README.md`](artifacts/operator-query-wait-2026-09-12/README.md) | 2026-09-12 | Two reloads of a 1,000-peer route server with 16 timed CLI calls | The exported operator query wait histogram reconciles with the observed calls | Soak qualification or a general operator deadline guarantee |
| [`artifacts/outbound-prefix-limit-admission-compaction-2026-07/README.md`](artifacts/outbound-prefix-limit-admission-compaction-2026-07/README.md) | Unstated | One cell per revision and fleet size through 100 members and 400,000 IPv4 routes | The acceptance allocator delta and behavior summary | Exact retained-heap ownership, run variance, or larger-shape extrapolation |
| [`artifacts/outbound-prefix-limit-recovery-slicing-2026-07/README.md`](artifacts/outbound-prefix-limit-recovery-slicing-2026-07/README.md) | Unstated | One source, 400,000 IPv4 routes, and 1, 10, or 100 recovering members | The six-cell recovery summary | Run variance or reduced total replay work |
| [`artifacts/outbound-prefix-limit-scale-2026-07/README.md`](artifacts/outbound-prefix-limit-scale-2026-07/README.md) | Unstated | One source and 400,000 IPv4 routes across the retained fleet sizes | Scale rows and adjacent same-SHA control subtraction | Run-to-run variance |
| [`artifacts/per-peer-rss-attribution-2026-07/README.md`](artifacts/per-peer-rss-attribution-2026-07/README.md) | Unstated | Real-daemon peer and BASE-route RSS attribution campaign | The exact 6,150,300-byte eager-reserve allocation stack | An attributable RSS improvement |
| [`artifacts/persisted-config-serialization-2026-08/README.md`](artifacts/persisted-config-serialization-2026-08/README.md) | Unstated | AB/BA/AB serialization of 320 policy definitions with 10,000 statements each | Byte identity and the retained memory and latency gates | Unstated |
| [`artifacts/policy-attribution-criterion-2026-07/README.md`](artifacts/policy-attribution-criterion-2026-07/README.md) | Unstated | Six-attempt policy-attribution Criterion package | The retained row classifications and verifier inputs | Unstated |
| [`artifacts/policy-attribution-criterion-2026-07/control-summary.md`](artifacts/policy-attribution-criterion-2026-07/control-summary.md) | Unstated | Same-SHA Criterion comparison summary | No confident regressions under the configured rule | Unstated |
| [`artifacts/policy-attribution-criterion-2026-07/isolated-summary.md`](artifacts/policy-attribution-criterion-2026-07/isolated-summary.md) | Unstated | Isolated Criterion comparison summary | No confident regressions under the configured rule | Unstated |
| [`artifacts/policy-attribution-criterion-2026-07/red-proofs.md`](artifacts/policy-attribution-criterion-2026-07/red-proofs.md) | Unstated | Independent verifier mutations | The named mutations make their verifier paths fail | Unstated |
| [`artifacts/policy-reload-cohort-partition-2026-07/README.md`](artifacts/policy-reload-cohort-partition-2026-07/README.md) | Unstated | Seven hundred sessions, 400,400 routes, 600 changed peers, 100 stable peers, and four reloads | Completion p50 improved 116.185 times while delivery-gap p50 worsened 2.070 times | An unconditional performance acceptance or sub-second delivery stall |
| [`artifacts/policy-reload-cohort-partition-2026-07/REPRODUCE.md`](artifacts/policy-reload-cohort-partition-2026-07/REPRODUCE.md) | Unstated | Reproduction instructions for the mixed export-policy reload campaign | Unstated | Unstated |
| [`artifacts/policy-set-store-2026-07/README.md`](artifacts/policy-set-store-2026-07/README.md) | 2026-07 | Common sets at 1, 10, 100, and 1,000 peers plus unique sets around 32-peer chunk boundaries | Bounded chunk sharing passed its common-set and unique-set gates | Arbitrarily many distinct sets per peer or a shipped CPU-regression claim |
| [`artifacts/policy-stats-owner-published-2026-09-26/README.md`](artifacts/policy-stats-owner-published-2026-09-26/README.md) | 2026-09-26 | Isolated `GetPolicyStats` reload cell at 1,000 route-server peers across the ADR-0136 slices | The in-band summed capture stage fell from 469 ms to under 1 ms on merged main, passing the flat criterion at this shape | Soak qualification, larger fleets, other placements or a general operator deadline |
| [`artifacts/private-single-best-fanout-2026-07/README.md`](artifacts/private-single-best-fanout-2026-07/README.md) | Unstated | Sanitized control and A/B summaries with exact Criterion estimates | The retained artifact inventory | Unstated |
| [`artifacts/private-single-best-fanout-2026-07/ab-summary.md`](artifacts/private-single-best-fanout-2026-07/ab-summary.md) | Unstated | Private single-best A/B Criterion summary | No confident regressions under the configured rule | Unstated |
| [`artifacts/private-single-best-fanout-2026-07/control-summary.md`](artifacts/private-single-best-fanout-2026-07/control-summary.md) | Unstated | Private single-best same-SHA Criterion summary | No confident regressions under the configured rule | Unstated |
| [`artifacts/raw-bridge-event-skew-2026-08/README.md`](artifacts/raw-bridge-event-skew-2026-08/README.md) | 2026-08-31 | One 4,000-pair run for each of six kernel and traffic-profile tuples | Every measured pair was FDB-first, with descriptive inter-arrival observations | Variance, a worst-case bound, freshness window, kernel regression, or production behavior |
| [`artifacts/reload-generation-phase-attribution-2026-08/README.md`](artifacts/reload-generation-phase-attribution-2026-08/README.md) | Unstated | Two four-row campaigns with 320 sessions | Later-reload growth is inside the synchronous batched authoritative RIB transition | The internal mechanism, an improvement, or authorization to optimize |
| [`artifacts/reload-stall-2026-07-16/README.md`](artifacts/reload-stall-2026-07-16/README.md) | 2026-07-16 | Accepted 700-member, 400,400-route reload-stall campaign outputs | The raw outputs behind the linked receipt's current numbers | Unstated |
| [`artifacts/revised-update-duplicate-table-2026-07/README.md`](artifacts/revised-update-duplicate-table-2026-07/README.md) | Unstated | Six same-revision and six immediate-baseline/candidate pairs plus allocation diagnostics | One allocation and 48 requested bytes removed per call, plus a narrower fixture-scoped timing separation | A formal bias correction, daemon, fleet, full-table, network, convergence, or RSS result |
| [`artifacts/revised-update-duplicate-table-2026-07/REPRODUCE.md`](artifacts/revised-update-duplicate-table-2026-07/REPRODUCE.md) | Unstated | Reproduction instructions for the duplicate-table comparisons | Unstated | Unstated |
| [`artifacts/revised-update-duplicate-table-2026-07/control-summary.md`](artifacts/revised-update-duplicate-table-2026-07/control-summary.md) | Unstated | Same-revision Criterion comparison summary | No confident regressions under the configured rule | Unstated |
| [`artifacts/revised-update-duplicate-table-2026-07/target-summary.md`](artifacts/revised-update-duplicate-table-2026-07/target-summary.md) | Unstated | Immediate-baseline/candidate Criterion summary | No confident regressions under the configured rule | Unstated |
| [`artifacts/rib-criterion-noise-floor-2026-07/README.md`](artifacts/rib-criterion-noise-floor-2026-07/README.md) | Unstated | Four six-attempt Criterion comparisons | The retained noise-floor and isolated-row evidence | Unstated |
| [`artifacts/rib-criterion-noise-floor-2026-07/runs/control-adj-rib-in-same-sha/summary.md`](artifacts/rib-criterion-noise-floor-2026-07/runs/control-adj-rib-in-same-sha/summary.md) | Unstated | Adj-RIB-In same-SHA Criterion summary | No confident regressions under the configured rule | Unstated |
| [`artifacts/rib-criterion-noise-floor-2026-07/runs/control-pipeline-bulk-same-sha/summary.md`](artifacts/rib-criterion-noise-floor-2026-07/runs/control-pipeline-bulk-same-sha/summary.md) | Unstated | Pipeline and bulk same-SHA Criterion summary | No confident regressions under the configured rule | Unstated |
| [`artifacts/rib-criterion-noise-floor-2026-07/runs/llgr-tag-guard-isolated/summary.md`](artifacts/rib-criterion-noise-floor-2026-07/runs/llgr-tag-guard-isolated/summary.md) | Unstated | Isolated LLGR tag-guard Criterion summary | No confident regressions under the configured rule | Unstated |
| [`artifacts/rib-criterion-noise-floor-2026-07/runs/v0.60.0-to-head/summary.md`](artifacts/rib-criterion-noise-floor-2026-07/runs/v0.60.0-to-head/summary.md) | Unstated | v0.60.0-to-head Criterion summary | No confident regressions under the configured rule | Unstated |
| [`artifacts/rib-memory-v0680-2026-08/README.md`](artifacts/rib-memory-v0680-2026-08/README.md) | Unstated | Twelve shared v0.67/v0.68 shapes and six v0.68-only shapes | The complete compact comparison output | A/B deltas for the six v0.68-only rows |
| [`artifacts/rib-rebaseline-2026-07-13/README.md`](artifacts/rib-rebaseline-2026-07-13/README.md) | 2026-07-13 | Eight CPU profiles and the full-daemon memory-attribution run | The revision-pinned artifact and classifier inventory | Unstated |
| [`artifacts/rib-route-paging-2026-07/README.md`](artifacts/rib-route-paging-2026-07/README.md) | 2026-07-13 | Four-repetition route-paging matrix | The retained matrix and manifest inventory | Unstated |
| [`artifacts/rib-route-paging-2026-07/ordered-index-ab/ab-final-post-fix.md`](artifacts/rib-route-paging-2026-07/ordered-index-ab/ab-final-post-fix.md) | Unstated | Three-group ordered-index post-fix A/B | Confident recompute regressions remained at sizes 1, 2, 4, and 8 | Unstated |
| [`artifacts/rib-route-paging-2026-07/ordered-index-ab/ab-initial-repro.md`](artifacts/rib-route-paging-2026-07/ordered-index-ab/ab-initial-repro.md) | Unstated | Two-attempt initial ordered-index reproduction | No confident regressions under the configured rule | A conclusion beyond the insufficient attempt count |
| [`artifacts/rib-route-paging-2026-07/ordered-index-ab/ab-noop-discriminator.md`](artifacts/rib-route-paging-2026-07/ordered-index-ab/ab-noop-discriminator.md) | Unstated | Three-attempt no-op-body discriminator | Confident recompute regressions at sizes 1, 4, and 8 | Unstated |
| [`artifacts/rib-route-paging-2026-07-route-churn-control.md`](artifacts/rib-route-paging-2026-07-route-churn-control.md) | 2026-07-13 | Four counterbalanced route-churn comparisons | No confident regression | Unstated |
| [`artifacts/rib-summary-rollback-2026-09-12/README.md`](artifacts/rib-summary-rollback-2026-09-12/README.md) | 2026-09-12 | Baseline/candidate pair of authoritative rollbacks at 1,000 route-server peers | Both runs kept operator reads within the 2-second deadline; the candidate served eight calls inside its frozen-summary interval | A reproduced baseline deadline failure or a speedup |
| [`artifacts/route-server-1000-2026-07/README.md`](artifacts/route-server-1000-2026-07/README.md) | Unstated | Real-daemon 1,000-peer route-server campaign artifacts | The bounded retained artifact inventory | Unstated |
| [`artifacts/selection-deferral-release-v0680-2026-08/README.md`](artifacts/selection-deferral-release-v0680-2026-08/README.md) | Unstated | Three timer-release modes at 700 peers and 400,400 routes, five runs per variant | Fully reusable homogeneous-wire cohorts improved 35.83 to 66.09 times | Whole-daemon convergence, policy reload timing, mixed-capability fleets, or fallback paths |
| [`artifacts/session-notification-flapstorm-2026-08/README.md`](artifacts/session-notification-flapstorm-2026-08/README.md) | 2026-08-25 | One 700-session, 400,400-prefix run with three 50-session flap rounds | All ten checkpoints drained notification accounting to zero | Handling completion, queue capacity, latency, memory, or an optimization bound |
| [`artifacts/unicast-prefix-announcer-index-2026-08/README.md`](artifacts/unicast-prefix-announcer-index-2026-08/README.md) | Unstated | Isolated allocator rows and 24 accepted A/B pairs from three campaigns | The verifier-bound memory and paired-result inventory | Unstated |
| [`artifacts/v0.61.0-final-performance-2026-07/README.md`](artifacts/v0.61.0-final-performance-2026-07/README.md) | Unstated | Three real-daemon route-server runs and one Criterion archive | The absolute release-tip baseline artifact inventory | An A/B optimization or CPU-delta claim |
| [`artifacts/v0.61.0-final-performance-2026-07/commands.md`](artifacts/v0.61.0-final-performance-2026-07/commands.md) | Unstated | Reproduction commands for the release-tip baseline | Unstated | Unstated |
| [`artifacts/wire-codec-allocation-2026-07/README.md`](artifacts/wire-codec-allocation-2026-07/README.md) | Unstated | Rich attribute-encode and six-attribute validation artifacts | The retained estimates, diagnostics, controls, and hashes | Unstated |
| [`artifacts/wire-codec-allocation-2026-07/red-proofs.md`](artifacts/wire-codec-allocation-2026-07/red-proofs.md) | Unstated | Six mutation-sensitive allocation-receipt gates | Exact output, error semantics, and diagnostic sensitivity | RSS, jemalloc, retained or peak heap, deallocation, or whole-daemon evidence |
| [`artifacts/wire-codec-production-parser-2026-07/README.md`](artifacts/wire-codec-production-parser-2026-07/README.md) | Unstated | Production parser, IPv6 MP Add-Path, and attribute encode/decode rows | Production-path coverage and sensitivity to each named path | An optimization or before/after performance gain |

## Metadata gaps

The index covers all 133 pre-existing Markdown files: 60 primary records and
73 supporting records. Supporting artifacts often rely on their parent receipt
for context; this index deliberately leaves their own missing metadata as
`Unstated` instead of copying it down.

Among primary records, every file states a workload or shape. Three do not
state a date:

- [`grouped-private-adj-rib-out-late-join-2026-07.md`][grouped-private-adj-rib-out-late-join-2026-07.md]
- [`policy-attribution-criterion-2026-07.md`][policy-attribution-criterion-2026-07.md]
- [`vpn-rib-query-occupancy-method.md`][vpn-rib-query-occupancy-method.md]

Every primary record states a claim and claim boundary. In the supporting
table, 55 files do not state their own date, four do not state an independent
claim, and 47 do not state an independent claim boundary. Those gaps appear as
`Unstated` in the affected row; every supporting file states at least its role
or workload.

Both tables derive every field from the linked record rather than treating a
filename, parent directory, or neighboring receipt as evidence.
