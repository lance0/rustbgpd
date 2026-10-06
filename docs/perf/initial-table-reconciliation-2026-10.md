# Initial-table reconciliation qualification, October 2026

Skipping redundant successful-export reconciliation reduced first-survivor
UPDATE latency by 23.660 ms (18.188%) in this ordinary 700-peer flap workload.
The candidate passed the predeclared payoff and regression limits across six
fresh daemon processes. All rounds, including an unusually fast control round
and withdrawal-tail regressions, remain in the evidence.

Measured on 2026-10-06. The [compact receipt](artifacts/initial-table-reconciliation-2026-10/README.md)
recomputes the comparison from all 18 rounds, 900 returning-peer observations
and 11,700 survivor observations. There are **three independent processes per
arm**, each with three correlated rounds; nine rounds are not nine independent
processes.

## Change and result

The shared outbound commit previously reconciled every candidate against the
rejected-route overlay unless it carried the clean grouped-delta prior. An
initial dump carries no such prior. When every exact-export probe succeeds and
the peer has no rejection overlay, that reconciliation keeps every candidate
and produces no withdrawal regardless of prior state or source exclusion.
The candidate extends the existing shortcut to this case. It retains exact
wire probes, the session-owned immutable snapshot, failure reconciliation,
capacity admission, and table-before-End-of-RIB ordering.

This is a bounded deletion in
[`distribution/mod.rs`](../../crates/rib/src/manager/distribution/mod.rs).
It does not batch registrations or introduce a persistent probe cache. Initial
replay, exact probing and per-session encoding still perform per-peer work.
The earlier [phase attribution](first-update-phase-attribution-2026-10.md)
motivated the experiment; its measurements are a separate source cohort.

The table reports the median of nine per-round quantiles per arm. “Round max”
is the median of nine round maxima, not the worst observed value.

| Endpoint | Control | Candidate | Change |
|---|---:|---:|---:|
| First-survivor UPDATE p50 | 130.086 ms | 106.426 ms | −23.660 ms / −18.188% |
| First-survivor UPDATE p95 | 131.584 ms | 107.958 ms | −17.955% |
| Full survivor reannouncement p50 | 274.815 ms | 252.001 ms | −8.302% |
| Withdrawal p50 | 244.580 ms | 247.761 ms | +1.301% |
| Withdrawal round max | 263.011 ms | 254.871 ms | −3.095% |
| Returning-peer completion p50 | 4.160038 s | 3.387751 s | −18.564% |
| Returning-peer completion round max | 7.823069 s | 6.310254 s | −19.338% |

Matched process-pair changes in first-arrival p50 were −19.243%, −17.309%
and −19.231%. Each pair compares the median of its three rounds. All 150
returning-peer process-pair medians also improved, by 7.662%–19.694%.
[The comparison](artifacts/initial-table-reconciliation-2026-10/comparison.json)
retains every endpoint's p50/p95/max, six process medians, three pair changes
and all 50 returning identities per pair.

The withdrawal diagnostics limit the conclusion:

- The third pair's median withdrawal round max increased **3.958%**.
- The absolute worst withdrawal increased from **275.378 to 280.428 ms**
  (**1.834%**), despite the improved median of round maxima.
- Control process 04, round 2 had unusually fast first/full reannouncement
  p50s of **7.852/153.961 ms**. It remains in every relevant aggregate.

The candidate therefore improves the declared median/pair endpoints in this
receipt; neither every round nor every maximum improves.

## Workload and clocks

This is ordinary S3 withdrawal/reannouncement on native loopback: 700 peers,
400,400 disjoint IPv4 prefixes (572 per source), 50 returning peers, 28,600
affected prefixes and eight ongoing churners. Readers are unpaced, with no
added RTT or GR retention. The daemon used its default jemalloc release build
and eight workers; the common scale-profile harness used 24 workers. Packing
settings were unchanged. No daemon phase instrumentation was present.

Order was control/candidate/candidate/control/control/candidate, three rounds
per fresh process: matched AB/BA/AB pairs, not perfectly position balanced.
Each leg passed the native host lock and two accepted quiet samples at least
30 seconds apart, then completed the full 300-second cooldown, including the
last leg. No other lab or build ran during the campaign.

The survivor clock starts after all 50 returning sessions reach Established,
immediately before their announcements are queued. First arrival is the first
UPDATE containing any base announcement, observed after frame reading, decode
and classification. It is not a kernel or packet-capture timestamp. The
separate first-affected-prefix stamp equals that published first-any stamp in
**all 11,700 survivor-rounds**, with no affected stamp before the trigger.

Each returning peer's clock starts after its successful OPEN write and ends
when both IPv4 EoR and the exact current full table excluding its own source
are present. All 900 returning records have 399,828 unique prefixes and an EoR;
the retained current-full timestamp never follows the latched completion.
In ordinary S3, EoR can precede restored full-table coverage: completion requires
both. This is separate from historical GR-retained converged-rejoin timing.

All 18 rounds retained 700/700 sessions, zero parse errors, full native
withdraw/reannouncement bitmap coverage and **531 readiness samples with zero
failures** at the existing 250 ms deadline. Every native harness, daemon,
HTTP and cleanup check passed. Before/after source and binary freezes matched;
process identities and monotonic stage records confirm six fresh processes
in the declared order. Cleanup left no owned processes or runtime scenario,
and the host lock was available.

## Frozen acceptance and reproducibility

Acceptance required at least **20 ms and 10%** improvement in first-arrival
p50, with all three matched process pairs improving; withdrawal and full
reannouncement p50 regression no greater than 3%; and no increase in returning
completion p50 or the median round max. **All seven conditions passed.**
The withdrawal maximum diagnostics above were retained for review; they were
not additional acceptance thresholds introduced after measurement.

Control source was `49abbb0171cbb889b7e2618c2bdcec6ea35699ae`; candidate source
was its clean descendant `6a715b409130b694a48fc20cefb115cd951f1423`. Subsequent
report files do not change the measured runtime. Both release producers used
`cargo build --locked --release --bin rustbgpd` with eight build jobs and
Rust 1.99.0. The complete selected dependency graphs matched: 345 nodes,
including build-script and proc-macro edges, with identical settings/features.
Actual RIB/daemon compiler arguments matched after path normalization.

The common [qualification patch](artifacts/initial-table-reconciliation-2026-10/common-qualification.patch)
adds post-round precision/coverage records, the existing readiness watcher,
and native HTTP/lifecycle receipts. It is outside shipped runtime code and is
identical for both arms. Binary, patch and build identities are recorded in
[provenance](artifacts/initial-table-reconciliation-2026-10/provenance.json).
An earlier source cohort was aborted after main changed; its sole control leg
is archived separately within the raw package and contributes no samples here.

The retained, unpublished raw package is
`initial-table-reconciliation-2026-10-06.tar.gz`, SHA-256
`f984db31ec891cf3b96fa8e0a0033b5a734b9465d0da3e0c0a9b630a94a97b49`.
It contains raw logs, source snapshots, producer records, fingerprints and
validation receipts. Public compact extracts reproduce the arithmetic and
check compact assertions; they do not independently reproduce raw extraction
or build provenance.

Local correctness validation at the measured runtime commit passed the full
gate (10,454 tests, zero failures) and feature-gated RIB checks. The initial
dump regression fails with the old eligibility guard restored and passes with
the shortcut. Differential tests cover grouped/private joins, source exclusion,
rejection, seven-family payloads, retained snapshots, withdrawal and EoR order.

No comparator daemon was run. This receipt establishes no current OpenBGPD
ranking, general scale bound, or result outside the disclosed workload.
