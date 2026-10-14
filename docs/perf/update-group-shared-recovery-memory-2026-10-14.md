# Shared update-group recovery memory (14 October 2026)

> **Document class: HISTORICAL.** This receipt covers eight fresh hosted VMs
> and pinned synthetic manager-direct RIB workloads. It is not a deployment
> memory or timing guarantee.

The qualified campaign passed all candidate contract checks. It retains 64 legs and 256 phase samples at source `cf80618599e59d9d97f4ea2ddb2deae95e3af830`.
At 256 receivers × 100,000 IPv4 routes, matched whole-scope mean peaks were 0.228303–0.264443 times the intermediate revision. Full-table cohorts retained 123,000,000 admitted proof keys; widening retained 135,300,000. All candidate fallback causes stayed zero. Peak proof reservation charge was 448,352,768 bytes, leaving 88,518,144 bytes of daemon reservation credit.
Final-run control strict failures: 0; candidate strict failures: 0. Refused proofs and failed controls remain visible; they are not relabeled as complete candidate proofs.
The [original receipt](update-group-recovery-memory-2026-10-14.md) remains unchanged;
its roughly fourfold whole-scope peak increase was not accepted as qualification.

## Shape and admission evidence

The original profile is 256 receivers × 100,000 IPv4 unicast routes. Full-table
unicast and VPN profiles use 100 receivers × (1,000,000 IPv4 + 230,000 IPv6 keys).
The VPN profile alternates distinct raw RD encodings with identical display text.
Prefixes, labels and attributes are synthetic fixture data: one source and
homogeneous plain RR clients, with fixed family next hops and no Add-Path or RTC
selection. This is route-key retention scale, not a captured Internet attribute
workload or a deployment memory envelope.
Each profile/cell VM builds the same frozen instrumentation on the original `c862af9338aa828b7462f3cf85781f63b0e79fe8`, intermediate `bdb7bc34dfe0e6a66fc8c0f1d56d3e57184dea00`, and candidate source.
Each selected cell/comparator runs A/B/B/A with two repetitions per arm.
The original baseline predates the admitted-key parity fixes; these are complete
revision comparisons, not an isolated allocation-owner experiment.

Reevaluation and actual source PeerDown pause and fill every receiver queue
before the actor proves simultaneous dirty/group-dirty overlap. Reevaluation
keeps eligibility unchanged and requires zero withdrawals. Source-down requires
one withdrawal per actually admitted exact key and empty final family folds.
Widening admits 100,000 new VPNv4 and 23,000 new VPNv6 keys using one owned queue
credit per member while the peers remain dirty. This is VPN widening in the VPN
profile and **mixed-family** widening in the unicast seed profile; it does not
prove pure-unicast churn. Paused folds still represent the seed; the closed
actor admission barrier and logical proof gauge establish admitted additions.
Final drained folds and family-specific BMP counts must agree.

## Whole-scope peaks

Values are MiB rounded from exact bytes in [comparison.json](artifacts/update-group-shared-recovery-memory-2026-10-14/comparison.json).
Ratios compare only matched arms within one profile/cell/VM; no incomplete or
strictly failed control receives a ratio.

| Profile | Cell | Control | Control peaks (MiB) | Candidate peaks (MiB) | Mean-peak ratio |
| --- | --- | --- | ---: | ---: | ---: |
| ipv4-100k | dataset-reevaluate | baseline | 195.363, 187.926 | 187.016, 187.691 | 0.977610 |
| ipv4-100k | dataset-reevaluate | intermediate | 806.125, 805.203 | 177.340, 190.531 | 0.228303 |
| ipv4-100k | peer-down | baseline | 212.703, 221.793 | 227.535, 218.773 | 1.027187 |
| ipv4-100k | peer-down | intermediate | 858.895, 847.301 | 223.316, 227.875 | 0.264443 |
| full-uc | dataset-reevaluate | baseline | 1358.590, 1368.699 | 1307.324, 1312.637 | 0.960647 |
| full-uc | dataset-reevaluate | intermediate | 1191.594, 1245.375 | 1305.066, 1315.957 | 1.075526 |
| full-uc | peer-down | baseline | 1684.141, 1675.477 | 1735.438, 1753.293 | 1.038431 |
| full-uc | peer-down | intermediate | 1676.285, 1685.492 | 1732.559, 1741.641 | 1.033441 |
| full-vpn | dataset-reevaluate | baseline | 2417.016, 2424.961 | 2475.035, 2475.219 | 1.022362 |
| full-vpn | dataset-reevaluate | intermediate | 2333.969, 2341.879 | 2474.898, 2476.887 | 1.059013 |
| full-vpn | peer-down | baseline | 2807.699, 2804.465 | 2855.383, 2850.695 | 1.016734 |
| full-vpn | peer-down | intermediate | 2806.086, 2802.977 | 2848.980, 2856.895 | 1.017260 |
| full-vpn | widen | baseline | 4010.500, 4016.820 | 4526.297, 4517.402 | 1.126615 |
| full-vpn | widen | intermediate | 4020.652, 4014.121 | 4523.023, 4518.930 | 1.125353 |
| mixed-widen | widen | baseline | 3095.598, 3105.020 | 3573.770, 3513.129 | 1.142934 |
| mixed-widen | widen | intermediate | 3092.070, 3086.816 | 3510.512, 3503.059 | 1.135086 |

These values include the RIB manager, production exact-export preflight,
consumers, queues, bitmaps and owned launcher/checker. They do not attribute
bytes to one allocation owner. No timing, full-daemon, final encoded-wire,
TCP, socket-buffer or full dataset-publication result is claimed.

## Proof charge and refusals

The unchanged budgets are 64 MiB per peer and 512 MiB for the daemon. Shared
key universes and per-member masks are reservation-accounted separately from
whole-scope memory. Sparse admitted additions remain charged.

| Profile | Peak reservation (bytes) | Remaining daemon budget (bytes) | Retained logical proof entries |
| --- | ---: | ---: | ---: |
| ipv4-100k | 6,436,000 | 530,434,912 | 25,600,000 |
| full-uc | 54,752,768 | 482,118,144 | 123,000,000 |
| full-vpn | 448,352,768 | 88,518,144 | 123,000,000, 135,300,000 |
| mixed-widen | 448,352,768 | 88,518,144 | 135,300,000 |

Budget headroom here is daemon reservation credit, not process/VM headroom or
an estimate of per-peer bytes. Historical refusal causes and candidate failure
records are retained per phase in the numeric evidence. The original baseline
has no recovery gauges/counters; its zero-filled cause map is not measured
absence of fallback. Cumulative per-leg counter maxima below show the distinct
values observed across repeats, without summing repeated phase snapshots.

| Profile | Cell | Role | Peer limit | Daemon limit | Allocation failure | Missing proof |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| ipv4-100k | dataset-reevaluate | intermediate | 0 | 129 | 0 | 0 |
| ipv4-100k | peer-down | intermediate | 0 | 129 | 0 | 0 |
| full-uc | dataset-reevaluate | intermediate | 111, 112 | 0 | 0 | 0 |
| full-uc | peer-down | intermediate | 110, 111 | 0 | 0 | 0 |
| full-vpn | dataset-reevaluate | intermediate | 100 | 0 | 0 | 0 |
| full-vpn | peer-down | intermediate | 100 | 0 | 0 | 0 |
| full-vpn | widen | intermediate | 100 | 0 | 0 | 0 |
| mixed-widen | widen | intermediate | 111 | 0 | 0 | 0 |

Every candidate fallback cause must remain zero to qualify. A fallback never turns
an incomplete candidate proof into a passing qualification. Settled live state
must restore the population-ready empty-proof charge with zero retained entries
and residue; the historical peak gauge remains populated. Scope exit snapshots
are after workload teardown and are not live RIB retention readings.

Sparse admitted additions retain a substantial cost. VPN widening raises
whole-scope mean peaks by 12.7% against the original control and 12.5% against
the intermediate; mixed widening raises them by 14.3% and 13.5%, respectively.
Their actual reservation charge and ratios remain visible; correct final folds
do not remove that cost. The unchanged budgets qualify only the tested shapes,
not an arbitrary widening fraction or a deployment headroom guarantee.

## Earlier attempts

Earlier rows remain in the evidence as separate attempts; none fills a cell in
this final exact-source roster. All archives were retained, including artifacts
emitted during cancellation. Failed or incomplete cells have no supported
ratios; validated prior cells retain their own scoped ratios.

| Attempt | Archived evidence | Qualification limit |
| --- | --- | --- |
| `35a0eaf950f739834de033bbdb685a5f53d458ee`, [run 38515345811](https://github.com/lance0/rustbgpd/actions/runs/38515345811) | Mixed widening: eight exits 101, 24 partial phases, no completion. Unicast: 9/16 completed legs, 37 phases. VPN: 5/24 completed legs, 23 phases. | Harness paused Snapshot/resume race; two campaigns interrupted. No combined qualification. |
| `dac3b620e2a10f6d9b9bb027f522b2c7430e9bf9`, [run 38521779642](https://github.com/lance0/rustbgpd/actions/runs/38521779642) | 45 started legs, 164 phases, 39 RIB completion barriers; 38 legs also had terminal ownership/accounting. IPv4 reevaluation validated 8/8 legs; source-down had eight RIB barriers but only seven valid lifetimes. | Observer exit race invalidated source-down; six other cells interrupted. No combined qualification. |
| `41fc8db4839e40fb95c50f51bf86fad5a1f2e83f`, [run 38524938181](https://github.com/lance0/rustbgpd/actions/runs/38524938181) | 56 started legs, 217 phases, 51 complete RIB/ownership barriers. Both IPv4 cells and unicast source-down validated; five cells interrupted. | Superseded for the reviewed bulk-withdrawal ledger runtime change. No combined qualification. |

The first failure handled Snapshot concurrently with an already-ready resume by
panicking the paused consumer. The correction snapshots the paused fold without
consuming credit. Its retained mixed samples showed 135,300,000 logical proof
entries, 448,352,744 charged bytes and 448,352,768 peak charged bytes with zero
fallback causes. These remain diagnostic observations, not qualification.

In the second failure the owned Rust child left cgroup membership before its
exit became observable. The checker rejected the missing active member despite
completed RIB folds. The correction requires terminal child-exit proof and a
fresh membership dump while rejecting missing other owners, foreign members
and populated descendants in every observed dump. The third revision replaced
repeated seed-universe searches with an ordered cursor; its counted-work control
is described below. The eight-cell split preserves all shapes, controls,
A/B/B/A ordering, barriers and the 120-minute ceiling. No old rows were pooled
into the final campaign.

## Correctness controls and limits

Separate local controlled regressions from earlier `010a7a7bf`/`edfe603b9`
implementation stages rejected: loss of an owed withdrawal when
the production missing-proof fallback was removed (debug assertions disabled),
eager prior materialization on a clean shared withdrawal, false admission of an
unset shared-universe bit, and failure to settle a successful refused-proof
initial dump/refresh. Failed-EoR retry remained required. These are correctness
controls, not off-box memory measurements. Source paths and mutant/restored-log
hashes are in [provenance.json](artifacts/update-group-shared-recovery-memory-2026-10-14/provenance.json).
Historical mutant runs are not exact-final-head mutations; the final workspace
suite contains the restored controls. The final `cf80618599` runtime additionally
passed all five bulk-withdrawal controls. Resetting its seed cursor for each key
fails a deterministic comparison bound; restored source bytes match the committed
file. This bounds only shared seed-universe matching to
`O(log U + visited span + W)`: tiny
withdrawal ranges skip the universe prefix, while widely spread keys scan their
span. Existing B-tree, filter and announcement costs are outside that statement.
These counted-work controls provide no timing measurement.

Fresh hosted Ubuntu 24.04 VMs built serially with the locked scale profile,
four jobs and separate targets. Workloads ran in distinct swap-fenced cgroup v2
scopes; scope/process incarnation and executable digests were bound to compiled
source/instrumentation identities. Swap and cgroup/host OOM invalidate evidence.
Ownership checks are sampled. Phase peaks are monotonic and scope exit peaks
cover all earlier samples. Host inventory snapshots do not establish deployment
headroom. EVPN is inactive; this receipt does not claim session reset coverage
or enable EVPN grouping.

## Evidence

[Run 38529705978](https://github.com/lance0/rustbgpd/actions/runs/38529705978) and the
[compact evidence](artifacts/update-group-shared-recovery-memory-2026-10-14/README.md) preserve every completed leg and
phase, including refusals and failures. Numeric values, PID/start identities,
source/binary/build hashes and raw archive ZIP digests are retained. Scope paths
are distinct aliases with original path hashes; executable paths become
basenames. Full checksum-verified archives are retained separately, because the
compact sanitized extract cannot replay the original ownership checks.
