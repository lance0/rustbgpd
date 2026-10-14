# Update-group recovery across unsynchronized dirty passes (14 October 2026)

> **Document class: HISTORICAL.** This receipt covers fresh hosted VMs and pinned manager-direct RIB workloads. It is not a deployment memory or timing guarantee.

**Qualification: PASS; 10/10 cells and 80/80 legs strictly reviewed.**

The measured runtime is `be0e13b20321118ed0a15b05c3be0fca589b5d69`. [Run 38597855188](https://github.com/lance0/rustbgpd/actions/runs/38597855188) selects nine complete cells from attempt 1 and the complete full-VPN widening cell from attempt 2, using ten qualifying fresh profile/cell VMs and A/B/B/A ordering against each of two pinned controls. All forty candidate legs and forty control legs passed. The timed-out first widening cell is retained separately as incomplete history; its seven complete legs never substitute for the required eight-leg retry cell. The frozen instrumentation manifest SHA-256 is `a9066f9a93ab69262c0db9e51e93a04f95a31e8cffe6ff7b8539cc9675746512`.

The original control is `c862af9338aa828b7462f3cf85781f63b0e79fe8`; the intermediate is `bdb7bc34dfe0e6a66fc8c0f1d56d3e57184dea00`. Both receive identical frozen harness input. Candidate instrumentation and observer patches are empty: its compiled source is the recorded runtime. These are complete-revision comparisons, not allocation-component attribution.

The measured commit remains the runtime above even when this receipt lands on a later main. Independent query and EVPN-preparation changes may already be present on that containing main; no whole-RIB/runtime byte-equivalence or new-head measurement is claimed. A receipt-only commit adds no runtime changes relative to its own immediate parent. Its documentation checks and subsequent main CI are separate evidence from this PR-head memory qualification.

## Shape and admission evidence

The IPv4 profile has 256 receivers × 100,000 keys and reevaluation/source-down cells. Full unicast and full VPN profiles have 100 receivers × (1,000,000 IPv4 + 230,000 IPv6 keys), each with reevaluation, source-down and unsynchronized-dirty cells; full VPN also has widening. Mixed widening seeds the unicast profile and admits VPN additions. VPN keys alternate distinct raw RD encodings with identical display text. All routes use synthetic attributes, one source and homogeneous plain RR clients, fixed family next hops, and no Add-Path or RTC selection.

Reevaluation keeps eligibility unchanged and requires zero withdrawals. Source-down requires one withdrawal per actually admitted exact key and empty final family folds. Widening admits 100,000 VPNv4 and 23,000 VPNv6 keys per receiver using one controlled queue credit while receivers remain dirty. Paused consumer folds remain at seed state; the actor admission barrier and proof gauges establish admitted additions. Drained family folds and BMP counts must agree.

Unsynchronized-dirty cells pause receivers progressively across 100 successive source passes. Each pass adds one key and closes an actor barrier over the exact OLD admission for the next receiver. Retained proofs must total 123,004,950 keys, rather than merely the synchronized 123,000,000 seed. All 100 per-leg barriers and actual receiver folds are checked. Final receivers contain seed + 100 keys with zero withdrawals. This qualifies unsynchronized addition into a live older snapshot; it does not qualify arbitrary churn or regroup sharing.

## Comparator-paired whole-scope peaks and coverage

MiB values are rounded from exact bytes in [comparison.json](artifacts/update-group-recovery-snapshot-churn-2026-10-14/comparison.json). Each row compares its own two control legs with its own two candidate legs; four candidate legs are never pooled against one control pair. Ratio is sum(candidate peaks) / sum(control peaks). `c862` has no recovery gauges or fallback counters, so absent proof data is not evidence of zero fallback. Intermediate coverage and fallback are shown because a smaller incomplete proof is not equivalent to a complete candidate proof.

| Profile | Cell | Control | Control peaks (MiB) | Paired candidate peaks (MiB) | Ratio | Control → candidate held proof keys | Control → candidate fallbacks |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| full-uc | dataset-reevaluate | c862af933 | 1409.86/1433.32 | 1303.48/1300.61 | 0.915911 | absent/absent → 123000000/123000000 | absent/absent → 0/0 |
| full-uc | dataset-reevaluate | bdb7bc34 | 1285.43/1295.89 | 1302.62/1310.00 | 1.012124 | 0/0 → 123000000/123000000 | 111/111 → 0/0 |
| full-uc | peer-down | c862af933 | 1677.87/1665.93 | 1743.79/1729.14 | 1.038619 | absent/absent → 123000000/123000000 | absent/absent → 0/0 |
| full-uc | peer-down | bdb7bc34 | 1680.05/1681.90 | 1747.32/1743.97 | 1.038473 | 0/0 → 123000000/123000000 | 111/111 → 0/0 |
| full-uc | unsynchronized-dirty | c862af933 | 1355.94/1369.74 | 1314.03/1312.27 | 0.963540 | absent/absent → 123004950/123004950 | absent/absent → 0/0 |
| full-uc | unsynchronized-dirty | bdb7bc34 | 1233.17/1229.63 | 1309.09/1312.81 | 1.064599 | 0/0 → 123004950/123004950 | 112/111 → 0/0 |
| full-vpn | dataset-reevaluate | c862af933 | 2414.94/2415.27 | 2471.09/2462.90 | 1.021487 | absent/absent → 123000000/123000000 | absent/absent → 0/0 |
| full-vpn | dataset-reevaluate | bdb7bc34 | 2334.06/2336.49 | 2471.41/2466.42 | 1.057227 | 0/0 → 123000000/123000000 | 100/100 → 0/0 |
| full-vpn | peer-down | c862af933 | 2812.38/2796.68 | 2852.74/2849.16 | 1.016551 | absent/absent → 123000000/123000000 | absent/absent → 0/0 |
| full-vpn | peer-down | bdb7bc34 | 2801.31/2804.15 | 2849.56/2858.86 | 1.018368 | 0/0 → 123000000/123000000 | 100/100 → 0/0 |
| full-vpn | unsynchronized-dirty | c862af933 | 2421.59/2417.05 | 2469.11/2466.74 | 1.020089 | absent/absent → 123004950/123004950 | absent/absent → 0/0 |
| full-vpn | unsynchronized-dirty | bdb7bc34 | 2339.36/2346.36 | 2469.57/2475.14 | 1.055274 | 0/0 → 123004950/123004950 | 100/100 → 0/0 |
| full-vpn | widen | c862af933 | 4012.93/4022.58 | 4501.89/4504.00 | 1.120761 | absent/absent → 135300000/135300000 | absent/absent → 0/0 |
| full-vpn | widen | bdb7bc34 | 4023.43/4010.67 | 4507.14/4513.02 | 1.122733 | 0/0 → 135300000/135300000 | 100/100 → 0/0 |
| ipv4-100k | dataset-reevaluate | c862af933 | 184.36/196.43 | 186.28/195.60 | 1.002862 | absent/absent → 25600000/25600000 | absent/absent → 0/0 |
| ipv4-100k | dataset-reevaluate | bdb7bc34 | 802.33/803.37 | 181.07/192.98 | 0.232949 | 12700000/12700000 → 25600000/25600000 | 129/129 → 0/0 |
| ipv4-100k | peer-down | c862af933 | 225.82/217.39 | 228.73/227.32 | 1.028988 | absent/absent → 25600000/25600000 | absent/absent → 0/0 |
| ipv4-100k | peer-down | bdb7bc34 | 854.44/846.72 | 226.12/235.57 | 0.271393 | 12700000/12700000 → 25600000/25600000 | 129/129 → 0/0 |
| mixed-widen | widen | c862af933 | 3095.72/3104.55 | 3517.20/3517.95 | 1.134651 | absent/absent → 135300000/135300000 | absent/absent → 0/0 |
| mixed-widen | widen | bdb7bc34 | 3096.25/3100.10 | 3504.77/3512.87 | 1.132544 | 0/0 → 135300000/135300000 | 112/111 → 0/0 |

The largest reduction is on the 256-peer IPv4 shapes against the intermediate revision, which retains only 127 of 256 peer proofs before daemon-limit fallback. Full-table intermediate legs generally retain no proof before peer-limit fallback. Candidate full-table proof coverage is complete. Costs are not universally lower: source-down, VPN and widening rows can exceed the original baseline; the table preserves those increases. Whole-scope peaks include the manager, production exact-export preflight, harness consumers, queues, masks and owned launcher/checker. They are not process RSS or a component allocation estimate.

## Phase deltas

Retained-phase current and monotonic-peak deltas below are relative to each leg’s own population-ready sample. A zero peak delta can mean population already set a higher peak; it does not mean no allocations. Exact population, retained, operation-end and settled measurements remain in the numeric evidence.

| Profile | Cell | Control | Current delta: control → paired candidate (MiB) | Peak delta: control → paired candidate (MiB) |
| --- | --- | --- | ---: | ---: |
| full-uc | dataset-reevaluate | c862af933 | 0.14/2.16 → -13.78/-0.88 | 0.00/0.00 → 0.00/0.00 |
| full-uc | dataset-reevaluate | bdb7bc34 | -30.86/-18.27 → -1.73/5.77 | 0.00/0.00 → 0.00/0.00 |
| full-uc | peer-down | c862af933 | -31.81/-11.41 → 8.89/25.66 | 310.77/325.01 → 623.98/624.43 |
| full-uc | peer-down | bdb7bc34 | -36.85/-47.74 → 14.72/12.35 | 441.73/428.95 → 633.00/621.29 |
| full-uc | unsynchronized-dirty | c862af933 | 0.00/-1.75 → 39.09/39.88 | 0.00/0.00 → 0.00/0.00 |
| full-uc | unsynchronized-dirty | bdb7bc34 | -7.92/-14.39 → 36.40/43.92 | 0.00/0.00 → 0.00/0.00 |
| full-vpn | dataset-reevaluate | c862af933 | 1.94/1.98 → 52.58/47.43 | 75.32/77.15 → 127.70/119.91 |
| full-vpn | dataset-reevaluate | bdb7bc34 | 9.51/10.92 → 46.79/49.98 | 85.59/81.00 → 122.46/122.91 |
| full-vpn | peer-down | c862af933 | -434.48/-430.09 → -375.76/-379.46 | 781.11/771.62 → 830.82/825.31 |
| full-vpn | peer-down | bdb7bc34 | -427.84/-433.54 → -376.85/-367.84 | 778.33/777.61 → 822.79/832.91 |
| full-vpn | unsynchronized-dirty | c862af933 | 0.25/0.16 → 54.15/49.68 | 0.00/0.00 → 0.00/0.00 |
| full-vpn | unsynchronized-dirty | bdb7bc34 | 8.09/8.37 → 47.08/53.39 | 0.00/0.00 → 0.00/0.00 |
| full-vpn | widen | c862af933 | 2038.33/2045.02 → 2544.24/2549.73 | 1985.61/1992.13 → 2471.87/2478.03 |
| full-vpn | widen | bdb7bc34 | 2059.34/2030.16 → 2552.53/2560.09 | 1994.18/1981.27 → 2481.94/2489.51 |
| ipv4-100k | dataset-reevaluate | c862af933 | -0.38/-6.00 → -19.40/-17.44 | 0.00/0.00 → 2.73/2.84 |
| ipv4-100k | dataset-reevaluate | bdb7bc34 | 603.23/600.86 → -23.54/-10.72 | 623.30/623.46 → 0.32/0.00 |
| ipv4-100k | peer-down | c862af933 | -2.84/-2.82 → -14.91/-20.49 | 52.41/50.16 → 62.71/57.38 |
| ipv4-100k | peer-down | bdb7bc34 | 616.57/619.08 → -4.70/-13.69 | 682.85/683.26 → 64.29/63.62 |
| mixed-widen | widen | c862af933 | 2215.33/2229.44 → 2639.28/2639.59 | 1715.91/1715.28 → 2408.70/2397.10 |
| mixed-widen | widen | bdb7bc34 | 2220.07/2222.96 → 2624.32/2641.55 | 1851.04/1859.51 → 2389.67/2439.51 |

## Logical proof charge and limits

The production caps remain 67,108,864 bytes per peer and 536,870,912 bytes per daemon. Logical proof reservation includes retained snapshot/mask/sparse/header capacities and checked allocation overlap; it is separate from whole-scope measured memory. Peer credit conservatively includes its referenced snapshot. The daemon charges the shared physical snapshot once.

| Profile | Cell | Candidate retained proof entries | Retained charge (bytes) | Peak charge (bytes) | Remaining daemon peak credit (bytes) |
| --- | --- | ---: | ---: | ---: | ---: |
| full-uc | dataset-reevaluate | 123000000 | 54752744 | 54752768 | 482118144 |
| full-uc | peer-down | 123000000 | 54752744 | 54752768 | 482118144 |
| full-uc | unsynchronized-dirty | 123004950 | 54911144 | 54914368 | 481956544 |
| full-vpn | dataset-reevaluate | 123000000 | 54752744 | 54752768 | 482118144 |
| full-vpn | peer-down | 123000000 | 54752744 | 54752768 | 482118144 |
| full-vpn | unsynchronized-dirty | 123004950 | 54911144 | 54914368 | 481956544 |
| full-vpn | widen | 135300000 | 448352744 | 448352768 | 88518144 |
| ipv4-100k | dataset-reevaluate | 25600000 | 6435976 | 6436000 | 530434912 |
| ipv4-100k | peer-down | 25600000 | 6435976 | 6436000 | 530434912 |
| mixed-widen | widen | 135300000 | 448352744 | 448352768 | 88518144 |

Every candidate cause counter and EVPN reset counter must remain zero. Settled live state must restore the population-ready empty-proof charge, zero logical keys, zero dirty peers/members and zero residue; retained historical peak charge is expected. Scope-exit snapshots occur after workload teardown and are not live RIB retention samples. The baseline lacks these counters; its synthesized zero cause map is not a measured absence.

The optimization reuses a still-live older raw key universe and records only authoritative actual OLD admission through masks and bounded sparse additions. Desired keys never prove admission. Last-owner release invalidates reuse; stale non-owning hints fall back to a new capture. Private/regroup proofs still use bounded flat storage. Sparse additions still cost O(receivers × new admitted keys) and can reach the unchanged budgets. No arbitrary widening fraction, cross-recreated-group reuse, unbounded snapshot cache or deployment headroom is qualified.

## Validation and scope

Fresh hosted Ubuntu 24.04 VMs build locked scale-profile binaries serially with four jobs and separate role targets. Each leg uses a distinct swap-fenced cgroup v2 scope. Source, instrumentation, build inputs, binary digests and process/cgroup incarnations are verified. Ownership checks reject foreign members, populated descendants, missing active owners, swap and host/cgroup OOM; terminal child-exit proof permits only the documented completed-child transition. Ownership is sampled, not continuously proven.

Exact snapshot caller regressions separately cover a 1,048,577-key flat proof, optional share refusal under a nonzero 8 KiB cap followed by successful flat OLD capture, key add/remove churn, last-owner release/stale hints, allocator/cap refusal and actual admission exceptions. Controlled mutations made the full-flat reservation, share-refusal fallback and older-hint reuse assertions fail, then restored source passed. These are local correctness controls, not local memory measurements.

This is manager-direct RIB memory with production preflight and harness consumers. No timing, whole-daemon, final encoded-wire, TCP/socket, EVPN grouping, deployment capacity, general regroup-scale or arbitrary policy/RTC/Add-Path workload claim is made. EVPN ownership stays inactive. Historical receipts remain unchanged and are not pooled into this exact-source roster.

## Evidence

[Run 38597855188](https://github.com/lance0/rustbgpd/actions/runs/38597855188) and the [compact artifact directory](artifacts/update-group-recovery-snapshot-churn-2026-10-14/README.md) preserve exact numeric phase rows, per-leg observations, source/build/binary/frozen hashes and original archive digests. Complete checksum-verified original archives are retained separately. A sanitized compact extract cannot replay original path-based ownership checks.
