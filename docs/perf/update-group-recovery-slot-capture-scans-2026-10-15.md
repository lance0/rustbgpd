# Slot-indexed recovery capture scans (15 October 2026)

> **Document class: HISTORICAL. PASS — selected common-family component cost bar.** Whole-system and release-candidate qualification remain pending.

The slot-indexed candidate at `03ee2ad6d905df3c32e1537ccf3d1646de0d856c` was measured in [hosted run 38680284008](https://github.com/lance0/rustbgpd/actions/runs/38680284008), started at **2026-10-15T04:12:49Z**. Six fresh profile/order VMs supplied all 36 cells and 144 timed legs, with zero refusals, complete exact-key proofs and clean last-owner settlement. All six receipt jobs succeeded. This records component behavior at the measured source; it does not measure containing main or assert unrelated CI outcomes.

All twelve pure-unicast candidate cells actually used `uc-slab-shared` and passed the approximately **1.5× candidate/flat complete-capture bar**: ratios range from **0.151 to 0.752**, including **0.671–0.752 for shuffled OLD**. All twelve VPN-negotiated candidate cells used `exact-flat` with reason `vpn-negotiated`, at **0.991–1.008×** flat. Those VPN rows establish bounded flat-path behavior, not a VPN sharing or memory win. Six of twelve dormant EVPN cells exceed 1.5×; EVPN group ownership remains disabled.

## Complete-capture results

Each cell has two samples per arm in flat/candidate/candidate/flat order. Sorted and deterministically shuffled OLD use separate fresh VMs and are not pooled. Every ratio below is a paired candidate/flat wall-time ratio; each entry gives **dense / older-sparse**. [comparison.json](artifacts/update-group-recovery-slot-capture-scans-2026-10-15/comparison.json) retains all 36 cells, exact samples, CPU ratios, counters, strategies and charges. [scan-rows.csv](artifacts/update-group-recovery-slot-capture-scans-2026-10-15/scan-rows.csv) preserves all 144 numeric legs, including zeros and explicit unavailable cold fields.

| Profile | OLD order | 2 records | 64 records | 480 records |
| --- | --- | ---: | ---: | ---: |
| full-uc | sorted | 0.685 / 0.151 | 0.669 / 0.157 | 0.678 / 0.156 |
| full-uc | shuffled | 0.702 / 0.706 | 0.671 / 0.695 | 0.694 / 0.752 |
| full-vpn | sorted | 0.991 / 1.008 | 1.008 / 1.002 | 0.996 / 0.993 |
| full-vpn | shuffled | 0.996 / 1.004 | 1.004 / 1.007 | 1.003 / 0.999 |
| evpn-soak | sorted | 2.267 / 2.269 | 1.102 / 1.098 | 0.841 / 0.835 |
| evpn-soak | shuffled | 1.891 / 1.861 | 1.584 / 1.585 | 1.435 / 1.442 |

The following ranges cover the six cell medians per profile/order, in milliseconds. Range endpoints need not belong to the same cell; they are not inputs to a ratio.

| Profile | OLD order | Flat capture median range ms | Candidate capture median range ms |
| --- | --- | ---: | ---: |
| full-uc | sorted | 30.431–136.208 | 20.544–21.273 |
| full-uc | shuffled | 162.271–166.493 | 110.481–122.296 |
| full-vpn | sorted | 181.086–185.310 | 182.010–184.266 |
| full-vpn | shuffled | 180.227–181.677 | 180.684–182.365 |
| evpn-soak | sorted | 0.987–2.680 | 2.239–2.244 |
| evpn-soak | shuffled | 5.624–7.504 | 10.537–10.823 |

The EVPN misses are both 2-record layouts in both orders and both shuffled 64-record layouts. The profile name `evpn-soak` denotes a key shape; these component jobs are not a soak and do not qualify activation.

## Workload and phase boundaries

Each leg has **one full anchor proof and one full capturing member**. All remaining records are empty. Record counts 2, 64 and 480 include anchor and target; they do not represent a populated dirty fleet or concurrent actor recovery. Full unicast and VPN each contain 1,230,000 generated keys: 1,000,000 IPv4 and 230,000 IPv6. VPN uses raw RD zero and path ID zero. EVPN uses 37,500 Type 2/5 keys in a 4:1 mix.

Common-family fixtures use one actual Adj-RIB-Out, preserving insertion/slab iteration lineage. Dense OLD matches the live anchor universe. Sparse mutation removes and replaces keys, reuses slab slots and appends others; the target retains the full requested key count. Sorted and shuffled input orders exercise that lineage separately.

Warm unicast capture performs the production count/selection and population walks against the existing pool index, validates exact prefix/path identity at slot hits, reserves actual mask/sparse capacity, populates and seals the proof. It performs no per-member ordering-buffer allocation or sort. Bounded slot mismatches can select exact flat capture; none of the eligible unicast candidate legs silently took that fallback here. The explicit flat warm control reserves its exact cardinality, populates and seals. VPN negotiation selects flat for the whole common OLD proof, including unicast entries. EVPN's ordered component path includes its temporary ordering work.

Fixture materialization is outside measured intervals. Shape and complete capture are independently invoked. Counted shape callbacks/comparisons run in a separate pass; they do not count full-capture comparisons or record-lookup work. Timed callbacks are no-ops, so production readiness servicing and yield cost are unmeasured. Exact-proof verification and final-owner retirement are outside timing.

## Cold anchor cost

Unlike a warm reuse, first-pool construction must collect/order keys and build the shared index. The common cold phase includes anchor begin, the full capture helper and sealing. **Both warm arms use the same cold anchor policy**: unicast slab sharing or negotiated-VPN flat capture. These observations therefore have **no attributable cold sharing-on/off ratio**.

The table covers all 24 individual cold observations per common profile/order, with their median, in milliseconds. Shuffled unicast cold anchor capture costs **739.603–818.664 ms**; this first-pool cost can matter to whole-system readiness even though warm capture passes its component bar.

| Profile | OLD order | Cold min / median / max ms |
| --- | --- | ---: |
| full-uc | sorted | 202.861 / 204.542 / 206.069 |
| full-uc | shuffled | 739.603 / 773.668 / 818.664 |
| full-vpn | sorted | 181.711 / 183.899 / 193.517 |
| full-vpn | shuffled | 180.815 / 181.830 / 191.565 |

EVPN cold timing is explicitly null with reason `evpn-not-production-cold-path`. It is neither zero nor a measured first-member result. No cold-arm ratio is inferred from common timings or from those nulls.

## Logical credit, clocks and correctness

The ranges below cover all record counts/layouts. Sorted and shuffled have identical logical charges. Credit includes the anchor, record metadata, key/index storage, masks, sparse capacity and charged allocation overlap; it excludes input fixtures, allocator overhead and RSS. It is not cgroup memory, whole-daemon memory or attribution of a component's bytes.

| Profile | Flat retained bytes | Candidate retained bytes | Flat peak bytes | Candidate peak bytes |
| --- | ---: | ---: | ---: | ---: |
| full-uc | 83794192–83863552 | 44587944–44672664 | 83794216–83863576 | 44587968–44672688 |
| full-vpn | 78720368–78789728 | 78720368–78789728 | 78720392–78789752 | 78720392–78789752 |
| evpn-soak | 4805232–4907232 | 2409920–2542640 | 4805256–4907256 | 2709968–2842688 |

Every target proof matched the requested actual OLD inventory, sparse classification excluded removed universe keys, and final-owner retirement restored the recorded empty-ledger charge. Production limits remain **64 MiB per peer / 512 MiB daemon-wide**. Private/regroup and VPN-negotiated full OLD captures remain flat; many concurrent flat proofs can consume those budgets sooner. Neither this receipt nor the component cost pass raises caps or removes the conservative no-proof fallback.

All jobs report 100 Hz thread CPU clocks. The artifacts preserve **83 zero-tick phase observations** and **21 null zero-denominator CPU ratios**. At 10 ms granularity, zero ticks do not mean zero work. Two samples per arm in a finite ABBA sequence are not a latency distribution or robust statistical estimate. Separate counter probes do not establish total capture work or production readiness cost.

Sampled process membership, lineage, executable identity and incarnation checks passed before/during/after execution, with 2/3/2 scope members and no descendant cgroups. Swap and cgroup OOM observations were zero; host OOM stayed zero. Ownership is sampled, not continuous proof. These safety checks do not turn logical ledger credit into a memory-performance receipt.

## Accepted component result and remaining qualification

The selected pure-unicast warm path and VPN flat fallback pass this component cost bar. Matched **whole-system mass-dirty readiness, receiver convergence and retained/peak memory** remain pending, including actual full OLD capture, sharing enabled/disabled controls, cold pool cost and fallback/reset counts. Qualification must establish real all-member dirty marking and a dirty-resync receipt for every exact member. State whether dirty overlap is established by pinned mark-all-before-staging source ordering or by sampling. A pending count at queue drain is not that witness: dirty state can clear when a batch is admitted. A soak on the **actual release candidate** also remains pending. One anchor plus one capturing target does not satisfy those requirements; local proof settlement is not final remote delivery.

The [earlier key-only receipt](update-group-recovery-capture-scans-2026-10-15.md) and [failed sorted-merge receipt](update-group-recovery-merge-capture-scans-2026-10-15.md) remain unchanged. Fixtures, selected policies and timing boundaries differ. Their absolute milliseconds cannot serve as an attributable implementation comparator, and no earlier sample is pooled here. Only the same-source warm candidate/flat pairs support this receipt's ratios. See [ADR-0099's current result](../adr/0099-update-groups-v2.md#amendment-2026-10-15-slot-indexed-component-cost-result) for the remaining gates.

## Provenance

All six ZIP digests match GitHub artifact metadata. Eight frozen instrumentation inputs and three Cargo inputs per campaign match the measured Git blobs; source, binary and process identity checks passed. The exact frozen v3 consumer reproduced each original comparison byte for byte on fresh copies. All 432 raw-file byte lengths and hashes are retained in [provenance.json](artifacts/update-group-recovery-slot-capture-scans-2026-10-15/provenance.json), with source/build/binary/instrumentation pins, job UTC times and sampled safety summaries. The common instrumentation-manifest SHA-256 is `b1fad407d31ff82e31eb9c25f1ee71cb6d42b77263116554e9360ec510e7e5c5`.

| Profile | OLD order | Original artifact | ZIP SHA-256 |
| --- | --- | --- | --- |
| full-uc | sorted | [11946749471](https://github.com/lance0/rustbgpd/actions/runs/38680284008/artifacts/11946749471) | `c28845030d440f01026351a827f5a95e62c527377bde5b17c088644abbb45d09` |
| full-uc | shuffled | [11948285487](https://github.com/lance0/rustbgpd/actions/runs/38680284008/artifacts/11948285487) | `5ae5dcdb9ed2531f883e6509d80a276fae8edaa558dd927e947cb2ec63828174` |
| full-vpn | sorted | [11946674821](https://github.com/lance0/rustbgpd/actions/runs/38680284008/artifacts/11946674821) | `e2fe5433854694f5a0239157a13b2a42477d0600d2f4fc44d9dbf8f17a8f1ebc` |
| full-vpn | shuffled | [11947064404](https://github.com/lance0/rustbgpd/actions/runs/38680284008/artifacts/11947064404) | `65d7bd193c2dc97e3e1397fdfb800e794037877cdf2f976ef1d29cc81310a861` |
| evpn-soak | sorted | [11947880554](https://github.com/lance0/rustbgpd/actions/runs/38680284008/artifacts/11947880554) | `2a417b722afb130bbf4cae63891d7ac6b8d5ce31fc0b491545c4c584a7da12fa` |
| evpn-soak | shuffled | [11947905557](https://github.com/lance0/rustbgpd/actions/runs/38680284008/artifacts/11947905557) | `9f28fa49a349a5d44f2bae32984a8a36a9c21a505d661f22282f070e8bd86f39` |

Complete checksum-verified archives are retained separately. Hosted artifact expiry times are recorded in provenance and links can expire. Compact extracts cannot replay the original path-based ownership checks. This receipt qualifies neither fleet/actor behavior, readiness, final wire/TCP delivery, whole-daemon memory, an actual-release-candidate soak nor EVPN ownership/activation.
