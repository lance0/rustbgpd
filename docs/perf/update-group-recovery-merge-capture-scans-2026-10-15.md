# Merge-based recovery capture scans (15 October 2026)

> **Document class: HISTORICAL. FAIL — capture-cost target.** Component evidence is complete; deployment and release are unqualified.

The sorted-merge candidate at `7e9fbd30f36c826a64943781b1ced1001f98f183` in [PR #3159](https://github.com/lance0/rustbgpd/pull/3159) was measured in [hosted run 38670839102](https://github.com/lance0/rustbgpd/actions/runs/38670839102). Six fresh VMs supplied all 36 cells and 144 timed legs, with zero refusals, complete exact-key proofs and clean last-owner settlement. All six receipt jobs succeeded. This establishes the component evidence, not the cost verdict or unrelated CI results.

The candidate **misses the approximately 1.5× shared/flat complete-capture target** in all 24 unicast/VPN cells and five of twelve EVPN cells. The largest observed ratio is 6.691× for shuffled VPN OLD. The candidate is not accepted for deployment by this receipt; it remains separate from the live unicast/VPN implementation. EVPN group ownership remains disabled.

## Complete-capture results

Each cell has two samples per arm in flat/shared/shared/flat order. The ranges below cover the six cell medians for that profile and OLD order, without pooling VMs or input orders. Flat and shared range endpoints need not belong to the same cell. [comparison.json](artifacts/update-group-recovery-merge-capture-scans-2026-10-15/comparison.json) contains every paired cell and both samples; [rows.jsonl](artifacts/update-group-recovery-merge-capture-scans-2026-10-15/rows.jsonl) preserves all 144 exact numeric rows.

| Profile | OLD order | Flat (ms) | Shared (ms) | Paired shared/flat |
| --- | --- | ---: | ---: | ---: |
| full-uc | sorted | 49.362–66.178 | 100.750–104.336 | 1.522–2.074 |
| full-uc | shuffled | 158.933–182.160 | 448.413–489.995 | 2.574–2.989 |
| full-vpn | sorted | 35.418–53.871 | 83.877–84.778 | 1.559–2.368 |
| full-vpn | shuffled | 100.345–111.243 | 659.933–672.617 | 5.953–6.691 |
| evpn-soak | sorted | 1.489–3.568 | 2.635–2.751 | 0.767–1.777 |
| evpn-soak | shuffled | 5.607–9.193 | 10.969–14.247 | 1.259–2.541 |

The shared classifier now uses a monotone universe cursor rather than one binary search per OLD key. That change alone does not make complete capture cheap: live OLD order is not guaranteed, and the candidate collects and sorts borrowed route references before classification and population. These results reject the candidate's complete-capture cost despite linear classification. No component ratio is extrapolated to fleet latency.

## Workload and boundaries

`full-uc` and `full-vpn` each contain 1,230,000 keys, with 1,000,000 IPv4 and 230,000 IPv6 keys. VPN uses raw RD zero and path ID zero. `evpn-soak` contains 37,500 Type 2/5 keys in a 4:1 mix; its name does not establish a soak. Record counts are 2, 64 and 480. Each leg has one full anchor proof and one capturing target; every other record is empty. Dense OLD matches the universe. Older-sparse OLD replaces as many low universe keys as the record count with keys outside the universe, keeping target cardinality fixed.

Both arms receive identical route-body fixtures. Sorted and deterministically shuffled OLD are prepared outside the measured phases and run on independent fresh VMs. **Shared complete capture includes** the production count traversal, fallible capacity-accounted reference collection, sorting, classification, reservation/attachment, batch population, sealing and physical scratch release/refund. Sorting remains O(n log n). Flat explicitly reserves its exact cardinality, populates keys and seals. Generic uncertain-length or unordered callers retain bounded binary lookup.

The shape phase runs independently; a separate untimed pass counts classifier key visits/comparisons. Those counters exclude sorting, population and record lookup. Timed callbacks are no-ops, so production readiness servicing is unmeasured. Anchor-universe creation, fixture construction, exact proof verification and final-owner retirement are outside the measured phase. In particular, this is not a cold first-member capture receipt.

Logical retained/peak charge includes the anchor universe, all records, masks, sparse storage and charged temporary overlap. It excludes route-body input fixtures, allocator overhead and RSS. Every target contains the full expected OLD inventory; sparse cases exclude removed keys. Final-owner retirement returns to empty-ledger charge. Logical credit must not be presented as cgroup memory or component attribution.

Per-thread CPU ticks resolve 10 ms (100 Hz). All 76 zero-tick phase samples are retained, and zero-denominator ratios remain null. Two samples per arm are not a latency distribution. The six builds report `rustc 1.99.0 (b940084d7 2026-09-28)` and use the locked scale profile with four build jobs per hosted VM.

The [earlier v1 receipt](update-group-recovery-capture-scans-2026-10-15.md) remains unchanged. It used key-only, presorted fixtures; this v2 method includes route references, production counting and ordering work. Historical absolute milliseconds and ratios do not isolate an attributable implementation speedup across these methods. Only each same-source v2 shared/flat pair supports the comparison above.

## Decision and remaining release bar

The live unicast/VPN shared-capture cost remains a release concern. A bounded exact-reserved flat path for full OLD captures is a proposed fallback, not an accepted CPU/memory trade in this receipt. It retains more keys per dirty member and can reach the unchanged 64 MiB per-peer / 512 MiB daemon limits sooner. Do not raise caps or conceal conservative no-proof fallback to obtain a passing comparison.

A release decision still needs matched whole-system mass-dirty readiness and receiver convergence with sharing enabled/disabled, including proof/fallback counts and retained/peak memory. The trigger must exercise full OLD capture rather than a private/regroup flat baseline. Dataset-only export-policy reevaluation preserves group identity and can select the entire cohort; an ordinary policy-changing reload is insufficient by itself. Local settlement is not remote wire convergence. The actual release candidate must also pass its soak. This component receipt qualifies none of those gates and does not qualify EVPN activation.

## Provenance

All six ZIP digests match GitHub's artifact metadata. All eight frozen instrumentation inputs and three Cargo build inputs match the measured commit. Compiled source, executed-binary, process incarnation, sampled cgroup ownership, swap/OOM status and zero driver/workload exits were verified. Each frozen consumer reproduced its comparison byte for byte on a fresh copy; all 432 original file hashes were retained. An independent verification pass revalidated ZIPs, source blobs, proofs, settlement and all 36 ratios.

| Profile | OLD order | Original artifact | ZIP SHA-256 |
| --- | --- | --- | --- |
| full-uc | sorted | [11944487753](https://github.com/lance0/rustbgpd/actions/runs/38670839102/artifacts/11944487753) | `e3dba7ff483e7dc7849014745bada0f153f8b7d171604650e3cd3a2778576bda` |
| full-uc | shuffled | [11944058076](https://github.com/lance0/rustbgpd/actions/runs/38670839102/artifacts/11944058076) | `d2319dd54631efdf48768793970cb8c3ddcfb566ee26548cab4075f0629a2d76` |
| full-vpn | sorted | [11944252691](https://github.com/lance0/rustbgpd/actions/runs/38670839102/artifacts/11944252691) | `5b87ae97390aec788053861578dea17488c1defcbce4dab722e9995a0f4c7deb` |
| full-vpn | shuffled | [11944551558](https://github.com/lance0/rustbgpd/actions/runs/38670839102/artifacts/11944551558) | `af16b37f4e1705856007a3b0809104066554c653eb94a61e48baca63569243d8` |
| evpn-soak | sorted | [11944487648](https://github.com/lance0/rustbgpd/actions/runs/38670839102/artifacts/11944487648) | `9646ca298df510da39de06dac79fd0ff9dade014c2dd5fc4d438869218abf983` |
| evpn-soak | shuffled | [11943906813](https://github.com/lance0/rustbgpd/actions/runs/38670839102/artifacts/11943906813) | `3c01dfde36811ca698b891ba1238781c84ef7e4da2a2135f258a496d88a99d14` |

The [artifact README](artifacts/update-group-recovery-merge-capture-scans-2026-10-15/README.md) describes the compact extract. Full archives are retained separately; hosted links have 30-day retention and can expire. Compact source/row/hash extracts cannot replay original path-based ownership checks. Sampled ownership is not continuous proof. This is neither a RIB-actor/fleet, final-wire, daemon-memory, readiness nor release-candidate soak receipt.
