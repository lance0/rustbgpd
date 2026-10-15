# Update-group recovery capture scans (15 October 2026)

> **Document class: HISTORICAL. PASS — component qualification at recorded source.** These measurements cover component capture work, not daemon or deployment performance.

The independently verified dataset below measures the final reviewed harness source `5b905336750ee5a8fb9a4e411f2d8d94249a7d7f` in [run 38659117804](https://github.com/lance0/rustbgpd/actions/runs/38659117804), started at **2026-10-15T00:16:52Z**: 18 component cells, 72/72 timed legs, zero refused legs, and three outer invocation exits of zero. All three measured profile jobs succeeded. This qualifies the recorded harness head for these component measurements. It does not measure containing main or qualify production activation.

## Acceptance and cost verdict

The measurement-evidence bar is a complete 18-cell matrix with all 72 legs eligible, no refused captures, exact OLD-key proofs, last-owner retirement to empty-ledger charge, successful invocation exits and verified source/artifact provenance. This dataset passes that bar. A successful process exit alone is insufficient: a summary containing no eligible comparison does not qualify.

The runtime cost is **not accepted for deployment by this receipt**. Shared complete capture was slower than the flat control in every cell, by 4.13–16.33 times; lower logical ledger reservation does not establish an acceptable recovery-latency tradeoff. There is no component-ratio threshold in the agreed deployment contract, and this receipt does not invent one. Activation still requires the [ADR-0099 qualification](../adr/0099-update-groups-v2.md): matched whole-system memory and readiness/convergence evidence, complete recovery and wire parity, including simultaneous mass-dirty and whole-fleet regroup cells with no execution-confirmed recovery resets. The component result identifies a cost that those gates must resolve or explicitly justify; it does not pass them.

## Workload and phase boundaries

Each leg has one full anchor proof keeping an immutable key universe alive and one capturing target. The remaining records are empty. Record counts 2, 64 and 480 include both anchor and target; this is not 2/64/480 simultaneous full peer captures or an actor/fleet workload.

`full-uc` and `full-vpn` each use 1,230,000 exact keys: 1,000,000 IPv4 and 230,000 IPv6 keys in the dense universe. VPN keys use raw RD zero and path ID zero. `evpn-soak` uses 37,500 keys, with Type 2 MAC and Type 5 prefix identities in a 4:1 mix. Its name denotes the key shape, not a soak or live EVPN ownership. Dense OLD matches the anchor universe. Older-sparse OLD shifts by the record count, excluding that many low universe keys and adding the same number of keys outside it; each target proof still contains exactly the requested key count.

Both arms use the same measured source and anchor. Flat explicitly bypasses target sharing; shared reuses the live universe and reserves its bitmap plus exact sparse additions. Each cell runs flat/shared/shared/flat, giving two samples per arm. Every invocation starts fresh ledgers and materializes/sorts its OLD input before the measured phases.

Complete **capture** includes target begin, shape/count, optional shared attachment, reservation, population and sealing, including their per-key search costs. The **shape** phase is timed in an independent invocation. Callback/comparison counts instrument only `capture_shape` in a separate untimed pass; they do not count full-capture comparisons or record-lookup work. Timed capture uses no-op callbacks for shape and subsequent reservation/population/sealing and contains no nested CPU-clock reads. Fixture setup, input materialization, proof verification and final release are outside those timing boundaries. This does not measure production readiness servicing or yield cost.

## Selected 480-record costs

Values are medians of two samples per arm. Milliseconds are rounded from exact nanoseconds in [comparison.json](artifacts/update-group-recovery-capture-scans-2026-10-15/comparison.json); [rows.jsonl](artifacts/update-group-recovery-capture-scans-2026-10-15/rows.jsonl) preserves every original numeric row. Logical retained bytes include the anchor and all ledger records, not just the target.

| Profile | Layout | Capture flat / shared (ms) | Shared / flat | Shared shape (ms) | Retained flat / shared (bytes) |
| --- | --- | ---: | ---: | ---: | ---: |
| full-uc | dense | 45.084 / 377.696 | 8.378 | 167.641 | 78943520 / 39737272 |
| full-uc | older-sparse | 44.855 / 378.155 | 8.431 | 166.523 | 78943520 / 39752632 |
| full-vpn | dense | 35.798 / 351.755 | 9.826 | 156.337 | 78943520 / 39737272 |
| full-vpn | older-sparse | 36.076 / 352.158 | 9.762 | 155.916 | 78943520 / 39752632 |
| evpn-soak | dense | 2.882 / 12.271 | 4.258 | 4.857 | 4903136 / 2507824 |
| evpn-soak | older-sparse | 2.969 / 12.262 | 4.130 | 4.833 | 4903136 / 2538544 |

Across all common unicast/VPN cells, shared complete capture took 8.38–16.33 times the flat capture wall time while using about half the total logical ledger reservation in this one-anchor/one-target shape. EVPN capture ratios ranged from 4.13 to 9.49. The smaller EVPN workload has substantial fixed record overhead. These ratios are component observations, not a prediction of fleet capture latency, readiness gaps or operational throughput.

## Complete 18-cell matrix

This matrix includes every measured cell, including the lower-record-count and sparse layouts. Exact per-arm sample pairs, ranges, CPU ticks, counts, proof sizes, additions, retained/peak/settled charge and null ratios remain in the artifacts.

| Profile | Records | Layout | Capture flat / shared (ms) | Shared / flat | Shared shape (ms) | Shared SHAPE comparisons / OLD key |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| full-uc | 2 | dense | 27.413 / 357.000 | 13.023 | 166.670 | 22 |
| full-uc | 2 | older-sparse | 27.565 / 357.054 | 12.953 | 166.627 | 22 |
| full-uc | 64 | dense | 37.615 / 374.745 | 9.963 | 166.174 | 22 |
| full-uc | 64 | older-sparse | 37.724 / 369.848 | 9.804 | 166.649 | 22 |
| full-uc | 480 | dense | 45.084 / 377.696 | 8.378 | 167.641 | 22 |
| full-uc | 480 | older-sparse | 44.855 / 378.155 | 8.431 | 166.523 | 22 |
| full-vpn | 2 | dense | 20.444 / 333.847 | 16.330 | 155.951 | 22 |
| full-vpn | 2 | older-sparse | 20.595 / 334.019 | 16.218 | 155.721 | 22 |
| full-vpn | 64 | dense | 30.345 / 344.371 | 11.348 | 156.349 | 22 |
| full-vpn | 64 | older-sparse | 30.289 / 344.674 | 11.379 | 155.945 | 22 |
| full-vpn | 480 | dense | 35.798 / 351.755 | 9.826 | 156.337 | 22 |
| full-vpn | 480 | older-sparse | 36.076 / 352.158 | 9.762 | 155.916 | 22 |
| evpn-soak | 2 | dense | 1.126 / 10.451 | 9.284 | 4.854 | 17 |
| evpn-soak | 2 | older-sparse | 1.107 / 10.505 | 9.493 | 4.833 | 17 |
| evpn-soak | 64 | dense | 2.184 / 11.571 | 5.298 | 4.859 | 17 |
| evpn-soak | 64 | older-sparse | 2.203 / 11.586 | 5.260 | 4.841 | 17 |
| evpn-soak | 480 | dense | 2.882 / 12.271 | 4.258 | 4.857 | 17 |
| evpn-soak | 480 | older-sparse | 2.969 / 12.262 | 4.130 | 4.833 | 17 |

The common flat shape/count operation over a materialized iterator with a no-op callback can optimize to an O(1) cardinality result. Its roughly half-microsecond measurements are close to clock/bookkeeping overhead; the enormous shared/flat **shape** ratios in the raw summaries are not an operational performance conclusion. The separate counted **shape-only** pass reports one logical flat callback per OLD key. Shared shape reports 22 key comparisons and 23 callbacks per common OLD key, or 17 comparisons and 18 callbacks per EVPN OLD key. These counts exclude reserve/populate/seal comparisons and record-lookup work even though those costs are included in complete-capture timings. A callback count is not a CPU-time measurement.

Per-thread CPU uses a 100 Hz clock (10 ms ticks). All zero-tick samples are retained, and ratios with a zero flat median remain JSON null. EVPN phases are close to this granularity; neither zero ticks nor their occasional nonzero ratios support fine CPU conclusions.

## Proof charge and correctness boundaries

Every target proof matched all requested OLD keys; sparse proofs excluded a removed universe key. There were no refusals. Last-owner retirement restored the observed empty ledger charge: 96 bytes for the common ledger and 104 bytes for EVPN at this exact source. These are current-run observations, not claims about older revisions.

Retained/peak credit records logical daemon ledger reservations, including the anchor universe, record metadata, masks, sparse capacities and charged allocation overlap. It excludes the materialized OLD input, allocator overhead and process RSS. Peak credit is a logical high-water mark. The artifacts preserve both retained and peak values; they must not be presented as whole-daemon or cgroup memory savings.

Fresh hosted scopes passed the recorded process membership/lineage, executable identity, incarnation, swap and OOM checks. Ownership was sampled before, during and after execution, with two launcher/observer members before and after and three members including the workload while active. This is not continuous ownership proof. Original complete archives remain separate; the sanitized compact extract cannot replay their original path-based checks.

No RIB actor/fleet concurrency, production readiness, final encoded-wire behavior, TCP, whole-daemon memory, soak, live EVPN update-group ownership or activation is qualified. The historical manager-direct memory receipts remain separate evidence and are not pooled with these component timings.

## Source and artifacts

The measured source is `5b905336750ee5a8fb9a4e411f2d8d94249a7d7f`. All three profiles use instrumentation manifest SHA-256 `021734a1660ed02fd9bd1a0f080bd14715d20227f0d2f65b1a5da9f28bf8c71b`, built locked in the scale profile with four jobs, Rust 1.99.0 and Cargo 1.99.0. [provenance.json](artifacts/update-group-recovery-capture-scans-2026-10-15/provenance.json) preserves all eight frozen input hashes, manifest/lock/build inputs, three binary digests, original file digests and sampled safety summaries.

| Profile | Original GitHub artifact | ZIP SHA-256 |
| --- | --- | --- |
| full-uc | [11937647682](https://github.com/lance0/rustbgpd/actions/runs/38659117804/artifacts/11937647682) | `1aaa65b3118a93cbe38d07a14fbc8aed39ddb25798567682c86456f67e11e3ef` |
| full-vpn | [11938506460](https://github.com/lance0/rustbgpd/actions/runs/38659117804/artifacts/11938506460) | `b5c5e891dc4d763b89914b295c3ffe61c8016506c7a3e0c2c585a94863665957` |
| evpn-soak | [11938486727](https://github.com/lance0/rustbgpd/actions/runs/38659117804/artifacts/11938486727) | `234e3fc14b826b4725f9ae4a6f77ec4a5af08ca9dc8181fd95370cbcfcde2eb8` |

Hosted artifact links have a 30-day retention policy. Complete checksum-verified archives are retained separately; the links are not a permanent retention guarantee. See the [artifact README](artifacts/update-group-recovery-capture-scans-2026-10-15/README.md).

### Earlier failed premeasurement attempt

[Run 38654266292](https://github.com/lance0/rustbgpd/actions/runs/38654266292), source `5cc4646a255f627a7e1a34fc8ee854f179e93940`, built all three components but rejected missing hosted identity after privilege/environment sanitization. It produced no timing samples and is excluded from every table and ratio above. Its three preserved archive digests are recorded separately in provenance.json; no historical header-size or cost claim is taken from that failed run.

### Valid intermediate measurement

[Run 38654928836](https://github.com/lance0/rustbgpd/actions/runs/38654928836), source `1b26a0a11130f25305788662a81adb0982284362`, independently passed all 18 cells and 72 timed legs. Two subsequent harness failure-path review fixes required the fresh complete run recorded above. The intermediate dataset and its three original archive digests are retained separately in provenance.json and the artifact README. None of its numeric samples enters the current rows, tables or ratios; validity at the intermediate source does not establish measured equivalence to the final source.
