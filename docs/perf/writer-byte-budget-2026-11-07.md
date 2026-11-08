# Complete-frame writer admission — November 2026

> **Document class: HISTORICAL.** Measurements from 2026-11-07 within the scope below.

This receipt records a writer's queued-byte bound and the measured cost of outbound admission and encoding for one session.

**Measured correctness cost accepted.** The historical timing rule remains FAIL: 24 of 30 cells pass and 6 have confirmed regressions. No further timing campaign is required.
The [campaign record](artifacts/writer-byte-budget-2026-11-07/README.md) links the [curated comparison](artifacts/writer-byte-budget-2026-11-07/comparison.json), with all 30 final timing cells and four allocation cases.

The control is `e17a00abf3f13a3e2dbe657021ad1597dd1cdf07`; the candidate is `1550b47f722a76a11a6e8d733625b531ff31ca76`. Both use the same benchmark definitions and library feature graph. Independent builds produced matching corresponding executable hashes. The host ran Linux 7.0.0-30-generic on a 32-core AMD Ryzen Threadripper 7970X with 125 GiB visible memory and no swap, Rust 1.99.1 and Criterion 0.8.2. Timed executables use jemalloc; separate allocation fixtures use a System wrapper.

The final source checks negotiated-maximum frame headroom inside each ordinary chunked sender and exact length for already encoded shared frames. It resumes partially sent groups from source indices and preserves original ownership. RIB attribute storage and export preparation match the parent; the estimator and its inbound timing scope were removed. No inbound timing scope applies to this final change.

The matrix contains 30 outbound cells: nine direct encoding, four shared failover, and 17 admission cases covering unicast, EVPN, VPN and global/VPN FlowSpec. Admission normally has 10,000 rows; the two large-attribute cases have 2,049. Each cell runs A/A, ABBA, then A/B confirmation, with 30 Criterion samples, a 1 s warm-up and a 2 s measurement target, pinned to CPU 5.

The direct encoder's mock sink drains only after the complete call. Its completion watch is temporarily removed outside the measured interval in both arms, preserving full encoding without byte-pressure admission. The other 21 cells retain the production completion watermark. A pre-timing smoke rejected incomplete direct output before this common harness correction; both arms were then rebuilt. All workloads, timer boundaries and the full-completion assertion remain.

Every leg uses the host lock and two accepted quiet samples at least 30 s apart: load below 2, performance governors, no competing work and no swap delta. The statistic is the median. A/A is `max(A1,A2)/min(A1,A2)`; ABBA is the mean of its two B/A pairs. A cell fails only when both ABBA and confirmation exceed `max(1.02, A/A + 0.01)`. A/A above 1.02 selected independent replication under the original protocol. After the complete campaign failed and its cost was accepted, no further measurements were run. The original timing rules and observations are preserved.

| Cell | A/A | Bar | ABBA | Confirmation | Verdict |
|---|---:|---:|---:|---:|---|
| `failover_encode/announce_only/32` | 1.055747 | 1.065747 | 0.995866 | 0.985046 | PASS |
| `failover_encode/announce_only/8` | 1.002457 | 1.020000 | 1.014710 | 0.989299 | PASS |
| `failover_encode/mixed/32` | 1.004368 | 1.020000 | 1.014308 | 1.000666 | PASS |
| `failover_encode/mixed/8` | 1.009496 | 1.020000 | 1.002976 | 0.989932 | PASS |
| `outbound_admission/distinct_values` | 1.000594 | 1.020000 | 1.030702 | 1.031608 | FAIL |
| `outbound_admission/equal_values` | 1.003464 | 1.020000 | 1.000719 | 1.003615 | PASS |
| `outbound_admission/evpn_distinct_values` | 1.001794 | 1.020000 | 1.019680 | 1.000143 | PASS |
| `outbound_admission/evpn_shared_arc` | 1.000630 | 1.020000 | 1.006505 | 1.015491 | PASS |
| `outbound_admission/evpn_withdraw` | 1.001793 | 1.020000 | 1.014634 | 1.040218 | PASS |
| `outbound_admission/flowspec_v4_distinct_values` | 1.062119 | 1.072119 | 1.080784 | 0.886899 | PASS |
| `outbound_admission/flowspec_v4_equal_values` | 1.015079 | 1.025079 | 1.002923 | 0.999039 | PASS |
| `outbound_admission/flowspec_v4_withdraw` | 1.004208 | 1.020000 | 1.004862 | 1.010480 | PASS |
| `outbound_admission/large_extended` | 1.053653 | 1.063653 | 0.619366 | 0.603507 | PASS |
| `outbound_admission/large_standard` | 1.004325 | 1.020000 | 1.020829 | 1.136513 | FAIL |
| `outbound_admission/shared_arc` | 1.000367 | 1.020000 | 0.985240 | 1.021214 | PASS |
| `outbound_admission/vpn_distinct_values` | 1.001684 | 1.020000 | 1.074727 | 1.064663 | FAIL |
| `outbound_admission/vpn_flowspec_v6_distinct_values` | 1.072349 | 1.082349 | 1.069503 | 0.936034 | PASS |
| `outbound_admission/vpn_flowspec_v6_equal_values` | 1.008204 | 1.020000 | 0.998719 | 0.969900 | PASS |
| `outbound_admission/vpn_flowspec_v6_withdraw` | 1.002808 | 1.020000 | 0.995924 | 0.998111 | PASS |
| `outbound_admission/vpn_shared_arc` | 1.008011 | 1.020000 | 0.930002 | 0.965432 | PASS |
| `outbound_admission/vpn_withdraw` | 1.013886 | 1.023886 | 0.948867 | 0.955767 | PASS |
| `outbound_encode/distinct_values/100` | 1.010089 | 1.020089 | 1.026396 | 1.032186 | FAIL |
| `outbound_encode/distinct_values/1000` | 1.008642 | 1.020000 | 1.019396 | 1.031879 | PASS |
| `outbound_encode/distinct_values/10000` | 1.004540 | 1.020000 | 1.028521 | 1.038085 | FAIL |
| `outbound_encode/equal_values/100` | 1.004535 | 1.020000 | 1.009529 | 1.008605 | PASS |
| `outbound_encode/equal_values/1000` | 1.006211 | 1.020000 | 1.005565 | 0.999531 | PASS |
| `outbound_encode/equal_values/10000` | 1.004480 | 1.020000 | 1.008133 | 1.014194 | PASS |
| `outbound_encode/shared_arc/100` | 1.000429 | 1.020000 | 1.070093 | 1.018188 | PASS |
| `outbound_encode/shared_arc/1000` | 1.009673 | 1.020000 | 1.017856 | 1.038440 | PASS |
| `outbound_encode/shared_arc/10000` | 1.000185 | 1.020000 | 1.031815 | 1.026807 | FAIL |

Verdicts use unrounded values; the comparison JSON retains all medians and both ABBA pair ratios.
Independent noisy-cell replication was not run because the full candidate campaign has confirmed failures.

The allocation fixture injects OPEN/KEEPALIVE through the FSM, aborts the writer task, and replaces its channel with a controlled 4,096-slot writer. Two cases use 2,049 distinct large updates in standard/extended modes. Two use 10,000 distinct global IPv4/VPN IPv6 FlowSpec rules. Each makes 1,024 blocked advances, then drains the complete writer and envelope. FlowSpec checks every decoded rule and End-of-RIB in order. Input fixtures remain alive and are excluded from requested-allocation deltas.

The bars cap held writer bytes at 655,358, require no allocation growth while blocked, and require drain/drop allocations at or below the pre-admission baseline. The fixed FlowSpec shapes also require peak requested-allocation deltas no higher than parent + 1 MiB. That prospective transient-scratch bar is separate from the writer cap and makes no general memory claim.

| Candidate case | Peak held bytes | Held frames | Retained requested delta | Peak requested delta | Blocked growth |
|---|---:|---:|---:|---:|---:|
| Standard | 654,143 | 161 | 822,483 B | 19,717,771 B | 0 B |
| Extended | 654,630 | 10 | 818,898 B | 271,210,398 B | 0 B |
| Global IPv4 FlowSpec, distinct | 315,392 | 4,096 | 450,124 B | 1,880,897 B | 0 B |
| VPN IPv6 FlowSpec, distinct | 401,408 | 4,096 | 536,140 B | 1,940,390 B | 0 B |

All four candidate cases pass the fixed bars. Large-message cases block on bytes; FlowSpec fills the slots first, leaving 5,904 unsent rules. Ordinary drains have 2,050 frames and match parent byte totals; FlowSpec has 10,001 frames with byte-identical ordered output. Drain/drop bars pass. AttrSet remains 56 B, alignment 8, with a 72 B requested Arc allocation. The extended preparation peak is 271,210,398 B versus 404,539,140 B in the parent: the strict queued-byte cap does not bound temporary slice preparation.

The expected parent control queues 8,321,024 / 134,068,224 B in standard/extended modes, exceeding the unchanged 655,358 B bound. The candidate’s extended preparation peak is transient per active peer slice: both next-hop attribute forms are prepared eagerly, then released before the writer pauses. The paused additional allocation is 818,898 B, including 654,630 queued B. Concurrent active preparation can compound peaks; reducing it is separate follow-up work.

The optional real-TCP comparison is INVALID: the parent's Linux peak-memory accounting check failed before any candidate repetition. That measurement-tool defect is tracked separately and excluded from this correctness gate. It supplies no candidate TCP performance result.

The 4 ms pacing target and initial charging boundary are unchanged. Both begin charging after source-slice materialization. The candidate also charges partial-group resumption. After this campaign, a resume only halves the next fresh slice when it overruns the target and never doubles it, and the six FlowSpec admission cells left the benchmark with the sizing walk they measured; neither later change was timed. The entrypoint is `just bench rustbgpd-transport outbound_encode`; the campaign record gives the immutable-executable sequence. There is no hosted Actions run for these measurements.

Outbound timings sum synchronous admission/encoding intervals and exclude writer draining. They establish neither thread CPU time nor TCP throughput. Requested allocations establish neither RSS nor whole-daemon capacity. This record does not qualify private or non-unicast TCP delivery, fleet scale, sustained memory behavior, forwarding or release-wide performance.
