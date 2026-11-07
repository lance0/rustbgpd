# Shared announcement stream retention

> **Document class: HISTORICAL.** Local campaign on 2026-11-07; scope stays tied to these builds.

The candidate releases completed shared announcement buffers before a blocked End-of-RIB and paced inventory retirement. Ownership, allocator release and the final elapsed-time comparisons pass the frozen bars.

Campaign: local Linux 7.0.0-30-generic, AMD Ryzen Threadripper 7970X (32 cores / 64 threads), about 125 GiB visible RAM, CPU 5. Rust 1.99.1 (`58cf8f9c3`), Criterion 0.8.2, jemallocator 0.7.0. No hosted run or public raw-run URL exists for this campaign.

Parent: `e17a00abf3f13a3e2dbe657021ad1597dd1cdf07`. Original candidate source applicability: `255d0479411f4d47af172c7b53486e3269327a8b`. Final candidate: `63e67fe6b4f4451833c0a056b8859a2974da23c2`.
The [comparison JSON](artifacts/shared-stream-retention-2026-11-07/comparison.json) records six unique binary hashes and their source identities. Original builds used equal probe instrumentation on both arms; later test/prose differences did not change compiled behavior. The final commit isolates the probe dependency; its algorithm and production release behavior remain unchanged.

Workloads: two shared-stream members with a delayed follower and blocked End-of-RIB; 1M grouped IPv4 unicast routes, 1M grouped VPN routes, and 100k IPv4 routes with distinct MEDs and 256 communities. The elapsed benchmark has nine direct encoding cells and four 8/32-member failover cells.

Frozen bars and procedure:

- Order A/A, ABBA, then one A/B confirmation. Use distinct binaries, an exclusive host lock and two quiet samples at least 30 seconds apart before each command. The original campaign has 24 fresh memory processes and eight 13-cell timing invocations.
- Every candidate must release the stream before blocked End-of-RIB. Net allocator deallocation must cover retained wire bytes minus the final queued frame, plus chunk-vector capacity.
- For allocated bytes and VmHWM, take the maximum observed across six phases. ABBA candidate means and confirmation must each stay within `max(parent × 1.05, parent + 32 MiB)`.
- Timing uses 30 samples, 1 s warmup and 2 s measurement. Its limit is `max(1.02, symmetric A/A + 0.01)`. A cell fails only when both mean paired ABBA and confirmation ratios exceed that limit.
- Select A/A ratios above 1.02 for independent builds. Preserve each original result and report both fresh and original replica limits. Drop durations remain report-only against the existing 50 ms reference.

| Campaign or retained attempt | Result | Reason |
| --- | --- | --- |
| Nonquiet correctness smokes | INVALID | Four memory and two elapsed smokes had no canonical quiet gates |
| Initial launcher | INVALID | Exit 126 before the lock, quiet gate or measurements; then invoke the unchanged script through bash |
| Original matched instrumentation, 16:15–16:37 UTC | PASS | All three memory shapes and all 13 elapsed cells meet their bars |
| Independent `shared_arc/10000`, 16:51–16:55 UTC | FAIL | ABBA 1.023854× and confirmation 1.026477× exceed fresh 1.02; both pass original 1.032769 |
| Corrected dependency graph, 17:27–17:36 UTC | PASS | All 13 elapsed cells pass; one noisy A/A cell selected |
| Independent `distinct_values/1000`, 17:55–17:59 UTC | PASS | ABBA 1.004155× and confirmation 1.015167× pass fresh 1.02 and original 1.032668 |

The failed replica compared a clean parent with an allocator-control dependency in the candidate. `shared_arc/10000` bypasses the changed constructor; no runtime cause was established. After isolating that dependency, both normal library graphs match and independent builds reproduce both hashes. The failed record remains separate.

| Memory shape | Minimum candidate net deallocated bytes | Allocated ABBA / confirmation | VmHWM ABBA / confirmation | Maximum final-owner drop |
| --- | ---: | --- | --- | ---: |
| `grouped_uc` | 5,157,888 | 1.000000 / 1.000000 | 0.998833 / 1.000249 | 0.060410 ms |
| `grouped_vpn` | 20,639,328 | 1.000000 / 1.000000 | 1.003500 / 1.000042 | 0.839548 ms |
| `diverse_uc` | 137,490,144 | 0.999998 / 0.999981 | 0.999257 / 0.999602 | 2.828177 ms |

Each parent retained its stream at blocked End-of-RIB; each candidate released it while the final writer frame remained owned. The parent/fix/fix-removal ownership regression returned red/green/red. Seeded retention, release, memory and elapsed regressions all failed their checkers.

| Final elapsed cell | A/A | Limit | ABBA | Confirmation | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| `failover_encode/announce_only/32` | 1.000087 | 1.020000 | 0.998497 | 1.009575 | PASS |
| `failover_encode/announce_only/8` | 1.018390 | 1.028390 | 0.997328 | 0.987498 | PASS |
| `failover_encode/mixed/32` | 1.012473 | 1.022473 | 0.996257 | 1.008737 | PASS |
| `failover_encode/mixed/8` | 1.000244 | 1.020000 | 0.997674 | 0.995306 | PASS |
| `outbound_encode/distinct_values/100` | 1.001645 | 1.020000 | 1.010956 | 0.995027 | PASS |
| `outbound_encode/distinct_values/1000` | 1.022668 | 1.032668 | 1.007273 | 0.999850 | PASS |
| `outbound_encode/distinct_values/10000` | 1.006287 | 1.020000 | 1.006685 | 1.002584 | PASS |
| `outbound_encode/equal_values/100` | 1.003793 | 1.020000 | 0.994371 | 0.985528 | PASS |
| `outbound_encode/equal_values/1000` | 1.019439 | 1.029439 | 0.999853 | 1.006540 | PASS |
| `outbound_encode/equal_values/10000` | 1.001613 | 1.020000 | 1.007374 | 1.004904 | PASS |
| `outbound_encode/shared_arc/100` | 1.007306 | 1.020000 | 1.029542 | 1.013955 | PASS |
| `outbound_encode/shared_arc/1000` | 1.019303 | 1.029303 | 0.989535 | 1.016181 | PASS |
| `outbound_encode/shared_arc/10000` | 1.002930 | 1.020000 | 1.023916 | 1.008958 | PASS |

Both `shared_arc/100` and `shared_arc/10000` cross their limit in ABBA only; their confirmations pass. The two-part rule remains unchanged. The independent `distinct_values/1000` control has A/A 1.000661 and passes both limits. All measured commands, quiet gates and final hash checks pass.

VmHWM limitation: a separate barrier-frozen control on this environment reported 2,264 → 7,640 → 2,264 KiB for VmHWM, despite unchanged process identity. Its current-RSS readings agreed. The original maximum-observed bar above remains unchanged; these snapshots do not establish a true lifetime peak RSS. Ownership and allocator-release conclusions do not depend on VmHWM.

Timing covers summed synchronous session intervals with writer drains excluded; it is not CPU time. Allocator release does not establish RSS reduction. This component campaign does not qualify daemon scale, remote application, TCP delivery, convergence or forwarding.

Reproduction uses the existing benchmark and ignored probe; the JSON gives the arm identities, controls, leg order and raw numerical rows:

```sh
cargo bench --locked -p rustbgpd-transport --features bench-internals --bench outbound_encode --no-run
cargo test --release --locked -p rustbgpd-transport --features retention-probe --lib --no-run
```

Run each separately built elapsed binary with `--bench --sample-size 30 --warm-up-time 1 --measurement-time 2 --noplot`. Run the probe `session::tests::shared_group_encode::retention_probe::shared_retention_memory_probe` with `--ignored --exact --nocapture --test-threads=1` and `SHARED_RETENTION_PROBE_SHAPE=grouped_uc`, `grouped_vpn` or `diverse_uc`. Pin each process to CPU 5 under the quiet procedure.

The original probe used `bench-internals` before feature isolation. Apply identical probe instrumentation to the parent and omit the release assignment. The original memory record remains applicable; no second memory campaign ran.

Published evidence: [curated comparison and hash](artifacts/shared-stream-retention-2026-11-07/README.md). Raw local logs remain unchanged; the curated record supplies the medians and memory rows needed to recompute the stated bars.
