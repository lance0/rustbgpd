# v0.84.0 release qualification against v0.83.0 — November 2026

> **Document class: HISTORICAL.** Measurements from 2026-11-22 UTC within the scope below.

This receipt compares the v0.84.0 release candidate with v0.83.0 on policy-reload stall, route-reflector throughput and memory, and the hot-path Criterion benchmarks.

**Verdict.** Every reload-stall bar and every rrharness bar passes. Both reload shapes commit on both releases, so distinct-150 completion has a timing verdict this time; the candidate completes it 11% faster and uses 18% less peak memory. Twelve of 159 gated Criterion cells fail their bars, reported as the cost of the correctness work in this release: eight Add-Path export-staging cells at 64 and 256 candidates (+2–5%), `attr_intern/many_unique/10000` (+3–4%), `bulk_initial_load/10000` (+2%), and two shared-Arc `attr_intern` cells at 10,000 attributes (+88–90%) whose control is bimodal.

## Arms and protocol

- **Control:** tag v0.83.0, `3686a4b67a555db16fa9a3825867f77d0cedb5b3`.
- **Candidate:** `5f5ca6a312d1bdf7094440ae363495574a6ddecc`, the head of the v0.84.0 release preparation: main at `6ac2530f3` plus version metadata, changelogs and documentation, 102 commits after v0.83.0. Its tree is identical to the v0.84.0 squash commit `8ac5f59ab`, and the tag at `0d2c9027a` adds only documentation changes. The daemons report versions 0.83.0 and 0.84.0.

Each side was built separately from its own tree with Rust 1.100.0: the daemon with `cargo build --locked --release -p rustbgpd --features rustbgpd/jemalloc`, rrharness with `--profile scale -p rrharness`, and the Criterion benches with `-C llvm-args=-align-all-functions=6`. All are non-test builds, so the `cfg(test)` checkpoint tally is compiled out on both sides. Every control/candidate binary pair differs by SHA-256 ([`SHA256SUMS`](artifacts/release-qualification-v0840-2026-11/SHA256SUMS)). The two control Criterion builds came out byte-identical, so the Criterion A/A compares one binary with itself.

The host was one Linux machine with a 32-core AMD Ryzen Threadripper 7970X and 125 GiB visible memory. One quiet campaign under the host lock ran reload stall (2026-11-22 06:34–07:51 UTC), rrharness (to 08:06) and Criterion (to 12:54 UTC). Each cell ran A/A (control twice), ABBA, then one confirmation pair; nothing was rerun. A cell fails only when ABBA and confirmation both exceed max(1.02, A/A + 0.01); Criterion calls a cell WIN when both fall below the reciprocal. Every daemon and rrharness leg ran in its own systemd scope with `memory.swap.max=0`, and swap peak was 0 throughout. A process watcher saw no competing build or second daemon in any run, so every point and cell is VALID.

## Reload stall

700 route-server peers × 400,400 IPv4 routes, with churn, a 30 s control window and two reloads per fresh daemon. Grouped 200:2 changes 200 peers in two export-policy groups; distinct 150 changes 150 peers, each with its own export policy. Values are ABBA means. The longest actor turn is the largest RIB actor turn any harness scrape saw; completion is the slowest changed peer's, averaged over the reloads.

| Shape | Metric | v0.83.0 | Candidate | A/A | ABBA | Confirmation | Verdict |
|---|---|---:|---:|---:|---:|---:|---|
| grouped 200:2 | Longest actor turn | 0.850 s | 0.763 s | 1.013 | 0.897 | 0.924 | PASS |
| grouped 200:2 | Completion | 1.70 s | 1.52 s | 1.000 | 0.897 | 0.909 | PASS |
| grouped 200:2 | cgroup peak | 796 MiB | 746 MiB | 1.012 | 0.937 | 0.945 | PASS |
| distinct 150 | Longest actor turn | 0.885 s | 0.779 s | 1.004 | 0.880 | 0.879 | PASS |
| distinct 150 | Completion | 128.0 s | 114.0 s | 1.006 | 0.891 | 0.889 | PASS |
| distinct 150 | cgroup peak | 9,416 MiB | 7,716 MiB | 1.004 | 0.819 | 0.825 | PASS |

Both daemons committed every reload at both shapes (`complete`, generation phase `committed`), so all six rows compare like with like. The v0.83.0 receipt's distinct-150 caveats (a control that rolled the reload back, and a memory row that compared two committed reloads with one rejected reload) do not apply here.

**Measurement.** One `reloadstall` harness binary, built unmodified from the candidate tree, and the candidate's scenario generator served both daemons. The harness and generator sources are identical in the two trees, and v0.83.0 already exports the `coalesced` reload-outcome label, so the v0.83.0 receipt's harness adaptation was not needed. The scorer was changed only to tolerate a point that the quiet-host gate skips; no timed point was skipped.

## rrharness

The fixed matrix of [`compare-rrharness.sh`](../../bench/scale/compare-rrharness.sh): each side's in-process rrharness, built from its own tree, pinned to one core, with 20 s windows. Cost is seconds per flood block or churn wave (lower is better), as ABBA means. Setup time is report-only, with ABBA ratios 0.975–1.024.

| Shape | Cost v0.83.0 → candidate | ABBA / confirmation | Threshold | cgroup peak MiB | ABBA / confirmation | Verdict |
|---|---:|---:|---:|---:|---:|---|
| flood, 256 clients × 100,000 routes | 0.3892 → 0.3913 | 1.005 / 0.994 | 1.020 | 3,065 → 2,955 | 0.964 / 0.967 | PASS |
| flood, 1,000 × 100,000 | 0.9665 → 0.9822 | 1.016 / 1.007 | 1.020 | 1,643 → 1,605 | 0.977 / 0.976 | PASS |
| churn, 256 × 256 × 3,000 | 0.0129 → 0.0132 | 1.023 / 0.995 | 1.036 | 510 → 513 | 1.006 / 1.007 | PASS |
| churn, 1,000 × 1,000 × 3,000 | 0.0403 → 0.0402 | 0.998 / 0.997 | 1.020 | 919 → 917 | 0.998 / 0.998 | PASS |

The memory threshold is 1.020 for every shape except flood 1,000 (1.022).

## Criterion

The `rib_ops` hot families, `fanout`, `outbound_encode` and `codec`, single core, using the median point estimate. There are 166 paired cells: 159 gated and 7 report-only. Gated results are 139 PASS, 8 WIN and 12 FAIL. No cell exists in only one arm.

| Failed family | Cells | A/A | ABBA | Confirmation |
|---|---:|---:|---:|---:|
| `add_path_export_staging`, 64 and 256 candidates | 8 | 1.001–1.023 | 1.027–1.051 | 1.023–1.052 |
| `attr_intern/many_unique/10000` | 1 | 0.998 | 1.028 | 1.039 |
| `attr_intern` shared-Arc, 10,000 attributes | 2 | 1.402–1.572 | 1.879–1.897 | 1.882–1.904 |
| `bulk_initial_load/10000` | 1 | 0.994 | 1.022 | 1.025 |

The Add-Path export-staging cost grows with candidate count: the 8-candidate rows are also 4–7% slower, but they pass because their A/A ratios are 1.046–1.093. The two shared-Arc `attr_intern` cells are bimodal on the control: five of its six runs measured 39–42 µs and one measured 58–64 µs, on byte-identical binaries, while all three candidate runs measured 68–85 µs. Their 100,000-attribute siblings and the independent-equal cells pass. The attribute-interning table and the benchmark sources are unchanged between the two tags. This campaign does not attribute any failure to a commit.

The 8 wins: 4 `policy_regroup_resync` cells (ABBA 0.932–0.964), `initial_table_peer_join/rr_client_ipv4_unicast/65536` (0.876), `route_refresh_group_member/8_sources/65536` (0.964), one `ixp_policy_regroup_resync` cell (0.977) and `attr_decode_revised/typical/6` (0.938). The report-only cells are the 4 `private_single_best_fanout/policy_peer_context` cells, which are noisy by nature, `adj_rib_in_insert/100000` and `rib_pipeline/50000`, which are bimodal per process, and `adj_rib_in_insert/500000`, report-only since 2026-11-16 for an unstable control (A/A 1.136 here). All seven would pass. The v0.83.0 receipt gated `adj_rib_in_insert/500000`; it is report-only here.

The fanout families that failed in the v0.83.0 receipt (`distribute_fanout`, `ixp_exact_export_fanout`, `adj_rib_out_family_gauge` and `queued_announce_fanout`) pass against v0.83.0.

## Scope

- Host loopback on one machine: no NIC, no second host, no WAN latency.
- Criterion runs on a single core and times isolated functions, not daemon throughput.
- One campaign; no cell was replicated from an independent build.
- These shapes only: no scale or cross-daemon claim.

The [campaign record](artifacts/release-qualification-v0840-2026-11/README.md) lists the curated reload-stall and rrharness JSON, the full Criterion table and the binary hashes.
