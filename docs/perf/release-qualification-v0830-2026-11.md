# v0.83.0 release qualification against v0.82.0 — November 2026

> **Document class: HISTORICAL.** Measurements from 2026-11-14 and 2026-11-15 UTC within the scope below.

This receipt compares the v0.83.0 release candidate with v0.82.0 on policy-reload stall, route-reflector throughput and memory, and the hot-path Criterion benchmarks.

**Verdict.** Every reload-stall turn and completion bar and every rrharness bar passes. Two items fail their bars and were accepted as the cost of correctness work: the distinct-150 reload's cgroup peak (+3.0% ABBA, +4.0% confirmation; not a like-for-like comparison) and 24 of 156 gated Criterion cells, 23 of them wide-fanout distribution cells at 64 peers and up (+2–5%). v0.82.0 rolled back the distinct-150 reload at every point; the candidate committed it every time.

## Arms and protocol

- **Control:** tag v0.82.0, `608dcaea0902272474bd2a25bcf30bff3dd3153b`.
- **Candidate:** `6aeeaa2e088ef3d4e4ed5aff663e22cd3a82b6c4`, 125 commits after v0.82.0. The v0.83.0 tag differs from it only in version metadata, changelogs and documentation. Both daemons report version 0.82.0.

Each side was built separately from its own tree with Rust 1.100.0: the daemon with `cargo build --locked --release -p rustbgpd --features rustbgpd/jemalloc`, rrharness with `--profile scale -p rrharness`, and the Criterion benches with `-C llvm-args=-align-all-functions=6`. Every control/candidate binary pair differs by SHA-256 ([`SHA256SUMS`](artifacts/release-qualification-v0830-2026-11/SHA256SUMS)). The two control Criterion builds came out byte-identical, so the Criterion A/A compares one binary with itself.

The host was one Linux machine with a 32-core AMD Ryzen Threadripper 7970X and 125 GiB visible memory. One quiet campaign under the host lock ran reload stall (2026-11-14 22:01–23:29 UTC), rrharness (to 23:44) and Criterion (to 2026-11-15 04:26). Each cell ran A/A (control twice), ABBA, then one confirmation pair; nothing was rerun. A cell fails only when ABBA and confirmation both exceed max(1.02, A/A + 0.01); Criterion calls a cell WIN when both fall below the reciprocal. Every daemon and rrharness leg ran in its own systemd scope with `memory.swap.max=0`, and swap peak was 0 throughout. A process watcher saw no competing build or second daemon in any run, so every point and cell is VALID.

## Reload stall

700 route-server peers × 400,400 IPv4 routes, with churn, a 30 s control window and two reloads per fresh daemon. Grouped 200:2 changes 200 peers in two export-policy groups; distinct 150 changes 150 peers, each with its own export policy. Values are ABBA means. The longest actor turn is the largest RIB actor turn any harness scrape saw; completion is the slowest changed peer's, averaged over the reloads.

| Shape | Metric | v0.82.0 | Candidate | A/A | ABBA | Confirmation | Verdict |
|---|---|---:|---:|---:|---:|---:|---|
| grouped 200:2 | Longest actor turn | 1.508 s | 0.856 s | 1.025 | 0.567 | 0.594 | PASS |
| grouped 200:2 | Completion | 106.9 s | 1.71 s | 1.007 | 0.016 | 0.016 | PASS |
| grouped 200:2 | cgroup peak | 861 MiB | 775 MiB | 1.004 | 0.900 | 0.883 | PASS |
| distinct 150 | Longest actor turn | 67.7 s | 0.868 s | 1.008 | 0.013 | 0.013 | PASS |
| distinct 150 | Completion | rolled back, 5 of 5 points | 128.6 s, committed | – | – | – | no ratio |
| distinct 150 | cgroup peak | 9,134 MiB | 9,407 MiB | 1.003 | 1.030 | 1.040 | FAIL, accepted |

The candidate committed every reload at both shapes. v0.82.0 committed the grouped reloads but rejected the first distinct-150 reload at all five points (`rejected_no_effect`): its RIB manager did not reply within the 120 s shared policy-walk budget, and the daemon restored the peers it had already changed. The 67 s turn is that restore. It ends 187.7–189.8 s after the SIGHUP, and no earlier scrape saw a turn above 1.52 s.

**Distinct-150 memory is not like-for-like.** Steady RSS before the reload was equal: 7,858–7,862 MiB in the control window on all eight points. The candidate then commits two full 150-peer export generations, while v0.82.0 runs one walk, fails it and restores; the harness stops at a rejected reload. The 274 MiB higher peak was accepted as the cost of a committed reload. A single-reload comparison was not run.

**Measurement change.** The candidate's `reloadstall` harness requires `bgp_sighup_reload_outcomes_total{outcome="coalesced"}`, which v0.82.0 exports as `ignored_in_flight`, and v0.82.0's own harness has no actor-turn records. One function in the candidate harness was changed to count either label, each optional ([diff](artifacts/release-qualification-v0830-2026-11/reloadstall-harness-adapt.diff)); the candidate's result is unchanged by it. One harness binary and the candidate's scenario generator served both daemons, and v0.82.0 accepts the generated configuration with `--check`. The harness is not part of the daemon package.

## rrharness

The fixed matrix of [`compare-rrharness.sh`](../../bench/scale/compare-rrharness.sh): each side's in-process rrharness, built from its own tree, pinned to one core, with 20 s windows. Cost is seconds per flood block or churn wave (lower is better), as ABBA means. Setup time is report-only, with ABBA ratios 0.979–1.023.

| Shape | Cost v0.82.0 → candidate | ABBA / confirmation | Threshold | cgroup peak MiB | ABBA / confirmation | Verdict |
|---|---:|---:|---:|---:|---:|---|
| flood, 256 clients × 100,000 routes | 0.3969 → 0.3981 | 1.003 / 0.990 | 1.024 | 3,048 → 3,048 | 1.000 / 1.004 | PASS |
| flood, 1,000 × 100,000 | 0.9907 → 0.9767 | 0.986 / 0.974 | 1.022 | 1,642 → 1,653 | 1.007 / 1.021 | PASS |
| churn, 256 × 256 × 3,000 | 0.0137 → 0.0129 | 0.943 / 1.024 | 1.025 | 508 → 507 | 0.998 / 1.009 | PASS |
| churn, 1,000 × 1,000 × 3,000 | 0.0407 → 0.0404 | 0.995 / 0.978 | 1.020 | 920 → 920 | 1.001 / 1.002 | PASS |

The memory threshold is 1.020 for every shape.

## Criterion

The `rib_ops` hot families, `fanout`, `outbound_encode` and `codec`, single core, using the median point estimate. There are 162 paired cells: 156 gated and 6 report-only. Gated results are 108 PASS, 24 WIN and 24 FAIL. Four cells exist only in the candidate and are unpaired.

| Failed family | Cells | ABBA | Confirmation |
|---|---:|---:|---:|
| `distribute_fanout`, 64 and 256 peers | 6 | 1.038–1.054 | 1.031–1.045 |
| `ixp_exact_export_fanout`, 64 and 256 peers | 4 | 1.036–1.049 | 1.028–1.042 |
| `adj_rib_out_family_gauge` second pass, 64, 256 and 1,000 peers | 3 | 1.034–1.047 | 1.043–1.050 |
| `queued_announce_fanout`, 64 peers | 10 | 1.022–1.052 | 1.020–1.046 |
| `adj_rib_in_insert/500000` | 1 | 1.022 | 1.102 |

The fanout cells' A/A ratios are 0.993–1.014, and the first three families pass at 8 peers (and at 1 peer where measured), so the cost grows with fanout width. It was accepted for this release as the cost of the correctness work between the two tags; this campaign does not attribute it to a commit. `adj_rib_in_insert/500000` fails mostly on its confirmation pair, and its 100,000-route sibling is report-only for allocator bimodality.

The 24 wins: 8 `outbound_encode` cells (ABBA 0.615–0.950), 8 `outbound_admission` cells (0.638–0.873), 3 `mp_exact_export_probe` cells (0.787–0.899), one cell each of `attr_decode`, `attr_encode` and `failover_encode` (0.907–0.923), and 2 `attr_intern` shared-Arc cells (0.528–0.599, with A/A 0.534–0.639, so noisy). The report-only cells are the 4 `private_single_best_fanout/policy_peer_context` cells, which are noisy by nature, plus `adj_rib_in_insert/100000` and `rib_pipeline/50000`. All six would pass.

## Crash-and-reload pass

A functional, untimed pass at the same 700 × 400,400 shapes passed four driven cases: a rejected reload with full restore at both shapes, a peer killed and restarted during the restore, and a BFD flap during the policy walk. There were no fail-stop or fence events and no nonzero exits. Two cases, a session-task crash and a graceful-restart reconnect replaced before its end is processed, cannot be driven against a release build and are covered only by small-scale tests.

## Scope

- Host loopback on one machine: no NIC, no second host, no WAN latency.
- Criterion runs on a single core and times isolated functions, not daemon throughput.
- One campaign; no cell was replicated from an independent build.
- The distinct-150 memory row compares two committed reloads with one rejected reload.
- The crash-and-reload pass is functional only; it measures no timing.
- These shapes only: no scale or cross-daemon claim.

The [campaign record](artifacts/release-qualification-v0830-2026-11/README.md) lists the curated reload-stall and rrharness JSON, the full Criterion table, the harness diff and the binary hashes.
