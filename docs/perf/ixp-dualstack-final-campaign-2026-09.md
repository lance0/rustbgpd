# Dual-stack policy-reload final campaign (2026-09)

This campaign checks dual-stack policy delivery and operator responsiveness across permit-preserving and filtering changes at 200 and 700 route-server members.

**All 13 cells passed supplemental gate v3:** the 20-member correctness cell, all four 200-member validations, and two complete four-cell 700-member campaigns. Eight cells also passed original gate v2. Five 700-member cells retain original v2 failures, each for 700 independently classified cleanup TCP-refusal warnings. No original result was overwritten or measured cell rerun to change its result.

## Source and executable identity

The measured source is `5dde6775a38bbc3e53a4d75a4a2563890e92f3c6`, tree `28179cfd569d2c56f66cc9faf793d48db84571ce`. The daemon identifies as **0.69.0**. It uses the normal release build, with no readiness diagnostic feature. The [build records](artifacts/ixp-dualstack-final-campaign-2026-09/20-50-F/build-receipt/commands.txt) bind the daemon, CLI, and reload harness to that source.

Daemon runtime source is unchanged from `4b0225b48ab1923aded42641c6cc505901ed987c`, the source selected for the separate qualifying soak. Changes since that revision affect measurement tooling, CI, and documentation. This receipt does not establish the outcome of that soak or qualify future 0.70.0 release binaries.

| Executable | SHA-256 |
|---|---|
| `rustbgpd` | `fdc5d032edf73e71344b505cfa4603d25113e1aac809f9e94a520b649ea782d0` |
| `rbgp` | `668bb6da048bda3d87d652ba81e50927394e43433c5f4122fd4ab18cc7cf4a61` |
| `reloadstall` | `bcec0a6876db258a2049769dd5c732acbc2fa504921547353019b710484af642` |

The daemon and CLI hashes match the earlier [accepted readiness pair](ixp-dualstack-readiness-2026-09.md#final-normal-pair-after-all-three-tooling-repairs). The harness now requires terminal daemon reload success together with receiver completion before recording a successful row or starting the next policy generation. The earlier pair and failed attempts remain at their original receipt paths.

## Pinned workload and completed cells

Each member establishes one IPv4 transport session negotiating IPv4 and IPv6 unicast. Routes are disjoint unique inventories, split among members using quotient/remainder allocation. P swaps a policy community while preserving the permit set; F removes base indexes `0..32` per family in generation B and restores them in A.

| Members | Total routes | IPv4 / IPv6 at 90/10 | IPv4 / IPv6 at 50/50 | Changed / stable |
|---|---:|---:|---:|---:|
| 20 correctness | 11,440 | — | 5,720 / 5,720 | 16 / 4 |
| 200 validation | 114,400 | 102,960 / 11,440 | 57,200 / 57,200 | 170 / 30 |
| 700 campaign | 400,400 | 360,360 / 40,040 | 200,200 / 200,200 | 600 / 100 |

Every cell uses four B/A/B/A reloads, a 30-second control window and 20-second cycle quiescence. Eight churners toggle 16 prefixes per family every 125 ms. F expects 480, 5,408, or 19,168 named withdrawals per family on each B reload at 20, 200, or 700 members respectively. P expects no filtering withdrawals.

| Cell | Status |
|---|---|
| 20, 50/50 F | PASS |
| 200, 90/10 P | PASS |
| 200, 90/10 F | PASS |
| 200, 50/50 P | PASS |
| 200, 50/50 F | PASS |
| 700 A, 90/10 P | Supplemental v3 PASS; original v2 FAIL retained |
| 700 A, 90/10 F | PASS under v2 and v3 |
| 700 A, 50/50 P | PASS under v2 and v3 |
| 700 A, 50/50 F | Supplemental v3 PASS; original v2 FAIL retained |
| 700 B, 90/10 P | PASS under v2 and v3 |
| 700 B, 90/10 F | Supplemental v3 PASS; original v2 FAIL retained |
| 700 B, 50/50 P | Supplemental v3 PASS; original v2 FAIL retained |
| 700 B, 50/50 F | Supplemental v3 PASS; original v2 FAIL retained |

Each 700-member cell requires a passing corresponding 200-member mix/shape with identical source and executable hashes. A and B denote separate full-shape campaigns, each covering all four workload combinations. Four reload cycles inside one cell are not four independent trials.

The retained original gate (v2) requires exact initial per-family inventories, complete receiver generations, named withdrawals, fresh stable-observer markers, actual churn writes within delivery intervals, all sessions, zero parse/leak/bystander/stable/duplicate errors, successful sampled health/RIB commands, acceptable RSS, and full daemon-log classification. Gate SHA-256 is `9ec25e91d1a2ed9a2a8c55d7a251cff4b3e31214e7e753a4ebf3940dcee16543`.

The runner retains the host mutex, two quiet samples 30 seconds apart, a 100-GiB process-tree RSS guard, 900-second outer abort ceiling and 300-second cooldown. Health loop delay is 50 ms after each command; alternating-family RIB query delay is 250 ms after each command. These are not fixed-rate sampling guarantees.

## Completed 20-member correctness cell

The [retained cell summary](artifacts/ixp-dualstack-final-campaign-2026-09/20-50-F/summary.json) covers 15:43:40–15:51:09 UTC on September 10, including admission and cooldown.

| Measurement | Observed |
|---|---:|
| Operating gate | PASS |
| Health starts / completed rows | 1,862 / 1,862 |
| Failed health rows | 0 |
| Health command p95 / maximum | 8.9 / 23.3 ms |
| RIB query rows / failures | 846 / 0 |
| RIB command p95 / maximum | 8.8 / 13.7 ms |
| Maximum IPv4 / IPv6 receiver completion | 0.082474 / 0.082478 s |
| Median full-generation duration | 40.3185 ms |
| Daemon VmHWM | 58,692 KiB |
| Maximum sampled process-tree RSS | 61,868 KiB |

All four reloads retained 20 sessions, four fresh stable observers per family, exact inventories, and the expected 480 withdrawals per family on B reloads. All receiver error counters were zero. Every health start has one successful result and no stderr. Native harness, cleanup, cell, daemon wait, driver, gate, and provenance exits were zero. The classifier retained one accepted startup warning and 190 accepted teardown warnings; no daemon ERROR was present.

Command durations measure complete CLI wall time, not RPC duration. RIB-query invocation starts are not recorded, so their counts cover retained rows. Receiver completion and full-generation duration have different endpoints. This small correctness observation does not establish 200/700-member acceptance, comparative performance, or endurance qualification.

## Completed 200-member validation

All four combinations passed the unchanged gate on the same source and exact executable hashes. Each completed four B/A/B/A reloads with 200 sessions, 30 stable observers per family, exact family inventories and actual churn overlap. F cells delivered 5,408 named withdrawals per family on each B reload; P cells recorded no filtering withdrawals. All receiver error counters were zero.

| Mix / shape | Health starts / results | Health p95 / max (ms) | RIB rows | RIB p95 / max (ms) |
|---|---:|---:|---:|---:|
| [90/10 P](artifacts/ixp-dualstack-final-campaign-2026-09/200-90-P/summary.json) | 1,924 / 1,924 | 9.4 / 288.4 | 872 | 10.3 / 88.9 |
| [90/10 F](artifacts/ixp-dualstack-final-campaign-2026-09/200-90-F/summary.json) | 1,912 / 1,912 | 9.4 / 255.7 | 868 | 10.3 / 255.3 |
| [50/50 P](artifacts/ixp-dualstack-final-campaign-2026-09/200-50-P/summary.json) | 1,922 / 1,922 | 9.5 / 185.4 | 870 | 10.5 / 177.3 |
| [50/50 F](artifacts/ixp-dualstack-final-campaign-2026-09/200-50-F/summary.json) | 1,907 / 1,907 | 9.5 / 290.9 | 866 | 10.6 / 302.5 |

Every health invocation has exactly one matching successful result, with no duplicate keys, missing rows, or stderr. All retained RIB queries succeeded. These timings include complete CLI execution; an observation above 200 ms does not establish an RPC exceeding its health deadline.

| Mix / shape | Full-generation median (ms) | Maximum IPv4 / IPv6 completion (s) | VmHWM (KiB) | Sampled process-tree RSS max (KiB) |
|---|---:|---:|---:|---:|
| 90/10 P | 285.3360 | 0.384057 / 0.384060 | 232,184 | 191,408 |
| 90/10 F | 453.1440 | 0.554399 / 0.554394 | 259,968 | 200,424 |
| 50/50 P | 330.1995 | 0.398010 / 0.398006 | 221,924 | 186,356 |
| 50/50 F | 501.1315 | 0.588507 / 0.588513 | 243,308 | 190,776 |

Native harness, cleanup, cell, daemon wait, driver, gate and provenance exits were zero for every cell. Each daemon log retained one accepted startup warning. Accepted teardown warnings numbered 19,775, 19,768, 19,779 and 19,811 respectively in the table order; no rejected warnings or daemon ERROR records were present. Full logs and the unchanged classifications remain in each cell.

These four cells establish the corresponding 200-member validation prerequisites. The two subsequent full-shape campaigns are recorded below.

## First 700-member cell: retained classifier failure

The 700-member A, 90/10 P cell completed with native harness, cleanup, driver and provenance exits zero, but **original gate v2 failed** on 700 `TCP connect failed` warnings. Its original checker, `gate.exit`, `evidence.json` and complete daemon log remain unchanged. Supplemental v3 now passes after classifying exactly those 700 warnings, with zero remaining errors. The cell is accepted under that explicitly revised classification.

The warnings occurred during cleanup. Each affected peer had received Administrative Shutdown (`Cease`, code 6, subcode 2) and logged its own session-down after measured delivery completed. The harness deliberately closes its clients after final quiescence. The daemon remains running while the outer runner observes harness exit and joins probes; its normal reconnect timer can expire during that interval. A connection refusal after an established session logs WARN, whereas a first startup refusal logs INFO. The pinned source shows [client finish](https://github.com/lance0/rustbgpd/blob/5dde6775a38bbc3e53a4d75a4a2563890e92f3c6/bench/scale/reloadstall/src/main.rs#L527), [outer cleanup ordering](https://github.com/lance0/rustbgpd/blob/5dde6775a38bbc3e53a4d75a4a2563890e92f3c6/bench/scale/matrix/run-matrix.sh#L443), [deferred reconnect](https://github.com/lance0/rustbgpd/blob/5dde6775a38bbc3e53a4d75a4a2563890e92f3c6/crates/transport/src/session/fsm.rs#L533), and [connect-failure log levels](https://github.com/lance0/rustbgpd/blob/5dde6775a38bbc3e53a4d75a4a2563890e92f3c6/crates/transport/src/session/io.rs#L45).

Supplemental gate v3 keeps every v2 check and error except an individually proven cleanup refusal. Eligibility requires the exact `TCP connect failed` WARN, `failure_source=socket`, `previously_established=true`, and `Connection refused (os error 111)`. The same peer must have received `Cease/6/2` after final measured completion, then logged its corresponding session-down before the warning. Any intervening establishment, including a state transition to `established`, invalidates that sequence. Only candidate peers' post-completion records establish this exception; unrelated startup log ordering cannot create a new failure. Missing or malformed candidate evidence fails closed. Active warnings, other notifications or errors, session losses, and health/receiver/RSS failures remain failures.

The supplemental result records the original pass/errors, checker identity, classification method and each accepted warning's peer/timestamp. It is a separate analysis of retained measurements, not a rerun or a replacement of the original failed result. Synthetic negative checks cover the rejected variants. All 13 completed cells passed supplemental replay. Eight retain original v2 passes. The five original v2 failures are 700 A, 90/10 P; 700 A, 50/50 F; 700 B, 90/10 F; 700 B, 50/50 P; and 700 B, 50/50 F. Each retains 700 original TCP-refusal errors and a separate v3 pass with zero remaining errors. The frozen v3 SHA-256 is `8e6405fa52d34d2963b1859d59704293d884fe6057263f79f1d69954f64da773`.

## Completed 700-member campaigns

Both A and B passed all four combinations under supplemental v3, using identical source and executable hashes and a passing corresponding 200-member prerequisite. Every cell has complete health start/result capture. The original v2 outcome and corrected warning count remain separate below. No receiver, health, query, session or resource failure was removed by the supplemental classification.

| Cell | Original v2 | Reclassified cleanup WARNs | Health starts / results | Health p95 / max (ms) | RIB rows | RIB p95 / max (ms) |
|---|---|---:|---:|---:|---:|---:|
| [700-A-90-P](artifacts/ixp-dualstack-final-campaign-2026-09/700-A-90-P/summary.json) | FAIL | 700 | 2,041 / 2,041 | 14.2 / 545.9 | 924 | 18.3 / 586.1 |
| [700-A-90-F](artifacts/ixp-dualstack-final-campaign-2026-09/700-A-90-F/summary.json) | PASS | 0 | 2,026 / 2,026 | 12.9 / 1452.1 | 922 | 17.8 / 862.7 |
| [700-A-50-P](artifacts/ixp-dualstack-final-campaign-2026-09/700-A-50-P/summary.json) | PASS | 0 | 2,035 / 2,035 | 15.5 / 341.7 | 915 | 18.9 / 800.5 |
| [700-A-50-F](artifacts/ixp-dualstack-final-campaign-2026-09/700-A-50-F/summary.json) | FAIL | 700 | 2,054 / 2,054 | 14.4 / 1107.4 | 938 | 33.7 / 964.9 |
| [700-B-90-P](artifacts/ixp-dualstack-final-campaign-2026-09/700-B-90-P/summary.json) | PASS | 0 | 2,050 / 2,050 | 13.5 / 401.9 | 922 | 18.0 / 678.9 |
| [700-B-90-F](artifacts/ixp-dualstack-final-campaign-2026-09/700-B-90-F/summary.json) | FAIL | 700 | 2,056 / 2,056 | 13.5 / 1033.3 | 942 | 25.8 / 1046.3 |
| [700-B-50-P](artifacts/ixp-dualstack-final-campaign-2026-09/700-B-50-P/summary.json) | FAIL | 700 | 2,038 / 2,038 | 14.5 / 742.9 | 918 | 21.0 / 713.3 |
| [700-B-50-F](artifacts/ixp-dualstack-final-campaign-2026-09/700-B-50-F/summary.json) | FAIL | 700 | 2,052 / 2,052 | 14.5 / 1108.7 | 936 | 30.9 / 1181.0 |

| Cell | Full-generation median (ms) | Maximum IPv4 / IPv6 completion (s) | VmHWM (KiB) | Sampled process-tree RSS max (KiB) |
|---|---:|---:|---:|---:|
| 700-A-90-P | 1469.5070 | 2.514999 / 2.515002 | 734,816 | 599,148 |
| 700-A-90-F | 2173.5715 | 3.661426 / 3.661429 | 822,908 | 832,356 |
| 700-A-50-P | 1629.7585 | 2.604856 / 2.604860 | 717,292 | 567,284 |
| 700-A-50-F | 2399.7030 | 4.093423 / 4.093419 | 802,380 | 678,548 |
| 700-B-90-P | 1439.6730 | 2.646551 / 2.646554 | 733,532 | 596,348 |
| 700-B-90-F | 2253.1010 | 3.898376 / 3.898379 | 817,696 | 828,780 |
| 700-B-50-P | 1607.4895 | 2.544536 / 2.544540 | 713,560 | 576,428 |
| 700-B-50-F | 2420.1495 | 3.849650 / 3.849655 | 807,296 | 603,488 |

Every retained health and RIB command succeeded. Health has no duplicate keys, missing results or stderr; RIB counts cover retained rows because invocation starts are not recorded. All four reloads in every cell retained 700 sessions, exact independent family inventories and 100 fresh stable observers per family. F delivered 19,168 named withdrawals per family on each B reload; P required none. All parse/leak/bystander/stable/duplicate error counters were zero, and actual churn overlap was retained. Native harness, cleanup, cell, daemon wait, driver and provenance exits were zero throughout; the five original gate failures remain explicitly distinct.

These observations complete the pinned rustbgpd-only 90/10 and 50/50 P/F operating campaign and its two fresh full-shape runs. They establish no comparison against another daemon, universal responsiveness bound, or endurance qualification. Four reloads per cell remain repeated cycles within one run.

## Evidence and reproduction

The [artifact README](artifacts/ixp-dualstack-final-campaign-2026-09/README.md) describes source/build binding, path normalization, checksums, retained failures and analysis-only replay. No earlier measured result is counted as a new cell in this campaign.
