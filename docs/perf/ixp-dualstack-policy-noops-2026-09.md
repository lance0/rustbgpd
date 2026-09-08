# Dual-stack policy-reload work reduction (2026-09-08)

This receipt measures the effect of retaining unchanged executable policies during dual-stack route-server reloads.

The post-change 200-member filtering cell passed all four reloads and the unchanged operating gate. Its median full-generation duration was **345.378 ms**, compared with **4,057.727 ms** in the earlier matched diagnostic. The new run targeted the 170 changed observers and avoided policy replacement for the 30 stable peers. These are four cycles within one run per implementation, not independent repeated trials or a general readiness bound.

The single 700-member cell removed the same redundant work and completed all four receiver reloads, but **failed operating acceptance** on health timeouts and two rejected warning records.

The [earlier receipt](ixp-dualstack-2026-09-08.md) retains the failed original acceptance cell and diagnostic runs. Their results have not been rewritten. The [new artifacts](artifacts/ixp-dualstack-policy-noops-2026-09/README.md) retain the post-change inputs, instruments, unchanged gate, and executable/build bindings.

## Implementation and fixed input

The daemon was built from merge `8264351811a80301e747ad217d751942056c0b3c`, whose tree matches reviewed head `4429c3f4032ba0e3761fd84997b3c635f8621a6d`. It uses ordinary release optimization level 3, default jemalloc, no debug assertions, and eight runtime workers. The daemon SHA-256 is `5f293bd925d451e3c6fe97ff4309f7f341c7e0e0dfdc8de7471f53cd3d019b9e`.

The CLI and harness are the unchanged binaries built from `f2e14e675d096e3fd79d81ece3e7885c6f3855e4`, with hashes and original build records retained separately. Their crate sources, workspace manifests/lockfiles, harness sources, and Cargo configuration were checked unchanged between the two revisions. They were reused, not rebuilt from the new daemon commit. The committed runner now retains health stderr; the earlier diagnostic used the same capture behavior as a disclosed local driver change.

The input remains 200 dual-stack sessions, 114,400 unique routes split equally into 57,200 IPv4 and 57,200 IPv6 routes, with 170 changed and 30 stable observers. Each member originates 286 routes per family over IPv4 transport negotiating both unicast families. Generation B filters base indexes `0..32` in each family; A restores them. Each B reload requires 5,408 named withdrawals per family.

The existing harness performs B/A/B/A reloads, a 30-second control window, and 20-second cycle quiescence. Eight churners toggle 16 prefixes per family every 125 ms. Health commands run at the existing 50 ms loop delay; IPv4/IPv6 RIB queries run at the existing 250 ms loop delay. Host locking, two quiet samples 30 seconds apart, a 100-GiB process-tree RSS guard, a 900-second outer abort ceiling, and 300-second cooldown remain in force. The wrapper ran from 20:18:00 to 20:25:34 UTC, including admission and cooldown.

## 200-member results

| Measurement | Earlier diagnostic, f2e14e6 | Post-change, 82643518 |
|---|---:|---:|
| Operating gate | FAIL: health | PASS |
| Total / cohort / remainder targets, every cycle | 200 / 170 / 30 | 170 / 170 / 0 |
| Import refreshes, every cycle | 170 | 0 |
| Median full-generation duration (ms) | 4,057.727 | 345.378 |
| Median authoritative remainder phase (ms) | 3,690.217 | 0.001 |
| Failed health commands / total | 3 / 1,801 | 0 / 1,916 |
| Failed RIB query commands / total | 0 / 846 | 0 / 872 |

The four new full-generation durations were 342.933, 349.309, 344.554 and 346.201 ms. All committed. The remainder phase took 0–1 µs, with no remainder targets. The cohort transition still reported `authoritative_fallback=true`; removal of redundant stable-peer work does not imply removal of that separate transition path. Full phase fields from both runs are in [phase-comparison.json](artifacts/ixp-dualstack-policy-noops-2026-09/phase-comparison.json).

All 200 sessions, exact per-family inventories, both-family stable markers, all named withdrawals, and actual churn writes within each delivery interval passed. There were no parse errors, leaked prefixes, or bystander/stable/duplicate named withdrawals. Maximum receiver completion across the four reloads was 0.444844 seconds for IPv4 and 0.444839 seconds for IPv6. Receiver completion and the daemon's full-generation timing have different endpoints and are reported separately.

All 1,916 health commands succeeded (maximum command wall time 289.1 ms, p95 9.3 ms), as did all 872 RIB commands (maximum 95.7 ms, p95 10.4 ms). Command wall time includes client work; a successful command taking more than 200 ms does not change the health RPC's shared 200 ms deadline. Daemon VmHWM was 244,072 KiB; maximum sampled process-tree RSS was 199,648 KiB.

Native driver, gate v2, and wrapper exited 0. The unchanged warning classifier retained one known startup warning and 19,754 warnings after measured completion during teardown. No measured-phase warning was exempted. The runner does not retain an explicit daemon wait exit code; none is claimed.

## 700-member follow-through

The single 700-member F cell used the same daemon, CLI, harness, filtering policy, churn schedule, control window, quiescence, health deadline and unchanged gate. Its larger fixed input was 400,400 total unique routes, split into 200,200 routes per family, with 600 changed and 100 stable observers. All four receiver reloads passed: 700 sessions, exact inventories, fresh markers at all 100 stable observers per family, observed churn writes, 19,168 named withdrawals per family on each B reload, and zero parse errors or leaked/bystander/stable/duplicate named withdrawals. Maximum receiver completion was 2.858433 seconds for IPv4 and 2.858429 seconds for IPv6.

All four full generations committed with **600 total targets, 600 cohort targets, zero remainder targets and zero import refreshes**. Their durations were 1,608.007, 1,892.259, 1,548.554 and 1,806.765 ms (median 1,707.386 ms). Remainder phase time was 1–2 µs. As at 200 members, the cohort transition still reported `authoritative_fallback=true`.

The earlier failed 700-member characterization completed only one full generation: 99.394569 seconds, including 97.618463 seconds of authoritative remainder work for 100 targets. Its second SIGHUP was ignored while that first generation remained active, and receiver reload 2 eventually failed the native watchdog. The new four completed generations therefore demonstrate removal of that measured remainder work; the old run supplies no four-cycle median or successful operating baseline. [Phase records](artifacts/ixp-dualstack-policy-noops-2026-09/phase-comparison-700.json) retain this unequal completion count explicitly.

**The operating gate failed.** Twelve of 2,022 health commands failed, all with `RIB manager probe timed out (200ms deadline)`. All 912 RIB query commands succeeded. Health command wall time reached 338.7 ms (p95 13.3 ms); RIB commands reached 872.7 ms (p95 19.6 ms). Daemon VmHWM was 762,580 KiB and maximum sampled process-tree RSS was 554,576 KiB.

The unchanged gate retained these exact errors:

- `probes.csv failure`
- `unclassified/active WARN: writer: write/flush failed`
- `unclassified/active WARN: failed to send IPv4 withdraw UPDATE`

The global warning-phase summary places one warning in startup and 186,772 in teardown. That broad phase label does not satisfy the stricter warning whitelist: the two rejected records at 20:35:13.218663 and 20:35:13.218678 UTC concern peer `127.1.1.122`, and remain failures. The `unclassified/active WARN` strings are the checker's error labels, not proof that the records occurred during measured reload delivery. No classifier change or warning exemption was applied.

Native driver and receiver harness exited 0; gate and wrapper exited 1. All binary checks matched. Admission, execution and cooldown ran from 20:32:28 to 20:40:17 UTC. No retry or further measurement was performed. The complete failed [gate result](artifacts/ixp-dualstack-policy-noops-2026-09/700-50-F/evidence.json.gz), logs and health stderr are retained.

## Scope and reproduction

The change retains installed chains when eligible executable policy content is unchanged, while adopting candidate source/catalog metadata. It avoids treating unrelated literal-set definitions as a policy change. This measurement does not establish general policy equivalence, a general actor-responsiveness bound, or the full dual-stack acceptance matrix.

Reproduction uses the retained [runner](artifacts/ixp-dualstack-policy-noops-2026-09/200-50-F/run.sh), [gate](artifacts/ixp-dualstack-policy-noops-2026-09/200-50-F/gate.py), and generated inputs. See the artifact README for neutral public paths and analysis replay. Rebuilt executable bytes require fresh provenance. The passing 200-member cell and failed 700-member cell do not establish a general readiness bound or the full dual-stack acceptance matrix. They supply neither two independent accepted full-shape runs nor results for other family mixes, non-filtering policies, or other daemons. The separate readiness problem remains unresolved.
