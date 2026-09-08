# Dual-stack route-server operating receipt (2026-09-08)

This receipt measures policy-reload delivery and operator-query responsiveness with IPv4 and IPv6 inventories on every member session.

**Acceptance campaign stopped: three 200-member cells accepted, one failed.** None of its eight planned 700-member cells ran. A separate single 700-member 50/50 F diagnostic characterization has failed; the harness exited 1 after its native 600-second no-progress watchdog. The outer matrix driver exited 0 while preserving the failed cell status; all three post-run binary hashes matched. Raw evidence is in the [artifact directory](artifacts/ixp-dualstack-2026-09-08/README.md).

This is a separate campaign from the [earlier correctness receipt](ixp-dualstack-2026-09.md). Its measurements and pinned shape remain historical.

## Implementation and workload

The four acceptance-campaign cells use source commit `f2e14e675d096e3fd79d81ece3e7885c6f3855e4` with a clean source tree. The [build binding](artifacts/ixp-dualstack-2026-09-08/build-binding.json) records daemon, CLI and harness executable hashes, compiler profiles and enabled features. Per-cell provenance records the compiler and runner sources. The daemon uses its default eight runtime workers and jemalloc.

| Members | Total unique routes | IPv4 / IPv6, 90/10 | IPv4 / IPv6, 50/50 | Changed / stable |
|---|---:|---:|---:|---:|
| 200 | 114,400 | 102,960 / 11,440 | 57,200 / 57,200 | 170 / 30 |
| 700 | 400,400 | 360,360 / 40,040 | 200,200 / 200,200 | 600 / 100 |

These are total unique routes, not routes per family or aggregate exported copies. Sessions use IPv4 loopback transport and negotiate both unicast families. Each family has disjoint per-member slices. In the 50/50 cells every member originates 286 routes per family. The 90/10 partition rounds the two families independently: at 200 members, 40 members originate 573 total routes, 120 originate 572 and 40 originate 571; at 700 the corresponding counts are 140, 420 and 140.

P changes the export community without changing the permit set. F also rejects base indexes `0..32` in each family in generation B, then permits them in A. B therefore requires 5,408 named withdrawals per family at 200 members and 19,168 at 700; A requires none. Stable observers retain their policy and must receive fresh markers in both families after changed-observer completion.

Every cell starts a fresh daemon, converges both family inventories, settles churn for three seconds, records a 30-second control window, and executes B/A/B/A reloads with 20-second quiescence between cycles. Eight churners toggle 16 prefixes per family every 125 ms. The receipt requires actual writes in both families within every reload completion interval. The host lock, quiet-host checks, 100-GiB process-tree RSS guard and 300-second post-cell cooldown apply throughout.

## Results

Each completion entry below is the maximum over all changed observers and four reloads. These are single-cell observations, not a statistical estimate across independent runs. Detailed per-reload distributions, gaps, first-marker latency, withdrawals and churn overlap remain in the raw logs and evidence JSON.

| Cell | Status | IPv4 completion maximum (s) | IPv6 completion maximum (s) | Daemon VmHWM (KiB) |
|---|---|---:|---:|---:|
| 200-validation-90-P | PASS | 0.306969 | 0.306972 | 228888 |
| 200-validation-90-F | PASS | 0.411717 | 0.411720 | 307944 |
| 200-validation-50-P | Accepted after warning review | 0.311776 | 0.311772 | 216204 |
| 200-validation-50-F | FAIL: two health commands | 0.441312 | 0.441315 | 311528 |
| 700-A-90-P | Not run: campaign stopped | — | — | — |
| 700-A-90-F | Not run: campaign stopped | — | — | — |
| 700-A-50-P | Not run: campaign stopped | — | — | — |
| 700-A-50-F | Not run: campaign stopped | — | — | — |
| 700-B-90-P | Not run: campaign stopped | — | — | — |
| 700-B-90-F | Not run: campaign stopped | — | — | — |
| 700-B-50-P | Not run: campaign stopped | — | — | — |
| 700-B-50-F | Not run: campaign stopped | — | — | — |

A validated cell requires successful driver and harness results, exact per-family delivery and withdrawals, no leaks or bystander/stable withdrawals, zero duplicate named withdrawals, all sessions up, no parse errors, fresh stable markers in both families, and observed churn overlap on all four reloads. Operator queries must succeed and span the campaign. Daemon warnings are retained and classified by startup, measured operation and teardown; teardown resynchronization warnings are not evidence of a measured reload failure.

## Failed operating check: 200-member 50/50 F

The harness and matrix driver exited successfully, but the broader evidence gate failed. Two of 1,805 `rbgp health` commands exited 1; the other 1,803 exited 0. All 848 IPv4/IPv6 RIB query commands exited 0. Full per-family inventories, withdrawals, churn overlap, session counts and warning-phase checks passed. These route-delivery results do not make the operating cell pass.

The failed health commands began at Unix timestamps `1788885986.113795007` and `1788885986.376223624` and lasted 208.8 ms and 209.3 ms. Both began during reload 2's delivery interval, approximately 129 ms and 391 ms after its SIGHUP trigger. The second command finished after delivery completion. The [probe CSV](artifacts/ixp-dualstack-2026-09-08/200-validation-50-F/rustbgpd/probes.csv) retains all calls.

The acceptance runner discarded command stderr, so those two original failures do not identify a particular RPC error. A separate 200-member 50/50 F diagnostic run captured three health failures, each reporting `RIB manager probe timed out (200ms deadline)`. This reproduces the health failure class; the complete actor-responsiveness repair remains unresolved. The original failed analysis, successful harness status and raw logs are preserved. The health acceptance requirement has not been relaxed.

## Separate diagnostic characterization

The acceptance campaign stopped at the failed 200-member 50/50 F cell. Its eight planned 700-member cells were not run; they are not queued acceptance runs.

The diagnostic 200-member run used the same pinned ordinary daemon, CLI and harness binaries, with an explicit driver change to capture health-command stderr. Its three RIB-probe deadline failures are diagnostic evidence, not a replacement for the failed acceptance cell. The [200-member diagnostic artifacts](artifacts/ixp-dualstack-2026-09-08/diagnostic-200-50-F/driver.log) and [driver diff](artifacts/ixp-dualstack-2026-09-08/diagnostic-200-50-F/driver-instrumentation.diff) are retained. The frozen v2 gate rejects this run solely for health-command failures: 3 of 1,801 health calls failed, while all 846 RIB queries succeeded.

The separate 700-member 50/50 F characterization has failed. Only reload 1 completed receiver delivery: its maximum completion was 2.916834 seconds, with exactly 19,168 named withdrawals per family, all 700 sessions up, and fresh stable markers at all 100 stable observers per family. This is one completed reload, not a passing four-reload characterization.

The daemon's first full reload generation took 99.394569 seconds, including 97.618463 seconds applying the authoritative remainder to 100 targets. Receiver delivery completion therefore did not establish completion of the whole configuration reload. At `17:18:42.356488Z`, the daemon warned `SIGHUP received while previous reload still in flight; ignoring`. The observers made no generation-2 progress.

The final query logs contain 111 failed health commands out of 9,835; all 111 report the RIB-manager 200 ms probe timeout. All 4,378 RIB query commands exited 0. The harness reported `reload 2 STALLED: no re-advertisement progress for 600s`, with 0 of 600 changed observers complete, and exited 1. Its [log](artifacts/ixp-dualstack-2026-09-08/diagnostic-700-50-F/rustbgpd/reloadstall.log), [health stderr](artifacts/ixp-dualstack-2026-09-08/diagnostic-700-50-F/rustbgpd/probes.csv.stderr.log), and [driver diff](artifacts/ixp-dualstack-2026-09-08/diagnostic-700-50-F/driver-instrumentation.diff) are retained. The outer matrix driver exited 0 after cooldown, while the cell status and harness exit remain failed. The [post-run check](artifacts/ixp-dualstack-2026-09-08/diagnostic-700-50-F/binary-check-after.log) verified all three unchanged binaries. Frozen gate v2 rejected the run for the failed harness, incomplete reload/SIGHUP sequences, health-command failures and the ignored-SIGHUP warning; its full error list is retained in the compressed analysis. No further 700-member runs are part of this characterization.

Before the completed 200-member diagnostic, a separate startup attempt failed because its inherited umask produced a group-writable runtime directory. The daemon rejected the directory before the harness launched. Its [startup failure record](artifacts/ixp-dualstack-2026-09-08/diagnostic-200-startup-failed/aborted-before-start.json), daemon log and driver exit of 143 are retained separately; this attempt supplied no reload measurements.

## Post-run warning review

The first analysis of `200-validation-50-P` failed: gate v1 rejected 102 writer `BrokenPipe` warnings. Route inventories, operator queries and per-family churn overlap passed. Independent log review found every warning after its own peer's down event, during teardown, more than 20 seconds after final reload completion.

Gate v2 accepts this warning only during teardown and after the same peer's down event. Negative checks reject a warning during active operation, another writer error during teardown, and a warning without that peer's down event. Reanalysis accepted the third cell and preserved the first two cells' results. The original failure remains part of the receipt; the analysis revision changed no binary, source, workload, measurement or daemon log, and no cell was rerun.

The [revision metadata](artifacts/ixp-dualstack-2026-09-08/gate-revision.json), [original gate](artifacts/ixp-dualstack-2026-09-08/gate-v1.py), [current gate](artifacts/ixp-dualstack-2026-09-08/gate.py), [negative-check results](artifacts/ixp-dualstack-2026-09-08/gate-v2-tests.json), and [independent warning review](artifacts/ixp-dualstack-2026-09-08/200-validation-50-P/warning-review.md) are exported. Each of the first three cells retains `evidence-v1.json.gz` and `evidence-v2.json.gz`; `evidence.json.gz` is the current reviewed analysis. The third cell also retains the original wrapper exit of 1.

## Reproduction and limits

The [campaign plan](artifacts/ixp-dualstack-2026-09-08/plan.tsv), [runner](artifacts/ixp-dualstack-2026-09-08/run.sh) and [evidence gate](artifacts/ixp-dualstack-2026-09-08/gate.py) record the exact inputs and acceptance checks. Public paths are neutral replacements described in the artifact README. Reproduction requires ordinary executable files at the runner's three binary paths; the first preflight attempt used symlinks and stopped before starting a daemon. Its [diagnostic log](artifacts/ixp-dualstack-2026-09-08/preflight-symlink-rejected/200-validation-90-P/driver.log) and failed analysis are preserved separately; no timing result came from that attempt.

Health and IPv4/IPv6 RIB query loops demonstrate command responsiveness, not returned route-content correctness. Sampling does not guarantee a query begins inside every short reload interval. Receiver inventories establish route delivery. The matrix runner does not record an explicit daemon wait exit status; none is claimed here.

This campaign provides no cross-daemon comparison, IPv6 optimization claim, IPv6 transport result, route-overlap workload, forwarding result, or extrapolation beyond the recorded cells. The acceptance campaign’s 700-member runs A and B were not run. Any future acceptance campaign requires a separately pinned implementation and a fresh validation sequence.
