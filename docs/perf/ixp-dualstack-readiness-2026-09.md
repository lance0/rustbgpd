# Dual-stack policy-reload readiness (2026-09)

This receipt checks operator responsiveness during dual-stack route-server policy replacement after readiness service was added throughout the replacement path.

The final normal 200- and 700-member runs at `a227c61e1` **passed the unchanged operating gate**, with complete health start/completion capture and clean native exits. All four receiver reloads passed at both shapes. Seven completed cells are retained, including the earlier cleanup failures and the separate diagnostic whose maximum readiness service gap was 26.012 ms, above the 25 ms soft target.

| Completed cell | Source | Unchanged gate | Health starts / CSV rows |
|---|---|---|---:|
| [Final normal 200](artifacts/ixp-dualstack-readiness-2026-09/shutdown-deadline-200-50-F/summary.json) | `a227c61e1` | PASS | 1,910 / 1,910 |
| [Final normal 700](artifacts/ixp-dualstack-readiness-2026-09/shutdown-deadline-700-50-F/summary.json) | `a227c61e1` | PASS | 2,027 / 2,027 |
| [Initial normal 200](artifacts/ixp-dualstack-readiness-2026-09/200-50-F/summary.json) | `d6d8a9e0d` | PASS | 1,914 / 1,914 |
| [Initial normal 700](artifacts/ixp-dualstack-readiness-2026-09/700-50-F/summary.json) | `d6d8a9e0d` | FAIL: shutdown warning; separate capture gap | 2,028 / 2,027 |
| [Diagnostic 700](artifacts/ixp-dualstack-readiness-2026-09/diagnostic-700-50-F/summary.json) | `d6d8a9e0d` | FAIL: 16 writer warnings | 2,023 / 2,023 |
| [Probe-cleanup normal 200](artifacts/ixp-dualstack-readiness-2026-09/runner-fixed-200-50-F/summary.json) | `dad3c0406` | FAIL: writer and withdrawal warnings | 1,909 / 1,909 |
| [Client-cleanup normal 200](artifacts/ixp-dualstack-readiness-2026-09/client-cleanup-200-50-F/summary.json) | `01a4d3b85` | PASS | 1,910 / 1,910 |

Each normal source/shape pair has one measured run with four reload cycles. The [artifacts](artifacts/ixp-dualstack-readiness-2026-09/README.md) retain complete instruments and source/build bindings; the [machine-readable summary](artifacts/ixp-dualstack-readiness-2026-09/summary.json) separates normal and diagnostic observations. Zero failures in recorded rows does not imply complete capture: the initial 700-member stderr retains a final transport error without a CSV completion.

## Implementation and source identity

The initial measurements use clean commit `d6d8a9e0dc43b79384343163efa1d9891bc2c776`. Merge `8585ce86adff37ca277a450fc77d4d01e82ccd4e` has the identical tree, `8888f84f2097e6d3daf84b471e973a2016d3b9cc`. The initial normal daemon, CLI, and harness were all built from that source. The daemon uses ordinary release optimization level 3, default jemalloc, no debug assertions, and eight runtime workers. Its SHA-256 is `fdc5d032edf73e71344b505cfa4603d25113e1aac809f9e94a520b649ea782d0`; [binary hashes and build records](artifacts/ixp-dualstack-readiness-2026-09/200-50-F/binaries.sha256) identify the other executables.

The runtime change services the dedicated readiness receiver while synchronous export-policy replacement walks inventories, prepares fallback baselines, commits outbound state, refreshes peers, and retires replaced state. A replacement scope retains the actor-owned Loc-RIB count and the original transition age. General RIB queries and mutations remain serialized behind the command. The scope restores normal readiness service before returning the command acknowledgement. This does not make every RIB operation preemptible or establish a universal scheduling bound.

The [previous policy-reload receipt](ixp-dualstack-policy-noops-2026-09.md) supplies historical observations at `8264351811a80301e747ad217d751942056c0b3c`: its 200-member cell passed; its 700-member cell completed all receiver reloads but failed the operating gate, including 12 health timeouts. That source precedes other API, CLI, transport, and reload changes. The historical runs reused older CLI/harness binaries; the initial campaign retained a build receipt covering all three executables. This report is operating acceptance against a fixed workload and unchanged checker, not a paired A/B measurement isolating one change. The historical failures remain intact.

## Fixed workload and operating gate

Each member uses one IPv4 transport session negotiating IPv4 and IPv6 unicast and originates 286 routes per family. The 200-member cell has 114,400 unique routes, split equally into 57,200 per family, with 170 changed and 30 stable observers. Generation B filters base indexes `0..32` in each family; A restores them. Each B reload requires 5,408 named withdrawals per family. The 700-member shape has 400,400 unique routes, split into 200,200 per family, with 600 changed and 100 stable observers; each B reload requires 19,168 named withdrawals per family.

The retained harness runs B/A/B/A reloads, a 30-second control window, and 20-second cycle quiescence. Eight churners toggle 16 prefixes per family every 125 ms. Health commands use the existing 50 ms loop delay; alternating IPv4/IPv6 RIB commands use the existing 250 ms loop delay. These delays follow command execution; they are not fixed-rate sampling guarantees. Host locking, two quiet samples 30 seconds apart, a 100-GiB process-tree RSS guard, a 900-second outer abort ceiling, and 300-second cooldown remain in force.

Gate v2 is byte-identical to the historical checker (SHA-256 `9ec25e91d1a2ed9a2a8c55d7a251cff4b3e31214e7e753a4ebf3940dcee16543`). It requires exact initial inventories, all sessions, four correctly ordered reloads, per-family named withdrawals and stable markers, actual churn writes inside each delivery interval, zero parse/leak/bystander/stable/duplicate errors, successful health and RIB commands spanning the reloads, RSS limits, quiet admission, no daemon errors, and the existing warning whitelist. No warning exemption or deadline change was applied.

## Final normal pair after all three tooling repairs

Both runs at clean source `a227c61e1b22f4601c0d40bdf335a7006ad0b6a5` **passed the unchanged gate**. Merge `c86170ca199319507c96c362ca019fd74648a4fa` has the identical tree, `d4b5d5aea5b1bcd0fdaa8cbcb0f75f0fe835a359`. Their daemon, CLI, and harness hashes match each other and the successful client-cleanup attempt exactly. The [200-member](artifacts/ixp-dualstack-readiness-2026-09/shutdown-deadline-200-50-F/summary.json) and [700-member](artifacts/ixp-dualstack-readiness-2026-09/shutdown-deadline-700-50-F/summary.json) source/build records bind the final shell deadline to these distinct runs.

| Measurement | 200 members | 700 members |
|---|---:|---:|
| Operating gate | PASS | PASS |
| Health starts / completed CSV rows | 1,910 / 1,910 | 2,027 / 2,027 |
| Failed health CSV rows | 0 | 0 |
| Health command p95 / maximum (ms) | 9.3 / 294.8 | 12.5 / 1,097.3 |
| Failed RIB query CSV rows / total | 0 / 866 | 0 / 913 |
| RIB command p95 / maximum (ms) | 10.5 / 291.1 | 19.0 / 1,116.1 |
| Median full-generation duration (ms) | 499.915 | 2,484.205 |
| Daemon VmHWM (KiB) | 241,732 | 764,400 |
| Maximum sampled process-tree RSS (KiB) | 194,108 | 650,576 |
| Maximum IPv4 receiver completion (s) | 0.657837 | 3.731620 |
| Maximum IPv6 receiver completion (s) | 0.657840 | 3.731625 |

All four receiver reloads passed at each shape, retaining every session, exact per-family inventories, fresh markers at every stable observer, actual churn overlap, and the expected named withdrawals. There were zero parse errors, leaked prefixes, or bystander/stable/duplicate named withdrawals. All generations committed with 170 or 600 total/cohort targets respectively, zero remainder targets, zero import refreshes, and `authoritative_fallback=true`.

The 200-member full-generation durations were 512.588, 502.960, 486.025, and 496.869 ms; the 700-member durations were 2,300.233, 2,629.351, 2,339.058, and 2,658.779 ms. Both medians remain above the historical observations. This receipt establishes the sampled operating result for these shapes, with no generation-speed improvement or isolated causal claim. Receiver completion and full-generation timing have different endpoints.

Every health invocation start matches a successful CSV completion, with no health stderr. RIB-query counts cover retained rows because the runner does not record their invocation starts. Complete client command wall times can exceed 200 ms without establishing that the health RPC exceeded its shared 200 ms deadline. Queries spanning the run do not prove that every short replacement interval contained a query; the receiver oracle separately checks route content.

Native harness/cleanup/cell results, daemon wait exit, driver exit, gate exit, and provenance exit were all 0 for both runs. The classifier retained one startup warning per run, plus 19,769 accepted teardown warnings at 200 members and 80,776 at 700 members, with no rejected records. The 200-member run lasted from 00:56:26 to 01:04:00 UTC on September 10; the 700-member run lasted from 01:04:22 to 01:12:11 UTC, including admission and cooldown.

## Tooling repairs and harness identity

The attempts exposed separate probe-capture, BGP-client, and native-process cleanup defects:

- At `dad3c0406130066799fb6dfddc46ff3290d2ff85`, the matrix runner stops and joins probe loops after their in-flight CLI commands write their final CSV rows. It also joins the RSS sampler, waits for the daemon, and retains the actual native exits. All three executable hashes match the initial normal build. The measured result below has complete health capture but still fails on BGP teardown warnings.
- Reviewed source `01a4d3b856d7588e272805b251e6d9bba5a17728`, tree `5744d3a53bf61b0168c83f6d0cc43e0dcb86552e`, adds final BGP client cleanup to `reloadstall`. After measurements and any final evidence acknowledgment, it stops and joins churn producers, queues an administrative-shutdown Cease through every existing writer, half-closes each write side, and keeps readers alive until EOF. Graceful Cease delivery and socket drain share a 15-second deadline. Read, write, task, or drain-timeout failures fail the harness; remaining reader, writer, and refresh tasks are canceled and cooperatively reaped before exit. The drain deadline is not a hard operating-system wall-clock bound on cancellation and reaping.
- Source `a227c61e1b22f4601c0d40bdf335a7006ad0b6a5`, tree `d4b5d5aea5b1bcd0fdaa8cbcb0f75f0fe835a359`, adds a dedicated 60-second deadline after SIGTERM for native daemon exit. Expiry sends SIGKILL, reaps the process, retains its actual exit code, and fails cleanup. This changes the shell runner, its tests, and the changelog; its completed build has the same three executable hashes as the client-cleanup revision.

The client-cleanup change has harness SHA-256 `992e0039279350a3ccb6f44087c50c72cf248e851444facf026382726e280eac`. The earlier `67ed73d48c3f261b96872de1f67ebacdac488bdd74a5b4d123d72dc007ebf7dc` harness identifies the initial normal and probe-cleanup attempts. Daemon and CLI source and bytes remain unchanged across the tooling repairs. The active reload workload, evidence checks, and gate v2 are unchanged; BGP client and native process cleanup follow final measurements. The final 200- and 700-member observations use that same source and exact executable hashes; the 700-member wrapper verified the passing 200-member prerequisite before starting.

## Initial normal 200-member results

| Measurement | Historical 82643518 | Candidate d6d8a9e0d |
|---|---:|---:|
| Operating gate | PASS | PASS |
| Failed health CSV rows / total | 0 / 1,916 | 0 / 1,914 |
| Health command p95 / maximum (ms) | 9.3 / 289.1 | 9.3 / 278.3 |
| Failed RIB query CSV rows / total | 0 / 872 | 0 / 868 |
| RIB command p95 / maximum (ms) | 10.4 / 95.7 | 10.5 / 289.1 |
| Median full-generation duration (ms) | 345.378 | 505.470 |
| Daemon VmHWM (KiB) | 244,072 | 233,888 |
| Maximum sampled process-tree RSS (KiB) | 199,648 | 187,236 |

All four receiver reloads passed with 200 sessions, both-family exact inventories, fresh markers at all 30 stable observers per family, and the expected named withdrawals. There were no parse errors, leaked prefixes, or bystander/stable/duplicate named withdrawals. Maximum receiver completion was 0.619229 seconds for IPv4 and 0.619231 seconds for IPv6.

The full-generation durations were 506.710, 502.633, 511.366, and 504.230 ms. All committed with 170 total/cohort targets, zero remainder targets, zero import refreshes, and `authoritative_fallback=true`. The median generation duration was higher than the historical observation; this receipt makes no generation-speed improvement claim. Receiver completion and full-generation timing have different endpoints.

Health and RIB command wall times include client work. A successful command exceeding 200 ms is not evidence of an RPC exceeding its shared 200 ms health deadline. The command CSVs establish sampled responsiveness; the receiver oracle separately establishes route content. All 1,914 health start markers in this 200-member run match CSV completions, with no health stderr. RIB-query invocation starts were not recorded, so query claims cover retained rows. Queries spanning the run do not prove that every short replacement interval contained a query.

The retained native driver, gate, and provenance checks exited 0, and the harness status is `pass`. The warning classifier retained one startup warning and 19,766 teardown warnings, with no rejected records. No explicit daemon wait exit or standalone outer-wrapper exit file was recorded. The run started at 23:53:12 UTC on September 9 and finished at 00:00:45 UTC on September 10, including admission and cooldown.

## Initial normal 700-member results and capture limit

The larger normal cell reused the exact normal 200-member executables and clean source identity. It had 700 members, 400,400 unique routes split into 200,200 per family, and 600 changed / 100 stable observers. Each B reload required 19,168 named withdrawals per family.

| Measurement | Historical 82643518 | Candidate d6d8a9e0d |
|---|---:|---:|
| Operating gate | FAIL: health and warnings | FAIL: shutdown warning |
| Failed health CSV rows / total | 12 / 2,022 | 0 / 2,027 |
| Health command p95 / maximum (ms) | 13.3 / 338.7 | 12.4 / 1,153.7 |
| Failed RIB query CSV rows / total | 0 / 912 | 0 / 916 |
| RIB command p95 / maximum (ms) | 19.6 / 872.7 | 18.5 / 1,005.2 |
| Median full-generation duration (ms) | 1,707.386 | 2,499.120 |
| Daemon VmHWM (KiB) | 762,580 | 757,760 |
| Maximum sampled process-tree RSS (KiB) | 554,576 | 640,880 |

All four receiver reloads passed with 700 sessions, exact per-family inventories, fresh markers at all 100 stable observers per family, actual churn overlap, and the expected named withdrawals. There were no parse errors, leaked prefixes, or bystander/stable/duplicate named withdrawals. Maximum receiver completion was 3.874256 seconds for IPv4 and 3.874252 seconds for IPv6.

All four full generations committed with 600 total/cohort targets, zero remainder targets, zero import refreshes, and `authoritative_fallback=true`. Their durations were 2,319.666, 2,732.109, 2,326.191, and 2,672.049 ms. As at 200 members, the generation median was higher than the historical observation.

**Zero failures in retained CSV rows is not complete command success.** Health stderr contains 2,028 invocation-start markers but only 2,027 matching CSV completions. The unmatched final start is `1788999489.227891962`; it is followed by `Error: daemon error: transport error`. Its exit code and elapsed time were not retained. The pinned runner kills the probe loops without waiting for an in-flight command before shutting down the daemon. RIB-query starts are not recorded, so their capture completeness cannot be established from this run. The [capture audit](artifacts/ixp-dualstack-readiness-2026-09/700-50-F/summary.json) preserves the unmatched invocation and exact stderr; no missing row was synthesized.

The unchanged gate independently failed with `unclassified/active WARN: gRPC listener shutdown grace expired; aborting remaining listeners`. That warning occurred at 00:18:10.381427 UTC during teardown and reported one remaining listener after the 1,000 ms grace period. The broad warning counts are one startup and 70,330 teardown records. The warning remains outside the whitelist; no exemption was added. Native driver and provenance exits were 0, gate exit was 1, and harness status was `pass`.

The normal 700-member run therefore does not establish operating acceptance. It ran from 00:15:20 to 00:23:09 UTC on September 10, including admission and cooldown. All original logs and the failed checker result remain intact.

## Separate 700-member diagnostic

A separate build enabled `rustbgpd-rib/bench-internals` at the identical source tree to record readiness gaps and allocation capacities. This instrumented run is characterization, not normal-build acceptance. It used 700 members, 400,400 routes split equally by family, and 600 changed / 100 stable observers with the same filtering, churn, and gate. Its [build and raw records](artifacts/ixp-dualstack-readiness-2026-09/diagnostic-700-50-F/summary.json) bind the distinct diagnostic executable.

Across the complete retained daemon log, 103 replacement scopes recorded 18 serviced readiness attempts and 345 capacity records. The maximum service gap was **26.012 ms**; five scopes exceeded the 25 ms soft target. This retains the observed exceedances rather than asserting a hard 25 ms or universal readiness bound. Scope elapsed times ranged from 51 to 1,117,112 µs, and each scope's retained Loc-RIB count was between 400,400 and 400,656 as churn changed the table between commands.

| Observed allocation | Maximum live length | Maximum capacity | Maximum raw slots |
|---|---:|---:|---:|
| Group unicast | 400,656 | 801,120 | 400,656 |
| Group before shrink | 400,560 | 400,624 | 400,560 |
| Filtered scope | 400,624 | 917,504 | — |
| Exact candidates / results, each | 400,560 | 400,560 | — |
| Export memo entries | 1,400 | 1,792 | — |
| Modified memo entries | 1 | 4 | — |
| Supplemental withdrawals | 64 | 64 | — |

These are componentwise maxima across recorded scopes, not a simultaneous allocation snapshot. Raw slots apply to the slab-backed group inventory; capacities for other containers do not count bytes. The observed private-unicast and group-OTC entries were empty. The run does not measure every other-family, fallback-baseline, or shared-helper path, nor does it time each indivisible operation separately. Instrumentation adds overhead, and terminal diagnostic logging occurs outside the recorded service-gap interval.

All four receiver reloads completed. All 2,023 retained health rows and all 912 retained RIB query rows have exit 0. Every diagnostic health start marker has a matching CSV completion, with no health stderr; RIB-query starts were not recorded. Health command wall time had p95 13.1 ms and maximum 1,068.2 ms; RIB command wall time had p95 18.2 ms and maximum 1,131.7 ms. These are complete client command times, not health RPC durations.

**The unchanged diagnostic gate failed.** It retained 16 errors, each `unclassified/active WARN: writer: write/flush failed`. The broad warning summary contains one startup warning and 79,417 teardown warnings. Fifteen rejected records have `ConnectionReset`, outside the existing `BrokenPipe` allowance; the remaining `BrokenPipe` record precedes that peer's own session-down record. The broad teardown label therefore does not satisfy the stricter whitelist and does not change the result. Native driver and provenance exits were 0, gate exit was 1, and harness status was `pass`. The complete failed result and all warning records are exported. The run lasted from 00:06:46 to 00:14:34 UTC on September 10, including admission and cooldown.

## Probe cleanup attempt

A subsequent 200-member run used clean source `dad3c0406130066799fb6dfddc46ff3290d2ff85`, tree `6324fea8a803aa06a6116edd368060ed30aac900`. Relative to the runtime merge, it changes only the matrix runner, its companion tests, and the changelog. The runner lets each in-flight CLI finish its CSV record, joins both probe loops and the RSS sampler, then stops and waits for the daemon. It records native harness, cleanup, and cell results separately, plus the daemon wait exit.

The new build's daemon, CLI, and harness hashes are **identical to the initial normal executables**. The workload and gate are unchanged. [This attempted cell](artifacts/ixp-dualstack-readiness-2026-09/runner-fixed-200-50-F/summary.json) uses the same executable bytes with the revised probe-cleanup lifecycle.

All 1,909 health invocation starts have matching CSV completions and no stderr; all health rows have exit 0. All 868 retained RIB query rows also have exit 0. Health command p95/maximum was 9.5/274.5 ms; RIB command p95/maximum was 10.6/177.0 ms. All four receiver reloads passed, with maximum completion 0.627874 seconds for IPv4 and 0.627879 seconds for IPv6. Median full-generation duration was 501.493 ms. Daemon VmHWM was 237,120 KiB; maximum sampled process-tree RSS was 190,228 KiB.

**The unchanged gate still failed**, retaining `unclassified/active WARN: writer: write/flush failed` and `unclassified/active WARN: failed to send IPv4 withdraw UPDATE`. Both appear during teardown; the broad phase totals are one startup warning and 19,734 teardown warnings. They remain outside the whitelist. Native harness/cleanup/cell results, daemon wait exit, driver exit, and provenance exit were all 0; gate exit was 1.

The run lasted from 00:30:10 to 00:37:44 UTC on September 10, including admission and cooldown. The required passing 200-member gate was not met, so no 700-member cell was run from this source. The failed attempt and complete probe capture remain in the archive.

## Client cleanup attempt

The 200-member run at `01a4d3b856d7588e272805b251e6d9bba5a17728` **passed the unchanged gate**, with complete health capture and clean native exits. It ran from 00:47:44 to 00:55:17 UTC on September 10, including admission and cooldown. Its [source/build records and full instruments](artifacts/ixp-dualstack-readiness-2026-09/client-cleanup-200-50-F/summary.json) retain the distinct harness binary and unchanged daemon/CLI hashes.

All 1,910 health starts match CSV completions without stderr; all health rows and all 868 retained RIB query rows have exit 0. Health command p95/maximum was 9.4/318.9 ms; RIB command p95/maximum was 10.6/280.9 ms. All four receiver reloads passed, with maximum completion 0.624985 seconds for IPv4 and 0.624989 seconds for IPv6. Median full-generation duration was 504.821 ms. Daemon VmHWM was 239,936 KiB; maximum sampled process-tree RSS was 186,124 KiB.

Native harness/cleanup/cell results, daemon wait exit, driver exit, gate exit, and provenance exit were all 0. The unchanged classifier retained one startup warning and 19,753 accepted teardown warnings, with no rejected writer or gRPC shutdown warnings. The matrix runner at this revision still lacked a dedicated native-daemon wait deadline. That separate shell correction was prepared before larger follow-through; no 700-member cell was run from this source. This passing attempt remains a separate observation.

## Scope and reproduction

The [artifact README](artifacts/ixp-dualstack-readiness-2026-09/README.md) explains normalized public paths, original/public checksums, fresh builds, and analysis-only replay. The exported gate reproduces the complete retained result without starting a daemon.

These observations cover the pinned filtering policy, dual-unicast family mix, and one host. Four cycles in one run are not four independent trials. This report does not establish the full dual-stack acceptance matrix, a general actor-responsiveness bound, other policy/family combinations, or a cross-daemon performance comparison.
