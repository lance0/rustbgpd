# Final prestaged-inventory attribution — 2026-10-11

A clean parent-versus-merged-child comparison confirms that #2930 moves most
of its fenced RIB saving into earlier destination prestage. Across this
default-shape ABBA, mean actor time falls **139.938 ms**, mean prestage rises
**127.157 ms**, and mean daemon SIGHUP-to-complete falls **23.557 ms**.
The first reloads show no completion gain, completion ranges overlap, and
full-wire completion remains mixed. This qualifies a bounded reduction in
fenced work, rather than a general end-to-end or CPU improvement.

This receipt supplies the clean final-source comparison missing from the
[earlier attribution receipt](policy-transition-release-followup-2026-10-10.md).
It does not reconstruct that receipt's instrumented historical fix binary,
allocate every step of the original 585.5→197.5 ms observation, or execute
the prepared main-versus-v0.75.0 S2/IRR comparison.

## Exact comparison and native acceptance

The measured parent is
[`6ee2a052607b34a11e8daa2f4a4d4639b5101690`](https://github.com/lance0/rustbgpd/commit/6ee2a052607b34a11e8daa2f4a4d4639b5101690),
tree `393acc58915f65e9e021fb2ec92db1d0d763bfb2`; the final merged child is
[`aceacb435677291fdb20c2e792f58cb9e4575b74`](https://github.com/lance0/rustbgpd/commit/aceacb435677291fdb20c2e792f58cb9e4575b74),
tree `e43026bd5e90766e8da8fea419fa736463f19117`.
Both source trees were clean and frozen. They are historical source arms,
not a claim about the current main tip.

Both normal release builds used exactly
`cargo build --release --locked -j 4 -p rustbgpd -p rustbgpctl`, pinned to CPUs
40–63, with rustc 1.99.0 (`b940084d7`) and Cargo 1.99.0 (`5f94df478`). Each
daemon and CLI was copied immutably before reusing the warm cache. The actual
binary-bound closures match in configuration, features, cfg and dependency
identities: **227 normal artifact units** (226 library fingerprints plus the
daemon binary) and **342 including-build units** per arm. Build-script
environment inputs and duplicate unit multiplicity are included; dependency
output signatures may differ. Daemon/RIB `bench-internals` is independently
absent in both arms. The identical 17,891-line normal/build resolution graph
is a separate resolution proxy, not the actual-closure proof.

Daemon digests are `4328bec4b2658a5c090aad1c5ee3e947cba6a03325a066484a3d2d95f446ad6d`
(parent) and `8452cb51673979474b61c77a1288bf29896e370f92946a82c0974921503ea48e`
(child). Separately built CLIs are byte-identical; all cells use one immutable
parent CLI, digest `578b90010df58157a6f9682329158096fb377e45503fd8afd5fbae0978a2d03d`.
One frozen policy-stats cell/analyzer/generator/quiet-helper revision,
`591ac39d4b50fc2c647942713a9ea99c0588a51a`, runs both arms with one engine,
digest `2701b6b81deca419dbcb55692cc74a9e976b73bcc628507dfa6c284116880b30`.
The complete [provenance](artifacts/policy-transition-final-inventory-attribution-2026-10-11/provenance.json)
retains source, tree, toolchain, input-refresh, actual-unit, command, original
file and instrument identities separately.

The four cells ran A/B/B/A under continuous canonical-host→light locks,
04:42:25–05:13:03 EDT on October 11. Shape: 1,000 peers × 400,000 IPv4 prefixes,
all peers changed, eight reloads/process, 15 s control and 40 s quiescence;
daemon CPUs 2–3, engine 4–5, probes 8–15. No shape, oracle or deadline changed.
Every leg passed its native quiet gate: two accepted samples at least 30 s
apart, one-minute load below 2, all 64 governors at performance, no competing
compiler/daemon/lab, and no swap-counter change. The quiet-admission timeout
was 600 s; the unchanged native cell run cap was 1,115 s.

All four native verdicts, leg/outer exits, and daemon/engine/probe exits are
zero/PASS. Every process has eight committed 1,000-member transitions,
complete fleet replies, flat policy-stats stage sums, no authoritative
fallback, no remainder, no deadline miss and no daemon ERROR through the
final evidence boundary. Complete in-band pairs are **7/8, 8/8, 8/8, 7/8**,
above the unchanged minimum six/process. Both out-of-band baseline first
reloads remain in the primary timing population. All 96 RPC calls are kept;
their maximum external duration is 317.113 ms, below 2 s. All original
integrity checks passed, children were reaped, and both locks were released.

The read pair fires **after cohort hot-apply**, at
`max(0, previous hot-apply→RIB-commit time − 110 ms)`; the first pair fires
immediately after hot-apply. It comprises concurrent ListNeighbors and
policy-stats calls. Quiescent policy-stats starts 20 s after the daemon reload
complete event. This is the unchanged workload, including its read pressure.

## Process clocks and contrary observations

All values below are median [minimum–maximum], in ms. Two independently
launched processes per arm provide the replication view; the 16 reloads per
arm are correlated. No significance or universal workload claim follows from
the pooled count.

| Process | Actor | Cohort | Prestage | Daemon complete |
| --- | --- | --- | --- | --- |
| Parent r1 | 331.000 [324–389] | 331.619 [325.299–389.775] | 370.299 [289.818–426.023] | 783.222 [686.458–886.960] |
| Child r1 | 197.500 [195–220] | 198.617 [195.702–221.217] | 484.348 [420.000–592.177] | 782.017 [726.646–869.352] |
| Child r2 | 199.000 [193–211] | 199.862 [194.029–211.741] | 449.822 [388.177–646.422] | 728.292 [685.931–913.296] |
| Parent r2 | 341.000 [326–383] | 359.784 [326.929–577.334] | 361.142 [291.698–411.622] | 804.800 [718.978–1064.467] |

Pooled actor median is **335→197.5 ms**, with disjoint observed row ranges;
cohort median is **337.508→198.617 ms**. Prestage median rises
**368.092→469.845 ms**, while daemon complete median falls
**794.757→754.978 ms** with strongly overlapping ranges. Child r1's completion
median is almost unchanged from parent r1; child r2 supplies the larger
completion difference. These process results constrain the end-to-end claim.

The first reload from each process (two/arm) has actor median **386→195.5 ms**,
prestage **401.409→594.838 ms**, and complete **859.296→861.913 ms**: completion
is slightly slower despite the actor saving. The remaining seven reloads
per process (14 correlated rows/arm) have actor **334→199.5 ms** and complete
**783.222→748.802 ms**. These are descriptive subsets; all 32 observations
remain primary.

Parent r2 reload 2 has actor **329 ms**, cohort **577.334 ms**, complete
**1064.467 ms**. Its 248.334 ms actor/cohort difference is retained. Parent
r2 reloads 4 and 7 also have cohort-minus-actor gaps of 30.764 and 38.406 ms.
The available clocks do not establish an exact CPU or scheduling cause for
these continuation differences.

Full-wire completion uses a distinct engine clock. Process medians of the
per-reload observer p50/p95/max are:

| Process | Wire p50 | Wire p95 | Wire max |
| --- | --- | --- | --- |
| Parent r1 | 2005.677 | 3017.844 | 3108.036 |
| Child r1 | 2071.267 | 3032.266 | 3130.393 |
| Child r2 | 1997.278 | 2966.364 | 3057.168 |
| Parent r2 | 2061.166 | 3044.803 | 3149.406 |

Pooled medians are 2042.450→2034.728, 3019.806→2994.289 and
3118.526→3099.491 ms, respectively. All observed ranges overlap; child r1
is slower than parent r1 in all three. Means differ by only about 2–3 ms.
These are medians of per-reload observer quantiles, not one combined fleet
distribution. They do not establish a repeatable full-wire gain.

## Where the complete-operation time goes

The actor timer is the RIB's integer `elapsed_ms`. Cohort is the surrounding
preparation/send/reply-return clock, and prestage includes destination
roundtrip plus session hot-apply. Daemon completion starts at the daemon's
SIGHUP-received log and ends at `config reload complete (one runtime
generation)`; it is neither the harness signal timestamp nor later durable
settlement. The engine's completion clock is separate.

Disjoint per-row spans close to the complete clock. The table uses **means**;
phase medians cannot be added. Before-generation time is reconstructed as
phase-log timestamp minus `total_us`, so log/timer boundary overhead remains
a small boundary limitation.

| Additive mean span, ms | Parent | Child | Change |
| --- | --- | --- | --- |
| SIGHUP log → reconstructed timed-generation start | 60.216 | 63.770 | +3.555 |
| Preflight | 0.145 | 0.157 | +0.012 |
| Cohort selection | 12.466 | 18.008 | +5.541 |
| Prestage and session apply | 355.517 | 482.674 | **+127.157** |
| Cohort RIB send/reply-return | 360.928 | 201.310 | **−159.618** |
| Remainder, deferred dispatch, convergence and unattributed | 1.443 | 1.436 | −0.006 |
| Phase log → complete log | 3.612 | 3.413 | −0.199 |
| **Complete operation** | **794.326** | **770.769** | **−23.557** |

The mean actor saving is 139.938 ms; the larger cohort saving also includes
the baseline's measured continuation differences. The source change moves
the shared route/prefix inventory walk into unfenced destination prestage.
The fenced `BuildInventory` consumes the staged inventory after checking
source/destination identity and changed keys; dirty or unsupported input
rebuilds under the fence or takes the existing fallback. The final merged
source retains cancellation/completion retirement ownership. It does not
eliminate the inventory walk. The paired source experiment and phase shift
support **moved work with a smaller observed total saving**, without assigning
exact CPU shares to the changed phases.

The [exact source diff](artifacts/policy-transition-final-inventory-attribution-2026-10-11/source-diff.patch)
and the amendment in
[`ADR-0105`](https://github.com/lance0/rustbgpd/blob/aceacb435677291fdb20c2e792f58cb9e4575b74/docs/adr/0105-grouped-export-policy-transition.md)
describe the inventory, changed-key recheck and fallback mechanism. No
additional runtime change or instrumentation was introduced for this run.

## Historical allocation and release scope

The earlier instrumented #2930 S2 result (335→185 ms actor, +130.404 ms
prestage, approximately flat complete time) remains historical evidence.
Its measured fix digest is
`ef83eae041e4301ced7a11046a12f61445399304ec89a3db68a500f7bf43b833`;
the recovered dirty diff did not match its source fingerprint. This clean
final-parent comparison qualifies the merged change without retrospectively
qualifying that unmatched historical binary.

#2955 is refuted as a cause of the clean actor-timer reduction: the changed
ordinary `send_route_update` path is bypassed by the successful clean
`CommitMembers` path's direct permit send. This does not exclude every
unrelated end-to-end effect. The earlier source audit and measured #2920,
#2921 and prefix-retirement evidence remain in the
[published historical allocation](policy-transition-release-followup-2026-10-10.md#the-part-of-the-drop-before-2952).
The earliest 574→486 ms S2 interval spans 26 commits and remains incompletely
allocated. The separate prefix-retirement default-shape −43 ms actor result
cannot be subtracted from that S2 −88 ms interval. Neither cross-date endpoint
arithmetic nor this new factor completes an exact 585.5→197.5 ms allocation.

Release assessment remains **NOTE**. This receipt confirms bounded fenced
work reduction and preserves the modest, mixed complete/wire behavior. The
[Q1 end-to-end regression assessment](policy-transition-release-followup-2026-10-10.md)
and subsequent
[shared-encoding fairness receipt](shared-encoding-slice-fairness-2026-10-10.md)
are separate source comparisons; this experiment does not reclassify them or
provide a universal throughput, resource or readiness guarantee.

## Quiet main-versus-v0.75.0 receipt is still preparation only

No S2/IRR build, adapter application, generated-config check, smoke or quiet
campaign was run or queued as part of this follow-up. Original Q2 remains
**INVALID** because the v0.75 IRR runner recorded no cgroup peak. The corrected
pairing is explicitly **v0.75.0's binary through main's runner**, using one
frozen main CLI, renderer, generator, verifier and engine in both arms.

The [source preparation](artifacts/policy-transition-final-inventory-attribution-2026-10-11/quiet-preparation.md)
makes the remaining adapter concrete: remove both unconditional IRR build
lines so installed immutable daemon and common tool bytes cannot be replaced.
This supersedes the older daemon-only adapter proposal for future execution;
the old recipe and all native evidence are unchanged. Before any future
window, commit the adapter on then-frozen main and check out both runner
trees clean at the same exact adapter commit. That commit, rather than
unmodified main or pre-patch HEAD, is `RUNNER_CANDIDATE_SHA`. Keep frozen-main,
adapter and daemon identities separate; if origin/main moves, refresh the
freeze/builds/manifest without disabling its source gate.

Default generated fields are source-compatible with v0.75.0, but actual
strict-config and tiny pipeline smokes remain **UNRUN**. Normal build
provenance for the retained old binary is also unqualified. The corrected
future full cells must retain main-runner cgroup placement, finite nonempty
`memory.peak`, zero-swap proof, shape/phase/settlement and original acceptance;
this preparation supplies no S2/IRR latency or memory result.

## Reproduction and evidence boundaries

The [artifact README](artifacts/policy-transition-final-inventory-attribution-2026-10-11/README.md)
documents all selected inputs, original native hashes, normalization and
reproduction commands. The checker binds full selected event dictionaries
and timestamps, validates all 96 compressed replies, audits every stats
stage and pair/deadline, reproduces all 32 wire rows and disjoint phase means,
and compares actual normal/including-build unit configurations. Plausible
broken-input controls must fail.

Selected and normalized public files were prepared **after** the successful
window was fully reaped. They are not the bytes executed by the native
scripts; original hashes identify the untouched local originals. Omitted
full logs, metrics, CPU streams and native settlement checks retain their
native verdicts/hashes rather than being claimed as independently recreated
from these projections.
