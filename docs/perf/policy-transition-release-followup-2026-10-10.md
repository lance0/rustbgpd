# Policy-stats reload completion after #2952 — 2026-10-10

The retained 2026-10-10 Q1 daemon logs place the long post-commit interval after
the RIB transition's input retirement, before the peer manager resumes.
Prestage/session apply also rises by about 93.5 ms in its pooled median. This
follow-up separates both effects and the admitted-read wait while preserving
the original campaign's verdict. A short ABBA confirms the shorter RIB timer
and the longer completion clock with concurrent reads. Note this workload
limitation for the release and keep the performance claim on the fenced RIB
transition.

The measured arms are #2952's parent
`3bbc1576cc3fd1f97a6c723131f183f82d4952f4` and #2952
`49abbb0171cbb889b7e2618c2bdcec6ea35699ae`. Both use the policy-stats cell
and `reloadstall` from `591ac39d4b50fc2c647942713a9ea99c0588a51a`.
The original Q1 is ABBA, two runs of 12 correlated reloads per arm, with
1,000 peers and 400,000 total prefixes. Every reload changes the community
on every exported route. Permit sets stay unchanged; this is a changed-policy
clean grouped transition, rather than an export-neutral reload.
The [original J2 receipt](policy-transition-attribution-2026-10.md) and its
[as-run verdict reproduction](artifacts/policy-transition-attribution-2026-10/recompute.py)
remain the campaign record.

## Where the original Q1 time goes

| Clock, pooled median in ms | Parent | #2952 |
|---|---:|---:|
| SIGHUP → complete | 723.321 | 852.525 |
| Prestage and session apply | 442.045 | 535.582 |
| Logged RIB transition | 197.500 | 56.000 |
| Cohort send → peer manager resumes | 198.063 | 273.605 |
| RIB committed log → generation phase log | 1.013 | 217.719 |
| RIB committed log → reload complete | 4.335 | 221.249 |
| Concurrent neighbor RPC | 24.540 | 286.448 |

**These medians are not additive.**
[`j2-reloads.json`](artifacts/policy-transition-release-followup-2026-10-10/j2-reloads.json)
and [`j2-timeline.jsonl`](artifacts/policy-transition-release-followup-2026-10-10/j2-timeline.jsonl)
retain every reload, including the short-cohort countercases. The phase log
accounts separately for selection, prestage, the cohort wait and the remaining
apply/convergence work. Refresh dispatch is about 0.007 ms and convergence
checks about 0.14 ms: neither hides the extra interval.

To account for the whole reload, split each reload into disjoint components
and take their **means**. The phase clock's start is reconstructed from its
end log minus `total_us`; the before/after intervals retain configuration
preparation and completion work outside that clock. The cohort's logged RIB
timer and its residual are also separated; the residual includes admission,
reply cleanup and waiting for the peer-manager continuation.

| Additive per-reload component, mean in ms | Parent | #2952 | Change |
|---|---:|---:|---:|
| Before the generation phase clock | 60.305 | 57.793 | −2.513 |
| Preflight and cohort selection | 13.026 | 12.887 | −0.139 |
| Prestage/session apply | 454.271 | 535.371 | +81.100 |
| Logged RIB transition | 200.417 | 55.583 | −144.833 |
| Cohort time outside that RIB timer | 3.726 | 167.869 | +164.143 |
| Remainder apply, refresh, convergence, phase unattributed | 1.422 | 1.499 | +0.077 |
| After the phase log → complete | 3.365 | 3.824 | +0.459 |
| **SIGHUP → complete** | **736.529** | **834.823** | **+98.294** |

Rounding accounts for the last displayed decimal. The median increase is
129.204 ms; the mean increase is 98.294 ms. These are different summaries of
the same bimodal data, not conflicting measurements. In the additive mean
accounting, the extra cohort continuation wait is larger than the saved RIB
time, while prestage also takes longer. Work outside the generation phase
and its final completion remains approximately flat. This is not simply
the same work moving from one clock into another with an unchanged end-to-end
result.
The logged RIB timer has integer-millisecond resolution; the cohort residual
includes that sub-millisecond rounding as well as the wait outside the actor
timer. Increased prestage wall time is observed, but its extra CPU cost is not
isolated by these logs.

The 18 long post-#2952 cohort waits have the long interval **after** the
RIB committed log. The six other post reloads complete about 4.5–5.1 ms after
that log. Five of those six nevertheless have long neighbor RPCs; total RPC
duration therefore cannot be used as the duration of an admitted peer-manager
read.

### The RIB reply boundary

The committed log precedes terminal input retirement. The actor then arms
`PostCommitQueryTrace`, finishes synchronous readiness cleanup and sends the
terminal oneshot reply, with no intervening await. See the
[measured actor](https://github.com/lance0/rustbgpd/blob/49abbb0171cbb889b7e2618c2bdcec6ea35699ae/crates/rib/src/manager/mod.rs#L4621).
The trace's timestamp minus `first_query_wait_us` estimates when it was armed;
this mixes the log wall clock and a monotonic duration, so it is an approximate
boundary rather than a separately instrumented reply timestamp. The outer
[readiness cleanup](https://github.com/lance0/rustbgpd/blob/49abbb0171cbb889b7e2618c2bdcec6ea35699ae/crates/rib/src/manager/mod.rs#L2061)
still runs after that boundary; a scheduling pause during it is not excluded.
These retained daemons used the normal release build without `bench-internals`.
None of the four Q1 logs has a readiness-scope-finished or terminal-cleanup
timestamp to bracket that remaining work; the original build logs and driver
are identified in the source hash roster.

For all 23 post reloads with a retained trace, that boundary falls only
0.205–0.322 ms after the committed log, median 0.256 ms. From this boundary to
the generation phase log, the 18 long cases wait 178.190–257.969 ms; the five
traced short cases wait 0.672–0.782 ms. Terminal retirement therefore does not
account for the long interval. The sixth short case has no trace. Publication
and scheduling between that proxy and the actual send are not separately
timed, so the interval does not establish when the reply was published.

The first subsequent RIB query trace reports a 226.733 ms median wait, of
which 10.669 ms is completed RIB work and 213.981 ms is unattributed. That
last field includes idle time, scheduling and uninstrumented work; it is not
a measurement of CPU time or of one transport task.

### Why an admitted read can postpone reload completion

The peer manager's
[`await_with_readiness`](https://github.com/lance0/rustbgpd/blob/49abbb0171cbb889b7e2618c2bdcec6ea35699ae/src/peer_manager/mod.rs#L970)
selects the owned RIB reply first when polling. Once it selects an operator
read, however, it awaits that handler to completion before polling the reply
again. [`ListPeers`](https://github.com/lance0/rustbgpd/blob/49abbb0171cbb889b7e2618c2bdcec6ea35699ae/src/peer_manager/snapshot.rs#L555)
fans out a bounded state query to all 1,000 session actors. The
[neighbor RPC](https://github.com/lance0/rustbgpd/blob/49abbb0171cbb889b7e2618c2bdcec6ea35699ae/crates/api/src/neighbor_service.rs#L1267)
then requests an aggregate RIB snapshot; its total latency
contains both phases. A long neighbor RPC admitted after the RIB reply was
already selected can coexist with a short cohort wait.

The cell aims its read pair from the previously observed transition, with a
110 ms lead. The parent starts the pair a median 110.591 ms before commit.
After the transition falls below the lead, the pair fires immediately after
session hot-apply and starts a median 55.065 ms before commit. The read's
overlap with the work changes even though the cell script is shared.

The transport's elected shared encoder is
[synchronous](https://github.com/lance0/rustbgpd/blob/49abbb0171cbb889b7e2618c2bdcec6ea35699ae/crates/transport/src/session/shared_group.rs#L541).
Session fan-out overlapping encode/delivery on the two daemon CPUs is a
source-consistent explanation for the delayed read and resumed owner. **It
is an inference:** these logs do not record each session's query service or
profile each runnable task. The observed interval spans terminal input
retirement to the peer-manager continuation, near the reply publication
boundary. The source establishes
the admitted-read interlock, while the exact split between publication,
read fan-out and scheduling is not measured. A later fenced RIB phase or
config settlement does not explain the interval.

## Release assessment

The original Q1 and the valid short confirmation establish a real increase
in the end-to-end clock for this operator-read workload. They also establish
the shorter fenced RIB transition. Calling the whole effect pure noise or
claiming an end-to-end gain would be unsupported. The probe timing and read
overlap change, so this is not evidence of the same end-to-end increase for
reloads without the concurrent read pair.

The original Q1 cells all pass, with no daemon error or read deadline miss. The
original Q2 S2 and IRR timing comparison stays approximately flat end to end;
its IRR memory result is invalid because the old runner lacked that instrument.
The short confirmation also passes every native cell criterion. On this
evidence, record the workload limitation as a release note rather than a
release blocker, and restrict the performance claim to the fenced transition.
This receipt does not supply a general reload-latency claim or a replacement
S2/IRR memory comparison.

## Short confirmation

The predeclared
[`confirmation-eight-acceptance.md`](artifacts/policy-transition-release-followup-2026-10-10/confirmation-eight-acceptance.md)
uses ABBA at the same peer/prefix shape, CPU placement and read workload,
with eight reloads per run instead of 12. It has 16 correlated reloads per
arm across two runs. Only the reload count changes. The canonical host lock
covered 12:03:28–12:34:04 EDT on 2026-10-10; every run passed the original
quiet-host gate. All four cells pass with eight complete in-band read pairs
each, all cell/daemon/harness/probe exits zero, and no daemon error, read
deadline miss or call over two seconds. The wrapper exited zero and released
the lock. The [confirmation provenance](artifacts/policy-transition-release-followup-2026-10-10/confirmation-provenance.json)
retains accepted quiet samples, instrument digests and hashes of the full
as-run evidence.

Keep process repetitions visible. The original has two process launches per
arm with 12 correlated reloads in each; the confirmation has two launches per
arm with eight correlated reloads in each. Pooled reload counts are not
independent process counts, and this does not establish statistical
significance. Each clock below is a median with its full reload range, in ms;
the final column counts cases with more than 100 ms from the RIB committed
log to the phase log.

| Campaign / process | Reloads | RIB | Cohort | SIGHUP → complete | Long cases |
|---|---:|---:|---:|---:|---:|
| Original parent r1 | 12 | 196.000 [192–237] | 196.831 [192.785–238.098] | 696.463 [670.323–913.204] | 0 |
| Original #2952 r1 | 12 | 55.500 [52–57] | 270.146 [52.456–296.371] | 827.166 [615.464–904.283] | 8 |
| Original #2952 r2 | 12 | 56.000 [52–60] | 276.524 [52.405–314.718] | 872.669 [671.113–948.659] | 10 |
| Original parent r2 | 12 | 199.000 [194–222] | 199.518 [194.749–232.316] | 724.002 [704.299–834.514] | 0 |
| Confirmation parent r1 | 8 | 196.500 [194–223] | 197.584 [195.103–249.884] | 747.415 [627.412–829.532] | 0 |
| Confirmation #2952 r1 | 8 | 56.500 [54–58] | 274.784 [56.327–288.066] | 874.318 [716.107–978.200] | 7 |
| Confirmation #2952 r2 | 8 | 56.000 [51–56] | 271.730 [51.958–288.859] | 867.055 [653.183–960.248] | 6 |
| Confirmation parent r2 | 8 | 201.000 [197–224] | 202.070 [197.932–225.138] | 760.007 [633.494–918.298] | 0 |

The confirmation's pooled medians are:

| Clock, median in ms | Parent | #2952 |
|---|---:|---:|
| SIGHUP → complete | 760.007 | 869.689 |
| Prestage/session apply | 460.486 | 540.024 |
| Logged RIB transition | 198.000 | 56.000 |
| Cohort | 199.314 | 271.730 |

The additive per-reload means reproduce the same accounting: prestage rises
457.336→560.154 ms, the logged RIB timer falls 201.375→55.688 ms, and cohort
time outside that timer rises 4.414→178.292 ms. The complete mean rises
742.952→868.187 ms, or 125.235 ms; the median rises 109.682 ms. Before-phase,
selection and final completion work do not account for that increase. The
[summary](artifacts/policy-transition-release-followup-2026-10-10/confirmation-summary.json)
and [per-reload table](artifacts/policy-transition-release-followup-2026-10-10/confirmation-correlation.csv)
retain every component, without adding medians.

Thirteen of 16 post reloads have the long continuation interval, versus zero
of 16 parent reloads. The three short post cases still have neighbor RPCs
lasting 257.785–298.375 ms. All 16 post traces put the approximate trace-arm
boundary 0.214–0.319 ms after the RIB committed log. From that proxy to the
phase log, the long cases take 190.572–232.533 ms and the short cases
0.654–0.802 ms. The same reply-publication and scheduling qualifications
apply; this is a repeat of the observed clocks, not a new CPU profile.

Two earlier attempts remain separate **INVALID** records. The
[four-reload attempt](artifacts/policy-transition-release-followup-2026-10-10/invalid-four-reload-attempt.json)
stopped at its first cell: four in-band pairs cannot satisfy the unchanged
minimum of six. The
[six-reload ABBA](artifacts/policy-transition-release-followup-2026-10-10/invalid-six-reload-attempt.json)
completed all four cells, but the final parent had only five complete in-band
pairs because one pair fell just outside the unchanged −220 ms boundary.
Their predeclarations, verdicts and complete original-file hashes are retained.
Neither attempt supplies passing confirmation evidence. The final eight-reload
declaration preceded its new output root and did not change that acceptance
bar or any instrument.

## The part of the drop before #2952

Q4 reproduces a 576.5 ms RIB timer at v0.73.0 on the same harness as Q1;
Q1's parent is 197.5 ms. The original cross-date policy-stats observation was
585.5 ms. Retained S2 scouts identify several contributing changes, but are
700-peer measurements rather than isolated measurements of each change at
the 1,000-peer cell. Their medians must not be summed into an attribution of
the exact 379 ms Q4→parent difference.

| S2 evidence, actor timer in ms | Observed step | Attribution limit |
|---|---:|---|
| `370e211b9` → `481e0187d`, 12 reloads per arm | 574 → 486 | 88 ms across 26 commits, still unisolated. Batched source-group prefix-index retirement `2a5b299eb` is a candidate; its fixture receipt does not measure daemon latency |
| [#2920 readiness clock](readiness-checkpoint-clock-2026-10.md), measured parent `aae915bb4` → `5fedc3499`, 16 reloads per arm | 494.5 → 365 | Avoids per-element readiness clock reads; direct measured parent/child |
| #2921 memo arm `003a6fd19` → snapshot arm `befc1ce08`, 16 reloads per arm | 368.5 → 329 | Isolates cached prefix snapshots within an earlier memo experiment. The merged snapshot patch matches, but the memo experiment was omitted from the merge. First reloads overlap; reloads 2–4 read 369.5 → 325 |
| [#2930 prestaged inventory](prestaged-transition-inventory-2026-10.md), instrumented base/first-change binaries, 12 reloads per arm | 335 → 185 | Inventory moves to prestage, whose phase clock rises 130.404 ms (about 130 ms). Both arms are instrumented; the fix-arm source fingerprint could not be reconstructed, so the recorded daemon digest identifies the measured binary |

#2930 therefore contributes a measured reduction in the fenced inventory
phase at S2. #2955 is excluded as a cause of the clean actor-timer reduction:
it changes the ordinary send/reconciliation guard, while clean CommitMembers
sends through its reserved permits. This does not exclude other end-to-end
effects. The fast #2952 child already precedes #2955. Neither a no-op policy
interpretation nor #2955 explains that clean actor-timer reduction.

The earliest 88 ms remains an interval attribution, not a commit result.
An exact attribution of that residual needs isolated parent/child evidence;
the existing fixture evidence does not supply it. These qualifications leave
the measured endpoints intact and prevent a broader numerical claim than the
receipts support.
The unpublished early-interval and prefix-snapshot scouts are now represented
by their [72 per-reload actor values](artifacts/policy-transition-release-followup-2026-10-10/pre2952-actor-reloads.csv),
[source/binary identities and original-file hashes](artifacts/policy-transition-release-followup-2026-10-10/pre2952-provenance.json),
and a recomputed summary in this bundle. They used each arm's own runner and
harness; the digest differences remain in the provenance. Memo→snapshot
leaves the harness source and dependency inputs unchanged. The earlier
interval keeps the harness runtime source unchanged but changes some
dependency inputs outside the measured IPv4 path; it is not a common-binary
comparison. No full private daemon log is copied into the repository.

## Prepared quiet-host comparison

The [corrected S2/IRR recipe](artifacts/policy-transition-release-followup-2026-10-10/quiet-preparation.md)
uses v0.75.0's pinned **binary under main's runner**, with main tools shared
between both arms. This closes the missing IRR cgroup instrument in the plan,
without changing original Q2's INVALID verdict. Its explicit preparation-only
adapter prevents the IRR runner's normal build from replacing the pinned old
daemon. The recipe has not been applied, built, smoked, queued or run. Main
must be frozen and its manifest refreshed before the future quiet window.
No S2 or IRR measurement is launched by this follow-up.

## Evidence

The new
[artifact bundle](artifacts/policy-transition-release-followup-2026-10-10/)
contains selected original log records and reload values, with hashes of the
retained originals. It leaves the earlier Q1–Q4 raw data and verdicts unchanged.
