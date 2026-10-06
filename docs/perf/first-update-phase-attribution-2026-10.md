# First survivor UPDATE phase attribution — October 2026

An in-flight initial-table operation is the strongest measured lead for the
133 ms first-survivor UPDATE floor in this native-loopback S3 campaign.

At the re-announcement trigger, a synchronous returning-member initial-table
operation still occupied the RIB actor for **122.231 ms median**. The sampled
survivor received its first affected UPDATE **5.604–13.255 ms after that operation
finished** in all nine instrumented rounds. In the six rounds where the traced
prefix was also the first affected UPDATE, its successful queue admission to RIB
ingest interval was **127.353 ms median**. This supports investigating bounded
registration work. It does not establish the gain from an unimplemented change.

This receipt ships no runtime instrumentation, optimization, or setting. The
[compact evidence](artifacts/first-update-phase-attribution-2026-10/README.md)
retains all 18 rounds, all 5,850 instrumented survivor-round observations, signed
phase intervals, overhead comparisons, and a recomputation script.

## Cohort and clocks

The measured source was `19842a5a114287af7a8f5ae66407aaacc9d0142a`, including the
subsequent grouped-join materialization change. The earlier
[cross-daemon receipt](cross-daemon-v0750-2026-10.md) reported 170 ms for rustbgpd
and 130 ms for OpenBGPD 9.3 using an older source cohort. Its full-reannouncement
medians were 300 ms and 17.83 seconds. Those historical values are context;
this experiment reran no comparator and establishes no new cross-daemon ranking
or attribution for the difference from 170 ms.

The canonical shape was 700 peers, 400,400 prefixes, 50 flapped members,
28,600 affected prefixes, and eight ongoing background churners. Each fresh
daemon process performed three flap rounds. The six process legs ran control /
instrumented / instrumented / control / control / instrumented: nine rounds per
arm, with **three independent processes per arm** and three correlated rounds
within each process. The AB / BA / AB order is not perfectly position-balanced.
No leg or round was excluded.

The harness establishes all 50 returning sessions sequentially, then records
`t_reann` immediately before queueing their announcements. It does not start this
clock at the first Established transition. The first-to-last Established span
was 18.729 ms median; the last transition preceded the trigger by 8 µs median.
Returning-member full-table completion uses a separate clock, starting at each
member's OPEN send.

The published first-arrival statistic selects each survivor's first UPDATE with
any base-table announcement after `t_reann`. Full reannouncement tracks complete
coverage of the affected prefix range. The diagnostic separately observes first
affected-prefix arrival and the exact prefix `20.0.0.0/24`, including a trace
through survivor 350's session and writer. These are three distinct observations.
The observer timestamps an UPDATE after reading its complete frame, decoding and
parsing it, and classifying base prefixes. Thus “arrival” is a harness observation
boundary, not a packet-capture timestamp or the instant bytes entered the kernel.

## Validation and probe overhead

Both arms used the existing event-clock placement and endpoint predicates. Both
harnesses printed post-round quantiles with six decimal places instead of two.
The control daemon had no phase instrumentation. The instrumented arm added
phase logging, affected-prefix observations, and the selected marker trace.

Each leg acquired the shared host mutex, passed two accepted quiet samples at
least 30 seconds apart, and retained a full 300-second cooldown, including the
final leg. Source, binary, harness, and helper freezes matched before and after
every leg. Actual runner, harness, daemon, and cleanup exits were zero; native
readiness checks returned HTTP 200 before and after each harness. Every round
retained 700 sessions, zero parse errors, returning-peer full-table coverage and
EoR, and all required observer and phase records. All owned processes and scopes
were removed, and the mutex was released. Build and execution provenance is in
the [receipt](artifacts/first-update-phase-attribution-2026-10/provenance.json).
Build logs record compilation of RIB and transport for both the clean control
and initial probe. The final probe rebuild compiled the reviewed transport
changes and reused the unchanged instrumented RIB; its four RIB patch sections
match the initial probe exactly. Both precision harnesses were compiled, and
the measured logs contain the required RIB phases only in the probe arm.

Values below are medians of the nine per-round p50s in each arm. Changes compare
the active probe against the control; they combine instrumentation effects with
run variation.

| Endpoint | Control | Instrumented | Change |
|---|---:|---:|---:|
| First survivor announcement | 133.376 ms | 132.673 ms | −0.527% |
| Full survivor reannouncement | 276.143 ms | 283.925 ms | +2.818% |
| Survivor withdrawal | 247.703 ms | 245.598 ms | −0.850% |
| Returning-member full-table completion | 4,178.450 ms | 4,164.914 ms | −0.324% |

| Matched control / probe legs | First-arrival p50 median change | Full-reannouncement p50 median change |
|---|---:|---:|
| 1 / 2 | −3.571% | +5.709% |
| 4 / 3 | +0.792% | −6.247% |
| 5 / 6 | +0.584% | +0.866% |

Control first-arrival p50s ranged from 130.058–140.727 ms; probe values ranged
from 129.771–134.801 ms. The diagnostic did not expose a large first-arrival
perturbation in this sample, but the paired variation and full-completion shift
prevent a zero-overhead claim. These data do not establish statistical
significance or justify treating sub-millisecond differences as optimization gains.

## Phase evidence

Published-first and affected-first observations were equal for **all 5,850
survivor-rounds**. The marker was also the first affected UPDATE at all 650
survivors in six rounds. It arrived later at every survivor in the other three:
median lags were 6.327 ms, 116.720 ms, and 49.079 ms. The marker path therefore
cannot explain the earliest arrival in those three rounds. Both populations
remain in the evidence; the six matching rounds are a correlation subset, not
replacement endpoint samples.

The initial-table probe brackets the RIB actor's synchronous `send_initial_table`
call. It measures assembly and enqueue work, not the returning member's complete
wire transfer. The median of per-round registration-dump p50s was 146.169 ms;
the corresponding group-registration work was 0.210 ms. One initial-table
operation overlapped the announcement trigger in each instrumented round.

| Observation or signed interval | Median | Range | Rounds |
|---|---:|---:|---:|
| In-flight initial-table work remaining at trigger | 122.231 ms | 120.092–126.357 ms | 9 |
| That operation's end → sampled first affected arrival | 9.226 ms | 5.604–13.255 ms | 9 |
| Marker admission → RIB ingest, when marker was first affected | 127.353 ms | 126.205–130.016 ms | 6 |
| Marker admission → RIB ingest, all marker traces | 129.006 ms | 126.205–246.093 ms | 9 |
| Marker ingest → distribution start | 0.649 ms | 0.553–1.296 ms | 9 |
| Distribution start → sampled member commit | 2.298 ms | 0.684–4.589 ms | 9 |
| Sampled commit → session envelope | 0.022 ms | 0.017–0.045 ms | 9 |
| Session envelope → accepted marker frame | 0.033 ms | 0.020–0.045 ms | 9 |
| Accepted marker frame → writer coalescing start | 0.018 ms | 0.006–0.022 ms | 9 |
| Sampled coalesced socket write | 0.013 ms | 0.007–0.019 ms | 9 |
| Shared encoder source ordering | 0.022 ms | 0.015–0.036 ms | 9 |
| Source ordering end → first encoded slice | 0.061 ms | 0.034–0.095 ms | 9 |

The shared encoder belongs to the producer of the marker-bearing survivor
envelope, which may differ from sampled member 350. Its first slice need not
contain the marker. Returning members' full-table inventories are excluded from
this delta-encoder attribution. Writer correlation instead follows the marker
frame's exact accepted byte end into one contiguous coalesced write by the same
sampled member in the same round.

These intervals are **not an additive serialized breakdown**. Distribution and
consumer work overlap. Successful admissions are stamped after the send returns,
so a consumer may already be running. Per-crate monotonic clocks are anchored
once to wall time, while observer events retain the harness's existing monotonic
clock and adjacent wall stamp. All derived differences retain their sign; none
are clamped. Clock alignment does not establish sub-microsecond ordering.

The sampled writer-end to marker-observation interval ranged from 0.011 to
35.926 ms, with a 0.030 ms median. It combines cross-process clock alignment,
kernel delivery and receiver scheduling. It is not an isolated TCP latency or
writer-wakeup measurement.

## Ranked follow-ups and stop rules

The following are proposed gates for a future clean-binary experiment, not
acceptance criteria retroactively applied to this diagnostic.

| Rank | Decision | Evidence and stop rule |
|---|---|---|
| 1 | Investigate bounded synchronous registration work | Every round overlaps roughly 120–126 ms of initial-table work; the six first-matching marker traces wait roughly 126–130 ms before RIB ingest. Investigate reuse or bounded scheduling of this work within the existing grouped-join design. Require at least 20 ms **and** 10% improvement in clean first-arrival p50 medians, consistent matched-pair direction, and no more than 3% regression in full-reannouncement or withdrawal p50 medians. Retain exact coverage, session, parse-error, EoR and readiness checks. Stop if the gain comes from delaying or degrading returning-member catch-up. |
| 2 | Defer downstream RIB/distribution micro-optimization | After the overlapping operation ends, the sampled first affected arrival takes only 5.6–13.3 ms. The traced ingest/distribution intervals offer less than the proposed 20 ms first-arrival gate by themselves. Reopen only if a controlled trace identifies another common delay large enough to meet that gate. |
| 3 | Do not tune a batching timer, source ordering, or writer coalescing for this floor | Source ordering and first-slice work are tens of microseconds; the sampled write is similarly small. The writer drains already queued frames, and the bounded RIB window admits already queued input: neither waits for a timer to fill a batch. A separate tail investigation would first need to reproduce and attribute the receiver-observation outlier. |

The existing source-group counting sort, queued-input coalescing, and grouped-join
materialization work are already present in the measured base. Repeating those
changes is not a new optimization proposal. The remaining registration lead
needs an implementation and a separate quiet A/B campaign; this receipt alone
does not predict a 122 ms saving or change a production default.
