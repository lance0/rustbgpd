# Reload publication and receiver boundaries — October 2026

This experiment measures the first source-eligible UPDATE across shared
publication, consumer admission, writer acceptance, and receiver processing.

**The measurement method failed its overhead qualification.** Across three
independent control/probe pairs, the probe increased changed-gap p50 by 26.81%
under the primary estimator and 23.84% under the pooled estimator. Both exceed
the unchanged 2% bar. All native coverage, joins and clock checks passed, but
these phase measurements do not qualify as production-tail attribution. No
retry or runtime optimization was selected.

## Question and source

The earlier [observer-tail diagnostic](reload-observer-tail-2026-10-06.md) left
two broad intervals unresolved: consumer entry to admission combined shared
publication with local execution, and writer start to the observer event
combined delivery with receiver processing. It measured member-release spans of
121–149 ms and rare release-to-consumer delays up to 144.826 ms. Its single
control/probe pair increased median stall p50 by 5.38%, so those probe tails did
not qualify as clean production measurements.

The new measurement freezes source
`49abbb0171cbb889b7e2618c2bdcec6ea35699ae`, including the probe-delta runtime
changes merged in [PR #2952](https://github.com/lance0/rustbgpd/pull/2952).
The earlier observer-tail diagnostic, published in
[PR #2954](https://github.com/lance0/rustbgpd/pull/2954), remains the historical
lead; its measurements describe the earlier source.

The initial preparation used
`c4639d7573bced02cf1cc4357981c242617eee70`. The runtime merge changed the paths
under measurement before this experiment ran any smoke or measured attempt.
That unmeasured preparation is retained as superseded evidence. The capture method was ported to the new source with the same process order
and qualification criteria. Preparation fixes for trace emission, gap-window
reconstruction and output framing preceded the final measured freeze; the
artifact guide retains that history. This restart was caused by source drift, not observed performance,
and does not consume the permitted retry after a failed measured method.

The daemon build command, default features, allocator, and linked dependency
graph match across arms. The retained graph comparison contains 345 semantic
dependency nodes in each arm with no mismatched settings or edges. Separate
producer-build and execution-source bindings retain the harness and runner
instrumentation.

## Workload and qualification

Each fresh process uses the native 700-peer, 400,400-prefix policy-reload cell,
with all peers changed, four reloads, a 30-second control period, no added RTT,
and unpaced readers. The workload changes both import and export policy. The
harness and daemon use their pinned default allocator and build features. The
control daemon has no runtime probe. Both harnesses retain the same post-round
observer outcomes and clock reporting; only the probe retains read/write capture
state, byte counters, and phase sampling. Their separate binary identities keep
that capture cost inside the overhead comparison.

The three control/probe pairs run in AB / BA / AB order. Every leg must pass the
native quiet-host admission, including two samples at least 30 seconds apart,
and retain its full 300-second cooldown. Monotonic witnesses bracket the native
cooldown sleep; source and helper bindings identify the runner used by every leg. Four reloads within one process remain
correlated observations. A complete attempt retains 24 native aggregate rows,
16,800 observer outcomes, and 8,400 first-frame joins from the three probe
processes. A small functional smoke validates emitters and joins only.

Both overhead estimators must stay within a 2% regression for native
maximum-gap p50 and completion p50:

1. Compute the median of each process's four round values, then the median of
   the three process medians for each arm.
2. Separately compute the median of all twelve round values per arm.

Every pair difference and every native round remains visible. A favorable pooled
value cannot replace a failed process-median result, or vice versa. Complete
stage coverage, exact frame identity, successful writer batches, bounded trace
buffers, source/build identity, clean process completion, and clock checks are
additional requirements. A failed method can be reduced once and rerun as a new
complete attempt; the rejected attempt remains in the receipt. No favorable
subset of rounds or processes can qualify the method.

Passing overhead and joins alone does not establish a dominant component. A
component can be ranked only when its measured interval is separated and its
phase ranking repeats across all three independent probe processes. Quantiles
from different phases are not added, and phase time is not a prediction of
recoverable latency.

## What each boundary means

| Boundary | Observation and limit |
|---|---|
| Member release | Bracket around the actual outbound permit send for that member. A consumer may run before the upper bracket timestamp. |
| Consumer entry | Entry into the session's outbound-envelope handler, joined to the exact shared inventory and member. |
| Eligible publication | Mutex-protected publication bracket for that member's first chunk after source exclusion. A producer-wide first-publish timestamp cannot substitute. |
| Consumer advance and snapshot | Entry into the admission cursor and the snapshot that contains the admitted chunk. These include local execution and possible mutex contention; they do not measure OS runnable time. |
| Successful admission | Bracket around enqueue and the exact successful bulk byte interval. Failed admission is not counted as accepted bytes. |
| Writer acceptance | Every retained `poll_write` result for the containing writer batch, including partial writes and `Pending`. The exact frame's first and last bytes are matched to accepted ranges. |
| Receiver read | Read intervals containing the exact frame's first and last bytes, retaining read-poll boundaries and split-read behavior. These do not isolate network delivery from receiver scheduling. |
| Decode, classify, observer | Decode entry/exit, classification completion, and the expected-generation observer event for the same frame. |

The elected encoder can enqueue its own chunk before publishing it to followers.
That role is identified exactly once per inventory and is reported separately
from follower publication wait. Release, publication, and cross-process clock
brackets can overlap; the reader retains bounds instead of inventing point
ordering. Source exclusion, shared encoding ownership, frame order, batching,
and writer coalescing retain their existing behavior.

The probe stores bounded records and writes them after the measured rounds or
at shutdown. Publication metadata is capped at 8,192 chunks per inventory;
writer sampling is capped at 64 poll results per selected batch. Overflow
rejects qualification. The receiver clock mapping has a 50 µs interval budget,
and the daemon's start/end mapping has a 100 µs drift/bracket budget. Passing
these checks does not prove that no intermediate wall-clock adjustment occurred.

## Overhead result

All six processes completed their four rounds and full cooldowns. The retained
native records contain 24 aggregate rows, 16,800 observer outcomes and 8,400
exact first-frame joins. Source/binary bindings, quiet admission, chronology,
process exits, cleanup receipts, and clock checks passed in the full raw audit.
The public reader rechecks the retained evidence within the limits described in
the [artifact guide](artifacts/reload-boundary-attribution-2026-10/README.md).

| Metric and estimator | Control | Probe | Change | ≤2% regression |
|---|---:|---:|---:|---|
| Changed-gap p50, median of process medians | 83.6235 ms | 106.0405 ms | +26.8071% | Fail |
| Changed-gap p50, pooled rounds | 84.1805 ms | 104.2470 ms | +23.8375% | Fail |
| Completion p50, median of process medians | 0.7509825 s | 0.7231155 s | −3.7107% | Pass |
| Completion p50, pooled rounds | 0.7509825 s | 0.7291970 s | −2.9009% | Pass |

Completion improvements cannot compensate for a failed stall bar. Each
independent pair also increased its changed-gap process median:

| Pair and execution order | Control changed-gap median | Probe changed-gap median | Change | Completion change |
|---|---:|---:|---:|---:|
| 1, control then probe | 99.8490 ms | 106.0405 ms | +6.2009% | −5.9282% |
| 2, probe then control | 80.5425 ms | 97.3310 ms | +20.8443% | +5.5576% |
| 3, control then probe | 83.6235 ms | 113.0005 ms | +35.1301% | −9.3541% |

The [24-round native table](artifacts/reload-boundary-attribution-2026-10/rounds.csv)
retains each round's p50, p95 and maximum. The
[recomputed result](artifacts/reload-boundary-attribution-2026-10/results.json)
also retains publication/release bounds, late-release groups, separated encoder
measurements, and changing slow-tail membership. No round or process was
removed to improve qualification.

## Diagnostic findings under the intrusive probe

The first expected-generation frame ended every tied maximum changed gap for
1,510 of 8,400 probe observer-rounds (17.98%), and every tied maximum all-window
gap for 1,499 (17.85%). No observer matched only one of several tied maxima.
Among each round's worst 5%, keeping every observer tied at the cutoff, the
first frame ended 367 of 420 maxima (87.38%) under both definitions. It ended
11 of the 12 absolute round maxima. The unmatched maximum was a later
153.673 ms inter-UPDATE gap; this first-frame trace cannot explain that gap.

There were no extra ties at a 5% cutoff in this campaign. The records still
retain all tied maximum-gap spans: one probe observer had two 54.689 ms UPDATE
gaps under both definitions, and one control observer had two 73.718 ms
all-window gaps. Neither tie set ended at its first-generation event. The
changed-gap window stops at each observer's completion; the all-window metric
includes the remaining round and its trailing gap.

To compare separated phases, the diagnostic takes each round's follower p95
bounds and then the median of those four bounds within each process. These are
distributions across observers, not an additive latency budget. The two largest
all-follower intervals exchange rank:

| Probe process | Accepted final byte → successful read poll | Eligible publication ready → consumer advance | Largest interval |
|---|---:|---:|---|
| 02 | 82.266–82.294 ms | 57.040–57.040 ms | Accept to read poll |
| 03 | 85.786–85.862 ms | 74.006–74.006 ms | Accept to read poll |
| 06 | 66.932–66.982 ms | 80.116–80.117 ms | Ready to advance |

The all-follower leader does not repeat across all three processes. A narrower
subset does repeat: among worst-5% followers whose maximum gap ends at the
traced first frame, intersecting each phase with that exact gap ranks the
accepted-final-byte-to-successful-read-poll interval first in all three process
aggregates (104.590–104.671, 121.419–121.456 and 107.382–107.436 ms). It leads
9 of 12 individual rounds. This is a diagnostic lead within the intrusive
probe, not a production cause or recoverable-gain estimate. That interval
includes delivery and receiver execution/scheduling; it does not isolate
network delay, kernel readiness, wakeups or OS runnable time.

Both frame endpoints arrived in the same read in all 8,400 joins, so first- and
last-byte read intervals must not be added. The elected encoder was observer 0
in every probe round; its 3.850–5.594 ms entry-to-first-admission span is kept
separate from follower publication waits. Each process's worst-5% sets covered
115, 115 and 116 distinct observers, with no observer in the worst set across
all four rounds. A fixed slow-peer cohort would misdescribe the result.

## Disposition and evidence limits

This is a complete failed measurement method, with a null production-attribution
result. The permitted retry was not used. The probe adds timestamp/atomic work,
a first-admission target-registry lock and chunk metadata capture at boundaries
that affect fan-out and ordering. Those costs are plausible perturbations, but
this campaign does not isolate their individual contribution to the regression.
Member and receiver capture already stop after their first target. There is no
evidence that removing two untargeted writer loads would recover the measured
overhead, and no such change is proposed here.

The complete failed attempt remains available through privacy-safe compact
records, executed method/build hashes and the retained external archive binding.
The public reader reproduces all joins, both overhead estimators, diagnostic
rankings and maximum-gap associations. It also checks that the small lint-only
public reader change produces the same full receiver analyses as its preserved
executed original. Public aliases and hashes cannot independently authenticate
omitted raw process identity, binary/source equality, cleanup or extraction;
those limits and the preparation/startup history are explicit in the artifact
guide.

No runtime instrumentation, scheduler change, batching change, shared-encode
change, actor offload or permanent measurement setting ships with this receipt.
Any later measurement redesign must independently meet the unchanged overhead
and join requirements before supporting production attribution.
