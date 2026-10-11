# Idle readiness checkpoint comparison — 2026-10-10

A matched normal-production A/B/B/A shows a modest reduction in the wall-time
between consecutive observer route-refresh handlers after removing the mutex
from an unforced idle readiness checkpoint. Both candidate process medians
are lower, but OPEN-to-table rejoin clocks are mixed. This supports the
bounded checkpoint change on this shape; it does not establish a general
completion, throughput or CPU improvement.

The [earlier route-refresh readiness receipt](route-refresh-readiness-2026-10.md)
measured the cost of serving readiness during replay. This new comparison
uses later source revisions and preserves that receipt as history. It retains
every requested observer pair, including both disconnected and settled
checkpoints, with no duration cutoff.

## Result

All four native cells passed. Each started a fresh daemon, ran three rounds,
and completed both exact-table/EoR checkpoints in every round. There are two
independent process launches per arm, six correlated rounds and twelve
correlated observer pairs per arm. Pooled rows describe these processes;
they are not independent samples for a significance claim.

All times below are milliseconds. A is the frozen baseline; B is the
candidate. The primary comparison is by process, in measured order:

| Process | Inter-handler median [min–max] | OPEN-to-table median [min–max] | Survivor maximum-gap range | Readiness samples |
|---|---:|---:|---:|---:|
| A1 | 215.421 [211.616–219.317] | 169.816 [165.956–176.893] | 105.419–118.084 | 36 |
| B1 | 211.626 [208.567–216.524] | 166.921 [164.253–169.245] | 105.560–109.299 | 36 |
| B2 | 210.901 [204.684–216.020] | 163.735 [159.817–164.122] | 102.053–105.671 | 36 |
| A2 | 215.966 [208.178–223.926] | 125.062 [120.091–127.056] | 100.007–106.652 | 36 |

Both B inter-handler medians are about 2% below both A medians, with overlapping
ranges. The descriptive pooled median is 215.493 → 211.626 ms (−1.8%). The
first round of each process gives 216.951 → 211.623 ms; the remaining two
rounds give 215.493 → 211.626 ms. Neither subgroup is independent replication.

Rejoin does not show the same repeatable improvement. Both B process medians
are below A1 and above the faster A2. The pooled OPEN-to-table median rises
146.506 → 164.188 ms (+12.1%). The complete per-round values and both replay
checkpoint phases are retained in the artifact bundle. No slow or contrary
row is excluded.

Zero readiness misses were observed in 144 successful samples across the
four watch intervals. The native watch samples `/readyz` once per second,
requires HTTP 200 within 250 ms, and fails on a late success. This is sampled
liveness evidence during the cell, not continuous deadline coverage or a
readiness latency distribution. The existing daemon's readiness service
semantics remain a separate contract.

## Clock boundaries and the fast closing baseline

The inter-handler clock is the timestamp difference between consecutive
`handling route refresh request` events for the two surviving observers.
These requests are sent back to back at each disconnected and settled
checkpoint. The gap includes replay, readiness service and scheduling before
the next handler starts. It is a wall-time proxy, not CPU time, a standalone
function timer or proof of full wire completion.

The harness's rejoin clock starts immediately after the stub successfully
writes its OPEN. Completion uses the reader-recorded decoded-message
timestamp: the later of the first EoR and exact current-table completion.
The 100 ms completion polling delays the outer wait and survivor window;
it does not round or delay this stored rejoin duration. The clock excludes
later replay of the joiner's source routes and GR settlement.
The survivor maximum-gap clock covers the harness's reconnect interval and
measures gaps between received UPDATEs for the 699 surviving peers. These
clocks have different boundaries and are not added together.

A bounded check of the original daemon logs found a shorter secondary span
in A2, and a much smaller difference between that span and the harness clock:

| Process | Median session-established → EoR-enqueued log | Median per-row difference from OPEN-to-table |
|---|---:|---:|
| A1 | 133.638 | 37.481 |
| B1 | 130.031 | 36.890 |
| B2 | 125.731 | 36.752 |
| A2 | 123.848 | 1.214 |

The `sent End-of-RIB` event follows successful queueing with `enqueue_bulk`;
it does not prove socket-write completion. A2's three difference values are
1.098–1.266 ms; the other nine are 36.178–38.004 ms. This locates part of the
native rejoin variation outside the logged established-to-EoR interval.
The retained logs do not timestamp the harness OPEN or table-completion
boundaries individually, so they cannot allocate that difference among
handshake, queued delivery, receiving, decoding and scheduling. Its mechanism
remains unresolved; the result is not classified as noise or a general
rejoin gain. Completion polling and microsecond rounding cannot account
for the roughly 36 ms residual difference. All twelve secondary clock rows
are published.

## Source, shape and instrument

| Role | Exact measured commit | Tree |
|---|---|---|
| A daemon; common runner, generator and harness source | `3102768788b9acba3ae177739483caf0771bfa82` | `099282d4b41b12be07456d7dfb5f9661df64558d` |
| B daemon | `308484000fd34f79c933d39f5780a7aa5ecb3950` | `28d4523ed87c4fe4b6239217433be5e26b397974` |

B's parent is `1adee3f2c500ee8cf02b2dc68a3bddc0ec7fadb6`, a documentation-only
child of A. The runtime comparator is therefore frozen A, rather than an
unspecified current main. The candidate adds receiver wake-state tracking
so an unforced checkpoint with no pending readiness or summary work can
return without locking or reading the clock. Forced service, queued work
and instrumented opportunity receipts retain their eligibility semantics.

The measured cell is the existing converged-rejoin scenario: 700 route-server
peers, 400,400 IPv4 prefixes, 572 disjoint prefixes per source, K=1 peer
flapped under GR helper, three rounds and a 30-second control interval.
Two surviving observers each require 399,828 distinct prefixes and EoR at
both checkpoints. Exact reconnect coverage must complete before the joiner
replays its own source routes. Every row reports 700 sessions up and zero
parse errors; native GR retention/settlement and survivor withdrawal checks
also passed.

Both daemons used one frozen generator and one immutable harness built from
A. The common CLI was retained as an instrument identity; this cell adds no
CLI read workload. The relevant SHA-256 hashes are:

| Binary | SHA-256 |
|---|---|
| A daemon | `ed7eefa9c6b3e985f7f0c8632db4ac15f960851d8ca946fcf1c14c5d985bf10e` |
| B daemon | `611a4a380d49fa0770e182a141aea79ba44a1e305b4bda1ebc02abb06897d8f3` |
| Common CLI | `8fc6ac7c24009ba6455ddc492a0e6ebf83198686ce481b517456651155001338` |
| Common reloadstall | `5574adf132d427f7f38e844442ddc01f0f738521c0254ce7608777d38a8efbe5` |

## Build and native qualification

Each clean daemon source tree was built with the identical normal-production
package selection, `cargo build --release --locked -j 4 -p rustbgpd -p
rustbgpctl`, pinned to CPUs 40–63. The common harness used `cargo build
--profile scale --locked -j 4 -p reloadstall` on the same toolchain. Builds
held the canonical host lock and shared target's build lock. Tracked Rust,
protobuf and Cargo input timestamps were refreshed without content changes;
the exact relative input lists, timestamps and hashes are retained. Each
binary was copied immutably and its actual dependency closure captured before
the next shared-cache build. All build and stage exits were zero.

The toolchain was rustc 1.99.0 (`b940084d7`, 2026-09-28), Cargo 1.99.0
(`5f94df478`, 2026-08-27), target `x86_64-unknown-linux-gnu`, LLVM 23.1.1.
Both captures contain 227 normal artifact units (226 library fingerprints
plus the daemon binary) and 343 units including build-script artifacts,
with no missing dependency signatures. Both complete sets match in unit
configuration, active features, build environment and dependency identities.
The comparison preserves duplicate unit multiplicity, including all-zero
run-script fingerprints. Source/output signatures may differ and are
retained separately. Neither actual daemon nor RIB normal unit enables
`bench-internals`; checking equality alone would not establish that.
The matching resolved normal/build Cargo graph is secondary evidence,
not a substitute for the actual fingerprint audit.

The four-cell native window ran on one Linux host from 2026-10-10
20:00:12 to 20:11:59 EDT. The outer inherited light-build lock was acquired
first, followed by the driver's continuous canonical host lock. Both were
held through A1/B1/B2/A2 and cleanup. Existing external work was allowed to
finish normally before acquisition. Every cell passed the canonical quiet
host gate before starting; the daemon used CPUs 12–32 and 34–39, the harness
40–63. No builds or competing local workloads ran inside the timing window.

All cell, harness, daemon, metrics, outer-wrapper and driver exits were zero;
no cleanup required a forced kill. End-of-window instrument, binary,
generated-input and acceptance checks passed. Every process was reaped and
both locks released. The result has no automatic retry or duration censoring.

## Assessment and evidence

Proceed with the bounded idle-checkpoint change: it removes an unnecessary
idle mutex path and this matched cell shows a small, consistent reduction
in the inter-handler proxy, while preserving all native controls. Describe
that measured scope and the mixed rejoin clocks together. Do not claim the
entire earlier approximately 20 ms cost was recovered, a universal wire or
completion gain, CPU savings, or a readiness guarantee under other loads.
A policy-reload S2 comparison was not run in this receipt.

The [artifact bundle](artifacts/idle-readiness-checkpoint-2026-10-10/README.md)
contains every native CSV row and observer pair, the secondary rejoin clocks,
quiet samples, generated inputs, exact as-run scripts, build/fingerprint
provenance and a runnable recomputation with broken-input controls. Public
copies replace private absolute paths only after the completed measurement;
raw-original and public-normalized hashes remain distinct. The checker
reconstructs the published clocks and retained acceptance metadata. Native
verdicts for omitted full daemon/metrics streams remain identified by their
original hashes and are not independently re-executed by recomputation.
