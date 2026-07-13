# Shared policy-regroup transition benchmark (July 2026)

## Scope

This receipt measures the strict clean update-group policy-transition path and
its bounded-readiness follow-up. It does not claim loaded reload acceptance:
the prior 700-peer campaign remains rejected until a fresh integrated run
supersedes it.

The optimized path is deliberately limited to clean grouped-to-grouped unicast
members whose staging profile differs only by export-chain content. It builds
one immutable old/new inventory, materializes changed route shells once, and
reuses successful exact-export lengths only when each session snapshot proves
wire compatibility. Dirty, force, ORF, Add-Path, RTC, VPN, mixed-family,
generation-mismatched, saturated, or exact-rejecting cohorts fall back before
the first optimized emission.

## Method and provenance

- Full-matrix base: `f70e4a6d49be18ac8e6c640a396537577061f29e`.
- Full-matrix safety head: `2d8ecabc` (`perf: share clean policy transition
  work`). The subsequent rebase did not change the measured RIB/benchmark
  code.
- Confirmation base: `d75f56a80b54eef00bf510e20863e4f814c2c503`.
- Confirmation source/head: `47f1b28a5513e987d2fd82aa7653ba6e234c72ac`.
  Subsequent changes affect only this receipt, fallback registration
  preflight, and PeerManager rollback; the measured shared RIB path and
  benchmark are unchanged.
- Toolchain: `rustc 1.97.0 (2d8144b78 2026-07-07)`.
- CPU: AMD Ryzen Threadripper 7970X 32-Cores.
- Profile: Criterion release benchmark, 1 second warm-up, 3 second target
  measurement, 10 samples, no plot.
- Workload: IPv4 unicast routes; 1, 8, or 64 homogeneous RR-client peers;
  export policy changes one community on every route; a real session export
  encoder is installed for every peer.
- Shared case: one batched RIB replacement command. A one-peer cohort is
  intentionally ineligible and exercises the existing fallback.
- Reference: the same replacements driven one peer at a time through the
  authoritative regroup path.

The rebased 64-peer confirmation ran both the shared and forced-reference
cases with:

```console
cargo bench -p rustbgpd-transport --features bench-internals --bench fanout -- \
  'policy_regroup_resync/.*/.*/64' \
  --warm-up-time 1 --measurement-time 3 --sample-size 10 --noplot
```

The counter/slice receipt used the same profile with the shared case selected
explicitly:

```console
RUSTBGPD_POLICY_TRANSITION_RECEIPT=1 \
cargo bench -p rustbgpd-transport --features bench-internals --bench fanout -- \
  'policy_regroup_resync/shared_plan/65536/64' \
  --warm-up-time 1 --measurement-time 3 --sample-size 10 --noplot
```

## Results

Criterion point estimates (middle value of each reported confidence interval):

| Routes | Peers | Batched/shared | Forced per-peer | Speedup |
| ---: | ---: | ---: | ---: | ---: |
| 4,096 | 1 | 3.568 ms | 3.377 ms | 0.95x (fallback) |
| 4,096 | 8 | 2.990 ms | 17.174 ms | 5.74x |
| 4,096 | 64 | 3.675 ms | 129.210 ms | 35.16x |
| 65,536 | 1 | 104.270 ms | 101.250 ms | 0.97x (fallback) |
| 65,536 | 8 | 74.971 ms | 579.930 ms | 7.74x |
| 65,536 | 64 | 80.260 ms | 4.197 s | 52.30x |

The required uniform 64-peer cohort gain is above 10x at both route counts.
The smaller 8-peer cohort improves materially but does not meet that gate; no
claim is made that every fanout size improves by 10x.

The rebased confirmation retained the gain. Values are Criterion point
estimates, with the reported confidence interval in parentheses:

| Routes | Batched/shared | Forced per-peer | Speedup |
| ---: | ---: | ---: | ---: |
| 4,096 | 3.702 ms (3.639-3.776) | 133.030 ms (131.030-135.020) | 35.93x |
| 65,536 | 85.961 ms (84.116-87.888) | 4.966 s (4.790-5.140) | 57.77x |

The 65,536-route/64-peer rebased counter receipt was:

```text
fast=true
plans=1
full_exact_probes=65536
route_shell_materializations=65536
max_actor_slice_ns=93198473
```

Thus plan builds scale with equivalent transitions, while full probes and
route-shell materializations scale with routes times compatible wire profiles,
not routes times peers. At 65,536 routes and 64 compatible peers that is 65,536
probes/materializations instead of the per-peer reference shape's 4,194,304.

## Original scheduling residual

The original and rebased PR-1 maximum synchronous RIB actor samples were 83.2
ms and 93.2 ms. Both exceeded the 50 ms engineering budget. The follow-up below
closes that specific scheduler-visible gap without generalizing chunking to
other `distribute_changes` shapes.

These results are microbenchmark evidence only. They do not accept or replace
the loaded reload campaign.

## Bounded responsiveness follow-up

The follow-up measurement source is `114072d7`, based on merged shared-plan
main `d6d07a76`. It keeps the strict PR-1 eligibility and fallback rules. One
actor-owned pending transition has exactly five phases: `Classify`,
`StageDestination`, `BuildInventory`, `ProbeAndPrepare`, and `Finalize`. The
RIB advances one production step, services only the explicitly enumerated
read-only priority lane, then calls `tokio::task::yield_now`. It does not poll
normal mutations, route batches, resync, GR/LLGR, refresh, selection, or other
timers while the transaction is pending. Classification processes at most
eight members per poll. Two deliberately explicit O(table) snapshot polls
precede the chunked bodies: `StageDestination` first snapshots all Loc-RIB
prefix identities, and `BuildInventory` later snapshots all destination-table
route keys. Both are measured production actor polls; the
`max_prefix_snapshot_poll_ns` receipt reports the slower sample. The 1,024
identity cap applies only to the staging, inventory-build, and exact-probe
chunk bodies after their snapshot exists. These samples do not establish or
extrapolate a hard bound for either full-table snapshot poll.

Successful exact-probe reuse checks only the cohort's largest encoded message
for each compatible member. The snapshot contract still proves wire
equivalence, and admitting the maximum proves every shorter message fits;
incompatible wire profiles still perform their own chunked full probe.

The final poll revalidates every active session, registration channel, encoder
owner/generation, source/destination classification, and reserved writer permit
before changing membership. Membership, counter replay, and all
reserved-permit sends then remain one synchronous section, so a priority query
observes either the old cohort or the complete new cohort. An incomplete
unowned destination is discarded before authoritative fallback. Dropping the
caller or closing the input channels does not cancel the owned transition.

PeerManager also has a dedicated, type-narrow `ListPeers` readiness channel.
The production `/readyz` path uses that channel plus the RIB priority-query
channel while retaining the same absolute 200 ms deadline. Session-policy and
RIB-reply waits select the transaction result first, then service one live
readiness snapshot at a time. Once a cohort command is successfully enqueued,
PeerManager owns its reply to terminal success, explicit failure, or sender
closure; it does not start rollback on the ordinary five-second per-peer RIB
timeout while the forward commit can still complete. Ordinary per-peer
timeouts are unchanged. Add/delete/reconfigure/config/policy commands remain
on the normal receiver and cannot bypass a transaction.

### Deterministic readiness gate

The paused-clock regression holds a uniform 16-peer export-only cohort at its
in-flight RIB commit, queues an ordinary runtime mutation, and issues eight
live `ListPeers` snapshots through the dedicated channel. All eight complete
inside the unchanged 200 ms timeout (zero timeouts), each returns all 16 live
peers, the mutation remains unanswered, and the transaction reply remains
unanswered until the held RIB commit is released. The same test advances past
the former five-second cohort timeout and proves that no rollback begins or
races the still-owned forward commit while readiness remains live:

```console
cargo test -p rustbgpd --bin rustbgpd \
  export_only_snapshot_services_readiness_without_admitting_mutations -- --nocapture
```

The exact-cohort regression additionally varies synthetic encoded lengths and
asserts that every compatible target rechecks one value (the cohort maximum),
not one value per route:

```console
cargo test -p rustbgpd-rib \
  clean_policy_transition_builds_and_probes_once_per_wire_cohort -- --nocapture
```

A current-thread scheduler regression creates a priority query only after the
first transition poll has completed. It proves that the query sees old
committed membership, no optimized envelope has been emitted, and queued
`PeerDown` plus a second replacement remain FIFO behind finalization:

```console
cargo test -p rustbgpd-rib \
  clean_policy_transition_yields_to_queries_and_fences_mutations -- --nocapture
```

Paused-time coverage also holds a session policy command for 250 ms, then
proves a live peer snapshot completes inside the unchanged 200 ms core
deadline with the independently stalled session marked stale. A separate
failure test interleaves readiness before a rejected RIB commit and preserves
newest-first rollback and prior policy state.

### Actor-poll receipts

- Toolchain: `rustc 1.97.0 (2d8144b78 2026-07-07)`.
- CPU: AMD Ryzen Threadripper 7970X 32-Cores.
- Profile: Criterion release benchmark, 1 second warm-up, 3 second target
  measurement, 10 samples, no plot.
- Workloads: the same 65,536-route/64-peer real-encoder transition, plus a
  4,096-route/700-peer run that isolates the largest required atomic member
  finalization.

```console
RUSTBGPD_POLICY_TRANSITION_RECEIPT=1 \
cargo bench -p rustbgpd-transport --features bench-internals --bench fanout -- \
  'policy_regroup_resync/shared_plan/65536/64' \
  --warm-up-time 1 --measurement-time 3 --sample-size 10 --noplot
```

The 65,536-route/64-peer result was 82.791 ms (81.704-83.994 ms) total
transition time, with this production state-machine receipt:

```text
fast=true
plans=1
full_exact_probes=65536
route_shell_materializations=65536
actor_polls=267
max_actor_poll_ns=4927435
max_prefix_snapshot_poll_ns=4927435
max_finalize_poll_ns=2075407
```

The 700-member finalization gate ran with:

```console
RUSTBGPD_POLICY_TRANSITION_RECEIPT=1 \
RUSTBGPD_POLICY_TRANSITION_LARGE_RECEIPT=1 \
cargo bench -p rustbgpd-transport --features bench-internals --bench fanout -- \
  'policy_regroup_resync/shared_plan/4096/700' \
  --warm-up-time 1 --measurement-time 3 --sample-size 10 --noplot
```

It completed in 7.970 ms (7.832-8.120 ms) total:

```text
fast=true
plans=1
full_exact_probes=4096
route_shell_materializations=4096
actor_polls=803
max_actor_poll_ns=2001396
max_prefix_snapshot_poll_ns=376183
max_finalize_poll_ns=2001396
```

The largest recorded production poll was 4.927 ms and the 700-member atomic
finalization was 2.001 ms, both below the 50 ms engineering budget. The old
1.676 ms pseudo-slice result is intentionally withdrawn: it measured internal
`try_recv` checkpoints without proving a Tokio scheduling opportunity. Total
times and individual poll samples—including the two O(table) prefix/inventory
snapshot polls—remain microbenchmark evidence, not an extrapolated bound or a
loaded-reload acceptance claim. The exclusive 700-peer campaign must run from
a fresh integrated SHA before the rejected campaign can be superseded.

## IXP remote-AS cohort follow-up

The IXP follow-up adds a complementary eBGP route-server fixture without
changing the homogeneous RR workload above. Before the fix, a clean transition
treated each remote ASN as a distinct exact-export profile even though encoding
consumed it only as eBGP/iBGP classification. At 4,096 routes and 700
distinct-ASN clients, that produced 2,867,200 full probes, 3,599 actor polls,
and a 510.332 ms median.

The exact-export profile now stores the derived eBGP/iBGP class while retaining
full equality for every actual wire input. The same distinct-ASN workload uses
4,096 full probes and 803 polls and completes in 7.604 ms, a -98.51% Criterion
mean change (-98.54%..-98.49%). The 64-client cell drops from 262,144 to 4,096
full probes and from 49.206 ms to 3.464 ms. Optimized homogeneous and
distinct-ASN receipts have identical plan/probe/shell/poll counts. Byte-level
tests prove cross-ASN eBGP equality and preserve the eBGP/iBGP incompatibility
boundary; per-member ceiling and generation checks remain mandatory.

The homogeneous 700-client cell showed no detected change (-1.60% mean,
-4.34%..+1.01%). The homogeneous 64-client cell also showed no detected change
(+1.07% mean, -0.72%..+2.67%). Both are retained because the benchmark matrix
is evidence rather than a selective headline.
The dynamic-neighbor capture canary additionally proves that configured
`remote_asn = 0` defers classification to the negotiated ASN for both eBGP and
same-AS iBGP sessions.

Raw medians, confidence bounds, deterministic counters, environment, and
reproduction commands are retained in
[`artifacts/ixp-exact-export-cohorts-2026-07/`](artifacts/ixp-exact-export-cohorts-2026-07/).
These results do not supersede the still-required loaded 700-peer campaign.
