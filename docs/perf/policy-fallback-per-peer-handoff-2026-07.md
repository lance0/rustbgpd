# Per-peer policy-fallback handoff receipt (July 2026)

## Scope

This change removes member-multiplied authoritative fallback work from the
clean policy-transition actor poll. The batched RIB command now returns one of
two typed outcomes:

- `Committed` means the optimized transition committed atomically.
- `RequiresAuthoritativePerPeerApply` means the optimized transition emitted
  nothing, changed no committed policy or membership, released prepared writer
  permits, and removed every destination it created. PeerManager then sends
  one ordinary `ReplacePeerExportPolicy` command and awaits its reply before it
  sends the next.

Cleanup failure is an error, not a handoff: an unexpectedly owned destination
is retained and the outer transaction rolls every session and RIB policy back
newest-first. The fallback retains the existing five-second deadline for each
ordinary RIB reply and services only the dedicated readiness lane while it
waits. It does not recursively select another cohort or hot-apply the session
chain a second time.

This is an availability repair, not a route-bounded scheduler. One peer still
does O(table) authoritative RIB work. Dirty-drain scheduling, mixed transition
partitioning, and resumable per-route fallback remain separate work.

## Provenance and method

- Source: `536cd63bc798523a4f3ddbb19229f29d1ade57cb`.
- Main/base: `d21bab786390de83284ab60929f6c1f9fce4e7a5`.
- Toolchain: `rustc 1.97.0 (2d8144b78 2026-07-07)`.
- CPU: AMD Ryzen Threadripper 7970X 32-Cores, 64 logical CPUs.
- Host setup: unpinned process placement; `amd-pstate-epp` with the CPU
  frequency governor set to `performance`.
- Profile: Criterion release benchmark, 1 second warm-up, 3 second requested
  measurement, 10 samples, no plot.
- Workload: 65,536 IPv4-unicast routes whose export policy changes one
  community; real exact-export encoders remain installed.

The one-peer stop gate exercises production's early one-member ineligibility
decision plus one authoritative RIB replacement. It does not create a staged
destination and therefore does not exercise destination cleanup. The benchmark
seam reports the decision directly; it does not send the typed reply through
PeerManager. Deterministic tests, rather than this timing seam, prove the typed
outcome, cleanup, and serial PeerManager handoff:

```console
RUSTBGPD_POLICY_TRANSITION_RECEIPT=1 \
cargo bench -p rustbgpd-transport --features bench-internals --bench fanout -- \
  'policy_regroup_resync/shared_plan/65536/1' \
  --warm-up-time 1 --measurement-time 3 --sample-size 10 --noplot
```

The 64-peer run is a synthetic lower-level authoritative RIB-work reference:

```console
RUSTBGPD_POLICY_TRANSITION_RECEIPT=1 \
cargo bench -p rustbgpd-transport --features bench-internals --bench fanout -- \
  'policy_regroup_resync/forced_per_peer/65536/64' \
  --warm-up-time 1 --measurement-time 3 --sample-size 10 --noplot
```

That reference intentionally calls the same synchronous per-peer RIB seam in a
loop. It omits the batch reply, cleanup, PeerManager, session, channel, and
readiness costs, so it is not end-to-end typed-handoff latency. Its individual
per-peer timer is nevertheless a production RIB actor-interval proxy: the live
handoff sends no following peer until the current ordinary command replies.

## Results

| Scenario | Routes | Peers | Criterion time | First warm-up maximum per-peer RIB apply |
| --- | ---: | ---: | ---: | ---: |
| Fallback decision + one RIB apply | 65,536 | 1 | 104.25 ms (102.73-106.02 ms) | 106.508 ms |
| Synthetic sequential RIB reference | 65,536 | 64 | 4.2930 s (4.2536-4.3276 s) | 108.819 ms |

The one-peer upper confidence bound, captured warm-up operation, and largest
retained per-iteration sample are all below the unchanged 200 ms readiness
deadline. The retained-sample maximum is 110.011 ms, calculated as
`max(times[i] / iters[i])` from the checked-in Criterion sample. This is the
experiment-wide uninterrupted-interval evidence; it is not a wall-clock
scheduler-latency measurement.

No total-work improvement is claimed. The 64-peer reference records the same
unchanged synchronous per-peer RIB helper in a loop: roughly 4.29 seconds. It
is a structural reference, not a historical-branch A/B comparison. Production
now admits PeerManager readiness and transaction progress between 64 ordinary
RIB commands; the lower-level reference's first warm-up invocation recorded
108.819 ms as its largest individual call.

`max_authoritative_peer_apply_ns` and `max_uninterrupted_work_ns` are printed
once, during the first warm-up invocation. They are not maxima across all
Criterion samples. Criterion's confidence interval is the experiment-wide
total-time evidence. Exact estimates, raw retained samples, SHA-256 checksums,
and verbatim warm-up receipts are stored under
`docs/perf/artifacts/policy-fallback-per-peer-handoff-2026-07/`.

## Correctness gates

Focused tests prove:

- early and late fallback return the typed handoff without optimized emission;
- a fully staged unowned destination is gone before the handoff reply;
- cleanup refuses an unexpectedly owned destination;
- a held ordinary RIB reply services readiness and does not prequeue the next
  peer;
- successful handoff advances every managed peer without a second session
  apply;
- a second-peer error restores session and RIB state newest-first; and
- a timed-out first peer completes its owned RIB operation before queued
  rollback commands restore the original payload and order.

These microbenchmarks and deterministic tests do not replace the loaded
700-peer reload campaign.
