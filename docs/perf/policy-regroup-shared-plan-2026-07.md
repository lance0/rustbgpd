# Shared policy-regroup transition benchmark (July 2026)

## Scope

This receipt measures the strict clean update-group policy-transition path. It
does not claim loaded reload acceptance: the 700-peer campaign remains rejected
until the separate PeerManager readiness lane and the measured actor-slice
residual are addressed.

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

## Residual and next gate

The initial and rebased maximum synchronous RIB actor-slice samples were 83.2
ms and 93.2 ms. This sample-level variance does not change the conclusion:
both exceed the 50 ms engineering budget. The next tranche must slice only
this explicit shared-plan builder/emitter and drain the existing priority-query
lane between slices; it must not generalize chunking to every
`distribute_changes` shape.

These results are microbenchmark evidence only. They do not accept or replace
the loaded reload campaign, which remains blocked on that responsiveness work
and the PeerManager readiness-query lane.

## Bounded responsiveness follow-up

The follow-up source `106df0cd` is a true stack on the shared-plan head
`2c5ad2bd`. It keeps the strict PR-1 eligibility and fallback rules, but bounds
only the expensive shared-plan preflight: destination staging, immutable diff
construction, and exact probing process at most 1,024 route identities before
servicing up to eight requests from the existing RIB priority-query lane.
Successful exact-probe reuse now checks only the cohort's largest encoded
message for each compatible member. The snapshot contract still proves wire
equivalence, and admitting the maximum proves every shorter message fits;
incompatible wire profiles still perform their own chunked full probe.

The final membership move and reserved-permit sends remain one synchronous,
infallible section. Priority queries cannot observe half-applied membership.
Every writer permit and exact snapshot is acquired before that section, then
owner, generation, and active-session identity are revalidated. A preflight
failure discards the local inventory and takes the authoritative whole-cohort
fallback before emission. Dropping the caller does not cancel an applied
prefix of the transaction: PeerManager continues to a complete RIB commit or
the existing newest-first rollback before returning to its normal mutation
lane.

PeerManager also has a dedicated, type-narrow `ListPeers` readiness channel.
The production `/readyz` path uses that channel plus the RIB priority-query
channel while retaining the same absolute 200 ms deadline. Session-policy and
RIB-reply waits select the transaction result first, then service one live
readiness snapshot at a time. Ordinary add/delete/reconfigure/config/policy
commands remain on the normal receiver and cannot bypass a transaction.

### Deterministic readiness gate

The paused-clock regression holds a uniform 16-peer export-only cohort at its
in-flight RIB commit, queues an ordinary runtime mutation, and issues eight
live `ListPeers` snapshots through the dedicated channel. All eight complete
inside the unchanged 200 ms timeout (zero timeouts), each returns all 16 live
peers, the mutation remains unanswered, and the transaction reply remains
unanswered until the held RIB commit is released:

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

### Actor-slice receipt

- Toolchain: `rustc 1.97.0 (2d8144b78 2026-07-07)`.
- CPU: AMD Ryzen Threadripper 7970X 32-Cores.
- Profile: Criterion release benchmark, 1 second warm-up, 3 second target
  measurement, 10 samples, no plot.
- Workload: the same 65,536-route, 64-peer, real-encoder shared policy-regroup
  case described above.

```console
RUSTBGPD_POLICY_TRANSITION_RECEIPT=1 \
cargo bench -p rustbgpd-transport --features bench-internals --bench fanout -- \
  'policy_regroup_resync/shared_plan/65536/64' \
  --warm-up-time 1 --measurement-time 3 --sample-size 10 --noplot
```

The recorded result was 79.289 ms (77.908-80.799 ms) total transition time,
with this counter receipt:

```text
fast=true
plans=1
full_exact_probes=65536
route_shell_materializations=65536
max_actor_slice_ns=1675871
```

The 1.676 ms maximum recorded slice is below the 50 ms engineering budget and
replaces the PR-1 samples of 83.2-93.2 ms. Total time remains microbenchmark
evidence, not a loaded-reload acceptance claim. The exclusive 700-peer campaign
must run from a fresh integrated SHA before the rejected campaign can be
superseded.
