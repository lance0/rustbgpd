# rrharness

Deliberate manual performance harness: CI compiles, lints, and unit-tests it, but the measured run is operator-initiated.

RibManager flood/churn CPU + memory profiling and late-client-join measurement
harness.

## What it measures

Drives the real `RibManager` run loop directly (no TCP/transport) on a
dedicated OS thread named `ribmgr` under a current-thread tokio runtime, with N
registered route-reflector-client outbound peers whose bounded channels are
drained by trivial consumer tasks. Route injection is via
`RibUpdate::RoutesReceived`; the staged Adj-RIB-Out is polled via
`RibUpdate::QueryBmpPeerStats`. Every synthetic session stages the same
authoritative exact-export encoder used by the transport fanout benchmark, so
the measured manager path includes production's fail-closed wire-size probe
instead of relying on a permissive test stub. Because the manager task is alone
on its thread, every profiler sample on `ribmgr` is manager-task work — no
bucketing.

Per run it reports RSS at each phase, cold stage/drain times, sustained
throughput (blocks or waves) over a profiled window, the manager thread's
CPU-seconds and busy fraction, and writes a deterministically sorted folded
profile to `<out>.folded` (root-to-leaf stack order:
`thread<TAB>frame;frame;...<TAB>count`). Classify it with
`../rebaseline/classify_cpu.py`; the committed map and fixtures are documented
in [`../rebaseline/README.md`](../rebaseline/README.md).

Because the harness reaches into `RibManager` internals, it must be kept
compiling against `crates/rib`, `crates/wire`, and `crates/telemetry` on `main`.

## Backs

- `docs/perf/rebaseline-2026-07.md` (ADR-0100 slice-0 manager-task phase table
  and whole-process RSS snapshots). This harness reports process RSS from
  `/proc` only; the per-component live-heap attribution table in that receipt
  is produced by the separate dhat/bgperf2 pass, not this harness.
- The 2026-07-10 re-profile.
- The v0.61.0 `flood 1000 100000 20` baseline (cold staged 1.326 s,
  213 MiB converged, manager-direct — **not** comparable to the
  transport-harness scale-receipt headline), recorded in
  [`docs/perf/ixp-matrix-2026-07.md`](../../../docs/perf/ixp-matrix-2026-07.md#1000-client-rr-cell--in-repo-manager-direct-harness).

## Hosted retirement attribution

The optional `CI` dispatch with `recovery_memory_receipt=true` and
`recovery_receipt_mode=retirement` measures four actual actor boundaries:
VPN stage-map retirement, and the detached Adj-RIB-In destructor after
peer-down recomputation and before attribute-intern garbage collection;
private all-family Adj-RIB-Out retirement; and retained regroup-baseline
retirement. The last two include the emptied collection's backing allocations.
The containing peer-down-to-query-barrier duration is reported separately;
it is not a bound on the complete peer-down operation or garbage collection.

Each fresh hosted VM runs one full-table profile: one million IPv4 plus
230,000 IPv6 routes, either unicast or VPN. Six cases each run in old-drop,
current, current, old-drop order: the original empty/full source departure,
empty/full private Adj-RIB-Out departure, and empty/full pending-regroup
departure. That is 24 actor invocations per VM, 48 across the two profiles.
The old-drop
binary differs only by restoring the former VPN stage-map drop. Both arms
use the current source, locked dependencies, scale profile and jemalloc.
The receiver-cleanup implementations are identical in both arms; those phases
are cost observations, not a cleanup improvement comparison.
Every leg must finish exact announced/withdrawn receiver inventories, actor
barriers and the required full-size retirement phases. Missing or empty
eligible work is invalid; absent VPN work in the unicast profile is reported
as ineligible rather than a zero-cost observation. The original source cases
retain their one-receiver topology and phase boundaries. The summarizer
accepts only the current v3 campaign: all six cases with bounded readiness
evidence. Earlier v1 and v2 archives remain as published.

The private Adj-RIB-Out cases use two grouped receivers with only two
unicast or VPN anchor routes, plus 1,230,000 private EVPN IMET routes in the
full case. EVPN group ownership remains disabled. These are private EVPN
rows, not 1,230,000 unicast or VPN rows. The empty control first announces and
withdraws a real IMET. Exact finite bitmaps validate EVPN keys, payloads,
attributes and folds before and after the target receiver departs.

The regroup cases first advertise the profile's full inventory privately to
a slow target while a grouped witness receives the same routes. The target
then pauses, and eight actual alternating one-key withdrawals/announcements
(announcements/withdrawals for the empty case) fill its queue. Each input
must reach the witness's exact fold and consume one target queue credit
before the next input is admitted, preventing ingest coalescing from creating
a false full-queue fixture. Clearing the slow flag must create a real retained
baseline with the full inventory while the target is dirty and its queue is
full. Only then does capture start and the target depart.

Both receiver cases keep the source and witness registered, preserve the
witness's group identity, selected unicast/VPN routes and exact receiver
folds, and clear the departed target's registration, dirty state and baseline.
The existing bounded EVPN page query also verifies received and best-route
totals outside the capture window, without copying the full table.
Receiver teardown does not fabricate withdrawals to the disconnected target;
its eight already-queued preparation messages drain after the measured barrier.
Source bodies and their shared attributes stay live, so the samples describe
receiver-owned collections rather than total route or attribute reclamation.

The in-process actor and harness share one 12 GiB cgroup with swap disabled.
The receipt retains both source patches, one hash per built binary, process
identity, commands, resource readouts and the driver exit, which covers
cleanup. The candidate patch must be empty, the control patch must touch only
the VPN distribution source, and the two binaries must differ. Raw observations and descriptive medians/maxima do not
constitute a daemon readiness, fleet, throughput or memory qualification.
Phase costs have no speedup pass threshold or automatic chunking decision.

The v3 receipt separately reports three readiness observations. For each
unmixed cleanup owner, the maximum interval between all checkpoint callbacks
covers entry, productive cleanup, and the final callback after backing storage
is released. Received-row cleanup includes attribute-intern garbage collection,
although the historical Adj-RIB-In phase timer still ends before that sweep.
The fixture uses at most four shared attribute sets, so this does not measure
attribute cleanup at real-table diversity or its full-table cost.
An eligible full cleanup must have productive callbacks for its real inventory,
successful in-owner queries delivered at a nonforced tagged cleanup callback,
and a maximum
instrumented callback interval of at most the existing 25 ms service budget.
Mixed owners, owners crossing capture boundaries, missing work or absent query
overlap cannot qualify. Empty controls report their actual work and overlap
without claiming a full-cleanup qualification.

The existing maximum gap between eligible service opportunities is a separate
counter. Its 25 ms target is not a strict 25 ms bound: eligibility includes the
budget and any overshoot. A third observation comes from one real readiness
query at a time on the existing dedicated lane, whose capacity remains 64.
An independent observer retains each admitted reply through the primary FIFO
barrier and a final post-barrier probe. Counts, actual owner overlap and the
maximum refill gap are retained; a single producer does not imply a permanently
nonempty queue. Every probe must succeed, and its measured reservation-to-reply
interval must stay within the existing 200 ms RIB-component deadline. This does
not qualify the complete shared peer-manager/RIB HTTP probe or its unchanged
250 ms external watcher deadline.

All these costs come from an instrumented `bench-internals` build. Its
checkpoint callbacks take the instrumentation lock and read the clock, so
phase and containing-operation costs include that overhead. Callback intervals
also include probe service and instrumentation overhead; they are not client
query latency. These instrumented observations must not be directly compared
with historical pre-checkpoint costs without a same-build control. Normal
daemon builds without `bench-internals` contain none of these capture fields
or callback clocks; a real-daemon receipt must retain its actual build features.

For correctness checks, `rrharness recovery-retirement
retirement-{full,empty,adj-out-full,adj-out-empty,regroup-full,regroup-empty}
full-uc|full-vpn|smoke-uc|smoke-vpn
--correctness-only` uses the same actor boundaries without reporting durations;
all duration fields, including readiness clocks, are null and no timing
qualification is made. Measured execution requires the hosted receipt
launcher. Capture instrumentation does not change readiness deadlines.

## Allocator

The harness links jemalloc as its global allocator, the same allocator the
daemon ships with, because the code it times and whose RSS it reports is the
daemon's own `RibManager` running in this process. Through v0.73.0 the
harness ran on glibc malloc, and so do the receipts listed under "Backs";
compare them with current runs only as cross-allocator observations, not as
same-build deltas.

## Build and run

Root-workspace member excluded from `default-members`; build it explicitly
with the profiling profile to retain folded-stack line tables:

```text
cargo build --profile scale --locked -p rrharness
./target/scale/rrharness <mode> <args...>
```

## Arg contract

Profiling and join modes (from `src/main.rs`):

```text
rrharness flood <n_clients> <n_prefixes> <secs> <out_prefix>
rrharness churn <n_clients> <n_cand> <n_prefixes> <secs> <out_prefix>
rrharness late-join <n_clients> <n_prefixes>
```

- `flood`: `n_clients` RR clients, inject `n_prefixes` distinct /24s, then run
  fresh-block injection for `secs` under the profiler. Folded output at
  `<out_prefix>.folded`.
- `churn`: prime `n_cand` candidate sources each announcing the full
  `n_prefixes` set, then run best-path flap waves (rotating winning source with
  escalating LOCAL_PREF) for `secs` under the profiler. Folded output at
  `<out_prefix>.folded`.
- `late-join`: start the real manager with no outbound peers, converge exactly
  `n_prefixes` routes in the Loc-RIB, snapshot process `VmRSS`, `VmSize`, and
  `VmHWM`, then register `n_clients` homogeneous route-reflector clients using
  the real fanout benchmark export encoder. It fails unless every client
  resolves to the same shared update group, every client reaches exactly
  `n_prefixes` staged Adj-RIB-Out routes, and the drain total reaches exactly
  `n_clients * n_prefixes`. Both arguments must be greater than zero.

The late-join wall time includes peer registration, update-group assignment,
manager staging and trivial channel draining. Its `/proc/self/status` snapshots
cover the whole rrharness process. It excludes TCP/session actors, UPDATE
final-envelope/output encoding in the transport actor, socket writers, kernel
socket buffers, and remote peer memory. Manager-side exact-export precommit
probing still uses the real fanout encoder and can prepare/build candidate
UPDATEs. The mode does not write a profile or make a capacity/performance
claim. Its convergence polling loops use a five-minute deadline while the
manager continues answering their query messages.

Receipt run shapes:

```text
rrharness flood 256  100000 20 flood-256-{a,b}
rrharness flood 1000 100000 20 flood-1000-{a,b}
rrharness churn 256  256  3000 20 churn-256-{a,b}
rrharness churn 1000 1000 3000 20 churn-1000-{a,b}
```

To A/B that matrix between two refs, use
[`../compare-rrharness.sh`](../compare-rrharness.sh). It builds base and
candidate in detached worktrees with the commit's release profiling profile
and `--locked` into
separate target directories, launches the prebuilt binaries directly on a
`taskset`-pinned performance-governor CPU behind the shared host lock, waits
for an idle host before every cell, and runs two counterbalanced repetitions
of every shape (repetition 1 base-first, repetition 2 head-first). The
rrharness tree must be identical at both refs — the instrument cannot be part
of the change.

```text
bench/scale/compare-rrharness.sh \
  --base origin/main \
  --head my-branch \
  --core 5 \
  --output-dir target/rrharness-compare/my-branch
```

Without `--pin` the receipt is advisory: `comparison.csv` has one row per
cell, `summary.csv` one row per rung (mean/min/max head-vs-base throughput
and a `noise` / `head-faster` / `head-slower` reading), and the manifest
records `"gates": "none"`. Two repetitions are a reading, not a verdict;
report every run.

`--pin FILE --diff-path PATH` is the opt-in exact form used for the original
grouped exact-export A/B: base and head must resolve to the pin's commits, the
normalized `base..head` diff of every `--diff-path` must hash to the pin's
digest, Cargo/toolchain inputs may not drift, and the pinned throughput gates
are applied. That campaign reproduces as:

```text
bench/scale/compare-rrharness.sh \
  --base b2ec55f21364978f26662b1ec35fd47ddcfce9a6 \
  --head ea579bea4ad6602dc719a1664441f04330c5ef64 \
  --pin bench/scale/rebaseline/lan395-run-pin.env \
  --diff-path crates/rib/src/manager/distribution/mod.rs \
  --core 5 \
  --output-dir target/rrharness-compare/reproduction
```

The companion parser and its adversarial tests live in
[`../rebaseline/parse_rrharness.py`](../rebaseline/parse_rrharness.py) and
[`../rebaseline/test_parse_rrharness.py`](../rebaseline/test_parse_rrharness.py);
`bench/tests/test-rrharness-driver.sh` covers the driver's refusals.

A tiny smoke shape (`flood 4 100 2 /tmp/smoke`) runs in a couple of seconds and
emits a folded profile.

A tiny late-join smoke shape exercises the staged/drained parity contract
without producing a retained measurement:

```text
rrharness late-join 2 100
```

The manager busy fraction uses the host's checked `sysconf(_SC_CLK_TCK)` value
and treats malformed or unreadable `/proc/self/task/<tid>/stat` data as an
error. It never substitutes a guessed tick rate or a zero CPU sample.

## Recovery memory receipt

`recovery-memory` measures manager-direct RIB recovery with four consumer runtime
workers and the dedicated manager thread. It emits no profiler, RSS, elapsed-time
or throughput result. Each profile has one registered source and homogeneous
plain RR clients in one shared group:

| Profile | Seed routes per receiver | Qualified receivers | Cells |
| --- | --- | --- | --- |
| `ipv4-100k` | 100,000 IPv4 unicast | 256 | reevaluation, source down |
| `full-uc` | 1,000,000 IPv4 + 230,000 IPv6 unicast | 100 | reevaluation, source down |
| `full-vpn` | 1,000,000 VPNv4 + 230,000 VPNv6 | 100 | reevaluation, source down, widening |
| `mixed-widen` | the `full-uc` seed, plus initially empty VPN families | 100 | widening only |

The original IPv4 and full unicast cells retain their ordinary family profile.
The mixed widening case proves new VPN admission during unicast recovery; it
**does not prove pure unicast churn**. VPN inventory alternates two legal raw RD
encodings that display as `65000:100` but identify different routes. Consumers
fold AFI, SAFI, canonical prefix/address/length, path ID and raw RD. They separately
check the expected label, attributes, route source and next hop, and reject
unknown or repeated exact-key withdrawals. Initial population can retry
announcements after bounded-queue deferral; actual announcement counts are kept.

Eight-slot outbound queues and fixed receiver bitmaps are charged to the scope.
At the original shape the bitmap occupies 12,504 bytes per receiver; the mixed
IPv4/IPv6 seed occupies 153,752 bytes. No per-receiver route map is added by the
harness. The source has an empty separate non-client profile.

Each cell drains and acknowledges every receiver, pauses consumption, and fills
all queues with empty envelopes. Reevaluation invokes the production
`ReevaluatePeerExportPolicies` path with unchanged eligibility. Source removal
sends the real generation-matched `PeerDown`. Both require observed dirty-peer
and group-dirty counts equal to the whole cohort. Actor FIFO query barriers and
receiver folds prove settlement, with family-specific BMP counts including VPN.
No unicast-only Loc-RIB count is used as proof for VPN.

Widening first establishes that same dirty seed boundary. A feature-only actor
transaction grants exactly one owned filler credit per receiver, then invokes
the existing `VpnRoutesReceived` handler before a retry timer can consume it.
It admits 100,000 new VPNv4 and 23,000 new VPNv6 keys. In `full-vpn` these extend
the VPN table; in `mixed-widen` they introduce the previously empty VPN families.
All receivers must remain dirty, and the candidate retained-key gauge must equal
`receivers × (seed + new keys)` behind that synchronous admission barrier.
Paused consumer folds still represent the seed; they are never presented as the
new admitted projection. After release, every receiver must fold the complete
expanded inventory. This exercises sparse **admitted** additions rather than
only pending desired routes.

Unchanged-policy reevaluation and widening require zero withdrawals throughout.
A withdrawal/reannouncement flap fails even when the final bitmap is full.
Source removal requires exactly one withdrawal per admitted key and an empty
final inventory in every family. Settlement also requires zero dirty/recovery
residue and matching operator projections. The finite 30-minute cell deadline
is a failure bound, not a timing result; query and drain barriers establish
completion.

The hosted-only driver
[`../compare-recovery-memory.sh`](../compare-recovery-memory.sh) builds the
candidate commit's harness and feature-only instrumentation on three source revisions:
`c862af9338aa828b7462f3cf85781f63b0e79fe8`, the intermediate refusal control
`bdb7bc34dfe0e6a66fc8c0f1d56d3e57184dea00`, and the exact candidate SHA. It
validates the unchanged observer bodies and atomic-credit seam, retains each
role's instrumentation patch, preserves manifests/lockfiles/pins, and builds serially with locked
`scale` settings, four jobs and separate targets. Each selected profile/cell
runs A/B/B/A separately against each historical control.

The default `--phase pilot` uses **four full-table receivers** for feasibility
only; it makes no 100-member qualification claim. An explicit
`--phase qualified` selects the qualified cohort sizes. `--profile PROFILE`
can limit a fresh VM to one profile. The dispatch-only job runs on a fresh
hosted `ubuntu-24.04` VM, only on `fix/update-group-recovery-memory`. Its reviewed
`RECOVERY_MEMORY_PHASE` and `RECOVERY_MEMORY_PROFILE` values select the campaign;
manual main/release CI does not run it. For example, on that hosted VM:

```sh
bash bench/scale/compare-recovery-memory.sh --head "$GITHUB_SHA" \
  --output-dir "$RUNNER_TEMP/recovery-pilot" --phase pilot --profile full-vpn
```

The driver refuses dev/self-hosted environments and fails before building if
cgroup v2 peak accounting or the zero-swap fence is unavailable. Each leg uses
a fresh root-owned transient systemd scope. Measured mode verifies its own
unified cgroup membership before allocating inventory, records PID/start-time,
and embeds its original revision. The checker binds those values to the
recorded role source and the launched process. Raw
ownership samples cover only the Bash launcher, Python checker and Rust workload
before, during and after execution; foreign members, populated descendants and
reused scope/workload identities are refused. Actual swap must stay zero and
any cgroup or host OOM invalidates the campaign.

Whole-scope `memory.peak` in bytes is primary. Current/stat snapshots, charged
recovery gauges and fixed per-cause counters are retained at population,
retained, operation-end and settled barriers. Candidate qualification requires
all logical proofs at the selected shape and zero budget/proof fallbacks. The
old baseline has no recovery gauges; the intermediate full-table control must
show an actual refusal. Historical route/contract failures remain failed evidence
and do not stop later matched candidate legs. They suppress a comparison ratio;
no incomplete control is promoted to a valid memory comparison. Every
summarizer writes `comparison.json` with a `PASS`, `FAIL` or `INVALID` verdict
and a one-line reason; only `PASS` exits zero. A candidate failure is `FAIL`.
Missing accounting, bad identity, swap, OOM or a failed driver invocation is
`INVALID`, independently of the route checks; finalizing a failed invocation
keeps an existing `FAIL` reason and never keeps a `PASS`.

Artifacts contain source SHAs, instrumentation patches, commands, exits, logs
and raw ownership/cgroup samples, including failed legs.
Host memory is recorded after builds and before each leg; pre-build free memory
is not used as a workload headroom claim. Any available EVPN exhaustion counter
must stay zero; EVPN remains inactive here. Common proof fallback is not described
as a session reset. Byte gauges account requested capacity, not component RSS.
Settlement restores the population-ready empty-proof charge, including fixed
headers, while retaining peak charge. Phase peaks are monotonic; scope exit peak
must cover the pre-workload and every phase high-water mark.

This receipt covers the production RIB and exact-export preflight plus harness
consumers. It makes no full-daemon, TCP, final encoded-wire, socket-buffer or
full dataset-publication claim. Separate small transport correctness controls
are required; they do not expand this memory scope. Per-peer/daemon cap refusal
correctness remains covered by bounded RIB controls, not a cap increase or a
claim that one full-table shape exhausts both caps.

The checker and adversarial fixtures are
[`../recovery_memory.py`](../recovery_memory.py) and
[`../test_recovery_memory.py`](../test_recovery_memory.py). Tiny correctness-only
runs skip **all** memory and `/proc` reads:

```text
rrharness recovery-memory dataset-reevaluate 4 smoke-uc --correctness-only
rrharness recovery-memory peer-down 4 smoke-vpn --correctness-only
rrharness recovery-memory widen 4 smoke-mixed --correctness-only
rrharness recovery-memory widen 4 smoke-vpn --correctness-only
```
