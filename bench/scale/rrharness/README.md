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

`recovery-memory` is a separate memory-only mode with four consumer runtime
workers and the dedicated manager thread. It has no profiler, RSS, elapsed-time
or throughput output:

```text
rrharness recovery-memory dataset-reevaluate 256 100000
rrharness recovery-memory peer-down 256 100000
```

One source originates 100,000 routes to 256 homogeneous plain RR clients in
one shared group. The registered non-client source has an empty separate
profile. Eight-slot outbound queues and compact, fixed receiver bitmaps are
included in the measured scope; each receiver bitmap occupies 12,504 bytes
at this shape. The consumers apply frozen source exclusions and reject unknown
or repeated withdrawals of exact prefix/path keys. Initial population may
retry announcements after bounded-queue deferral; the receipt records their
actual count.

Both cells drain, pause and acknowledge every receiver, then fill its queue
with empty envelopes. The first drives production
`ReevaluatePeerExportPolicies` for the shared client group; it does not drive
the full dataset publication coordinator. The second sends the registered
source's actual generation-matched `PeerDown` and confirms an empty Loc-RIB.
Both require the actor's observed dirty-peer and group-dirty counts to equal
the full receiver cohort before recording retained and operation-end samples.
Consumers resume afterward. Settlement requires zero outbound recovery
residue, matching advertised counts and exact folded receiver inventories;
source removal additionally requires exactly 100,000 withdrawals per client.
Actor query and receiver drain barriers establish completion, with a finite
deadline for failure rather than a fixed sleep as proof.

The hosted-only driver
[`../compare-recovery-memory.sh`](../compare-recovery-memory.sh) freezes the
committed harness source and minimally broadens two existing observer cfg gates
on both `c862af9338aa828b7462f3cf85781f63b0e79fe8` and the exact candidate SHA.
It verifies the unchanged observer bodies, retains the instrumentation and
patches, preserves each revision's lockfile/pins, and builds serially with the
`scale` profile, locked dependencies, four build jobs and separate targets.
Each cell runs in A/B/B/A order in fresh root-owned transient systemd scopes.

The dispatch-only `recovery_memory_receipt` CI job runs on a fresh hosted
`ubuntu-24.04` VM **only when explicitly dispatching
`fix/update-group-recovery-bounds`**. Manual main or release CI does not run
the campaign. The driver refuses dev/self-hosted environments and fails before
building if cgroup v2 peak accounting or the zero-swap fence is unavailable.
Measured mode also verifies its own unified cgroup membership and records
PID/start-time identity before allocating the RIB or receiver inventory.
The binary embeds its original revision and instrumentation digest; the
checker matches those identities and the running `/proc/PID/exe` digest to
the recorded build. Raw ownership samples cover the scoped Bash launcher,
Python checker and Rust workload before, during and after the workload, with
foreign members and populated descendant cgroups refused. Every leg requires
a distinct scope and workload identity.
Primary evidence is whole-scope `memory.peak` in bytes, with current/stat
snapshots at population, retained, operation-end and settled barriers; actual
swap must remain zero and any cgroup or host OOM invalidates the campaign.

Artifacts retain source and binary hashes, toolchain/build inputs, commands,
exits, logs, raw cgroup files, phase gauges and per-cause fallback counts.
Candidate recovery gauges are required; their baseline absence is recorded
explicitly. Any available EVPN provenance-exhaustion counter is recorded as
inactive/zero: this plain RR receipt does not exercise EVPN or imply that the
common fallback resets sessions. Recovery-byte gauges are reservation charges,
not a component attribution of RSS. The same fixed launcher and consumer
overhead are charged to both revisions. The comparison has no timing verdict
or automatic capacity threshold and is not a full-daemon, TCP, socket-buffer,
dataset-publication or final transport-writer receipt.
Settlement restores the population-ready empty-proof reservation charge,
including the fixed ledger header, and retains the peak charge. Cgroup phase
peaks must be monotonic, and the end snapshot must cover the pre-workload and
all phase high-water marks.

The checker and adversarial fixtures are
[`../recovery_memory.py`](../recovery_memory.py) and
[`../test_recovery_memory.py`](../test_recovery_memory.py). A local, tiny
correctness exercise skips all memory and `/proc` reads:

```text
rrharness recovery-memory dataset-reevaluate 4 200 --correctness-only
rrharness recovery-memory peer-down 4 200 --correctness-only
```
