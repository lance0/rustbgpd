# rrharness

RibManager flood/churn CPU + memory profiling and late-client-join measurement
harness.

## What it measures

Drives the real `RibManager` run loop directly (no TCP/transport) on a
dedicated OS thread named `ribmgr` under a current-thread tokio runtime, with N
registered route-reflector-client outbound peers whose bounded channels are
drained by trivial consumer tasks. Route injection is via
`RibUpdate::RoutesReceived`; the staged Adj-RIB-Out is polled via
`RibUpdate::QueryAdjRibOutCounts`. Every synthetic session stages the same
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

## Build and run

Standalone crate (not a workspace member — build it explicitly):

```text
cd bench/scale/rrharness
cargo build --release
./target/release/rrharness <mode> <args...>
```

## Arg contract

Three modes (from `src/main.rs`):

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

For the pinned LAN-395 A/B campaign, use
[`../compare-rrharness.sh`](../compare-rrharness.sh). It builds the exact base
and candidate in detached worktrees, launches prebuilt binaries directly on a
performance-governor CPU, counterbalances two repetitions of every shape, and
refuses to complete a receipt unless every log/profile parses and every
throughput gate passes. The companion parser and its adversarial tests live in
[`../rebaseline/parse_rrharness.py`](../rebaseline/parse_rrharness.py) and
[`../rebaseline/test_parse_rrharness.py`](../rebaseline/test_parse_rrharness.py).
Retained runs must execute from the canonical driver in a clean pin commit;
that commit may add only `lan395-run-pin.env` over the reviewed tooling parent.
This binds the driver, parser, classifier, production refs, and normalized
production diff before the shared host lock or any build begins.

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
