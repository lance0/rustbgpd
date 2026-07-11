# rrharness

RibManager flood/churn CPU + memory profiling harness.

## What it measures

Drives the real `RibManager` run loop directly (no TCP/transport) on a
dedicated OS thread named `ribmgr` under a current-thread tokio runtime, with N
registered route-reflector-client outbound peers whose bounded channels are
drained by trivial consumer tasks. Route injection is via
`RibUpdate::RoutesReceived`; the staged Adj-RIB-Out is polled via
`RibUpdate::QueryAdjRibOutCounts`. Because the manager task is alone on its
thread, every profiler sample on `ribmgr` is manager-task work — no bucketing.

Per run it reports RSS at each phase, cold stage/drain times, sustained
throughput (blocks or waves) over a profiled window, the manager thread's
CPU-seconds and busy fraction, and writes a folded-stack profile to
`<out>.folded` (Brendan-Gregg format: `thread<TAB>frame;frame;...<TAB>count`).
Classify the folded output by the owning-function markers listed in Part 1 of
the receipt.

Because the harness reaches into `RibManager` internals, it must be kept
compiling against `crates/rib`, `crates/wire`, and `crates/telemetry` on `main`.

## Backs

- `docs/perf/rebaseline-2026-07.md` (ADR-0100 slice-0 manager-task phase table
  and whole-process RSS snapshots). This harness reports process RSS from
  `/proc` only; the per-component live-heap attribution table in that receipt
  is produced by the separate dhat/bgperf2 pass, not this harness.
- The 2026-07-10 re-profile that produced LAN-348.

## Build and run

Standalone crate (not a workspace member — build it explicitly):

```text
cd bench/scale/rrharness
cargo build --release
./target/release/rrharness <mode> <args...>
```

## Arg contract

Two modes (from `src/main.rs`):

```text
rrharness flood <n_clients> <n_prefixes> <secs> <out_prefix>
rrharness churn <n_clients> <n_cand> <n_prefixes> <secs> <out_prefix>
```

- `flood`: `n_clients` RR clients, inject `n_prefixes` distinct /24s, then run
  fresh-block injection for `secs` under the profiler. Folded output at
  `<out_prefix>.folded`.
- `churn`: prime `n_cand` candidate sources each announcing the full
  `n_prefixes` set, then run best-path flap waves (rotating winning source with
  escalating LOCAL_PREF) for `secs` under the profiler. Folded output at
  `<out_prefix>.folded`.

Receipt run shapes:

```text
rrharness flood 256  100000 20 flood-256-{a,b}
rrharness flood 1000 100000 20 flood-1000-{a,b}
rrharness churn 256  256  3000 20 churn-256-{a,b}
rrharness churn 1000 1000 3000 20 churn-1000-{a,b}
```

A tiny smoke shape (`flood 4 100 2 /tmp/smoke`) runs in a couple of seconds and
emits a folded profile.
