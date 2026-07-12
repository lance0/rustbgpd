# bench/scale

Scale/perf harnesses that back the published perf receipts in `docs/perf/`.

Each is a standalone crate with its own empty `[workspace]` table, deliberately
kept **out of** the root workspace so normal `cargo build --workspace` does not
build it. CI compiles and tests each crate explicitly so API drift cannot leave
a receipt harness broken on `main`.

| Harness | Measures | Backs |
|---|---|---|
| [`rrharness/`](rrharness/) | RibManager flood/churn CPU + memory profiling (manager task in isolation, folded-stack output) | `docs/perf/rebaseline-2026-07.md`, LAN-348 re-profile |
| [`reloadstall/`](reloadstall/) | Policy-reload UPDATE-stall at route-server scale (real BGP stub clients vs a running daemon) | `docs/perf/reload-stall-2026-07.md` (LAN-333) |

Build (from repo root):

```text
cd bench/scale/rrharness   && cargo build --release
cd bench/scale/reloadstall && cargo build --release
```

See each harness's `README.md` for its arg contract and run shapes.

The deterministic CPU and DHAT classifiers, fixtures, and revision-pinned
receipt procedure live in [`rebaseline/`](rebaseline/).
