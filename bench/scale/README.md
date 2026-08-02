# bench/scale

Scale/perf harnesses that back the published perf receipts in `docs/perf/`.

Each is a standalone crate with its own empty `[workspace]` table, deliberately
kept **out of** the root workspace so normal `cargo build --workspace` does not
build it. CI compiles and tests each crate explicitly so API drift cannot leave
a receipt harness broken on `main`.

| Harness | Measures | Backs |
|---|---|---|
| [`rrharness/`](rrharness/) | RibManager flood/churn CPU + memory profiling (manager task in isolation, folded-stack output) | `docs/perf/rebaseline-2026-07.md`, LAN-348 re-profile |
| [`rrtransport/`](rrtransport/) | Fixed real-transport RR correctness smoke plus a gated 1,000-peer × 100,000-route measurement instrument with exact staged/wire classification | CI foundation and LAN-694 measurement campaign; no published claim yet |
| [`reloadstall/`](reloadstall/) | Policy-reload UPDATE-stall at route-server scale (real BGP stub clients vs a running daemon) | `docs/perf/reload-stall-2026-07.md` (LAN-333) |
| [`irrreload/`](irrreload/) | Full IRR-policy reload matrix plus a two-run, one-collector RFC 9069 dump/live-buffer boundary receipt | IRR reload evidence and BMP Loc-RIB buffer measurement; no general capacity claim |
| [`route-server-1000/`](route-server-1000/) | Fixed-shape 1,000-peer rustbgpd route-server retained receipt driver | LAN-508 ([retained receipt](../../docs/perf/route-server-1000-2026-07.md)) |
| [`outbound-prefix-limits/`](outbound-prefix-limits/) | ADR-0113 outbound unicast prefix maxima end to end: four real stub sessions against a real daemon, wire-side prefix counts under a cap, and the operator surfaces | [receipt](../../docs/perf/outbound-prefix-limits-2026-07.md) |
| [`config-persistence/`](config-persistence/) | Config persistence, applied-config history, `config rollback`, and the three commit-confirm outcomes end to end: three real stub sessions against a real daemon it restarts itself, plus an injected persistence rejection that must leave sessions, counters, and wire state unchanged | [receipt](../../docs/perf/config-persistence-2026-07.md) |

Build (from repo root):

```text
cd bench/scale/rrharness              && cargo build --release
cd bench/scale/reloadstall            && cargo build --release
cd bench/scale/outbound-prefix-limits && cargo build --release
cd bench/scale/config-persistence     && cargo build --release
```

See each harness's `README.md` for its arg contract and run shapes.

The deterministic CPU and DHAT classifiers, fixtures, and revision-pinned
receipt procedure live in [`rebaseline/`](rebaseline/).
