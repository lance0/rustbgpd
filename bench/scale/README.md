# bench/scale

Scale/perf harnesses that back the published perf receipts in `docs/perf/`.

The harness crates are members of a dedicated workspace rooted at
[`Cargo.toml`](Cargo.toml) with one shared [`Cargo.lock`](Cargo.lock),
deliberately kept **out of** the root workspace so normal
`cargo build --workspace` does not build them. CI compiles and tests each
crate explicitly so API drift cannot leave a receipt harness broken on
`main`. Binaries land in `bench/scale/target/`.

Release-time lockfile refresh (syncs the path-dep versions after a
workspace version bump) is one command:

```text
cargo update --workspace --manifest-path bench/scale/Cargo.toml
```

| Harness | Measures | Backs |
|---|---|---|
| [`rrharness/`](rrharness/) | RibManager flood/churn CPU + memory profiling (manager task in isolation, folded-stack output) | `docs/perf/rebaseline-2026-07.md`, LAN-348 re-profile |
| [`rrtransport/`](rrtransport/) | Fixed real-transport RR correctness smoke plus a gated 1,000-peer × 100,000-route measurement instrument with exact staged/wire classification | CI foundation and LAN-694 measurement campaign; no published claim yet |
| [`reloadstall/`](reloadstall/) | Policy-reload UPDATE-stall at route-server scale (real BGP stub clients vs a running daemon) | `docs/perf/reload-stall-2026-07.md` (LAN-333) |
| [`matrix/`](matrix/) | Sequential same-host rustbgpd, BIRD, and OpenBGPD reload-stall comparison driver | `docs/perf/ixp-matrix-2026-07.md` |
| [`enhanced-route-refresh/`](enhanced-route-refresh/) | Real-session one-peer × 100,000-prefix RFC 7313 inventory and memory receipt | `docs/perf/enhanced-route-refresh-2026-07.md` |
| [`irrreload/`](irrreload/) | Full IRR-policy reload matrix plus a two-run, one-collector RFC 9069 dump/live-buffer boundary receipt | IRR reload evidence and BMP Loc-RIB buffer measurement; no general capacity claim |
| [`route-server-1000/`](route-server-1000/) | Fixed-shape 1,000-peer rustbgpd route-server retained receipt driver | LAN-508 ([retained receipt](../../docs/perf/route-server-1000-2026-07.md)) |

Build (from repo root; binaries land in `bench/scale/target/release/`):

```text
cargo build --release --manifest-path bench/scale/rrharness/Cargo.toml
cargo build --release --manifest-path bench/scale/reloadstall/Cargo.toml
```

See each harness's `README.md` for its arg contract and run shapes.

These are deliberate manual performance harnesses: CI compiles, lints, and
unit-tests every member (and executes only the `rrtransport` smoke tripwire),
but the measured runs are operator-initiated. The retired
`outbound-prefix-limits`, `config-persistence`, and
`outbound-prefix-limit-scale` members live on as workspace integration tests
(`tests/outbound_prefix_limits.rs`, `tests/config_persistence_lifecycle.rs`)
or as archive pointers in their sealed receipts under `docs/perf/`.

The deterministic CPU and DHAT classifiers, fixtures, and revision-pinned
receipt procedure live in [`rebaseline/`](rebaseline/).
