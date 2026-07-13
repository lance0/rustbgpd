# Revision-reproducible RIB rebaseline — 2026-07-13

This receipt replaces the non-reproducible tables in
[`rebaseline-2026-07.md`](rebaseline-2026-07.md). The daemon-facing harness,
the exact production export encoder, the classifiers, and the measured code all
come from clean source `4800061b178a84a7b62c74bf0b6a71c4e413b8f2`, whose parent
is main merge `a7ab255211d9055706736cb07e9131f2986ba101`.

The complete retained evidence is in
[`artifacts/rib-rebaseline-2026-07-13/`](artifacts/rib-rebaseline-2026-07-13/).
Every loaded run acquired the shared host lock, started with the one-minute load
average below 2.0, found no concurrent Cargo/Rust compiler/rrharness process,
and ran with the CPU governor set to `performance`.

## Manager-task CPU

The standalone rrharness runs the real `RibManager` on its own OS thread,
installs the production exact export encoder, drains outbound channels on a
separate runtime, and samples only the manager thread at 997 Hz. Each shape ran
twice; both runs are shown.

| Shape | Delivered throughput (A / B) | Manager busy (A / B) | `distribute_changes` residual (A / B) |
|---|---:|---:|---:|
| flood 256 clients x 100k routes | 0.566 / 0.559 blocks/s | 0.999 / 0.998 | 88.40% / 88.28% |
| flood 1000 clients x 100k routes | 0.161 / 0.160 blocks/s | 1.000 / 0.999 | 96.54% / 96.58% |
| churn 256 clients x 256 candidates x 3000 prefixes | 9.43 / 9.47 waves/s | 0.969 / 0.965 | 95.01% / 94.74% |
| churn 1000 clients x 1000 candidates x 3000 prefixes | 2.39 / 2.36 waves/s | 0.994 / 0.993 | 89.79% / 89.71% |

The exact phase rows and integer sample counts are the eight retained
`*.cpu.tsv` files. The most important result is diagnostic: once the harness
uses the mandatory production encoder, the historical `member-emit` marker no
longer describes the common grouped path. That path remains inside
`distribute_changes`, so the old “29.4% Arc clone + try_send tail” attribution
is not valid on current code. Raw-stack inspection shows exact message
construction is a low-single-digit bucket; successful rejection-overlay and
prior-advertisement bookkeeping are the next measured target. LAN-395 records
the bounded fast-path experiment and a 15% pre-committed gate. LAN-348 was
canceled by its own gate rather than adding an actor boundary around the wrong
work.

The large throughput difference from the historical July table is not a
regression introduced by this receipt. The older harness did not install the
production exact encoder and therefore omitted the fail-closed export
precommit that shipped in PR #858. This receipt is the first like-for-like
baseline for future exact-export optimization.

## Full-daemon live heap at peak

The same clean source was built in a no-cache DHAT image by pinned bgperf2
revision `fe4fdab9f7efb56e2e98ad6e6bcffeda047761a9`. The image digest is
`sha256:7da0b34b0327dbc153061bf3785313478f13ef88520e56ecc197cddd6a3b4002`;
its Rust and Debian bases, locked build, toolchain, package inventories, and OCI
source labels are retained.

The exact 2 peers x 100k run converged 200,000 / 200,000 routes in 16 seconds,
reported zero tester errors, and reached 0.238 GB maximum RSS under DHAT
instrumentation. The two actual BIRD logs were copied before SIGTERM and have
zero `RMT` records after the pinned `NEXT_HOP` exclusion. bgperf2's BIRD timeout
column is structurally zero, so this receipt does not claim an independently
measured tester-timeout count. After convergence, SIGTERM flushed the same process's
heap profile. The deterministic derivative accounts for 210,338,877 bytes
live at the process-wide heap maximum:

| Component | Bytes | Share |
|---|---:|---:|
| Group RIB-Out table | 46,399,748 | 22.06% |
| Loc-RIB best-path map | 44,302,352 | 21.06% |
| Adj-RIB-In route storage | 33,556,528 | 15.95% |
| Adj-RIB-In + group prefix tries | 34,435,264 | 16.37% |
| Transport known-path memory | 15,204,416 | 7.23% |
| Announcing-peers index | 14,942,224 | 7.10% |
| Transport import-decision cache | 5,002,096 | 2.38% |
| Daemon core | 4,632,060 | 2.20% |
| Transport session buffers/scratch | 3,236,991 | 1.54% |
| Telemetry / tokio / rest | 5,329,665 | 2.53% |
| API / peer-manager | 2,521,505 | 1.20% |
| RIB other + unclassified | 677,340 | 0.32% |
| Per-peer Adj-RIB-Out | 98,688 | 0.05% |

The update-group result remains clear: per-peer Adj-RIB-Out is effectively
gone for grouped peers. Current memory work should target the shared group
table, Loc-RIB, Adj-RIB-In, their tries, the announcing-peers index, and
transport known-path state. The exact numbers above supersede the older 69.8
MiB group-table / 218.5 MiB total capture.

## Reproduction and limitations

[`manifest.json`](artifacts/rib-rebaseline-2026-07-13/manifest.json) records
every concrete run argv, UTC start, load value, compiler/lock/classifier hash,
image/base digest, config, and source identity. The artifact README contains
the offline verification commands.

- CPU shares are statistical pprof samples; the retained A/B runs are the
  error bar. Absolute rates remain host-specific.
- The memory attribution is one structural capture at an exact route count;
  the sanitized derivative is lossless for component classification but omits
  raw addresses, paths, and source locations.
- The current CPU classifier intentionally reports exact-precommit work as
  `distribute residual` rather than inventing attribution from unstable closure
  numbers. LAN-395 requires stable named helpers and classifier fixtures before
  publishing a finer phase split.
- The bgperf2 run is a DHAT-instrumented receipt for attribution, not a release
  performance comparison against BIRD or GoBGP.
