# Shared route-refresh replay A/B, 2026-10-11

Sharing replay work across already queued compatible refresh requests reduced
K=50 completion from 10.469–11.019 s to 0.257–0.295 s in a 200-peer IPv4 route
reflector with 400,000 prefixes. Matched round reductions were 97.24–97.55%.
K=1 also improved, while K=50 sampled RSS was higher by 3–19 MiB per matched
round. These are same-host results for the integrated candidate and this shape.

The [evidence bundle](artifacts/shared-route-refresh-2026-10-11/README.md)
retains all eight harness logs, quiet samples, integer clocks, paired results,
native exits and actual build-configuration comparison. There are **two fresh
processes per arm and K**, with three correlated rounds per process. Six rounds
are not six independent processes; no pooled significance estimate is reported.

## Sources and build equivalence

| Arm | Commit | Daemon SHA-256 |
|---|---|---|
| A: frozen main snapshot | `56cc5c4af5a607951915d175966de17241fca9a9` | `86180dd6501516d8a391fcae6100d4a811c25c64c71a04e7395b2a4f98c2ec11` |
| B: integrated shared-refresh candidate | `e623cb194475362c122ddbcb6505dca289556eea` | `d2e5a21b3c28a092f7080d4514c488c322cc3a91fb511789ed3d4c57f1372c79` |

B is a direct child of A and changes 11 files under the RIB, transport and
changelog directories. It includes lazy prior-state materialization, queued
refresh cohort admission and shared announcement encoding. This comparison does
not separate their individual contributions. Earlier lazy-prior measurements
used another base and remain separate evidence; subtracting their percentages
would not establish an incremental cohort benefit.

A and B were frozen once before the run. A subsequent documentation merge to
main is outside the comparison. This receipt identifies the measured source,
not an arbitrary later main or release.

The measured candidate passed `just gate` and `just gate-rib` before the builds,
including locked workspace tests, strict Clippy and rustdoc. The separate
[source validation record](artifacts/shared-route-refresh-2026-10-11/source-validation.json)
keeps those outcomes distinct from subsequent receipt-only changes.

Both ordinary daemons used `cargo build --release --locked -j 4 -p rustbgpd
-p rustbgpctl` with Rust 1.99.0 and Cargo 1.99.0. All 781 tracked Rust, protobuf,
manifest and lockfile inputs were refreshed before each serial build. The
normal artifact closure was captured before the next build touched the cache.
Both builds and the comparison exited zero:

- 227 normal artifact units per arm; 343 including build units.
- No missing or unmatched units, feature/configuration differences, or
  dependency-identity differences. Normal/build dependency resolution matched.
- Rust compiler, target, profile, flags and recorded build-script environment
  inputs matched. Neither daemon nor RIB enabled `bench-internals`.
- No Cargo manifest or lockfile difference. CLI binary bytes were identical.

These checks establish matching artifact configuration and dependency graphs;
they are not an independent proof of binary ABI equivalence. Binaries were
copied aside, made read-only and hash-checked before and after every cell.
Both arms used the same prebuilt `reloadstall` instrument at
`0fc491c61f77cfab0c04c125469aa714702ed8eb`, SHA-256
`045e1ae2ed431ed8f1d581a2f35323f3d6390ba8b6f3af36344c70b36318164e`.

## Shape and method

- 200 iBGP route-reflector clients in ASN 65000, 400,000 disjoint IPv4 prefixes,
  2,000 per client. Each receiver must hold exactly 398,000 prefixes after its
  own 2,000 are excluded.
- Plain ROUTE-REFRESH at K=1 and K=50, three rounds per process. Eight clients
  continuously churn a separate prefix block. No session flap or policy reload.
- Eight fresh-daemon cells in order A1/K1, B1/K1, B1/K50, A1/K50, A2/K50,
  B2/K50, B2/K1, A2/K1. Each retains a 30-second control and three-second hold.
- One continuous host lock, followed by the light-work lock, covered the
  campaign. Before every cell, two accepted quiet samples at least 30 seconds
  apart showed load below 2, all 64 CPU governors set to `performance`, no
  competing compiler or BGP daemon and no swap-counter drift.
- One AMD Ryzen Threadripper 7970X host. Daemon affinity was CPUs 12–32 and
  34–39; the harness used 40–63. No build ran during measurement.

The campaign held its locks from 07:17:20 to 07:30:48 UTC on 2026-10-11.
Every cell used the same scenario generator, deadlines and instrument bytes.
The first native failure would stop the remaining cells; all eight succeeded.

**Completion clock.** For each requester, duration starts at its refresh-write
completion and ends at the later of exact-table coverage and fresh End-of-RIB.
The table below reports the slowest requester in each round, recomputed from
integer microsecond clocks. These are harness timestamps after frame decoding,
not packet-capture or forwarding timestamps. Queue-attempt, write, first-base,
exact-table and End-of-RIB timestamps for every requester remain in the evidence.

**Readiness.** The instrument polls `/readyz` during refresh with a 250 ms
response deadline. Archived request/response timestamps establish actual overlap
with the measured refresh windows; sample counts alone do not establish that.

## Results

All entries are seconds; each row retains its three rounds in order.

| Process | K | Round 1 | Round 2 | Round 3 |
|---|---:|---:|---:|---:|
| A1 | 1 | 0.273813 | 0.278805 | 0.277969 |
| B1 | 1 | 0.181949 | 0.176011 | 0.176783 |
| B2 | 1 | 0.173928 | 0.176859 | 0.176957 |
| A2 | 1 | 0.276926 | 0.279869 | 0.272848 |
| A1 | 50 | 10.502650 | 10.713639 | 10.642578 |
| B1 | 50 | 0.256899 | 0.295358 | 0.292409 |
| B2 | 50 | 0.279824 | 0.259602 | 0.291327 |
| A2 | 50 | 10.629680 | 10.468741 | 11.019455 |

| K | Matched B1/A1 ratios, rounds 1–3 | Matched B2/A2 ratios, rounds 1–3 |
|---|---|---|
| 1 | 0.664501, 0.631305, 0.635981 | 0.628067, 0.631935, 0.648555 |
| 50 | 0.024460, 0.027568, 0.027475 | 0.026325, 0.024798, 0.026438 |

K=50 saved 10.209–10.728 s per matched round. Its candidate and baseline ranges
are disjoint, as are K=1's. Within each process, K=50/K=1 completion ratios were
1.412–1.678 for B and 37.406–40.387 for A. This supports removing the dominant
per-request serialization on this homogeneous shape; it does not establish a
K-independent bound.

## Validity, responsiveness and memory

All 24 rounds had 200 sessions up, zero parse errors, exact 398,000-prefix
coverage and fresh End-of-RIB for every requester. All initial 200-receiver
bitmaps were exact. All native campaign, cell, harness, daemon and metrics exits
were zero; no forced kill occurred. The owner, child processes and temporary
scenarios were reaped or removed before acceptance validation. The unchanged
acceptance validator and frozen input-integrity checks passed.

| Observation | A | B |
|---|---|---|
| K=1 survivor maximum update-gap range | 216.630–225.051 ms | 115.487–123.871 ms |
| K=50 survivor maximum update-gap range | 10.454–10.971 s | 185.037–215.790 ms |
| K=1 round-end daemon RSS | 312–316 MiB | 311–318 MiB |
| K=50 round-end daemon RSS | 313–319 MiB | 321–332 MiB |

**Memory cost.** B's K=50 RSS samples were 3–19 MiB above the corresponding A
rounds. They are daemon `VmRSS` at round end, not peak RSS, allocator accounting
or whole-cgroup memory. This receipt does not establish a peak-memory bound.

**Control outlier.** B1/K1's control maximum update gap was 65.86 ms; all other
cells' control maxima were 41.27–42.04 ms. It is retained as contrary evidence
and is not attributed to the candidate from one process.

**Sampled readiness.** All 85 samples succeeded, with a longest response of
31.376 ms. Every K=1 round and every B/K=50 round had one sample; A/K=50 had
11, 11, 11 samples in A1 and 11, 11, 12 in A2. Each requester's write-to-complete
window overlapped at least one successful readiness request/response interval.
This is evidence of sampled responsiveness, not continuous readiness or a
failure-rate estimate. Fewer samples on B follow its shorter refresh window.

## Limits

This is one homogeneous IPv4 route-reflector shape on one host, measured with
two fresh processes per arm and K. It does not qualify mixed policy or wire
profiles, Add-Path, other families, larger K, policy reload, reconnect behavior,
end-to-end forwarding, or another daemon. Shared-refresh fallback and terminal
ordering have separate correctness tests; they are not additional measured
shapes in this receipt.
