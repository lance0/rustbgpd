# Grouped outbound prefix-limit admission compaction receipt — 2026-07

This immediate-parent A/B measures the live memory required
to materialize ADR-0113's exact per-member admitted-prefix sets for grouped
peers. The candidate keeps the exact semantics but stores IPv4 and IPv6
prefixes in family-typed sets rather than retaining the larger `Prefix` enum
in each family's set.

## Pinned revisions and shape

The parent is `c2ff317cc5480bfa7fab16ec447fefe4e2469478` (tree
`f782216dfb1b75fd5f579ffb0e44632f08e01479`). The candidate is its literal
first child, `3952d1538530f887f5a0286248e630ba9bcc7673` (tree
`5b3208444d23c1fd6c4e15c011bb447d063ecccf`). Both revisions contain the
identical fixed-shape harness tree
`d91c5049930ed651da92508375c9fde71c8e629e`; only the candidate's production
and unit-test implementation differs.

Each release-daemon cell used:

- one private route-server-client source;
- 400,000 unique IPv4 unicast `/32`s, followed by a 64-route withheld tail;
- 1, 10, or 100 homogeneous limited members in exactly one update group;
- no Add-Path; and
- a finite `max_prefixes_out_ipv4 = 400000` applied after unlimited
  convergence, followed by limit removal and full recovery.

The adjacent pairs alternated order: parent/candidate at one member,
candidate/parent at ten, then parent/candidate at 100.

## Correctness receipt

All six cells passed, with identical parent/candidate check inventories at
each fleet size: 67, 427, and 4,027 checks per cell, or 9,042 checks total with
zero failures. The harness pinned:

- one update group containing exactly every requested member, with only the
  source on the private fallback;
- 400,000 unique wire-visible prefixes per member after the limit was applied;
- exactly 64 blocked attempts per member, the finite limit, and the blocking
  latch on production metrics;
- one apply histogram sample and exactly one recovery sample per member;
- all 400,064 prefixes delivered after limit removal; and
- zero withdrawals, unexpected NLRI, decode errors, session flaps, or
  limit-only peer deletion.

Every generated configuration was valid. Its only warnings were the expected
permit-all route-server warnings for the source plus every member: 2, 11, or
101 neighbors depending on fleet size. The receipt does not reinterpret those
warnings as a clean production configuration.

## Allocated-memory gate

The predeclared gate compares the change in the production
`jemalloc_allocated_bytes` gauge between the settled unlimited baseline and
the settled finite-limit snapshot:

```text
candidate apply allocated delta <= 50% of parent apply allocated delta
```

| Members | Parent allocated delta | Candidate allocated delta | Candidate / parent | Reduction | Gate |
|---:|---:|---:|---:|---:|:---:|
| 1 | 10,059,664 B | 3,161,832 B | 31.430791% | 68.569209% | PASS |
| 10 | 99,983,496 B | 31,500,344 B | 31.505544% | 68.494456% | PASS |
| 100 | 997,022,824 B | 315,423,808 B | 31.636568% | 68.363432% | PASS |

Across the measured points, the candidate therefore uses about 3.15 MB of
additional live allocated memory per member, versus about 9.97–10.06 MB for
the parent. The ratio is stable across the measured range, but this one
campaign does not license extrapolation beyond 100 members or 400,000 IPv4
routes.

## Memory surfaces and claim boundary

Only the allocated delta above gates acceptance. The other apply-boundary
measurements are retained as diagnostics:

| Members | Active delta, parent → candidate | Resident delta, parent → candidate | Point RSS delta, parent → candidate |
|---:|---:|---:|---:|
| 1 | 10,059,776 → 3,174,400 B | 8,175,616 → 139,264 B | 7,560 → 1,000 KiB |
| 10 | 100,159,488 → 31,444,992 B | 102,481,920 → 8,638,464 B | 99,944 → 7,320 KiB |
| 100 | 997,560,320 → 316,100,608 B | 1,034,309,632 → 321,777,664 B | 959,044 → 272,128 KiB |

These surfaces are deliberately distinct:

- `allocated` is jemalloc's live application allocation gauge;
- `active` is allocator pages in active extents;
- `resident` is jemalloc's resident-page accounting;
- `VmRSS` is the kernel's point-in-time process resident set; and
- the independent one-second sampler records separate RSS and HWM maxima.

This campaign did not run DHAT or another ownership/lifetime profiler and did
not collect a jemalloc retained-extent metric. It therefore does **not** claim
an exact object-owned retained-heap reduction. Concurrent allocator page
decay is visible in the active/resident/RSS boundaries, which is why none of
those report-only values is substituted for the allocated gate.

The candidate's apply actor observations were 0.012111130, 0.148598562, and
1.523071596 seconds, versus 0.020562114, 0.222357119, and 2.064777307 seconds
for the parent. Recovery actor work and wall time are retained only as single
observations. With one cell per revision and fleet size, this receipt makes no
timing or variance claim.

## Limits, reproduction, and artifacts

The result covers one Linux host, one IPv4-unicast table, a homogeneous
single-group fleet, and one run per revision/size. It does not cover IPv6,
Add-Path, heterogeneous groups, multiple simultaneous families, run-to-run
variance, or object-level heap attribution. The sampled 100-member candidate
also recorded a maximum point RSS slightly above its sampled HWM, reinforcing
that kernel HWM is diagnostic rather than an acceptance source.

To regenerate this exact literal-parent A/B, check out candidate commit
`3952d1538530f887f5a0286248e630ba9bcc7673` in a clean worktree, then run:

```text
bench/scale/outbound-prefix-limit-scale/run-receipt.sh
```

Raw configs, logs, Prometheus scrapes, process snapshots, IDs, timestamps,
host identity, and paths remain private under `target/`. The compact sanitized
provenance, exact summaries, independently derived memory boundaries, behavior
counts, binary identities, and checksums are retained in
[`artifacts/outbound-prefix-limit-admission-compaction-2026-07/`](artifacts/outbound-prefix-limit-admission-compaction-2026-07/README.md).
