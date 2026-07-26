# Grouped private Adj-RIB-Out late-join receipt

Status: **accepted for the fresh grouped-join allocation claim**.

## Result

A grouped peer joining a converged one-million-route `RibManager` used to
request a second one-million-slot private unicast `RouteSlab`, even though its
unicast advertised state is owned by the shared update group. Installing the
peer's private multi-family table with zero unicast capacity at the group
membership seam removes that request without changing the shared table or
non-unicast state.

The retained A/B/B/A campaign measured one and eight homogeneous RR clients
joining after one million routes had converged:

| Late join shape | Control `VmSize` growth | Candidate `VmSize` growth | Difference | Control/candidate `VmRSS` growth |
|---|---:|---:|---:|---:|
| 1 client × 1,000,000 routes | 375,012 KiB | 250,008 KiB | **−125,004 KiB (−33.33%)** | 264,076 / 264,054 KiB mean |
| 8 clients × 1,000,000 routes | 1,315,576 KiB | 315,544 KiB | **−1,000,032 KiB (−76.01%)** | 312,224 / 311,930 KiB mean |

Both repetitions produced the exact same `VmSize` growth within each
variant. The harness reports a 128-byte `Option<Route>` slot, so the observed
difference is the allocator equation, including one 4 KiB mapping overhead per
peer:

```text
1 peer  × ((1,000,000 × 128 bytes) / 1024 + 4 KiB) =   125,004 KiB
8 peers × ((1,000,000 × 128 bytes) / 1024 + 4 KiB) = 1,000,032 KiB
```

This is a virtual allocation/capacity win, **not a retained-RSS headline**.
The unused private slabs were never touched, so the one-client mean `VmRSS`
growth changed by only 22 KiB and the eight-client mean by 294 KiB (less than
0.1% of join-time growth). Those differences are not claimed. Join wall time
also had no consistent improvement and is not claimed.

## Compared revisions

- Product control:
  `aea3d4133047bb06cce5813658bf619e5c11b829`
- Product candidate:
  `d25578b20ddfaad9eb688c38bc156b910141c993`
- Control plus measurement-only harness:
  `34bfc2b91579915a1a48bf0f54fe58c90ac1f258`
- Candidate plus byte-identical measurement harness:
  `65129f178699955b16e133fecf01a6770514bf15`

`git diff --exit-code
34bfc2b9:bench/scale/rrharness
65129f17:bench/scale/rrharness` passed before the campaign. The only product
difference is the grouped private-table invariant, its allocation
introspection, documentation, and regressions.

## Measurement contract

The `rrharness late-join` mode:

1. starts the real `RibManager` with no outbound clients;
2. injects routes and waits for the exact Loc-RIB count;
3. snapshots `VmRSS`, `VmSize`, and `VmHWM` from
   `/proc/self/status`;
4. registers homogeneous route-reflector clients using the real
   `fanout_bench_export_encoder`;
5. fails unless every client reports the same `group:*` update group, every
   client has exactly the requested staged route count, and the channel drain
   total is exactly `clients × routes`; and
6. takes the post-join process snapshot only after those gates pass.

The campaign ran serially in A/B/B/A order with the CPU governor set to
`performance`, no cargo/rustc/rrharness/rustbgpd/bgperf/containerlab process
active before the first run, and four unrelated long-running containers left
unchanged. The harness covers the manager process only. It excludes TCP
session actors, the transport actor's final envelope/output encoding, socket
writers, kernel socket buffers, and remote peers. Manager-side exact-export
precommit probing still uses the real fanout encoder and can prepare/build
candidate UPDATEs.

## Load-bearing regression proof

Each new test was made red by an isolated production or parser break and then
restored before the final gates:

- `grouped_peer_private_unicast_stays_unallocated_during_distribution`:
  deleting the zero-capacity table install lets ordinary grouped distribution
  reserve the populated Loc-RIB and makes its capacity assertion red.
- `grouped_late_join_private_unicast_stays_unallocated_during_initial_dump`:
  the same deletion makes a populated initial dump reserve the private slab
  and turns the capacity assertion red.
- `grouped_peer_non_unicast_first_delta_keeps_private_unicast_unallocated`:
  the same deletion lets the FlowSpec first-creator path reserve the populated,
  non-sendable unicast Loc-RIB; the assertion reads capacity `1` instead of
  `0`.
- `grouped_peer_ungroup_seeds_private_advertised_routes`: clearing the captured
  unicast baseline before the ungroup seed makes the no-duplicate-wire-update
  assertion red.
- `parses_required_proc_status_memory_fields`: mapping `VmHWM` from `VmRSS`
  makes the exact fixture assertion red.
- `rejects_missing_or_malformed_proc_status_memory_fields`: removing the
  `kB`/extra-field validation makes the malformed-unit fixture red.

## Scope and worst case

This fixes fresh grouped membership, including a non-unicast family becoming
the first route-bearing delta. It deliberately does not add a shrink/rebuild
operation for an already-populated ungrouped peer that later moves into a
group: `RouteSlab::clear` retains capacity, and reclaiming it is a separate
lifecycle trade-off.

At the published 1,000-peer shape, if every peer joins only after a
one-million-route table has converged, the removed requests scale
structurally to 128,004,096,000 bytes (119.2 GiB) of virtual reservations,
including the observed 4 KiB mapping overhead per peer. That is an
extrapolation from the exact per-peer capacity equation, not a measured RSS or
fleet result. Peers established before routes arrive and peers on the
authoritative ungrouped path do not have this redundant late-join request.

## Artifacts

The exact raw rows, derived table, safe provenance, commands, and checksum
envelope are retained in
[`artifacts/grouped-private-adj-rib-out-late-join-2026-07/`](artifacts/grouped-private-adj-rib-out-late-join-2026-07/README.md).
