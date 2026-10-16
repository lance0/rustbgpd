# Peer-teardown cleanup readiness at `7ff33596` — 2026-10-16

> **Document class: HISTORICAL RECEIPT.** Component-level readiness during
> full-table peer-teardown cleanup passes its bars. This is not an HTTP
> `/readyz` or wire-driven qualification, and release qualification remains held.

Source: [`7ff33596cbe70deadb74389c38c6fbb4e8449f9c`](https://github.com/lance0/rustbgpd/commit/7ff33596cbe70deadb74389c38c6fbb4e8449f9c),
merged to main as `4a37214a8`. Hosted
[run 38831528639](https://github.com/lance0/rustbgpd/actions/runs/38831528639).
The summarizer `python3 bench/scale/recovery_memory.py summarize-retirement <campaign>`
exits 0 on both campaigns.

## Shape

Each profile removes 1,230,000 keys (1,000,000 IPv4 plus 230,000 IPv6) on a fresh
hosted VM: `full-uc` is unicast, `full-vpn` is VPNv4/VPNv6 with the same counts.
Six cells run per profile: full and empty variants of received cleanup including
attribute garbage collection, private Adj-RIB-Out outbound cleanup, and
regroup-baseline cleanup. Each cell runs two arms (current and old-drop) over two
legs: 48 invocations in total. The old-drop arm only restores the former VPN
stage-map drop; the receiver-cleanup code is identical in both arms. Cell
definitions are in the [retirement harness notes](https://github.com/lance0/rustbgpd/blob/4a37214a8/bench/scale/rrharness/README.md#hosted-retirement-attribution).

## Bars

- Maximum interval between cleanup checkpoints is at most 25 ms (the existing
  service budget).
- An in-process RIB readiness query replies within 200 ms.
- Productive overlap: at least one healthy in-owner reply lands at a nonforced
  Progress callback.

All three pass in every full cell and both arms. No probe errors occurred.

## Full cells, current arm, maximum over legs

| Profile / cell | Phase (ms) | Max checkpoint interval (ms) | Min body replies | RIB reply max (ms) |
|---|---:|---:|---:|---:|
| UC received + GC | 757.9 | 0.86 | 29 | 49.4 |
| UC private outbound | 259.5 | 1.64 | 10 | 25.0 |
| UC regroup baseline | 264.0 | 1.05 | 10 | 25.0 |
| VPN received + GC | 541.8 | 9.16 | 21 | 81.3 |
| VPN private outbound | 256.5 | 1.65 | 10 | 25.0 |
| VPN regroup baseline | 321.0 | 1.39 | 12 | 25.0 |

In the VPN received cell, the VPN stage-map retirement accounts for about 140 ms
of the phase. Old-drop phase durations are within 5% of the current arm in every
full cell; the largest gap is UC private outbound, where old-drop is 4.3% slower.
Empty cells complete in microseconds and are not productive-overlap cells.

## Scope

- Phase durations are an **instrumented upper bound**. The bench-internals build
  takes a lock and reads the clock at every checkpoint, so they are not comparable
  to the earlier uninstrumented detached-free figure of about 54 ms and are not
  production cost.
- Fixture attributes are uniform (at most four shared attribute sets). The
  attribute sweep is not measured at real full-table attribute diversity.
- The 1.23M private-outbound rows are EVPN IMET rows, not unicast or VPN routes.
- The RIB readiness bar is a component measurement. It is not a `/readyz` HTTP
  result and not a wire-driven qualification. Release qualification is separate
  and remains held.

## Artifacts

The [artifact directory](artifacts/peer-teardown-cleanup-readiness-7ff33596-2026-10-16/README.md)
holds the unchanged [UC](artifacts/peer-teardown-cleanup-readiness-7ff33596-2026-10-16/full-uc-comparison.json)
and [VPN](artifacts/peer-teardown-cleanup-readiness-7ff33596-2026-10-16/full-vpn-comparison.json)
comparison files with their SHA-256 digests.
