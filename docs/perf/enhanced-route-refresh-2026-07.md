# Enhanced Route Refresh inventory receipt — 2026-07

Inbound Enhanced Route Refresh (ERR) keeps a per-peer inventory of routes that
existed at Beginning-of-RIB-Refresh (BoRR). Replayed routes leave that
inventory; End-of-RIB-Refresh (EoRR), or the independent five-minute timeout,
withdraws what remains. This receipt measures the current implementation before
any representation or ownership change.

## Pinned path and fleet

The real release daemon, `rbgp`, and the standalone TCP BGP driver were built
from commit `1096438f13645f65839308c32e0ab1ff21b14ebc` (tree
`dd40bd879aa0ab13d20b3617a0a4132c93859043`). The production base was main at
`68212e14`; the measured commit adds only this receipt harness.

The driver negotiated Enhanced Route Refresh over one real TCP session and
announced exactly 100,000 unique IPv4 unicast `/24`s. The daemon used the
release profile and jemalloc. The sampler slept 25 ms between scrapes around
actions; scrape time makes the observed wall-clock interval slightly longer.
The settled baseline came from that same process and SHA immediately before
the first BoRR; this is an absolute-path receipt, not a cross-commit A/B.
The run used Linux 6.17.0-35-generic, an AMD Ryzen Threadripper 7970X 32-Core
CPU, rustc 1.97.0, and LLVM 22.1.6.

This is an **observed one-peer, 100,000-route result**. No 1M-route run was
performed. The retained inventory may look linear in route identities, but
neither a 1M memory figure nor a 1M actor-duration figure is claimed here.

## Correctness receipt

The session established once and recorded zero flaps. Every phase reached its
exact production state:

| Phase | Adj-RIB-In | Max-prefix usage | Refresh stale | Active |
|---|---:|---:|---:|---:|
| settled baseline | 100,000 | 100,000 | 0 | no |
| first BoRR | 100,000 | 100,000 | 100,000 | yes |
| replay one | 100,000 | 100,000 | 99,999 | yes |
| duplicate BoRR | 100,000 | 100,000 | 100,000 | yes |
| EoRR | 0 | 0 | 0 | no |
| restored | 100,000 | 100,000 | 0 | no |
| timeout BoRR | 100,000 | 100,000 | 100,000 | yes |
| timeout complete | 0 | 0 | 0 | no |

The first, middle, and last prefixes were queried independently through the
shipped API. All three existed through active refresh windows and were absent
after both completion paths. Duplicate BoRR therefore took a fresh snapshot,
and neither completion could pass by zeroing metrics without sweeping the
transport-owned max-prefix count and the actual routes.

## Memory result

| Action | Allocated delta | Active delta | Resident delta | RSS delta | Phase RSS HWM above pre-action RSS |
|---|---:|---:|---:|---:|---:|
| first BoRR | +5,593,608 B | +5,652,480 B | 0 B | +92 KiB | +92 KiB |
| duplicate BoRR | -52,040 B | -28,672 B | +2,007,040 B | +2,652 KiB | +2,652 KiB |
| EoRR | +1,962,608 B | +2,076,672 B | +18,874,368 B | +14,212 KiB | +36,440 KiB |
| timeout BoRR | +5,595,536 B | +5,677,056 B | +6,291,456 B | +6,124 KiB | +6,124 KiB |
| timeout complete | -5,750,592 B | -5,767,168 B | +15,286,272 B | +15,304 KiB | +36,280 KiB |

The inventory retained about 5.6 MB of live jemalloc allocations at both clean
BoRR boundaries. The first BoRR barely moved RSS because jemalloc already had
mapped pages; the later timeout BoRR made nearly the same live allocation
visible as a 6,124 KiB RSS increase. These are two views of the same
allocator/process boundary, not values to add together.

Duplicate BoRR did not retain a second inventory: allocated and active bytes
were slightly lower after replacement. It did cause allocator mapping and page
touch churn, so flat live bytes must not be reported as flat RSS.

Both completion paths reached almost the same kernel high-water envelope:
36,440 KiB above pre-action RSS for EoRR and 36,280 KiB for timeout. The
sampler with a 25 ms inter-scrape sleep captured only four EoRR observations,
so the reset kernel
`VmHWM` is the authoritative completion peak. Post-action allocated bytes are
not an ownership estimate: allocator caches, metric scrapes, recomputation, and
distribution remain live after the route inventory is swept.

## Actor duration

Histogram deltas isolate each accepted operation:

| Operation | Actor duration |
|---|---:|
| first BoRR | 5.222 ms |
| duplicate BoRR | 4.098 ms |
| timeout-window BoRR | 6.371 ms |
| EoRR completion | 135.978 ms |
| timeout completion | 141.278 ms |

The result establishes that completion, not snapshot creation, is the dominant
single-actor work for this 100k all-withdraw shape. It does not establish a
fleet-wide convergence regression or justify a linear 1M extrapolation.

## Smallest-correct production options

Ranked by expected effect and safety:

1. **Move or drain the existing family inventory at completion instead of
   cloning it into a second key vector.** Key the stale owner so a completed
   family can be taken intact, then consume it while building only the affected
   prefix set that recomputation requires. Expected result: lower completion
   allocation/HWM and some actor-time reduction; no change to the approximately
   5.6 MB active-window inventory. Fencing risk is low if the active window and
   deadline remain owned until the drain is committed, replay continues to
   retire exact `(prefix, path_id)` identities, and max-prefix accounting stays
   transport-owned. This is the first implementation experiment.
2. **Mark refresh generation on existing Adj-RIB-In identities instead of
   owning duplicate keys.** This could remove most of the observed 100k
   active-window allocation and make duplicate BoRR a generation advance.
   Expected memory impact is larger than option 1; actor impact is uncertain
   because begin and completion still scan. Risk is medium/high: Add-Path
   identity, route replacement, GR/LLGR exclusion, family overlap, and copied
   route values can silently break the fence. Confirm the field fits without
   growing every resident route and prove all lifecycle interactions before
   choosing it.
3. **Chunk completion across actor turns while retaining the refresh fence.**
   This targets actor monopolization rather than total work. It is not justified
   by the 100k result alone: 136–141 ms is observable but bounded. Measure a
   representative larger table first. Risk is highest because partial sweeps
   must not declare convergence, expose stale route-page generations, or allow
   a later session/EoRR to complete the wrong window.

A sorted vector is not recommended: replay needs exact, frequent identity
retirement, and linear removal would exchange a bounded memory cost for
quadratic refresh work. A broad RIB representation rewrite is also not
warranted by this receipt.

## Reproduce, artifacts, and red proofs

Run the host-locked receipt:

```text
bench/scale/enhanced-route-refresh/run-receipt.sh
```

It refuses dirty source, builds real release binaries, runs for approximately
six minutes, and keeps private raw logs and metric streams under
`target/enhanced-route-refresh/`. The compact, sanitized evidence retained for
this result is under
[`artifacts/enhanced-route-refresh-2026-07/`](artifacts/enhanced-route-refresh-2026-07/README.md).

The harness's generated-wire test goes red if any one of the 100,000 prefixes
is dropped, duplicated, or changed. Its fixed-shape test goes red if the 100k
guard is removed. Validator mutation tests go red if the EoRR RIB-zero
obligation or accepted-BoRR actor observation is removed. The live receipt goes
red if the RIB snapshot, duplicate resnapshot, EoRR/timeout route sweep,
max-prefix reconciliation, actor histogram, session continuity, or exact API
sentinels regress.
