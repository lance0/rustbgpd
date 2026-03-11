# Benchmarks

Micro-benchmarks using [Criterion](https://github.com/bheisler/criterion.rs) 0.5.
All numbers from a single run on an AMD Ryzen 9 / Linux 6.17, compiled with
`--release` (LTO, codegen-units=1). Your mileage will vary — these are meant
for relative comparison and regression tracking, not absolute guarantees.

## Running

```bash
# All benchmarks
cargo bench --bench codec --bench rib_ops

# Wire codec only
cargo bench -p rustbgpd-wire --bench codec

# RIB only
cargo bench -p rustbgpd-rib --bench rib_ops

# Specific group
cargo bench -p rustbgpd-rib --bench rib_ops -- "adj_rib_in_insert"
```

HTML reports are generated to `target/criterion/`.

## Wire Codec

The wire codec (`rustbgpd-wire`) is the hot path for every inbound and outbound
UPDATE. It uses a two-phase design: `decode()` is O(1) framing only, `parse()`
is O(n) structural decode.

### NLRI Encode / Decode

| Prefixes | Decode | Encode | Per-prefix decode |
|----------|--------|--------|-------------------|
| 1 | 21 ns | 12 ns | 21 ns |
| 10 | 94 ns | 26 ns | 9.4 ns |
| 100 | 662 ns | 198 ns | 6.6 ns |
| 500 | 3.0 us | 1.0 us | 6.0 ns |

NLRI encoding is a tight `memcpy` loop. Decoding adds masking and validation.
At 500 prefixes, decode throughput is ~167M prefixes/sec.

### UPDATE Build / Parse

Full UPDATE message construction and structural parsing, including path
attributes and NLRI.

| Prefixes | Build | Parse | Per-prefix parse |
|----------|-------|-------|------------------|
| 1 | 156 ns | 158 ns | 158 ns |
| 10 | 207 ns | 231 ns | 23 ns |
| 100 | 498 ns | 868 ns | 8.7 ns |
| 500 | 1.6 us | 3.3 us | 6.6 ns |

At 500 prefixes, parse throughput is ~151M prefixes/sec. The fixed cost
(~130 ns) is attribute decode; marginal cost per prefix is ~6 ns.

### Path Attributes

| Set | Decode | Encode |
|-----|--------|--------|
| Typical (6 attrs) | 133 ns | 89 ns |
| Rich (8 attrs, large communities) | 182 ns | 167 ns |

"Typical" = Origin, AS_PATH (3 ASNs), NextHop, LocalPref, MED, Communities (2).

### Validation

| Benchmark | Time |
|-----------|------|
| `validate_update` (typical attrs) | 133 ns |

## RIB Operations

The RIB data structures (`rustbgpd-rib`) are pure synchronous structs with no
async or locking overhead. `RibManager` owns them in a single tokio task.
Both `AdjRibIn` and `AdjRibOut` use secondary prefix indexes for O(1)
per-prefix lookup, avoiding the O(N) full-scans that dominated earlier versions.

### Best-Path Comparison

1000 pairwise `best_path_cmp()` calls per iteration. The 10-step tiebreak
(stale, RPKI, LOCAL_PREF, AS_PATH len, ORIGIN, MED, eBGP pref, CLUSTER_LIST,
ORIGINATOR_ID, peer addr) is the inner loop of best-path selection.

| Scenario | Time (1000 calls) | Per-call |
|----------|-------------------|----------|
| Equal routes (full tiebreak) | 18.5 us | 18.5 ns |
| LOCAL_PREF differs (early exit) | 4.4 us | 4.4 ns |
| Different peers (peer addr tiebreak) | 18.5 us | 18.5 ns |

Early exit at LOCAL_PREF is 4x faster than a full tiebreak. In typical eBGP
deployments most comparisons resolve at LOCAL_PREF or AS_PATH length.

### Adj-RIB-In Insert

Bulk insert into a fresh `AdjRibIn` (HashMap keyed by `(Prefix, path_id)` plus
secondary prefix index).

| Routes | Time | Throughput |
|--------|------|------------|
| 10,000 | 2.6 ms | 3.8M routes/sec |
| 100,000 | 40.5 ms | 2.5M routes/sec |
| 500,000 | 190 ms | 2.6M routes/sec |

Throughput is ~2.6M routes/sec (vs 4.5M without the prefix index). The
trade-off is worthwhile: insert is ~1.8x slower, but `iter_prefix()` goes from
O(N) to O(1), making the full pipeline 25-86x faster at scale. A full Internet
table (900k prefixes) inserts in ~350ms.

### Loc-RIB Recompute

Best-path selection for a single prefix with N candidate routes.

| Candidates | Time |
|------------|------|
| 1 | 88 ns |
| 2 | 103 ns |
| 4 | 140 ns |
| 8 | 213 ns |

Linear in candidate count, as expected. With Add-Path or multiple peers
advertising the same prefix, each additional candidate adds ~18 ns
(one `best_path_cmp` call).

### Full Pipeline

End-to-end: insert routes from 2 peers into Adj-RIB-In, recompute best path
for every prefix, install into Adj-RIB-Out. This exercises the real hot path
without async/channel overhead.

| Prefixes (x2 peers) | Time | Per-prefix |
|----------------------|------|------------|
| 1,000 | 759 us | 759 ns |
| 10,000 | 10.8 ms | 1.08 us |
| 50,000 | 82 ms | 1.64 us |

Scaling is now linear (O(N)) thanks to the secondary prefix index. Previous
versions used an O(N) scan per prefix in `iter_prefix()`, making the full
pipeline O(N^2) — the 50k benchmark took 7.1 seconds vs 82ms now (**86x
improvement**).

Extrapolating linearly, a full Internet table (900k prefixes x 2 peers) would
complete the pipeline in ~1.5 seconds.

### Route Churn

10,000 base routes from peer 1, then 1,000 route announcements from peer 2
followed by 1,000 withdrawals, with best-path recomputation at each step.

| Benchmark | Time |
|-----------|------|
| 10k base + 1k announce/withdraw cycle | 761 us |

A 1k-prefix churn event reconverges in under 1ms, including both the announce
and withdraw phases. This is 37x faster than the pre-index version (27.9ms).

## Memory Footprint

Measured using a tracking global allocator that counts every `alloc` and
`dealloc`. Run with:
`cargo test -p rustbgpd-rib --test memory_profile -- --nocapture`

### Type Sizes (stack)

| Type | Size |
|------|------|
| `Route` | 88 bytes |
| `Prefix` | 18 bytes |
| `PathAttribute` | 72 bytes |
| `AsPath` | 24 bytes |
| `AdjRibIn` | 264 bytes |
| `LocRib` | 96 bytes |

`Route.attributes` is `Arc<Vec<PathAttribute>>` — cloning a route between
Adj-RIB-In, Loc-RIB, and Adj-RIB-Out shares the attribute allocation via
reference counting. Mutation uses `Arc::make_mut()` (copy-on-write).

Path attribute interning in `AdjRibIn` deduplicates identical attribute sets
across routes from the same peer. A `HashSet<Arc<Vec<PathAttribute>>>` intern
table maps each unique attribute set to a shared `Arc`. Routes with identical
attributes (common in bulk advertisements) share one heap allocation instead of
each having their own copy.

### Per-Route Heap Allocation

| Attribute set | Heap | Stack | Total |
|---------------|------|-------|-------|
| Typical (6 attrs, 3-ASN path, 2 communities) | 524 B | 88 B | 612 B |
| Rich (8 attrs, 5-ASN+SET path, 5 communities, ORIGINATOR_ID, CLUSTER_LIST) | 736 B | 88 B | 824 B |

These are per-unique-attribute-set costs. With interning, routes sharing the
same attributes pay only the 88-byte `Route` stack cost plus an 8-byte `Arc`
pointer.

### AdjRibIn at Scale (single peer, typical attrs)

| Routes | Resident | Per-route |
|--------|----------|-----------|
| 10,000 | 3.3 MB | 340 B |
| 100,000 | 26.7 MB | 279 B |
| 500,000 | 203 MB | 426 B |
| 900,000 | 217 MB | 252 B |

Per-route cost is ~252-426 bytes including HashMap overhead, prefix index, and
intern table. The dramatic reduction from pre-interning numbers (776-950 B/route)
comes from sharing the ~524-byte attribute allocation across all routes with
identical attributes. A typical peer's full table has only a handful of unique
attribute sets (~50-200), so the attribute heap cost is effectively amortized
to near zero per route.

### Full RIB: 2 Peers + LocRib (typical attrs)

| Prefixes | Total memory | Per-prefix |
|----------|-------------|------------|
| 100,000 | 68 MB | 707 B |
| 500,000 | 519 MB | 1.1 KB |
| 900,000 | 547 MB | 637 B |

A full Internet table (900k prefixes) with 2 peers and best-path selection uses
**547 MB**. Each prefix stores 3 Route instances (2x Adj-RIB-In + 1x Loc-RIB)
with `Arc` sharing across all three copies. Path attribute interning within each
`AdjRibIn` further reduces memory by sharing attribute allocations across routes
with identical attributes. This is **15-29x less than GoBGP** (8-16+ GB) and
approaching BIRD (~325 MB for 30 peers).

### Optimization History

| Version | Full RIB (900k x 2 peers) | Per-prefix | vs GoBGP |
|---------|--------------------------|------------|----------|
| Pre-Arc (`Vec<PathAttribute>`) | 1.80 GB | 2.1 KB | 4-9x less |
| Arc sharing (v0.4.2) | 1.41 GB | 1.6 KB | 6-11x less |
| Arc + interning (current) | 547 MB | 637 B | 15-29x less |

### Remaining Optimization Opportunities

- **AdjRibOut index memory compaction** — the secondary prefix index uses
  `HashMap<Prefix, Vec<u32>>`. For the common single-best case (path_id=0),
  a `SmallVec<[u32; 1]>` or specialized single-entry encoding would reduce
  per-prefix overhead.
- **Bulk initial load mode** — initial full-table floods still distribute on
  every chunk. Coalescing more of the initial export work could reduce best-path
  recomputation churn and emit fewer, larger UPDATEs.

## Interpretation

**Wire codec** — The codec is not a bottleneck. Parsing a full-size UPDATE (500
prefixes, typical attributes) takes 3.3us. At 1 Gbps line rate, BGP UPDATE
arrival rate is far lower than decode capacity. The two-phase decode/parse
design means sessions that only need header inspection (keepalives, most
notifications) pay no attribute decode cost.

**RIB insert** — Bulk insert at 2.6M routes/sec means a full Internet table
loads in ~350ms. This is well within acceptable convergence time for
route-server deployments.

**Best-path selection** — At 18.5ns per comparison, even 8-candidate Add-Path
selection completes in 213ns per prefix. Best-path is not a bottleneck.

**Pipeline scaling** — With the secondary prefix index, the pipeline scales
linearly. 50k prefixes x 2 peers completes in 82ms. Extrapolated full-table
(900k) would take ~1.5s for a complete 2-peer recomputation — well within
operational requirements.

**Route churn** — Sub-millisecond reconvergence for 1k-prefix flap events.
Real-world churn involves far fewer prefixes per UPDATE (typically 1-50),
so per-event reconvergence is effectively instant.

## End-to-End System Benchmarks

Measured using [bgperf2](https://github.com/netenglabs/bgperf2), a Docker-based
BGP benchmarking harness. Each test runs a target daemon, N BIRD tester peers
(each advertising P prefixes), and a GoBGP monitor peer that observes convergence.
The monitor's accepted route count is the ground truth for completion.

**Environment:** AMD Ryzen 9 7950X (64 logical cores), 125 GB RAM, Linux 6.17,
Docker 27.x. All daemons run in containers on the same host.

**Methodology:** Convergence time is measured from first prefix received by the
monitor to all expected prefixes received. The test harness waits for 5 seconds
of stability before declaring completion. Total time includes session
establishment.

### Results

#### 10 peers x 1,000 prefixes (10k total)

| | BIRD 2.18 | GoBGP 4.3.0 | rustbgpd 0.4.2 |
|---|---|---|---|
| Convergence | 1s | 2s | 2s |
| Max CPU | 9% | 10% | 18% |
| Max Memory | 2 MB | 188 MB | 80 MB |
| Total time | 2s | 3s | 11s |

#### 2 peers x 10,000 prefixes (20k total)

| | BIRD 2.18 | GoBGP 4.3.0 | rustbgpd 0.4.2 |
|---|---|---|---|
| Convergence | 1s | 2s | 2s |
| Max CPU | 9% | 10% | 18% |
| Max Memory | 1 MB | 89 MB | 62 MB |
| Total time | 2s | 3s | 11s |

#### 2 peers x 100,000 prefixes (200k total)

| | BIRD 2.18 | GoBGP 4.3.0 | rustbgpd 0.4.2 |
|---|---|---|---|
| Convergence | 2s | 5s | 12s |
| Max CPU | 13% | 16% | 195% |
| Max Memory | 7 MB | 578 MB | 406 MB |
| Total time | 3s | 6s | 21s |

### Understanding the Numbers

**Session establishment.** rustbgpd's ConnectRetryTimer defaults to 5 seconds
(reduced from the RFC 4271 suggested 30 seconds). When BIRD tester peers start
after rustbgpd, the first outbound connection attempt fails and the retry fires
within 5 seconds. Total establishment overhead is ~9 seconds, compared to 1-2
seconds for BIRD (accepts inbound immediately) and GoBGP (passive neighbor
mode). Further improvement would require listen-mode-first startup.

**Route processing.** At 10k and below, convergence completes in 2 seconds —
matching GoBGP and within 1 second of BIRD. At 200k prefixes, rustbgpd
converges in 12 seconds — competitive with GoBGP (5s) and within striking
distance of BIRD (2s). The key optimization was adding a secondary prefix
index to `AdjRibOut`, converting per-prefix lookup from O(N) full-scan to O(1)
HashMap lookup. Before this fix, `distribute_changes()` cost scaled from
1.4 µs/prefix (small table) to 780 µs/prefix (200k entries), causing the
71-second bottleneck.

**CPU efficiency.** rustbgpd uses a single-threaded RIB (single tokio task,
no locks). At 200k scale it peaks at 195% CPU (RIB + transport tasks), up from
93% pre-index because distribution now runs fast enough that RIB processing
and transport serialization overlap more heavily. BIRD is the most efficient
at 13% CPU, reflecting decades of C optimization with a radix-tree RIB.

**Memory.** rustbgpd uses 406 MB for 200k routes (2 peers + Loc-RIB +
Adj-RIB-Out), **1.4x less than GoBGP** (578 MB). The increase from 168 MB
(pre-index) reflects the `AdjRibOut` secondary prefix index
(`HashMap<Prefix, Vec<u32>>`) trading memory for O(1) lookup speed. BIRD uses
7 MB — still an order of magnitude less, reflecting its compact radix-tree
representation. At full-table scale (900k prefixes, micro-bench), rustbgpd
uses 547 MB for Adj-RIB-In + Loc-RIB vs GoBGP's published 8-16+ GB.

**gRPC under load.** A priority query channel separates read-only gRPC queries
from the route-processing pipeline, ensuring management API requests are
serviced between route batches even during bulk loading. At 100k+ scale, the
API remains responsive rather than blocking behind thousands of queued route
updates.

### Comparison Summary

| Metric | BIRD | GoBGP | rustbgpd |
|--------|------|-------|----------|
| Architecture | Single-threaded C, radix tree | Go, goroutine-per-peer | Single-threaded Rust, HashMap RIB |
| Route processing (200k) | 2s | 5s | 12s |
| CPU model | 1 core, very efficient | Multi-core, GC overhead | 1-2 cores, no GC |
| Memory model | Radix tree, minimal overhead | Go heap, GC managed | Arc sharing, attribute interning |
| Memory (200k routes) | 7 MB | 578 MB | 406 MB |
| Memory (900k, micro-bench) | ~325 MB (published, 30 peers) | 8-16+ GB (published) | 547 MB (2 peers + Loc-RIB) |
| API during load | Responsive (no RIB contention) | Responsive (concurrent) | Responsive (priority query channel) |

BIRD is the clear performance leader — 30+ years of optimization in a
purpose-built C codebase is hard to beat. rustbgpd converges 200k prefixes in
12 seconds — 2.4x slower than GoBGP (5s) and 6x slower than BIRD (2s), but a
dramatic improvement from the pre-index 71 seconds. Memory at 406 MB is 1.4x
less than GoBGP (578 MB); at full-table scale (900k, micro-bench) the gap
widens further (547 MB vs 8-16 GB). The `AdjRibOut` secondary prefix index
eliminated the dominant O(N^2) bottleneck in outbound distribution. Remaining
optimization opportunities include `AdjRibOut` index memory compaction
(e.g. `SmallVec<[u32; 1]>` for the common single-best case) and bulk initial
load coalescing.
