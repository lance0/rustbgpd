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
`AdjRibIn` uses a secondary prefix index (`HashMap<Prefix, HashSet<u32>>`) for
O(1) prefix lookup, avoiding the O(N) full-scan that dominated earlier versions.

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
| `Route` | 104 bytes |
| `Prefix` | 18 bytes |
| `PathAttribute` | 72 bytes |
| `AsPath` | 24 bytes |
| `AdjRibIn` | 216 bytes |
| `LocRib` | 96 bytes |

### Per-Route Heap Allocation

| Attribute set | Heap | Stack | Total |
|---------------|------|-------|-------|
| Typical (6 attrs, 3-ASN path, 2 communities) | 484 B | 104 B | 588 B |
| Rich (8 attrs, 5-ASN+SET path, 5 communities, ORIGINATOR_ID, CLUSTER_LIST) | 696 B | 104 B | 800 B |

### AdjRibIn at Scale (single peer, typical attrs)

| Routes | Resident | Per-route |
|--------|----------|-----------|
| 10,000 | 8.1 MB | 850 B |
| 100,000 | 74.8 MB | 784 B |
| 500,000 | 450 MB | 943 B |
| 900,000 | 648 MB | 755 B |

Per-route cost is ~755-943 bytes including HashMap and prefix index overhead.
Variance comes from HashMap load factor at different sizes.

### Full RIB: 2 Peers + LocRib (typical attrs)

| Prefixes | Total memory | Per-prefix |
|----------|-------------|------------|
| 100,000 | 212 MB | 2.2 KB |
| 500,000 | 1.23 GB | 2.6 KB |
| 900,000 | 1.80 GB | 2.1 KB |

A full Internet table (900k prefixes) with 2 peers and best-path selection uses
**1.8 GB**. Each prefix stores 3 Route instances (2x Adj-RIB-In + 1x Loc-RIB)
plus HashMap/index overhead. This is 4-9x less than GoBGP (8-16+ GB) but larger
than BIRD (~325 MB for 30 peers) which shares path attribute storage across
routes with identical attributes.

### Optimization Opportunities

- **Path attribute interning** — routes from the same peer often share identical
  attributes. A `HashMap<Arc<Vec<PathAttribute>>, ...>` dedup table could reduce
  memory 3-5x for large tables, approaching BIRD-class efficiency.
- **HashMap pre-sizing** — `with_capacity()` on AdjRibIn construction would
  reduce peak allocation by avoiding rehash copies.

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

## Comparison with Other BGP Stacks

These are micro-benchmarks of rustbgpd's data structures, not end-to-end system
benchmarks. Direct comparison requires a common harness like
[bgperf2](https://github.com/netenglabs/bgperf2), which is future work.
The numbers below provide context for where rustbgpd sits relative to published
benchmarks from other stacks.

### GoBGP

rustbgpd is architecturally inspired by GoBGP's API-first model, so this is the
most natural comparison. Published bgperf2 results for GoBGP 2.29.0:

| Metric | GoBGP | rustbgpd | Notes |
|--------|-------|----------|-------|
| Route ingestion (100k routes, 10 peers) | ~11k routes/sec | 2.6M routes/sec (insert only) | GoBGP is end-to-end; rustbgpd is RIB insert micro-benchmark |
| CPU usage (100k routes) | 1450% (all cores) | Single-threaded | GoBGP uses goroutine-per-peer; rustbgpd uses single-owner RIB |
| Memory (full table, ~900k) | 8-16+ GB | 1.8 GB (2 peers + LocRib) | 4-9x less than GoBGP |
| Full table convergence | Test abandoned (too slow) | ~1.5s estimated (pipeline extrapolation) | GoBGP was excluded from full-table rounds of bgperf2 |

GoBGP's Go runtime incurs GC pressure, interface boxing overhead, and
goroutine scheduling costs that Rust avoids entirely. rustbgpd's single-owner
RIB design eliminates the lock contention that costs GoBGP CPU across all cores.

### BIRD and FRR

BIRD and FRR are the performance leaders in the open-source BGP space. Published
bgperf2 results:

| Metric | BIRD | FRR 8.0 | rustbgpd |
|--------|------|---------|----------|
| Route ingestion (100k, 10 peers) | ~25k routes/sec | ~33k routes/sec | 2.6M routes/sec (insert only) |
| CPU usage (100k routes) | ~100% (single core) | ~100% (single core) | Single-threaded |
| Memory (100k routes, 2 peers) | 15 MB | 100 MB | 212 MB |
| Full table (800k x 30 peers) | Completes | Completes | Not yet tested |

BIRD and FRR are mature, battle-tested stacks with radix-tree RIBs and decades
of optimization. rustbgpd's raw data structure throughput is competitive, but
end-to-end performance (including TCP I/O, timer management, gRPC overhead, and
multi-peer coordination) has not been benchmarked yet.

### What These Numbers Mean

The micro-benchmarks show that rustbgpd's core data structures are not the
bottleneck — wire codec, best-path comparison, and RIB operations are all fast
enough for full-table scale. The remaining unknowns are:

1. **End-to-end throughput** — how fast can the full daemon ingest routes from
   live BGP peers? This requires bgperf2 or equivalent system benchmarks.
2. **Memory footprint** — 1.8 GB for a full table with 2 peers. 4-9x less than
   GoBGP, but larger than BIRD. Path attribute interning could close the gap.
3. **Multi-peer scaling** — the single-owner RIB avoids lock contention but
   serializes all RIB operations through one tokio task. Channel backpressure
   under high peer counts needs testing.
