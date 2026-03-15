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

### Optimization History (end-to-end, bgperf2 2p/100k)

| Change | Memory | Convergence |
|--------|--------|-------------|
| Pre-AdjRibOut index | 168 MB | 71s |
| + AdjRibOut secondary prefix index | 415 MB | 12s |
| + Skip unnecessary Arc deep clones | 257 MB | 11s |
| + AdjRibOut capacity hints | ~260 MB | 11s |

The Arc deep-clone fix (`RouteModifications::is_empty()` guard) was the biggest
memory win: `Arc::make_mut()` was called unconditionally on every route in
`distribute_single_best_prefix()`, forcing deep clone of `Vec<PathAttribute>`
even when no export policy modifications were configured. With the guard, ~85%
of routes share the same `Arc` across LocRib and AdjRibOut — no deep copy.

Capacity hints (pre-sizing AdjRibOut/LocRib HashMaps) were tested and shown to
be neutral on steady-state RSS, confirming the remaining HashMap overhead is
structural (power-of-2 rounding), not rehash churn.

Remaining memory is HashMap bucket arrays (~78%) and actual Route data (~19%).
No obvious accidental overhead remains.

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

Benchmarks run at v0.4.2; no RIB performance changes in v0.5.0–v0.7.0.

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
| Convergence | 2s | 5s | 2s |
| Max CPU | 13% | 16% | 112% |
| Max Memory | 7 MB | 578 MB | 257 MB |
| Total time | 3s | 6s | 11s |

### Understanding the Numbers

**Session establishment.** rustbgpd's ConnectRetryTimer defaults to 5 seconds
(reduced from the RFC 4271 suggested 30 seconds). When BIRD tester peers start
after rustbgpd, the first outbound connection attempt fails and the retry fires
within 5 seconds. Total establishment overhead is ~9 seconds, compared to 1-2
seconds for BIRD (accepts inbound immediately) and GoBGP (passive neighbor
mode). Further improvement would require listen-mode-first startup.

**Route processing.** At 10k and below, convergence completes in 2 seconds —
matching GoBGP and within 1 second of BIRD. At 200k prefixes, rustbgpd
converges in 2 seconds (monitor time), competitive with BIRD (2s) and faster
than GoBGP (5s). The key optimizations were: (1) secondary prefix index in
`AdjRibOut` converting per-prefix lookup from O(N) to O(1), and (2) skipping
unnecessary `Arc::make_mut()` deep clones in the distribution path when no
export policy modifications are configured.

**CPU efficiency.** rustbgpd uses a single-threaded RIB (single tokio task,
no locks). At 200k scale it peaks at 112% CPU (RIB + transport tasks). BIRD
is the most efficient at 13% CPU, reflecting decades of C optimization with a
radix-tree RIB.

**Memory.** rustbgpd uses 257 MB for 200k routes (2 peers + Loc-RIB +
Adj-RIB-Out), **2.3x less than GoBGP** (578 MB). Remaining memory is
dominated by HashMap bucket arrays (~78% of tracked heap) and Route struct
data (~19%). BIRD uses 7 MB — still an order of magnitude less, reflecting
its compact radix-tree representation. At full-table scale (900k prefixes,
micro-bench), rustbgpd uses 547 MB for Adj-RIB-In + Loc-RIB vs GoBGP's
published 8-16+ GB.

**gRPC under load.** A priority query channel separates read-only gRPC queries
from the route-processing pipeline, ensuring management API requests are
serviced between route batches even during bulk loading. At 100k+ scale, the
API remains responsive rather than blocking behind thousands of queued route
updates.

### Comparison Summary

| Metric | BIRD | GoBGP | rustbgpd |
|--------|------|-------|----------|
| Architecture | Single-threaded C, radix tree | Go, goroutine-per-peer | Single-threaded Rust, HashMap RIB |
| Route processing (200k) | 2s | 5s | 2s |
| CPU model | 1 core, very efficient | Multi-core, GC overhead | 1-2 cores, no GC |
| Memory model | Radix tree, minimal overhead | Go heap, GC managed | Arc sharing, attribute interning |
| Memory (200k routes) | 7 MB | 578 MB | 257 MB |
| Memory (900k, micro-bench) | ~325 MB (published, 30 peers) | 8-16+ GB (published) | 547 MB (2 peers + Loc-RIB) |
| API during load | Responsive (no RIB contention) | Responsive (concurrent) | Responsive (priority query channel) |

BIRD is the clear performance leader — 30+ years of optimization in a
purpose-built C codebase is hard to beat. rustbgpd converges 200k prefixes in
2 seconds (monitor time), matching BIRD and beating GoBGP (5s). Memory at
257 MB is 2.3x less than GoBGP (578 MB); at full-table scale (900k,
micro-bench) the gap widens further (547 MB vs 8-16 GB). The remaining memory
is structural — HashMap bucket arrays and Route data — with no obvious
accidental overhead. Further memory reduction would require shared route
storage across RIB views or alternative data structures.

## Running End-to-End Benchmarks

End-to-end system benchmarks use [bgperf2](https://github.com/netenglabs/bgperf2),
a Docker-based BGP benchmarking harness. bgperf2 lives outside the rustbgpd repo.

### Prerequisites

- Docker running
- bgperf2 checked out (e.g. `/home/lance/projects/bgperf2`)
- Python virtualenv with bgperf2 dependencies

### Build the Docker image

```bash
cd /path/to/bgperf2
source .venv/bin/activate
python -c "
from rustbgpd import RustBGPd
RustBGPd.build_image(force=True, nocache=True)
"
```

**Critical:** Always use `nocache=True` when rebuilding. Without it, Docker
caches the builder stage and reuses stale binaries. This has caused phantom
benchmark results in the past.

### Run a benchmark

```bash
# Clean up any leftover containers
docker rm -f $(docker ps -aq --filter "name=bgperf") 2>/dev/null
docker network rm bgperf-net bgperf2-br 2>/dev/null

# Run: 2 peers, 100k prefixes each (200k total)
python bgperf2.py bench -t rustbgpd -n 2 -p 100000

# Other scenarios
python bgperf2.py bench -t rustbgpd -n 10 -p 1000    # 10 peers, 1k each
python bgperf2.py bench -t rustbgpd -n 2 -p 10000     # 2 peers, 10k each

# Compare against other daemons
python bgperf2.py bench -t bird -n 2 -p 100000
python bgperf2.py bench -t gobgp -n 2 -p 100000
```

Output is a CSV line with convergence time, max CPU, max memory, etc.

### Heap profiling with dhat

rustbgpd has a feature-gated dhat heap profiler. To capture a heap profile:

```bash
# Build with dhat profiling (slower, ~2x overhead)
python -c "
from rustbgpd import RustBGPd
RustBGPd.build_image(force=True, nocache=True, profile='dhat')
"

# Run the benchmark in the background
python bgperf2.py bench -t rustbgpd -n 2 -p 100000 &

# Wait for convergence (~40s with dhat overhead)
sleep 50

# Send SIGTERM to rustbgpd to trigger profile dump
# Note: pgrep/kill may not exist in the container; use /proc scanning
docker exec bgperf_rustbgpd_target bash -c '
for p in /proc/[0-9]*/cmdline; do
  if grep -ql rustbgpd "$p" 2>/dev/null; then
    pid=$(echo "$p" | cut -d/ -f3)
    kill -TERM "$pid"
  fi
done'

# Wait for profile write, then extract
sleep 8
docker cp bgperf_rustbgpd_target:/root/config/dhat-heap.json ./dhat-heap.json
```

View the profile at https://nnethercote.github.io/dh_view/dh_view.html

### Gotchas

- **Docker image caching.** Always `nocache=True`. Stale binaries produce
  misleading results.
- **Container cleanup.** bgperf2 sometimes leaves containers running after the
  benchmark script exits. Clean up with `docker rm -f $(docker ps -aq --filter "name=bgperf")`.
- **PID 1 in Docker.** The `exec` in the startup script doesn't always replace
  bash as PID 1. rustbgpd may be a child process (e.g. PID 7). Use `/proc`
  scanning to find the right PID for SIGTERM.
- **Variance.** RSS measurements vary ~10-15% between runs due to allocator
  behavior and timing. Run 2-3 times and take the median.
- **dhat overhead.** dhat wraps every allocation, adding ~2x CPU overhead and
  ~40% memory overhead. The tracked heap numbers are accurate but RSS will be
  higher than production builds.
