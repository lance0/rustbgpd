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

### Best-Path Comparison

1000 pairwise `best_path_cmp()` calls per iteration. The 10-step tiebreak
(stale, RPKI, LOCAL_PREF, AS_PATH len, ORIGIN, MED, eBGP pref, CLUSTER_LIST,
ORIGINATOR_ID, peer addr) is the inner loop of best-path selection.

| Scenario | Time (1000 calls) | Per-call |
|----------|-------------------|----------|
| Equal routes (full tiebreak) | 17.7 us | 17.7 ns |
| LOCAL_PREF differs (early exit) | 4.3 us | 4.3 ns |
| Different peers (peer addr tiebreak) | 17.8 us | 17.8 ns |

Early exit at LOCAL_PREF is 4x faster than a full tiebreak. In typical eBGP
deployments most comparisons resolve at LOCAL_PREF or AS_PATH length.

### Adj-RIB-In Insert

Bulk insert into a fresh `AdjRibIn` (HashMap keyed by `(Prefix, path_id)`).

| Routes | Time | Throughput |
|--------|------|------------|
| 10,000 | 1.4 ms | 7.1M routes/sec |
| 100,000 | 22.6 ms | 4.4M routes/sec |
| 500,000 | 108 ms | 4.6M routes/sec |

Throughput is stable at ~4.5M routes/sec. A full Internet table (900k prefixes)
would insert in ~200ms. The cost is dominated by HashMap resizing; pre-sizing
would improve this.

### Loc-RIB Recompute

Best-path selection for a single prefix with N candidate routes.

| Candidates | Time |
|------------|------|
| 1 | 93 ns |
| 2 | 107 ns |
| 4 | 145 ns |
| 8 | 213 ns |

Linear in candidate count, as expected. With Add-Path or multiple peers
advertising the same prefix, each additional candidate adds ~17 ns
(one `best_path_cmp` call).

### Full Pipeline

End-to-end: insert routes from 2 peers into Adj-RIB-In, recompute best path
for every prefix, install into Adj-RIB-Out. This exercises the real hot path
without async/channel overhead.

| Prefixes (x2 peers) | Time | Per-prefix |
|----------------------|------|------------|
| 1,000 | 2.3 ms | 2.3 us |
| 10,000 | 265 ms | 26.5 us |
| 50,000 | 7.1 s | 142 us |

The superlinear scaling (10x prefixes = 115x time from 1k to 10k) is caused by
`iter_prefix()` — a linear scan over the Adj-RIB-In HashMap to find all routes
for a given prefix. This is O(N) per prefix, making the full pipeline O(N^2).
For the current route-server and control-plane use case (sub-100k prefixes),
this is adequate. A secondary prefix index would make this O(1) per lookup
if full-table scale becomes a requirement.

### Route Churn

10,000 base routes from peer 1, then 1,000 route announcements from peer 2
followed by 1,000 withdrawals, with best-path recomputation at each step.

| Benchmark | Time |
|-----------|------|
| 10k base + 1k announce/withdraw cycle | 27.9 ms |

This simulates a realistic route flap event. The 1k-prefix churn window
reconverges in ~28ms including both the announce and withdraw phases.

## Interpretation

**Wire codec** — The codec is not a bottleneck. Parsing a full-size UPDATE (500
prefixes, typical attributes) takes 3.3us. At 1 Gbps line rate, BGP UPDATE
arrival rate is far lower than decode capacity. The two-phase decode/parse
design means sessions that only need header inspection (keepalives, most
notifications) pay no attribute decode cost.

**RIB insert** — Bulk insert at 4.5M routes/sec means a full Internet table
loads in under 200ms. This is well within acceptable convergence time for
route-server deployments.

**Best-path selection** — At 17.8ns per comparison, even 8-candidate Add-Path
selection completes in 213ns per prefix. Best-path is not a bottleneck.

**Pipeline scaling** — The `iter_prefix()` O(N) scan is the dominant cost at
scale. At 10k prefixes this is acceptable (265ms for a full 2-peer
recomputation). At 50k+ it becomes the bottleneck. For full-table deployments,
adding a `HashMap<Prefix, Vec<(IpAddr, u32)>>` secondary index in `AdjRibIn`
would reduce this to O(candidates) per prefix. This optimization is deferred
until full-table scale is a validated requirement.
