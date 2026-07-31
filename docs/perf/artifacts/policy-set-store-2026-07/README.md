# Bounded eager policy-set sharing receipt — 2026-07

> **Historical receipt.** This captures the superseded 32-neighbor chunk
> implementation. Current loading interns sets once for the whole compiled
> unit; the measurements and rows below are preserved as historical evidence,
> not as the current sharing contract.

This is the implementation gate for sharing content-equal indexed `.rpol`
sets while resolving a retained neighbor roster. The accepted implementation
uses one content-keyed `SetStore` per contiguous 32-neighbor chunk. It
preserves roster order and bounds canonical-key retention independently of
fleet size.

Validation is deliberately unchanged: direct chain and validation callers
retain one local store per chain. A standalone effective-policy or neighbor
resolution owns one store for that single neighbor call. Only
`Config::resolved_neighbors` shares across neighbors, and only within a
32-neighbor chunk.

## Why the unbounded design was rejected

The first candidate used one store for the entire roster. A unique-set control
gave every peer its own `.rpol` file and distinct 10,000-entry IPv6 prefix set.
Fixture generation and config load were outside the allocator window.

| Peers | Local-store peak delta | Unbounded peak delta | Extra peak | End delta, both |
|---:|---:|---:|---:|---:|
| 1 | 2,021,912 | 2,021,912 | 0 | 1,107,012 |
| 10 | 11,973,980 | 14,854,376 | 2,880,396 | 11,056,873 |
| 100 | 111,468,521 | 143,152,613 | 31,684,092 | 110,551,418 |

The extra transient grew by approximately 320,041 bytes per additional unique
10,000-entry set, projecting to about 319.7 MB at 1,000 peers. End live bytes
were identical because the store drops when collection returns, but the
unbounded peak was material. That design was a no-go. Its exact rows remain in
`unique-unbounded-{control,candidate}.csv`.

## Accepted shapes and controls

The common-set fixture contains one 10,000-entry `.rpol` prefix set referenced
by `{1, 10, 100, 1000}` static peers. The unique-set fixture uses
`{1, 10, 31, 32, 33, 95, 96, 97, 100}` peers to cover both sides of chunk
boundaries. Each unique peer has a separate `.rpol` file and disjoint
10,000-entry IPv6 set.

The control is an exact mechanism reversal on the candidate tree:
`resolve_chain_with_store` ignores its caller-owned store and creates the
per-chain local store used by base commit
`9a7b64615fd0a81572fc75e938dd2084890fecbe`. No workload or harness input
differs. The common-set harness asserts that retained canonical copies equal
`ceil(peers / 32)` in the candidate and `peers` in the control.

The diagnostic binary wraps `System` and records successful allocation calls,
requested bytes, peak live requested bytes, and end live requested bytes.
These are not jemalloc resident/active bytes or process RSS. Elapsed times are
diagnostic implementation-gate evidence, not a shipped-allocator headline.

## Common-set result

At 1,000 peers:

| Metric | Local-store control | Chunked candidate | Change |
|---|---:|---:|---:|
| median elapsed | 375.858 ms | 121.903 ms | -67.6% |
| requested bytes | 1,926,234,568 | 588,636,680 | -69.4% |
| allocation calls | 10,038,001 | 341,545 | -96.6% |
| end live requested bytes | 843,210,568 | 29,184,520 | -96.5% |
| retained canonical copies | 1,000 | 32 | -96.8% |

The first control resolution run was cold (736.106 ms); the subsequent
same-binary runs were 375.421 and 375.858 ms. Candidate runs were 125.950,
121.903, and 119.662 ms. Raw rows are `control.csv` and `candidate.csv`.

## Unique-set stop gate

| Peers | Control peak | Chunked peak | Extra peak | End delta, both |
|---:|---:|---:|---:|---:|
| 1 | 2,022,464 | 2,022,464 | 0 | 1,105,356 |
| 10 | 11,970,668 | 14,851,064 | 2,880,396 | 11,053,561 |
| 31 | 35,183,225 | 44,785,205 | 9,601,980 | 34,266,121 |
| 32 | 36,288,585 | 46,210,565 | 9,921,980 | 35,371,481 |
| 33 | 37,393,945 | 46,211,117 | 8,817,172 | 36,476,841 |
| 95 | 105,926,265 | 115,528,245 | 9,601,980 | 105,009,161 |
| 96 | 107,031,625 | 116,953,605 | 9,921,980 | 106,114,521 |
| 97 | 108,136,985 | 116,954,157 | 8,817,172 | 107,219,881 |
| 100 | 111,453,065 | 116,955,813 | 5,502,748 | 110,535,962 |

End live bytes are byte-identical at every shape. Extra peak is bounded by
9,921,980 bytes at full chunk boundaries. The measured-shape gate requires
that overhead to stay at or below the larger of 16 MiB and 5% of control
reload coexistence (`peak + end`); the 9.92 MB maximum clears its 16 MiB
floor. Persistent end overhead must remain at or below 1%; it is exactly zero.
For this fixed one-10k-set-per-peer shape, the 1,000-peer projection must
remain below 64 MiB; chunking bounds it to the same 9.92 MB maximum. This is
not a bound for arbitrarily many distinct sets attached to each peer.

The unique candidate was slower in these single diagnostic runs: at 100 peers,
98.298 ms versus 83.497 ms (+17.7%), and at 96 peers, 95.418 ms versus
82.287 ms (+15.9%). One run per shape under the tracking allocator cannot
support a shipped CPU-regression claim, but the opposite-shape observation is
retained rather than hidden. Raw rows and fixture/baseline overhead are in
`unique-{control,candidate}.csv`.

## DHAT ownership cross-check

A separate symbolized `release-prof` capture starts after fixture load,
profiles only the 1,000-peer `Config::resolved_neighbors` call, retains the
roster until profiler close, and asserts exactly 32 canonical common-set
copies.

| Capture | Total live at peak | `SetStore::prefix_set` owner stacks | Live at end |
|---|---:|---:|---:|
| local-store control | 843,996,605 | 841,503,756 | 843,210,568 |
| chunked candidate | 30,042,949 | 27,550,100 | 29,184,520 |

The indexed-set owner reduction is 813,953,656 bytes (96.726%). The seven
aggregated owner rows in each profile run through `SetStore::prefix_set`,
`PrefixSet::new`, `resolve_rpol_chain_ref`, and the resolved-neighbor path.

Raw DHAT JSON is not committed. `dhat/*.dhat-derivative.tsv` are lossless
sanitized derivatives generated by the repository classifier: raw addresses
and host paths are removed while stack symbols and byte counts remain.

```console
for profile in control candidate; do
  python3 bench/scale/rebaseline/classify_dhat.py \
    --from-derivative \
    "docs/perf/artifacts/policy-set-store-2026-07/dhat/${profile}.dhat-derivative.tsv" \
    >/dev/null
done
```

## Provenance

The accepted production patch and both measurement harnesses were frozen
before the final receipt:

| Input | SHA-256 |
|---|---|
| `git diff --binary 9a7b6461 -- src/config/mod.rs src/config/parse.rs` | `5f85b8739e0c343f67ea82c1647d015841ddb08686ed8c6eac75977b35ff82d0` |
| `tests/policy_set_store_allocation.rs` | `2fd7a29aed2a69e41d65dce51816d7db06363cf5d297042d01fbff70c5f06175` |
| `tests/policy_set_store_dhat.rs` | `f691ee21476a860e15d1e663db46eab92aaa0db7cc196aca506316152625926a` |

`src/config/validation.rs` is byte-identical to the base commit; validation is
outside this optimization's scope.

## Reproduce

Run the allocation receipts serially because they share one global diagnostic
allocator:

```console
POLICY_SET_STORE_RUNS=3 cargo test -p rustbgpd \
  --no-default-features --features bench-internals --release \
  --test policy_set_store_allocation receipt -- \
  --ignored --nocapture --test-threads=1
```

Run the symbolized ownership capture:

```console
POLICY_SET_STORE_DHAT_FILE=/tmp/policy-set-store.json \
  cargo test -p rustbgpd --no-default-features \
  --features bench-internals,dhat-heap --profile release-prof \
  --test policy_set_store_dhat -- --ignored --nocapture
```

Environment: AMD Ryzen Threadripper 7970X (32 cores / 64 threads), Linux
6.17.0-35-generic, rustc 1.97.0.

This receipt claims no benefit for validation, TOML policies, unique per-peer
sets, AS-path regex compilation, daemon RSS, or convergence. Unique IXP member
filters receive no storage-sharing win; the chunk bound exists specifically
to keep their transient canonical-key overhead small.
