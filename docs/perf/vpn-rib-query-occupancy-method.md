# VPN RIB query occupancy campaign

This retained campaign measures the existing `ListVpnRoutes` path. It neither
changes that API nor proposes a redesign. The per-commit gate is only a
256-route executable smoke plus corruption fixtures; CI never runs or publishes
the campaign.

## Executable shape

The harness seeds VPNv4 `/32` routes across 16 peers and uses the production
priority query channel and `RibService::list_vpn_routes`. `U` is unfiltered;
`F` filters exactly `10.0.0.1`. Every process measures exactly one case and
writes one receipt. Semantic checksums cover RD, prefix, peer, and label.

Two separately compiled executables prevent allocation instrumentation from
contaminating timing:

- `vpn_query_timing` uses bare jemalloc and emits timing evidence.
- `vpn_query_allocation` wraps jemalloc with absolute live-requested-byte
  accounting. `peak_live_requested_bytes > 8 GiB` is capacity-censored.
  `/proc` `VmRSS` and `VmHWM` are recorded only as observations and never drive
  classification. Its allocator forwarding and bookkeeping are serialized by
  a no-allocation spin lock, so this mode is diagnostic; its timings are not
  performance results.

The driver builds each executable once, copies it into the campaign directory,
records SHA-256, commit, and `rustc` provenance, then refuses missing, changed,
or corrupt binaries. Commit, Git tree, clean status, toolchain, and binary
hashes are captured before the locked build and rechecked through completion.
It acquires the shared retained-performance host lock and
requires the same load, CPU-governor, and competing-process fence before build
and every process.

## Fixed campaign

For each size `10,000`, `100,000`, and `1,000,000`, the driver launches 16 fresh
timing processes in this immutable order:

`U1,F1,U2,F2,U3,F3,U4,F4,U5,F5,U6,F6,U7,F7,U8,F8`

That is exactly 48 uniquely numbered receipts. Selective reruns, randomization,
reordering, missing receipts, and dual-case receipts are invalid.
One complete clean retry may be requested with `--retry`; it reuses the exact
prebuilt binaries and must contain all 48 cells. Partial, selective, or third
attempts are invalid.
Every receipt, including a censor, names its attempt. The verifier inventories
all `attempt-*` entries, validates every completed earlier attempt, and accepts
only the exact ordered prefix of the censored current attempt.

Within each cell, pairs are repetitions `(1,2)`, `(3,4)`, `(5,6)`, and `(7,8)`.
For actor-handler values `a,b`, `pair_noise = abs(a-b) / ((a+b)/2)` and cell
noise is the maximum of those four values. The noise ceiling is 5% at 10k and
100k and 10% at 1M.

`service_method_ns` encloses the trait call. The retained decomposition is
computed with `service_method_ns.checked_sub(actor_handler_ns)`; underflow or
missing evidence fails closed. A zero post-actor duration is valid.
Every setup/query timeout produces the typed `capacity_censored` process
outcome. The driver catches only its exit status 75, stops all remaining cells,
and verifies the censor receipt; every other nonzero exit is a hard failure.

Classifier precedence is exact:

1. `capacity_censored`
2. `inconclusive` (cell noise above its size-specific ceiling)
3. `instrumentation_suspect` (filtered/unfiltered actor medians disagree by
   more than `max(cell noise, 5%)`, or actor medians fail to increase strictly
   with size)
4. `urgent` (worst actor handler above 200 ms)
5. `design_followup` (worst actor handler above 25 ms)
6. `no_redesign`

## Commands

Run the bounded mechanics and 256-route executable smoke:

```console
bash bench/tests/test-vpn-query-campaign.sh
bash bench/tests/test-vpn-query-receipt.sh
```

An operator may run the full retained campaign on a dedicated host:

```console
bench/run-vpn-query-campaign.sh /uncommitted/output-directory
```

The output is intentionally not a committed result. A valid campaign is checked
with:

```console
python3 bench/verify-vpn-query-campaign.py /uncommitted/output-directory
```

## Load-bearing gates

The tests demonstrate red outcomes for fixed-order mutation, receipt
count/order/pair drift, a dual-case receipt, timing underflow, binary corruption,
row/checksum corruption, and removal of the allocator seam. These are executable
mutation proofs, not prose-only claims.
