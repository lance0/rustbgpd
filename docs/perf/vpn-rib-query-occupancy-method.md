# VPN RIB query occupancy method

This instrument measures the existing `ListVpnRoutes` path without changing its
API or optimizing it. It exists to separate the RIB actor's full-table snapshot
cost from the service's filtering and protobuf conversion cost before any
production change is proposed.

## Shape

- 16 peers: `10.0.0.1` through `10.0.0.16`.
- VPNv4 `/32` routes are assigned round-robin to peers.
- Every route has a unique RD-plus-prefix key, one MPLS label, shared realistic
  path attributes, and route target `65000:100`.
- Each peer is seeded in its own primary-channel updates, with batches no
  larger than 4096. Before every send, the harness asserts that each announced
  route belongs to the update's actual envelope peer.
- A `QueryLocRibCount` sent on that same primary channel is the FIFO ingest
  barrier. Its unicast count is intentionally ignored.
- Both samples call the actual `RibService::list_vpn_routes` method through the
  priority query channel. The first is unfiltered; the second uses
  `peer_filter = 10.0.0.1` and an empty `afi_safi`.

The supported campaign sizes are 10,000, 100,000, and 1,000,000 routes. The
per-commit gate runs only the exact 256-route smoke shape; it does not publish a
performance claim.

## Timings and occupancy

`actor_handler_ns` begins at the production `QueryVpnRoutes` match arm and ends
after the snapshot reply is sent. `actor_rows` and `actor_capacity` describe the
actual `Vec<VpnRibRoute>` allocated there.

`service_method_ns` is measured outside the service across the trait method call
and await. It includes the bounded benchmark-only service receipt `try_send`
before the trait method returns. `actor_handler_ns` and `post_actor_ns` exclude
publication of their respective receipts. Benchmark receipts use bounded
persistent channels compiled only by `bench-internals`; an unarmed
production/default build is unchanged.

Setup has one absolute deadline shared by all seed sends and the FIFO barrier
send and receive. Each query then has its own absolute deadline shared by the
service call and both receipt awaits: 10 seconds in the exact smoke and 120
seconds in campaign mode. A stalled actor or receipt publication failure
therefore makes the smoke fail in bounded time instead of hanging.

The timing executable installs the workspace `tikv-jemallocator` directly.
The mechanics gate parses only the supplied benchmark source and requires its
`#[global_allocator]` attribute immediately before the `tikv-jemallocator`
static. Receipts identify allocator and mode so results from a different build
cannot be silently compared.

Semantic checksums are calculated after the timed method returns. They are
order-independent and cover RD, prefix, peer, and label. No sorting or hashing
is added to the service path.

## Commands

Run the exact smoke and its corruption proofs:

```console
bash bench/tests/test-vpn-query-receipt.sh
```

Produce one campaign receipt without committing it:

```console
cargo bench -p rustbgpd-api --bench vpn_query --features bench-internals -- \
  measure 10000 /tmp/vpn-query-10000.json
```

Repeat for 100,000 and 1,000,000 only on an otherwise idle host. This slice
defines the instrument and gate; it does not run or publish that campaign.

## Load-bearing failures

- Replacing the actor snapshot collection with `Vec::new()` breaks exact row
  counts and semantic checksums.
- Giving a seed update the wrong envelope peer fails its ownership assertion
  before the update is sent to the actor.
- Stalling the manager during setup fails at the internal aggregate setup
  deadline.
- Removing the peer predicate changes 16 filtered rows to 256.
- Selecting a different peer while preserving the filtered count breaks the
  explicit assertion that every returned row belongs to `10.0.0.1`.
- Bypassing or zeroing any timing breaks the nonzero decomposition assertions.
- Removing only `#[global_allocator]` makes the structural allocator seam check
  fail.
- Removing actor or service receipt publication fails at the shared absolute
  deadline instead of hanging.
- Corrupting either row counts or the exact deterministic smoke checksums makes
  the shell verifier fail; its checksum mutation remains nonzero.
