# ADR-0017: PeerManager — channel-based single-task ownership for dynamic peer management

**Status:** Accepted
**Date:** 2026-02-27

## Context

Prior to M4, peer sessions were spawned at boot from the config file and stored
in a local `Vec` inside `main.rs::run()`. This had two problems:

1. **No dynamic peer management.** Peers could not be added or removed at
   runtime via gRPC — the NeighborService had no handle to the peer lifecycle.
2. **No state queries.** There was no way to query a peer's FSM state or prefix
   count without reaching into the transport layer.

The RibManager already demonstrated a proven pattern: a single tokio task owns
all state, commands arrive via bounded `mpsc`, replies via embedded `oneshot`.

## Decision

Create a `PeerManager` using the same channel-based single-task ownership
pattern as `RibManager`:

- `PeerManagerCommand` enum sent via `mpsc::Sender<PeerManagerCommand>`
- Commands: `AddPeer`, `DeletePeer`, `ListPeers`, `GetPeerState`, `EnablePeer`,
  `DisablePeer`, `Shutdown`
- Each command with a reply carries a `oneshot::Sender` for the response
- The PeerManager owns a `HashMap<IpAddr, ManagedPeer>` with peer handles
- State queries use `PeerHandle::query_state()` which sends a `QueryState`
  command to the peer's session task and awaits the reply

Shared types (`PeerManagerCommand`, `PeerManagerNeighborConfig`, `PeerInfo`)
live in `crates/api/src/peer_types.rs` so both the binary crate and the API
crate can use them without circular dependencies.

## Consequences

**Positive:**
- Consistent architecture — PeerManager and RibManager follow the same pattern.
- Dynamic peer add/remove works via gRPC without restart.
- State queries available for monitoring and operational tooling.
- No new locks or shared mutable state.
- Starting with zero configured peers is now valid (peers added dynamically).

**Negative:**
- One extra hop for peer operations (gRPC → PeerManager → PeerHandle).
- Shared types in the API crate create a mild coupling between crates.
