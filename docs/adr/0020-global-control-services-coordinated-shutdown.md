# ADR-0020: GlobalService, ControlService, and coordinated shutdown

**Status:** Accepted
**Date:** 2026-02-27

## Context

At the time of this ADR, the proto file defined five gRPC services —
`GlobalService`, `NeighborService`, `RibService`, `InjectionService`, and
`ControlService`. Three of these were
implemented (M1–M4), but `GlobalService` and `ControlService` had no server-side
implementation. Clients generated from the proto would get UNIMPLEMENTED for 5 RPCs.

Additionally, shutdown was not coordinated. The `run()` function sent
`PeerManagerCommand::Shutdown` to the PeerManager then returned immediately,
allowing the tokio runtime to drop and abort tasks mid-shutdown — before peers
could receive NOTIFICATION messages.

Options considered for shutdown coordination:

1. **tokio-util `CancellationToken`** — clean API but adds a new dependency.
2. **`tokio::sync::watch<bool>`** — no new dep, but heavier than needed for a
   one-shot signal.
3. **Two `oneshot` channels** — minimal, no new deps, clear ownership. One for
   ctrl-c-initiated gRPC shutdown, one for RPC-initiated shutdown.

## Decision

Implement both services and use two `oneshot` channels for shutdown coordination.

### GlobalService

- `GetGlobal` — returns read-only ASN, router_id, listen_port set at construction.
- `SetGlobal` — returns `UNIMPLEMENTED`. Runtime ASN/router-id mutation is complex
  (requires re-negotiating all sessions) and deferred to post-v1.

### ControlService

- `GetHealth` — queries PeerManager via `ListPeers` and filters to Established
  state for `active_peers`. Queries Loc-RIB count via `QueryLocRibCount` for
  `total_routes`. Reports uptime from `Instant` captured at daemon start. (M8:
  previously counted all configured peers and summed per-peer prefix counts.)
- `GetMetrics` — gathers Prometheus text from the explicit `BgpMetrics` registry,
  reusing the same pattern as `metrics_server.rs`.
- `Shutdown` — sends `PeerManagerCommand::Shutdown`, then fires the gRPC shutdown
  oneshot. The shutdown sequence is spawned so the RPC can return a response before
  the server stops.

### Coordinated shutdown

Two oneshot channels:
- `grpc_shutdown_tx/rx` — main fires this after PeerManager drains, stopping tonic.
- `rpc_shutdown_tx/rx` — ControlService fires this from the Shutdown RPC.

Shutdown flow (ctrl-c path):
1. `tokio::select!` on `ctrl_c()` and `rpc_shutdown_rx`
2. Send `PeerManagerCommand::Shutdown` to PeerManager
3. Await PeerManager `JoinHandle` (peers send NOTIFICATIONs, close TCP)
4. Send `grpc_shutdown_tx` — tonic's `serve_with_shutdown` exits
5. `run()` returns cleanly

Shutdown flow (RPC path):
1. Shutdown RPC spawns: send `PeerManagerCommand::Shutdown`, then fire
   `rpc_shutdown_tx`
2. Main's `select!` detects `rpc_shutdown_rx`, enters the same drain sequence

## Consequences

**Positive:**
- All 5 proto services are now implemented — no more UNIMPLEMENTED surprises.
- Peers receive proper Cease NOTIFICATIONs on shutdown.
- gRPC server exits gracefully — in-flight RPCs can complete.
- No new dependencies.

**Negative:**
- `SetGlobal` returns UNIMPLEMENTED — callers must handle this. Documented as
  deferred; the proto already exists so the surface is stable.
- `Shutdown` RPC has no authentication — any gRPC client can shut down the daemon.
  Access control is a post-v1 concern (same as all other RPCs).
