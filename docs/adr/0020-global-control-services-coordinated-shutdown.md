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

Implement both services. The original two-`oneshot` design evolved into one
tonic-stop `oneshot` plus a `watch<bool>` signal from ControlService to main.

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
- `Shutdown` — after authorization and logging, synchronously sets only the
  RPC-to-main shutdown watch. The handler neither spawns teardown nor sends
  `PeerManagerCommand::Shutdown`; tonic remains available long enough for the
  accepted in-flight response to complete.

### Coordinated shutdown

Two distinct channels:
- `grpc_shutdown_tx/rx` — a oneshot main fires late in teardown to stop tonic.
- `rpc_shutdown_tx/rx` — a `watch<bool>` ControlService sets to ask main to shut
  down.

Signals, a true RPC watch value, and unexpected supervised component exits all
enter main's common ordered shutdown path. Main closes admission and settles
configuration work, fences EVPN runtime apply, and drains the EVPN originators,
segment routes, and IMET routes while BGP sessions are still alive. It then
sends the sole `PeerManagerCommand::Shutdown`, awaits peer teardown, drains the
remaining local dataplane, BFD, and BMP owners, and only then fires
`grpc_shutdown_tx` to stop tonic.

Shutdown flow (RPC path):
1. The authorized handler synchronously sets `rpc_shutdown_tx` and returns its
   response; it does not spawn or directly shut down PeerManager.
2. Main's `select!` observes the true watch value and enters the common ordered
   path above.

## Consequences

**Positive:**
- All 5 proto services are now implemented — no more UNIMPLEMENTED surprises.
- Peers receive proper Cease NOTIFICATIONs on shutdown.
- gRPC server exits gracefully — in-flight RPCs can complete.
- The watch-only handler removes the proven pre-signal bounded-channel stall and
  teardown-order bypass. It does not attribute every historical quickstart
  timeout to that path; other bounded shutdown stages remain independent.
- No new dependencies.

**Negative:**
- `SetGlobal` returns UNIMPLEMENTED — callers must handle this. Documented as
  deferred; the proto already exists so the surface is stable.
- At adoption the `Shutdown` RPC had no authentication; current listeners
  require mutating access before the watch-only dispatch.
