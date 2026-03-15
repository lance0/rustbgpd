# Architecture

> Update this file when crate boundaries, runtime ownership, or cross-crate
> contracts change. Do not put milestone or status content here.

---

## Crate Dependency Graph

```
wire           (no internal deps)
fsm            ──► wire
policy         ──► wire
rpki           ──► wire
bmp            (no internal deps)
mrt            ──► wire, rib
telemetry      (no internal deps)
rib            ──► wire, policy, telemetry, rpki
transport      ──► wire, fsm, rib, policy, telemetry, bmp
api            ──► wire, fsm, rib, policy, transport, telemetry
cli            (no internal deps — uses tonic codegen directly)
```

### Crate summary

| Crate | Description |
|-------|-------------|
| `rustbgpd-wire` | BGP message codec. Zero internal deps. Independently publishable and fuzzed. |
| `rustbgpd-fsm` | RFC 4271 state machine. Pure -- no tokio, no sockets, no tasks. |
| `rustbgpd-transport` | Tokio TCP glue. Owns BGP peer session I/O and drives the FSM. |
| `rustbgpd-rib` | Adj-RIB-In, Loc-RIB best-path, Adj-RIB-Out. Single-task ownership, no locks. |
| `rustbgpd-policy` | Policy engine: prefix/community/AS_PATH matching, route modifications. |
| `rustbgpd-rpki` | RPKI origin validation: RTR client, VRP table, multi-cache aggregation. |
| `rustbgpd-bmp` | BMP exporter: RFC 7854 codec, collector clients, manager fan-out. |
| `rustbgpd-mrt` | MRT dump: RFC 6396 TABLE_DUMP_V2 codec, atomic writer, periodic manager. |
| `rustbgpd-api` | gRPC server (tonic). Seven services, proto codegen at build time. |
| `rustbgpd-telemetry` | Prometheus metrics + structured tracing. |
| `rustbgpctl` | CLI tool. Client-only gRPC stubs, no internal crate deps. |

### Hard rules

- `wire` depends on nothing internal. It is a pure codec library, independently publishable.
- `fsm` depends on `wire` types (message enums, capability structs) and nothing else. It never imports tokio, never touches a socket, never spawns a task.
- `transport` is the only crate that owns BGP peer TCP session I/O and drives the FSM. Other crates (`api`, `bmp`, `rpki`, `mrt`) run their own async tasks for gRPC serving, collector connections, RTR sessions, and dump I/O respectively.
- `rib` and `policy` are independent of transport and fsm — they consume route update events.
- `api` provides the gRPC server; the binary crate (`src/main.rs`) wires everything together.

---

## Runtime Model

One tokio task per peer session, one RibManager task, one PeerManager task. No shared mutable routing state. State-owning task boundaries primarily use bounded `tokio::mpsc`, with `oneshot` for request/reply, `broadcast` for route event streaming, and one intentional unbounded channel for collision-resolution notifications.

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ PeerSession │     │ PeerSession │     │ PeerSession │
│  (per peer) │     │  (per peer) │     │  (per peer) │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       │    RibUpdate      │    RibUpdate      │
       ▼                   ▼                   ▼
   ┌──────────────────────────────────────────────┐
   │              RibManager task                 │
   │  Adj-RIB-In · Loc-RIB · Adj-RIB-Out         │
   │  best-path · export policy · distribution    │
   └──────────────────┬───────────────────────────┘
                      │ OutboundRouteUpdate
       ┌──────────────┼──────────────┐
       ▼              ▼              ▼
   PeerSession    PeerSession    PeerSession

   ┌──────────────────────────────────────────────┐
   │           PeerManager task                   │
   │  neighbor lifecycle · config intent          │
   └──────────────────────────────────────────────┘
       ▲
       │ PeerManagerCommand
   ┌───┴──────────────────────────────────────────┐
   │              gRPC API server                 │
   └──────────────────────────────────────────────┘
```

Each peer session runs a `tokio::select!` loop over TCP socket I/O, protocol timers (hold, keepalive, connect-retry), and inbound commands. The RIB task processes updates sequentially — no locks, no contention. IPv4 and IPv6 routes coexist in the same `HashMap<Prefix, Route>`. The sharding seam is at the channel boundary: if scale demands it, split to one RIB task per AFI/SAFI without changing session code.

---

## Ownership Model

Each component is the single source of truth for its domain. No overlapping authority.

| Component | Owns | Authoritative for |
|-----------|------|-------------------|
| **PeerManager** | Neighbor lifecycle, config intent | Which peers should exist and their parameters |
| **FSM** | Protocol state transitions | What state each peer session is actually in |
| **RIB** | Routing state | What routes exist, which is best, what to advertise |
| **Transport** | Socket I/O, wire framing | TCP connections, message encode/decode, session runtime |
| **API** | Request/response adaptation | Nothing — it translates gRPC into commands and queries |

The API layer is explicitly *not* a source of truth. It is an adapter between gRPC callers and the authoritative components.

---

## Design Invariants

These are not negotiable. Every contributor and every PR is measured against them.

1. **The FSM is pure.** It takes message and timer inputs, produces message and state outputs. No tokio, no sockets, no file descriptors.

2. **The wire crate is independently usable.** Zero internal dependencies. `cargo add rustbgpd-wire` works without the daemon.

3. **No accidental unbounded channels.** Channels are bounded by default. One intentional exception: session-notification for collision handling (unbounded to avoid `send().await` deadlock with synchronous peer-state queries).

4. **No silent attribute drops.** Every ignored, filtered, or rejected attribute emits a structured event. Operators can explain every routing decision from logs alone.

5. **No panics on malformed input.** Network input is untrusted. The wire decoder returns `Result` for all paths. A panic on malformed BGP data is a DoS vulnerability.

6. **All protocol violations produce structured events.** Every NOTIFICATION sent/received, every malformed message, every RFC violation — machine-parseable log entries with peer address, error classification, and context.

7. **Resource limits are enforced, not advisory.** Max prefixes, max message size, max channel depth produce defined behavior (NOTIFICATION, backpressure, rejection) when exceeded.

8. **Interop is tested, not assumed.** No feature is complete until validated against FRR and BIRD in a containerlab topology.

---

## Cross-Crate Seam Types

These types define the contracts between crates. They are the key interfaces to understand when working across boundaries.

| Type | Defined in | Contract between |
|------|-----------|-----------------|
| `Prefix` | `wire::nlri` | Everything. AFI-agnostic route identity (`V4`/`V6` enum). `Copy`. |
| `Route` | `rib::route` | Transport → RIB → distribution. Carries prefix, next-hop (`IpAddr`), attributes, origin, validation state, staleness. |
| `RibUpdate` | `rib::update` | Transport → RIB. Enum: `RoutesReceived`, `PeerUp`, `PeerDown`, `PeerGracefulRestart`, `InjectRoute`, `QueryRoutes`, `RpkiCacheUpdate`, FlowSpec variants, etc. |
| `OutboundRouteUpdate` | `rib::update` | RIB → Transport. Announces + withdrawals + FlowSpec changes for a single peer, after export policy. |
| `PeerManagerCommand` | `api::peer_types` | API → PeerManager. Enum: `AddPeer`, `DeletePeer`, `EnablePeer`, `DisablePeer`, `QueryState`, `ReconcilePeers`, etc. |
| `NegotiatedSession` | `fsm::action` | FSM → Transport. Capabilities, peer ASN/ID, negotiated families, GR state, Add-Path modes. Produced on `Established`. |
| `PathAttribute` | `wire::attribute` | Wire → everything. Typed + raw hybrid enum. Known attrs decoded to Rust types; unknown optional-transitive preserved as `RawAttribute` for byte-exact re-emission. |
| `PolicyChain` | `policy::engine` | Config → Transport/RIB. Wraps `Vec<Policy>` with chain evaluation semantics (permit=continue, deny=stop). |

---

## Data Flow

### Inbound (receiving routes)

```
TCP bytes
  → wire::decode (framing, message parse)
  → transport validation (attribute checks per RFC 4271)
  → import policy (match + modify + filter)
  → RibUpdate::RoutesReceived sent to RIB task
  → RIB: insert Adj-RIB-In, recompute best-path, update Loc-RIB
  → RIB: for each peer, apply export policy → Adj-RIB-Out
  → OutboundRouteUpdate sent to each peer's TX channel
```

### Outbound (advertising routes)

```
OutboundRouteUpdate received by PeerSession
  → transport: build UPDATE message (AS_PATH prepend, NEXT_HOP rewrite, private AS removal)
  → wire::encode (serialize to bytes)
  → TCP write
```

### API queries

```
gRPC request
  → API service handler
  → PeerManagerCommand or RibUpdate (query variant) via channel
  → oneshot reply with result
  → API serializes to protobuf response
```

---

## Where to Change X

| Task | Start here |
|------|-----------|
| Wire codec (message parse/encode) | `crates/wire/src/` — `message.rs`, `attribute.rs`, `nlri.rs` |
| Path attribute decode/encode | `crates/wire/src/attribute.rs` |
| FlowSpec NLRI | `crates/wire/src/flowspec.rs` |
| FSM state transitions | `crates/fsm/src/lib.rs` |
| Capability negotiation | `crates/fsm/src/negotiation.rs` |
| Peer session runtime | `crates/transport/src/session.rs` |
| Outbound UPDATE construction | `crates/transport/src/session.rs` — `prepare_outbound_attributes()` |
| Policy evaluation | `crates/policy/src/engine.rs` |
| Best-path selection | `crates/rib/src/manager/` — `best_path_cmp()` in `helpers.rs` |
| Route distribution | `crates/rib/src/manager/distribution.rs` |
| Peer lifecycle (GR, LLGR, ERR) | `crates/rib/src/manager/graceful_restart.rs`, `route_refresh.rs` |
| RIB event loop | `crates/rib/src/manager/mod.rs` — `run()` |
| gRPC service handlers | `crates/api/src/` — one file per service |
| RPKI / RTR | `crates/rpki/src/` |
| BMP export | `crates/bmp/src/` |
| MRT dump | `crates/mrt/src/` |
| CLI tool | `crates/cli/src/` |
| Config loading + validation | `src/config/` |
| Startup wiring | `src/main.rs` |
| Looking glass (REST API) | `src/looking_glass.rs` |
| Prometheus metrics | `crates/telemetry/src/lib.rs` |

---

## Lifecycle Flows

### Startup

1. `main.rs` loads TOML config, validates, initializes logging and metrics.
2. Checks for GR restart marker file (`runtime_state_dir/gr-restart.toml`). If present and not expired, static peers will advertise `R=1` in OPEN.
3. Spawns RibManager task (owns all routing state).
4. Spawns PeerManager task (owns neighbor lifecycle).
5. Spawns BgpListener (accepts inbound TCP on port 179).
6. Spawns gRPC API server. Optionally spawns Prometheus metrics server (if `prometheus_addr` configured) and looking glass HTTP server (if `[global.telemetry.looking_glass]` configured).
7. Optionally spawns BMP manager + per-collector clients, MRT manager, RPKI VRP manager + RTR clients.
8. For each configured neighbor, sends `AddPeer` to PeerManager → PeerManager spawns a PeerSession task.

### Peer Establishment

1. PeerSession opens TCP (outbound) or accepts TCP (inbound via listener).
2. FSM drives OPEN exchange. Transport encodes/decodes, feeds FSM events.
3. On `Established`, FSM produces `NegotiatedSession` with capabilities.
4. Transport sends `RibUpdate::PeerUp` to RIB with negotiated families and outbound channel.
5. RIB registers the peer, dumps existing Loc-RIB routes to the peer's Adj-RIB-Out, sends End-of-RIB.
6. Inbound UPDATEs flow through the normal data path.

### Config Reload (SIGHUP)

1. Signal handler sets reload flag in the main `select!` loop.
2. `reload_config()` re-reads TOML, calls `diff_neighbors()` against current config.
3. Sends `ReconcilePeers` command to PeerManager with add/delete deltas.
4. PeerManager applies changes: spawns new sessions, tears down removed ones.
5. Global config changes (ASN, router-id) are logged as warnings and ignored (require restart).

### Graceful Shutdown

1. SIGTERM or `Shutdown` gRPC RPC triggers shutdown.
2. Writes GR restart marker file (if any peer has GR enabled) with expiry.
3. Sends NOTIFICATION/Cease (Administrative Shutdown) to all established peers.
4. Signals BMP manager to send Termination messages to collectors.
5. Waits up to 5 seconds for TCP sends to flush, then hard-drops.
6. Flushes final telemetry.

### Graceful Restart (receiving)

1. Peer goes down. If peer had GR capability + restart state, transport sends `PeerGracefulRestart` (not `PeerDown`) to RIB.
2. RIB marks the peer's routes as GR-stale. Starts `gr_restart_time` timer.
3. Peer re-establishes. RIB moves families to "awaiting EoR" state.
4. As new UPDATEs arrive, they replace stale routes.
5. End-of-RIB received → RIB sweeps remaining stale routes for that family.
6. If GR timer expires before EoR → if LLGR negotiated, promote to LLGR-stale (add `LLGR_STALE` community, start `llgr_stale_time` timer); otherwise purge stale routes.

### Enhanced Route Refresh

1. `SoftResetIn` gRPC call → transport sends ROUTE-REFRESH to peer.
2. If peer supports Enhanced Route Refresh: send BoRR → peer re-advertises → send EoRR.
3. On BoRR received: RIB marks peer's routes as refresh-stale.
4. Replacement UPDATEs clear the refresh-stale flag.
5. On EoRR received (or 5-minute timeout): RIB sweeps unreplaced refresh-stale routes.

---

## Failure and Backpressure Model

### Channel boundaries

All inter-task communication uses bounded `tokio::mpsc` channels (capacity 4096 by default). This provides natural backpressure without locks.

| Channel | Producer | Consumer | On full |
|---------|----------|----------|---------|
| RIB inbound | PeerSession, API | RibManager | Producer's `send().await` blocks. Session stalls but does not lose data. |
| Adj-RIB-Out | RibManager | PeerSession | `try_send()` — update dropped, peer marked dirty for resync. |
| PeerManager commands | API | PeerManager | `send().await` blocks. gRPC call waits. |
| BMP events | Transport | BmpManager | `try_send()` — event dropped, warning logged. |

One intentional unbounded channel: session-notification used for TCP collision detection. Bounded send would deadlock with synchronous peer-state queries during collision resolution.

### Dirty-peer resync

When an Adj-RIB-Out channel is full, the update is dropped and the peer is marked "dirty." On the next successful send, RibManager schedules a full table resync for that peer. This ensures eventual consistency without blocking the RIB task.

### Prefix limits

Per-peer `max_prefixes` is enforced at Adj-RIB-In insertion. Exceeding the limit produces NOTIFICATION (Cease, Maximum Number of Prefixes Reached) and session teardown. A global `max_total_routes` limit tears down the offending session with NOTIFICATION (Cease, Out of Resources).

### Why no locks

The RIB is the hottest data structure. Wrapping it in `Arc<RwLock>` would create contention under UPDATE storms and make reasoning about ordering difficult. Instead, the RIB runs as a single task with exclusive ownership. All access is serialized through the channel. This trades parallelism for simplicity and determinism — the right tradeoff at current scale. The sharding seam (channel boundary) is ready if scale demands splitting.
