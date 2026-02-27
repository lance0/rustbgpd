# rustbgpd — Design Document

A modern, API-first BGP daemon in Rust, inspired by GoBGP's ergonomics and "drive it via gRPC" operating model.

**Author:** Lance  
**Status:** Draft  
**Last updated:** 2026-02-27

---

## Goals

**API-first routing control plane.** gRPC is the primary interface for all configuration and operations. The config file is a convenience for initial boot state — once the daemon is running, gRPC owns the truth. Clients in Python, Go, Rust, and Node should have a clean, typed experience from day one.

**Interop correctness over feature breadth.** RFC-compliant session behavior and attribute encoding/decoding, validated against real peers (FRR, BIRD, Junos, Arista EOS, Cisco IOS-XE/NX-OS where possible). A small feature set that works correctly is worth more than a large one that doesn't.

**Observable by default.** Prometheus metrics, structured logs, and machine-parseable errors everywhere. Operators should never have to guess what the daemon is doing or why a session flapped.

**Safe, boring, maintainable.** Minimal `unsafe` (ideally none). Fuzzed wire decoder. Explicit resource limits. No clever tricks — just correct, auditable Rust.

## Non-Goals (v1)

This is not a full routing suite replacement. rustbgpd will not implement OSPF, IS-IS, LDP, full VRF support, EVPN, or a complete policy language in v1. It will not attempt every BGP extension at once (Add-Path, GR, LLGR, etc.). The goal is a reliable, API-driven BGP speaker — not a kitchen sink.

## Target v1 Use Cases

**Route server mode (IX-style).** Many peers, simple policies, RIB dump and monitoring, API-driven automation.

**Programmable edge speaker.** Inject and withdraw prefixes programmatically. Minimal, reliable session handling.

**Later:** FlowSpec speaker mode (ties into prefixd lineage).

---

## Key Principles

**Split protocol core from I/O.** The codec and FSM must be testable without sockets. The FSM is a pure state machine that consumes messages and timer events, and produces messages and state transitions. It never touches a socket, never spawns a task, never calls `tokio::time` directly.

**Make invalid states unrepresentable.** Types and enums for message and attribute invariants. If the type system can prevent a bug, it should.

**Limits everywhere.** Max prefixes per peer, max attribute sizes, max message size, bounded channels. Every resource has an explicit cap, and exceeding it produces a structured error, not a crash.

**Interop test before "feature complete."** Correctness is measured by real peers in containers, not unit tests alone.

**Errors are first-class.** Every error condition — BGP NOTIFICATION, channel overflow, config rejection — produces a structured, machine-parseable event. Operators and automation get rich error codes, not strings.

---

## Architecture

### High-Level Components

**wire** (codec) — BGP message encode/decode: OPEN, KEEPALIVE, UPDATE, NOTIFICATION, ROUTE-REFRESH. Capability parsing/encoding (4-byte ASN, MP-BGP). NLRI and path attributes, starting with IPv4 unicast. This crate has zero internal dependencies — it is a pure codec library.

**Path attribute representation:** The wire crate uses a typed + raw hybrid model. Known attributes (ORIGIN, AS_PATH, NEXT_HOP, etc.) are decoded into typed Rust enums. Unknown attributes are preserved as `RawAttribute { flags: u8, type_code: u8, data: Bytes }` alongside typed ones. This is a hard architectural requirement — the daemon must be able to re-emit unknown optional transitive attributes byte-for-byte with the Partial bit set correctly. Dropping unknown transitive attributes is a protocol correctness bug that breaks interop with peers running newer BGP extensions.

```rust
// Illustrative API — types may evolve, but the typed + raw hybrid model is the commitment.
enum PathAttribute {
    Origin(Origin),
    AsPath(AsPath),
    NextHop(Ipv4Addr),
    LocalPref(u32),
    Med(u32),
    // ... other known attributes
    Unknown(RawAttribute),  // preserved raw bytes, re-emitted unchanged
}

struct RawAttribute {
    flags: u8,
    type_code: u8,
    data: Bytes,
}
```

**fsm** (session state machine) — RFC 4271 FSM: Idle, Connect, Active, OpenSent, OpenConfirm, Established. Timers modeled as inputs (not spawned internally). Negotiation result struct: negotiated caps, AFI/SAFI set, peer ASN, peer ID. Depends on `wire` types only.

**transport** — TCP connection management via tokio. Read loop → decode → FSM input. FSM output → encode → write loop. Backpressure via bounded queues. This is the only crate that touches async I/O. Depends on `wire` and `fsm`.

**rib** — AdjRibIn per neighbor, LocRib best-path selection, AdjRibOut computed per neighbor. Route objects keyed by (AFI, SAFI, prefix).

**policy** (v1 minimal) — Prefix allow/deny lists, max-prefix enforcement, simple attribute set/clear. Enough to be operationally useful, not enough to invite bikeshedding.

**api** — gRPC server exposing neighbor lifecycle, state queries, RIB queries, and route injection. Defined by `rustbgpd.proto` — our own types, not GoBGP's.

**telemetry** — Prometheus metrics endpoint, structured tracing logs.

### Dependency Graph

```
transport ──► fsm ──► wire
    │
    ▼
   rib ◄── policy
    │
    ▼
   api ──► telemetry
```

Hard rules:
- `wire` depends on nothing internal. It is a pure codec library.
- `fsm` depends on `wire` types (message enums, capability structs) and nothing else.
- `fsm` never imports `tokio`, never touches a socket, never spawns a task.
- `transport` is the adapter that owns TCP streams, runs async read/write loops, and feeds the FSM.
- `rib` and `policy` are independent of transport and fsm — they consume route update events.
- `api` is the orchestration layer that wires everything together.

### Runtime Model

One tokio task per neighbor session, internally split into reader and writer subtasks. A central RIB task processes updates from all sessions sequentially via a bounded `tokio::mpsc` channel. The API layer pushes commands into the neighbor manager and RIB via channels.

**Data flow:**

```
Session RX:  bytes → wire::decode → fsm::on_message → RibUpdate → RIB task
RIB:         computes best path → AdjRibOut updates → per-neighbor TX channels
Session TX:  AdjRibOut events → wire::encode → bytes
API:         gRPC call → command → neighbor manager / RIB task
```

**Control plane ownership — where is truth:**
- **Neighbor manager** is authoritative for desired configuration (which peers should exist, their parameters).
- **FSM** is authoritative for session state (what state each peer is actually in).
- **RIB** is authoritative for routing state (what routes exist, which is best).
- **API** is an adapter layer. It translates gRPC requests into commands and queries against the authoritative components. It is never the source of truth for any state.

**RIB concurrency (v1):** A single RIB task behind a bounded channel is correct for IPv4 unicast. Sessions send `RibUpdate` messages; the RIB processes them sequentially; best-path results fan out to per-neighbor AdjRibOut channels. The sharding seam is at the channel boundary — when a second address family is added (IPv6, FlowSpec), split to one RIB task per AFI/SAFI without changing session code.

**RIB snapshot model:** Snapshots are generation-based, not deep copies. The RIB stores immutable per-prefix route sets behind `Arc`. A snapshot is a `(generation_id, Arc<RibView>)` handle. Paginated gRPC queries iterate that handle. The active RIB can advance generations without blocking readers. This avoids O(n) cloning on every query — at 10M routes, a full clone per paginated request is a non-starter. Stale snapshots are dropped when the last reader releases its `Arc` handle.

**Redesign triggers (instrumented from day one):**
- `rib_update_latency_p99` — per-batch processing time. If p99 exceeds 10ms under sustained load, evaluate sharding or batch coalescing.
- `rib_channel_backpressure_total` — counter of sends that block because the RIB channel is full. Any non-zero sustained rate means session tasks are stalling, which risks cascading flaps.
- `adjribout_channel_drops_total` — counter of AdjRibOut events dropped due to slow peers. Non-zero means a peer is falling behind and may receive stale routing state.
- `rib_snapshot_generation_lag` — difference between current generation and oldest live snapshot. High lag means a slow consumer is pinning old state in memory.

These metrics exist from Milestone 0. The threshold for triggering a redesign conversation is: sustained p99 RIB latency above 10ms, or any backpressure-induced session flap in the interop test suite.

---

## gRPC API

### Design Decision: Own Our Protos

rustbgpd defines its own `.proto` files from day one. No GoBGP proto reuse.

Rationale: GoBGP's protos carry Go-specific patterns and years of accumulated feature baggage. Anyone writing automation against rustbgpd is writing new client code regardless. Our protos should map 1:1 to Rust domain types — `NeighborState` as a proper enum, AFI/SAFI as typed enums, not integers. A GoBGP-compat adapter can be written later if anyone actually asks for it.

### Service Architecture

Five separate gRPC services, not one. This forces API boundary clarity, prevents god-service creep, enables future permission scoping (e.g., monitoring gets read-only RIB access, cannot inject routes), and mirrors internal architecture.

```protobuf
// Global daemon configuration and identity
service GlobalService {
  rpc GetGlobal(GetGlobalRequest)     returns (GlobalState);
  rpc SetGlobal(SetGlobalRequest)     returns (SetGlobalResponse);
}

// Neighbor lifecycle and state
service NeighborService {
  rpc AddNeighbor(AddNeighborRequest)       returns (AddNeighborResponse);
  rpc DeleteNeighbor(DeleteNeighborRequest)  returns (DeleteNeighborResponse);
  rpc ListNeighbors(ListNeighborsRequest)    returns (ListNeighborsResponse);
  rpc GetNeighborState(GetNeighborStateRequest) returns (NeighborState);
  rpc EnableNeighbor(EnableNeighborRequest)  returns (EnableNeighborResponse);
  rpc DisableNeighbor(DisableNeighborRequest) returns (DisableNeighborResponse);
}

// RIB queries — paginated unary for point-in-time, streaming for live watch
service RibService {
  // Paginated point-in-time queries (snapshot at start of iteration)
  rpc ListReceivedRoutes(ListRoutesRequest)   returns (ListRoutesResponse);
  rpc ListBestRoutes(ListRoutesRequest)       returns (ListRoutesResponse);
  rpc ListAdvertisedRoutes(ListRoutesRequest) returns (ListRoutesResponse);

  // Live update streams (backpressure via bounded channel; slow consumers get dropped)
  rpc WatchRoutes(WatchRoutesRequest)         returns (stream RouteEvent);
}

// Route injection and withdrawal
service InjectionService {
  rpc AddPath(AddPathRequest)       returns (AddPathResponse);
  rpc DeletePath(DeletePathRequest) returns (DeletePathResponse);
}

// Daemon control and health
service ControlService {
  rpc Shutdown(ShutdownRequest)     returns (ShutdownResponse);
  rpc GetHealth(HealthRequest)      returns (HealthResponse);
  rpc GetMetrics(MetricsRequest)    returns (MetricsResponse);
}
```

### RIB Query Model

**Paginated unary (default).** `ListRoutesRequest` includes a `page_size` (max results per page, capped server-side) and an opaque `page_token` (cursor). The RIB snapshots at the start of the first page request; subsequent pages iterate the same snapshot for consistency. No lock held on the RIB task — the snapshot is a read-only copy.

```protobuf
message ListRoutesRequest {
  string neighbor_address = 1;      // filter by peer (empty = all)
  AddressFamily afi_safi = 2;       // address family filter
  uint32 page_size = 3;             // max results (server-capped at 10000)
  string page_token = 4;            // opaque cursor for next page
}

message ListRoutesResponse {
  repeated Route routes = 1;
  string next_page_token = 2;       // empty = no more pages
  uint64 total_count = 3;           // total matching routes (for UI/progress)
}
```

**Streaming watch (opt-in).** `WatchRoutes` returns a live stream of `RouteEvent` messages (add, withdraw, best-path change). Backpressure via bounded server-side channel — if the consumer falls behind, the stream is terminated with a `RESOURCE_EXHAUSTED` status and the client must reconnect. This prevents a slow consumer from becoming a DoS vector.

**Watch stream semantics:**
- **Delivery guarantee:** Best effort. Events may be dropped if the consumer is slow. This is not an "at least once" stream — it is a live feed with finite buffer.
- **Ordering:** Ordered per peer event queue, not globally. Events from the same peer arrive in order; events across peers may interleave arbitrarily.
- **Reconnect model:** No cursor or resume token. On reconnect, clients issue a paginated snapshot query (`ListBestRoutes` or `ListReceivedRoutes`) to establish current state, then resume watching for deltas. This is simple, correct, and avoids server-side cursor tracking overhead.
- **Payload scope:** RouteEvent contains route identifiers (prefix, peer, AFI/SAFI) and minimal metadata (event type, timestamp). Full route details (attributes, path) are retrieved via `List*` RPCs. This keeps the stream lightweight and prevents accidental performance traps from fat streaming payloads.

### Error Model

Errors are domain-typed, not collapsed into BGP semantics. gRPC responses use proper status codes with a `ErrorDetail` detail payload:

```protobuf
message ErrorDetail {
  oneof kind {
    BgpProtocolError bgp = 1;
    ResourceLimitError resource = 2;
    ConfigError config = 3;
  }
}

message BgpProtocolError {
  uint32 error_code = 1;        // RFC 4271 §4.5 error code
  uint32 error_subcode = 2;     // RFC 4271 §4.5 error subcode
  string description = 3;       // human-readable description
  string peer_address = 4;      // peer involved
}

message ResourceLimitError {
  string limit_name = 1;        // e.g., "max_prefixes", "channel_capacity"
  uint64 current_value = 2;     // current usage
  uint64 max_value = 3;         // configured limit
  string peer_address = 4;      // peer involved, if applicable
}

message ConfigError {
  string field_path = 1;        // e.g., "neighbors[0].hold_time"
  string message = 2;           // validation failure description
  string provided_value = 3;    // what was given
}
```

No generic `INTERNAL` with a string. Machine-parseable errors for every failure path. Each error domain carries its own context fields.

---

## Operational Behavior

### Configuration Model

The boot config file (TOML) provides initial state. At startup, the daemon loads the file, translates it into the equivalent of gRPC commands, and applies them. From that point forward, gRPC owns runtime state.

**The contract:**
- Peers can be added, removed, enabled, and disabled at runtime via gRPC. Zero restarts required.
- Changes made via gRPC live until the daemon restarts, at which point the file is reloaded.
- Config persistence (writing gRPC changes back to the file) is a v2 feature.
- If the file changes on disk, a restart picks up the new file state.

### Minimal Config Example

```toml
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "peer-frr-lab"
hold_time = 90
max_prefixes = 100_000

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65001
description = "ibgp-reflector"
hold_time = 90

[[neighbors.policy]]
import = "allow-all"
export = "deny-all"
```

### Graceful Shutdown

Shutdown is triggered by SIGTERM or by the `Shutdown` gRPC RPC:

1. Stop accepting new gRPC commands.
2. Send NOTIFICATION/Cease (Administrative Shutdown, subcode 2) to every established peer.
3. Wait up to 5 seconds for TCP sends to flush. Hard-drop after the timeout — don't hang.
4. Drop all sessions and close listener sockets.
5. Flush final telemetry (last metrics scrape, final log entries).
6. Exit.

No state persistence in v1. Restart is a clean boot from the config file. This is a deliberate choice — stateless restart is simpler to reason about and debug.

### Error and Event Philosophy

Every operationally significant event emits a structured log entry with typed fields:

```json
{
  "event": "notification_sent",
  "peer": "198.51.100.1",
  "code": 3,
  "subcode": 1,
  "description": "UPDATE Message Error / Malformed Attribute List",
  "timestamp": "2026-02-27T14:30:00Z"
}
```

```json
{
  "event": "session_state_change",
  "peer": "198.51.100.1",
  "from": "OpenConfirm",
  "to": "Established",
  "timestamp": "2026-02-27T14:30:01Z"
}
```

Categories of structured events:
- Session state transitions (every FSM transition, not just Established)
- NOTIFICATIONs sent and received (with full code/subcode)
- RIB changes (route learned, route withdrawn, best-path change)
- Policy actions (route filtered, max-prefix exceeded)
- Resource limit hits (channel full, prefix limit reached)
- gRPC command results (neighbor added, path injected, errors)

---

## Protocol Scope and Milestones

### Milestone 0: "Establish"

Implement OPEN, KEEPALIVE, NOTIFICATION. FSM transitions and timer handling. Session reaches Established and stays there.

**Exit criteria:**
- Establish and hold for 30+ minutes with steady keepalives against FRR (container) and BIRD (container).
- Survive peer restart: peer goes down, comes back, session re-establishes cleanly.
- Survive TCP reset: unexpected connection drop, FSM returns to Idle/Active, retries on schedule.
- Correct NOTIFICATION on malformed OPEN (wrong ASN, bad hold time, unsupported capability).
- Prometheus metrics capture all state transitions and flap events.
- Structured log events for every FSM transition.

### Attribute Validation Matrix

UPDATE processing is where most BGP implementations accumulate subtle bugs. rustbgpd validates every attribute against RFC 4271 with explicit, auditable checks.

| Validation | RFC Reference | Behavior on Failure |
|---|---|---|
| Mandatory attributes present (ORIGIN, AS_PATH, NEXT_HOP for eBGP) | RFC 4271 §5.1.2 | NOTIFICATION (3, 3) — Missing Well-known Attribute |
| No duplicate attributes in a single UPDATE | RFC 4271 §5 | NOTIFICATION (3, 1) — Malformed Attribute List |
| Attribute flags match type (well-known, transitive, etc.) | RFC 4271 §4.3 | NOTIFICATION (3, 4) — Attribute Flags Error |
| Attribute ordering (well-known before optional) | RFC 4271 §4.3 | Accept out-of-order but log; strict mode configurable |
| AS_PATH segment type valid (AS_SET, AS_SEQUENCE) | RFC 4271 §4.3 | NOTIFICATION (3, 11) — Malformed AS_PATH |
| AS_PATH length consistent with segment encoding | RFC 4271 §4.3 | NOTIFICATION (3, 11) — Malformed AS_PATH |
| 4-byte ASN handling (AS_TRANS mapping) | RFC 6793 | Map AS_TRANS correctly; reject inconsistent mappings |
| NEXT_HOP is valid IP, not 0.0.0.0, not multicast | RFC 4271 §5.1.3 | NOTIFICATION (3, 8) — Invalid NEXT_HOP Attribute |
| ORIGIN value is valid (IGP, EGP, INCOMPLETE) | RFC 4271 §4.3 | NOTIFICATION (3, 6) — Invalid ORIGIN Attribute |
| Attribute length does not exceed UPDATE length | RFC 4271 §4.3 | NOTIFICATION (3, 1) — Malformed Attribute List |
| Total path attributes length consistent with UPDATE length | RFC 4271 §4.3 | NOTIFICATION (3, 1) — Malformed Attribute List |
| Unrecognized well-known attribute | RFC 4271 §5 | NOTIFICATION (2, 7) — Unrecognized Well-known Attribute |
| Unrecognized optional non-transitive attribute | RFC 4271 §5 | Silently ignore (do NOT drop silently — emit structured event) |
| Unrecognized optional transitive attribute | RFC 4271 §5 | Pass through, set Partial bit (see policy below) |
| Attribute exceeds configured max size | rustbgpd limit | NOTIFICATION (3, 1) + structured event |

Every validation failure produces a structured log event with the peer address, attribute type code, raw bytes (truncated), and the RFC section violated. No silent drops.

#### Partial Bit Policy

When rustbgpd re-advertises an unrecognized optional transitive attribute, it ensures the Partial bit (flag 0x20) is set. The attribute bytes and all other flags are preserved unchanged — only the Partial bit is OR'd. If the Partial bit was already set on receipt, this is a no-op.

Rationale: rustbgpd has not validated the semantics of the attribute, so marking it Partial is the correct conservative signal to downstream peers. This matches the behavior of most production implementations and avoids ambiguity about whether the daemon "understood" the attribute. This is not configurable in v1.

### Milestone 1: "Hear"

Decode UPDATEs. Support IPv4 unicast NLRI. Support attributes: ORIGIN, AS_PATH (2-byte and 4-byte as negotiated), NEXT_HOP, LOCAL_PREF (iBGP), MED (optional, low effort). Store in Adj-RIB-In. Expose via `ListReceivedRoutes`.

**Exit criteria:**
- RIB dump matches peer's advertised routes for a controlled prefix set.
- Fuzz harness in CI for the UPDATE decoder (at least smoke-level coverage).
- Structured events for every route learned and withdrawn.

### Milestone 2: "Decide" `[complete]`

Loc-RIB best-path selection — minimal but deterministic. The comparison function is a **total ordering**: it must never return equality for distinct paths (from distinct peers).

Best-path rules (implemented), applied in order:
1. Highest LOCAL_PREF (default 100 if absent)
2. Shortest AS_PATH (AS_SET counts as 1, per RFC 4271 §9.1.2.2)
3. Lowest ORIGIN (IGP < EGP < INCOMPLETE)
4. Lowest MED (deterministic — always-compare across all peers, not just same-AS)
5. Lowest peer address (final disambiguator — guarantees strict ordering)

**Implementation choices (ADR-0014):**
- `best_path_cmp()` is a standalone function, not `Ord` on `Route`. Domain-specific ordering doesn't belong as a trait impl — multiple orderings may be needed.
- Deterministic MED (always-compare) matches GoBGP default. Simpler and avoids ordering sensitivity.
- eBGP/iBGP and router-id tiebreakers are deferred to M3 when outbound advertisement requires the full decision process.
- `LocRib` lives inside `RibManager` — same single-task ownership pattern, no new locks.
- Incremental recompute: only prefixes affected by each update are re-evaluated.

Exposed via `ListBestRoutes` gRPC endpoint with offset pagination.

**Exit criteria:**
- Deterministic outcomes for all decision inputs, verified by property tests (antisymmetry, transitivity, totality).
- Stable best-path selection with multiple paths from multiple peers.
- Structured debug events for best-path changes.
- 248 tests pass, clippy clean, fmt clean.

### Milestone 3: "Speak"

Inject and withdraw routes via gRPC (`AddPath` / `DeletePath`). Build Adj-RIB-Out per neighbor. Advertise to peers, withdrawals work correctly. v1 policy: import/export allow/deny lists + max-prefix guard.

**Exit criteria:**
- A client can programmatically announce a prefix and verify it appears on the peer.
- Withdrawals propagate correctly.
- Max-prefix enforcement drops session with NOTIFICATION when exceeded.
- Resource limits enforced and observable via metrics.

### Milestone 4: "Route Server Mode"

Many peers, no transit behavior by default. Per-peer import and export filters. Simple communities pass-through (optional). RIB scaling evaluation.

**Exit criteria:**
- 50+ peers in a containerlab scenario, stable under churn.
- Route reflection behavior explicitly not supported in v1 (document this).
- Per-peer policy enforcement verified end-to-end.

---

## Testing and Quality

### Interop Test Matrix

Primary targets (containerlab-based, run in CI):
- FRR (bgpd)
- BIRD
- GoBGP (as peer)

Stretch targets (lab environments):
- Junos vMX/vPTX
- Arista cEOS
- Cisco (if available)

containerlab is the test harness — not "where feasible," but the default. Every interop scenario is a reproducible topology file.

### Fuzzing

libFuzzer harnesses for:
- Message decoding (all message types)
- Attribute decoding (all supported attributes)
- NLRI parsing (IPv4 unicast)

Short fuzz runs on every PR. Extended fuzz on nightly CI schedule.

### Property Tests

- `encode(decode(x)) == x` roundtrip invariants for all valid message types.
- Decoder rejects: length mismatches, invalid attribute flags, truncated NLRI, oversized attributes beyond configured limits.
- FSM property: no invalid state transitions for any sequence of valid inputs.

### CI Pipeline

- Unit tests (every PR)
- Fuzz smoke — short run (every PR)
- Extended fuzz (nightly)
- Interop tests via containerlab (every PR, against FRR and BIRD at minimum)
- Clippy + deny(warnings) + cargo deny for dependency audit

---

## Security Posture

This section defines the security stance for rustbgpd. Not all items are v1 implementations, but the posture is established now so that design decisions don't foreclose security later.

### Session Authentication

**Supported platforms (v1): Linux (x86_64, aarch64).** TCP MD5, GTSM via `IP_TTL`, and certain socket options are Linux-specific. macOS and BSD may work for development builds but are not tested or supported targets. This is stated explicitly to prevent bug reports about platform-specific socket behavior.

**TCP MD5 (RFC 2385):** Supported in v1. This is table stakes for any BGP daemon deployed in production — most peers will require it. Implemented via `setsockopt(TCP_MD5SIG)` on the listener and per-peer outbound sockets. Linux only.

**TCP-AO (RFC 5925):** Not v1. Acknowledged as the superior mechanism. Design will not preclude it — the transport layer abstracts authentication as a per-peer config option, so TCP-AO can be added without architectural changes. Documented as a roadmap item.

**GTSM (RFC 5082):** Supported in v1 as a configurable option (`ttl_security = true` per neighbor). Sets `IP_TTL` to 255 on outbound and checks inbound TTL >= 254. Simple, effective, and prevents most remote session hijacking.

### Connection Rate Limiting

- Max inbound TCP connections per source IP: configurable, default 5 per minute.
- Max total pending connections: configurable, default 100.
- Connections from unconfigured peers are dropped immediately after TCP accept — no BGP processing.
- All rate limit events produce structured log entries.

### Malformed Message Handling Philosophy

- **Never panic on malformed input.** Any input from the network is untrusted. Panics on malformed BGP messages are security vulnerabilities.
- **Always NOTIFICATION.** Every malformed message produces the correct NOTIFICATION error code per RFC 4271, followed by session teardown. No silent drops, no "log and ignore."
- **Always log.** Every malformed message produces a structured event with peer address, message type, error description, and truncated raw bytes for forensic analysis.
- **Fuzz everything.** The wire decoder is the attack surface. It runs under continuous fuzzing in CI.

### Memory Exhaustion Guards

- All channels are bounded. No unbounded queues anywhere in the system.
- Per-peer prefix limits enforced at Adj-RIB-In insertion. Exceeding the limit produces NOTIFICATION (Cease, Maximum Number of Prefixes Reached) and session teardown.
- Total route limit enforced at the RIB level (see Global Route Limit Policy below).
- UPDATE attribute size limits enforced at decode time. Oversized attributes are rejected before allocation.
- gRPC request size limits enforced by tonic configuration.

### Global Route Limit Policy

When `max_total_routes` is exceeded, the offending session is torn down with NOTIFICATION Cease (Out of Resources, subcode 4) as defined in RFC 4486 §3. The structured event includes the peer address, the route that triggered the limit, and the current total count.

**Interop note:** Cease subcodes are defined in RFC 4486, not RFC 4271. Some older implementations may not recognize subcode 4. If interop testing reveals a peer that rejects unknown Cease subcodes, the fallback is generic Cease (code 6, subcode 0). This is documented in INTEROP.md per peer.

This is a deliberate choice. The alternative — partial acceptance (reject individual prefixes while keeping the session established) — introduces per-UPDATE partial semantics that generate subtle correctness bugs and are difficult to reason about operationally. Option A (tear down the session) is explainable, safe, and what operators expect.

If the global limit is hit, it means either the limit is configured too low or the peer is sending more routes than expected — both conditions warrant human attention, not silent partial behavior.

### gRPC Security (v1)

- gRPC listens on a configurable address (default: localhost only).
- TLS for gRPC: optional in v1, strongly recommended for non-localhost. mTLS is a roadmap item.
- No authentication/authorization model in v1 — the service split (five separate gRPC services) is designed to support per-service auth policies when added.

---

## Performance and Limits

### Configurable Limits (with defaults)

| Limit | Default | Notes |
|---|---|---|
| Max message size | 4096 bytes | RFC 4271 strict; NOTIFICATION + disconnect on violation |
| Max attributes per UPDATE | 256 | Safety bound |
| Max prefixes per neighbor | 1,000,000 | NOTIFICATION on exceed |
| Max total routes | 10,000,000 | Backpressure, not crash |
| Bounded channel size | 4096 | Per-session and RIB channels |
| Connect retry interval | 30s | RFC 4271 default |
| Hold time | 90s | Negotiated per-peer |

All limits are configurable via TOML and overridable per-peer via gRPC.

---

## Repository Layout

```
rustbgpd/
  src/
    main.rs             # binary entry point, wiring, config loading
  crates/
    wire/               # BGP codec (zero internal deps)
    fsm/                # RFC 4271 FSM + timer model (depends on wire)
    rib/                # RIB data structures and best-path
    policy/             # simple filters
    api/                # gRPC server, tonic bindings
    telemetry/          # metrics + structured logging
    transport/          # tokio TCP, read/write loops, session runtime
  proto/
    rustbgpd.proto      # our own proto definitions
  docs/
    DESIGN.md           # this document
    RFC_NOTES.md        # implementation notes keyed to RFC sections
    INTEROP.md          # interop test results and known behaviors
  tests/
    interop/            # containerlab topologies and test scripts
    fuzz/               # fuzz harnesses
  Cargo.toml            # workspace root
```

`cargo run` builds and runs the daemon directly. Everything under `crates/` is the library layer.

---

## Roadmap Beyond v1

- MP-BGP extensions (IPv6 unicast)
- Communities and extended communities
- FlowSpec speaker mode (prefixd lineage)
- BMP exporter
- RPKI validation integration (RTR client)
- Graceful restart (only after core stability)
- Plugin-based policy engine (WASM or embedded DSL) — only after core stability
- Config persistence (gRPC changes written back to TOML)

---

## Compatibility and Behavior Matrix

This matrix tracks every protocol behavior: its RFC basis, implementation status, and interop validation. It is the source of truth for what rustbgpd does and does not do, and it stays current as the project evolves. Milestone targets (M0–M4) indicate planned implementation phase — not current status.

| Behavior | RFC | Target Milestone | Interop Targets | Notes |
|---|---|---|---|---|
| OPEN / KEEPALIVE / NOTIFICATION | 4271 §4.2–4.5 | M0 | FRR, BIRD | — |
| FSM state transitions | 4271 §8 | M0 | FRR, BIRD | Includes retry and error paths |
| 4-byte ASN capability | 6793 | M0 | FRR, BIRD | AS_TRANS mapping |
| UPDATE decode (IPv4 unicast) | 4271 §4.3 | M1 | FRR, BIRD | — |
| ORIGIN attribute | 4271 §5.1.1 | M1 | FRR, BIRD | — |
| AS_PATH attribute | 4271 §5.1.2 | M1 | FRR, BIRD | 2-byte and 4-byte |
| NEXT_HOP attribute | 4271 §5.1.3 | M1 | FRR, BIRD | Validation per RFC |
| LOCAL_PREF attribute | 4271 §5.1.5 | M1 | FRR, BIRD | iBGP only |
| MED attribute | 4271 §5.1.4 | M1 | FRR, BIRD | Optional, same-AS comparison configurable |
| Unknown transitive attr pass-through | 4271 §5 | M1 | FRR | Partial bit set, raw bytes preserved |
| Best-path selection | 4271 §9.1.2 | M2 | FRR, BIRD | Total ordering, see decision rules |
| UPDATE encoding / Adj-RIB-Out | 4271 §9.2 | M3 | FRR, BIRD | — |
| Route injection via gRPC | rustbgpd | M3 | FRR | — |
| Max-prefix enforcement | rustbgpd | M3 | FRR | NOTIFICATION Cease |
| TCP MD5 authentication | 2385 | M3 | FRR | Linux only |
| GTSM (TTL security) | 5082 | M3 | FRR | Configurable per-peer |
| Route server mode (many peers) | — | M4 | FRR, BIRD, GoBGP | No transit by default |
| MP-BGP (IPv6 unicast) | 4760 | Post-v1 | — | Roadmap |
| Communities | 1997 | Post-v1 | — | Roadmap |
| Extended communities | 4360 | Post-v1 | — | Roadmap |
| FlowSpec | 8955 | Post-v1 | — | Roadmap (prefixd lineage) |
| Graceful restart | 4724 | Post-v1 | — | Roadmap |
| TCP-AO | 5925 | Post-v1 | — | Roadmap |
| BMP exporter | 7854 | Post-v1 | — | Roadmap |
| RPKI / RTR client | 8210 | Post-v1 | — | Roadmap |

This matrix is updated with every milestone. "Interop Tested" means validated in the containerlab CI suite, not "someone tried it once."

---

## Project Governance

### Supported Platforms

- **v1:** Linux (x86_64, aarch64). These are the only tested and supported targets.
- macOS and BSD may compile and run for development purposes but are not CI-tested. Platform-specific socket options (TCP_MD5SIG, IP_TTL for GTSM) are Linux-only.
- Windows is not supported.

### Compatibility Targets

- **Must not break:** FRR and BIRD. These are tested in CI on every PR via containerlab.
- **Should not break:** GoBGP (as peer). Tested in CI but failures are investigated, not gating.
- **Best effort:** Junos, Arista cEOS, Cisco. Lab-tested when available, not CI-gated.

### Proto Stability

gRPC proto definitions are treated with semver discipline:
- **Pre-1.0:** Breaking changes allowed with a changelog entry and migration notes.
- **Post-1.0:** No breaking changes to existing RPCs or message fields. New fields are additive. New RPCs are additive. Deprecation requires a full minor version cycle before removal.

### Release Process

Milestone-based releases. Each milestone (M0–M4) is a tagged release with:
- Passing CI (unit tests, fuzz smoke, interop)
- Updated compatibility matrix
- Updated CHANGELOG
- Migration notes if protos changed

### Contribution Policy

- **Bug fixes and test improvements:** PR directly.
- **New protocol behavior:** Requires an issue with RFC citation and proposed interop test plan before implementation.
- **Architectural changes:** Requires design discussion in an issue or discussion thread. No surprise features.
- **All PRs** must pass CI, including interop tests, and must not violate any design constraint.

### Security Policy

- Vulnerabilities are reported via email (address TBD) or GitHub security advisories.
- Critical vulnerabilities (remote crash, session hijack) are patched and released within 72 hours of confirmation.
- The wire decoder is the primary attack surface and runs under continuous fuzzing.

---

## Positioning

rustbgpd is:
- **API-first BGP control plane** — gRPC is the primary interface, not CLI
- **Correctness and observability focused** — tested against real peers, observable by default
- **Rust-native, GoBGP-shaped** — familiar operating model, memory-safe implementation
- **Not a kitchen sink routing suite** — does one thing well

---

## Design Constraints We Will Not Violate

These are invariants. They are not negotiable, not deferrable, and not subject to "just this once" exceptions. Every contributor and every PR is measured against them.

1. **The FSM is pure and testable without sockets.** It takes message and timer inputs, produces message and state outputs. It never imports tokio, never spawns a task, never touches a file descriptor.

2. **The wire crate remains independently usable.** It has zero internal dependencies. Anyone should be able to `cargo add rustbgpd-wire` and use it as a standalone BGP codec library without pulling in the rest of the daemon.

3. **No unbounded channels anywhere.** Every channel in the system has an explicit capacity. Backpressure is a feature, not a bug.

4. **No silent attribute drops.** If an attribute is ignored, filtered, or rejected, a structured event is emitted. Operators must be able to explain every routing decision from logs alone.

5. **No panics on malformed input.** Any input from the network is untrusted. A panic on malformed BGP data is a denial-of-service vulnerability. The wire decoder handles all malformed input gracefully with `Result` types.

6. **All protocol violations produce structured events.** Every NOTIFICATION sent or received, every malformed message, every RFC violation detected — all produce machine-parseable structured log entries with peer address, error classification, and context.

7. **Resource limits are enforced, not advisory.** Max prefixes, max message size, max channel depth — these are hard limits that produce defined behavior (NOTIFICATION, backpressure, rejection) when exceeded. Never silently ignored.

8. **Interop is tested, not assumed.** No feature is considered complete until it has been validated against at least FRR and BIRD in a containerlab topology. Unit tests are necessary but not sufficient.
