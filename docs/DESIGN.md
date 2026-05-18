# rustbgpd — Design Document

A modern, API-first BGP daemon in Rust, inspired by GoBGP's ergonomics and "drive it via gRPC" operating model.

**Author:** lance0
**Status:** pre-1.0 hardening — P0/P1/P2/P2.5 complete, publishing prep
**Last updated:** 2026-05-13

---

## Goals

**API-first routing control plane.** gRPC is the primary interface for all configuration and operations. The config file is a convenience for initial boot state — once the daemon is running, gRPC owns the truth. Clients in Python, Go, Rust, and Node should have a clean, typed experience from day one.

**Interop correctness over feature breadth.** RFC-compliant session behavior and attribute encoding/decoding, validated against real peers (FRR, BIRD, Junos, Arista EOS, Cisco IOS-XE/NX-OS where possible). A small feature set that works correctly is worth more than a large one that doesn't.

**Observable by default.** Prometheus metrics, structured logs, and machine-parseable errors everywhere. Operators should never have to guess what the daemon is doing or why a session flapped.

**Safe, boring, maintainable.** Minimal `unsafe` (one module for TCP MD5/GTSM socket options). Fuzzed wire decoder. Explicit resource limits. No clever tricks — just correct, auditable Rust.

## Non-Goals (v1)

This is not a full routing suite replacement. rustbgpd will not implement OSPF, IS-IS, LDP, full VRF support, or a complete policy language in v1. It will not attempt every BGP extension at once (Confederation, VPNv4/v6, MPLS-EVPN encap, etc.). The goal is a reliable, API-driven BGP speaker — not a kitchen sink.

## Target v1 Use Cases

**Route server mode (IX-style).** Many peers, simple policies, RIB dump and monitoring, API-driven automation.

**Programmable edge speaker.** Inject and withdraw prefixes programmatically. Minimal, reliable session handling.

**EVPN Route Reflector (VXLAN-EVPN DC fabric).** iBGP route reflector for Type 1-5 RFC 7432 routes between VTEPs; control plane only, VTEPs handle their own DF election and data-plane encapsulation. See ADR-0050.

**EVPN VTEP — bidirectional (Phase 2 Gates 7a + 7b + 7b+1 + 7b+2 + 7c).** Local EVI/VNI domain types (`crates/evpn`) and an `[[evpn_instances]]` TOML schema with a read-only `EvpnService.ListEvpnInstances` gRPC surface (Gate 7a, ADR-0052). Linux kernel reconciliation programs remote-MAC FDB entries from received Type 2 routes (Gate 7b, ADR-0054). Local-MAC origination subscribes to `RTNLGRP_NEIGH` and emits Type 2 routes per RFC 7432 §15.1 mobility sequencing, plus one Type 3 IMET per L2VNI carrying the PMSI Tunnel attribute (Gate 7b+1, ADR-0055). `advertise_svi_mac` originates a Type 2 for the bridge's own MAC (RFC 9135 §6.1) on instance-Ready by surfacing the bridge link-layer address through `InstanceDataplaneStatus.bridge_mac`; `sticky_macs` (ADR-0056) marks origination with the RFC 7432 §15.4 sticky bit. Gate 7b+2 closes the MAC+IP path: with `bridge link set ... neigh_suppress on`, ARP/ND-snooped `(IP, MAC)` bindings on the bridge's neighbour table drive MAC+IP Type 2 origination under the FRR-style replace model — one Type 2 per MAC at any time, `IpAdded` upgrades from MAC-only to MAC+IP, last `IpRemoved` downgrades back. Mobility events propagate sub-second via the EVPN-keyed `EvpnRouteEvent` broadcast in `crates/rib`; the 5 s `QueryEvpnRoutes` poll stays as a `Lagged` / cold-start backstop (Gate 7c). RR-only deployments (empty `[[evpn_instances]]`) spawn no kernel-facing tasks for either direction.

**Later:** Duplicate-MAC remote-route processing and dataplane loop-protection (local-origin suppression shipped in ADR-0055 §9), production-default multi-homing enforcement flip for `apply_bum_enforcement` / `apply_aliasing_ecmp` (the Gate 8b MAC-churn 24 h soak passed 2026-05-16; the default flip is a separate release decision), RFC 9135 overlay-index IRB (Gate 9 ships the Interface-less variant per RFC 9136 §4.4.2 / ADR-0058), auto-derived Route Targets (RFC 8365 §5.1.2.1), VPNv4/v6, MPLS-EVPN encap.

---

## Key Principles

**Split protocol core from I/O.** The codec and FSM must be testable without sockets. The FSM is a pure state machine that consumes messages and timer events, and produces messages and state transitions. It never touches a socket, never spawns a task, never calls `tokio::time` directly.

**Make invalid states unrepresentable.** Types and enums for message and attribute invariants. If the type system can prevent a bug, it should.

**Limits everywhere.** Max prefixes per peer, max attribute sizes, max message size, explicit queueing policy. Every resource has a defined behavior under pressure, and exceeding limits produces a structured error, not a crash.

**Interop test before "feature complete."** Correctness is measured by real peers in containers, not unit tests alone.

**Errors are first-class.** Every error condition — BGP NOTIFICATION, channel overflow, config rejection — produces a structured, machine-parseable event. Operators and automation get rich error codes, not strings.

---

## Architecture

For crate dependency graph, runtime model, ownership model, data flow, lifecycle flows, backpressure model, and the "where to change X" guide, see [ARCHITECTURE.md](../ARCHITECTURE.md).

### Key Design Choices

**Path attribute representation:** The wire crate uses a typed + raw hybrid model. Known attributes (ORIGIN, AS_PATH, NEXT_HOP, etc.) are decoded into typed Rust enums. Unknown attributes are preserved as `RawAttribute { flags, type_code, data: Bytes }` alongside typed ones. This is a hard architectural requirement — the daemon must re-emit unknown optional transitive attributes byte-for-byte with the Partial bit set correctly. Dropping unknown transitive attributes is a protocol correctness bug.

**RIB snapshot model:** Snapshots are generation-based, not deep copies. The RIB stores immutable per-prefix route sets behind `Arc`. Paginated gRPC queries iterate a snapshot handle while the active RIB advances generations without blocking readers. This avoids O(n) cloning on every query.

**Redesign triggers (instrumented from day one):**
- `rib_update_latency_p99` — if p99 exceeds 10ms under sustained load, evaluate sharding or batch coalescing.
- `rib_channel_backpressure_total` — any non-zero sustained rate means session tasks are stalling.
- `adjribout_channel_drops_total` — non-zero means a peer is falling behind.
- `rib_snapshot_generation_lag` — high lag means a slow consumer is pinning old state.

The threshold for triggering a redesign conversation is: sustained p99 RIB latency above 10ms, or any backpressure-induced session flap in the interop test suite.

---

## gRPC API

### Design Decision: Own Our Protos

rustbgpd defines its own `.proto` files from day one. No GoBGP proto reuse.

Rationale: GoBGP's protos carry Go-specific patterns and years of accumulated feature baggage. Anyone writing automation against rustbgpd is writing new client code regardless. Our protos should map 1:1 to Rust domain types — `NeighborState` as a proper enum, AFI/SAFI as typed enums, not integers. A GoBGP-compat adapter can be written later if anyone actually asks for it.

### Service Architecture

Nine separate gRPC services (Global, Neighbor, Policy, PeerGroup, Rib, Event, Injection, Control, Evpn), not one. This forces API boundary clarity, prevents god-service creep, enables permission scoping (for example, read-only listeners for monitoring), and mirrors internal architecture.

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
  rpc SoftResetIn(SoftResetInRequest)        returns (SoftResetInResponse);
}

// RIB queries — paginated unary for point-in-time, streaming for live watch
service RibService {
  rpc ListReceivedRoutes(ListRoutesRequest)   returns (ListRoutesResponse);
  rpc ListBestRoutes(ListRoutesRequest)       returns (ListRoutesResponse);
  rpc ListAdvertisedRoutes(ListRoutesRequest) returns (ListRoutesResponse);
  rpc ExplainAdvertisedRoute(ExplainAdvertisedRouteRequest) returns (ExplainAdvertisedRouteResponse);
  rpc ExplainBestPath(ExplainBestPathRequest) returns (ExplainBestPathResponse);
  rpc ListRouteEvents(ListRouteEventsRequest) returns (ListRouteEventsResponse);
  rpc WatchRoutes(WatchRoutesRequest)         returns (stream RouteEvent);
  rpc ListFlowSpecRoutes(ListFlowSpecRequest) returns (ListFlowSpecResponse);
}

// Route injection and withdrawal
service InjectionService {
  rpc AddPath(AddPathRequest)       returns (AddPathResponse);
  rpc DeletePath(DeletePathRequest) returns (DeletePathResponse);
  rpc AddFlowSpec(AddFlowSpecRequest)       returns (AddFlowSpecResponse);
  rpc DeleteFlowSpec(DeleteFlowSpecRequest) returns (DeleteFlowSpecResponse);
}

// Policy CRUD and chain assignment
service PolicyService { /* 14 RPCs: List/Get/Set/Delete for policies, neighbor sets, chains */ }

// Peer group CRUD
service PeerGroupService { /* 6 RPCs: List/Get/Set/Delete groups, Set/Clear neighbor membership */ }

// Daemon control and health
service ControlService {
  rpc Shutdown(ShutdownRequest)     returns (ShutdownResponse);
  rpc GetHealth(HealthRequest)      returns (HealthResponse);
  rpc GetMetrics(MetricsRequest)    returns (MetricsResponse);
  rpc TriggerMrtDump(TriggerMrtDumpRequest) returns (TriggerMrtDumpResponse);
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

**Recent event history.** `ListRouteEvents` exposes the same unicast
best-path event shape from a bounded in-memory RIB ring for after-the-fact
debugging. It is a diagnostic timeline, not durable audit storage: the ring is
process-local, fixed-size, and resets on daemon restart.

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
- Neighbor add/delete mutations made via gRPC are persisted back to the config file via atomic write (temp file + rename).
- `SIGHUP` triggers a config reload: `diff_neighbors()` computes the delta and `ReconcilePeers` applies structured per-peer add/delete operations.
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

Neighbor add/delete mutations made via gRPC are persisted back to the config file (ADR-0043). Full route-state persistence remains deferred — restart replays the config file and re-learns routes from peers.

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
5. eBGP over iBGP (only `RouteOrigin::Ebgp`; Local uses LOCAL_PREF/AS_PATH)
5.5. Shortest CLUSTER_LIST length (RFC 4456 §9)
5.6. Lowest ORIGINATOR_ID (RFC 4456 §9) — only when both routes carry the attribute
6. Lowest peer address (final disambiguator — guarantees strict ordering)

**Implementation choices (ADR-0014):**
- `best_path_cmp()` is a standalone function, not `Ord` on `Route`. Domain-specific ordering doesn't belong as a trait impl — multiple orderings may be needed.
- Deterministic MED (always-compare) matches GoBGP default. Simpler and avoids ordering sensitivity.
- `Route` carries `origin_type: RouteOrigin` (Ebgp/Ibgp/Local) for eBGP-over-iBGP preference (step 5) and iBGP split-horizon. Note: `Local` sorts equal to iBGP at step 5 — local routes win via LOCAL_PREF or shorter AS_PATH, not an explicit origin preference.
- `LocRib` lives inside `RibManager` — same single-task ownership pattern, no new locks.
- Incremental recompute: only prefixes affected by each update are re-evaluated.

Exposed via `ListBestRoutes` gRPC endpoint with offset pagination.

**Exit criteria:**
- Deterministic outcomes for all decision inputs, verified by property tests (antisymmetry, transitivity, totality).
- Stable best-path selection with multiple paths from multiple peers.
- Structured debug events for best-path changes.
- 388 tests pass (v0.2.0), clippy clean, fmt clean.

### Milestone 3: "Speak" `[complete]`

Inject and withdraw routes via gRPC (`AddPath` / `DeletePath`). Build Adj-RIB-Out per neighbor. Advertise to peers, withdrawals work correctly. v1 policy: import/export allow/deny lists + max-prefix guard. TCP MD5 authentication and GTSM/TTL security.

**Implementation choices:**
- Adj-RIB-Out lives inside `RibManager` — same single-task ownership, no new locks (ADR-0015).
- Per-peer outbound channel (mpsc, capacity 4096) created in `PeerSession`, sender registered via `PeerUp` message on Established.
- Outbound UPDATEs bypass the pure FSM — consistent with inbound pattern.
- Injected routes stored under sentinel peer `0.0.0.0` in standard Adj-RIB-In, participating in normal best-path selection and distribution.
- `UpdateMessage::build()` high-level constructor for outbound UPDATEs.
- eBGP outbound: prepend local ASN to AS_PATH, set NEXT_HOP to session's local IPv4 socket address (reachable, not router-id), strip LOCAL_PREF.
- iBGP outbound: ensure LOCAL_PREF present (default 100), pass NEXT_HOP through.
- TCP MD5 and GTSM require `socket2::Socket` for pre-connect `setsockopt` calls (ADR-0016). Only `unsafe` code in the project, isolated to `socket_opts` module.
- Policy engine: first-match-wins evaluation with match conditions (prefix, community, AS_PATH regex) and route modifications (LOCAL_PREF, MED, communities, AS_PATH prepend, next-hop). Separate import/export policies.

**Exit criteria:**
- A client can programmatically announce a prefix and verify it appears on the peer.
- Withdrawals propagate correctly.
- Max-prefix enforcement drops session with NOTIFICATION when exceeded.
- Resource limits enforced and observable via metrics.
- 284 tests pass (M3), clippy clean, fmt clean.

### Milestone 4: "Route Server Mode" `[complete]`

Dynamic peer management, per-peer policy, typed communities, real-time route event streaming.

**Implementation choices:**
- `PeerManager` uses the same channel-based single-task ownership pattern as `RibManager` (ADR-0017). Commands arrive via bounded mpsc, replies via oneshot.
- Shared types (`PeerManagerCommand`, `PeerInfo`) live in `crates/api/src/peer_types.rs` to avoid circular dependencies between the binary and API crates.
- Per-peer export policy: `RibManager` stores per-peer policies from `PeerUp`, resolves via `export_policy_for()` (per-peer overrides global). Config supports per-neighbor `import_policy` / `export_policy` sections.
- Typed COMMUNITIES (RFC 1997): `PathAttribute::Communities(Vec<u32>)` replaces opaque `Unknown` for type code 8. Each `u32` is `(ASN << 16) | value`.
- `WatchRoutes` uses `tokio::sync::broadcast` (ADR-0018) — zero overhead with no subscribers, independent receivers, lagged subscribers get error instead of blocking.
- `PeerHandle::query_state()` enables FSM state queries from PeerManager without shared mutable state.
- Starting with zero configured neighbors is now valid — peers can be added entirely via gRPC.

**Exit criteria:**
- Dynamic peer add/remove via gRPC, verified end-to-end.
- Per-peer export policy enforcement (different peers see different routes).
- Communities decoded, exposed in gRPC, injected via AddPath.
- WatchRoutes streams real-time route events to multiple subscribers.
- 10-peer interop validated against FRR 10.3.1 (17/17 automated tests pass).
- 306 tests pass (M4), clippy clean, fmt clean.

---

## EVPN Route Reflector Architecture (Phase 1)

Added 2026-04 per ADR-0050. Extends the RIB / transport / gRPC stack with a parallel typed-NLRI family for RFC 7432 routes, following the FlowSpec pattern (ADR-0035). Scope is **RR role only**: reflect all 5 route types between VTEP peers per RFC 4456 without local EVI state or data-plane integration.

### Key architectural decisions

**Parallel tables, not `Prefix` extension.** `Prefix` is `Copy` and participates in longest-prefix-match semantics — neither fits EVPN routes, which are variable-length typed TLVs. `AdjRibIn`, `AdjRibOut`, and `LocRib` each gain `HashMap<EvpnRouteKey, EvpnRibRoute>` tables alongside `flowspec_routes`. The compiler enforces parallel method coverage; FlowSpec already proved the pattern scales.

**Split payload from identity.** `EvpnRoute` carries the full RFC 7432 wire payload (labels, optional IPs, gateway) — needed to round-trip through reflection. `EvpnRouteKey` carries only the identifying fields per route type and is `Copy + Eq + Hash` — suitable as the RIB HashMap key. EAD per-ES and EAD per-EVI share wire format but get distinct key variants so the RIB never collapses them.

**Reflection reuses existing RFC 4456 helper.** `stage_evpn_routes` builds a synthetic `Route` probe carrying only peer / router-id / origin-type metadata and passes it to the existing `should_suppress_ibgp_inner`. Same pattern FlowSpec uses — no EVPN-specific reflection logic.

**Best-path: type-specific head + shared BGP body.** `evpn_tiebreak_simple` runs a Type-2-specific MAC Mobility head (sticky flag + sequence per RFC 7432 §15.1), then falls through to the standard BGP chain (LocalPref → AS_PATH → MED → eBGP>iBGP → peer). Type 1/4 DF-election tiebreaks are not implemented — the RR reflects, downstream VTEPs elect. Types 3/5 have no type-specific head.

**Policy uses placeholder prefix.** EVPN `RouteContext` carries a synthesized `0.0.0.0/0` prefix — the existing context fields (extended communities, communities, AS_PATH, peer metadata) are what operators actually filter on. RT-based filtering works through the existing `match_community` clause. A dedicated `match_evpn_route_type` clause is a Phase 1.5 item if operators need it.

**Next-hop preserved across reflection.** Outbound EVPN MP_REACH_NLRI carries the originating VTEP's loopback IP as next-hop, not the RR's address. This is what lets downstream VTEPs build VXLAN tunnels correctly — the RR is a control-plane waypoint, not a data-plane middlebox.

**Withdrawal wire framing from keys.** Outbound EVPN withdrawals emit MP_UNREACH_NLRI with routes reconstructed from `EvpnRouteKey` via `evpn_route_from_key`. Unknown label / optional fields are zeroed; receivers identify by key only, so round-trip fidelity is unnecessary on the withdrawal path.

### What's deferred to future phases

Phase 1 hardening (Gates 0-6 in [evpn-enablement.md](evpn-enablement.md))
covers reflection of all five RFC 7432 route types, GR + LLGR + Enhanced
Route Refresh, MAC mobility / sticky preservation, multi-homing Type 4
ES reflection (Type 1 EAD-per-EVI is wire-codec-tested but not gated
end-to-end — FRR origination requires VLAN-aware bridge + SVI which is
Phase 3 scope), scale validation (50k Type 2 + churn), and
controller-driven injection for Type 2 / Type 3. What remains:

- **VTEP mode:** local EVI / VRF / VNI state and kernel FDB MAC learning are
  shipped (Gates 7a + 7b + 7b+1 + 7b+2 + 7c); the daemon now both
  programs remote MACs into the kernel FDB and originates local
  Type 2 + Type 3 IMET routes from kernel-learned MACs.
  `advertise_svi_mac` originates the bridge's own MAC on
  instance-Ready, `sticky_macs` (ADR-0056) marks origination with
  the RFC 7432 §15.4 sticky bit, Gate 7b+2 adds MAC+IP Type 2
  origination via ARP/ND suppression under the FRR replace model
  (requires `bridge neigh_suppress on`), and Gate 7c switches the
  originator from a 5 s poll to a push-notified RIB broadcast for
  sub-second mobility convergence. **Still ahead in Phase 2:**
  duplicate-MAC remote-route processing and dataplane loop-protection.
- **Multi-homing execution:** Gate 8/8b covers rustbgpd-as-VTEP
  DF election (RFC 7432 §8 + RFC 8584), Type 1/4 origination, opt-in
  Non-DF BUM suppression, ESI-aware Type 2 origination, aliasing
  projection, and receive-side EAD-per-ES mass-withdraw filtering.
  ADR-0059 closes the aliasing-ECMP receive-path data path via
  FDB nexthop groups (slices 1-4 shipped on `main`, M40 protected
  self-hosted smoke validated against FRR EVPN-MH 10.3.1); slice 3.5
  hardening (PRs #91 / #92 / #93) followed up with the
  `apply_aliasing_ecmp` per-instance off-switch, periodic
  `RTM_GETNEXTHOP` drift recovery, and homogeneous IPv6 alias
  members. The MAC-churn variant of the Gate 8b soak passed
  2026-05-16 ([`docs/soak-gate8b-mac-churn-24h.md`](soak-gate8b-mac-churn-24h.md)),
  which unblocks flipping the `apply_bum_enforcement` and
  `apply_aliasing_ecmp` defaults to `true`; the flip itself is a
  separate release decision.
- **Symmetric Interface-less IRB:** Gate 9 ships end-to-end in
  v0.18.0 — RFC 9136 §4.4.2 / ADR-0058. The `[[evpn_ip_vrfs]]`
  config object, `IpVrfStatus` readiness probe, Linux VRF +
  L3VXLAN dumps, per-IP-VRF kernel-route observation, Type 5
  origination via `RibUpdate::InjectEvpn`, remote Type 5 import
  through the transactional `L3OwnedState` model with four-phase
  apply ordering, Router MAC conflict detection, and the M39
  protected self-hosted smoke are all on `main`. RFC 9135
  overlay-index IRB and auto-derived RTs (RFC 8365 §5.1.2.1)
  remain follow-ups.
- **Controller injection beyond Type 2 / Type 3:** Type 5 IP-Prefix and
  Type 1 / Type 4 multi-homing route injection are not yet exposed in
  the injection RPCs. Native daemon Type 1/4 origination exists via
  `[[ethernet_segments]]`.
- **RFC 9251 Route Types 6-8** (IGMP multicast), **RFC 7623 PBB-EVPN**,
  **MPLS encap**, **Add-Path for EVPN (RFC 9252)** (Phase 5).

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

**TCP-AO (RFC 5925):** Staged via ADR-0062. Static-neighbor `tcp_ao` TOML is
validated and installed on Linux startup sockets: active-open sessions install
the key before `connect()`, and the passive BGP listener installs configured
peer keys before `listen()`. Runtime key rotation, dynamic-neighbor wildcard
MKTs, multi-key rollover, and protected interop smoke remain follow-up work.

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

Bounded channels, prefix limits, and backpressure behavior are detailed in [ARCHITECTURE.md — Failure and Backpressure Model](../ARCHITECTURE.md#failure-and-backpressure-model). Additional guards:

- UPDATE attribute size limits enforced at decode time. Oversized attributes are rejected before allocation.
- gRPC request size limits enforced by tonic configuration.

### Global Route Limit Policy

When `max_total_routes` is exceeded, the offending session is torn down with NOTIFICATION Cease (Out of Resources, subcode 8) as defined in RFC 4486 §3. The structured event includes the peer address, the route that triggered the limit, and the current total count.

**Interop note:** Cease subcodes are defined in RFC 4486, not RFC 4271. If interop testing reveals a peer that rejects unknown Cease subcodes, the fallback is generic Cease (code 6, subcode 0). This is documented in INTEROP.md per peer.

This is a deliberate choice. The alternative — partial acceptance (reject individual prefixes while keeping the session established) — introduces per-UPDATE partial semantics that generate subtle correctness bugs and are difficult to reason about operationally. Option A (tear down the session) is explainable, safe, and what operators expect.

If the global limit is hit, it means either the limit is configured too low or the peer is sending more routes than expected — both conditions warrant human attention, not silent partial behavior.

### gRPC Security (v1)

- gRPC listens on a configurable address (default: localhost only).
- No built-in TLS in v1. For non-loopback exposure, front rustbgpd with an
  mTLS/TLS-authenticated proxy.
- Per-listener access mode (`read_only` / `read_write`) controls which RPCs
  are available. The nine-service split supports per-service auth policies
  when finer-grained authorization is added.

---

## Performance and Limits

### Configurable Limits (with defaults)

| Limit | Default | Notes |
|---|---|---|
| Max message size | 4096 bytes (65535 with RFC 8654) | 4096 by default; raised per-session only when Extended Messages is negotiated |
| Max attributes per UPDATE | 256 | Safety bound |
| Max prefixes per neighbor | 1,000,000 | NOTIFICATION on exceed |
| Max total routes | 10,000,000 | Backpressure, not crash |
| Bounded channel size | 4096 | Per-session and RIB channels |
| Connect retry interval | 5s | Reduced from RFC 4271 default of 120s |
| Hold time | 90s | Negotiated per-peer |

All limits are configurable via TOML and overridable per-peer via gRPC.

---

## Repository Layout

See [ARCHITECTURE.md — Where to Change X](../ARCHITECTURE.md#where-to-change-x) for a task-oriented guide. The crate dependency graph and runtime model are also in ARCHITECTURE.md.

---

## Roadmap Beyond v1

- Plugin-based policy engine (WASM or embedded DSL) — only after core stability

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
| MP-BGP (IPv6 unicast) | 4760 | v0.2.0 | FRR | `MP_REACH_NLRI` / `MP_UNREACH_NLRI`, `Prefix` enum, AFI/SAFI negotiation |
| Communities (standard) | 1997 | M4 | FRR | Typed decode/encode, gRPC exposure |
| Extended communities | 4360 | v0.3.0+ | FRR | RT, RO, 4-byte AS (ADR-0025/0026) |
| FlowSpec | 8955 | post-v0.3.0 | — | IPv4/IPv6 unicast FlowSpec implemented; speaker-mode hardening continues |
| Graceful restart (receiving speaker) | 4724 | v0.3.0 | FRR | Stale demotion, per-family EoR, two-phase timer (ADR-0024) |
| LLGR (two-phase GR timer) | 9494 | post-v0.3.0 | FRR | Implemented; GR-stale → LLGR-stale promotion, configurable stale time |
| TCP-AO | 5925 | Post-v1 | — | Static-neighbor startup install; dynamic / rollover follow-ups deferred |
| BMP exporter | 7854 | post-v0.3.0 | — | Implemented (ADR-0041); reconnect replay + periodic stats + coordinated-shutdown termination |
| MRT dump export | 6396 | post-v0.3.0 | — | Implemented (ADR-0044); TABLE_DUMP_V2 periodic + on-demand, gzip optional |
| RPKI / RTR client | 8210 | post-v0.3.0 | — | Implemented (ADR-0034); runtime gRPC management deferred |

This matrix is updated with every milestone. "Interop Tested" means validated
by a documented containerlab or privileged-netns procedure. CI-gated rows are
called out explicitly; privileged kernel dataplane smokes run locally until a
privileged runner is available.

---

## Project Governance

### Supported Platforms

- **v1:** Linux (x86_64, aarch64). These are the only tested and supported targets.
- macOS and BSD may compile and run for development purposes but are not CI-tested. Platform-specific socket options (TCP_MD5SIG, IP_TTL for GTSM) are Linux-only.
- Windows is not supported.

### Compatibility Targets

- **Must not break:** FRR. Core FRR interop rows are gated on every PR.
- **Should not break:** BIRD and GoBGP as peers. BIRD has documented M0
  validation; GoBGP rows run in the interop suite but are not the primary
  compatibility gate.
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

## Design Invariants

The 8 non-negotiable constraints are defined in [ARCHITECTURE.md — Design Invariants](../ARCHITECTURE.md#design-invariants). They cover: pure FSM, independent wire crate, bounded channels, no silent drops, no panics on malformed input, structured protocol violation events, enforced resource limits, and interop-tested features.
