# rustbgpd — Design Document

> **Document class: CURRENT.** This maintained page reflects the project as it is now; dated sections remain bounded to their stated scope.

A modern, API-first BGP daemon in Rust, inspired by GoBGP's ergonomics and "drive it via gRPC" operating model.

**Author:** lance0
**Status:** pre-1.0 hardening — public alpha

---

## Goals

**API-first routing control plane.** gRPC is the primary interface for all configuration and operations. The config file is a convenience for initial boot state — once the daemon is running, gRPC owns the truth. Clients in Python, Go, Rust, and Node should have a clean, typed experience from day one.

**Interop correctness over feature breadth.** RFC-compliant session behavior and attribute encoding/decoding, validated against real peers (FRR, BIRD, Junos, Arista EOS, Cisco IOS-XE/NX-OS where possible). A small feature set that works correctly is worth more than a large one that doesn't.

**Observable by default.** Prometheus metrics, structured logs, and machine-parseable errors everywhere. Operators should never have to guess what the daemon is doing or why a session flapped.

**Safe, boring, maintainable.** Minimal `unsafe` — every crate root denies it, and exactly three modules take a reviewed opt-out (transport socket options, the settlement watchdog's terminal `_exit`, the BFD receive-TTL socket option). Fuzzed wire decoder. Explicit resource limits. No clever tricks — just correct, auditable Rust.

## Non-Goals (v1)

This is not a full routing suite replacement. rustbgpd will not implement OSPF, IS-IS, LDP, or full VRF support in v1 (the `.rpol` policy language shipped via ADR-0096). It will not attempt every BGP extension at once (Confederation, PE-role VPNv4/v6 — the RR/controller-feed slice shipped per ADR-0077 — MPLS-EVPN encap, etc.). The goal is a reliable, API-driven BGP speaker — not a kitchen sink.

## Target v1 Use Cases

**Route server mode (IX-style).** Many peers, simple policies, RIB dump and monitoring, API-driven automation.

**Programmable edge speaker.** Inject and withdraw prefixes programmatically. Minimal, reliable session handling.

**EVPN Route Reflector (VXLAN-EVPN DC fabric).** iBGP route reflector for Type 1-5 RFC 7432 routes between VTEPs; control plane only, VTEPs handle their own DF election and data-plane encapsulation. See ADR-0050.

**EVPN VTEP — bidirectional (Phase 2: declarative instance schema, FDB reconciler, local MAC + MAC+IP origination, VTEP convergence).** Local EVI/VNI domain types (`crates/evpn`) and an `[[evpn_instances]]` TOML schema with a read-only `EvpnService.ListEvpnInstances` gRPC surface (declarative EVPN instance schema, ADR-0052). The EVPN VXLAN VTEP dataplane (Linux FDB reconciler) programs remote-MAC FDB entries from received Type 2 routes (ADR-0054). EVPN local MAC origination subscribes to `RTNLGRP_NEIGH` and emits Type 2 routes per RFC 7432 §15.1 mobility sequencing, plus one Type 3 IMET per L2VNI carrying the PMSI Tunnel attribute (Type-2 + Type-3 IMET, ADR-0055). `advertise_svi_mac` originates a Type 2 for the bridge's own MAC (RFC 9135 §6.1) on instance-Ready by surfacing the bridge link-layer address through `InstanceDataplaneStatus.bridge_mac`; `sticky_macs` (ADR-0056) marks origination with the RFC 7432 §15.4 sticky bit. MAC-with-IP origination closes the MAC+IP path: with `bridge link set ... neigh_suppress on`, ARP/ND-snooped `(IP, MAC)` bindings on the bridge's neighbour table drive MAC+IP Type 2 origination under the FRR-style replace model — one Type 2 per MAC at any time, `IpAdded` upgrades from MAC-only to MAC+IP, last `IpRemoved` downgrades back. Mobility events propagate sub-second via the EVPN-keyed `EvpnRouteEvent` broadcast in `crates/rib`; the 5 s `QueryEvpnRoutes` poll stays as a `Lagged` / cold-start backstop (EVPN VTEP convergence). RR-only deployments (empty `[[evpn_instances]]`) spawn no kernel-facing tasks for either direction.

**Later:** the EVPN runtime convergence remainder is down to L3VNI/device/table IP-VRF identity redefine (restart-required by design); decomposable mixed edits already commit live with fail-stop semantics — see [evpn-enablement.md](evpn-enablement.md) for the full live-vs-fail-closed breakdown. VPNv4/v6 reflection has shipped; MPLS-EVPN encap remains later. (Shipped since: duplicate-MAC remote-route suppression + bounded atomic quarantine listing + manual clear, production-default `apply_bum_enforcement` / `apply_aliasing_ecmp` enforcement, auto-derived Route Targets per RFC 8365 §5.1.2.1, receive-side RFC 9135 overlay-index Type 5 recursion with fail-closed unresolved / ambiguous gateways, and controller Type 5 Gateway Address injection.)

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

Linux dataplane reconcilers use a separate internal live-walk contract: an
opt-in ordered prefix index serves bounded best-route and ECMP pages, exact
key revalidation, and conservative route/peer-group version seals. The index
is enabled only when BLACKHOLE enforcement or a general FIB table is active;
control-plane-only processes keep the lazy RIB layout.

**Redesign triggers (instrumented from day one):**
- `bgp_rib_ingest_channel_depth` — queued `RibUpdate` messages sampled once per manager loop. Pegged at the channel capacity means producers are parked; evaluate sharding or batch coalescing. The `bgp_rib_outbound_prefix_limit_actor_duration_seconds` and `bgp_rib_route_refresh_actor_duration_seconds` histograms time the actor operations that hold the loop.
- `bgp_inbound_rib_backpressure_total` — any non-zero sustained rate means session tasks are stalling on a full RIB channel (ADR-0078).
- `bgp_outbound_route_drops_total` — non-zero means a peer's writer channel was full or closed and outbound work was dropped.
- `bgp_event_stream_lagged_total` — non-zero means a live event-stream subscriber is too slow to keep up and is missing events.

The threshold for triggering a redesign conversation is: sustained ingest-channel depth at capacity, or any backpressure-induced session flap in the interop test suite.

---

## gRPC API

### Design Decision: Own Our Protos

rustbgpd defines its own `.proto` files from day one. No GoBGP proto reuse.

Rationale: GoBGP's protos carry Go-specific patterns and years of accumulated feature baggage. Anyone writing automation against rustbgpd is writing new client code regardless. Our protos should map 1:1 to Rust domain types — `NeighborState` as a proper enum, AFI/SAFI as typed enums, not integers. A GoBGP-compat adapter can be written later if anyone actually asks for it.

### Service Architecture

Twelve native `rustbgpd.v1` gRPC services (Global, Config, Neighbor, Policy,
PeerGroup, Rib, Bfd, Rpki, Event, Injection, Control, Evpn), plus the separate
`gnmi.gNMI` service, not one god service. This forces API boundary clarity,
enables permission scoping (for example, read-only listeners for monitoring),
and mirrors internal architecture.

```protobuf
// Abridged — proto/rustbgpd.proto is authoritative; NeighborService has
// 12 RPCs and RibService 21, only representative subsets are shown here.

// Global daemon configuration and identity
service GlobalService {
  rpc GetGlobal(GetGlobalRequest)     returns (GlobalState);
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
  rpc RefreshOutbound(RefreshOutboundRequest) returns (RefreshOutboundResponse);
}

// Paginated point-in-time RIB queries; EventService owns live route streams
service RibService {
  rpc ListReceivedRoutes(ListRoutesRequest)   returns (ListRoutesResponse);
  rpc ListBestRoutes(ListRoutesRequest)       returns (ListRoutesResponse);
  rpc ListAdvertisedRoutes(ListRoutesRequest) returns (ListRoutesResponse);
  rpc ExplainAdvertisedRoute(ExplainAdvertisedRouteRequest) returns (ExplainAdvertisedRouteResponse);
  rpc ExplainBestPath(ExplainBestPathRequest) returns (ExplainBestPathResponse);
  rpc LookupBestPath(LookupBestPathRequest) returns (ExplainBestPathResponse); // outside v1
  rpc ListRouteEvents(ListRouteEventsRequest) returns (ListRouteEventsResponse);
  rpc ListFlowSpecRoutes(ListFlowSpecRequest) returns (ListFlowSpecResponse);
}

// Route injection and withdrawal
service InjectionService {
  rpc AddPath(AddPathRequest)       returns (AddPathResponse);
  rpc DeletePath(DeletePathRequest) returns (DeletePathResponse);
  rpc AddFlowSpec(AddFlowSpecRequest)       returns (AddFlowSpecResponse);
  rpc DeleteFlowSpec(DeleteFlowSpecRequest) returns (DeleteFlowSpecResponse);
}

// Policy CRUD, chain assignment, and import-policy explain
service PolicyService { /* 23 RPCs: policies, neighbor sets, chains, explain/rejected views, dry-run/stats, validation posture */ }

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

**Paginated unary (default).** `ListRoutesRequest` includes a `page_size` (max results per page, capped server-side) and an opaque `page_token` (cursor). Unfiltered listings resume directly from ordered route indices and clone only the requested page plus one lookahead row; `ListReceivedRoutes` without a peer performs a bounded k-way merge over the per-peer indices. A grouped advertised iterator can inspect additional underlying rows while applying member-local split horizon and exact-export rejection, but it does not restart or materialize the group view per page. API-filtered listings retain a full scan so `total_count` and filter semantics remain exact. Tokens are process-local and bind the last route key to the exact RPC scope, a fixed-size digest of canonical filter semantics, and a conservative manager-owned generation. Received and Best share the table generation so clients can atomically join the views; Advertised is independent. Reusing a token with a changed scope or filter fails with gRPC `INVALID_ARGUMENT`; `page_size` may change safely. Any mutation in the same scope class between pages makes the next request fail with gRPC `ABORTED`; this can conservatively abort a peer-specific walk after an unrelated peer changes. Clients must restart with an empty token. This fail-closed contract avoids serving a torn listing without retaining server-side snapshots or cursor registries.

```protobuf
message ListRoutesRequest {
  string neighbor_address = 1;      // filter by peer (empty = all)
  AddressFamily afi_safi = 2;       // address family filter
  uint32 page_size = 3;             // max results (server-capped at 1000)
  string page_token = 4;            // opaque cursor for next page
}

message ListRoutesResponse {
  repeated Route routes = 1;
  string next_page_token = 2;       // empty = no more pages
  uint64 total_count = 3;           // total matching routes (for UI/progress)
}
```

**Streaming watch (opt-in).** `EventService.WatchEvents` with
`EVENT_CATEGORY_ROUTE` returns a live stream of route events (add, withdraw,
best-path change, export-policy filtered) wrapped in `BgpEvent`. A bounded
broadcast channel prevents a slow consumer from becoming a DoS vector. If a
consumer falls behind, the missed events are skipped,
`bgp_event_stream_lagged_total` increments, and the stream stays connected
with an in-band `stream_lagged` event. Clients that need durable replay use
`SubscribeFromEvent` with event history enabled.

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

A bare config boots. No gRPC listener or `[security.grpc]` section is needed
for local operation: the daemon synthesizes an owner-only Unix socket at
`<runtime_state_dir>/grpc.sock`, and under the default tier authorization its
clients are authorized as the implicit `local-operator` principal — the
socket's filesystem permissions are the authentication. Declaring listeners,
principals, and roles only becomes necessary for remote (TCP) or
group-accessible access; see `docs/CONFIGURATION.md` under `[security.grpc]`.

```toml
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
# Explicit RFC 8212 posture. Omit it and the config inherits the legacy
# permit-all default, which raises the `rfc8212_secure_default_ready`
# advisory: `--check` warns, `--check --strict` exits 1.
ebgp_requires_policy = true

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

# Explicit, labeled permit-all. An eBGP neighbor with no policy is not a
# smaller config, it is an unfiltered one.
[policy.definitions.permit-all-import]
default_action = "permit"

[policy.definitions.permit-all-export]
default_action = "permit"

[policy]
import_chain = ["permit-all-import"]
export_chain = ["permit-all-export"]

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
```

### Coordinated Shutdown

Shutdown is triggered by SIGINT, SIGTERM, the `Shutdown` gRPC RPC, or an
unexpected supervised-component exit. Signal handlers are registered before
the daemon becomes externally reachable, so a signal arriving during startup
is never dropped. The common path follows
[ADR-0020](adr/0020-global-control-services-coordinated-shutdown.md):

1. Close mutation admission and wait for any owned runtime-config operation to
   settle or reach its recovery boundary.
2. Attempt the optional warm checkpoint and restart-marker publication, then
   fence EVPN runtime applies out of teardown.
3. Ask the local-MAC, SVI-MAC, L3, and segment originators to drain, waiting up
   to five seconds for each actor, then await the complete best-effort sweep of
   locally originated IMET routes. These peer-visible withdrawal attempts
   deliberately start before Administrative Shutdown while BGP sessions are still
   established. An actor that exceeds its five-second wait is detached and can
   finish after Cease begins, so completion before Cease is best-effort for
   those four actors. The IMET sweep completes before the next step, but each
   per-route outcome may still be rejected, unavailable, or reply-unknown.
   Writer-owned KEEPALIVEs keep sessions live during the bounded attempts
   independently of a session task blocked on RIB delivery
   ([ADR-0078](adr/0078-inbound-rib-backpressure.md)).
4. Send the sole PeerManager shutdown command, which initiates
   Cease/Administrative Shutdown (subcode 2), and await peer teardown.
5. Drain local-only BLACKHOLE and general-FIB state, BFD sessions, and EVPN
   Linux dataplane state, followed by the remaining daemon services.

The coordinated path does not replace Administrative Shutdown with an
Administrative Shutdown Hard Reset. When Notification GR is negotiated, the
ordinary NOTIFICATION follows the behavior recorded in
[ADR-0046](adr/0046-notification-gr.md) and
[RFC 8538 section 4](https://www.rfc-editor.org/rfc/rfc8538.html#section-4).

Configured and default hold timers describe BGP peer-silence handling; they are
not a time-to-Cease service-level promise or a minimum period for keeping a
session open. Several explicit stages are individually bounded, but the IMET
and PeerManager handoffs have no shared deadline, so shipped code has no finite
aggregate upper bound from shutdown request to first Cease.

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

Dispositions follow RFC 7606, not RFC 4271's blanket session reset: `wire::validate::ErrorDisposition` classifies each error as attribute-discard, treat-as-withdraw, or session-reset, and the session applies the strongest disposition in the message (§3 (h)). Treat-as-withdraw and attribute-discard keep the session Established. See [RFC_NOTES.md — RFC 7606](RFC_NOTES.md#rfc-7606--revised-bgp-update-error-handling) for the authoritative per-attribute table.

| Validation | RFC Reference | Behavior on Failure |
|---|---|---|
| Mandatory attributes present (ORIGIN, AS_PATH, NEXT_HOP for eBGP) | RFC 4271 §5.1.2, RFC 7606 §3 (d) | Treat-as-withdraw; subcode (3, 3) travels on the §5.2 escalation only |
| No duplicate attributes in a single UPDATE | RFC 7606 §3 (g) | Attribute-discard, keeping the first occurrence — except a duplicate MP_REACH_NLRI / MP_UNREACH_NLRI, which is session-reset with NOTIFICATION (3, 1) |
| Attribute flags match type (well-known, transitive, etc.) | RFC 4271 §4.3, RFC 7606 §3 (c) | Treat-as-withdraw; session-reset on MP_REACH_NLRI / MP_UNREACH_NLRI (§5.3) |
| Attribute ordering (well-known before optional) | RFC 4271 §4.3 | Accepted out of order; ordering is not enforced |
| AS_PATH segment type valid (AS_SET, AS_SEQUENCE) | RFC 4271 §4.3, RFC 7606 §7.2 | Treat-as-withdraw; subcode (3, 11) |
| AS_PATH length consistent with segment encoding | RFC 4271 §4.3, RFC 7606 §7.2 | Treat-as-withdraw; subcode (3, 11) |
| 4-byte ASN handling (AS_TRANS mapping) | RFC 6793 | Reconstruct valid AS4 compatibility attributes; discard or ignore inconsistent sidecars per RFC 6793 |
| NEXT_HOP is valid IP, not 0.0.0.0, not multicast | RFC 4271 §5.1.3, RFC 7606 §7.3 | Treat-as-withdraw; subcode (3, 8) |
| ORIGIN value is valid (IGP, EGP, INCOMPLETE) | RFC 4271 §4.3, RFC 7606 §7.1 | Treat-as-withdraw; subcode (3, 6) |
| Attribute length does not exceed the attribute section | RFC 7606 §§4, 5.3 | Treat-as-withdraw; a visible MP_REACH_NLRI / MP_UNREACH_NLRI overrun is session-reset because its embedded NLRI cannot be parsed |
| Total path attributes length consistent with UPDATE length | RFC 7606 §3 (b) | Session-reset — NOTIFICATION (3, 1), the NLRI field boundaries cannot be trusted |
| Unrecognized well-known attribute | RFC 4271 §5, RFC 7606 §3 (c) | Treat-as-withdraw; subcode (3, 2) |
| Unrecognized optional non-transitive attribute | RFC 4271 §5 | Not a failure — accepted and ignored |
| Unrecognized optional transitive attribute | RFC 4271 §5 | Pass through, set Partial bit (see policy below) |
| Message exceeds the negotiated maximum length | RFC 4271 §4.1, RFC 8654 | NOTIFICATION (1, 2) — Bad Message Length + structured event |

Every validation failure produces a structured log event with the peer address, attribute type code, raw bytes (truncated), and the RFC section violated, and increments `bgp_update_malformed_total{peer,disposition}`. No silent drops.

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
6. Lowest peer address (tiebreaker)
7. Lowest inbound Add-Path path identifier (same-peer route identity only; reported as `lower_path_id` in explain)

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
- TCP MD5 and GTSM require `socket2::Socket` for pre-connect `setsockopt` calls (ADR-0016). The `unsafe` this needs is isolated to the `socket_opts` module — one of the project's three scoped `unsafe` modules, and the only one in the transport path. `SECURITY.md` carries the full inventory.
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
- Route-event streaming uses `tokio::sync::broadcast` (ADR-0018) — zero overhead with no subscribers, independent receivers, and lagged receivers skip missed events without blocking.
- `PeerHandle::query_state()` enables FSM state queries from PeerManager without shared mutable state.
- Starting with zero configured neighbors is now valid — peers can be added entirely via gRPC.

**Exit criteria:**
- Dynamic peer add/remove via gRPC, verified end-to-end.
- Per-peer export policy enforcement (different peers see different routes).
- Communities decoded, exposed in gRPC, injected via AddPath.
- Route-event streaming delivers real-time route events to multiple subscribers.
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

**Policy uses placeholder prefix.** EVPN `RouteContext` carries a synthesized `0.0.0.0/0` prefix — the existing context fields (extended communities, communities, AS_PATH, peer metadata) are what operators actually filter on. RT-based filtering works through the existing `match_community` clause. A dedicated `match_evpn_route_type` clause shipped in v0.11.0 and matches the RFC 7432 §7 / RFC 9136 route type directly.

**Next-hop preserved across reflection.** Outbound EVPN MP_REACH_NLRI carries the originating VTEP's loopback IP as next-hop, not the RR's address. This is what lets downstream VTEPs build VXLAN tunnels correctly — the RR is a control-plane waypoint, not a data-plane middlebox.

**Withdrawal wire framing from keys.** Outbound EVPN withdrawals emit MP_UNREACH_NLRI with routes reconstructed from `EvpnRouteKey` via `evpn_route_from_key`. Unknown label / optional fields are zeroed; receivers identify by key only, so round-trip fidelity is unnecessary on the withdrawal path.

### What's deferred to future phases

Phase 1 hardening (the RR enablement ladder in [evpn-enablement.md](evpn-enablement.md))
covers reflection of all five RFC 7432 route types, GR + LLGR + Enhanced
Route Refresh, MAC mobility / sticky preservation, multi-homing Type 4
ES reflection (Type 1 EAD-per-EVI is wire-codec-tested but not gated
end-to-end — FRR origination requires VLAN-aware bridge + SVI which is
Phase 3 scope), scale validation (50k Type 2 + churn), and
controller-driven injection for Type 2 / Type 3. What remains:

- **VTEP mode:** local EVI / VRF / VNI state and kernel FDB MAC learning are
  shipped (declarative instance schema, FDB reconciler, local MAC + MAC+IP
  origination, VTEP convergence); the daemon now both
  programs remote MACs into the kernel FDB and originates local
  Type 2 + Type 3 IMET routes from kernel-learned MACs.
  `advertise_svi_mac` originates the bridge's own MAC on
  instance-Ready, `sticky_macs` (ADR-0056) marks origination with
  the RFC 7432 §15.4 sticky bit, MAC-with-IP origination adds MAC+IP Type 2
  origination via ARP/ND suppression under the FRR replace model
  (requires `bridge neigh_suppress on`), and EVPN VTEP convergence switches the
  originator from a 5 s poll to a push-notified RIB broadcast for
  sub-second mobility convergence. Later EVPN work added remote
  duplicate-MAC suppression + manual clear, native GW-IP overlay-index
  Type 5 origination, single-active ESI overlay-index Type 5 receive
  (M71), all-active ESI overlay-index Type 5 receive (M72), and
  receive-side overlay-index recursion. The remaining VTEP tail is the
  ADR-0063 mixed-edit runtime boundary, the Linux softswitch local-bias
  split-horizon gap, true non-zero-Ethernet-Tag / shared-VNI service,
  managed netdev ergonomics, and standards features outside the
  Linux/VXLAN alpha boundary.
- **Multi-homing execution:** EVPN multi-homing (ESI, Type-1/Type-4) plus
  BUM-flood suppression + DF election cover rustbgpd-as-VTEP
  DF election (RFC 7432 §8 + RFC 8584), Type 1/4 origination, opt-in
  Non-DF BUM suppression, ESI-aware Type 2 origination, aliasing
  projection, and receive-side EAD-per-ES mass-withdraw filtering.
  ADR-0059 closes the aliasing-ECMP receive-path data path via
  FDB nexthop groups (shipped on `main`, M40 hosted smoke validated against FRR EVPN-MH 10.3.1); aliasing-ECMP
  hardening (PRs #91 / #92 / #93) followed up with the
  `apply_aliasing_ecmp` per-instance off-switch, periodic
  `RTM_GETNEXTHOP` drift recovery, and homogeneous IPv6 alias
  members. The MAC-churn variant of the BUM-state soak passed
  2026-05-16 ([`docs/soaks/soak-gate8b-mac-churn-24h.md`](soaks/soak-gate8b-mac-churn-24h.md)),
  which motivated flipping the `apply_bum_enforcement` and
  `apply_aliasing_ecmp` defaults to `true`, shipped in v0.23.0;
  operators who need observe-only behavior set them = `false`
  explicitly.
- **Symmetric Interface-less IRB:** EVPN symmetric IRB (Type-5 / L3VNI) ships end-to-end in
  v0.18.0 — RFC 9136 §4.4.2 / ADR-0058. The `[[evpn_ip_vrfs]]`
  config object, `IpVrfStatus` readiness probe, Linux VRF +
  L3VXLAN dumps, per-IP-VRF kernel-route observation, Type 5
  origination via `RibUpdate::InjectEvpn`, remote Type 5 import
  through the transactional `L3OwnedState` model with four-phase
  apply ordering, Router MAC conflict detection, and the M39
  hosted smoke are all on `main`. Auto-derived RTs
  (RFC 8365 §5.1.2.1) shipped in v0.25.0. Receive-side RFC 9135
  overlay-index Type 5 recursion now resolves non-zero Gateway Address
  routes through unambiguous linked Type 2 MAC/IP state while leaving
  unresolved or ambiguous gateways fail-closed.
- **Controller injection beyond Type 2 / Type 3 / Type 5:** Type 5
  IP-Prefix injection, including non-zero Gateway Address for targeted
  overlay-index testing, is exposed in the injection RPCs. Type 1 / Type 4
  multi-homing route injection is not exposed; native daemon Type 1/4
  origination exists via `[[ethernet_segments]]`.
- **RFC 9251 Route Types 6-8** (IGMP multicast), **RFC 9572 Route Types
  9-11** (BUM segmentation), **RFC 7623 PBB-EVPN**, **MPLS encap**,
  **BGP Add-Path (RFC 7911) for L2VPN EVPN** (Phase 5).

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

22 libFuzzer targets across six crates, each with its own `fuzz/` workspace:

- `crates/wire/fuzz` (13) — OPEN / UPDATE / message and Route Refresh
  decoding, Route Distinguisher parsing, and per-family NLRI decoders
  (FlowSpec, EVPN, BGP-LS, MPLS-VPN, labeled-unicast, RT-Constrain) plus an
  EVPN encode target and a canonical structured UPDATE encoder target.
- `crates/policy/fuzz` (4) — `.rpol` compilation, dataset parsing, mixed-chain compilation, and mixed-chain explain/live-walk agreement.
- `crates/mrt/fuzz` (2) — snapshot-reader drain and warm-bundle manifest.
- `crates/bfd/fuzz` (1) — BFD control-packet decoding.
- `crates/rpki/fuzz` (1) — RTR PDU decoding.
- `crates/evpn/fuzz` (1) — Route Target parsing.

Run them per crate — `cd` into the owning crate and use `cargo fuzz list` /
`cargo fuzz run <target>` on the pinned nightly. Seed corpora are tracked
under each crate's `fuzz/seeds/<target>/`. The repo-root `fuzz/` directory is
OSS-Fuzz build scaffolding, not a runnable target set.

All 13 wire targets have tracked roots. The scheduled workflow can reuse one
versioned `main`-lineage corpus, but cached bytes are staged outside the
checkout and must pass the exact target layout, regular-file, per-target
`max_len`, sorted SHA-256 manifest, 20,000-file, and 16 MiB checks before they
enter the live corpus. A cache miss or service outage falls back to the tracked
roots; invalid matched content stops before the campaign. Successful runs seal
a fresh staging tree, and only `main` schedule/manual runs write the lineage.
This preserves deterministic tracked inputs while allowing nightly discovery
to accumulate within explicit bounds.

Fuzz runs on a nightly CI schedule (`fuzz.yml`, all targets); PRs gate on the unit/property/interop suites.

### Property Tests

- `encode(decode(x)) == x` roundtrip invariants for all valid message types.
- Decoder rejects: length mismatches, invalid attribute flags, truncated NLRI, oversized attributes beyond configured limits.
- FSM property: no invalid state transitions for any sequence of valid inputs.

### CI Pipeline

- Unit tests (every PR)
- Fuzz — all targets, nightly schedule (not PR-gated)
- Interop tests via containerlab (every PR, against FRR and BIRD at minimum)
- Clippy + deny(warnings) + cargo deny for dependency audit

---

## Security Posture

This section defines the security stance for rustbgpd. Not all items are v1 implementations, but the posture is established now so that design decisions don't foreclose security later.

### Session Authentication

**Supported platforms (v1): Linux (x86_64, aarch64).** TCP MD5, GTSM via
`IP_TTL`, and certain socket options are Linux-specific. Non-Linux daemon
builds are unsupported; portable components do not expand the canonical
[platform support contract](../SUPPORT.md#platform-support).

**Dual-family BGP listener:** The daemon always listens for inbound BGP on both address families — `0.0.0.0:{listen_port}` and `[::]:{listen_port}` — behind one accept loop and one accept channel; there is no listen-address knob (ADR-0019). `IPV6_V6ONLY` is set explicitly on the IPv6 socket so v4-mapped connections always arrive through the IPv4 socket. Every listener-side authentication entry below (MD5 key, TCP-AO MKT, GTSM selector) is installed on the socket matching the peer's address family, so IPv6 peers get the same inbound enforcement as IPv4 peers. If one family cannot be bound (for example IPv6 disabled on the host), a warning names the family and the other keeps serving; startup fails only when neither family binds.

**TCP MD5 (RFC 2385):** Supported in v1. This is table stakes for any BGP daemon deployed in production — most peers will require it. Active-open sockets install the password via `setsockopt(TCP_MD5SIG)` before `connect()`. The passive BGP listener installs host-scoped keys for static neighbors (`TCP_MD5SIG`) and prefix-scoped keys for dynamic-neighbor ranges (`TCP_MD5SIG_EXT` with `TCP_MD5SIG_FLAG_PREFIX`, Linux ≥ 4.13) before `listen()`; the kernel resolves overlapping keys by longest prefix match, rejects unsigned segments from covered peers during the handshake, and copies the matched key onto each accepted child. SIGHUP reload replaces the listener key inventory; a changed password is inherently session-disruptive. Linux only.

**TCP-AO (RFC 5925):** Staged via ADR-0062. Static-neighbor and direct
dynamic-prefix `tcp_ao` TOML accepts ordered keyrings on Linux:
active-open sessions install the selected key and remaining MKTs before
`connect()`, and the passive BGP listener installs configured keyrings before
`listen()`. Accepted protected sockets are validated fail-closed, live
KeyIDs/counters are queryable through the neighbor API/CLI, and M43 covers BIRD
interop. SIGHUP can append nonpreferred successor keys across the listener and
managed protected sessions without changing Current/RNext, then in a later
immutable generation select an installed successor as local RNext and commit
predecessor deprecation only after cohort observation. Linux Current remains
peer-driven. A later immutable SIGHUP generation can delete only deprecated
MKTs that are neither Current nor RNext while keeping the owner set, survivor
order, key definitions, and selected key exact. Protected-owner changes and
key edits/reordering remain restart-required.

**GTSM (RFC 5082):** Supported in v1 as a configurable option (`ttl_security = true` per neighbor or peer group). Outbound TTL/Hop-Limit is 255; inbound `IP_MINTTL` / `IPV6_MINHOPCOUNT` is `256 - ttl_security_hops`, with an omitted hop distance preserving the exact-255 one-hop policy. Active-open sockets are configured before `connect()`; inbound connections are configured on the accepted socket at accept time, resolved per peer (exact static neighbor first, then longest dynamic-range match), since the shared listener socket cannot carry per-peer TTL policy — handshake segments therefore precede the filter, but every later segment, including any KEEPALIVE required to reach Established, is enforced. This supports bounded multihop sessions without weakening adjacent-peer defaults.

### Connection Rate Limiting

- Per-source inbound accept-rate limiting (ADR-0120, top-level
  `[inbound_admission]`) is **opt-in**: `enabled` defaults to `false`.
- When enabled, a token bucket per aggregated source: `rate_per_minute`
  default 12, `burst` default 5, source aggregation at
  `v4_aggregation_len = 32` / `v6_aggregation_len = 64`, and
  `table_capacity = 4096` LRU-evicted tracking entries bounding limiter
  memory regardless of offered load. All fields are restart-required.
- Statically configured neighbor addresses are exempt — a flapping legitimate
  peer is never rate-limited out of its own session.
- Connections from unconfigured peers are dropped immediately after TCP accept — no BGP processing.
- All rate limit events produce structured log entries and increment
  `bgp_inbound_connections_dropped_total`.
- See [CONFIGURATION.md](CONFIGURATION.md#inbound_admission).

### Malformed Message Handling Philosophy

- **Never panic on malformed input.** Any input from the network is untrusted. Panics on malformed BGP messages are security vulnerabilities.
- **Never silently ignore.** Malformed framing — header, message length, NLRI or Withdrawn Routes fields — produces the RFC 4271 NOTIFICATION and tears the session down. Malformed path attributes follow RFC 7606: attribute-discard or treat-as-withdraw keeps the session Established, and session-reset is retained only where the NLRI cannot be trusted. Every case emits a structured event and increments `bgp_update_malformed_total{peer,disposition}`.
- **Always log.** Every malformed message produces a structured event with peer address, message type, error description, and truncated raw bytes for forensic analysis.
- **Fuzz everything.** The wire decoder is the attack surface. It runs under continuous fuzzing in CI.

### Memory Exhaustion Guards

Bounded channels, prefix limits, and backpressure behavior are detailed in [ARCHITECTURE.md — Failure and Backpressure Model](../ARCHITECTURE.md#failure-and-backpressure-model). Additional guards:

- UPDATE attribute size limits enforced at decode time. Oversized attributes are rejected before allocation.
- gRPC request size limits enforced by tonic configuration.

### gRPC Security (v1)

- There is no default TCP listener. By default gRPC is reachable only on the
  owner-only Unix domain socket the daemon synthesizes at
  `<runtime_state_dir>/grpc.sock`. TCP is opt-in via
  `[global.telemetry.grpc_tcp]` and requires bearer-token or native-mTLS
  identity.
- Native gRPC mTLS is supported on TCP listeners via `tls_cert_file` /
  `tls_key_file` / `tls_client_ca_file` (all three required together; no
  TLS-without-mTLS half-mode) — see docs/CONFIGURATION.md "Native gRPC mTLS".
  UDS listeners and bearer-token auth are also available.
- Per-method tier authorization (ADR-0064) is the enforcement model: every
  RPC carries a tier assignment (docs/grpc-method-inventory.md), listeners
  enforce a `max_tier` ceiling, and `[security.grpc].enforcement = "tier"`
  maps authenticated principals to role ceilings. `"tier"` has been the
  default since v0.24.0 and is now the only accepted value —
  `GrpcEnforcementConfig` has a single variant, and the `"legacy"` mode and
  its validation branch are gone. The per-listener `access_mode = "read_only"` setting remains as
  a compatibility ceiling on top of the twelve-service split.

---

## Performance and Limits

### Configurable Limits (with defaults)

| Limit | Default | Notes |
|---|---|---|
| Max message size | 4096 bytes (65535 with RFC 8654) | 4096 by default; raised per-session only when Extended Messages is negotiated |
| Max attributes per UPDATE | 256 | Safety bound |
| Max prefixes per neighbor | none (unbounded) | `max_prefixes` (aggregate) and the independent `max_prefixes_ipv4` / `max_prefixes_ipv6` per-family caps (ADR-0108) default to `None`; exceeding a cap latches the peer down. Without negotiated Notification GR, the daemon sends RFC 4486 Cease/1: aggregate violations retain an empty data field, while per-family violations carry AFI (2 octets), SAFI (1 octet), and the upper bound (4 octets). When Notification GR was negotiated, RFC 8538 Cease/9 encapsulates that Cease/1 code, subcode, and data. The pre-policy `max_prefixes_received_ipv4` / `max_prefixes_received_ipv6` bounds count announced prefixes before import policy under the same teardown contract. |
| Max advertised prefixes per neighbor (outbound) | none (unbounded) | `max_prefixes_out_ipv4` / `max_prefixes_out_ipv6` (ADR-0113) bound one peer's advertised-state growth: excess net-new prefixes are withheld while the session stays Established — nothing already advertised is withdrawn and no NOTIFICATION is sent. Blocking state plus usage/limit/headroom are on neighbor detail, JSON, and Prometheus (`bgp_outbound_prefix_{usage,limit,headroom,blocking,blocked_total}`) |
| Max-prefix restart hold-down | none (indefinite latch) | A non-zero `max_prefix_restart_seconds` opts into one generation-fenced automatic attempt after the hold-down. Failure to deliver `PeerCommand::Start` consumes that attempt and leaves the peer latched until explicit enable; successful delivery removes the latch and returns the session to ordinary TCP/OPEN retry. `rbgp neighbor <addr>` exposes the effective action and active countdown |
| Bounded channel size | 4096 | Per-session and RIB channels |
| Connect retry interval | 1s for the first two refused TCP dials, then 5s exponential backoff capped at 300s | Applies to prompt TCP failures where the peer is not listening yet; OPEN/config failures use the slower Idle reconnect guard. The 1s floor and two-attempt count are fixed daemon defaults. |
| Hold time | 90s | Negotiated per-peer |

Most runtime limits are configurable via TOML and overridable per-peer via
gRPC where the API exposes the corresponding field; connect-retry timing is a
daemon default today.

---

## Repository Layout

See [ARCHITECTURE.md — Where to Change X](../ARCHITECTURE.md#where-to-change-x) for a task-oriented guide. The crate dependency graph and runtime model are also in ARCHITECTURE.md.

---

## Roadmap Beyond v1

- Plugin-based policy engine (WASM) — the embedded DSL shipped as `.rpol` (ADR-0096); WASM plugins only after core stability

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
| TCP-AO | 5925 | Post-v1 | BIRD | Static and direct dynamic-prefix keyrings; fail-closed accept validation and live API/CLI health; successor install, observation-gated RNext selection/deprecation, and later deprecated unselected-MKT deletion |
| BMP exporter | 7854 | post-v0.3.0 | — | Implemented (ADR-0041); reconnect replay + periodic stats + coordinated-shutdown termination |
| MRT dump export | 6396 | post-v0.3.0 | — | Implemented (ADR-0044); TABLE_DUMP_V2 periodic + on-demand, gzip optional |
| RPKI / RTR client | 8210 | post-v0.3.0 | — | Implemented (ADR-0034); `RpkiService` provides bounded point validation and read-only configured-cache accepted-epoch inventory, while cache mutation remains deferred |

This matrix is updated with every milestone. "Interop Tested" means validated
by a documented containerlab or privileged-netns procedure. CI-gated rows are
called out explicitly; privileged kernel dataplane smokes run locally until a
privileged runner is available.

---

## Project Governance

### Supported Platforms

- **v1:** Linux x86_64 and aarch64 are the supported daemon targets.
- Published containers are built and runtime-verified natively on Linux x86_64
  and aarch64. Broader daemon, interoperability, and privileged CI remains
  Linux x86_64; packages and tarballs retain their documented cross-build path
  where applicable.
- Non-Linux daemon builds are unsupported. See the canonical
  [platform support contract](../SUPPORT.md#platform-support).

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
- Passing CI (unit tests, interop; fuzz runs nightly)
- Updated compatibility matrix
- Updated CHANGELOG
- Migration notes if protos changed

### Contribution Policy

- **Bug fixes and test improvements:** PR directly.
- **New protocol behavior:** Requires an issue with RFC citation and proposed interop test plan before implementation.
- **Architectural changes:** Requires design discussion in an issue or discussion thread. No surprise features.
- **All PRs** must pass CI, including interop tests, and must not violate any design constraint.

### Security Policy

- Vulnerabilities are reported through GitHub private vulnerability reporting, the single channel named in the repository-root `SECURITY.md`. There is no email channel, and security issues must not be filed as public issues.
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
