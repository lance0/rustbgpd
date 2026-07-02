# Milestone History (M0-M9 plus later interop milestones)

Archived build orders, exit criteria, and design choices from the
initial development phase. For the current feature roadmap, see
[ROADMAP.md](../ROADMAP.md). For a full changelog, see
[CHANGELOG.md](../CHANGELOG.md).

All milestones below shipped as **v0.1.0** (2026-02-28).

---

## M0 — "Establish"

Session establishment and stability. The daemon connects to peers,
completes OPEN/KEEPALIVE exchange, and holds Established state.

### Build Order

1. **rustbgpd-wire** — OPEN, KEEPALIVE, NOTIFICATION encode/decode
   - BGP header (marker, length, type) parsing with 4096-byte enforcement
   - OPEN message: version, ASN, hold time, router ID, capabilities
   - Capability TLV parsing: 4-byte ASN (code 65), MP-BGP (code 1)
   - KEEPALIVE message (header only, no body)
   - NOTIFICATION message: error code, subcode, data
   - Property tests: `encode(decode(x)) == x` roundtrip
   - Fuzz harness: message decode from arbitrary bytes

2. **rustbgpd-fsm** — Pure RFC 4271 state machine
   - Six states: Idle, Connect, Active, OpenSent, OpenConfirm, Established
   - Input events: message received, timer fired, TCP connected/disconnected
   - Output actions: send message, start/stop timer, connect, disconnect
   - OPEN negotiation: hold time, capabilities, ASN validation
   - Negotiation result struct: agreed caps, AFI/SAFI set, peer ASN, peer ID
   - No tokio imports, no I/O — pure function from (State, Event) → (State, Actions)

3. **rustbgpd-telemetry** — Metrics and structured logging
   - Prometheus counters: session state transitions, flaps, NOTIFICATIONs
   - RIB metric stubs (exist at zero): update latency, backpressure, drops
   - Structured JSON events for FSM transitions

4. **rustbgpd-transport** — Tokio TCP glue
   - Single-task-per-peer session runtime with `tokio::select!`
   - Read loop: bytes → `peek_message_length` → `decode_message` → FSM event
   - Write loop: FSM action → `encode_message` → TCP write
   - Timer management: `Option<Pin<Box<Sleep>>>` with freestanding `poll_timer`
   - `PeerHandle` / `PeerCommand` API for external control (Start, Stop, Shutdown)
   - Iterative action loop avoids async recursion
   - Full telemetry integration (state transitions, messages, notifications)

5. **Daemon entrypoint** — Config, metrics, peer wiring, shutdown
   - TOML config loading and validation (`src/config.rs`)
   - Prometheus `/metrics` HTTP endpoint (`src/metrics_server.rs`)
   - CLI arg parsing, telemetry init, peer spawn, SIGTERM shutdown (`src/main.rs`)
   - CI workflow: fmt, clippy, test (`.github/workflows/ci.yml`)

6. **Interop validation** — FRR and BIRD
   - Containerlab topology: rustbgpd ↔ FRR (10.3.1) — **Pass**
   - Containerlab topology: rustbgpd ↔ BIRD (2.0.12) — **Pass**
   - Test: session establishment — **Pass** (both peers)
   - Test: peer restart recovery — **Pass** (both peers)
   - Test: TCP reset recovery — **Pass** (both peers)
   - Test: establish, hold 30+ minutes, verify keepalives — **Pass** (FRR 35min/73 KAs, BIRD 35min)
   - Test: malformed OPEN → correct NOTIFICATION — **Pass** (Bad Peer AS → code 2/subcode 2)

### Exit Criteria

- Establish and hold 30+ minutes with FRR and BIRD
- Survive peer restart and TCP reset
- Correct NOTIFICATION on malformed OPEN
- Prometheus metrics capture all state transitions
- Structured log events for every FSM transition

---

## M1 — "Hear"

Decode UPDATEs. Store in Adj-RIB-In. Expose via gRPC.

### Build Order

1. **Wire — NLRI parsing** (`crates/wire/src/nlri.rs`)
   - `Ipv4Prefix` type with `Copy`, `Hash`, `Eq`, `Ord` derives
   - `decode_nlri` / `encode_nlri` per RFC 4271 §4.3 prefix-length encoding
   - Host bit masking, 0-32 range validation, truncation detection
   - 11 unit tests including roundtrip, edge cases (/0, /32), malformed input

2. **Wire — Path attribute decode/encode** (`crates/wire/src/attribute.rs`)
   - `decode_path_attributes` / `encode_path_attributes` with `four_octet_as` flag
   - TLV header parsing: flags + type + length (1 or 2 byte) + value
   - Types: ORIGIN, AS_PATH (2-byte + 4-byte), NEXT_HOP, MED, LOCAL_PREF, Unknown
   - Extended Length flag support, unknown attribute preservation
   - 22 tests including roundtrip for both AS widths

3. **Wire — Attribute validation** (`crates/wire/src/validate.rs`)
   - Separate from decode: structural ("can I read?") vs semantic ("is it correct?")
   - Checks: duplicate types (3,1), unrecognized well-known (3,2), missing mandatory (3,3),
     flag mismatch (3,4), invalid NEXT_HOP (3,8), malformed AS_PATH (3,11)
   - 14 tests covering all error subcodes and valid cases

4. **Wire — ParsedUpdate + fuzz** (`crates/wire/src/update.rs`)
   - `ParsedUpdate { withdrawn, attributes, announced }` struct
   - `UpdateMessage::parse(four_octet_as)` delegates to NLRI + attribute decoders
   - New fuzz target `decode_update` in CI

5. **RIB crate** (`crates/rib/`)
   - `Route { prefix, next_hop, attributes, received_at }`
   - `AdjRibIn` per-peer with `HashMap<Ipv4Prefix, Route>`
   - `RibUpdate` enum: `RoutesReceived`, `PeerDown`, `QueryReceivedRoutes`
   - `RibManager` single tokio task, bounded mpsc (4096), oneshot queries
   - 9 tests (5 unit + 4 async integration)

6. **Transport + FSM integration**
   - FSM: payloadless `UpdateReceived`, new `UpdateValidationError` event
   - Transport: `process_update()` pipeline (parse → validate → RIB → FSM)
   - `PeerDown` sent to RIB on session teardown
   - `rib_tx` threaded from daemon entrypoint through `PeerHandle::spawn()`

7. **gRPC API** (`crates/api/`)
   - Proto codegen via `tonic_prost_build` in `build.rs` (was `tonic_build` until tonic 0.14 split prost-coupled codegen out)
   - `ListReceivedRoutes` with offset pagination (default page_size=100)
   - Other RibService RPCs return `UNIMPLEMENTED`
   - Server on configurable gRPC listeners (UDS by default, optional explicit
     TCP listener via `grpc_tcp`)
   - CI updated with `protobuf-compiler`, Dockerfile updated for builder stage

8. **Interop validation** — 15/15 automated tests pass
   - Containerlab topology: `m1-frr.clab.yml` (FRR advertising 3 prefixes)
   - FRR config with `network` statements for 192.168.1.0/24, 192.168.2.0/24, 10.10.0.0/16
   - Automated test script `test-m1-frr.sh`: routes received, attributes correct, withdrawal propagates, peer restart clears/repopulates RIB
   - Peer restart test uses watchfrr auto-restart + rustbgpd deferred reconnect (~33s)

### Exit Criteria

- RIB dump matches peer's advertised routes for a controlled prefix set
- Fuzz harness in CI for the UPDATE decoder
- Attribute validation covers all RFC 4271 §6.3 checks
- gRPC `ListReceivedRoutes` returns correct routes with pagination
- 222 tests pass, clippy clean, fmt clean

---

## M2 — "Decide"

Loc-RIB best-path selection per RFC 4271 §9.1.2.

### Build Order

1. **Route peer field** (`crates/rib/src/route.rs`)
   - Added `peer: IpAddr` to `Route` for tiebreaker and gRPC reporting
   - Accessor helpers: `origin()`, `as_path()`, `local_pref()`, `med()`
   - Ripple fixes across transport, adj_rib_in, and manager tests

2. **Best-path comparison** (`crates/rib/src/best_path.rs`)
   - `best_path_cmp(a, b) -> Ordering` — preferred route sorts `Less`
   - Decision steps: LOCAL_PREF → AS_PATH length → ORIGIN → MED → peer address
   - Deterministic MED (always-compare) — simpler, matches GoBGP behavior
   - Standalone function, not `Ord` on `Route` (ADR-0014)
   - 9 unit tests (one per decision step + edge cases)
   - 3 proptest property tests: antisymmetry, transitivity, totality

3. **Loc-RIB struct** (`crates/rib/src/loc_rib.rs`)
   - `LocRib { routes: HashMap<Ipv4Prefix, Route> }` — best route per prefix
   - `recompute(prefix, candidates)` picks best via `min_by(best_path_cmp)`
   - Returns whether best changed (for event emission)
   - 5 unit tests: single candidate, replacement, withdrawal, unchanged, multi-candidate

4. **RibManager integration** (`crates/rib/src/manager.rs`)
   - `loc_rib: LocRib` field inside `RibManager`
   - Incremental recompute: only affected prefixes on announce/withdraw/peer-down
   - `PeerDown`: collects affected prefixes *before* clearing Adj-RIB-In
   - `QueryBestRoutes` variant in `RibUpdate` enum
   - Debug tracing for best-path changes
   - 4 integration tests: winner query, peer-down promotion, withdrawal update, per-prefix winners

5. **gRPC endpoint** (`crates/api/src/rib_service.rs`)
   - `list_best_routes()` with same pagination pattern as `list_received_routes()`
   - `route_to_proto()` updated to use `route.peer` for `peer_address` field
   - `best: true` flag set on best routes

### Design Choices

- **Deterministic MED** — always-compare across all peers (not just same-AS).
  Simpler, avoids ordering sensitivity, matches GoBGP default.
- **Peer address tiebreaker** — router-id tiebreak deferred to M3/M4 when
  we have outbound route advertisement and need full BGP decision process.
- **eBGP/iBGP step skipped** — deferred until transport distinguishes session
  types and router-id is available for a more complete implementation.

6. **Interop validation** — FRR 10.3.1
   - Reused M1 containerlab topology (`m1-frr.clab.yml`)
   - M1 automated test script: 15/15 tests pass (route receipt, attributes,
     withdrawal, peer restart recovery)
   - `ListBestRoutes` returns 3 best routes with `best: true` and correct
     `peerAddress` populated from `route.peer`
   - `ListBestRoutes` pagination verified (page_size=2, nextPageToken, page 2)

### Exit Criteria

- Deterministic outcomes for all decision inputs, verified by property tests
- Stable best-path selection with multiple paths from multiple peers
- Structured debug events for best-path changes
- `ListBestRoutes` gRPC endpoint with pagination
- Interop validated against FRR 10.3.1 (15/15 M1 tests + M2 best-routes)
- 248 tests pass, clippy clean, fmt clean

---

## M3 — "Speak"

Route injection, advertisement, and policy. The daemon becomes a real BGP
speaker: when best-path changes, advertise/withdraw to all peers. Operators
can inject routes via gRPC, apply prefix-list policy, and use TCP
authentication.

### Build Order

1. **Policy crate** — `PrefixList`
   - `PolicyAction` (Permit/Deny), `PrefixListEntry` with ge/le range matching
   - `PrefixList::evaluate()` — first-match-wins prefix filter
   - `check_prefix_list()` convenience function (None = permit all)
   - 9 tests covering exact match, ge/le range, first-match-wins, defaults

2. **Wire — `UpdateMessage::build()`**
   - High-level constructor: `build(announced, withdrawn, attributes, four_octet_as)`
   - Encodes NLRI and path attributes into raw Bytes fields
   - 4 tests: roundtrip, withdrawal-only, announce-only, mixed

3. **Config — new neighbor fields + policy config**
   - Neighbor: `max_prefixes`, `md5_password`, `ttl_security`
   - Global `[policy]` section with import/export prefix-list entries
   - `Config::import_policy()` / `Config::export_policy()` → `Option<PrefixList>`
   - 4 new config tests

4. **Telemetry — outbound metrics**
   - `rib_adj_out_prefixes` (IntGaugeVec), `rib_loc_prefixes` (IntGaugeVec),
     `max_prefix_exceeded` (IntCounterVec)
   - Recording methods on `BgpMetrics`

5. **RIB — Adj-RIB-Out, outbound distribution, route injection**
   - `AdjRibOut` struct (per-peer HashMap)
   - `OutboundRouteUpdate { announce, withdraw }` type
   - `RibUpdate` variants: `PeerUp`, `InjectRoute`, `WithdrawInjected`, `QueryAdvertisedRoutes`
   - `RibManager::distribute_changes()` — split-horizon + export policy + delta
   - `RibManager::send_initial_table()` — full Loc-RIB dump on PeerUp
   - Injected routes stored under sentinel peer `0.0.0.0` (ADR-0015)
   - 8 new M3 tests (38 total RIB tests)

6. **Transport — outbound channel + UPDATE sending**
   - Per-peer outbound channel (mpsc, capacity 4096)
   - `tokio::select!` branch for `OutboundRouteUpdate` in Established state
   - `send_route_update()` — build wire UPDATEs from outbound updates
   - `prepare_outbound_attributes()` — eBGP: prepend ASN, set NEXT_HOP, strip
     LOCAL_PREF; iBGP: ensure LOCAL_PREF (default 100)
   - Import policy filtering in `process_update()`
   - Max-prefix enforcement with Cease/1 NOTIFICATION
   - `PeerUp` sent to RIB on SessionEstablished
   - 5 unit tests for attribute preparation

7. **gRPC — InjectionService + ListAdvertisedRoutes**
   - `InjectionService` with `AddPath` (returns UUID) and `DeletePath`
   - `ListAdvertisedRoutes` implemented (was UNIMPLEMENTED stub)
   - Both services registered in gRPC server

8. **TCP MD5 + GTSM**
   - `socket_opts.rs` — `set_tcp_md5sig()` and `set_gtsm()` (Linux only, ADR-0016)
   - `attempt_connect()` refactored to use `socket2::Socket` for pre-connect options
   - Non-Linux stubs return `Unsupported`
   - Dependencies: `socket2`, `libc`

9. **Interop validation**
   - 3-node containerlab topology: rustbgpd + FRR-A (AS 65002) + FRR-B (AS 65003)
   - Test script with 5 scenarios: redistribution, split horizon, injection,
     withdrawal propagation, DeletePath

### Exit Criteria

- Routes redistributed between peers with correct AS_PATH prepending
- Split horizon prevents echo (route not sent back to originator)
- `AddPath` / `DeletePath` inject and withdraw routes via gRPC
- Max-prefix enforcement tears down session with Cease/1 NOTIFICATION
- Import/export prefix-list policy filters routes
- TCP MD5 and GTSM socket options applied before connect (Linux)
- 288 tests pass, clippy clean, fmt clean

---

## M4 — "Route Server Mode"

Dynamic peer management, per-peer policy, typed communities, real-time
route event streaming.

### Build Order

1. **Wire — Typed COMMUNITIES attribute** (`crates/wire/src/attribute.rs`)
   - `PathAttribute::Communities(Vec<u32>)` variant for RFC 1997 communities
   - Decode/encode in attribute codec, `communities()` accessor on Route
   - 6 tests: decode single/multiple/empty, odd-length error, roundtrip, type_code+flags

2. **Proto + gRPC — communities in Route message**
   - `repeated uint32 communities` field added to Route and AddPathRequest
   - `route_to_proto()` and injection service updated

3. **Per-peer import/export policy**
   - `import_policy` / `export_policy` fields on `[[neighbors]]` config section
   - Per-neighbor overrides global: neighbor-specific if present, else global fallback
   - `RibManager::export_policy_for()` resolution helper
   - `PeerUp` carries per-peer export policy to RIB manager
   - 5 new config + RIB tests

4. **PeerManager + session state query** (`src/peer_manager.rs`)
   - Channel-based single-task ownership (ADR-0017)
   - Commands: AddPeer, DeletePeer, ListPeers, GetPeerState, EnablePeer, DisablePeer, Shutdown
   - `PeerHandle::query_state()` returns FSM state + prefix count
   - Starting with zero configured neighbors is now valid
   - Shared types in `crates/api/src/peer_types.rs`
   - 7 tests

5. **NeighborService gRPC** (`crates/api/src/neighbor_service.rs`)
   - All 6 RPCs: add, delete, list, get state, enable, disable
   - Maps PeerInfo to proto NeighborState

6. **WatchRoutes streaming**
   - `tokio::sync::broadcast` channel (capacity 4096) in RibManager (ADR-0018)
   - `RouteEvent` type: Added, Withdrawn, BestChanged
   - Events emitted after `recompute_best()` with old/new state diff
   - `SubscribeRouteEvents` variant in `RibUpdate`
   - gRPC `watch_routes()` uses `BroadcastStream` with peer address filtering
   - Lagged subscribers logged and skipped (no crash)
   - 4 new tests

7. **Interop validation** — 17/17 automated tests pass
   - 10-peer containerlab topology: `m4-frr.clab.yml` (rustbgpd + 10× FRR)
   - 8 static peers + 2 dynamic peers (added/removed via gRPC)
   - Per-peer export policy: FRR-01 deny on 10.0.0.0/8 le 32, others permit all
   - Test script `test-m4-frr.sh`: 7 test scenarios covering sessions,
     ListNeighbors, received routes, per-peer export policy, dynamic
     AddNeighbor/DeleteNeighbor, and Enable/Disable

### Exit Criteria

- Dynamic peer add/remove via gRPC, verified end-to-end
- Per-peer export policy enforcement (different peers see different routes)
- Communities decoded, exposed in gRPC, injected via AddPath
- WatchRoutes streams real-time route events to multiple subscribers
- 10-peer interop topology validated against FRR 10.3.1 (17/17 tests pass)
- 306 tests pass, clippy clean, fmt clean

---

## M5 — "Polish"

Inbound listener, API hardening, session counters, NLRI batching, metrics
server hardening.

### Build order

1. Strict config parsing — `#[serde(deny_unknown_fields)]` on all structs
2. API input validation — reject ASN=0, hold_time 1-2, next_hop 0.0.0.0/multicast
3. Session counters — updates, notifications, flaps, uptime, last_error
4. Accurate prefix_count — `HashSet<Ipv4Prefix>` replaces add/subtract heuristic
5. NLRI batching — group outbound UPDATEs by shared attributes
6. Metrics server hardening — per-connection spawn, 404, write timeout, RIB drop metric
7. Inbound TCP listener — `BgpListener`, `PeerSession::new_inbound()`, PeerManager integration
8. Documentation — ADR-0019, CHANGELOG, README, ROADMAP

### Exit criteria

- Inbound TCP listener accepts passive peering
- All NeighborState fields populated
- API rejects invalid inputs with INVALID_ARGUMENT
- prefix_count accurate under re-announcement
- NLRI batching reduces wire UPDATE count
- Metrics server returns 404 for non-/metrics paths
- 314 tests pass, clippy clean, fmt clean

---

## M6 — "Compliance"

Wire RFC compliance, GlobalService, ControlService, coordinated shutdown.

### Build order

1. Crates.io packaging — version 0.1.0, metadata, proto copied into api crate
2. Review nits — ASN truncation → AS_TRANS, config validation, pagination dedup
3. GlobalService + ControlService — GetGlobal, GetHealth, GetMetrics, Shutdown (ADR-0020)
4. Coordinated shutdown — ctrl-c and Shutdown RPC both trigger ordered teardown
5. eBGP NEXT_HOP fix — uses TCP local socket addr instead of router-id
6. afi_safi validation — reject unsupported address families with INVALID_ARGUMENT
7. Wire attribute RFC compliance — flag validation at decode, specific subcodes, Partial bit

### Exit criteria

- All 5 gRPC services operational
- Coordinated shutdown from both ctrl-c and RPC
- Wire attribute errors produce RFC-correct subcodes and data
- 332 tests pass, clippy clean, fmt clean

---

## M7 — "Wire & RIB Correctness"

Peer-visible bugs found during full-project code review.

### Completed

1. **Adj-RIB-Out divergence on channel-full** (`crates/rib/src/manager.rs`)
   - Stage-then-commit with dirty peer tracking. On send failure, AdjRibOut
     is preserved and peer is marked dirty. A persistent pinned 1-second
     resync timer fires via `tokio::select!`, independent of both route
     mutations and query traffic. 4 tests.

2. **Malformed NLRI maps to wrong NOTIFICATION** (`crates/wire/src/nlri.rs`, `error.rs`)
   - Both prefix_len > 32 and truncated NLRI now return `InvalidNetworkField`
     → subcode 10 with the offending field bytes. 2 tests.

3. **PARTIAL bit set too broadly on unknown attributes** (`crates/wire/src/attribute.rs`)
   - PARTIAL now only set when both OPTIONAL and TRANSITIVE flags present.
     Well-known transitive attributes (e.g., ATOMIC_AGGREGATE) no longer
     get PARTIAL incorrectly. 1 test.

4. **Policy prefix lengths >32 can panic** (`src/config.rs`)
   - Config rejects prefix lengths > 32, ge > 32, ge < prefix length,
     le > 32, and ge > le at load time. 4 tests.

5. **Best-path omits eBGP-over-iBGP preference** (`crates/rib/src/best_path.rs`)
   - Added eBGP-over-iBGP preference as step 5 (between MED and peer
     address tiebreaker). `Route` gains `origin_type: RouteOrigin` field
     (Ebgp/Ibgp/Local). 3 tests.

### Exit criteria

- All 5 findings fixed with regression tests
- 344 tests pass (+10 new), clippy clean, fmt clean

---

## M8 — "API & Observability"

API contract issues and metrics accuracy found during code review. These
affect operators and automation consumers.

### Completed

1. **IPv6 neighbors accepted but unsupported** (`src/config.rs`, `crates/api/src/neighbor_service.rs`)
   - Config validation and gRPC `AddNeighbor` now reject IPv6 addresses.
     Wire crate is IPv4-only and GTSM uses IPv4-only socket options. 2 tests.

2. **SetGlobal permanently UNIMPLEMENTED** (`proto/rustbgpd.proto`, `crates/api/src/global_service.rs`)
   - SetGlobal RPC, request, and response annotated as reserved for future
     use (documentation-only). RPC still returns UNIMPLEMENTED.

3. **DeletePath.uuid ignored** (`proto/rustbgpd.proto`, `crates/api/src/injection_service.rs`)
   - Removed fake UUID from `AddPathResponse` and `DeletePathRequest`.
     Both fields reserved for wire compatibility.

4. **Dead Prometheus gauges** (`crates/rib/src/manager.rs`)
   - `set_rib_prefixes`, `set_adj_rib_out_prefixes`, `set_loc_rib_prefixes`
     wired at all RIB mutation points. Zero-valued gauges initialized on
     PeerUp for stable dashboard series. 3 tests.

5. **WatchRoutes loses withdrawals and peer transitions** (`crates/rib/src/event.rs`, `crates/rib/src/manager.rs`, `crates/api/src/rib_service.rs`)
   - `RouteEvent` gains `previous_peer` and `timestamp`. `recompute_best()`
     captures previous best peer before Loc-RIB mutation. WatchRoutes filter
     checks both `event.peer` and `event.previous_peer`. Proto gains
     `previous_peer_address` field. 4 tests.

6. **Health/neighbor counters semantically wrong** (`crates/api/src/control_service.rs`, `crates/api/src/neighbor_service.rs`, `crates/rib/src/update.rs`, `crates/rib/src/manager.rs`)
   - `active_peers` filters to Established only. `total_routes` queries
     Loc-RIB via `QueryLocRibCount`. `prefixes_sent` queries Adj-RIB-Out
     via `QueryAdvertisedCount` (returns `Status::internal` on failure,
     not silent 0). 4 tests.

### Exit criteria

- API contracts match implementation behavior
- Metrics reflect actual RIB state
- Consumers get correct data from all gRPC endpoints
- 357 tests pass (+13 new), clippy clean, fmt clean

---

## M9 — "Production Hardening"

Security, resilience, operational safety, and core protocol compliance
(TCP collision detection promoted from post-v1).

### Build order

1. **Metrics server hardening** (`src/metrics_server.rs`)
   - Read timeout (5s), request-line size limit (8192 bytes), concurrent
     connection cap (64 via `Semaphore`), `gather()` errors return 500
     instead of panicking. 3 new tests.

2. **gRPC security posture** (`src/main.rs`, `docs/SECURITY.md`)
   - Non-loopback gRPC bind logs warning at startup. New `docs/SECURITY.md`
     documents authentication posture, privileged RPCs, and recommendations.

3. **TCP collision detection** (RFC 4271 §6.8)
   - Wire: Cease subcode 7 (`CONNECTION_COLLISION_RESOLUTION`).
   - Transport: `SessionNotification` enum (`OpenReceived`, `BackToIdle`),
     session ids / roles, `CollisionDump` command, `remote_router_id` in
     `PeerSessionState`, session notification channel threaded to all spawn
     sites.
   - PeerManager: live `pending_inbound` candidate per peer,
     `session_notify_rx` in `select!` loop, session-id stale notification
     filtering, `resolve_collision()` compares BGP Identifiers,
     promote/drop helpers for the survivor. Branch coverage covers
     remote-wins, local-wins, equal-router-id, primary-idle promotion,
     stale notifications, and disable/shutdown drains.

4. **gRPC server supervision** (`src/main.rs`)
   - gRPC `JoinHandle` added to shutdown `select!`. Unexpected gRPC exit
     triggers coordinated shutdown (API-first daemon without API should
     not keep running).

5. **Documentation refresh**
   - ROADMAP: updated completed summary, M9 marked complete, v1 scope
     section added.
   - CHANGELOG: M9 entry with all items.
   - `docs/SECURITY.md`: new file documenting gRPC security posture.

### Exit criteria

- No panic paths from external input (metrics gather errors handled)
- Documented security posture for gRPC exposure
- TCP collision detection per RFC 4271 §6.8
- gRPC lifecycle supervised
- 367 tests pass (+20 new), clippy clean, fmt clean

---

## M29-M33 — "EVPN Route Reflector (Phase 1)"

Single feature shipped across five interop milestones plus correctness
hardening. See [docs/evpn-enablement.md](evpn-enablement.md) for the
gate ladder and [docs/adr/0050-evpn-route-reflector.md](adr/0050-evpn-route-reflector.md)
for the architectural record.

### Milestones

| ID | Scope |
|----|-------|
| **M29** | Capability sanity — L2VPN/EVPN negotiated with FRR 10.3.1, gRPC `ListEvpnRoutes` returns a well-formed response. |
| **M30** | Real Type 2 MAC/IP reflection end-to-end through a kernel VXLAN data plane (3-node containerlab + FRR VTEPs). |
| **M31** | MAC mobility (RFC 7432 §15.1) + sticky-MAC preservation (§7.7) across three VTEPs. |
| **M32** | Multi-homing reflection — Type 1 EAD-per-EVI + Type 4 ES routes from two VTEPs sharing an Ethernet Segment on a bond interface, reflected unchanged through the RR with correct ORIGINATOR_ID + CLUSTER_LIST. |
| **M33** | Scale validation — 50,000 Type 2 routes + 60 s of 1,000 rps churn through the RR. In-tree iBGP load generator (`bench/evpn-load`), no third-party daemon in the measurement path. |

### Build Order

1. **AFI 25 / SAFI 70 + wire codec** (`crates/wire/src/evpn.rs`) — five
   route types (Type 1 EAD per-ES + EAD per-EVI, Type 2 MAC/IP, Type 3
   IMET, Type 4 ES, Type 5 IP-Prefix per RFC 9136), `EvpnRoute` /
   `EvpnRouteKey` split, RouteDistinguisher / EthernetSegmentIdentifier /
   MplsLabel / MacAddress primitives, fuzz target.
2. **6 typed extended-community accessors** (`crates/wire/src/attribute.rs`) —
   BGP Encapsulation (RFC 8365 / 9012), MAC Mobility (RFC 7432 §7.7),
   ESI Label (§7.5), ES-Import RT (§7.6), Router MAC (RFC 9135 §4.1),
   Default Gateway (RFC 4761 §3.2.5).
3. **Parallel RIB tables** (`crates/rib/src/`) — `HashMap<EvpnRouteKey,
   EvpnRibRoute>` in AdjRibIn / Loc-RIB / AdjRibOut, mirroring the
   FlowSpec pattern from M22.
4. **Best-path with MAC Mobility head** (`crates/rib/src/loc_rib.rs`) —
   stale → MAC Mobility (sticky + sequence) → standard BGP chain
   (LocalPref → AS_PATH → ORIGIN → MED → eBGP/iBGP → CLUSTER_LIST →
   ORIGINATOR_ID → peer address).
5. **Reflection pipeline** (`crates/rib/src/manager/distribution.rs`) —
   source-peer split horizon, RFC 4456 ORIGINATOR_ID + CLUSTER_LIST,
   same-peer attribute-change detection, EVPN initial dump for late-
   joining peers.
6. **GR + LLGR + Enhanced Route Refresh for EVPN** (graceful_restart.rs,
   route_refresh.rs) — `mark_stale_evpn`, `promote_to_llgr_stale_evpn`,
   `sweep_stale_evpn`, `sweep_llgr_stale_evpn`, `clear_stale_evpn`,
   `clear_llgr_stale_evpn`; `refresh_stale_evpn` BoRR/EoRR tracking.
7. **Inbound/outbound transport** (`crates/transport/src/session/`) —
   EVPN MP_REACH/MP_UNREACH parsing, EVPN withdrawals propagated through
   AS_PATH-loop and CLUSTER_LIST-loop branches, max-prefix counting EVPN
   keys + FlowSpec rules.
8. **gRPC + CLI** — `ListEvpnRoutes` RPC on RibService with `route_type`
   / `peer` / `rd` filters; `AddEvpnRoute` / `DeleteEvpnRoute` on
   InjectionService for Type 2 (MAC/IP) and Type 3 (IMET) origination
   with proto3-default-correct `disable_vxlan_encap`. `rbgp evpn`
   list + `add-mac-ip` / `add-imet` / `delete-mac-ip` / `delete-imet`
   subcommands.
9. **Five interop harnesses** — M29 capability sanity, M30 Type 2
   reflection with kernel VXLAN, M31 MAC mobility + sticky, M32 multi-
   homing Type 1 EAD-per-EVI + Type 4 ES reflection (FRR ES on a bond
   interface), M33 50k-route scale + churn against the in-tree
   `bench/evpn-load` generator.
10. **Correctness hardening** — 12 fixes from three review rounds,
    each with regression tests: source-peer suppression,
    same-peer redistribution, full RFC 4456 tie-break, EVPN withdrawals
    through both loop branches, max-prefix counting, EVPN initial dump,
    ERR refresh tracking, Type 5 prefix in policy context, proto3
    `disable_vxlan_encap` rename, Default Gateway value-byte validation.

### Exit Criteria

- All five route types decode/encode with fuzz coverage and round-trip
  identity tests.
- Reflection preserves next-hop, ORIGINATOR_ID, CLUSTER_LIST, and all
  unrecognized attributes per RFC 4456.
- M30 validates real Type 2 MAC reflection through a kernel VXLAN data
  plane against FRR 10.3.1.
- M33 validates 50k Type 2 routes reflected to a third observer with
  post-churn count within ±tester-batch (40 routes) of 50,000 and
  ≥½·`CHURN_RATE`·`CHURN_DURATION` withdrawal events observed across
  60 s of 1,000 rps churn (initial convergence 5.1 s, peak RR memory
  ~80 MB on the reference hardware).
- Controller can inject Type 2 / Type 3 routes via gRPC; the RR
  reflects them through the same pipeline as iBGP-learned routes.
- All correctness gaps surfaced by review are fixed with regression
  tests; no known unfixed bugs at merge time.

### Phase 2 progress and what's still deferred

- **VTEP foundation (Gate 7a, v0.13.0) — landed.** Declarative
  domain in `crates/evpn` (`EvpnInstance`, `EvpnInstanceTable`,
  `RouteTarget`), `[[evpn_instances]]` TOML schema, read-only
  `EvpnService.ListEvpnInstances` + `rbgp evpn instances`,
  wire-side `RouteDistinguisher::from_str`. ADR-0052 codifies the
  boundary: domain-only, kernel-free; RR-only deployments
  unchanged.
- **VTEP kernel reconciliation (Gate 7b, v0.14.0) — landed.** New
  `crates/evpn-linux` crate ships the level-triggered
  `ReconcileActor<D: Dataplane>` programming remote-MAC FDB
  entries via rtnetlink (single combined-flag `RTM_NEWNEIGH` with
  `NTF_SELF | NTF_MASTER | NTF_EXT_LEARNED` and `NUD_NOARP |
  NUD_PERMANENT`). Foreign-entry preservation is structural — the
  delete pass iterates `OwnedSet`, never the kernel snapshot. M36
  containerlab smoke validates 8/8 PASS against Linux 6.17 + FRR
  10.3.1. ADR-0054 locks the boundary.
- **VTEP local-MAC origination (Gate 7b+1, v0.15.0) —
  landed (2026-05-07, PR #35).** `crates/evpn/src/origination.rs`
  ships the deterministic `LocalMacOriginator` state machine
  encoding RFC 7432 §15.1 sequence rules.
  `crates/wire/src/pmsi.rs` adds `PathAttribute::PmsiTunnel`
  (RFC 6514 §5, type 22) with EVPN-VXLAN convention per
  RFC 8365 §5.1.3 (label = raw 24-bit VNI).
  `crates/evpn-linux/src/linux/notify.rs` subscribes to
  `RTNLGRP_NEIGH` (enum group id 3) and classifies bridge FDB
  events. Daemon-side `src/evpn_originator.rs` + `src/evpn_imet.rs`
  emit Type 2 routes per mobility sequencing + one Type 3 IMET
  per L2VNI carrying PMSI Tunnel. Coordinated shutdown drains
  EVPN originator + IMET keys before peer manager shutdown.
  M37 containerlab smoke 4/4 PASS against Linux 6.17 + FRR 10.3.1.
  ADR-0055 locks the boundary.
- **Closed in v0.17.0 (post-v0.16.0):**
  `advertise_svi_mac` consumption (`src/evpn_svi.rs`),
  `sticky_macs` config schema (ADR-0056), sub-second mobility
  convergence (Gate 7c — EVPN-keyed `EvpnRouteEvent` broadcast in
  `crates/rib`; the 5 s poll stays as `Lagged` / cold-start
  backstop), and MAC-with-IP Type 2 origination via ARP/ND
  suppression (Gate 7b+2 — `AF_INET` / `AF_INET6` classifier,
  `LocalMacIpOriginator` state machine, daemon correlation under
  the FRR-style replace model per RFC 9135 §7.2.3. Operator
  prerequisite: bridge `neigh_suppress on`).
- **Multi-homing foundation (Gate 8, v0.17.0, ADR-0057) — landed.**
  Three Type 1/4 origination state machines in
  `crates/evpn/src/origination_es.rs` (Type 4 ES + Type 1 EAD-per-ES
  + Type 1 EAD-per-EVI), RFC 7432 §8.5 service carving + RFC 8584 §3
  algorithm negotiation in `crates/evpn/src/df_election.rs`, and a
  Prometheus `evpn_df_role` surface so operators can observe DF /
  Non-DF role per `(ESI, EVI)`. **M38 containerlab smoke** validates
  the DF inputs end-to-end against FRR.
- **Multi-homing enforcement alpha (Gate 8b) — landed (default-on with opt-out).**
  ESI Label + ES-Import RT extcomms attached to Type 1/4
  origination, DF-role-aware Type 2 ESI attachment, RFC 7432 §14
  aliasing receive-side projection
  (`crates/evpn/src/aliasing.rs`), RFC 7432 §8.4 receive-side
  EAD-per-ES mass-withdraw filtering
  (`crates/evpn/src/mass_withdraw.rs`), and opt-in kernel BUM-port
  enforcement (RFC 7432 §8.5) via `apply_bum_enforcement`. The
  enforcement primitive flips `flood off / mcast_flood off /
  bcast_flood off` on the kernel bridge port — validated end-to-end
  by `evpn_bum_filter_kernel` in CI under a Docker harness with
  `CAP_NET_ADMIN + CAP_SYS_ADMIN`. Production-default enforcement
  awaits the 24 h churn soak.
- **Gate 9 slice 6 — symmetric Interface-less IRB datapath
  landed.** Foundation
  (ADR-0058 + `[[evpn_ip_vrfs]]` config schema) landed, then
  pure-logic Type 5 origination + projection helpers in
  `crates/evpn/src/ip_vrf/`, the IP-VRF readiness probe
  (`crates/evpn/src/ip_vrf/readiness.rs`), Linux IP-VRF / L3
  VXLAN netlink dumps in `crates/evpn-linux`, and
  `Dataplane::probe_ip_vrfs` plumbed through `DataplaneIntent`
  and the reconcile call. **Slice 6 PR A (#77)** wires the
  daemon-side origination: per-pass kernel-route dump per
  IP-VRF + conservative classifier, watch-channel publication,
  L3 originator task with a level-triggered diff loop that
  gates on readiness, and `IpVrfState.originated_routes_count`
  surfaced via gRPC/CLI. **Slice 6 PR B (#78)** wires the
  dataplane import: best-path subscription drives
  `project_ip_prefix_routes()` against a transactional
  `L3OwnedState` that tracks both per-prefix install state and
  shared kernel resolution rows (`kernel_neighbors`,
  `kernel_fdb`) with value-aware drift detection so a Router
  MAC or next-hop transition under the same prefix triggers an
  atomic `.replace()` rather than silent misforwarding. A
  four-phase apply order (route-remove → resolution-add →
  route-add → resolution-remove) keeps the kernel
  forwarding-safe across transitions; Router MAC conflicts drop
  conflicting prefixes with `L3Drop::RouterMacConflict`;
  foreign state preservation is enforced by diffing only
  against `L3OwnedState`. Validated by 12 unit tests in
  `crates/evpn-linux/src/l3_diff.rs` and three privileged netns
  integration tests at `crates/evpn-linux/tests/netns_l3_install.rs`
  (gated on `EVPN_LINUX_NETNS=1`) against Linux 6.17, including
  foreign-route preservation and route-event wakeup. **M39 containerlab smoke**
  validates the bidirectional symmetric Interface-less IRB
  datapath against FRR 10.3.1.
- **Still deferred (alpha-soak follow-up):** duplicate-MAC remote-route
  processing / dataplane loop-protection (local-origin suppression
  shipped per ADR-0055 §9), runtime mutation RPCs
  (`AddEvpnInstance` / `DeleteEvpnInstance`).
  Tracked in [docs/evpn-alpha-soak.md](evpn-alpha-soak.md).
- **Symmetric Interface-less IRB** (RFC 9136 §4.4.2) — shipped
  end-to-end in v0.18.0 (Gate 9 slice 6 PR A #77 origination +
  PR B #78 import/install + PR #79 sub-second route-event
  refresh + M39 hosted smoke). `label2` and Router MAC are now
  interpreted: Router MAC is operator-supplied via
  `[[evpn_ip_vrfs]].router_mac`, `label2` carries the L3VNI on
  origination, and remote Type 5 import maps `(L3VXLAN ifindex,
  router_mac)` to the next-hop's L3 neighbor + L3VXLAN FDB rows
  with conflict detection. Full RFC 9135 overlay-index IRB
  remains deferred.
- **ADR-0059 EVPN aliasing dataplane via FDB nexthop groups** —
  shipped on `main` v0.19.0 across slices 1-4 + M40 hosted smoke (PRs #84/#86/#87/#88/#89). Multi-homed Type 2 routes
  program FDB nexthop groups via `NDA_NH_ID` / `NHA_FDB` on the
  receive path; FRR-validated against EVPN-MH 10.3.1.
  Slice 3.5 hardening follow-ups shipped in v0.20.0 — PRs
  #91 / #92 / #93: per-instance `apply_aliasing_ecmp` off-switch,
  periodic `RTM_GETNEXTHOP` drift recovery, and homogeneous IPv6
  alias members.
- **Type 1 / Type 4 origination via gRPC** — still deferred.
  Native Type 1/4 origination ships through `[[ethernet_segments]]`;
  Type 5 controller injection, including non-zero Gateway Address for
  targeted overlay-index testing, is exposed.
- **RFC 9251 Route Types 6-8** (multicast EVPN), **RFC 9572 Route
  Types 9-11** (BUM segmentation), **RFC 7623 PBB-EVPN**, **MPLS
  encapsulation**, **BGP Add-Path (RFC 7911) for L2VPN EVPN** — still
  deferred.

### Phase 2 interop scripts (local-only driver scripts)

Beyond the M29-M33 set above, several Phase 2 smokes live in
`tests/interop/scripts/` but are not wired into PR-CI — they need
either privileged kernel capabilities or wall time that hosted
runners can't sustain:

| ID | Scope | Status |
|----|-------|--------|
| **M30b** | EVPN Type 5 / IP-Prefix reflection through the RR against a real FRR VTEP with L3VNI binding. | Manual; blocked on hosted runners (Azure-tuned `ubuntu-latest` kernel ships without the `vrf` module so `ip link add ... type vrf` fails inside the FRR container). Runs cleanly on a local box. |
| **M36** | Gate 7b downward path — rustbgpd-as-VTEP, FRR-as-originator. Validates kernel FDB program/withdraw via rtnetlink. | Manual; needs `CAP_NET_ADMIN` (privileged Docker). |
| **M37** | Gate 7b+1 upward path — rustbgpd-as-originator, FRR-as-consumer. Validates Type 2 + IMET origination per ADR-0055. | Manual; needs `CAP_NET_ADMIN`. |
| **M37+IP** | Gate 7b+2 — MAC+IP Type 2 origination via ARP/ND suppression under the FRR-style replace model. | Manual; needs `CAP_NET_ADMIN`. Script: `test-m37-evpn-mac-ip-origination.sh`. |
| **M38** | Gate 8 — observable DF election with two rustbgpd-as-VTEPs sharing an ESI. Validates Type 1/4 origination + the Prometheus `evpn_df_role` surface. | Manual; needs `CAP_NET_ADMIN`. Script: `test-m38-evpn-df-election.sh`. |
| **M39** | Gate 9 slice 6 — bidirectional EVPN Type 5 / symmetric Interface-less IRB (RFC 9136 §4.4.2) between rustbgpd PE1 and FRR PE2. Validates origination + import + kernel route/neighbor/L3VXLAN FDB programming + ping over the L3VNI VXLAN tunnel + the withdraw leg. | `kernel-dataplane` CI (GitHub-hosted; `vrf` loaded from `linux-modules-extra`). Script: `test-m39-evpn-type5-symmetric-irb.sh`. |
| **M40** | ADR-0059 aliasing dataplane ECMP via FDB nexthop groups against FRR EVPN-MH. Validates FDB rows with `nhid`, nexthop groups, alias member collapse, and cleanup. | `kernel-dataplane` CI (GitHub-hosted); needs `CAP_NET_ADMIN` and Linux FDB-NHG support. Script: `test-m40-evpn-aliasing-ecmp-frr.sh`. |
| **M42** | ADR-0061 opt-in general unicast Linux FIB runtime. Validates configured-table install shape, foreign-route preservation, withdraw, SIGTERM drain, and key-only delete semantics against FRR. | `kernel-dataplane` CI (GitHub-hosted). Script: `test-m42-fib-runtime-frr.sh`. |
| **M50** | ADR-0066 unicast multipath/ECMP FIB install. Two FRR peers in the same AS each originate the same prefix; rustbgpd with `[[fib_tables]] maximum_paths=2` installs a kernel `RTA_MULTIPATH` route with both gateways, collapses to the survivor when one path withdraws, and restores the two-way ECMP when it returns. | `kernel-dataplane` CI (GitHub-hosted). Script: `test-m50-fib-ecmp-frr.sh`. |
| **M51** | ADR-0067 single-hop async BFD + RFC 5882 coupling against FRR `bfdd`. Validates BGP Established + BFD Up from both sides (`GetBfdSessions` + `show bfd peers`), then kills `bfdd` and asserts the coupling tears BGP down faster than the 90 s hold timer, and that BFD + BGP recover once `watchfrr` restarts `bfdd`. | `kernel-dataplane` CI (GitHub-hosted). Script: `test-m51-bfd-frr.sh`. |
| **M52** | ADR-0066 multipath-relax. Two FRR peers in different ASes (65002 / 65003) originate the same prefix with equal `AS_PATH` length; rustbgpd with `[global] multipath_relax=true` + `maximum_paths=2` co-installs them as a kernel ECMP route (exact-`AS_PATH` grouping would not), collapses to the survivor on withdraw, and restores ECMP on re-advertise. | `kernel-dataplane` CI (GitHub-hosted). Script: `test-m52-fib-ecmp-relax-frr.sh`. |
| **M58** | ADR-0061 FIB-table runtime CRUD. Drives `SetFibTable` / `DeleteFibTable` / `ListFibTables` against a real kernel: runtime table add, `table_id`/`metric` key-move (old rows withdraw, new install), persist-across-restart, delete withdraws only its rows, and `NOT_FOUND` on a missing name. Companion to M42 (startup FIB path). | `kernel-dataplane` CI (GitHub-hosted). Script: `test-m58-fib-table-crud-frr.sh`. |
| **M60** | ADR-0079 single-dst FDB adoption sweep kill-and-restart. FRR advertises two Type 2 MACs; rustbgpd programs them, is SIGKILLed (netns + kernel FDB survive), one MAC is withdrawn while the daemon is down, and the restart runs with `RUSTBGPD_EVPN_ADOPTION_REAP_DEFERRAL_SECS=5`. Proves the still-desired row stays present continuously (adopted + re-claimed), the unclaimed row is reaped after the deferral, foreign-static rows survive, and the `evpn_fdb_single_dst_adopted_total` / `_reaped_total` counters report the cycle. | `kernel-dataplane` CI (GitHub-hosted). Script: `test-m60-evpn-adoption-sweep.sh`. |
| **M61** | ADR-0079 EVPN L3 adoption sweep kill-and-restart. FRR originates two Type 5 prefixes over the M48 symmetric-IRB topology; rustbgpd imports both into vrf1's kernel table (`proto bgp onlink`) plus the shared L3 neighbor / L3VXLAN FDB resolution rows, is SIGKILLed (netns + kernel rows survive), one prefix is withdrawn while the daemon is down, and the restart runs with `RUSTBGPD_EVPN_ADOPTION_REAP_DEFERRAL_SECS=5`. Proves the still-desired route + shared resolution rows stay marked continuously, the unclaimed route is reaped after the deferral, foreign `proto static` route / non-`extern_learn` neighbor / zebra-stamped `extern_learn` neighbor / stamp-less `extern_learn` + permanent neighbor (the ADR-0082 strict default refuses the pre-stamp legacy shape) rows survive, the re-claimed neighbor row carries the `NDA_PROTOCOL` ownership stamp (`proto bgp`), and the six `evpn_l3_*_adopted_total` / `_reaped_total` counters report the cycle. | `kernel-dataplane` CI (GitHub-hosted). Script: `test-m61-evpn-l3-adoption-sweep.sh`. |
| **M62** | ADR-0079 blackhole discard adoption sweep kill-and-restart. FRR tags two host routes with BLACKHOLE (65535:666) over the M41 topology; rustbgpd installs both as kernel `RTN_BLACKHOLE` + `RTPROT_BGP` discards, is SIGKILLed (netns + kernel rows survive), one prefix is withdrawn while the daemon is down, and the restart runs with `RUSTBGPD_BLACKHOLE_ADOPTION_REAP_DEFERRAL_SECS=5`. Proves the still-desired discard stays present continuously (adopted + re-claimed, `ListBlackholeDiscards` reads `installed/adopted` → `owned`), the unclaimed row surfaces as `adopted_pending_reap` and is reaped only after the deferral, a foreign `proto static` blackhole row survives, and the `bgp_blackhole_discard_adopted_total` / `_reaped_total` counters report the cycle. | `kernel-dataplane` CI (GitHub-hosted). Script: `test-m62-blackhole-adoption-sweep.sh`. |
| **M65** | ADR-0083 single-active failover blackout measurement. rustbgpd is the remote VTEP (receive side); two GoBGP-driven PEs share a single-active ES and a host behind the DUT pings the dual-homed CE at a 100 ms grain across an AC failure (active PE's CE leg down + EAD-per-ES withdrawn, MAC route retained — the RFC 7432 §8.2 mass-withdraw shape). Proves the slice-2 pre-install (one-member FDB NHG, standby NH pre-created but not a member), the slice-3 swap (same group id retargeted to the pre-created backup NH in one membership replace, the MAC row's nhid held continuously, withdrawn PE's NH GC'd, swap counter == 1, gauge == 1), the last-PE ordered teardown (rows flushed, group + NHs gone, teardown counter == 1, pings hard-dead), and foreign FDB rows + an untagged fdb nexthop untouched. Blackout measured informationally (~4.5 s locally, dominated by the dataplane supervisor's 5 s RIB-poll cadence; the swap itself is one `NLM_F_REPLACE`) with a hard < 30 s bound separating the poll-driven repair from the ≤60 s periodic-reconcile backstop. | `kernel-dataplane` CI (GitHub-hosted). Script: `test-m65-evpn-single-active-failover.sh`. |
| **M66** | ADR-0084 Ethernet Segment drain service handover — rustbgpd on both sides (the proof M65 couldn't be: the runtime drain is the origination-side withdrawal stimulus M65 lacked). Two full-dataplane rustbgpd PEs share a single-active ES (RFC 9785 highest-preference DF) behind a rustbgpd VTEP/RR; a host behind the VTEP pings the dual-homed CE at a 100 ms grain. Proves the steady state (Type 4 + EAD-per-ES + EAD-per-EVI from both PEs, CE-MAC Type 2 from the DF only behind the ADR-0083 one-member NHG with the backup NH pre-created), the ADR-0064 operator_only ceiling on the drain RPC (observer principal → PermissionDenied, unknown ESI → NotFound, via rbgp against tier-enforced bearer-token/UDS listeners), the drain itself (all four route classes withdrawn while the peer PE's survive, `changed=true` → repeat `changed=false` idempotence, df gauge → 0, pe2 promotes to DF), the service handover (pe2 learns the CE MAC through the flood path, originates its own Type 2, and the VTEP's CE-MAC FDB row re-resolves toward pe2), SIGHUP-while-drained non-resurrection (a live L2VNI-add reload demonstrably applies while the drained ES stays withdrawn — ADR-0084 decision 3), and the undrain (Type 4 + both EAD classes return immediately, pe1 re-wins DF revertively; after one CE maintenance-exit ARP broadcast — required by two pre-existing daemon gaps the proof surfaces and documents: no same-ESI local bias in the PE remote-MAC projection, and no local-delete observation for the in-place port usurpation it causes — the CE-MAC Type 2 and end-to-end service are asserted back). Blackout measured informationally with a generous < 30 s bound; the BUM-flood-only enforcement limit (non-DF/drained ACs do not block known unicast) typically keeps the observed gap near zero. | `kernel-dataplane` CI (GitHub-hosted). Script: `test-m66-evpn-es-drain-handover.sh`. |
| **M67** | ADR-0085 link-driven Ethernet Segment drain failover and held-off recovery — the M66 sibling with the production trigger: a real AC failure, not an RPC, drives the drain end-to-end (closing the origination-side withdrawal-stimulus arc). Same five-node M66 topology, but the rustbgpd PEs bind their CE-facing attachment circuit (`interface = "eth2"`, `recovery_delay_secs = 5`); the injection is `ip link set eth2 down` inside pe1 (the binding watches pe1's own ifindex carrier; the veth peer — the CE leg — drops too: cable-pull semantics). Proves the carrier monitor armed at steady state with all `evpn_es_drained{esi, reason}` gauges 0; on AC loss the `link` reason gauge → 1 with no operator action (operator gauge stays 0), df gauge → 0, all four route classes withdraw (RFC 7432 §8.2 shape) while pe2's survive, pe2 promotes to DF, the VTEP hands the CE MAC to exactly pe2, and service recovers (blackout informational, 100–300 ms locally — the AC is really dead, so this is the genuine failover — with a generous < 30 s bound); on carrier return the recovery hold-off keeps the gauge at 1 through up+3 s (strict-ish, 2 s margin on the 5 s window) before releasing (~5.5 s observed) and pe1 re-wins DF revertively; a down-up-down-up flap inside the hold-off stays drained past the FIRST up's would-be deadline (the re-arm cancelled it) and recovers only after the LAST up + hold-off; and the reasons compose (ADR-0085 decision 2): an operator drain plus a full link cycle stays withdrawn — link recovery never overrides a maintenance drain — until the operator undrain. Re-runnable: a prior cycle's shared-ESI co-advertisement (legitimate RFC 7432 aliasing once the CE has spoken on both legs) downgrades the two fresh-only steady-state pins to informational. Also asserts the single-active whole-port AC gate (RFC 7432 non-DF full-AC blocking, the ADR-0085 binding follow-on): the non-DF's bound AC port `state disabled` at steady state, `forwarding` on DF promotion, re-blocked after the revert. | `kernel-dataplane` CI (GitHub-hosted). Script: `test-m67-evpn-link-drain-failover.sh`. |
| **M68** | ADR-0087 native GW-IP overlay-index Type 5 consume-side proof against FRR. rustbgpd originates a Type 5 for `203.0.113.0/24` from a static VRF route via Gateway Address `10.1.1.5`, with L2VNI 10 linked to L3VNI 100 / vrf1 on both PEs. FRR runs `enable-resolve-overlay-index`; the driver asserts FRR receives the Type 5 but keeps it out of vrf1 until rustbgpd originates the companion MAC/IP Type 2 for `10.1.1.5`, then imports the prefix into vrf1 via that gateway (BGP RIB and kernel route). Withdrawing the static route drops the Type 5 and imported route. | `kernel-dataplane` CI (GitHub-hosted). Script: `test-m68-evpn-type5-gwip-overlay-index-frr.sh`. |
| **M69** | RFC 9785 highest-preference DF election, cross-vendor with FRR. rustbgpd advertises ES-DF preference 100 and FRR 200 (`evpn mh es-df-pref 200`); default RFC 7432 modulo service-carving would elect rustbgpd for VNI 200, so asserting rustbgpd NonDF + FRR DF proves the preference algorithm overrides carving on both sides. | `kernel-dataplane` CI (GitHub-hosted). Script: `test-m69-evpn-preference-df-frr.sh`. |
| **M70** | ADR-0089 VLAN-aware bridge FDB attribution against FRR. rustbgpd owns one `vlan_filtering=1` bridge (`brvlan`, VLAN10/VNI100 + VLAN20/VNI200); FRR (traditional one-bridge/VXLAN-per-VNI) originates the same MAC independently in both VNIs. Proves rustbgpd programs VLAN-scoped (`NDA_VLAN`) remote-MAC FDB rows and that a VNI100 withdraw removes only the VLAN10 row while the VLAN20 row survives. | `kernel-dataplane` CI (GitHub-hosted). Script: `test-m70-evpn-vlan-aware-bridge-frr.sh`. |
| **M71** | RFC 9136 §4.3 ESI overlay-index Type 5 single-active recursion, rustbgpd receive side. A GoBGP route source injects a non-zero-ESI RT-5 plus EAD-per-ES / EAD-per-EVI state into a full rustbgpd L3 datapath. Proves the RT-5 is held unresolved before EAD state exists, imports through exactly one single-active remote VTEP when EAD-per-ES carries the Single-Active flag, fails closed when the same EAD-per-ES is advertised all-active by the single PE (`unsupported_all_active_target_set`), and withdraws cleanly. M72 proves the multi-PE all-active success path. | `kernel-dataplane` CI (GitHub-hosted). Script: `test-m71-evpn-esi-overlay-type5-receive-gobgp.sh`. |
| **M72** | RFC 9136 §4.3 ESI overlay-index Type 5 all-active recursion, rustbgpd receive side. Two GoBGP-driven PEs advertise the same non-zero-ESI RT-5 all-active with EAD-per-ES / EAD-per-EVI state into a full rustbgpd L3 datapath. Proves the all-active multi-PE success path M71 deferred: the RT-5 recursively resolves through both remote VTEPs (ECMP), complementing M71's single-active single-PE coverage. | `kernel-dataplane` CI (GitHub-hosted). Script: `test-m72-evpn-esi-overlay-type5-all-active-gobgp.sh`. |
| **M73** | RFC 9552 BGP-LS reflection interop receipt, GoBGP ↔ rustbgpd. A GoBGP route source injects BGP-LS link-state NLRI; rustbgpd reflects it (route-reflector path) and the receipt asserts the reflected link-state routes arrive intact. | Hosted CI (GitHub-hosted) in `.github/workflows/interop.yml`. Script: `test-m73-bgpls-reflection-gobgp.sh`. |
| **M76** | RFC 9107 Optimal Route Reflection divergent-best interop receipt, GoBGP ↔ rustbgpd. A linkstate-only GoBGP source injects a four-link BGP-LS square; two GoBGP PEs announce the same prefix with different next-hops; two RR clients pinned to different `orr_vantage` IGP locations receive DIVERGENT best paths for that one prefix, driven purely by the injected topology. A metric flip moves only the affected client (no session flap, zero UPDATEs toward the other), withdrawing the LSDB falls both clients back to one identical standard best, re-injection restores the divergence, the RR touches no dataplane, and the linkstate-only source session never flaps across the run (wire regression pin for the #632 implicit-IPv4 negotiation fix this topology exposed). | Hosted CI (GitHub-hosted) in `.github/workflows/interop.yml`. Script: `test-m76-orr-divergent-best-gobgp.sh`. |

---

## Post-v0.1 feature history

Build-order and implementation detail for features that shipped after the
initial v0.1.0 milestone set above. This is the historical worklog relocated
out of `ROADMAP.md` so the roadmap stays forward-looking. For the current
capability state see [ROADMAP.md](../ROADMAP.md); for per-release deltas see
[CHANGELOG.md](../CHANGELOG.md). Development-phase labels have been translated
to the plain capability they delivered.

### Config reload and runtime mutation

- **SIGHUP policy/peer-group reconciliation** (v0.12.0) — `reload_config`
  applies named-policy / neighbor-set / peer-group / global-chain edits, not
  just `[[neighbors]]` deltas. Each delta routes through the same
  `apply_policy_change` / `apply_peer_group_change` paths the gRPC API uses,
  so runtime effect matches the API. Order: definitions/sets/peer-groups/chains
  add+change first, then `[[neighbors]]` reconcile, then deletes in
  reverse-dependency order. Inline `policy.import` / `policy.export` still
  require restart (no runtime swap surface); `--diff` flags this under
  Restart-required.
- **Effective neighbor diff via peer-group resolution** (v0.12.0) —
  `rustbgpd --diff` surfaces per-neighbor "effective impact" via
  `effective_neighbor_impact` / `ConfigDiff::effective_neighbor_impact`, so a
  single peer-group / policy / neighbor-set edit shows every neighbor whose
  resolved chain would move at reload, not just the raw upstream change.
- **Auto-retry pending soft-resets and policy hot-applies across SIGHUP
  boundaries.** `update_runtime_policies` is bail-and-retry across every
  downstream step: `ManagedPeer.pending_refresh` covers unfired Route Refresh
  intent; `ManagedPeer.pending_export_apply` covers unfired session-side export
  updates with the same bail-and-carry semantics; advancing
  `managed.import_policy` / `managed.export_policy` is deferred until the
  session ACKs, and bails before the RIB update + Route Refresh when any
  session-side hot-apply fails. Cross-side carry re-arms both pending flags so
  the retry pipeline picks up every unfired step; the RIB-failure path also
  re-arms `pending_refresh`. Closes the silent-stale-routes class across
  import / export / RIB / refresh failure modes.
- **Dead-letter pending flags on dynamic-peer auto-removal** (v0.13.2) —
  `PeerManager` carries a per-IP `dead_lettered_pending` side table (bounded at
  `dynamic_neighbor_limit`) that snapshots `pending_refresh` /
  `pending_export_apply` before `BackToIdle`'s `peers.remove(...)` and restores
  them when `handle_inbound` recreates a dynamic `ManagedPeer` at the same
  address. Closes the silent-loss case for transient TCP drops on
  `[[dynamic_neighbors]]` peers carrying unfired hot-apply intent.
- **Post-reload sync resilience** (v0.13.2) — `apply_reload_outcome` lifts the
  post-reload sync and reorders it: peer manager first (unbounded, can only
  fail on receiver-drop), config bridge second. Failure surfaces as a named
  stage (`peer_mgr_snapshot` / `config_bridge`). Same release fixed the gRPC
  `ConfigEvent` → persister bridge holding a stale `current_config` across
  SIGHUP (which would overwrite the persisted file with the pre-reload snapshot
  plus one mutation); replacement now routes through the bridge so the bridge's
  snapshot and the persister advance in lockstep.
- **Reload on its own task** (v0.13.2) — `reload_config` runs on a dedicated
  tokio task tracked as `Option<JoinHandle<...>>`. The main `select!` polls the
  completion handle via the standard arm-gating pattern, so SIGINT / SIGTERM /
  gRPC shutdown observation is no longer blocked by an in-flight reload.
  Concurrent reloads are rejected with a warning; coordinated shutdown aborts
  any in-flight reload before tearing down the peer manager.
- **Native gRPC mTLS** (v0.11.0) — TCP listeners terminate TLS in-process via
  tonic + rustls/ring. `tls_cert_file`, `tls_key_file`, and `tls_client_ca_file`
  are required together on `[global.telemetry.grpc_tcp]`; partial config is
  rejected at `Config::load`, and the three PEM files are read at config-load /
  `--check` time so missing, unreadable, empty, non-PEM, or wrong-kind material
  fails before the daemon starts. No "TLS-without-mTLS" half-mode — server
  identity + client-cert verification land together. UDS listeners are
  unchanged (filesystem permissions remain their auth surface).

### CLI surface

- **`rbgp` policy / peer-group / neighbor-set commands** (#61) — three
  subcommand trees wrap `PolicyService` (18 RPCs) and `PeerGroupService`
  (6 RPCs): read (`policy list/get`, `peer-group list/get`,
  `neighbor-set list/get`); write (`policy set/delete`, `peer-group set/delete`,
  `neighbor-set set/delete`, `set` accepting `--from-file PATH` whose shape
  mirrors the proto message, with `serde(deny_unknown_fields)` rejecting typos
  at parse time); chain management (`policy chain
  show|set-import|set-export|clear-import|clear-export [--neighbor ADDR]`);
  peer-group binding (`peer-group attach ADDR --group NAME` / `detach ADDR`).
  29 mock-server / clap-parse tests pin the dispatch path. `--explain-peer`
  on `rib --explain` (Add-Path send view) shipped alongside. Daemon-side
  `rustbgpd --diff` reports reload-applied policy / peer-group /
  effective-neighbor impact, restart-required startup-only surfaces, and
  hot-applied global honor flags. A live `rbgp policy diff
  <candidate.toml>` against an API-exported runtime snapshot remains a larger
  config-snapshot design task if operators need it.

### Graceful Shutdown and BLACKHOLE

- **BGP Graceful Shutdown (RFC 8326)** (v0.13.3, ADR-0053, M35) — well-known
  `GRACEFUL_SHUTDOWN` community (`65535:0`) end-to-end. Wire constant in
  `crates/wire`; policy engine accepts `"GRACEFUL_SHUTDOWN"` as a community
  alias on match and set sides. Receiver behavior: opt-in
  `[global] honor_graceful_shutdown = true` appends an implicit chain-tail rule
  (`match GRACEFUL_SHUTDOWN → set local_pref = 0`) to every EBGP peer's import
  chain — chain tail (not head) so the demotion wins last-writer accumulation
  against any operator policy that also sets `LOCAL_PREF`; iBGP exempt.
  Initiator behavior: gRPC `NeighborService.SetGracefulShutdown { address,
  enabled }` (empty address = all peers) + `rbgp gshut [--peer X]
  [--clear]`, stored on `ManagedPeer`, mirrored to the live session, replayed on
  session restart, and triggering `RibUpdate::RefreshPeerOutbound` so wire state
  updates immediately. M35 validates both legs plus the clear leg against FRR
  10.3.1. Follow-ups that subsequently shipped: dynamic-peer GShut replay via
  the per-peer dead-letter side table (v0.13.4); honor-knob SIGHUP hot-reload
  with per-peer effective-chain recompute (v0.13.4); FlowSpec + EVPN
  initiator-leg coverage (M35b injects FlowSpec, M35c injects an EVPN Type 2
  route, both toggling GShut without route churn). Confederation gating of the
  EBGP gate inside `effective_policy_chains_for_neighbor` remains a follow-up
  (the current `remote_asn != self.global.asn` gate is correct for the
  traditional EBGP/iBGP topology rustbgpd supports today and becomes load-bearing
  only when confederations land — tracked in `KNOWN_ISSUES.md`).
- **RFC 7999 BLACKHOLE receiver + opt-in FIB discard** (v0.21.0) — natural
  sibling to RFC 8326. Well-known `BLACKHOLE` community (`65535:666`) signals
  "drop traffic to this prefix" for DDoS mitigation; receiver behavior is
  data-plane (install a discard/null route) rather than control-plane (de-pref).
  Wire constant `COMMUNITY_BLACKHOLE` plus RFC 1997 well-known constants for
  `NO_EXPORT` / `NO_ADVERTISE` / `NO_EXPORT_SUBCONFED`; policy alias on every
  community-match/set site; CLI renders all of these plus `GRACEFUL_SHUTDOWN`,
  `LLGR_STALE`, and `NO_LLGR`. Opt-in `[global] honor_blackhole = true` appends
  an EBGP import chain-tail rule (`match BLACKHOLE → permit, add BLACKHOLE +
  NO_ADVERTISE`) and hot-applies on SIGHUP. `[global] install_blackhole_discard
  = true` (paired with `honor_blackhole`) starts a Linux kernel-discard
  reconciler: installs daemon-owned `RTN_BLACKHOLE` routes for EBGP-learned
  BLACKHOLE best routes, defaults to host routes only (`/32` and `/128`),
  refuses to overwrite pre-existing kernel routes, cleans up on withdraw /
  shutdown, and surfaces status through `rbgp rib blackholes` + Prometheus
  counters. M41 is CI-gated against FRR 10.3.1. Remaining BLACKHOLE work:
  per-peer / peer-group allow-lists, active-blackhole / rate limits, startup
  adoption or explicit stale-cleanup policy, audit trails, and an outbound
  advertise surface (gRPC `SetBlackhole { peer, prefix, enabled }` or
  per-prefix import-filter `set_community_add = ["BLACKHOLE"]`).

### Unicast FIB integration

- **Opt-in unicast Linux FIB integration** (v0.21.0, ADR-0061, M42) —
  configured `[[fib_tables]]` blocks start a default-off reconciler that
  projects unicast Loc-RIB best routes into explicit non-reserved Linux route
  tables. Pure intent/diff model plus a runtime actor; conservative ownership
  (`RTPROT_BGP` is not ownership proof, so pre-existing and externally-drifted
  rows are preserved and reported as `foreign_route_exists`); status via
  `RibService.ListFibRoutes`, `rbgp rib fib`, and Prometheus `bgp_fib_*`
  counters; privileged netns harness plus the M42 FRR containerlab smoke.
  Follow-up hardening added per-peer / peer-group allow-lists, route-count caps,
  and exact-match crash-restart recovery through persisted owned-state under
  `runtime_state_dir`.

### Dependency / audit hygiene

- **`cargo audit` findings resolution** (v0.13.1 / v0.13.2 / v0.14.0) —
  RUSTSEC-2024-0437 (protobuf 2.28.0 uncontrolled recursion, transitive via
  `prometheus 0.13.4`) cleared in v0.13.1 by bumping `prometheus 0.13 → 0.14`
  (protobuf 3.x; migrated four test/internal files to the proto-3 field/method
  API split); stale ignore entry dropped in v0.13.2. RUSTSEC-2026-0097
  (`rand` unsound with a custom logger, transitive via the ratatui-termwiz CLI
  `top` dependency) accepted as unreachable in v0.13.2 — the workspace installs
  no custom rand logger. RUSTSEC-2024-0436 (`paste` 1.0.15 unmaintained,
  transitive via `netlink-packet-utils → rtnetlink`) accepted in v0.14.0 as
  informational (pure proc-macro, no runtime behavior); revisit when upstream
  swaps `paste` for `pastey`. v0.14.0 also granted `checks: write` to the audit
  workflow so the rustsec/audit-check action can post findings via the GitHub
  Checks API.

### EVPN VXLAN VTEP / IRB dataplane

- **EVPN Route Reflector — Phase 1** (v0.9.0, RFC 7432, ADR-0050, M29–M33) —
  L2VPN/EVPN (AFI 25 / SAFI 70) RR role for VXLAN-EVPN DC fabrics. All five
  RFC 7432 route types (EAD per-ES, EAD per-EVI, MAC/IP, IMET, Ethernet Segment,
  IP Prefix per RFC 9136), MAC mobility best-path per §15.1 with sticky-flag
  preservation, RFC 4456 reflection applied to EVPN routes, six typed
  extended-community accessors (BGP Encapsulation for VXLAN per RFC 8365/9012,
  MAC Mobility, ESI Label, ES-Import RT, Router MAC per RFC 9135, Default
  Gateway). `ListEvpnRoutes` gRPC RPC + `rbgp evpn` CLI. Includes review
  correctness fixes: source-peer split horizon, same-peer attribute-change
  detection, full RFC 4456 tie-break chain, max-prefix counting EVPN keys +
  FlowSpec rules, EVPN withdrawals propagated through both AS_PATH and
  CLUSTER_LIST loop branches, EVPN initial dump for late-joining peers, EVPN ERR
  refresh tracking, Type 5 prefix in policy context. See the M29–M33 section
  above for the build order and `docs/evpn-enablement.md` for the gate ladder.
- **EVPN VXLAN VTEP dataplane — Linux FDB reconciler** (v0.14.0, ADR-0054, M36)
  — new workspace crate `crates/evpn-linux` ships the level-triggered
  `ReconcileActor<D: Dataplane>` and the pure `compute_diff` function with
  structural foreign-entry preservation (delete pass iterates `OwnedSet`, never
  the kernel snapshot), per-op exponential backoff (100 ms → 5 s with
  deterministic ±25% jitter), per-op-fingerprint permanent-failure suppression,
  and a `tokio::sync::watch<Arc<DataplaneIntent>>` input from the daemon.
  `crates/evpn` gains `DataplaneIntent` / `RemoteMacTable` / `LocalMacObservation`
  plus a pure `project_evpn_routes` from RIB best-paths. The daemon polls the
  RIB's `QueryEvpnRoutes` channel every 5 s and only bumps the intent generation
  on semantic change; empty `[[evpn_instances]]` short-circuits the spawn so
  RR-only deployments incur zero dataplane cost. `LinuxDataplane` programs FDB
  via a single `RTM_NEWNEIGH` with combined `NTF_SELF | NTF_MASTER |
  NTF_EXT_LEARNED` and `ndm_state = NUD_NOARP | NUD_PERMANENT`; the dump path
  merges the kernel's `NTF_SELF` (carries `dst`) and `NTF_MASTER` (no `dst`)
  rows for the same `(VNI, MAC)` so `dst` survives; the errno-based classifier
  maps `EPERM`/`EACCES`, `EOPNOTSUPP`, and `EINVAL` to permanent-class errors.
  M36 real-VTEP containerlab smoke passes 8/8 against Linux 6.17 + FRR 10.3.1.
- **EVPN local MAC origination — Type-2 + Type-3 IMET** (v0.15.0, ADR-0055, M37)
  — closes the upward EVPN flow. `crates/evpn/src/origination.rs` ships the
  deterministic `LocalMacOriginator` state machine encoding RFC 7432 §15.1
  sequence rules (17 in-module tests including a monotonicity invariant).
  `crates/wire/src/pmsi.rs` adds the PMSI Tunnel path attribute (RFC 6514 §5,
  type 22) with a typed `PmsiTunnelType` encoding the label as the raw 24-bit
  VNI per RFC 8365 §5.1.3. `src/evpn_originator.rs` mirrors the dataplane actor
  on the upward flow; `src/evpn_imet.rs` originates one Type 3 IMET per
  `EvpnInstance` at startup and withdraws at shutdown. The upward channel in
  `crates/evpn-linux` subscribes to `RTNLGRP_NEIGH`, drains the unsolicited
  multicast stream, and classifies via a pure `classify_neigh` (drops
  `NTF_EXT_LEARNED` echoes and VXLAN-port ifindexes, resolves bridge-port → VNI).
  Coordinated shutdown drains originator → IMET withdraws → reconciler. M37
  containerlab smoke validates rustbgpd as a Type 2 + Type 3 originator against
  an FRR consumer.
- **EVPN VTEP convergence + MAC+IP** (v0.17.0) — MAC-with-IP Type 2 origination
  under ARP/ND suppression (`AF_INET` / `AF_INET6` classifier,
  `LocalMacIpOriginator`, FRR-style replace model per RFC 9135 §7.2.3; operator
  prerequisite `bridge neigh_suppress on`); push-notified RIB broadcasts for
  sub-second mobility convergence (EVPN-keyed `EvpnRouteEvent`, with the 5 s poll
  retained as `Lagged` / cold-start backstop); `advertise_svi_mac` originating
  the bridge's own MAC on Ready; `sticky_macs` config carrying the RFC 7432
  §15.4 sticky bit on origination (ADR-0056); and the RFC 7432 §15.1
  duplicate-MAC detector with detect-only default plus opt-in `suppress_local`
  quarantine, remote-route processing suppression, receive-side intent
  filtering, and a manual `ClearDuplicateMacQuarantine` API.
- **EVPN runtime mutation** (ADR-0063, #210) — the daemon actor converger
  commits single L2VNI add/delete/redefine, single IP-VRF
  add/standalone-delete/redefine with unchanged L3VNI/device/table identity,
  single Ethernet Segment add/delete/redefine (including ES add/redefine over a
  member VNI added by an earlier live L2VNI add), additive build-up, atomic
  tenant teardown (M47/M48), and `ip_vrf` relink. Restart-required/fail-closed
  edits: L3VNI/device/table IP-VRF identity changes (a kernel VRF lifecycle
  operation, restart-required by design) and generic mixed add/delete/redefine
  edits (fail closed with a "split the request" error, pending a generalized
  converge-to-candidate follow-up).
- **EVPN multi-homing — ESI, Type-1/Type-4** (v0.17.0, ADR-0057, M38/M46/M49) —
  observable DF election + Type 1/4 origination. Pure DF election state machine
  (RFC 7432 §8.5 service carving + RFC 8584 §3.2 Highest Random Weight + RFC 9785
  Highest-/Lowest-Preference, with fallback to default when candidates disagree),
  three Type 1/4 originator state machines (Type 4 ES, Type 1 EAD-per-ES with
  MAX_ET, Type 1 EAD-per-EVI), daemon orchestrator subscribed to the EVPN
  best-path broadcast, Prometheus `evpn_df_role{esi,vni,role}` gauge +
  `evpn_df_role_changes_total` counter, and an ADR-0063 runtime owner/control
  surface keeping complete desired-ES snapshots under the segment actor. M38
  covers default modulo, M46 covers HRW, M49 covers RFC 9785 Highest-Preference.
  Auto-derived ES-Import RT extcomm on Type 4 ES routes and ESI Label extcomm on
  Type 1 EAD-per-ES routes; `[[ethernet_segments]].redundancy_mode` sets the ESI
  Label `single_active` flag (`all-active` default), and the receiver suppresses
  all-active aliasing ECMP for remote single-active ES reachability. RFC 9785
  local Don't-Preempt origination shipped (`df_dont_preempt`; the DP bit is
  origination + parse only). Stateful non-revertive election + single-active
  backup-path pre-install remain deferred.
- **EVPN BUM-flood suppression + DF election enforcement** (v0.17.0
  onward) — DF-election role state feeds the Linux dataplane supervisor as a
  portable `(ESI, VNI)` BUM-enforcement table; the reconciler resolves bridge,
  VXLAN ifindex, and CE-facing port identity and reports `allow` for DF /
  `suppress` for Non-DF through `DataplaneReport.bum_enforcement`. The
  enforcement primitive flips `flood off / mcast_flood off / bcast_flood off` on
  the kernel bridge port — validated end-to-end by `evpn_bum_filter_kernel` in
  CI under a Docker harness with `CAP_NET_ADMIN + CAP_SYS_ADMIN`. RFC 7432 §14
  aliasing receive-side projection (`crates/evpn/src/aliasing.rs`) and §8.4
  receive-side EAD-per-ES mass-withdraw filtering
  (`crates/evpn/src/mass_withdraw.rs`) landed alongside. BUM-port enforcement and
  aliasing ECMP became production defaults (`apply_bum_enforcement` /
  `apply_aliasing_ecmp` default `true`, explicit `false` opt-out) since v0.23.0,
  after the BUM-state 24 h MAC-churn soak and the M37 local-origination 24 h soak
  cleared the default-flip gate. Note this is role-based DF/non-DF BUM
  suppression + aliasing ECMP, not source-conditioned local-bias split-horizon
  (see the deferred items in ROADMAP.md).
- **EVPN symmetric IRB — Type-5 / L3VNI** (v0.18.0, ADR-0058, M39) —
  `[[evpn_ip_vrfs]]` TOML schema with VRF / L3VXLAN device binding and
  operator-supplied Router MAC, plus an L2VNI `ip_vrf` link; pure-logic
  `IpVrf` / `IpVrfTable` domain types in `crates/evpn::ip_vrf`. Pure-logic
  Type 5 origination + projection helpers enforce the RFC 9136 §4.4.2
  Interface-less symmetric IRB model. `IpVrfStatus` readiness probe checks the
  seven ADR-0058 §3 predicates (VRF device exists + UP + matches `table_id`;
  L3 VXLAN exists + UP + matches VNI + matches local VTEP IP + enslaved to the
  VRF + MAC matches Router MAC). `crates/evpn-linux` adds rtnetlink-backed VRF /
  L3VXLAN dumps building an `IpVrfKernelSnapshot`; `Dataplane::probe_ip_vrfs`
  wires it through, the reconcile actor calls it every pass, and readiness
  transitions surface via `tracing` + `DataplaneReport.ip_vrf_status` +
  `EvpnService.ListIpVrfs` / `GetIpVrf` + `rbgp evpn vrfs`. The
  daemon-side origination feed (#77) does a per-pass kernel-route dump per
  IP-VRF with a conservative classifier (filters routes from other daemons,
  non-forwardable types, and routes egressing the L3 VXLAN), a `watch`
  observation channel, an L3 originator task with a level-triggered diff loop
  gated on readiness, and `originated_routes_count`. The dataplane import (#78)
  drives `project_ip_prefix_routes()` against a transactional `L3OwnedState`
  tracking per-prefix install state plus shared `kernel_neighbors` /
  `kernel_fdb` rows with value-aware drift detection (a Router MAC or next-hop
  transition under the same prefix triggers an atomic `.replace()`). A four-phase
  apply ordering (route-remove → resolution-add → route-add → resolution-remove)
  keeps the kernel forwarding-safe across transitions; Router MAC conflicts drop
  conflicting prefixes with `L3Drop::RouterMacConflict`; foreign state is
  preserved by diffing only against `L3OwnedState`. 11 unit tests in
  `l3_diff.rs` and two privileged netns integration tests validate kernel
  programming against Linux 6.17. M39 hosted kernel-dataplane smoke validates the
  bidirectional symmetric IRB datapath against FRR 10.3.1.
- **EVPN aliasing dataplane ECMP via FDB nexthop groups** (v0.19.0–v0.20.0,
  ADR-0059, M40) — multi-homed Type 2 routes on the receive path program FDB
  nexthop groups via `NDA_NH_ID` / `NHA_FDB` (raw-netlink construction because
  `rtnetlink 0.21` exposes no nexthop API). Portable intent
  (`RemoteMacEntry::alias_group_key`) + projection same-AF guard; the
  `nexthop_raw` netlink primitive with the canonical member-set encoder; state
  types (`NhIdAllocator` with `0x3000`/`0x4000` tag bits, `GroupOwnedMap`
  refcount) + apply primitive + CVE-2025-39851 inline guard (refuses install on
  a VXLAN device with `learning on`); `compute_diff` Pass 1b emitting
  `InstallFdbNhg` / `UpdateFdbNhgMembers` / `RemoveFdbNhg`, the reconcile actor
  coordinator orchestrating ADR-0059 §5 invariant order, `NexthopOps` impls on
  `LinuxDataplane` + `InMemoryDataplane`, startup NHID adoption with a
  snapshot-aware retention set, partial-install rollback, a three-key-space retry
  schedule, a `pending_deletes` retry queue, and shutdown teardown. M40
  containerlab smoke against FRR EVPN-MH 10.3.1 passes 16/16 first-shot,
  validating the `NHG_TAG | n` / `VTEP_NH_TAG | n` tag scheme and the clean
  drain-to-single-dst transition when an alias withdraws. v0.20.0 hardening:
  per-instance `apply_aliasing_ecmp` off-switch (restart-required); periodic
  `RTM_GETNEXTHOP` drift recovery that heals missing/mis-shaped per-VTEP members,
  drifted groups, stale tagged FDB rows, and untracked tagged NHIDs (with a
  `(VNI, MAC)` desired-intent guard so cleanup never removes live forwarding
  state); and homogeneous IPv6 alias members (`encode_add_fdb_member` picks
  `AF_INET` / `AF_INET6` from the gateway form). The obsolete
  `NexthopError::Ipv6Unsupported` variant was removed for v0.21.0.
- **EVPN overlay-index recursion (receive side)** — auto-derived Route Targets
  (RFC 8365 §5.1.2.1) are an explicit config opt-in for `[[evpn_instances]]` and
  `[[evpn_ip_vrfs]]`, and receive-side RFC 9135 §9.2 recursion resolves non-zero
  Type 5 Gateway Address routes through linked Type 2 MAC/IP state in L2VNIs
  linked to the target IP-VRF, tie-breaking contenders by MAC mobility sequence.
  Controller injection can synthesize non-zero Gateway Address Type 5 routes
  (M45) while native IP-VRF origination remains Interface-less. Missing links,
  unresolved gateways, multi-MAC gateways, self-originated rows, quarantined
  MACs, mass-withdraw-filtered rows, RT misses, and L3VNI mismatches all stay
  fail-closed. Remaining standards-completeness items live in ROADMAP.md
  (native local overlay-index origination, multi-homed-gateway ECMP,
  protected recursion-path interop smoke).

### Observability and durable events

- **Durable event history — local outbox** (ADR-0072, #286–#290) — daemon-local
  SQLite WAL outbox with a monotonic `event_id` that survives restart. The new
  `crates/event-history` crate hosts the `EventHistoryManager` actor + the
  3-step actor-ordered cursor handoff for `SubscribeFromEvent` (replay → live
  without gaps or duplicates). Producer wiring covers RIB route + EVPN (through a
  `RibEventSink` trait), PeerManager session-lifecycle + notification + policy
  (in-place enqueue), and the BFD bridge; the gRPC handler replaces the
  `UNIMPLEMENTED` stub with the cursor handler (single-category-cursor fast path
  + post-filter for repeated categories / `event_types` / `afi_safi` /
  `prefix_length`, leading `StreamLagEvent` when the requested cursor is older
  than the retention floor); CLI `rbgp events watch --from-event-id <u64>`;
  `examples/event-bridge/` reference binary. Legacy `WatchEvents` /
  `WatchRoutes` / `List*Events` surfaces stay byte-identical. Notification events
  are durably persisted for the first time, closing ADR-0071's
  notification-history gap. `bgp_event_outbox_cursor_gap_total` signals
  undersized retention vs the collector reconnect SLA.
- **Durable-event-history downstream closeouts** (v0.30.0) — #291 wired the
  dataplane FIB / blackhole producers through the event-history manager (closes
  the ADR-0072 v1 dataplane deferral); #292 added the structured
  `OtcRouteBlockedEvent` payload under `EVENT_CATEGORY_POLICY` with the next-free
  `BGP_EVENT_TYPE_OTC_ROUTE_BLOCKED` enum, sourced from a new `TransportEventSink`
  trait mirroring `RibEventSink` (closes the ADR-0071 deferral); #293 wired gNMI
  `STREAM ON_CHANGE` for `…/neighbor[neighbor-address=*]/state/session-state`,
  sourcing live FSM transitions from `EventHistoryManager::subscribe_live()` with
  fresh-snapshot-on-reconnect semantics (closes the ADR-0070 deferral, ships
  M56). Each PR preserves the original ADR deferral text with a "Resolved by
  PR #N" annotation. #291 is unit + integration tested; #292 leans on the
  existing M55 OTC interop; #293 ships M56 (gNMI ON_CHANGE against FRR 10.3.1).

### Post-v0.7.0 incremental releases

- **ASPA verification** (v0.7.0, ADR-0049) — upstream path verification with
  RTR v2 support.
- **Config diff** (v0.7.0) — `rustbgpd --diff` previews SIGHUP changes.
- **Looking glass REST API** (v0.7.0) — birdwatcher-compatible endpoints.
- **Best-path explain** (v0.7.0) — `ExplainBestPath` RPC + `--explain` CLI.
- **Writer-task split** (v0.10.0, ADR-0051) — closes the +46-min `GetHealth`
  wedge under sustained churn; validated on 1 h + 4 h + 12 h M33 soaks. The peer
  session task no longer owns the TCP write half; a dedicated writer task per
  peer holds the `OwnedWriteHalf` plus a bounded bulk channel + unbounded
  priority channel with biased select so NOTIFICATION/KEEPALIVE/OPEN preempt
  UPDATE backlog. When the bulk channel saturates the session emits `Cease/8`
  (Out of Resources) and tears down — silent drops become observable flaps with
  clean BGP restart semantics. (Root cause of the original wedge was later found
  to be a load-test bug: `bench/evpn-load`'s synthetic peers exposed
  `PeerHandle.rx` but the tester never drained it, so RR-side reflection filled
  the 65 536-deep channel in ~43.7 minutes. The writer split was always correct;
  it kept Cease/8-disconnecting a broken consumer because that is its job.)
- **BMP `bmp_*_total` Prometheus counters** (v0.10.0) — four counters cover
  source / collector / replay / control-event drops.
- **EVPN BMP + MRT export** (v0.11.0) — RouteMonitoring already flowed; MRT now
  emits `RIB_GENERIC` for EVPN with `MP_REACH_NLRI` in RFC 6396 §4.3.4 reduced
  form.
- **`EvpnRibRoute` payload+key refactor** (v0.11.0) — drops the cached key,
  identity derived on demand.
- **IPv6 link-local next-hop preserved end-to-end** (v0.11.0) — 32-byte
  `MP_REACH_NLRI` next-hops (RFC 4760 §3 / RFC 2545) round-trip through wire
  codec, RIB, and MRT exports; closes the long-standing "link-local discarded"
  limitation. `rustbgpd-wire` 0.7.0 → 0.8.0 (breaking — adds
  `link_local_next_hop` to `MpReachNlri`).
- **EVPN VTEP foundation — declarative EVI/VNI domain model** (v0.13.0,
  ADR-0052) — new `crates/evpn` exposes the runtime `EvpnInstance` /
  `EvpnInstanceTable` types; `[[evpn_instances]]` config block (VNI, RD, RTs,
  local VTEP IP, optional bridge, `advertise_svi_mac`); read-only
  `EvpnService.ListEvpnInstances` + `rbgp evpn instances`; wire crate gains
  `RouteDistinguisher::from_str`. Empty by default — RR-only deployments
  unchanged.

### RibManager split and module hygiene

- **RibManager submodule split** — 8,318-line `manager.rs` split into 7
  submodules (`mod.rs`, `distribution.rs`, `peer_lifecycle.rs`,
  `route_refresh.rs`, `graceful_restart.rs`, `helpers.rs`, `tests.rs`).

### Transport→RIB inbound backpressure (ADR-0078)

- **Block-never-drop inbound delivery, writer-owned KEEPALIVE cadence, and
  pending-input hold-timer re-arm** — proven against a real FRR peer by the
  **M63** interop job (`test-m63-stalled-rib-hold-timer.sh`, hosted
  `interop.yml` CI). The RIB manager is stalled 12 s per `RoutesReceived`
  batch via the test-only `RUSTBGPD_TEST_RIB_INGEST_STALL_MS` env with the
  transport→RIB channel shrunk to 2 slots via
  `RUSTBGPD_TEST_RIB_CHANNEL_CAPACITY`; FRR floods 4000 /32 statics in 8
  waves spaced 2 s apart (the spacing lower-bounds the UPDATE batch count
  regardless of NLRI packing, so the guaranteed stall is ≥ 96 s ≫ 2× the 9 s
  negotiated hold time). Asserts both ends stay Established at 1 s grain
  through a 40 s survival window inside the stall,
  `bgp_inbound_rib_backpressure_total` > 0, exactly 4000 routes in the RIB
  after the drain (never-drop receipt), and zero flaps from both vantage
  points; `bgp_hold_timer_rearmed_pending_input_total` is logged
  informationally (expected 0 in this shape — each parked delivery
  completes with the UPDATE's normal hold reset, so the select loop never
  observes an expired deadline; that path stays pinned by unit tests).
