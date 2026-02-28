# Roadmap

Build order and milestone plan for rustbgpd. Each milestone is a tagged
release with passing CI, updated interop matrix, and changelog entry.

---

## Market Context

The BGP daemon space is dominated by monolithic C implementations that
bundle BGP with OSPF, IS-IS, and every other routing protocol:

| Project | Language | Model | Strengths | Gaps |
|---------|----------|-------|-----------|------|
| FRR | C | Full routing suite | Feature-complete, wide adoption | Monolith, CLI-first, limited API |
| BIRD | C | Full routing suite | Excellent filter language, lightweight | CLI-first, no native gRPC |
| OpenBGPD | C | BGP-only | Clean design, OpenBSD pedigree | Limited platform support, no API |
| GoBGP | Go | BGP-only, gRPC API | API-first, good ergonomics | GC pauses at scale, Go-specific protos |

**Why rustbgpd exists:**

- **GoBGP proved the model.** API-first BGP with gRPC works. Operators
  want programmable routing, not CLI scripting. But GoBGP carries Go's
  GC overhead and its protos are Go-flavored.
- **No Rust BGP daemon exists for production use.** Memory safety,
  zero-cost abstractions, and no GC make Rust ideal for a control plane
  that must be reliable and predictable under load.
- **The codec is independently valuable.** `rustbgpd-wire` as a
  standalone, fuzzed BGP codec library fills a gap in the Rust ecosystem.
  Anyone building BGP tooling in Rust (monitors, analyzers, test harnesses)
  can use it without pulling in a full daemon.
- **Observability is an afterthought in existing daemons.** Prometheus
  metrics, structured JSON logs, and machine-parseable errors from day
  one — not bolted on later.

**Target users:** Network automation teams, IX operators, anyone who
currently drives GoBGP via gRPC and wants memory safety and predictable
performance. Not a replacement for FRR/BIRD in full routing suite roles.

---

## Completed

1. **rustbgpd-wire** — BGP message codec (OPEN, KEEPALIVE, NOTIFICATION,
   UPDATE encode/decode, capability parsing, property tests). RFC-compliant
   attribute flag validation, specific UPDATE error subcodes, Partial bit
   handling, Cease subcode 7 (Connection Collision Resolution).
2. **rustbgpd-fsm** — RFC 4271 finite state machine (all 6 states, full
   transition table, OPEN negotiation, exponential backoff, property tests)
3. **rustbgpd-telemetry** — Prometheus metrics (state transitions, flaps,
   notifications, messages, RIB gauges at all mutation points, outbound
   route drops) + structured JSON logging
4. **rustbgpd-transport** — Tokio TCP session runtime (single task per peer,
   length-delimited framing, timer management, PeerHandle API, session
   notifications for collision detection, outbound UPDATE batching,
   import/export policy, max-prefix enforcement, TCP MD5/GTSM, session
   counters, accurate prefix tracking)
5. **rustbgpd-rib** — Adj-RIB-In, Loc-RIB, Adj-RIB-Out, best-path
   selection (RFC 4271 §9.1.2 with eBGP-over-iBGP), outbound distribution
   with split-horizon and per-peer export policy, route injection, dirty
   peer resync, WatchRoutes broadcast streaming
6. **rustbgpd-api** — 5 gRPC services: GlobalService, ControlService,
   NeighborService, InjectionService, RibService. WatchRoutes streaming,
   coordinated shutdown, input validation
7. **Daemon entrypoint** — TOML config loading with validation, dynamic
   peer management (PeerManager), inbound TCP listener, Prometheus
   `/metrics` endpoint (hardened), gRPC server supervision, coordinated
   shutdown (ctrl-c + Shutdown RPC + gRPC failure), non-loopback gRPC
   security warning
8. **CI workflow** — GitHub Actions: `cargo fmt --check`, `cargo clippy`,
   `cargo test --workspace` on every push and PR. Nightly fuzz CI.

---

## M0 — "Establish" `[complete]`

Session establishment and stability. The daemon connects to peers,
completes OPEN/KEEPALIVE exchange, and holds Established state.

### Build Order

1. ~~**rustbgpd-wire** — OPEN, KEEPALIVE, NOTIFICATION encode/decode~~ **Done**
   - BGP header (marker, length, type) parsing with 4096-byte enforcement
   - OPEN message: version, ASN, hold time, router ID, capabilities
   - Capability TLV parsing: 4-byte ASN (code 65), MP-BGP (code 1)
   - KEEPALIVE message (header only, no body)
   - NOTIFICATION message: error code, subcode, data
   - Property tests: `encode(decode(x)) == x` roundtrip
   - Fuzz harness: message decode from arbitrary bytes

2. ~~**rustbgpd-fsm** — Pure RFC 4271 state machine~~ **Done**
   - Six states: Idle, Connect, Active, OpenSent, OpenConfirm, Established
   - Input events: message received, timer fired, TCP connected/disconnected
   - Output actions: send message, start/stop timer, connect, disconnect
   - OPEN negotiation: hold time, capabilities, ASN validation
   - Negotiation result struct: agreed caps, AFI/SAFI set, peer ASN, peer ID
   - No tokio imports, no I/O — pure function from (State, Event) → (State, Actions)

3. ~~**rustbgpd-telemetry** — Metrics and structured logging~~ **Done**
   - Prometheus counters: session state transitions, flaps, NOTIFICATIONs
   - RIB metric stubs (exist at zero): update latency, backpressure, drops
   - Structured JSON events for FSM transitions

4. ~~**rustbgpd-transport** — Tokio TCP glue~~ **Done**
   - Single-task-per-peer session runtime with `tokio::select!`
   - Read loop: bytes → `peek_message_length` → `decode_message` → FSM event
   - Write loop: FSM action → `encode_message` → TCP write
   - Timer management: `Option<Pin<Box<Sleep>>>` with freestanding `poll_timer`
   - `PeerHandle` / `PeerCommand` API for external control (Start, Stop, Shutdown)
   - Iterative action loop avoids async recursion
   - Full telemetry integration (state transitions, messages, notifications)

5. ~~**Daemon entrypoint** — Config, metrics, peer wiring, shutdown~~ **Done**
   - TOML config loading and validation (`src/config.rs`)
   - Prometheus `/metrics` HTTP endpoint (`src/metrics_server.rs`)
   - CLI arg parsing, telemetry init, peer spawn, SIGTERM shutdown (`src/main.rs`)
   - CI workflow: fmt, clippy, test (`.github/workflows/ci.yml`)

6. ~~**Interop validation** — FRR and BIRD~~ **Done**
   - ~~Containerlab topology: rustbgpd ↔ FRR (10.3.1)~~ **Pass**
   - ~~Containerlab topology: rustbgpd ↔ BIRD (2.0.12)~~ **Pass**
   - ~~Test: session establishment~~ **Pass** (both peers)
   - ~~Test: peer restart recovery~~ **Pass** (both peers)
   - ~~Test: TCP reset recovery~~ **Pass** (both peers)
   - ~~Test: establish, hold 30+ minutes, verify keepalives~~ **Pass** (FRR 35min/73 KAs, BIRD 35min)
   - ~~Test: malformed OPEN → correct NOTIFICATION~~ **Pass** (Bad Peer AS → code 2/subcode 2)

### Exit Criteria

- Establish and hold 30+ minutes with FRR and BIRD
- Survive peer restart and TCP reset
- Correct NOTIFICATION on malformed OPEN
- Prometheus metrics capture all state transitions
- Structured log events for every FSM transition

---

## M1 — "Hear" `[complete]`

Decode UPDATEs. Store in Adj-RIB-In. Expose via gRPC.

### Build Order

1. ~~**Wire — NLRI parsing** (`crates/wire/src/nlri.rs`)~~ **Done**
   - `Ipv4Prefix` type with `Copy`, `Hash`, `Eq`, `Ord` derives
   - `decode_nlri` / `encode_nlri` per RFC 4271 §4.3 prefix-length encoding
   - Host bit masking, 0-32 range validation, truncation detection
   - 11 unit tests including roundtrip, edge cases (/0, /32), malformed input

2. ~~**Wire — Path attribute decode/encode** (`crates/wire/src/attribute.rs`)~~ **Done**
   - `decode_path_attributes` / `encode_path_attributes` with `four_octet_as` flag
   - TLV header parsing: flags + type + length (1 or 2 byte) + value
   - Types: ORIGIN, AS_PATH (2-byte + 4-byte), NEXT_HOP, MED, LOCAL_PREF, Unknown
   - Extended Length flag support, unknown attribute preservation
   - 22 tests including roundtrip for both AS widths

3. ~~**Wire — Attribute validation** (`crates/wire/src/validate.rs`)~~ **Done**
   - Separate from decode: structural ("can I read?") vs semantic ("is it correct?")
   - Checks: duplicate types (3,1), unrecognized well-known (3,2), missing mandatory (3,3),
     flag mismatch (3,4), invalid NEXT_HOP (3,8), malformed AS_PATH (3,11)
   - 14 tests covering all error subcodes and valid cases

4. ~~**Wire — ParsedUpdate + fuzz** (`crates/wire/src/update.rs`)~~ **Done**
   - `ParsedUpdate { withdrawn, attributes, announced }` struct
   - `UpdateMessage::parse(four_octet_as)` delegates to NLRI + attribute decoders
   - New fuzz target `decode_update` in CI

5. ~~**RIB crate** (`crates/rib/`)~~ **Done**
   - `Route { prefix, next_hop, attributes, received_at }`
   - `AdjRibIn` per-peer with `HashMap<Ipv4Prefix, Route>`
   - `RibUpdate` enum: `RoutesReceived`, `PeerDown`, `QueryReceivedRoutes`
   - `RibManager` single tokio task, bounded mpsc (4096), oneshot queries
   - 9 tests (5 unit + 4 async integration)

6. ~~**Transport + FSM integration**~~ **Done**
   - FSM: payloadless `UpdateReceived`, new `UpdateValidationError` event
   - Transport: `process_update()` pipeline (parse → validate → RIB → FSM)
   - `PeerDown` sent to RIB on session teardown
   - `rib_tx` threaded from daemon entrypoint through `PeerHandle::spawn()`

7. ~~**gRPC API** (`crates/api/`)~~ **Done**
   - Proto codegen via `tonic_build` in `build.rs`
   - `ListReceivedRoutes` with offset pagination (default page_size=100)
   - Other RibService RPCs return `UNIMPLEMENTED`
   - Server on configurable `grpc_addr` (default `127.0.0.1:50051`)
   - CI updated with `protobuf-compiler`, Dockerfile updated for builder stage

8. ~~**Interop validation**~~ **Done** — 15/15 automated tests pass
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

## M2 — "Decide" `[complete]`

Loc-RIB best-path selection per RFC 4271 §9.1.2.

### Build Order

1. ~~**Route peer field** (`crates/rib/src/route.rs`)~~ **Done**
   - Added `peer: IpAddr` to `Route` for tiebreaker and gRPC reporting
   - Accessor helpers: `origin()`, `as_path()`, `local_pref()`, `med()`
   - Ripple fixes across transport, adj_rib_in, and manager tests

2. ~~**Best-path comparison** (`crates/rib/src/best_path.rs`)~~ **Done**
   - `best_path_cmp(a, b) -> Ordering` — preferred route sorts `Less`
   - Decision steps: LOCAL_PREF → AS_PATH length → ORIGIN → MED → peer address
   - Deterministic MED (always-compare) — simpler, matches GoBGP behavior
   - Standalone function, not `Ord` on `Route` (ADR-0014)
   - 9 unit tests (one per decision step + edge cases)
   - 3 proptest property tests: antisymmetry, transitivity, totality

3. ~~**Loc-RIB struct** (`crates/rib/src/loc_rib.rs`)~~ **Done**
   - `LocRib { routes: HashMap<Ipv4Prefix, Route> }` — best route per prefix
   - `recompute(prefix, candidates)` picks best via `min_by(best_path_cmp)`
   - Returns whether best changed (for event emission)
   - 5 unit tests: single candidate, replacement, withdrawal, unchanged, multi-candidate

4. ~~**RibManager integration** (`crates/rib/src/manager.rs`)~~ **Done**
   - `loc_rib: LocRib` field inside `RibManager`
   - Incremental recompute: only affected prefixes on announce/withdraw/peer-down
   - `PeerDown`: collects affected prefixes *before* clearing Adj-RIB-In
   - `QueryBestRoutes` variant in `RibUpdate` enum
   - Debug tracing for best-path changes
   - 4 integration tests: winner query, peer-down promotion, withdrawal update, per-prefix winners

5. ~~**gRPC endpoint** (`crates/api/src/rib_service.rs`)~~ **Done**
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

6. ~~**Interop validation** — FRR 10.3.1~~ **Done**
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

## M3 — "Speak" `[complete]`

Route injection, advertisement, and policy. The daemon becomes a real BGP
speaker: when best-path changes, advertise/withdraw to all peers. Operators
can inject routes via gRPC, apply prefix-list policy, and use TCP
authentication.

### Build Order

1. ~~**Policy crate** — `PrefixList`~~ **Done**
   - `PolicyAction` (Permit/Deny), `PrefixListEntry` with ge/le range matching
   - `PrefixList::evaluate()` — first-match-wins prefix filter
   - `check_prefix_list()` convenience function (None = permit all)
   - 9 tests covering exact match, ge/le range, first-match-wins, defaults

2. ~~**Wire — `UpdateMessage::build()`**~~ **Done**
   - High-level constructor: `build(announced, withdrawn, attributes, four_octet_as)`
   - Encodes NLRI and path attributes into raw Bytes fields
   - 4 tests: roundtrip, withdrawal-only, announce-only, mixed

3. ~~**Config — new neighbor fields + policy config**~~ **Done**
   - Neighbor: `max_prefixes`, `md5_password`, `ttl_security`
   - Global `[policy]` section with import/export prefix-list entries
   - `Config::import_policy()` / `Config::export_policy()` → `Option<PrefixList>`
   - 4 new config tests

4. ~~**Telemetry — outbound metrics**~~ **Done**
   - `rib_adj_out_prefixes` (IntGaugeVec), `rib_loc_prefixes` (IntGaugeVec),
     `max_prefix_exceeded` (IntCounterVec)
   - Recording methods on `BgpMetrics`

5. ~~**RIB — Adj-RIB-Out, outbound distribution, route injection**~~ **Done**
   - `AdjRibOut` struct (per-peer HashMap)
   - `OutboundRouteUpdate { announce, withdraw }` type
   - `RibUpdate` variants: `PeerUp`, `InjectRoute`, `WithdrawInjected`, `QueryAdvertisedRoutes`
   - `RibManager::distribute_changes()` — split-horizon + export policy + delta
   - `RibManager::send_initial_table()` — full Loc-RIB dump on PeerUp
   - Injected routes stored under sentinel peer `0.0.0.0` (ADR-0015)
   - 8 new M3 tests (38 total RIB tests)

6. ~~**Transport — outbound channel + UPDATE sending**~~ **Done**
   - Per-peer outbound channel (mpsc, capacity 4096)
   - `tokio::select!` branch for `OutboundRouteUpdate` in Established state
   - `send_route_update()` — build wire UPDATEs from outbound updates
   - `prepare_outbound_attributes()` — eBGP: prepend ASN, set NEXT_HOP, strip
     LOCAL_PREF; iBGP: ensure LOCAL_PREF (default 100)
   - Import policy filtering in `process_update()`
   - Max-prefix enforcement with Cease/1 NOTIFICATION
   - `PeerUp` sent to RIB on SessionEstablished
   - 5 unit tests for attribute preparation

7. ~~**gRPC — InjectionService + ListAdvertisedRoutes**~~ **Done**
   - `InjectionService` with `AddPath` (returns UUID) and `DeletePath`
   - `ListAdvertisedRoutes` implemented (was UNIMPLEMENTED stub)
   - Both services registered in gRPC server

8. ~~**TCP MD5 + GTSM**~~ **Done**
   - `socket_opts.rs` — `set_tcp_md5sig()` and `set_gtsm()` (Linux only, ADR-0016)
   - `attempt_connect()` refactored to use `socket2::Socket` for pre-connect options
   - Non-Linux stubs return `Unsupported`
   - Dependencies: `socket2`, `libc`

9. ~~**Interop validation**~~ **Done**
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

## M4 — "Route Server Mode" `[complete]`

Dynamic peer management, per-peer policy, typed communities, real-time
route event streaming.

### Build Order

1. ~~**Wire — Typed COMMUNITIES attribute** (`crates/wire/src/attribute.rs`)~~ **Done**
   - `PathAttribute::Communities(Vec<u32>)` variant for RFC 1997 communities
   - Decode/encode in attribute codec, `communities()` accessor on Route
   - 6 tests: decode single/multiple/empty, odd-length error, roundtrip, type_code+flags

2. ~~**Proto + gRPC — communities in Route message**~~ **Done**
   - `repeated uint32 communities` field added to Route and AddPathRequest
   - `route_to_proto()` and injection service updated

3. ~~**Per-peer import/export policy**~~ **Done**
   - `import_policy` / `export_policy` fields on `[[neighbors]]` config section
   - Per-neighbor overrides global: neighbor-specific if present, else global fallback
   - `RibManager::export_policy_for()` resolution helper
   - `PeerUp` carries per-peer export policy to RIB manager
   - 5 new config + RIB tests

4. ~~**PeerManager + session state query** (`src/peer_manager.rs`)~~ **Done**
   - Channel-based single-task ownership (ADR-0017)
   - Commands: AddPeer, DeletePeer, ListPeers, GetPeerState, EnablePeer, DisablePeer, Shutdown
   - `PeerHandle::query_state()` returns FSM state + prefix count
   - Starting with zero configured neighbors is now valid
   - Shared types in `crates/api/src/peer_types.rs`
   - 7 tests

5. ~~**NeighborService gRPC** (`crates/api/src/neighbor_service.rs`)~~ **Done**
   - All 6 RPCs: add, delete, list, get state, enable, disable
   - Maps PeerInfo to proto NeighborState

6. ~~**WatchRoutes streaming**~~ **Done**
   - `tokio::sync::broadcast` channel (capacity 4096) in RibManager (ADR-0018)
   - `RouteEvent` type: Added, Withdrawn, BestChanged
   - Events emitted after `recompute_best()` with old/new state diff
   - `SubscribeRouteEvents` variant in `RibUpdate`
   - gRPC `watch_routes()` uses `BroadcastStream` with peer address filtering
   - Lagged subscribers logged and skipped (no crash)
   - 4 new tests

7. ~~**Interop validation**~~ **Done** — 17/17 automated tests pass
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

## M5 — "Polish" `[complete]`

Inbound listener, API hardening, session counters, NLRI batching, metrics
server hardening.

### Build order

1. ~~Strict config parsing~~ — `#[serde(deny_unknown_fields)]` on all structs **Done**
2. ~~API input validation~~ — reject ASN=0, hold_time 1-2, next_hop 0.0.0.0/multicast **Done**
3. ~~Session counters~~ — updates, notifications, flaps, uptime, last_error **Done**
4. ~~Accurate prefix_count~~ — `HashSet<Ipv4Prefix>` replaces add/subtract heuristic **Done**
5. ~~NLRI batching~~ — group outbound UPDATEs by shared attributes **Done**
6. ~~Metrics server hardening~~ — per-connection spawn, 404, write timeout, RIB drop metric **Done**
7. ~~Inbound TCP listener~~ — `BgpListener`, `PeerSession::new_inbound()`, PeerManager integration **Done**
8. ~~Documentation~~ — ADR-0019, CHANGELOG, README, ROADMAP **Done**

### Exit criteria

- Inbound TCP listener accepts passive peering
- All NeighborState fields populated
- API rejects invalid inputs with INVALID_ARGUMENT
- prefix_count accurate under re-announcement
- NLRI batching reduces wire UPDATE count
- Metrics server returns 404 for non-/metrics paths
- 314 tests pass, clippy clean, fmt clean

---

## M6 — "Compliance" `[complete]`

Wire RFC compliance, GlobalService, ControlService, coordinated shutdown.

### Build order

1. ~~Crates.io packaging~~ — version 0.1.0, metadata, proto copied into api crate **Done**
2. ~~Review nits~~ — ASN truncation → AS_TRANS, config validation, pagination dedup **Done**
3. ~~GlobalService + ControlService~~ — GetGlobal, GetHealth, GetMetrics, Shutdown (ADR-0020) **Done**
4. ~~Coordinated shutdown~~ — ctrl-c and Shutdown RPC both trigger ordered teardown **Done**
5. ~~eBGP NEXT_HOP fix~~ — uses TCP local socket addr instead of router-id **Done**
6. ~~afi_safi validation~~ — reject unsupported address families with INVALID_ARGUMENT **Done**
7. ~~Wire attribute RFC compliance~~ — flag validation at decode, specific subcodes, Partial bit **Done**

### Exit criteria

- All 5 gRPC services operational
- Coordinated shutdown from both ctrl-c and RPC
- Wire attribute errors produce RFC-correct subcodes and data
- 332 tests pass, clippy clean, fmt clean

---

## M7 — "Wire & RIB Correctness" `[complete]`

Peer-visible bugs found during full-project code review.

### Completed

1. ~~**Adj-RIB-Out divergence on channel-full** (`crates/rib/src/manager.rs`)~~
   - Stage-then-commit with dirty peer tracking. On send failure, AdjRibOut
     is preserved and peer is marked dirty. A persistent pinned 1-second
     resync timer fires via `tokio::select!`, independent of both route
     mutations and query traffic. 4 tests.

2. ~~**Malformed NLRI maps to wrong NOTIFICATION** (`crates/wire/src/nlri.rs`, `error.rs`)~~
   - Both prefix_len > 32 and truncated NLRI now return `InvalidNetworkField`
     → subcode 10 with the offending field bytes. 2 tests.

3. ~~**PARTIAL bit set too broadly on unknown attributes** (`crates/wire/src/attribute.rs`)~~
   - PARTIAL now only set when both OPTIONAL and TRANSITIVE flags present.
     Well-known transitive attributes (e.g., ATOMIC_AGGREGATE) no longer
     get PARTIAL incorrectly. 1 test.

4. ~~**Policy prefix lengths >32 can panic** (`src/config.rs`)~~
   - Config rejects prefix lengths > 32, ge > 32, ge < prefix length,
     le > 32, and ge > le at load time. 4 tests.

5. ~~**Best-path omits eBGP-over-iBGP preference** (`crates/rib/src/best_path.rs`)~~
   - Added eBGP-over-iBGP preference as step 5 (between MED and peer
     address tiebreaker). `Route` gains `is_ebgp: bool` field. 3 tests.

### Exit criteria

- All 5 findings fixed with regression tests
- 344 tests pass (+10 new), clippy clean, fmt clean

---

## M8 — "API & Observability" `[complete]`

API contract issues and metrics accuracy found during code review. These
affect operators and automation consumers.

### Completed

1. ~~**IPv6 neighbors accepted but unsupported** (`src/config.rs`, `crates/api/src/neighbor_service.rs`)~~
   - Config validation and gRPC `AddNeighbor` now reject IPv6 addresses.
     Wire crate is IPv4-only and GTSM uses IPv4-only socket options. 2 tests.

2. ~~**SetGlobal permanently UNIMPLEMENTED** (`proto/rustbgpd.proto`, `crates/api/src/global_service.rs`)~~
   - SetGlobal RPC, request, and response annotated as reserved for future
     use (documentation-only). RPC still returns UNIMPLEMENTED.

3. ~~**DeletePath.uuid ignored** (`proto/rustbgpd.proto`, `crates/api/src/injection_service.rs`)~~
   - Removed fake UUID from `AddPathResponse` and `DeletePathRequest`.
     Both fields reserved for wire compatibility.

4. ~~**Dead Prometheus gauges** (`crates/rib/src/manager.rs`)~~
   - `set_rib_prefixes`, `set_adj_rib_out_prefixes`, `set_loc_rib_prefixes`
     wired at all RIB mutation points. Zero-valued gauges initialized on
     PeerUp for stable dashboard series. 3 tests.

5. ~~**WatchRoutes loses withdrawals and peer transitions** (`crates/rib/src/event.rs`, `crates/rib/src/manager.rs`, `crates/api/src/rib_service.rs`)~~
   - `RouteEvent` gains `previous_peer` and `timestamp`. `recompute_best()`
     captures previous best peer before Loc-RIB mutation. WatchRoutes filter
     checks both `event.peer` and `event.previous_peer`. Proto gains
     `previous_peer_address` field. 4 tests.

6. ~~**Health/neighbor counters semantically wrong** (`crates/api/src/control_service.rs`, `crates/api/src/neighbor_service.rs`, `crates/rib/src/update.rs`, `crates/rib/src/manager.rs`)~~
   - `active_peers` filters to Established only. `total_routes` queries
     Loc-RIB via `QueryLocRibCount`. `prefixes_sent` queries Adj-RIB-Out
     via `QueryAdvertisedCount` (returns `Status::internal` on failure,
     not silent 0). 4 tests.

### Exit criteria

- API contracts match implementation behavior
- Metrics reflect actual RIB state
- Consumers get correct data from all gRPC endpoints
- 347 tests pass (+13 new), clippy clean, fmt clean

---

## M9 — "Production Hardening" `[complete]`

Security, resilience, operational safety, and core protocol compliance
(TCP collision detection promoted from post-v1).

### Build order

1. ~~**Metrics server hardening** (`src/metrics_server.rs`)~~ **Done**
   - Read timeout (5s), request-line size limit (8192 bytes), concurrent
     connection cap (64 via `Semaphore`), `gather()` errors return 500
     instead of panicking. 3 new tests.

2. ~~**gRPC security posture** (`src/main.rs`, `docs/SECURITY.md`)~~ **Done**
   - Non-loopback gRPC bind logs warning at startup. New `docs/SECURITY.md`
     documents authentication posture, privileged RPCs, and recommendations.

3. ~~**TCP collision detection** (RFC 4271 §6.8)~~ **Done**
   - Wire: Cease subcode 7 (`CONNECTION_COLLISION_RESOLUTION`).
   - Transport: `SessionNotification` enum (`OpenReceived`, `BackToIdle`),
     `CollisionDump` command, `remote_router_id` in `PeerSessionState`,
     session notification channel threaded to all spawn sites.
   - PeerManager: `pending_inbound` per peer, `session_notify_rx` in
     `select!` loop, `resolve_collision()` compares BGP Identifiers,
     `replace_with_inbound()` helper. 4 new tests.

4. ~~**gRPC server supervision** (`src/main.rs`)~~ **Done**
   - gRPC `JoinHandle` added to shutdown `select!`. Unexpected gRPC exit
     triggers coordinated shutdown (API-first daemon without API should
     not keep running).

5. ~~**Documentation refresh**~~ **Done**
   - ROADMAP: updated completed summary, M9 marked complete, v1 scope
     section added.
   - CHANGELOG: M9 entry with all items.
   - `docs/SECURITY.md`: new file documenting gRPC security posture.

### Exit criteria

- No panic paths from external input (metrics gather errors handled)
- Documented security posture for gRPC exposure
- TCP collision detection per RFC 4271 §6.8
- gRPC lifecycle supervised
- 366 tests pass (+19 new), clippy clean, fmt clean

---

## v1 Scope

Linux-first, IPv4-unicast only, API-first BGP daemon. M0–M9 form the
v1 release with these intentional boundaries:

- **Single address family:** IPv4 unicast only. MP-BGP (IPv6) is post-v1.
- **No full routing suite:** BGP only. No OSPF, IS-IS, MPLS.
- **No built-in auth:** gRPC has no TLS or authentication. Use a proxy or
  network-level access control for non-loopback deployments.
- **No config persistence:** gRPC mutations (AddNeighbor, etc.) are not
  written back to TOML. Restart reloads the config file.
- **No graceful restart:** Sessions do not survive daemon restart.
- **No TCP-AO:** TCP MD5 (RFC 2385) is supported; TCP-AO (RFC 5925) is
  deferred.

---

## Post-v1

### Protocol extensions
- MP-BGP (IPv6 unicast)
- Extended communities (type 16)
- FlowSpec speaker mode (prefixd lineage)
- Graceful restart
- Extended message support (RFC 8654)

### Infrastructure
- BMP exporter
- RPKI validation (RTR client)
- TCP-AO authentication
- Config persistence (gRPC → TOML writeback)

---

## Non-Goals

These are explicitly out of scope. Not "maybe later" — out of scope.

- **Full routing suite.** No OSPF, IS-IS, LDP, MPLS, PIM. This is a BGP daemon.
- **CLI-first operation.** The CLI is a convenience wrapper around gRPC,
  not the primary interface. If you want rich CLI, use `grpcurl` or write
  a client.
- **GoBGP proto compatibility.** Our protos are our own. A compat adapter
  can exist as a separate project if anyone wants it.
- **Windows support.** Linux is the target. macOS for dev builds only.
- **Web UI / dashboard.** Grafana + Prometheus is the monitoring story.
  We export metrics, not render dashboards.
- **Plugin system in v1.** Policy is built-in and minimal. WASM/DSL
  plugins are post-v1 if the core is stable enough to warrant them.
