# Changelog

All notable changes to rustbgpd will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses milestone-based versioning aligned with the design
document (M0–M4).

---

## [Unreleased]

### Added (M4 — "Route Server Mode")

- `rustbgpd-wire`: Typed COMMUNITIES attribute (RFC 1997). `PathAttribute::Communities(Vec<u32>)`
  variant replaces opaque `Unknown` for type code 8. Decode, encode, and `Route::communities()`
  accessor. 6 tests.
- `rustbgpd-rib`: `RouteEvent` type with `Added`, `Withdrawn`, `BestChanged` variants.
  `tokio::sync::broadcast` channel (capacity 4096) emits events after best-path recomputation.
  `SubscribeRouteEvents` variant in `RibUpdate`. (ADR-0018)
- `rustbgpd-rib`: Per-peer export policy support. `RibManager` stores per-peer policies via
  `PeerUp`, resolves with `export_policy_for()` (per-peer overrides global). Cleaned up on
  `PeerDown`. 2 new tests.
- `rustbgpd-api`: `NeighborService` gRPC implementation with all 6 RPCs: `AddNeighbor`,
  `DeleteNeighbor`, `ListNeighbors`, `GetNeighborState`, `EnableNeighbor`, `DisableNeighbor`.
- `rustbgpd-api`: `WatchRoutes` gRPC streaming endpoint. Subscribes to RIB broadcast channel,
  wraps in `BroadcastStream`, filters by peer address, maps `RouteEvent` to proto `RouteEvent`.
  Lagged subscribers are logged and skipped.
- `rustbgpd-api`: `peer_types` module with shared `PeerManagerCommand`, `PeerManagerNeighborConfig`,
  and `PeerInfo` types used by both binary and API crate.
- `rustbgpd-api`: Communities field populated in `route_to_proto()` and accepted in
  `AddPath` injection requests.
- `rustbgpd-transport`: `PeerCommand::QueryState` variant returns `PeerSessionState`
  (FSM state, prefix count, negotiated hold time, four-octet-AS flag).
- `PeerManager` (`src/peer_manager.rs`): Channel-based single-task ownership for dynamic
  peer lifecycle management. Commands: AddPeer, DeletePeer, ListPeers, GetPeerState,
  EnablePeer, DisablePeer, Shutdown. (ADR-0017)
- Config: per-neighbor `import_policy` and `export_policy` sections in `[[neighbors]]`.
  Neighbor-specific policy overrides global; absence falls back to global.
- Config: starting with zero `[[neighbors]]` is now valid (peers added dynamically).
- Dependencies: `tokio-stream` (with `sync` feature) for `BroadcastStream` wrapper.
- Interop: 10-peer containerlab topology `m4-frr.clab.yml` (rustbgpd + 10× FRR).
  8 static peers + 2 dynamic. Automated test script `test-m4-frr.sh` with 7 test
  scenarios (17 pass/fail checks): static sessions, ListNeighbors, received routes,
  per-peer export policy, dynamic AddNeighbor/DeleteNeighbor, Enable/Disable.

### Changed

- MSRV bumped from Rust 1.85 to 1.93. Required for `let` chains and
  `usize::is_multiple_of()` stabilization.
- Dockerfile updated from `rust:1.85-bookworm` to `rust:1.93-bookworm`.

### Added (M3 — "Speak")

- `rustbgpd-policy`: `PrefixList` with ge/le range matching, first-match-wins
  evaluation, and `check_prefix_list()` convenience function. 9 tests.
- `rustbgpd-wire`: `UpdateMessage::build()` high-level constructor for creating
  outbound UPDATEs from structured data (announced prefixes, withdrawn prefixes,
  path attributes). 4 tests.
- `rustbgpd-rib`: `AdjRibOut` per-peer outbound route table. `OutboundRouteUpdate`
  type for announce/withdraw batches. (ADR-0015)
- `rustbgpd-rib`: `RibManager` gains outbound distribution: `distribute_changes()`
  computes deltas per peer with split-horizon and export policy filtering.
  `send_initial_table()` sends full Loc-RIB dump on peer establishment.
- `rustbgpd-rib`: Route injection via `InjectRoute` / `WithdrawInjected` messages.
  Injected routes stored under sentinel peer `0.0.0.0` in standard Adj-RIB-In,
  participating in normal best-path selection and distribution.
- `rustbgpd-rib`: `QueryAdvertisedRoutes` variant for querying Adj-RIB-Out per peer.
  8 new M3 tests (38 total).
- `rustbgpd-transport`: Per-peer outbound channel (mpsc, capacity 4096) receives
  `OutboundRouteUpdate` from RIB manager. `send_route_update()` converts to wire
  UPDATEs. `prepare_outbound_attributes()` handles eBGP (ASN prepend, NEXT_HOP
  rewrite, LOCAL_PREF strip) and iBGP (default LOCAL_PREF 100). 5 unit tests.
- `rustbgpd-transport`: Import policy filtering — inbound UPDATEs filtered by
  global prefix-list before RIB insertion.
- `rustbgpd-transport`: Max-prefix enforcement — tracks accepted prefix count,
  sends Cease/1 (Maximum Number of Prefixes Reached) NOTIFICATION when exceeded.
- `rustbgpd-transport`: TCP MD5 authentication (RFC 2385) via `setsockopt(TCP_MD5SIG)`.
  Linux only. Configurable per-neighbor via `md5_password` config field. (ADR-0016)
- `rustbgpd-transport`: GTSM / TTL security (RFC 5082) via `setsockopt(IP_MINTTL)`.
  Linux only. Configurable per-neighbor via `ttl_security` config field.
- `rustbgpd-transport`: TCP connection refactored to use `socket2::Socket` for
  pre-connect socket option application.
- `rustbgpd-api`: `InjectionService` with `AddPath` (returns UUID derived from
  prefix) and `DeletePath` gRPC endpoints.
- `rustbgpd-api`: `ListAdvertisedRoutes` implemented (previously UNIMPLEMENTED stub).
  Queries Adj-RIB-Out for a specific peer.
- `rustbgpd-telemetry`: New metrics — `rib_adj_out_prefixes` (gauge),
  `rib_loc_prefixes` (gauge), `max_prefix_exceeded` (counter).
- Config: `max_prefixes`, `md5_password`, `ttl_security` fields on `[[neighbors]]`.
  Global `[policy]` section with `import` and `export` prefix-list entries.
- Interop: 3-node containerlab topology `m3-frr.clab.yml` (rustbgpd + 2× FRR).
  Automated test script `test-m3-frr.sh` with 5 test scenarios: route
  redistribution, split horizon, route injection, withdrawal propagation, DeletePath.

### Added (M2 — "Decide")

- `rustbgpd-rib`: `Route` now carries `peer: IpAddr` for tiebreaking and gRPC
  reporting. Accessor helpers `origin()`, `as_path()`, `local_pref()`, `med()`
  extract attributes with RFC-appropriate defaults.
- `rustbgpd-rib`: Best-path comparison function `best_path_cmp()` implementing
  RFC 4271 §9.1.2 decision process: LOCAL_PREF → AS_PATH length → ORIGIN → MED
  → peer address. Deterministic MED (always-compare). Standalone function, not
  `Ord` on `Route`. (ADR-0014)
- `rustbgpd-rib`: Property tests for best-path comparison (antisymmetry,
  transitivity, totality) via proptest.
- `rustbgpd-rib`: `LocRib` struct — stores one best route per prefix, with
  incremental `recompute()` that returns whether the best path changed.
- `rustbgpd-rib`: `RibManager` now owns a `LocRib` and recomputes best paths
  on every announce, withdraw, and peer-down event. Only affected prefixes are
  recomputed. `QueryBestRoutes` variant added to `RibUpdate`.
- `rustbgpd-api`: `ListBestRoutes` gRPC endpoint with offset pagination,
  returning routes with `best: true`. `route_to_proto()` now uses `route.peer`
  for the `peer_address` field.
- Interop validation: FRR 10.3.1 — M1 automated test script (15/15 pass),
  `ListBestRoutes` returns correct best routes with pagination. Reuses M1
  containerlab topology (`m1-frr.clab.yml`).

### Fixed

- Interop test script: peer restart test (test 4) now relies on watchfrr to
  auto-restart bgpd instead of manually running `/usr/lib/frr/bgpd -d` which
  failed to load FRR's integrated config. Wait timeout increased to 90s to
  accommodate the 30s reconnect timer.

- `rustbgpd-wire`: Unknown NOTIFICATION error codes are now preserved as
  `NotificationCode::Unknown(u8)` instead of being silently mapped to `Cease`.
  This fixes incorrect logging and metrics for NOTIFICATIONs with future or
  non-standard error codes. (ADR-0011)
- `rustbgpd-transport`: Use `code.as_u8()` instead of `code as u8` cast for
  NOTIFICATION metric labels — more explicit and correct with the new enum
  representation.
- `rustbgpd-transport`: Fix hot reconnect loop when peer persistently rejects
  OPENs (e.g., ASN mismatch). Auto-reconnect now uses a deferred timer
  (connect-retry interval, default 30s) instead of firing `ManualStart`
  immediately. Discovered during malformed OPEN interop testing against FRR.

### Added (M1 — "Hear")

- `rustbgpd-wire`: `Ipv4Prefix` type with NLRI encode/decode per RFC 4271 §4.3
  prefix-length encoding. Host bit masking, 0-32 range validation, Display impl.
- `rustbgpd-wire`: Path attribute decode/encode (`decode_path_attributes`,
  `encode_path_attributes`) supporting ORIGIN, AS_PATH (2-byte and 4-byte),
  NEXT_HOP, MED, LOCAL_PREF, and unknown attribute preservation. Extended Length
  flag support.
- `rustbgpd-wire`: UPDATE attribute validation (`validate_update_attributes`)
  separate from structural decode. Checks: duplicate types (3,1), unrecognized
  well-known (3,2), missing mandatory attributes (3,3), flag mismatch (3,4),
  invalid NEXT_HOP (3,8), malformed AS_PATH (3,11). (ADR-0012)
- `rustbgpd-wire`: `ParsedUpdate` struct and `UpdateMessage::parse()` for
  combined NLRI + attribute decoding.
- `rustbgpd-wire`: Fuzz target for UPDATE decoder (`decode_update`), added to
  nightly fuzz CI.
- `rustbgpd-rib`: Adj-RIB-In implementation with `Route`, `AdjRibIn`, and
  `RibManager`. Single tokio task owns all state via bounded mpsc channel (4096).
  Queries via embedded oneshot. No `Arc<RwLock>`. (ADR-0013)
- `rustbgpd-fsm`: `UpdateValidationError` event — triggers NOTIFICATION and
  session teardown on RFC-violating UPDATEs. `UpdateReceived` is now payloadless
  (transport handles UPDATE content).
- `rustbgpd-transport`: UPDATE processing pipeline in `process_update()`:
  structural decode → semantic validation → RIB insertion → FSM event. Sends
  `PeerDown` to RIB on session teardown.
- `rustbgpd-api`: gRPC server via tonic with proto codegen. `ListReceivedRoutes`
  RPC with offset pagination (default page_size=100). Other RibService RPCs
  return UNIMPLEMENTED.
- Config: `grpc_addr` field in `[global.telemetry]` (default `127.0.0.1:50051`)
  with SocketAddr validation.
- Daemon: gRPC server spawned alongside metrics server and RIB manager.
- CI: `protobuf-compiler` installed in GitHub Actions workflow.
- Dockerfile: `protobuf-compiler` added to builder stage for tonic-build.
- Containerlab topology `m1-frr.clab.yml`: FRR advertising 3 prefixes
  (192.168.1.0/24, 192.168.2.0/24, 10.10.0.0/16) for UPDATE/RIB interop testing.
- Interop test script `test-m1-frr.sh`: validates routes received, path
  attributes, withdrawal propagation, and RIB clearing on peer restart.

### Added (M0 — "Establish")

- Workspace with 7 crates: wire, fsm, transport, rib, policy, api, telemetry
- gRPC proto skeleton (`rustbgpd.v1` package, all 5 services)
- Containerlab interop topologies for FRR 10.x and BIRD 2.x
- Design document, RFC notes, interop matrix template
- Roadmap with market context and milestone plan (M0–M4)
- `rustbgpd-wire`: OPEN, KEEPALIVE, NOTIFICATION, UPDATE encode/decode
- `rustbgpd-wire`: Capability parsing (4-byte ASN, MP-BGP, unknown pass-through)
- `rustbgpd-wire`: Strict 4096-byte message size enforcement
- `rustbgpd-wire`: `DecodeError::to_notification()` mapping for protocol errors
- `rustbgpd-wire`: Property tests (`encode(decode(x)) == x` roundtrip)
- `rustbgpd-fsm`: RFC 4271 §8 state machine (all 6 states, full transition table)
- `rustbgpd-fsm`: Timer management as input events / output actions
- `rustbgpd-fsm`: OPEN validation and capability negotiation
- `rustbgpd-fsm`: Exponential backoff on connect retry (30s–300s)
- `rustbgpd-fsm`: Property tests (no panics on arbitrary event sequences)
- `rustbgpd-telemetry`: Prometheus metrics (state transitions, flaps, notifications, messages)
- `rustbgpd-telemetry`: RIB metric stubs (registered at zero for M1)
- `rustbgpd-telemetry`: Structured JSON logging via tracing-subscriber with env-filter
- `rustbgpd-transport`: Single-task-per-peer Tokio TCP session runtime
- `rustbgpd-transport`: Length-delimited framing with `peek_message_length`
- `rustbgpd-transport`: Timer management with `poll_timer` future for `select!` compatibility
- `rustbgpd-transport`: `PeerHandle` / `PeerCommand` API for spawning and controlling sessions
- `rustbgpd-transport`: Full OPEN/KEEPALIVE handshake, reconnection, and teardown
- `rustbgpd-transport`: Telemetry integration (state transitions, messages, notifications)
- Daemon entrypoint: TOML config loading, peer spawning, graceful SIGTERM shutdown
- Prometheus `/metrics` HTTP endpoint served via `tokio::net::TcpListener`
- Config module (`src/config.rs`) with validation (router ID, neighbor addresses, hold time)
- CI workflow (`.github/workflows/ci.yml`): fmt, clippy, test on push/PR
- Nightly fuzz CI (`.github/workflows/fuzz.yml`): 5-minute wire decoder fuzzing
- `rustbgpd-wire`: Negative property tests — 5 corruption strategies (bit flip,
  truncation, insertion, overwrite, trailing garbage) verify decoder never panics
- `rustbgpd-wire`: Fuzz harness for `decode_message` via cargo-fuzz / libfuzzer
- Malformed OPEN interop test config (`rustbgpd-frr-badopen.toml`)

---

## [0.0.1] — Unreleased

Target: **M0 — "Establish"**

### Done

- `rustbgpd-wire`: OPEN, KEEPALIVE, NOTIFICATION encode/decode
- `rustbgpd-wire`: Capability parsing (4-byte ASN, MP-BGP)
- `rustbgpd-wire`: Strict 4096-byte message size enforcement
- `rustbgpd-fsm`: RFC 4271 state machine (all 6 states)
- `rustbgpd-fsm`: Timer inputs (ConnectRetry, Hold, Keepalive)
- `rustbgpd-fsm`: OPEN negotiation and capability exchange
- `rustbgpd-telemetry`: Prometheus metric stubs (8 metrics, all counters at zero)
- `rustbgpd-telemetry`: Structured JSON log events via tracing-subscriber
- `rustbgpd-transport`: Single-task-per-peer TCP session runtime
- `rustbgpd-transport`: Framing, timers, connect/disconnect lifecycle
- `rustbgpd-transport`: 18 tests (12 unit + 6 integration with mock peer)
- Daemon binary: config loading → telemetry init → peer spawn → metrics server → shutdown
- CI pipeline: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --workspace`

### Exit Criteria

- Establish and hold 30+ minutes with FRR and BIRD
- Survive peer restart and TCP reset
- Correct NOTIFICATION on malformed OPEN
- Prometheus metrics capture all state transitions
- Structured log events for every FSM transition
