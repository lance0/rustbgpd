# Changelog

All notable changes to rustbgpd will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- **Enhanced Route Refresh (RFC 7313).** Capability code 70 is now
  advertised alongside RFC 2918 Route Refresh. ROUTE-REFRESH message type 5
  now models subtype `0/1/2` (Normal/BoRR/EoRR). `SoftResetIn` gains
  family-scoped replacement semantics for ERR-capable peers: inbound `BoRR`
  marks current routes refresh-stale, refreshed announcements/withdrawals
  clear replaced entries, and inbound `EoRR` sweeps unreplaced state.
  Active ERR windows now also have a fixed 5-minute timeout, which performs
  the same unreplaced-state sweep if `EoRR` never arrives.
  Outbound route-refresh responses emit `BoRR -> routes -> EoRR` for ERR
  peers while preserving existing `routes -> EndOfRib` behavior for
  RFC 2918-only peers. (ADR-0038)

- **Extended Next Hop (RFC 8950).** Capability code 5 is now advertised
  automatically for dual-stack unicast peers. IPv4 unicast NLRI can be
  received and advertised via `MP_REACH_NLRI` / `MP_UNREACH_NLRI` with an
  IPv6 next hop. Existing peers that do not negotiate RFC 8950 keep the
  legacy body-NLRI + `NEXT_HOP` encoding. Add-Path for IPv4 unicast remains
  compatible in both legacy and RFC 8950 MP-encoding modes. (ADR-0037)

- **Policy chaining + named policies (ADR-0036).** Named policy definitions
  in TOML with configurable `default_action` (permit or deny). Policy chains
  reference named policies by name in ordered sequences. GoBGP-style chain
  semantics: permit accumulates modifications and continues, deny stops
  immediately, implicit permit after all policies. Backward compatible —
  existing inline `import_policy`/`export_policy` entries still work.
  `RouteModifications::merge_from()` accumulates across chain steps (scalars:
  later wins; lists accumulate, with later conflicting add/remove operations
  winning). New TOML syntax: `[policy.definitions.*]`,
  `import_chain`/`export_chain` on global and per-neighbor.

- **Admin shutdown communication (RFC 8203).** DisableNeighbor gRPC reason
  field is now propagated through to the Cease/2 (Administrative Shutdown)
  NOTIFICATION data as a 1-byte length + UTF-8 string (max 128 bytes).
  Inbound Cease/2 and Cease/4 NOTIFICATIONs with shutdown communication
  are decoded and logged. Wire helpers: `encode_shutdown_communication()`
  and `decode_shutdown_communication()` in the notification module.
- **Notification GR (RFC 8538).** GR capability now advertises the N-bit
  (notification support). NOTIFICATION-triggered teardown now preserves routes
  only when both sides negotiated N-bit support. Cease/Hard Reset (subcode 9)
  sent or received bypasses Graceful Restart, forcing immediate route purge
  instead of stale preservation. Completes the GR story alongside ADR-0024 (helper),
  ADR-0040 (restarting speaker), and ADR-0042 (LLGR). (ADR-0046)
- **AS_PATH length matching in policy.** New `match_as_path_length_ge` and
  `match_as_path_length_le` fields on policy statements for inclusive
  range-based AS_PATH length filtering. Fields can be used independently or
  together (AND logic), and work standalone or combined with existing match
  criteria (prefix, community, regex, RPKI). `AS_SET` counts as 1 per
  RFC 4271.
- **Private AS removal.** New per-neighbor `remove_private_as` config strips
  private ASNs (64512–65534, 4200000000–4294967294) from AS_PATH before
  eBGP advertisement. Three modes: `"remove"` (entire path must be private),
  `"all"` (unconditional), `"replace"` (substitute local ASN). Applied before
  local ASN prepend in both unicast and FlowSpec outbound paths. eBGP only;
  route-server clients skip. (ADR-0045)
- **Transparent route server mode.** Static neighbor config now supports
  `route_server_client = true` for eBGP peers. Outbound unicast
  advertisements to route-server clients preserve the original next hop and
  skip the automatic local-AS prepend normally applied on eBGP export.
  Explicit export-policy next-hop overrides still win. RFC 8950 IPv4 over
  IPv6 next-hop and IPv6 unicast both honor the same transparent behavior.
  FlowSpec transparency remains deferred. (ADR-0039)
- **Graceful Restart restarting speaker (minimal mode).** Static peers now
  advertise GR `restart_state = true` after a coordinated daemon restart
  when a persisted marker file is present in `global.runtime_state_dir`.
  This is an honest helper-to-speaker bridge only: `forwarding_preserved`
  remains false for all families, and dynamic gRPC-added peers do not
  participate in the restart window. (ADR-0040)
- **FlowSpec fuzz target.** New `decode_flowspec` fuzz target exercises
  FlowSpec NLRI decoding directly with both IPv4 and IPv6 AFIs, complementing
  the existing `decode_message` and `decode_update` targets.
- **BMP exporter (RFC 7854).** New `crates/bmp/` crate implementing the BGP
  Monitoring Protocol. Unidirectional streaming of BGP state to external
  collectors (OpenBMP, pmacct). Encodes Initiation, Peer Up, Peer Down, Route
  Monitoring, Stats Report, and Termination messages. Per-collector async TCP
  client with reconnect/backoff. Fan-out manager distributes encoded BMP
  messages to all configured collectors. Raw BGP PDU capture in transport layer
  (`ReadBuffer::try_decode()` returns `(Message, Bytes)`) enables byte-perfect
  Route Monitoring and Peer Up messages. TOML config: `[bmp]` section with
  `[[bmp.collectors]]`. Near-zero overhead when BMP is not configured (raw
  frame capture uses `Bytes` refcount clones, not data copies). (ADR-0041)
- **Periodic BMP Stats Report.** `PeerManager` now emits periodic per-peer BMP
  Statistics Report messages every 60 seconds (RFC 7854 type 7: routes in
  Adj-RIB-In), using current `prefix_count` from transport session state.
- **CLI tool (`rustbgpctl`).** New `crates/cli/` crate providing a command-line
  interface wrapping the gRPC API. Client-only proto codegen — no dependency on
  internal crates. Commands: `global`, `neighbor` (list/show/add/delete/enable/
  disable/softreset), `rib` (best/received/advertised/add/delete), `watch`
  (streaming), `flowspec` (list/add/delete), `health`, `metrics`, `shutdown`.
  Global `--json` flag for structured output on all commands. Global `--addr`
  flag with `RUSTBGPD_ADDR` env var support.
- **Long-Lived Graceful Restart (RFC 9494).** Two-phase GR timer: when
  the GR restart timer expires, routes for LLGR-negotiated families are
  promoted to LLGR-stale (with `LLGR_STALE` community, well-known
  0xFFFF0006) instead of being purged. Routes carrying `NO_LLGR`
  (0xFFFF0007) are purged at the GR-to-LLGR transition. Effective stale
  time is `min(local llgr_stale_time, peer per-family minimum)`.
  Three-tier best-path ranking: fresh > GR-stale > LLGR-stale at step 0
  (before LOCAL_PREF). New capability code 71 with per-family 24-bit
  stale time. Config: `llgr_stale_time` per neighbor (0 = disabled,
  default). EoR during LLGR clears `is_llgr_stale` and removes locally-
  injected `LLGR_STALE` communities. PeerUp during LLGR moves families
  back to GR phase.
- **Config persistence + SIGHUP reload.** Neighbor add/delete mutations
  via gRPC are now persisted back to the TOML config file via atomic
  write (temp file + rename). `ConfigPersister` task accepts mutations
  through a bounded channel. Sending `SIGHUP` to the daemon triggers a
  config reload: `diff_neighbors()` computes the delta, `ReconcilePeers`
  applies per-peer add/delete operations. Global config changes are logged
  as warnings but require restart. Structured per-peer failure reporting
  on reconciliation.
- **MRT dump export (RFC 6396).** New `crates/mrt/` crate implementing
  `TABLE_DUMP_V2` (type 13) periodic and on-demand RIB snapshots.
  `MrtManager` runs a configurable interval timer and accepts on-demand
  triggers via the new `TriggerMrtDump` gRPC RPC on `ControlService`.
  Snapshots query Adj-RIB-In routes from `RibManager` via
  `QueryMrtSnapshot` (no Loc-RIB overlay to avoid duplication). Peer
  metadata (`peer_asn`, `peer_bgp_id`) is tracked in `RibManager` and
  retained during GR/LLGR transitions. Codec synthesizes next-hop
  attributes stripped by the MP-BGP architecture: `NEXT_HOP` for IPv4,
  `MP_REACH_NLRI` for IPv6, and `MP_REACH_NLRI` with `Afi::Ipv4` for
  RFC 8950 IPv4-with-IPv6-NH routes. Add-Path subtypes 8/9 per RFC 8050.
  `EncodeError` enum for explicit length-overflow handling (no truncation).
  Atomic file writes with optional gzip compression (flate2).
  Collision-resistant filenames (seconds + nanoseconds). TOML config:
  `[mrt]` section with `output_dir`, `dump_interval`, `compress`, and
  `file_prefix`. CLI: `mrt-dump` subcommand. (ADR-0044)

### Changed

- **RibManager submodule split.** The 8,318-line `manager.rs` has been
  split into 7 files under `crates/rib/src/manager/`: `mod.rs` (893
  lines, struct + event loop), `distribution.rs` (729 lines),
  `peer_lifecycle.rs` (193 lines), `route_refresh.rs` (333 lines),
  `graceful_restart.rs` (170 lines), `helpers.rs` (100 lines), and
  `tests.rs` (5,969 lines). Zero behavior change — pure refactor for
  reviewability.

### Fixed

- **Neighbor gRPC `remove_private_as` parity.** `AddNeighbor` now validates
  and applies `remove_private_as` (`"", remove, all, replace`) instead of
  silently forcing disabled mode for dynamic peers. `ListNeighbors` and
  `GetNeighborState` now return the active `remove_private_as` mode from
  runtime peer state.
- **Neighbor gRPC mutations are now fail-fast when persistence is unavailable.**
  `AddNeighbor` and `DeleteNeighbor` reserve config-persistence queue capacity
  before mutating runtime state. If the persistence channel is busy/closed, the
  RPC fails with `INTERNAL` instead of applying an unpersisted runtime change.
- **SIGHUP reload no longer silently accepts partial reconcile failures.**
  `ReconcilePeers` now returns structured per-peer failures; reload logs each
  failed operation and keeps the previous in-memory config snapshot when
  reconciliation is incomplete.
- **LLGR_STALE community provenance preserved.** Adj-RIB-In now tracks which
  `LLGR_STALE` communities were injected locally during LLGR promotion and
  only removes those on stale clear/EoR. Peer-originated `LLGR_STALE`
  communities are preserved.
- **Neighbor duplicate detection uses canonical IP identity.** Config
  validation now detects duplicates by parsed `IpAddr` (e.g., `::1` and
  `0:0:0:0:0:0:0:1` are treated as the same neighbor address).
- **BMP Termination on coordinated shutdown.** Main runtime now sends an
  explicit BMP shutdown control event, then drains BMP manager/client tasks
  with bounded waits so connected collectors receive BMP Termination (type 5,
  reason 0) before daemon exit.
- **BMP client write timeout.** Per-collector TCP writes now use a 5-second
  timeout to avoid indefinite stalls on slow or wedged collectors.
- **CLI gRPC connect timeout.** `rustbgpctl` now sets a 5-second
  `Endpoint::connect_timeout(...)` to avoid hanging indefinitely when the
  daemon endpoint is unreachable.
- **CLI FlowSpec DSCP validation.** `mark-dscp=` is now bounds-checked in the
  CLI (0..=63) and fails fast on invalid values before RPC submission.
- **CLI prefix IP validation.** Prefix parsing now validates address syntax
  (`IpAddr`) instead of only slash-length bounds.
- **`sendable_families` excluded IPv6 for route-server clients.** eBGP peers
  without a local IPv6 next-hop had IPv6 unicast filtered from
  `sendable_families`, silently preventing IPv6 route advertisement to
  `route_server_client` peers that preserve the original next-hop. Fixed by
  including route-server clients in the filter condition.
- **BMP collector reconnect replay.** `BmpManager` now caches live Peer Up
  state and replays it only to the collector that just reconnected, instead of
  requiring fresh session transitions to rebuild collector state.
- **Policy engine test modularization.** Extracted the `RouteModifications::merge_from`
  and `PolicyChain` test cluster into `crates/policy/src/engine/tests/chain.rs`
  to reduce monolithic test sprawl in `engine.rs`.
- **Export policy IPv6 next-hop discarded on MP path.** When export policy set
  `NextHopAction::Specific(IpAddr::V6(addr))`, the IPv6 MP_REACH send path
  detected the policy but used `route.next_hop` instead of extracting the
  policy address. Fixed by matching `Specific(addr)` directly.
- **IPv6 policy next-hop on classic IPv4 body-NLRI now warns.** Setting an IPv6
  next-hop via export policy for a non-RFC-8950 peer is unencodable in the
  classic `NEXT_HOP` attribute. This now logs a warning and falls through to
  default next-hop selection instead of silently discarding the policy address.

- **Cease subcode constants.** `ADMINISTRATIVE_RESET` (4) added,
  `OUT_OF_RESOURCES` corrected from 4 to 8 per RFC 4486. Description
  table updated for subcode 4 ("Administrative Reset") and 8.

- **FlowSpec (RFC 8955/8956).** IPv4 and IPv6 unicast FlowSpec (SAFI 133)
  with all 13 component types: destination/source prefix, IP protocol,
  port, destination/source port, ICMP type/code, TCP flags, packet length,
  DSCP, fragment, flow label. Numeric and bitmask operator encoding per
  RFC 8955. `FlowSpecRule`/`FlowSpecRoute` parallel types preserve
  `Prefix`'s `Copy` trait. FlowSpec actions (rate-limit, redirect, DSCP
  mark) encoded as extended communities. Separate FlowSpec collections in
  AdjRibIn/LocRib/AdjRibOut. Transport decode/encode via MP_REACH/MP_UNREACH
  with NH length 0. gRPC `AddFlowSpec`/`DeleteFlowSpec`/`ListFlowSpecRoutes`
  RPCs. Same policy/iBGP/RR infrastructure. Config families
  `"ipv4_flowspec"` and `"ipv6_flowspec"`. (ADR-0035)
- **RPKI Origin Validation (RFC 6811).** New `rustbgpd-rpki`
  crate with persistent RTR client (RFC 8210), per-cache-server async
  client, `SerialNotify`-triggered refreshes, enforced expiry timers,
  and multi-cache VRP aggregation. Routes stamped with `RpkiValidation`
  (Valid/Invalid/NotFound). Best-path step 0.5 prefers Valid > NotFound >
  Invalid. Policy `match_rpki_validation` enables rejection of invalid
  routes. Config `[rpki]` section with `[[rpki.cache_servers]]` for
  connecting to validators (Routinator, rpki-client, FORT). Prometheus
  metrics for VRP counts. gRPC `validation_state` on Route messages.
  (ADR-0034)
- **Extended Communities (RFC 4360).** `ExtendedCommunity(u64)` newtype
  with helpers for type/sub-type extraction, route target, and route origin
  decoding. Full wire codec (type 16, Optional|Transitive), stored on
  routes, exposed via gRPC `Route` and `AddPath`. (ADR-0025)
- **Extended Community Policy Matching.** Import/export policy can now match
  on route target (`RT:`) and route origin (`RO:`) values via
  `match_community` in prefix list entries. Encoding-agnostic matching
  (2-octet AS, IPv4-specific, and 4-octet AS compare equal). Prefix is now
  optional — entries can match community-only, prefix-only, or both (AND).
  Multiple communities in one entry use OR logic. (ADR-0026)
- **M12 interop test** — Extended communities validated against FRR 10.3.1.
  FRR route-map sets RT:65002:100, rustbgpd decodes/stores/exposes via gRPC.
  Injection round-trip verified. 14/14 tests pass.
- **Route Refresh (RFC 2918).** ROUTE-REFRESH message codec (type 5),
  capability code 2 advertised unconditionally. Inbound: peer requests
  trigger Loc-RIB re-advertisement for the requested family. Outbound:
  `SoftResetIn` gRPC RPC sends ROUTE-REFRESH to peers for soft inbound
  reset after policy changes. (ADR-0027)
- **AS_PATH loop detection (RFC 4271 §9.1.2).** Routes containing the
  local ASN in any AS_PATH segment (AS_SEQUENCE or AS_SET) are discarded
  before RIB entry. Applies to all peers (eBGP and iBGP). Withdrawals
  in the same UPDATE are still processed. New metric:
  `bgp_as_path_loop_detected_total` (labeled by peer, counts rejected
  prefixes).
- **iBGP split-horizon (RFC 4271 §9.1.1).** Non-route-reflector speakers
  no longer re-advertise iBGP-learned routes to other iBGP peers. Applies
  to `distribute_changes()`, `send_initial_table()`, and route refresh
  responses. Uses `RouteOrigin` enum (Ebgp/Ibgp/Local) instead of a
  boolean — locally originated routes pass through to all peers.
- **Standard Communities Policy Matching (RFC 1997).** Import/export
  policy can now match on standard community values via `match_community`
  in prefix list entries. Three formats: `ASN:VALUE` (e.g., `65001:100`),
  well-known names (`NO_EXPORT`, `NO_ADVERTISE`, `NO_EXPORT_SUBCONFED`),
  and existing extended community syntax (`RT:65001:100`). Standard and
  extended community criteria use OR semantics within a single entry.
  (ADR-0028)
- **Route Reflector (RFC 4456).** Designated speakers can reflect
  iBGP-learned routes based on client/non-client roles, eliminating
  the full-mesh requirement. Config: `cluster_id` (global),
  `route_reflector_client` (per-neighbor). Reflection rules: client
  routes go to all iBGP peers, non-client routes go to clients only.
  ORIGINATOR_ID (type 9) and CLUSTER_LIST (type 10) attributes with
  full wire codec, inbound loop detection, outbound manipulation
  (set on reflection, stripped on eBGP). Best-path tiebreakers:
  shortest CLUSTER_LIST, lowest ORIGINATOR_ID (RFC 4456 §9). New
  metric: `bgp_rr_loop_detected_total`. (ADR-0029)
- **Policy actions — route modification on import/export.** Policy
  engine redesigned from accept/reject to full match+modify+filter.
  `set_local_pref`, `set_med`, `set_next_hop` (self or IP),
  `set_community_add`/`set_community_remove` (standard, extended,
  large), `set_as_path_prepend` (ASN + count). Import modifications
  stored on Route; export modifications clone Loc-RIB route. Policy
  types renamed from prefix-list terminology to engine terminology.
  (ADR-0030)
- **AS_PATH regex matching.** `match_as_path` field in policy
  statements supports Cisco/Quagga-style patterns (`^65100_`,
  `_65200$`, `_65100_`). `_` expands to boundary anchor. ANDed with
  existing prefix and community conditions. `AsPath::to_aspath_string()`
  for regex-matchable format. (ADR-0030)
- **Large Communities (RFC 8092).** 12-byte community values for
  4-byte ASN operators. Wire codec (type 32, Optional|Transitive),
  `Route::large_communities()` accessor, gRPC API fields on Route and
  AddPath, policy matching (`LC:global:local1:local2` format in
  `match_community`), and set/delete in policy actions. (ADR-0031)
- **Extended Messages (RFC 8654).** Raises the 4096-byte BGP message
  limit to 65535 bytes. Capability code 6 advertised unconditionally.
  Negotiated per-session; dynamic buffer sizing on establishment.
  `max_message_len` parameter threaded through header decode, message
  decode, and UPDATE encode. (ADR-0032)
- **Add-Path (RFC 7911) — receive + multi-path send.** Accept and
  advertise multiple paths per prefix. Capability code 69 with
  `AddPathMode` (Receive/Send/Both) negotiation. `NlriEntry` and
  `Ipv4NlriEntry` structs for path-id-aware NLRI. RIB re-keyed with
  composite `(Prefix, path_id)` keys in Adj-RIB-In and Adj-RIB-Out.
  Multi-path send (route server mode): `distribute_multipath_prefix()`
  collects all candidates, applies per-candidate export policy, assigns
  rank-based path IDs. TOML config: `[neighbors.add_path] receive = true`,
  `send = true`, `send_max = N`. gRPC API: `path_id` on Route,
  RouteEvent, AddPathRequest, DeletePathRequest. (ADR-0033)

### Fixed

- **IPv4 `set_next_hop` now reaches the wire.** `apply_modifications()` updates
  `PathAttribute::NextHop` directly for `Specific(V4)` addresses. Export path
  carries full `NextHopAction` (not a boolean) so `prepare_outbound_attributes()`
  can skip eBGP rewrite when policy explicitly sets an address. IPv6 policy
  next-hop override also wired through.
- **RT/RO extended community ASN validation.** `build_rt_ec()`/`build_ro_ec()`
  now reject ASN > 65535 at config load time (2-octet AS-Specific sub-type only
  carries u16). Previously silently truncated to u16.
- **RT/RO impossible match specs rejected.** `parse_community_match()` rejects
  RT/RO match patterns with local fields exceeding the encoding capacity (e.g.
  `RT:192.0.2.1:70000` where IPv4-specific only allows u16 local).
- **AS_PATH regex `_` now matches AS_SET braces.** Expanded from `(?:^| |$)` to
  `(?:^| |$|[{}])` so patterns like `_65003_` match inside `{65003 65004}`.
- **Zero-length LARGE_COMMUNITIES rejected.** Wire decoder now rejects
  zero-length attribute value (must carry at least one 12-byte community).
- **Extended community add/remove uses logical RT/RO equivalence.**
  `set_community_remove` and `set_community_add` now compare RT/RO semantically,
  not by raw bytes. Removes work across encodings (2-octet AS, 4-octet AS,
  IPv4-specific) and adds avoid creating logical duplicates.
- **AS_PATH prepend overflow guard.** `set_as_path_prepend` no longer creates
  AS_SEQUENCE segments longer than 255 ASNs (wire segment length is u8). When
  merging would exceed the limit, a separate leading AS_SEQUENCE is created.
- **Proto `large_communities` format documented.** Added format comments
  (`"global_admin:local_data1:local_data2"`) to `Route` and `AddPathRequest`
  message fields.
- **Dead code removed.** Deleted `prefix_list.rs` (969 lines of duplicated code
  superseded by `engine.rs`). Removed 36 duplicate tests.

### Known Limitations

- **Large community duplicates preserved.** Duplicate large communities in
  received UPDATEs are stored and re-advertised unchanged. Strict RFC 8092
  normalization (dedup on receipt) is deferred as a hardening item.

- **Proto: single source of truth.** Eliminated duplicate proto file;
  `crates/api/build.rs` now compiles from `proto/rustbgpd.proto` directly.
  `SoftResetIn` RPC is now in the public proto.
- **ROUTE-REFRESH: unknown AFI/SAFI no longer tears down session.**
  `RouteRefreshMessage` stores raw wire values; unknown families are logged
  and ignored instead of triggering a decode error.
- **ROUTE-REFRESH: outbound queue no longer leaks across reconnects.**
  Outbound channel is recreated on `SessionDown` so stale updates from a
  dying session cannot be sent on the next one.
- **ROUTE-REFRESH: negotiated family/capability checks on both paths.**
  Inbound and outbound ROUTE-REFRESH now verify the requested family is
  negotiated and the peer advertised the capability.
- **SoftResetIn: accurate gRPC error codes.** Peer-not-found returns
  `NOT_FOUND`; send failures return `INTERNAL` (was all `NOT_FOUND`).
- **SoftResetIn: docs corrected.** Empty families means "all configured"
  (not "all negotiated"); transport filters to negotiated.
- **Route refresh: backpressure observable.** RIB channel full and EoR
  enqueue failures are now logged at `warn` level.
- **EoR retry under backpressure.** Failed EoR markers are tracked in
  `pending_eor` and retried on the next dirty-peer resync, so the protocol
  completion signal is no longer permanently lost.
- **SoftResetIn returns actual send outcome.** `SendRouteRefresh` is now a
  request/reply command; the gRPC response reflects whether the message was
  sent, not just enqueued.
- **AS_PATH loop fast-path: negotiated-family filter on withdrawals.** The
  loop-detection branch now applies the same `negotiated_families` check to
  `MP_UNREACH_NLRI` as the normal UPDATE path, preventing withdrawals for
  unnegotiated address families from reaching the RIB.
- **Best-path step 5 comment corrected.** The comment now accurately states
  that only `RouteOrigin::Ebgp` is preferred over iBGP; `Local` routes do
  not receive explicit preference at this step (they win via LOCAL_PREF or
  shorter AS_PATH instead).

---

## [0.3.0] — 2026-03-01

Graceful Restart (RFC 4724) — receiving speaker. Wire codec hardening.
448 tests.

### Added

- **Graceful Restart — receiving speaker (RFC 4724).** When a peer restarts
  with GR capability, routes are preserved as stale during the restart window
  instead of immediately withdrawn. End-of-RIB markers clear stale flags;
  timer expiry sweeps remaining stale routes. Enabled by default.
  - Wire: capability code 64 encode/decode with per-family forwarding flags
  - Config: `graceful_restart` (default `true`), `gr_restart_time` (default
    `120`), `gr_stale_routes_time` (default `360`)
  - FSM: peer GR capability negotiation
  - RIB: stale route demotion in best-path (step 0, before LOCAL_PREF),
    timer-based stale sweep, End-of-RIB detection and sending
  - Transport: GR-aware session teardown (PeerGracefulRestart vs PeerDown)
  - Metrics: `bgp_gr_active_peers`, `bgp_gr_stale_routes`,
    `bgp_gr_timer_expired_total`
- `rustbgpd-wire`: `Capability::encode()` now returns `Result<(), EncodeError>`
  — validates capability value lengths and `restart_time` range before encoding
- Config: `gr_restart_time=0` rejected when `graceful_restart` is enabled;
  `gr_stale_routes_time` capped at 3600 seconds; duplicate address families
  in config are deduplicated

### Fixed

- **Graceful Restart state machine corrections (RFC 4724 review).**
  - GR trigger now checks `peer_gr_capable` instead of the R-bit from the
    dying session; R-bit is only meaningful in the *new* OPEN after restart
  - All families from the peer's GR capability are retained as stale, not
    just those with `forwarding_preserved=true`
  - Routes for negotiated families NOT in the peer's GR capability are
    withdrawn immediately on GR start
  - `PeerUp` during GR no longer clears stale flags — routes stay stale
    until End-of-RIB per family, matching RFC 4724 §4.2
  - Initial GR timer uses `restart_time` (session window); timer resets to
    `stale_routes_time` on `PeerUp` (EoR window)
  - `graceful_restart=false` config now gates GR in transport
  - `bgp_gr_stale_routes` metric updated during partial EoR recovery
  - Dead outbound channels cleaned up on GR start
- `rustbgpd-wire`: capability decode now bounded to the enclosing
  optional-parameter slice — a malformed capability length can no longer
  consume into the next parameter or beyond the OPEN body
- `rustbgpd-wire`: `restart_time > 4095` in `Capability::encode()` now
  returns an error instead of silently masking with `& 0x0FFF`

- `rustbgpd-rib`: Adj-RIB-Out no longer diverges from wire state for eBGP
  peers without a valid IPv6 next-hop. `sendable_families` passed at `PeerUp`
  time filters unsendable address families before Adj-RIB-Out insertion,
  keeping `ListAdvertisedRoutes`, withdraw bookkeeping, and dirty-peer resync
  in sync with what the transport actually sends.
- `rustbgpd-wire`: `MP_REACH_NLRI` flags corrected from optional-transitive
  (0xC0) to optional-non-transitive (0x80) per RFC 4760 §3. Affects encoding,
  decoding validation (`expected_flags`), and `flags()` accessor.
  `MP_UNREACH_NLRI` was already correct.
- `rustbgpd-wire`: `validate_update_attributes()` now requires `NEXT_HOP` for
  body NLRI even when `MP_REACH_NLRI` is present. Mixed UPDATEs (body NLRI +
  MP_REACH) no longer incorrectly waive NEXT_HOP.
- `rustbgpd-wire`: `Ipv4Prefix::new()` clamps prefix length to 32;
  `Ipv6Prefix::new()` clamps to 128. Wire decoders already rejected invalid
  lengths but constructors silently created invalid prefixes.
- `rustbgpd-wire`: IPv6 next-hops in `MP_REACH_NLRI` validated — link-local
  (`fe80::/10`), loopback, multicast, and unspecified addresses rejected with
  NOTIFICATION (3,8).
- `rustbgpd-transport`: IPv6 routes built from `MP_REACH_NLRI` no longer
  inherit `PathAttribute::NextHop(ipv4)` from the same UPDATE.
- `rustbgpd-transport`: IPv6 eBGP next-hop resolution: uses
  `local_ipv6_nexthop` config > local socket address > suppress (no longer
  falls back to `::`).
- `rustbgpd-transport`: IPv6 outbound batching now groups by `(attributes,
  next_hop)` instead of just attributes. Routes with different next-hops get
  separate UPDATEs.
- `rustbgpd-transport`: Negotiated address families enforced at inbound and
  outbound edges. Routes for non-negotiated families are ignored inbound and
  filtered outbound.
- `rustbgpd-transport`: Send-time IPv6 next-hop filter now rejects loopback,
  link-local, and multicast (was only rejecting `::`), consistent with
  receive-side validation.
- `rustbgpd-fsm`: Implicit IPv4 unicast fallback per RFC 4760 §8 — when
  neither side advertises MP-BGP for IPv4, IPv4 unicast is still negotiated.
- `rustbgpd-api`: `ListReceivedRoutes`, `ListBestRoutes`, `ListAdvertisedRoutes`,
  and `WatchRoutes` now filter results by the requested `afi_safi` family
  (previously validated the enum but returned all routes regardless).
- `rustbgpd-api`: `AddNeighbor` gRPC now accepts `families` field for address
  family configuration (previously hardcoded to IPv4 unicast).
- `rustbgpd-api`: `ListNeighbors` and `GetNeighborState` now return configured
  address families (was hardcoded to empty).
- `rustbgpd-api`: `local_ipv6_nexthop` config now properly wired through
  `PeerManagerNeighborConfig` for statically configured peers (was dead config).
- `rustbgpd-rib`: Metrics label changed from `"ipv4_unicast"` to `"all"` since
  RIB now tracks both IPv4 and IPv6 routes.
- Config: `local_ipv6_nexthop` validation now rejects loopback, link-local,
  multicast, and unspecified addresses (was only checking parse-ability).

### Added

- Config: `local_ipv6_nexthop` field on `[[neighbors]]` — explicit IPv6
  next-hop address for eBGP sessions over IPv4 transport.
- `rustbgpd-wire`: Public `is_valid_ipv6_nexthop()` helper for reuse across
  config validation, send-time filtering, and receive-side validation.

## [0.2.0] — 2026-02-28

MP-BGP (IPv6 unicast) support. rustbgpd is now a dual-stack BGP speaker —
IPv6 prefixes are exchanged via `MP_REACH_NLRI` / `MP_UNREACH_NLRI` (RFC 4760)
alongside existing IPv4 unicast. This is a cross-cutting change touching all 7
crates. 388 tests pass.

### Added

- `rustbgpd-wire`: `Ipv6Prefix` type with NLRI encode/decode (prefix-length
  encoding, max 128, host-bit masking). `Prefix` enum wrapping `Ipv4Prefix` and
  `Ipv6Prefix` for AFI-agnostic route representation. Helper methods
  `addr_string()` and `prefix_len()` on `Prefix`.
- `rustbgpd-wire`: `MpReachNlri` and `MpUnreachNlri` path attribute variants
  (types 14 and 15). Full decode/encode per RFC 4760 §3: AFI/SAFI, variable-
  length next-hop (16 or 32 bytes for IPv6, take global address), NLRI.
  `Afi` and `Safi` enums with `Unknown(u16)` / `Unknown(u8)` variants.
- `rustbgpd-wire`: `MP_REACH_NLRI` (14) and `MP_UNREACH_NLRI` (15) constants.
  Flag validation: type 14 = Optional (0x80), type 15 = Optional (0x80)
  per RFC 4760 §3/§4 (both are optional non-transitive).
- `rustbgpd-fsm`: `intersect_families()` computes the intersection of locally
  configured address families and peer-advertised MP-BGP capabilities.
  `NegotiatedSession` gains `negotiated_families: Vec<(Afi, Safi)>`.
- `rustbgpd-transport`: `process_update()` extracts `MpReachNlri` and
  `MpUnreachNlri` from parsed attributes, builds routes with `Prefix::V6` and
  `IpAddr::V6` next-hops, combines with body NLRI for unified RIB insertion.
- `rustbgpd-transport`: `send_route_update()` splits outbound routes by AFI —
  IPv4 routes use body NLRI (existing path), IPv6 routes use `MpReachNlri` /
  `MpUnreachNlri` attributes. eBGP IPv6 next-hop rewritten to local socket
  address.
- `rustbgpd-api`: `InjectionService` accepts IPv6 prefixes and next-hops in
  `AddPath` and `DeletePath`. Prefix length validated against AFI-specific
  maximum (32 for IPv4, 128 for IPv6).
- `rustbgpd-api`: `RibService` accepts IPv6 unicast in `afi_safi` filter
  (previously rejected non-IPv4). `WatchRoutes` events carry correct AFI based
  on prefix type.
- Config: `families` field on `[[neighbors]]` — list of address families to
  negotiate (e.g., `["ipv4_unicast", "ipv6_unicast"]`). Defaults to
  `["ipv4_unicast"]` for IPv4 neighbors, `["ipv4_unicast", "ipv6_unicast"]`
  for IPv6 neighbors.
- Config: IPv6 neighbor addresses now accepted (previously rejected at
  validation).
- Config: IPv6 prefixes supported in policy prefix lists (e.g.,
  `prefix = "2001:db8::/32"`). Prefix length validation uses AFI-specific
  maximum (32 for IPv4, 128 for IPv6).
- Interop: `m10-frr-ipv6.clab.yml` containerlab topology — rustbgpd + FRR
  dual-stack (IPv4 session with MP-BGP IPv6 unicast). FRR advertises 2 IPv4
  and 2 IPv6 prefixes.
- Interop: `test-m10-frr-ipv6.sh` automated test script with 6 tests: session
  with IPv6 capability, IPv4 backward compat, IPv6 prefix receipt, IPv6 best
  routes, IPv6 withdrawal, IPv6 route injection via gRPC.
- ADR-0023: Prefix enum and AFI-agnostic RIB for MP-BGP.

### Changed

- `rustbgpd-wire`: `UpdateMessage::build()` now encodes path attributes when
  attributes are non-empty, even if body NLRI is empty. Required for IPv6-only
  UPDATEs that carry NLRI inside `MpReachNlri` attributes.
- `rustbgpd-wire`: `validate_update_attributes()` relaxes the NEXT_HOP
  requirement when `MP_REACH_NLRI` is present (RFC 4760 §3 — next-hop is
  carried inside the MP attribute for non-IPv4 families).
- `rustbgpd-rib`: `Route.prefix` changed from `Ipv4Prefix` to `Prefix` enum.
  `Route.next_hop` changed from `Ipv4Addr` to `IpAddr`. All RIB data
  structures (`AdjRibIn`, `LocRib`, `AdjRibOut`) generalized from
  `HashMap<Ipv4Prefix, _>` to `HashMap<Prefix, _>`.
- `rustbgpd-rib`: `RibUpdate` and `OutboundRouteUpdate` use `Prefix` for
  withdrawn routes (was `Ipv4Prefix`). `RouteEvent.prefix` is now `Prefix`.
- `rustbgpd-policy`: `PrefixListEntry` generalized to match both IPv4 and IPv6
  prefixes. `le` defaults to 32 for IPv4, 128 for IPv6.
- `rustbgpd-transport`: `known_prefixes` changed from `HashSet<Ipv4Prefix>` to
  `HashSet<Prefix>`. `prepare_outbound_attributes()` strips `MpReachNlri` and
  `MpUnreachNlri` from cloned attributes (rebuilt per-route for outbound).
- Workspace version bumped to 0.2.0.

## [0.1.0] — 2026-02-28

First tagged release. Covers milestones M0–M9: a fully functional,
IPv4-unicast BGP daemon with gRPC API, RFC 4271 compliance, TCP collision
detection, and interop validation against FRR 10.3.1 and BIRD 2.0.12.
367 tests pass.

### Fixed

- `rustbgpd-transport`: `SessionNotification::OpenReceived` now reads
  `self.fsm.negotiated()` (available at `OpenConfirm`) instead of
  `self.negotiated` (set later at `SessionEstablished`). Previously the
  notification never fired, bypassing TCP collision detection entirely.
  1 integration test.
- `rustbgpd-transport`: `QueryState` now reads `remote_router_id` (and
  `negotiated_hold_time`, `four_octet_as`) from `self.fsm.negotiated()`
  with fallback to `self.negotiated`. Previously `handle_inbound()` in
  OpenConfirm could not resolve collisions because `remote_router_id` was
  `None`. 1 integration test.
- `rustbgpd-transport`: Session notification channel changed from bounded
  `mpsc::channel(64)` with `try_send()` to `mpsc::unbounded_channel()` with
  `send()`. Collision notifications are no longer silently dropped under
  channel pressure. Unbounded is safe here because rate is bounded by FSM
  state transitions (infrequent). Avoids deadlock risk that `send().await`
  on a bounded channel would introduce (PeerManager queries peer state via
  the same task).
- `PeerManager`: `disable_peer()` now clears `pending_inbound`. `BackToIdle`
  handler guards against accepting pending inbound for disabled peers.
  Previously disabling a peer could be undone by a queued inbound connection.
  1 test.
- `src/metrics_server.rs`: Semaphore permit acquired before `accept()` for
  exact connection cap (was off-by-one: 65 instead of 64).
- `docs/SECURITY.md`: Corrected metrics endpoint description (no default
  address; common port is 9179, not 9090).
- `README.md`: Docker section now warns that `grpc_addr = "0.0.0.0:50051"`
  exposes unauthenticated RPCs. Links to `docs/SECURITY.md`.
- `crates/fsm/src/session.rs`: Doc comment on `negotiated()` corrected from
  "available after Established" to "available after `OpenConfirm`".
- `ROADMAP.md`: Corrected M8 test count from 347 to 357.

## M9 — "Production Hardening"

### Added

- `rustbgpd-wire`: Cease subcode 7 (`CONNECTION_COLLISION_RESOLUTION`) for
  TCP collision detection per RFC 4271 §6.8. Human-readable description in
  `notification::description()`.
- `rustbgpd-transport`: `SessionNotification` enum (`OpenReceived`,
  `BackToIdle`) sent from peer sessions to PeerManager for collision detection
  coordination. `CollisionDump` command variant on `PeerCommand` — sends
  Cease/7 NOTIFICATION, cleans up RIB if Established, closes TCP.
  `remote_router_id: Option<Ipv4Addr>` added to `PeerSessionState`. Session
  notification channel threaded through `PeerHandle::spawn()` and
  `PeerHandle::spawn_inbound()`. (ADR-0021)
- `PeerManager`: TCP collision detection. `pending_inbound` per peer stores
  inbound TCP streams awaiting resolution. `session_notify_rx` in `select!`
  loop handles `OpenReceived` (resolve collision) and `BackToIdle` (accept
  pending). `resolve_collision()` compares BGP Identifiers — higher wins.
  `replace_with_inbound()` helper extracted for clean session replacement.
  4 new tests. (ADR-0021)
- `docs/SECURITY.md`: new document covering gRPC security posture,
  authentication gaps, privileged RPCs, and deployment recommendations.
- `docs/adr/0021-tcp-collision-detection.md`: ADR for collision detection
  architecture.
- `docs/adr/0022-grpc-server-supervision.md`: ADR for gRPC server
  supervision.

### Changed

- `src/main.rs`: gRPC server `JoinHandle` now supervised — unexpected exit
  triggers coordinated shutdown (API-first daemon without API should not
  keep running). Added to shutdown `select!` alongside ctrl-c and Shutdown
  RPC. (ADR-0022)
- `src/main.rs`: Non-loopback gRPC bind address triggers a warning at
  startup, informing operators that all RPCs are unauthenticated.
- `src/metrics_server.rs`: Read timeout (5s) prevents slow-client
  exhaustion. Request-line size limit (8192 bytes) returns 400 for oversized
  requests. Concurrent connection cap (64 via `tokio::sync::Semaphore`)
  provides backpressure. `gather()` errors return 500 Internal Server Error
  instead of panicking. 3 new tests.
- CHANGELOG updated with versioning through M9.
- ROADMAP updated: completed summary reflects M0–M8 work, M9 marked
  complete, v1 scope section added, TCP collision detection moved from
  post-v1 into M9.

## M8 — "API & Observability"

### Fixed

- `rustbgpd-rib`: WatchRoutes event model now carries `previous_peer` and
  `timestamp` on all `RouteEvent` variants. Subscribers filtered to a specific
  peer now see "route moved away" events (BestChanged/Withdrawn) where the old
  peer matches. `recompute_best()` captures previous best peer before Loc-RIB
  mutation. 4 tests.
- `rustbgpd-rib`: Prometheus gauges (`bgp_rib_prefixes`, `bgp_rib_adj_out_prefixes`,
  `bgp_rib_loc_prefixes`) wired at all RIB mutation points — RoutesReceived,
  PeerDown, distribute_changes, send_initial_table, InjectRoute, WithdrawInjected,
  recompute_best. Zero-valued gauges initialized on PeerUp for stable dashboard
  series. 3 tests.
- `rustbgpd-api`: `active_peers` in GetHealth now counts only Established peers
  (was counting all configured peers). `total_routes` now queries Loc-RIB count
  (was summing per-peer prefix counts). 1 test.
- `rustbgpd-api`: `prefixes_sent` in ListNeighbors and GetNeighborState now
  queries Adj-RIB-Out count per peer (was hardcoded to 0). Returns
  `Status::internal` on RIB manager failure instead of silently returning 0.
  1 test.
- Config: IPv6 neighbor addresses rejected at config validation and gRPC
  `AddNeighbor` boundary. Wire crate is IPv4-only and GTSM uses IPv4-only
  socket options. 2 tests.

### Changed

- Proto: `AddPathResponse.uuid` removed (was a fake 6-byte value derived from
  prefix bytes that `DeletePath` ignored). Both `AddPathResponse` field 1 and
  `DeletePathRequest` field 3 are now reserved for wire compatibility.
- Proto: `SetGlobal` RPC, `SetGlobalRequest`, and `SetGlobalResponse` annotated
  as reserved for future use (documentation-only; RPC still returns UNIMPLEMENTED).
- Proto: `RouteEvent` gains `previous_peer_address` (field 7) and timestamp
  comment clarified as Unix epoch seconds.
- `rustbgpd-rib`: `QueryLocRibCount` and `QueryAdvertisedCount` variants added
  to `RibUpdate` for accurate health and neighbor counters. 2 tests.
- `rustbgpd-api`: `ControlService` and `NeighborService` now accept `rib_tx`
  for querying RIB state.

## M7 — "Wire & RIB Correctness"

### Fixed

- `rustbgpd-rib`: Adj-RIB-Out divergence on channel-full. `distribute_changes()`
  and `send_initial_table()` now stage deltas before `try_send()`. Mutations
  commit only on success. On failure the peer is marked dirty and a persistent
  resync timer (1 second, pinned across loop iterations) fires independently of
  both incoming mutations and non-mutating query traffic, diffing the entire
  Loc-RIB against AdjRibOut to recover missed updates and withdrawals. AdjRibOut
  is preserved (not cleared) so knowledge of the peer's on-wire state is
  retained. 4 tests.
- `rustbgpd-wire`: Both malformed NLRI cases — prefix length > 32 and truncated
  NLRI buffer — now produce `InvalidNetworkField` with UPDATE subcode 10
  (Invalid Network Field). Previously prefix_len > 32 used subcode 1 and
  truncation mapped to Message Header / Bad Message Length (1/2). Error data
  includes the offending length byte and available address bytes. 2 tests.
- `rustbgpd-wire`: PARTIAL bit on re-advertised unknown attributes narrowed
  to optional transitive only (both OPTIONAL and TRANSITIVE flags set).
  Previously set PARTIAL whenever TRANSITIVE was set, incorrectly marking
  well-known transitive attributes like ATOMIC_AGGREGATE. 1 test.
- Config: policy prefix lengths eagerly validated in `Config::validate()` at
  load time. Rejects prefix length > 32, ge > 32, ge < prefix length, le > 32,
  and ge > le. Previously deferred to first policy access, which could cause
  panics in `PrefixListEntry::matches()`. Both global and per-neighbor policies
  are now checked. 4 tests.

### Added

- `rustbgpd-rib`: eBGP-over-iBGP preference in best-path selection. `Route`
  gains `origin_type: RouteOrigin` field (Ebgp/Ibgp/Local). Best-path step 5
  (between MED and peer address tiebreaker) prefers eBGP routes over iBGP per
  RFC 4271 §9.1.2. 3 tests.

## M6 — "Compliance"

### Added

- `rustbgpd-wire`: RFC-compliant attribute flag validation at decode time. Known
  attribute types are checked for correct Optional/Transitive flags, producing
  `UpdateAttributeError` with subcode 4 (Attribute Flags Error) and full attribute
  data per RFC 4271 §6.3. Replaces dead `check_wellknown_flags` in validator.
- `rustbgpd-wire`: Specific UPDATE error subcodes replace generic subcode 1
  (Malformed Attribute List) — length errors produce subcode 5, invalid ORIGIN
  produces subcode 6, malformed AS_PATH produces subcode 11. All include the
  offending attribute as NOTIFICATION data.
- `rustbgpd-wire`: `UpdateAttributeError` variant on `DecodeError` carrying subcode,
  attribute data, and detail string. `to_notification()` maps it to the correct
  `(UpdateMessage, subcode, data)` tuple.
- `rustbgpd-wire`: Shared `attr_error_data()` helper builds RFC 4271 §6.3 error data
  (flags + type + length + value), correctly setting the Extended Length flag for
  values > 255 bytes. Replaces buggy `encode_attr_for_error` in validator.
- `rustbgpd-wire`: Partial bit (0x20) is now OR'd into flags when encoding unknown
  transitive attributes for re-advertisement, per RFC 4271 §5. 10 new tests.
- `rustbgpd-api`: `GlobalService` gRPC implementation — `GetGlobal` returns daemon
  ASN, router-id, and listen port; `SetGlobal` returns UNIMPLEMENTED (runtime mutation
  deferred to post-v1). 2 tests. (ADR-0020)
- `rustbgpd-api`: `ControlService` gRPC implementation — `GetHealth` returns uptime,
  active peer count, and total route count; `GetMetrics` returns Prometheus text
  exposition; `Shutdown` initiates coordinated daemon shutdown via gRPC. 2 tests.
  (ADR-0020)
- Coordinated shutdown: ctrl-c and `Shutdown` RPC both trigger ordered teardown —
  PeerManager drains all peers (sending NOTIFICATIONs), then gRPC server exits
  gracefully via `serve_with_shutdown`. Previously the runtime dropped mid-shutdown.

### Fixed

- `rustbgpd-transport`: eBGP NEXT_HOP rewrite now uses the TCP session's local
  address instead of `local_router_id`. Router-id is often a loopback that is
  not reachable from the peer; the local socket address is correct.
- `rustbgpd-api`: `AddPath` with empty `as_path` no longer produces a zero-length
  AS_SEQUENCE segment that fails our own UPDATE validator. Empty input now creates
  an AS_PATH with no segments (correct for locally-originated routes).
- `rustbgpd-api`: `afi_safi` field in `ListReceivedRoutes`, `ListBestRoutes`,
  `ListAdvertisedRoutes`, and `WatchRoutes` is now validated. Requesting an
  unsupported address family (e.g., IPv6) returns `INVALID_ARGUMENT` instead of
  silently returning IPv4 data.
- `rustbgpd-wire`: 2-octet ASN encoding no longer silently truncates 4-byte ASNs.
  ASNs > 65535 are now mapped to `AS_TRANS` (23456) per RFC 6793.
- Config: invalid policy entries (unknown action, malformed prefix) now return
  `ConfigError::InvalidPolicyEntry` instead of being silently filtered. 2 tests.
- `KNOWN_ISSUES.md`: removed stale entries about missing inbound listener and
  outbound UPDATE generation (resolved in M5 and M3 respectively).
- Metrics server: inbound accept forwarding failure now logged instead of silently
  dropped.

### Changed

- `rustbgpd-api`: Deduplicated pagination logic in `RibService` — extracted
  `parse_page_params()` and `build_response()` helpers used by all 3 list RPCs.
- Workspace version bumped to 0.1.0. Repository URL fixed. Added `rust-version`,
  `keywords`, `categories` metadata for crates.io publishing. Proto file copied
  into api crate for standalone packaging.

### Added (M5 — "Polish")

- `rustbgpd-transport`: Inbound TCP listener. `BgpListener` accepts connections on
  `listen_port` and forwards to PeerManager via `AcceptInbound` command. `PeerSession::new_inbound()`
  starts with an already-connected stream. `PeerHandle::spawn_inbound()` spawns inbound sessions.
  (ADR-0019)
- `rustbgpd-transport`: Session counters — `updates_received`, `updates_sent`,
  `notifications_received`, `notifications_sent`, `flap_count`, `uptime_secs`, `last_error`
  tracked per session and exposed via `PeerSessionState` and gRPC `NeighborState`.
- `rustbgpd-transport`: Accurate prefix tracking via `HashSet<Ipv4Prefix>` instead of
  add/subtract heuristic. Duplicate announcements no longer inflate count; withdrawals
  of unknown prefixes no longer underflow.
- `rustbgpd-transport`: NLRI batching — outbound UPDATEs with identical path attributes
  are grouped into a single wire UPDATE message.
- `rustbgpd-api`: Input validation for `AddNeighbor` (reject `remote_asn=0`,
  `hold_time` of 1 or 2) and `AddPath` (reject `next_hop` of `0.0.0.0` or multicast).
  4 unit tests.
- `rustbgpd-api`: `NeighborState` proto fields fully populated — uptime, update/notification
  counters, flap count, last error, hold_time, max_prefixes. Previously hardcoded to 0.
- `rustbgpd-rib`: `RibManager` accepts `BgpMetrics` and records `outbound_route_drops`
  counter when `try_send()` fails.
- `rustbgpd-telemetry`: `outbound_route_drops` IntCounterVec metric (labeled by peer).
- Config: `#[serde(deny_unknown_fields)]` on all config structs — typos now cause
  startup errors instead of silent acceptance. 2 tests.
- Metrics server: per-connection task spawn, HTTP path routing (404 for non-`/metrics`),
  5-second write timeout. 2 tests.

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

- MSRV bumped from Rust 1.85 to 1.88. Required for `let` chains and
  `usize::is_multiple_of()` stabilization.
- Dockerfile updated from `rust:1.85-bookworm` to `rust:1.88-bookworm`.

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
