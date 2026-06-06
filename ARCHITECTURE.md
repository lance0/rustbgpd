# Architecture

> Update this file when crate boundaries, runtime ownership, or cross-crate
> contracts change. Do not put milestone or status content here.

---

## Crate Dependency Graph

```
wire           (no internal deps)
bfd            (no internal deps)
fsm            ──► wire
policy         ──► wire
rpki           ──► wire
bmp            (no internal deps)
mrt            ──► wire, rib
telemetry      (no internal deps)
event-history  ──► telemetry
evpn           ──► wire
evpn-linux     ──► evpn
rib            ──► wire, policy, telemetry, rpki
transport      ──► wire, fsm, rib, policy, rpki, telemetry, bmp
api            ──► wire, fsm, rib, policy, transport, telemetry, evpn, event-history
cli            (no internal deps — uses tonic codegen directly)
```

The daemon binary (`src/`) depends on every crate above; it wires them
together and owns the runtime actors that are not themselves crates (the
unicast Linux FIB, the BFD socket actor, and the EVPN dataplane glue).

### Crate summary

| Crate | Description |
|-------|-------------|
| `rustbgpd-wire` | BGP message codec. Zero internal deps. Independently publishable and fuzzed. |
| `rustbgpd-fsm` | RFC 4271 state machine. Pure -- no tokio, no sockets, no tasks. |
| `rustbgpd-bfd` | RFC 5880/5881 single-hop BFD: control-packet codec + sans-IO session state machine. Pure -- no tokio, no sockets (ADR-0067). The UDP/timer actor that drives it lives in the daemon binary (`src/bfd_runtime.rs`). |
| `rustbgpd-transport` | Tokio TCP glue. Owns BGP peer session I/O and drives the FSM. |
| `rustbgpd-rib` | Adj-RIB-In, Loc-RIB best-path, Adj-RIB-Out. Single-task ownership, no locks. |
| `rustbgpd-policy` | Policy engine: prefix/community/AS_PATH matching, route modifications. |
| `rustbgpd-rpki` | RPKI origin validation: RTR client, VRP table, multi-cache aggregation. |
| `rustbgpd-bmp` | BMP exporter: RFC 7854 codec, collector clients, manager fan-out. |
| `rustbgpd-mrt` | MRT dump: RFC 6396 TABLE_DUMP_V2 codec, atomic writer, periodic manager. |
| `rustbgpd-event-history` | Durable local event outbox (ADR-0072): SQLite WAL store with monotonic `event_id`, `EventHistoryManager` actor + storage thread, in-process `subscribe_live()` broadcast, retention by count + bytes, payload-opaque (producer-encoded bytes are persisted and broadcast byte-identically). Producers (RIB, EVPN, PeerManager session lifecycle, policy, BFD bridge, dataplane FIB / blackhole) enqueue prost-encoded `BgpEvent` envelopes; the gRPC `SubscribeFromEvent` cursor in `api` does the replay → live handoff. |
| `rustbgpd-evpn` | EVPN local VTEP domain model: `EvpnInstance` / `EvpnInstanceTable` / `RouteTarget` / `IpVrf` / `IpVrfTable` (RFC 7432 / RFC 8365 / RFC 9136). Includes the `LocalMacOriginator` / `LocalMacIpOriginator` / `LocalEsOriginator` / `LocalEadPerEs*` state machines (RFC 7432 §15.1 mobility + §8 multi-homing), the `DataplaneIntent` / `RemoteMacTable` snapshot types with `RemoteMacEntry::alias_group_key` for ADR-0059 aliasing-ECMP wire intent, the IP-VRF readiness probe (Gate 9), and the pure-logic Type 5 origination + projection helpers (RFC 9136 §4.4.2 Interface-less IRB). Aliasing module (`aliasing::group_members`) produces the canonical alias VTEP set for a multi-homed Type 2. Domain-only, kernel-free. See ADR-0052, ADR-0054, ADR-0055, ADR-0057, ADR-0058, ADR-0059. |
| `rustbgpd-evpn-linux` | Linux kernel dataplane for EVPN VTEP mode (`cfg(target_os = "linux")`). Reconciles remote-MAC FDB programming via rtnetlink, surfaces local-MAC observations from `RTNLGRP_NEIGH` upward (plus `RTNLGRP_IPV4_ROUTE` / `RTNLGRP_IPV6_ROUTE` for slice 6a sub-second IP-VRF route observation), supplies Linux rtnetlink dumps for VRF / L3VXLAN inventory (Gate 9), implements the `Dataplane::probe_ip_vrfs` IRB readiness call, and programs FDB nexthop groups via `NDA_NH_ID` / `NHA_FDB` for aliasing-ECMP receive paths (ADR-0059). `linux::nexthop_raw` is the raw-netlink primitive (rtnetlink 0.21 has no nexthop API); `linux::fdb_nhg` is the apply primitive with the CVE-2025-39851 guard; `group_state` + `nh_id_alloc` carry the refcount + NHID-tagging state the reconcile coordinator uses. Consumes domain types from `rustbgpd-evpn`; never imports `rib` or `transport`. See ADR-0054, ADR-0055, ADR-0058, ADR-0059. |
| `rustbgpd-api` | gRPC server (tonic). Eleven services, proto codegen at build time. |
| `rustbgpd-telemetry` | Prometheus metrics + structured tracing. |
| `rustbgpctl` | CLI tool. Client-only gRPC stubs, no internal crate deps. |

### Hard rules

- `wire` depends on nothing internal. It is a pure codec library, independently publishable.
- `fsm` depends on `wire` types (message enums, capability structs) and nothing else. It never imports tokio, never touches a socket, never spawns a task.
- `bfd` is a pure sans-IO crate with zero internal deps: RFC 5880 control-packet codec plus the session state machine. Like `fsm`, it never imports tokio or touches a socket — the daemon binary's `src/bfd_runtime.rs` owns the UDP sockets, per-session timers, and discriminator demux (ADR-0067).
- `transport` is the only crate that owns BGP peer TCP session I/O and drives the FSM. Other crates (`api`, `bmp`, `rpki`, `mrt`) run their own async tasks for gRPC serving, collector connections, RTR sessions, and dump I/O respectively.
- `rib` and `policy` are independent of transport and fsm — they consume route update events.
- `evpn` is the local-VTEP domain crate (ADR-0052, ADR-0055, ADR-0058). It depends only on `wire`. It does **not** depend on `rib` or `transport`, and it never programs the kernel — kernel reconciliation lives in `crates/evpn-linux` (ADR-0054, shipped Gate 7b/7b+1; Gate 9 IP-VRF readiness probe + Linux netlink dumps + `probe_ip_vrfs` trait surface). The bidirectional VTEP loop is wired in the daemon binary by `src/evpn_dataplane.rs` (downward: RIB best-path → kernel FDB; also publishes the `IpVrfTable` through `DataplaneIntent` so the reconciler can probe IRB readiness every pass) and `src/evpn_originator.rs` + `src/evpn_imet.rs` (upward: kernel local-MAC observations → BGP Type 2 / Type 3 originations). RR-only deployments (empty `[[evpn_instances]]` and empty `[[evpn_ip_vrfs]]`) spawn no background tasks for either direction.
- `api` provides the gRPC server; the binary crate (`src/main.rs`) wires everything together.

---

## Runtime Model

One tokio task per peer session, one RibManager task, one PeerManager task. No shared mutable routing state. State-owning task boundaries primarily use bounded `tokio::mpsc`, with `oneshot` for request/reply, `broadcast` for route event streaming, and one intentional unbounded channel for collision-resolution notifications.

The daemon binary owns the runtime-config coordinator that serializes SIGHUP,
runtime CRUD, and config transactions. `PlanConfigTransaction` is a
PeerManager-backed validate-only path that reads the live runtime config
snapshot and returns an optimistic snapshot token. `ApplyConfigTransaction` and
the confirmed-commit controls run under the same coordinator lock used by
SIGHUP and runtime CRUD, so mutation paths share one ordering point before they
stage the runtime snapshot, apply live effects, wait for persistence
acknowledgement, and release the lock. The API crate exposes the gRPC surface;
the binary owns the actual executors because rollback needs binary-only
channels to the PeerManager, FIB reconciler, and config persistence bridge.

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
| **FIB runtime** | Kernel forwarding state (`src/fib_runtime.rs`) | Which unicast routes are installed in Linux and their owned-state across restart; the sole owner of netlink route programming |
| **BFD actor** | BFD session liveness (`src/bfd_runtime.rs`) | Whether each BFD-tracked peer's forwarding path is up; the sole owner of BFD sockets, timers, and discriminators (drives RFC 5882 coupling) |
| **Config transaction controller** | Transaction execution, confirmed-commit state, rollback orchestration | Which candidate TOML changes can commit atomically and when runtime config mutations are fenced |
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
| `PeerKey` | `api::peer_types` | API ↔ PeerManager. Stable peer identity: `address` plus an optional `interface` for scoped IPv6 link-local peers (RFC 4007 — a `fe80::/10` address is not globally unique). Numbered peers carry `interface: None`; renders as `fe80::x%ifname` (ADR-0069). |
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
| Peer session runtime | `crates/transport/src/session/` (split into `mod.rs`, `fsm.rs`, `inbound.rs`, `outbound.rs`, `io.rs`, `commands.rs`, `writer.rs`) |
| Outbound UPDATE construction | `crates/transport/src/session/outbound.rs` — `prepare_outbound_attributes()` |
| Policy evaluation | `crates/policy/src/engine.rs` |
| Best-path selection | `crates/rib/src/best_path.rs` — `best_path_cmp` / `best_path_cmp_with_reason` |
| Route distribution | `crates/rib/src/manager/distribution.rs` |
| Peer lifecycle (GR, LLGR, ERR) | `crates/rib/src/manager/graceful_restart.rs`, `route_refresh.rs` |
| RIB event loop | `crates/rib/src/manager/mod.rs` — `run()` |
| FIB install candidates (best + ECMP siblings, weights, scoped next-hop dedup) | `crates/rib/src/manager/mod.rs` — `handle_query_fib_install_candidates` |
| Unicast Linux FIB install (ECMP, weighted multipath, scoped link-local `dev`) | `src/fib.rs` (intent projection, diff, next-hop canonicalize/identity by `(addr, ifindex)`), `src/fib_runtime.rs` (netlink reconcile actor, owned-state persistence) — ADR-0061 / 0066 / 0068 / 0069 |
| BFD codec + sans-IO session FSM | `crates/bfd/src/` — `packet.rs`, `session.rs` (RFC 5880/5881, ADR-0067) |
| BFD socket/timer actor + BGP coupling | `src/bfd_runtime.rs` (UDP sockets, per-session timers, discriminator demux), `src/peer_manager/bfd.rs` (RFC 5882 session coupling) |
| gRPC service handlers | `crates/api/src/` — one file per service |
| RPKI / RTR | `crates/rpki/src/` |
| BMP export | `crates/bmp/src/` |
| MRT dump | `crates/mrt/src/` |
| Local EVPN/VTEP domain | `crates/evpn/src/` — `instance.rs`, `route_target.rs`, `mac.rs` (LocalMacObservation, RemoteMacTable), `dataplane.rs` (DataplaneIntent / DataplaneReport), `origination.rs` / `origination_macip.rs` / `origination_es.rs` (per-route-type state machines), `projection.rs` (RIB → RemoteMacTable), `segment.rs` / `df_election.rs` / `aliasing.rs` / `mass_withdraw.rs` / `label_allocator.rs` (Gate 8/8b multi-homing), `ip_vrf/` (IpVrf / IpVrfTable, readiness probe, Type 5 origination + projection helpers — Gate 9) |
| EVPN Linux kernel dataplane | `crates/evpn-linux/src/` — reconcile actor, in-memory fake, `linux/fdb.rs` (program/withdraw), `linux/links.rs` (bridge + VXLAN inventory), `linux/notify.rs` (RTNLGRP_NEIGH classifier + RTNLGRP_IPV4_ROUTE / RTNLGRP_IPV6_ROUTE route observer), `linux/probe.rs`, `linux/bum_filter.rs` (Gate 8b split-horizon), `linux/ip_vrf.rs` (Gate 9 VRF / L3VXLAN dumps + `probe_ip_vrfs`), `l3_diff.rs` + `linux/l3.rs` + `linux/routes.rs` (Gate 9 slice 6 import-side L3 FIB programming), `linux/nexthop_raw/` + `linux/fdb_nhg.rs` + `group_state.rs` + `nh_id_alloc.rs` + `diff.rs` Pass 1b (ADR-0059 FDB nexthop group aliasing-ECMP) |
| EVPN wire codec extras | `crates/wire/src/pmsi.rs` — RFC 6514 §5 PMSI Tunnel attribute (path attr type 22), used on Type 3 IMET routes |
| EVPN daemon glue | `src/evpn_dataplane.rs` (RIB → reconciler supervisor), `src/evpn_originator.rs` (kernel local-MAC → Type 2 actor), `src/evpn_imet.rs` (Type 3 IMET startup-inject + shutdown-withdraw) |
| CLI tool | `crates/cli/src/` |
| Config loading + validation | `src/config/` |
| Scoped link-local / unnumbered neighbor identity | `src/config/validation.rs` + `src/config/mod.rs` (`interface` / `scope_id` parse + resolve), `crates/api/src/peer_types.rs` (`PeerKey`), `crates/transport/src/config.rs` (`peer_interface` / `peer_scope_id`), `crates/transport/src/socket_opts.rs` (scoped connect, AF-aware GTSM), `src/peer_manager/inbound.rs` (passive scope match) — ADR-0069 |
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

1. Signal handler sets a reload flag in the main `select!` loop.
2. `reload_config()` re-reads the TOML and diffs the new config against
   the current snapshot bucket-by-bucket: neighbor sets, named policies,
   peer groups, global import / export chains, and `[[neighbors]]` deltas.
3. For each bucket (in dependency order — definitions first, then
   `[[neighbors]]` reconcile, then deletes in reverse-dependency order
   so transient `still referenced` rejections don't fire), the binary
   sends a single-shot command to the peer manager that goes through
   `apply_policy_change` / `apply_peer_group_change`. Runtime effect
   matches the existing gRPC API path: hot-applied policy chains, peer
   re-add for changed peer-group memberships.
4. Reload halts at the first step failure and returns a partial-state
   snapshot via `halt_partial`, so the daemon's in-memory config tracks
   what the peer manager actually applied (operator fixes the failing
   TOML and reloads again to converge against the half-applied state).
   Exception: the neighbor-reconcile step returns `None` on partial
   failure because live state is genuinely ambiguous after a
   delete-then-readd partial; earlier reload steps still land at the
   manager and remain in effect.
5. When an effective import policy changes via SIGHUP (or any gRPC
   `SetPolicy` / `SetPeerGroup` / chain mutation),
   `PeerManager::update_runtime_policies` automatically issues a Route
   Refresh (RFC 2918) to the affected Established peers so routes
   already in `AdjRibIn` get re-evaluated against the new policy.
   `pending_refresh` / `pending_export_apply` flags on `ManagedPeer`
   carry unfired retry intent across calls (e.g. peer mid-reconnect at
   refresh time, transient mpsc backpressure).
6. Global config changes that are not hot-reloadable
   (`[global]` ASN/router-id/families, `[rpki]`, `[bmp]`, `[mrt]`,
   `[global.telemetry.grpc_*]` listener config, inline
   `policy.import` / `policy.export` legacy global-fallback statements)
   are surfaced under "Restart-required" in `rustbgpd --diff` and logged
   at reload time. The runtime listener config for `grpc_tcp` / `grpc_uds`
   is pinned back to the live values so subsequent diffs keep flagging
   the drift until an actual restart happens.

### Config Transactions

1. `PlanConfigTransaction` sends the full candidate TOML and expected runtime
   snapshot token to the PeerManager. The PeerManager parses and validates the
   candidate, compares it with its live runtime snapshot, and classifies each
   changed section as supported, unsupported, or restart-required for the v1
   transaction model.
2. `ApplyConfigTransaction` is handled in the daemon binary. It takes the
   runtime-config coordinator lock shared with SIGHUP and runtime CRUD,
   validates the optimistic snapshot token, stages the candidate snapshot in the
   PeerManager, applies the one supported runtime family, waits for the config
   persistence acknowledgement, and only then releases the lock.
3. Rollback is executor-specific and LIFO. FIB-table, dynamic-neighbor,
   static-neighbor, catalog-only, and live-policy-impact transactions restore
   their prior runtime state and previous PeerManager config snapshot on
   apply/persist failure. Rollback failures are surfaced to the caller and
   logged as `error!`; silent partial rollback is not an acceptable outcome.
4. Commit-confirmed mode stores a singleton pending transaction with the
   captured pre-commit snapshot. `ConfirmConfigTransaction` makes it permanent;
   `AbortConfigTransaction` or timer expiry re-applies the captured snapshot
   through the same transaction executor. While a transaction is applying or
   pending confirmation, other persisted runtime config mutators return
   `FAILED_PRECONDITION`.
5. Transaction state is process-local. A daemon restart during the confirm
   window leaves the already-persisted candidate live and clears the in-memory
   auto-revert timer; operators must re-plan after restart.

### Graceful Shutdown

1. SIGTERM or `Shutdown` gRPC RPC triggers shutdown.
2. Writes GR restart marker file (if any peer has GR enabled) with expiry.
3. Sends NOTIFICATION/Cease (Administrative Shutdown) to all established peers.
4. Signals BMP manager to send Termination messages to collectors (bounded
   ~2s for the BMP send-and-drain step).
5. Drains all peer sessions through the peer manager.
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
