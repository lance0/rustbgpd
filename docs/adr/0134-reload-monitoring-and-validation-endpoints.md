# ADR-0134: Reload-Apply BMP Collectors and RPKI Cache Endpoints Without Session Resets

**Status:** Proposed
**Lifecycle:** Active
**Date:** 2026-09-15

## Context

On running route servers, route reflectors, and peering edge routers (often
hosting 500–1,000+ active BGP sessions), three routine monitoring and validation
adjustments currently demand a full daemon restart:

1. **BMP collectors (`[bmp]`):** Adding a new collector, pointing monitoring at
   a new relay host, or updating collector query filters.
2. **RPKI RTR caches (`[rpki]`):** Migrating validator infrastructure (e.g.
   transitioning between Routinator and StayRTR instances), adding a second cache
   for high-availability redundancy, or retiring a decommissioned cache endpoint.
3. **MRT dumps (`[mrt]`):** Enabling periodic diagnostic table dumps, disabling
   scheduled dumps after an incident investigation settles, or tuning output
   intervals.

Today, `docs/reference/reload-matrix.md` classifies `[bmp]`, `[rpki]`, and
`[mrt]` as `restart-required`. When `diff_config` detects changes to these
sections (`bmp_changed`, `rpki_changed`, `mrt_changed` in `src/config/mod.rs`),
the entire candidate configuration is treated as requiring a restart.

A daemon restart tears down and resets every established BGP session across the
entire fleet. Even when coordinated Graceful Restart
([ADR-0040](0040-gr-restarting-speaker.md)) is negotiated, restarting forces a
complete restart cycle: all member sessions disconnect, all inbound routes are
withdrawn or marked stale, and post-restart recovery incurs a massive wave of
parallel TCP handshakes, wire decoding, policy pipeline evaluations, and best-path
calculations. For route-server operators hosting hundreds of members, an
operational necessity as mundane as pointing telemetry at a new collector
relay host triggers network-wide churn.

### Industry Prior Art

The operational state-of-the-art avoids BGP session disruption for auxiliary
monitoring and validation connections:

- **BIRD:** In BIRD (`cli-configure`, `doc/bird.sgml`), runtime `configure`
  smoothly switches to the candidate configuration: protocols are reconfigured
  if possible, restarted otherwise. BMP, RPKI (RTR), and MRT operate as
  independent protocol instances. A configuration change modifying or adding an
  RTR cache or BMP collector reconfigures or restarts that specific protocol
  subsystem without affecting the BGP protocol instances or tearing down
  peering sessions.
- **GoBGP:** GoBGP exposes fine-grained runtime RPCs (`AddBmp`/`DeleteBmp`,
  `AddRpki`/`DeleteRpki`/`ResetRpki`, and `EnableMrt`/`DisableMrt` defined in
  `api/gobgp_grpc.pb.go`). Operators can add or retire monitoring endpoints at
  will via runtime management without resetting BGP sessions.

### In-Tree Precedent and Capabilities

rustbgpd already contains the architectural blueprint and core building blocks
needed to reconcile these endpoints cleanly:

1. **`[gnmi_dialout]` reconciliation:** Added in the telemetry arc,
   `[gnmi_dialout]` is fully `reload-applied`
   (`docs/reference/reload-matrix.md:378`). On SIGHUP, the daemon plans and
   applies target diffs via `DialoutManager::apply`
   (`crates/api/src/gnmi_dialout.rs:267`):
   - Removed targets are stopped and their Prometheus series reaped.
   - Added targets are spawned and initiate connection loops.
   - Changed targets tear down and redial.
   - Unchanged targets maintain their established TCP sessions without drop or
     churn.
   - Preflight validation failures cleanly reject the candidate before any
     state is mutated.
2. **Deferred BMP management:** [ADR-0041](0041-bmp-exporter.md) noted runtime
   collector add/remove under **Deferred**, not rejected. The BMP subsystem
   already incorporates per-collector connection generation fencing
   (`generation: Arc<AtomicU64>`), RFC 7854 message fan-out, targeted
   bootstrap sequencing, and Loc-RIB dump End-of-RIB synchronization.
3. **Per-cache RPKI runtime inventory:** The RPKI subsystem already maintains
   isolated per-cache state via `CacheInventoryAttachment`
   (`crates/rpki/src/vrp_manager.rs`), providing per-cache connection status,
   retained End-of-Data (EoD) readiness, and contribution metrics.
4. **Delta-scoped RPKI revalidation:** The VRP and ASPA managers already support
   cache withdrawal semantics (`VrpUpdate::ServerDown`). When a cache is
   removed, its contributions are purged from `server_tables` and
   `server_aspa_tables`, merged snapshots are rebuilt, and delta-scoped
   revalidation notifies the RIB to update validation state without resetting
   peering sessions.

## Decision

We decide to promote `[bmp]`, `[rpki]`, and `[mrt]` from `restart-required` to
`reload-applied` configuration sections, executing their runtime adjustments
without resetting BGP sessions.

Configuration files reloaded via SIGHUP (and transaction-staged `rbgp config
apply` transactions once classified) remain the authoritative operator surface.

### Explicit Non-Goals

1. **No ad-hoc gRPC CRUD APIs:** We deliberately reject introducing dedicated
   imperative gRPC methods (such as `AddBmp` or `DeleteRpki`). Maintaining
   imperative RPC mutation alongside declarative configuration files creates
   drift and split-brain configuration risk. All runtime mutations must proceed
   through declarative configuration reconciliation via SIGHUP or unified
   configuration transactions.
2. **No new cryptographic transport wrappers:** BMP over TLS and RTR over
   TLS/SSH were evaluated during competitive analysis and identified as
   non-gaps. Supported transports remain plain TCP, TCP MD5, and TCP-AO (for
   authenticated cache connections preflighted against the kernel).

---

### Slice 1: BMP Collector Reconciliation (`[[bmp.collectors]]`) [Size: M]

The BMP subsystem shall reconcile configured collectors by diffing the active
collector set against the reloaded configuration on SIGHUP, following the
`[gnmi_dialout]` reconciliation model.

#### Reconciliation Contract

1. **Diffing:** Match configured `[[bmp.collectors]]` by their canonical socket
   address (`address`).
2. **Removed Collector:**
   - The manager sends an RFC 7854 BMP Termination message (Reason 0:
     Administratively down) if the TCP connection is live.
   - The associated `BmpClient` task is aborted, the TCP connection is closed,
     and the per-collector channel is dropped.
   - Prometheus metrics carrying the `collector` label for that address are
     reaped from `BgpMetrics`.
3. **Added Collector:**
   - `BmpManager` allocates an internal collector entry, registers its
     configured message filters, and initializes its connection generation at 0.
   - Spawns a new `BmpClient` task targeting the specified address with
     configured reconnect backoff.
   - Upon successful TCP connection, the client initiates the RFC 7854 sequence:
     sends Initiation, replays Peer Up messages for all currently established
     BGP sessions, and initiates a Loc-RIB dump if configured (`loc_rib = true`).
4. **Changed Collector:**
   - If per-collector parameters change (`reconnect_interval`, `version`, or
     `monitor` filter views), the manager triggers a generation closure and
     reconnect cycle for that specific collector only.
   - The collector reconnects, re-sends Initiation, and synchronizes state
     according to the updated filters.
5. **Unchanged Collector:**
   - Live TCP connections, buffered outbound messages, and active streaming are
     completely untouched.
   - Unchanged collectors NEVER receive redundant Peer Up replays or
     unnecessary reconnect cycles.
6. **Top-Level Attributes (`sys_name`, `sys_descr`):**
   - RFC 7854 Initiation PDUs advertise `sys_name` and `sys_descr` once at
     connection setup. Modifying these top-level strings requires redialing all
     running collectors so they receive fresh Initiation PDUs.
   - Crucially, redialing collectors MUST NOT reset or bounce any BGP sessions.

#### Handling Post-Policy Adj-RIB-Out Mirroring (`bmp_rib_out`)

Per RFC 8671, mirroring outbound UPDATEs (`BmpMonitorView::RibOutPost`) requires
the peer session's transport layer to clone outbound messages and emit them onto
the BMP channel.

Today, `TransportConfig.bmp_rib_out` is computed once when the session is
constructed (`src/peer_manager/mod.rs:1426`) and read on the hot write path
(`crates/transport/src/session/io.rs:283`).

- **Contract:** Outbound UPDATE mirroring must not require bouncing BGP sessions
  when a collector requesting `RibOutPost` is added or removed.
- **Mechanism:** The peer manager provides an atomic switch (`Arc<AtomicBool>`)
  or broadcasts an in-session configuration event to active peer sessions. When
  the aggregate count of collectors requiring `RibOutPost` transitions between 0
  and >0, the active sessions dynamically toggle outbound mirroring.
  - Adding the first `RibOutPost` collector begins outbound mirroring
    immediately without resetting the peer. (Initial Adj-RIB-Out state
    synchronization for the newly added collector is completed via the
    replayed outbound route dump or explicit peer replay).
  - Removing the last `RibOutPost` collector turns off outbound UPDATE cloning,
    eliminating transport overhead.

#### Generation Fencing and Stream Invariants

Reconciling BMP collectors must strictly preserve established streaming
invariants:

- **Per-Collector Generation Fencing:** Every collector instance maintains an
  `Arc<AtomicU64>` generation counter. Any reconnect or redial increments the
  generation before spawning a new connection cycle.
- **Loc-RIB Dump End-of-RIB (EoR) Ordering:** In-flight Loc-RIB dumps and
  buffered live deltas (`ActiveDump`, `loc_rib_buffer`) are bound to the
  specific generation that requested them. A redialed or removed collector
  immediately aborts in-flight dump tasks. Live updates occurring after
  generation start are held back and replayed only after the dump's End-of-RIB
  marker, ensuring no post-generation updates precede the dump on the wire.
- **Channel Saturation Isolation:** Slow or stalled collectors continue to fail
  closed independently at the per-collector channel cap without stalling
  adjacent collectors or impacting BGP session packet processing.

---

### Slice 2: RTR Cache Endpoint Reconciliation (`[[rpki.cache_servers]]`) [Size: M]

The RPKI subsystem shall reconcile cache servers on SIGHUP by comparing active
RTR clients against candidate `[[rpki.cache_servers]]`.

#### Reconciliation Contract

1. **Diffing:** Match configured cache servers by socket address (`address`).
2. **Added Cache Server:**
   - Candidate address and authentication options (TCP MD5 or TCP-AO) are
     preflight-checked against the kernel.
   - The address is registered with `CacheInventoryAttachment`.
   - The initial End-of-Data readiness gauge is explicitly published as false:
     `rpki_cache_end_of_data_ready{cache=...} = 0`.
   - A new `RtrClient` task is spawned. The client initiates TCP connection,
     performs RTR Reset Query, and populates initial VRP and ASPA tables.
3. **Removed Cache Server:**
   - The associated `RtrClient` task is aborted, active TCP sockets are closed,
     and any kernel-installed TCP MD5 / TCP-AO keys are cleared.
   - `VrpManager` receives `VrpUpdate::ServerDown { server }`.
   - `VrpManager` purges the cache's tables from internal storage
     (`server_tables.remove(&server)` and `server_aspa_tables.remove(&server)`).
   - Merged VRP and ASPA tables are recomputed from the remaining active caches.
   - Merged table deltas are dispatched to the RIB manager. The RIB invokes
     delta-scoped revalidation over prefixes covered by the withdrawn records,
     re-evaluating validity states and triggering Route Refresh only where
     outcomes change. Peering sessions are NOT reset.
   - Associated Prometheus metrics (`rpki_cache_effective_expire_seconds`,
     `rpki_cache_end_of_data_ready`) are reaped.
4. **Changed Cache Server:**
   - If endpoint identity or authentication changes, the cache is treated as a
     remove-then-add operation.
   - If operational timers change (`refresh_interval`, `retry_interval`), the
     running `RtrClient` is updated in place via its control channel without
     dropping the live TCP connection or RTR session.
5. **Unchanged Cache Server:**
   - Live TCP connections, negotiated RTR session IDs, serial numbers, and
     cached VRP/ASPA data remain completely uninterrupted.
6. **Global RPKI Knobs:**
   - Global validation parameters (`strict` mode enforcement, RFC 8212 fallback
     interactions, and system-wide `expire_interval` ceilings) remain
     `restart-required`. Attempting to alter these settings without a restart is
     rejected during reload preflight.

#### Readiness and Strictness Fencing

- A newly configured cache server must not cause false readiness reports.
- When `rpki strict` mode is configured, BGP routes requiring valid RPKI state
  shall not treat a newly added cache as authoritative until that cache reaches
  its first successful End of Data (EoD).
- If existing caches are already healthy and delivering VRPs, adding an
  additional cache shall not degrade the operational readiness of the running
  daemon.

---

### Slice 3: MRT Dump Configuration (`[mrt]`) [Size: S]

The MRT dump subsystem shall reconcile configuration changes on SIGHUP without
affecting the BGP routing engine.

#### Reconciliation Contract

1. **Enablement (`None` → `Some(MrtConfig)`):**
   - The candidate output directory path is validated for filesystem writability
     during preflight.
   - `MrtManager` task is spawned with configured interval, file prefix, and
     compression settings.
2. **Disabling (`Some(MrtConfig)` → `None`):**
   - The running `MrtManager` task is aborted.
   - Any currently open partial dump file is flushed, closed, and finalized.
3. **Adjustment (`dump_interval`, `file_prefix`, `compress`):**
   - If output parameters change, the running manager updates its interval
     timers or restarts its periodic dump loop cleanly.
   - Peering sessions and RIB states are completely unaffected.

---

### Lifecycle, Failure Recovery, and SIGHUP Architecture

#### SIGHUP Reload Route Classification

The route classifier in `src/config/mod.rs` shall be updated:

- Candidate configurations containing changes *only* to `[bmp]`, `[rpki]`, or
  `[mrt]` do not touch static neighbor state, policy ASTs, or kernel dataplane
  bindings. They execute along the sequential reload route (or a dedicated
  auxiliary reconciler stage).
- Mixed configurations (e.g. updating a neighbor description while adding a BMP
  collector) execute the generation route for peer updates, followed by the
  monitoring endpoint reconciliations.

#### Failure Recovery and Atomic Preflight

Preflight validation must run before any state mutation:

1. **Validation:** All candidate IP addresses, ports, directories, and timer
   ranges are verified during candidate parsing (`Config::load_and_validate`).
2. **Clean Failure Rejection:** If preflight fails (e.g. invalid IP address,
   unwritable MRT directory, or contradictory timer bounds), the reload halts
   immediately. The error is logged, and running BMP collectors, RTR caches, MRT
   tasks, and BGP sessions continue operating completely unaffected.
3. **Runtime Connection Failures:** If an added BMP collector or RTR cache
   fails to establish TCP connectivity at runtime, the failure is handled by the
   subsystem's standard backoff and retry loop. It NEVER cascades into BGP
   session failure or daemon instability.

---

## Testing Matrix Requirements

Every implementation slice must fulfill the following verification gates before
acceptance:

1. **Reload Matrix Updates:**
   - Update `docs/reference/reload-matrix.md` to reflect `reload-applied` status
     for the reconciled sections.
2. **Negative / Failed-Reload Proofs:**
   - Unit and integration tests verifying that a candidate configuration with
     syntactic or semantic errors in `[bmp]`, `[rpki]`, or `[mrt]` is rejected
     cleanly, leaving all running collectors, RTR caches, and MRT tasks running
     with their prior configurations.
3. **Real-Collector and Real-Cache Integration Lanes:**
   - **BMP Lane:** Automated multi-collector test using real collector software
     (pmacct or gobmp in the container test lane). Verify dynamic addition,
     re-pointing, and removal of collectors while 1,000 routes are processed over
     live BGP sessions, proving zero BGP session resets occur.
   - **RPKI Lane:** Automated multi-cache test using real RTR validators
     (StayRTR and Routinator). Verify:
     - Adding a second validator reaches EoD and contributes to the merged table
       without BGP flaps.
     - Removing a validator purges its specific records, runs delta-scoped
       revalidation, and updates route validation states without BGP session
       flaps.
   - **MRT Lane:** Verify enabling MRT dumps creates valid uncorrupted dump
     files, adjusting interval updates dump frequency, and disabling stops dumps
     cleanly.
4. **Documentation & Release Artifacts:**
   - Provide explicit CHANGELOG entries and upgrade notes detailing the
     transition from `restart-required` to `reload-applied`.
   - Document metric lifecycle semantics (specifically noting that Prometheus
     series for removed collectors or caches are reaped upon removal).

---

## Workload Sizing and Sequencing

| Slice | Workload | Size | Dependencies |
|---|---|---|---|
| **ADR-0134** | Architecture and decision record | **S** | None |
| **Slice 1** | BMP collectors reconcile (`[bmp]`) | **M** | ADR-0134 |
| **Slice 2** | RTR cache endpoints reconcile (`[rpki]`) | **M** | ADR-0134, Slice 1 patterns |
| **Slice 3** | MRT dump on/off and interval tuning (`[mrt]`) | **S** | ADR-0134 |

**Sequencing:** Slice 1 (BMP) addresses the most acute operational need
(telemetry re-pointing on route servers) and establishes the endpoint diffing
and metric reaping infrastructure. Slice 2 (RTR) follows, integrating with the
existing `CacheInventoryAttachment` and delta-scoped revalidation. Slice 3 (MRT)
completes the auxiliary endpoint set.

---

## Consequences

### Positive

- Route server and route reflector operators can adjust monitoring relays, add
  redundant RPKI caches, and enable diagnostic dumps without dropping active
  peering sessions.
- Eliminates unnecessary network-wide route churn and CPU spikes caused by daemon
  restarts for auxiliary endpoint reconfigurations.
- Brings rustbgpd operational ergonomics to parity with BIRD and GoBGP.
- Reuses proven internal patterns: the `[gnmi_dialout]` diffing lifecycle, BMP
  generation fencing, and RTR delta-scoped revalidation.

### Negative

- Introduces additional state reconciliation logic into daemon reload processing.
- Metric series for removed collectors and RTR caches disappear from `/metrics`,
  requiring monitoring systems to handle dynamic metric label lifecycles (same
  behavior as `[gnmi_dialout]`).

### Neutral

- Global RPKI configuration knobs (validation mode strictness, RFC 8212
  interactions, expire ceilings) remain restart-required.
- SIGHUP and configuration transactions remain the sole operator interface; no
  divergent gRPC CRUD APIs are introduced.
