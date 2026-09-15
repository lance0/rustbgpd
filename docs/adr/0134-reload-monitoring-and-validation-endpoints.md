# ADR-0134: Reload-Apply BMP Collectors, RPKI Cache Endpoints, and MRT Dumps

**Status:** Proposed (no runtime behavior is shipped by this ADR)
**Date:** 2026-09-15

Line citations refer to main at `2db490acb`.

## Context

On a running route server or route reflector, three routine monitoring and
validation changes need a daemon restart today:

1. **`[bmp]`:** adding a collector, pointing monitoring at a new collector
   host, or changing a collector's monitored views.
2. **`[rpki]`:** replacing an RTR cache (a validator migration), adding a
   second cache for redundancy, or retiring one.
3. **`[mrt]`:** changing the dump interval, prefix, compression, or output
   directory, or stopping periodic dumps after an investigation.

The [reload matrix](../reference/reload-matrix.md#rpki-bmp-mrt) classes all
three sections restart-required. `diff_config` sets `rpki_changed`,
`bmp_changed`, and `mrt_changed` (`src/config/mod.rs:2199-2206`, computed at
`:4669-4672`). On SIGHUP those three sections are pinned to their running
values (`src/reload.rs:1851-1853`) and each difference is logged at `ERROR`
(`:1942-1950`); the rest of the candidate still applies. `rustbgpd --diff`
lists them under `restart_required_sections` (`src/config/mod.rs:3801-3809`),
and config transactions treat them the same way.

A restart resets every session. Coordinated graceful restart
([ADR-0040](0040-gr-restarting-speaker.md)) keeps members' forwarding state,
but the daemon still re-runs full ingest, policy, and best-path selection for
the whole fleet, and every member sees its session drop.

### Prior art

- **BIRD:** `configure` "will smoothly switch itself to the new configuration,
  protocols are reconfigured if possible, restarted otherwise". RPKI, BMP, and
  MRT are separate protocol instances, so a change to one does not restart the
  BGP protocols (`doc/bird.sgml`, `cli-configure`;
  <https://gitlab.nic.cz/labs/bird/-/raw/master/doc/bird.sgml>, checked
  2026-09-14).
- **GoBGP:** exposes `AddBmp`/`DeleteBmp`, `AddRpki`/`DeleteRpki`/`ResetRpki`,
  and `EnableMrt`/`DisableMrt` RPCs
  (<https://github.com/osrg/gobgp/blob/master/api/gobgp_grpc.pb.go>, checked
  2026-09-14).

### In-tree precedent

`[gnmi_dialout]` is reload-applied. The target set is planned during the
reload's plan phase (`src/reload.rs:2080-2082`; a bad target set is a clean
reload failure) and reconciled in the finalize step after the generation is
acknowledged (`src/reload.rs:1655-1765`, applied at `:1759-1762`).
`DialoutManager::apply` stops removed targets and reaps their series, starts
added ones, and leaves unchanged targets and their live connections alone
(`crates/api/src/gnmi_dialout.rs:267-291`). Config transactions reject the
section as unsupported and point at SIGHUP (`src/config/mod.rs:3779-3782`).
[ADR-0041](0041-bmp-exporter.md) lists runtime collector add/remove under
Deferred, not rejected (`docs/adr/0041-bmp-exporter.md:111`).

### What the subsystems do today

**BMP.** Collectors are keyed by their index in the configuration list
(`crates/bmp/src/types.rs:286-287`; `crates/bmp/src/manager.rs:217`, used by
`loc_rib_suppressed` at `:233`, `active_dumps` at `:238`, replay enrollment
at `:68`, and the connect address check at `:940-947`). Each collector has a
connection generation the manager advances on connect, disconnect, and fence
(`manager.rs:206`, `:951`, `:1071`, `:1294`). In-flight Loc-RIB dumps and
held-back live deltas are bound to that generation (`manager.rs:72-83`,
`:147-160`, `:1087-1165`); a per-collector fence retires a generation and
its dump task (`manager.rs:1226-1265`). The per-collector channel holds 4096
messages (`crates/bmp/src/client.rs:22`). Only the client sends Termination,
with reason 0, and only on daemon shutdown via the shared reconnect watch
(`client.rs:136-141`, `:223-229`). Metric reap helpers exist and run from
the manager's `Drop` (`crates/telemetry/src/metrics.rs:5978`,
`manager.rs:1312-1318`). The manager, its channels, and the `bmp_tx` handed
to the peer manager and every session exist only when `[bmp]` has at least
one collector at startup (`src/main.rs:3991-3992`, `:4412`); RFC 9069 Loc-RIB
identity and the dump channel are likewise fixed at startup.

Post-policy Adj-RIB-Out mirroring is a per-session flag computed from the
configured collectors when the transport config is built
(`src/peer_manager/mod.rs:1422-1426`), read per UPDATE on the write path
(`crates/transport/src/session/io.rs:283`), and required by outbound replay
(`crates/transport/src/session/replay.rs:173-176`). Collectors are plain TCP
(`src/config/schema.rs:642-655`).

**RPKI.** `RpkiConfig` has one field, `cache_servers`
(`src/config/schema.rs:567-572`); every timer, ceiling, and authentication
option is per cache (`:575-604`). `CacheInventoryAttachment` tracks per-cache
connection and accepted End of Data state, but its server set is fixed at
construction (`crates/rpki/src/vrp_manager.rs:183-212`) and updates for an
unknown server are ignored (`:393-406`). `RtrClient` has no control channel
(`crates/rpki/src/rtr_client.rs:204-235`; builders at `:277-327`); the cache's
End of Data overrides the configured refresh, retry, and expire timers
(`:673-736`). The VRP manager, inventory, and cache query handle are created
only when `[rpki]` has caches at startup (`src/main.rs:4184-4196`). Every RTR
client runs in one supervised `JoinSet`: the first task exit of any kind is
fatal, the supervisor aborts the rest, and the daemon shuts down with exit 1
(`src/main.rs:3165-3212`, `:5828-5838`;
[operations](../reference/operations.md#rpki-subsystem-task-exits-unexpectedly)).

Removing a cache's data today is not delta-scoped. `VrpUpdate::ServerDown`
drops the server's VRP and ASPA tables and carries no delta
(`vrp_manager.rs:585-592`, pinned by a test at `:886`, documented at
`:228-230`), so the RIB revalidates everything. Every distributed update also
calls `trigger_import_validation_refresh` (`src/main.rs:4212-4230`,
`:4239-4257`), which soft-resets every established peer whose import chain
depends on RPKI or ASPA (`src/peer_manager/policy.rs:2677-2745`).
Distribution is skipped only when the merged table is unchanged
(`vrp_manager.rs:619-622`). An added cache contributes nothing until its
first End of Data (`vrp_manager.rs:510-525`), and its readiness gauge starts
false at spawn (`src/main.rs:4289`).

**MRT.** `MrtManager` owns its writer config, RIB handle, and trigger channel
(`crates/mrt/src/manager.rs:49-110`); the on-demand trigger sender is an
`Option` created only when `[mrt]` is configured at startup
(`src/main.rs:4358-4372`, `:5244`). Dumps are written to a `.tmp` file and
published by atomic rename (`crates/mrt/src/writer.rs:20-71`). Validation
checks only that `output_dir` is non-empty and `dump_interval` is positive
(`src/config/validation.rs:579-590`).

## Decision

Reconcile `[bmp]`, `[rpki]`, and `[mrt]` on SIGHUP for subsystems that were
enabled at startup, in the finalize step, the way `[gnmi_dialout]` is
reconciled today. No BGP session is reset by any of these changes.

### Scope boundary

Enabling `[bmp]`, `[rpki]`, or `[mrt]` from zero remains restart-required,
and so does adding the first `loc_rib` collector when none was configured at
startup. The managers, channels, and handles for these subsystems are
constructed only when they are configured at startup: `bmp_tx` is `None` in
the peer manager and every session, the VRP manager and cache inventory do
not exist, and the MRT trigger sender is `None`. Wiring those handles into a
running daemon is a larger change than reconciling an existing manager and
is not proposed here. Disabling a subsystem entirely (removing the last
collector or cache, or removing `[mrt]`) is in scope: the manager stays
alive with an empty set.

### Reload integration

- **No classifier or route change.** The reconcile runs in
  `finalize_sighup_authority` after the generation is acknowledged, as
  dial-out does, including on a `KnownPartial` outcome.
- **Every fallible check runs in the plan phase**, so a rejected candidate
  has no side effect: address parsing and duplicate detection (already in
  validation, `src/config/validation.rs:997-1012`, `:1126-1137`), the kernel
  MD5/TCP-AO preflight for an added or re-authenticated cache
  (`preflight_authenticated_dial`, as startup does at `src/main.rs:3824`),
  and MRT `output_dir` writability (new).
- **Endpoints are not compensated by generation rollback.** A rejected
  generation changes no endpoints; an acknowledged generation reconciles them
  once. This matches dial-out.
- **SIGHUP only.** The three sections stay `unsupported` in config
  transactions, like `[gnmi_dialout]` (`src/config/mod.rs:3779-3782`).

### Non-goals

- No gRPC add/remove RPCs for collectors or caches. The configuration file
  is the surface; an imperative RPC family alongside it invites drift.
- No BMP over TLS and no RTR over TLS or SSH; transports stay plain TCP for
  collectors and plain TCP, TCP MD5, or TCP-AO for caches.
- No Adj-RIB-Out dump when a collector connects. Complete post-policy state
  comes from `rbgp neighbor replay-outbound` or a `loc_rib` collector.
- Per-member BFD add/remove on SIGHUP is the same class of problem (a
  neighbor added by reload that inherits BFD gets no BFD session until
  restart) but a different actor and slice list; it is tracked separately.

### Slice 1: BMP collectors (`[[bmp.collectors]]`), size M

1. **Diffing.** Match collectors by canonical socket address, the same key
   validation uses to reject duplicates.
2. **Stable collector ids.** Collector ids stop being list indexes. Each
   collector gets an id that is never reused for the life of the process, so
   removing a middle collector cannot shift the id another collector's
   active dump, suppression entry, replay enrollment, or control event
   refers to. This is the first change in the slice; the id-shift case is a
   required regression test.
3. **Removed collector.** The manager signals that collector's client to
   stop (new per-collector stop signal; today only the shared shutdown watch
   exists). The client drains its accepted queue, sends Termination with
   RFC 7854 §4.5 reason 4 (session permanently administratively closed),
   closes the socket, and exits. The manager fences the generation through
   the existing path, drops the entry, and reaps the collector's series with
   the existing helpers.
4. **Added collector.** The manager allocates an entry with a fresh id and
   generation 0 and spawns a client. On connect the existing bootstrap runs:
   Initiation, Peer Up replay for established sessions, and the Loc-RIB dump
   when the collector monitors `loc_rib` (`monitor = ["loc_rib"]`,
   `src/config/schema.rs:647-650`, `:666-675`) and Loc-RIB was configured at
   startup.
5. **Changed collector.** Any field change at the same address is a remove
   followed by an add. The collector sees Termination then a fresh
   Initiation and bootstrap under its new filter and version. No in-place
   mutation of a live collector's filter or version is proposed.
6. **Unchanged collector.** Untouched: no Peer Up replay, no reconnect.
7. **`sys_name` / `sys_descr`.** Initiation carries them once per connection
   (`crates/bmp/src/client.rs:268-269`), so a change is a remove-then-add of
   every collector. BGP sessions are unaffected.
8. **`rib_out_post` toggle.** The per-session mirroring flag becomes live:
   the peer manager pushes the new value to established sessions when the
   count of collectors monitoring `rib_out_post` crosses zero. Mirroring
   starts with the next UPDATE; the replay gate at
   `crates/transport/src/session/replay.rs:173-176` reads the same flag.
   Complete state for a newly added `rib_out_post` collector comes from
   `rbgp neighbor replay-outbound` or a `loc_rib` collector, not from a
   dump on connect. The code comment at `src/peer_manager/mod.rs:1422-1425`
   is updated.
9. **Stream invariants.** Removal and replacement reuse the existing
   generation fence and dump cancellation; no second teardown path. The
   per-collector channel cap and fail-closed behaviour are unchanged.

### Slice 2: RTR cache endpoints (`[[rpki.cache_servers]]`), size M

1. **Diffing.** Match caches by socket address. Any other field change
   (`md5_password`, `tcp_ao`, `refresh_interval`, `retry_interval`,
   `expire_interval`, `max_expire_interval`) is a remove followed by an add.
   The cache's End of Data overrides the configured timers anyway, so no
   in-place timer update is proposed.
2. **Added cache.** Plan phase: kernel MD5/TCP-AO preflight. Finalize: the
   cache is registered with the inventory (new: the inventory learns to add
   and remove servers), its End-of-Data gauge is published false at spawn
   as at startup, and an `RtrClient` is spawned into the supervised
   `JoinSet` with its kind registered. The client contributes nothing until
   its first End of Data, so an add-only reload cannot change any verdict
   before the cache has data.
3. **Removed cache.** The client receives an explicit stop signal (new: the
   client gains a stop input). It closes the socket and returns; the
   supervisor recognises that exit as requested and does not treat it as
   fatal. Panics and unexpected returns stay fatal. The
   [operations contract](../reference/operations.md#rpki-subsystem-task-exits-unexpectedly)
   is updated to say so. `VrpUpdate::ServerDown` runs through the existing
   path: the server's tables are dropped, the merged table is rebuilt, and,
   as today, the RIB revalidates everything and every RPKI/ASPA-dependent
   established peer is soft-reset once. Delta-scoped removal (wiring the
   removed set through as the delta) is optional Slice 2 work, not assumed.
   The inventory entry is removed and the cache's `cache`-labelled series
   are reaped (new: no RPKI reap helper exists).
4. **Cache replacement is make-before-break.** When one reload removes a
   cache and adds another, the removed cache's contribution stays in the
   merged table until the added cache reaches its first End of Data, with a
   bounded wait; after the bound, the removal proceeds. Without this, the
   merged table would empty between removal and the new cache's first End of
   Data, every route would read NotFound, and every RPKI/ASPA-dependent peer
   would soft-reset on both transitions. The bound keeps a cache that never
   answers from pinning stale data past the operator's intent.
5. **Unchanged cache.** Untouched: connection, session id, serial, and
   retained data are preserved.

### Slice 3: MRT dumps (`[mrt]`), size S

1. **Changed `dump_interval`, `file_prefix`, `compress`, or `output_dir`.**
   Plan phase: the new `output_dir` must be writable. Finalize: the running
   manager is stopped and a new one started with the new config; the trigger
   sender is replaced.
2. **Removed `[mrt]`.** The manager is stopped and the trigger sender
   cleared; on-demand dump requests report MRT as not configured.
3. **In-flight dump on stop.** The dump either finishes and publishes
   normally or is aborted and its `.tmp` file unlinked. A partial dump is
   never renamed into place.
4. **Enabling `[mrt]` from zero** stays restart-required (scope boundary).

### Compatibility surfaces

Each slice updates the surfaces that state or test the current class:

- `rustbgpd --diff` text `restart_required_sections`
  (`src/config/mod.rs:3801-3809`) and JSON `restart_required.rpki_changed`,
  `bmp_changed`, `mrt_changed` (`:4094-4096`); the reload-applied text and
  `has_reload_applied_changes` (`:4320-4325`, `:2504-2527`).
- `rbgp config plan` `diff_json.reload_applied`
  (`crates/cli/src/commands/config.rs:2429`).
- The `CacheServer` field docs "Restart-required like the rest of `[rpki]`"
  (`src/config/schema.rs:580`, `:585`), which feed
  `docs/reference/rustbgpd.schema.json`.
- The code comment at `src/peer_manager/mod.rs:1422-1425`.
- Metric consumers that read per-cache series and would see a removed cache
  until its series is reaped: `bgp_rpki_cache_end_of_data_ready{cache}` and
  `bgp_rpki_cache_effective_expire_seconds{cache}`
  (`crates/telemetry/src/metrics.rs:1997-2011`), read by `rbgp` control
  (`crates/cli/src/commands/control.rs:58`) and `rbgp doctor`
  `rpki.vrp_table` (`crates/cli/src/commands/doctor.rs:1229-1250`).
- The reload matrix rows, `operations.md`, CHANGELOG, and upgrade notes.
- No new RPCs.

## Validation

Each slice ships with:

1. The reload matrix row moved to reload-applied, with the scope boundary
   stated.
2. A failed-reload test: a candidate with an invalid `[bmp]`, `[rpki]`, or
   `[mrt]` change is rejected in the plan phase and running collectors,
   caches, and the MRT manager are untouched.
3. A real-endpoint lane. BMP: the M81 trio
   (`tests/interop/m81-bmp-trio-gobgp.clab.yml`; pmacct and gobmp are v3
   semantic oracles, so a v3-to-v4 collector change is asserted through the
   raw bmpsink collector). RTR: the M84 multi-cache topology
   (`tests/interop/m84-rtr-multicache.clab.yml`) plus
   `tests/interop/scripts/test-rtr-tcp-md5.sh` for authenticated caches.
   Each lane proves no BGP session reset across add, change, and remove.
4. Negative and edge cases:
   - the kernel refuses TCP-AO or MD5 for an added cache: rejected in the
     plan phase, nothing changes;
   - a middle collector is removed during another collector's Loc-RIB dump;
   - the same address is removed and re-added in one reload;
   - the only cache is replaced (make-before-break, then the bounded wait
     expiring);
   - a mixed candidate whose generation is rejected: endpoints unchanged;
   - a `KnownPartial` outcome: the reconcile still runs;
   - a cache flapping while the reload runs;
   - a supervised RTR client is removed without a fatal shutdown, while a
     panic in another client still is fatal.
5. CHANGELOG and upgrade notes for the class change.

## Sizing and order

| Slice | Work | Size |
|---|---|---|
| Slice 1 | BMP: stable ids, per-collector stop and Termination, live `rib_out_post`, reconcile | M |
| Slice 2 | RTR: supervisor stop path, inventory add/remove, client stop input, make-before-break, metric reap, operations contract | M |
| Slice 3 | MRT: writability preflight, manager replace/stop, `.tmp` cleanup | S |

Slice 1 first: it is the acute case for route servers pointing telemetry at
a new collector, and it establishes the diff, stop, and reap shape in the
finalize step. Slice 2 follows and is the riskier one because of the
supervisor and the replacement hazard. Slice 3 is independent.

## Consequences

### Positive

- Collector, cache, and dump changes on an already-enabled subsystem no
  longer reset sessions or re-run fleet-wide ingest.
- The reconcile reuses the dial-out finalize shape, the BMP generation
  fence, and the RTR `ServerDown` path rather than adding parallel ones.

### Negative

- More reconciliation logic in the finalize step, and three new
  small pieces of plumbing (collector stop signal, RTR client stop input,
  inventory add/remove) that must be tested for the supervisor's fatal-exit
  contract.
- Series for removed collectors and caches disappear from `/metrics`, as
  `gnmi_dialout_connected{target}` already does.
- Removing a cache still soft-resets every RPKI/ASPA-dependent peer once;
  the slice does not promise delta-scoped removal.

### Neutral

- Enabling a subsystem from zero, and the first `loc_rib` collector, stay
  restart-required.
- SIGHUP remains the only path; config transactions keep rejecting these
  sections as unsupported.
