# Reload Matrix

Reference for every user-facing config key: what does it take to put a
change into effect?

This doc is the operator-facing index. The authoritative classification
lives in the source — `neighbor_runtime_equal()` and `ConfigDiff` (in
`src/config/mod.rs`), `reload.rs` (pinning helpers `pin_tcp_ao_startup_only_runtime`,
`pin_bfd_startup_only_runtime`, and the per-section error/warn arms), and
the parse-time `ConfigError` family in `src/config/validation.rs`. If
the matrix and the code disagree, the code is right and the matrix has a
bug — file an issue.

## Reload classes

| Class | Meaning |
|---|---|
| **live** | Change applies on SIGHUP or a supported runtime CRUD RPC without bouncing the BGP session. The diff routes through `neighbor_runtime_equal()` / `diff_neighbors()` / `diff_policy()` and the daemon reconciles in place. |
| **reload-applied** | Change hot-applies to a running subsystem reconciler or derived matcher on SIGHUP / supported runtime CRUD, but unlike per-session `live` the in-memory config snapshot advances only after the subsystem or snapshot consumer **acks** the new desired set. Used by `[[fib_tables]]` (ADR-0061 FIB reconciler) and `[[dynamic_neighbors]]` matcher rebuilds. Surfaced under the `reload_applied.*` keys in `rustbgpd --diff --json`. |
| **restart-required** | Change is accepted at parse time but **pinned back to the live value** for the duration of this reload — the new value won't take effect until the next daemon restart. Surfaced as an `ERROR`-level log line during reload and visible in `rustbgpd --diff` until restart. |
| **rejected** | Validation refuses the change at parse time with a typed `ConfigError`. The daemon keeps running with the old value; no state mutates. |
| **unsupported** | Field is accepted at parse time but currently has no runtime effect. Documented so operators don't mistake it for live. Future PRs may promote unsupported fields to live; the matrix tracks the current daemon. |
| **validation-only** | Field is validated at parse time (typically as a cross-field constraint marker) and has no runtime effect of its own. |

## Session-establishment caveat

Several **live** fields take effect on the *next session establishment*,
not mid-session. Examples: `md5_password`, `families`, `add_path`,
`graceful_restart`. These are not restart-required (the daemon doesn't
need to restart to pick them up) but they only become observable after
the affected session is bounced — by the peer, by `rbgp neighbor
disable`/`enable`, or by any natural flap. The matrix calls this out per
row.

---

## Transaction overlay

The matrix above describes what SIGHUP reload or targeted runtime CRUD does with
each config field. ADR-0076 config transactions add a stricter overlay:
`PlanConfigTransaction` may reject a SIGHUP-hot-applied change unless the daemon
has a rollback-capable transaction executor for that exact impact shape.

Current transaction support includes pure `[[fib_tables]]`, pure
`[[dynamic_neighbors]]`, static `[[neighbors]]` add/delete/modify, catalog-only
policy / neighbor-set / peer-group / global-chain changes, pure live
policy-chain impact for static neighbors or accepted dynamic peers, and
peer-group/session reshape impact. Reshapes include peer-group field edits or
static-neighbor peer-group reassignments that require affected sessions to be
rebuilt; the transaction executor captures prior static peer configs and
restores them if apply or persistence fails, and after a successful persist it
gracefully resets the live dynamic sessions accepted by an affected range so
they re-accept under the committed config (ADR-0086). SIGHUP and targeted
peer-group RPCs hot-apply policy-only peer-group edits to live dynamic
sessions, but no-preview session-shaping peer-group edits on those paths leave
dynamic sessions on their running config until reconnect. Dynamic-range
peer-group reassignments and mixed policy/session effective-impact candidates
remain rejected even though SIGHUP can hot-reconcile some of those shapes
best-effort.
Identical peer-group or peer-group-membership mutations are treated as runtime
no-ops: they return success without publishing a policy event or rebuilding
sessions.

## `[[neighbors]]`

The diff key is the `(address, interface, remote_asn)` triple. Changing
any of those three is treated as **delete + add** by the reconciler —
the old neighbor is torn down, the new one starts fresh.

| Field | Class | Notes |
|---|---|---|
| `address` | restart-required (identity) | Part of the diff key. Edit = delete + add. To change the peer address in place, delete the old neighbor (gRPC or remove from config + reload), then add the new one. |
| `interface` | restart-required (identity) | Part of the diff key. Same as `address`. Used by IPv6 link-local + BGP unnumbered peering. |
| `remote_asn` | restart-required (identity) | Part of the diff key. Same as `address`. |
| `description` | live | Metadata only; flows through reconcile. |
| `peer_group` | live | Group inheritance resolves at reconcile time; effective fields update in place. |
| `hold_time` | live (effective next session) | New value used in the next OPEN exchange. Existing session keeps the negotiated hold time until renegotiation. |
| `send_hold_time` | live (effective next session) | RFC 9687 send hold timer. The per-peer writer task captures the value when its TCP connection is established, so a new value (including 0 = disable) guards the next session; the existing session keeps the old timer. |
| `max_prefixes` | live | Threshold re-evaluated on every received UPDATE. |
| `md5_password` | live (effective next session) | New password is staged in the transport config; the next active-open socket installs it. **TCP-MD5 keys are per-socket**, so the running session keeps the old key until it bounces. To rotate, change the value and either wait for a natural flap or disable+enable the neighbor. |
| `tcp_ao` | restart-required | Pinned by `pin_tcp_ao_startup_only_runtime`. RFC 5925 MKTs are installed only when the socket is created (active-open) or when the passive listener boots. Add/remove/rotate requires a daemon restart. Logged at `ERROR` during reload. |
| `bfd` | restart-required | Pinned by `pin_bfd_startup_only_runtime`. The ADR-0067 BFD actor resolves `[[bfd_profiles]]` plus per-neighbor/peer-group `bfd` once at startup. Logged at `ERROR` during reload. |
| `ttl_security` | live (effective next session) | New value passed through reconcile; takes effect on next TCP connect (GTSM is a socket option). |
| `families` | live (effective next session) | Address families to negotiate in OPEN. Negotiated capability set is fixed for the life of a session. |
| `graceful_restart` | live (effective next session) | GR capability advertised in OPEN. Toggling on an established session has no in-session effect. |
| `gr_restart_time` | live (effective next session) | Advertised in GR capability. |
| `gr_stale_routes_time` | live | Used by the local stale-route reaper for received GR routes. Re-evaluated against existing stale routes on reconcile. |
| `llgr_stale_time` | live (effective next session) | RFC 9494 LLGR capability stale time. |
| `local_ipv6_nexthop` | live | Used on outbound advertisements; new value applied on next route emission. |
| `route_reflector_client` | live (effective next session) | RFC 4456 RR-client flag affects iBGP best-path + reflection behavior. Toggling re-evaluates the existing Adj-RIB-Out on the next distribution pass. |
| `orr_vantage` | live (effective next session) | RFC 9107 ORR vantage point (the client's IGP location as a BGP-LS topology node). Registered with the RIB manager at session establishment, so a change takes effect on the next session. Currently drives the vantage registry, cached SPF state, and `rbgp orr` status only; the per-vantage best-path selection ships with the ORR distribution switch. |
| `route_server_client` | live (effective next session) | Transparent RS-client behavior on egress. |
| `per_client_best` | live (effective next session) | RFC 7947 §2.3.2 per-client best-path selection mode. Registered with the RIB manager at session establishment (like `orr_vantage`), so a change takes effect on the next session. |
| `role` | live (effective next session) | RFC 9234 BGP Role capability — advertised in OPEN. Compatibility check + NOTIFICATION 2/11 enforcement happen at OPEN time, so role changes require a session bounce to renegotiate. The §5 OTC procedures (driven by the local role) re-evaluate against the next received/emitted UPDATE. |
| `strict_role` | live (effective next session) | Strict-mode toggle. Without an OPEN renegotiation, the existing session keeps whatever it negotiated. |
| `prefix_orf_receive` | live (effective next session) | RFC 5291/5292 Address-Prefix ORF receive capability — advertised in OPEN. Like `add_path`/`role`, a toggle is reconciled by the ReconcilePeers delete/re-add path and takes effect on the next session; an established session keeps whatever ORF it negotiated. Reported by `describe_neighbor_changes`; a transaction-model edit is a supported `[[neighbors]] modify`. |
| `disable_ipv4_unicast` | live (effective next session) | IPv6-only peering: drops IPv4 unicast from the advertised MultiProtocol capability and suppresses the RFC 4760 §8 implicit-IPv4 fallback — both OPEN-time properties, so a toggle takes effect on the next session. Rejected at load when the effective `families` resolve to `ipv4_unicast` only. |
| `remove_private_as` | live | Applied to every outbound advertisement; the next distribution pass picks up the new value. |
| `add_path` | live (effective next session) | RFC 7911 Add-Path send/receive modes are negotiated in OPEN. Mid-session changes are no-ops until renegotiation. |
| `log_level` | live | Per-peer tracing filter; takes effect on next log emission. |
| `import_policy` | live | Inline import statements; re-evaluated against all received routes on reconcile. |
| `export_policy` | live | Inline export statements; re-evaluated against the Adj-RIB-Out on next distribution. |
| `import_policy_chain` | live | Named-chain reference; same re-evaluation behavior. |
| `export_policy_chain` | live | Named-chain reference; same re-evaluation behavior. |

## `[peer_groups.<name>]`

Peer-group fields mirror `[[neighbors]]` minus the identity triple
(`address`, `interface`, `remote_asn`) and TCP-AO. Inheritance is resolved at
each reconcile. Neighbor-level policy fields override inherited peer-group
policy fields. TCP-AO remains a static-neighbor-only field because
dynamic-neighbor TCP-AO needs a separate wildcard-MKT design.

| Field | Class | Notes |
|---|---|---|
| `hold_time` | live (effective next session) | Same as neighbor. |
| `send_hold_time` | live (effective next session) | Same as neighbor. |
| `max_prefixes` | live | Same as neighbor. |
| `md5_password` | live (effective next session) | Same as neighbor — pinned by group, applied to the inheriting peer's next socket. |
| `bfd` | restart-required | Pinned. |
| `ttl_security` | live (effective next session) | |
| `families` | live (effective next session) | |
| `graceful_restart` | live (effective next session) | |
| `gr_restart_time` | live (effective next session) | |
| `gr_stale_routes_time` | live | |
| `llgr_stale_time` | live (effective next session) | |
| `local_ipv6_nexthop` | live | |
| `route_reflector_client` | live (effective next session) | |
| `orr_vantage` | live (effective next session) | Inherited RFC 9107 vantage; same semantics as the neighbor field. |
| `route_server_client` | live (effective next session) | |
| `per_client_best` | live (effective next session) | Inherited per-client best-path mode; same semantics as the neighbor field. |
| `role` | live (effective next session) | |
| `strict_role` | live (effective next session) | |
| `prefix_orf_receive` | live (effective next session) | Group-level ORF toggle is caught by `diff_peer_groups` (whole-record compare) and named by `describe_peer_group_changes`; effective on the inheriting peer's next session. |
| `disable_ipv4_unicast` | live (effective next session) | Group-level IPv6-only toggle; same OPEN-time semantics as the neighbor field, effective on the inheriting peer's next session. |
| `remove_private_as` | live | |
| `add_path` | live (effective next session) | |
| `log_level` | live | |
| `import_policy` | live | Inline import statements inherited by peers that do not set their own import policy / chain. |
| `export_policy` | live | Inline export statements inherited by peers that do not set their own export policy / chain. |
| `import_policy_chain` | live | Named-chain reference inherited by peers that do not set their own import policy / chain. |
| `export_policy_chain` | live | Named-chain reference inherited by peers that do not set their own export policy / chain. |

## `[[dynamic_neighbors]]`

Direct TOML edits are **reload-applied**: on SIGHUP the peer manager swaps the
runtime config snapshot and rebuilds the live inbound-accept matcher, so adding,
removing, or editing a `[[dynamic_neighbors]]` block changes which future
inbound connections are accepted without bouncing existing sessions. Runtime
gRPC CRUD — `rbgp dynamic-neighbor {add,delete}`
(`AddDynamicNeighbor` / `DeleteDynamicNeighbor`) — uses the same reload-applied
matcher-update path: it updates the runtime config snapshot and inbound-accept
matcher, then persists the accepted change back to the TOML when the daemon was
started with `--config`. Runtime CRUD and SIGHUP reload share a coordinator
lock, held through the persistence acknowledgement, so reload sees either the
pre-mutation TOML or the committed post-mutation TOML.

| Field | Class | Notes |
|---|---|---|
| `prefix` | reload-applied | Consulted on every inbound TCP accept. |
| `peer_group` | reload-applied | Inheritance resolves when a passive session promotes to a managed peer. |
| `remote_asn` | reload-applied | Validated against the OPEN's `my_as` at promotion. |
| `description` | reload-applied | Metadata. |

## `[global]`

The `[global]` section is mostly restart-required because its values
feed daemon-wide subsystems (router-id, listen socket, telemetry sinks)
that are stood up once at startup. Two flags are hot-pluggable.

| Field | Class | Notes |
|---|---|---|
| `asn` | restart-required | Identity. |
| `router_id` | restart-required | Identity. Advertised in every OPEN. |
| `listen_port` | restart-required | The listen socket is created at startup. |
| `cluster_id` | restart-required | RFC 4456 cluster identity; affects every iBGP advertisement. |
| `honor_graceful_shutdown` | live | Hot-applied by `reload.rs`. Re-evaluates the GShut LOCAL_PREF de-preference against existing Adj-RIB-In on toggle. |
| `honor_blackhole` | live (with FIB-discard caveat) | Hot-applied when `[global] install_blackhole_discard` is false. When the FIB-discard reconciler is configured (`install_blackhole_discard = true` and the FIB table is set up), `honor_blackhole` is **restart-required** — toggling it would change the discard-spawn-gate decision made at startup. Logged as `ERROR` during reload in that case. |
| `install_blackhole_discard` | restart-required | The RFC 7999 kernel-discard reconciler spawns once at startup. |
| `allow_blackhole_broad_prefixes` | restart-required | Same — feeds the discard-spawn gate. |
| `apply_bum_enforcement` | restart-required | EVPN BUM-port enforcement is pinned per ADR-0058. |
| `multipath_relax` | restart-required | RIB best-path tie-break behavior; reconciling mid-flight would require an Adj-RIB-Out rebuild. |
| `link_bandwidth_weighted` | restart-required | Weighted-multipath behavior (ADR-0068). |
| `dynamic_neighbor_limit` | restart-required | Pre-allocated cap on dynamic-neighbor slots. |
| `worker_threads` | restart-required | Tokio runtime worker-thread count; the runtime is built once at startup. Unset caps to `min(CPU parallelism, 8)`; `RUSTBGPD_WORKER_THREADS` overrides. |
| `runtime_state_dir` | restart-required | File-system paths (`gr-restart.toml`, `fib-owned.json`, `grpc.sock`) are bound at startup. |

### `[global.telemetry]`

| Field | Class | Notes |
|---|---|---|
| `prometheus_addr` | restart-required | The exporter listener binds at startup. |
| `log_format` | restart-required | The `tracing` subscriber is initialized at startup. |
| `looking_glass.*` | restart-required | Bound to the gRPC server set up at startup. |

### `[global.telemetry.grpc_tcp]` and `[global.telemetry.grpc_uds]`

Pinned by the reload path — both transports stand up once and don't
rebind on reload.

| Field | Class | Notes |
|---|---|---|
| `address` | restart-required | Listener address. |
| `tls.*` (mTLS material) | restart-required | All TLS/mTLS fields pinned. |
| `path` (`grpc_uds`) | restart-required | UDS path bound at startup. |
| `mode` (`grpc_uds`) | restart-required | Permissions set at bind time. |

## `[policy]`

The `[policy]` section is the one part of the config that supports
genuinely structural hot-reload — named definitions, neighbor-sets, and
chains all add/change/remove cleanly via reload.

| Field | Class | Notes |
|---|---|---|
| `definitions` (named) | live | Add/remove/edit named policy definitions; re-evaluated on the next distribution pass. |
| `neighbor_sets` (named) | live | Add/remove/edit named neighbor sets; the resolved set drives per-peer chain bindings. |
| `import_chain` (named) | live | Reorder, add, or remove named imports. |
| `export_chain` (named) | live | Reorder, add, or remove named exports. |
| `[policy.import]` (inline, top-level) | validation-only | Parsed for backward compatibility but **does not hot-apply**. Logged as `WARN` during reload when changed: "evaluated at session start and requires a full restart to apply. Migrate to named definitions plus import_chain/export_chain for hot-reload support." |
| `[policy.export]` (inline, top-level) | validation-only | Same. |
| `[policy.explain] enabled` (ADR-0073) | restart-required (per peer) | Read by `build_transport_config` when a session is constructed, so the new value is adopted into the config snapshot (sessions established *after* the reload honour it) but live sessions keep their current import-explain write behaviour until they re-establish. Logged as `WARN` during reload when changed. Diagnostic retention only — never affects which routes are accepted. |
| `[policy.explain] cache_size` (ADR-0073) | restart-required (per peer) | Same — the per-session LRU is sized at session construction. A live session's cache is not resized in place; the new capacity applies on its next establishment. |

## `[rpki]`, `[bmp]`, `[mrt]`

| Section | Class | Notes |
|---|---|---|
| `[rpki]` | restart-required | RPKI VRP tables + cache connections stand up once at startup. |
| `[bmp]` | restart-required | BMP exporter binds once. |
| `[mrt]` | restart-required | MRT writer opens its output dir at startup. |

## `[[evpn_instances]]`, `[[evpn_ip_vrfs]]`, `[[ethernet_segments]]`

SIGHUP reuses the ADR-0063 EVPN runtime coordinator for the same supported
live shapes as `EvpnService.ApplyEvpnRuntime`: single L2VNI/IP-VRF/ES
add/delete/redefine within the documented identity bounds, atomic tenant
teardown, `ip_vrf` relink, additive build-up, and standalone L2VNI swaps that
only combine L2VNI adds with standalone L2VNI deletes, plus L2VNI-only batch
redefines that do not relink IP-VRF membership. Mixed edits beyond those
shapes now hot-apply through the **#268 plan decomposer**: the candidate is
split into an ordered sequence of already-supported primitive plans (deletes
→ redefines → `ip_vrf` relink → adds), each committing **its own runtime
generation** — one SIGHUP produces N generations in `rbgp`/gRPC runtime
snapshots and logs, one per step. Every step is validated up front, before
anything commits; a candidate with an unsupported step (an IP-VRF
L3VNI/device/table identity redefine, or a shape the fixed phase order
cannot express — relink away from an IP-VRF deleted in the same candidate,
relink onto an IP-VRF added in the same candidate, an ES left memberless
mid-sequence) fails closed naming the offending step. A residual
mid-sequence convergence failure is fail-stop: generations committed by
earlier steps stay committed (no cross-step rollback), the model pins, and a
re-SIGHUP after fixing the config converges only the remainder. The runtime
snapshot advances only after the coordinator and daemon actor converger
accept the candidate. Unsupported shapes, missing EVPN actors, or actor
convergence failure are pinned back to the committed runtime model and
logged at `ERROR`, so repeated SIGHUPs keep surfacing the drift. Static
`rustbgpd --diff` is shape-aware: it lists coordinator-supported EVPN edits
under reload-applied — a decomposable mixed edit shows as "hot-applied
through the ADR-0063 coordinator (decomposed: N steps, one runtime
generation each)" — and keeps undecomposable mixed edits or restart-only
identity changes in restart-required. The static diff still cannot predict
live actor availability or a later convergence failure; those remain runtime
SIGHUP outcomes.

| Section | Class | Notes |
|---|---|---|
| `[[evpn_instances]]` | coordinator-gated | Supported ADR-0063 L2VNI shapes hot-apply, including standalone L2VNI swaps and L2VNI-only batch redefines; mixed edits decompose into ordered primitive steps (#268), one committed generation per step; undecomposable shapes, missing actors, or convergence failure pin/log. |
| `[[evpn_ip_vrfs]]` | coordinator-gated | Supported IP-VRF add/delete/redefine and `ip_vrf` relink hot-apply, including decomposed mixed edits (#268); L3VNI/device/table identity changes stay restart-required by design — kernel VRF identity lifecycle (destroy + recreate); a runtime drain/recreate risks a dual-state window (see the ADR-0063 amendment). |
| `[[ethernet_segments]]` | coordinator-gated | Supported ES add/delete/redefine and atomic tenant teardown hot-apply when the segment actor can converge; mixed edits decompose (#268) with ES redefines applied one segment per generation. |
| `[managed_netdevs]` | restart-required | ADR-0091 bridge, fixed-VNI VXLAN, SVD / collect-metadata VXLAN, VLAN upper, VRF, and L3VXLAN lifecycle is resolved at startup and reconciled by the dataplane actor (create, stamp, restart adoption, same-owner orphan reap). Managed netdevs are not live-mutable in this tranche. |

## `[[fib_tables]]` and FIB runtime

| Section | Class | Notes |
|---|---|---|
| `[[fib_tables]]` | reload-applied | Hot-applies to the running ADR-0061 FIB reconciler on SIGHUP (add/remove a table; change `allowed_neighbors` / `allowed_peer_groups` / `max_routes` / ECMP caps / `families`). Snapshot advances only after the actor acks. Starting FIB from an empty config (reconciler not spawned) still requires a restart. |
| `[global] install_blackhole_discard` (FIB-side) | restart-required | See `[global]` above. |

## `[[bfd_profiles]]`

| Section | Class | Notes |
|---|---|---|
| `[[bfd_profiles]]` | restart-required | Pinned alongside per-neighbor/peer-group `bfd`. The ADR-0067 BFD actor resolves the profile set once. |

## `[security.grpc.*]`

| Field | Class | Notes |
|---|---|---|
| `[security.grpc] enforcement` | restart-required | `tier` vs `legacy` mode, consumed by the gRPC interceptor at server bind time. |
| `[security.grpc.roles]` | restart-required | Principal → role (`observer` / `automation` / `operator`) map read at bind. The per-method tier matrix is compiled into `crates/api/src/authz.rs` and is not runtime-configurable. |

## `[event_history]` (ADR-0072)

The durable event-history outbox is configured once at startup and
its lifecycle (open / quarantine / diagnostic sidecar) is fixed for the
process. Hot-reload of the outbox config is a P1 nice-to-have;
v1 pins every field as restart-required and surfaces the change as
an `ERROR`-level log line during reload so operators see exactly
what's deferred.

| Field | Class | Notes |
|---|---|---|
| `enabled` | restart-required | Off ⇒ EHM does not open `events.db`; live event broadcast paths remain possible, but no durable outbox/replay state is created. (See ADR-0072 for the pass-through contract on `required = false` recovery failures, which is a runtime degraded state distinct from `enabled = false`.) |
| `required` | restart-required | If `true`, the daemon fails to start when the events DB cannot be opened or recovered. Default `false`: degrade to pass-through with `bgp_event_outbox_degraded = 1`. |
| `path` | restart-required | Relative to `runtime_state_dir`. Empty ⇒ `<runtime_state_dir>/events.db`. |
| `max_events` | restart-required | Hard count cap; default 100,000. Retention sweeps every 60s evict oldest `event_id` first. |
| `max_bytes` | restart-required | Byte retention target on `events.db` + WAL combined; default 256 MB. SQLite may reuse freed pages rather than shrink the main DB immediately, so this is not a strict filesystem cap in v1. |
| `synchronous` | restart-required | SQLite `PRAGMA synchronous` mode. `full` (default) fsyncs per commit; `normal` checkpoints periodically and trades a small crash window for throughput. |
| `overflow` | restart-required | v1 only supports `drop`; `block` is reserved for a future ADR. |
| `queue_capacity` | restart-required | Per-producer mpsc capacity. |
| `batch_size` | restart-required | Batch-commit size threshold. |
| `batch_interval_ms` | restart-required | Batch-commit time threshold. |

## Rejected configurations (parse-time)

These are the `ConfigError` variants in `src/config/validation.rs` that
refuse a config outright. The daemon either fails to start (initial
load) or rejects the reload and keeps running on the previous config
(SIGHUP).

| Validation rule | Trigger | Notes |
|---|---|---|
| `strict_role` requires `role` | `[[neighbors]] strict_role = true` without `role` | RFC 9234 requires Roles to be configured before strict mode is meaningful. |
| `disable_ipv4_unicast` requires a non-IPv4-unicast family | `[[neighbors]] disable_ipv4_unicast = true` with effective `families` resolving to `ipv4_unicast` only | The combination is contradictory: the session could never negotiate any family. |
| `role` requires eBGP | `[[neighbors]] role = "..."` on an iBGP session (`remote_asn == global.asn`) | RFC 9234 §4 scopes Roles to eBGP. |
| `tcp_ao` mandatory fields | Missing `key`, `send_id`, `recv_id`, or `algorithm` | TCP-AO MKT is incomplete. |
| `bfd.profile` references unknown profile | The `[[bfd_profiles]]` entry referenced by `[[neighbors]] bfd.profile` doesn't exist | |
| iBGP-only fields on eBGP (or vice versa) | `route_reflector_client = true` on eBGP, etc. | |
| Cross-section reference integrity | `peer_group` references a missing `[[peer_groups]]` entry, `import_policy_chain` references a missing `[policy] import_chain` name, etc. | |
| TOML schema (`#[serde(deny_unknown_fields)]`) | Any misspelled or extraneous field | Catches typos before the daemon sees them. |

## Validation-only constraints

These are checked at parse time but don't drive any runtime behavior of
their own — they exist to keep the schema honest.

| Constraint | What it enforces |
|---|---|
| Cross-section reservation | E.g. static `[[neighbors]]` cannot set `remote_asn = 0`; that sentinel is reserved for `[[dynamic_neighbors]]` accept-any matching. Flagged at parse, no runtime effect of its own. |
| Address-family well-formedness | `families = ["ipv4_unicast"]` accepted; misspellings rejected at parse, used at session-establishment. |

## How to verify a reload before applying

```sh
# Parse + validate, do not apply
rustbgpd --check /etc/rustbgpd/config.toml

# Compute the diff against the running daemon's view; print expected
# reload class per change
rustbgpd --diff /etc/rustbgpd/config.toml

# Apply via SIGHUP
systemctl reload rustbgpd
# …or
kill -HUP $(pidof rustbgpd)
```

`rustbgpd --diff` calls into the same `ConfigDiff` machinery the
reload path uses; what it reports is what reload will do.

## Related

- [`docs/CONFIGURATION.md`](CONFIGURATION.md) — field-by-field config reference.
- [`docs/OPERATIONS.md`](OPERATIONS.md) — operator runbook (startup, SIGHUP, upgrade).
- [`docs/adr/0061-opt-in-unicast-linux-fib-integration.md`](adr/0061-opt-in-unicast-linux-fib-integration.md) — FIB-discard reconciler scope.
- [`docs/adr/0067-bfd-single-hop.md`](adr/0067-bfd-single-hop.md) — BFD startup-only runtime.
- [`docs/adr/0071-bgp-roles-otc.md`](adr/0071-bgp-roles-otc.md) — RFC 9234 roles + OTC reload semantics.
