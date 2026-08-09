# Reload Matrix

Reference for every user-facing config key: what does it take to put a
change into effect?

This doc is the operator-facing index. The authoritative classification
lives in the source — `neighbor_runtime_equal()`, `config_field_impact()`,
`neighbor_change_hot_applicable()`, and `ConfigDiff` (in
`src/config/mod.rs`), `reload.rs` (the changed-neighbor hot/rebuild
partition, `pin_unreconciled_daemon_runtime_fields`, and the
per-section error/warn arms) together with the pinning helpers
`pin_tcp_ao_startup_only_runtime` / `pin_bfd_startup_only_runtime` it
invokes from `src/config/mod.rs`, and
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

Several **live** fields bind at session establishment (OPEN negotiation
or socket creation), not mid-session. Examples: `md5_password`,
`families`, `add_path`, `graceful_restart`, `hold_time`, `min_hold_time`. These are not
restart-required, but applying them takes a session reset — and on
SIGHUP reload of a static neighbor the reconciler performs that reset
**immediately**: any changed session-reset-class field routes the
neighbor through the session rebuild path (delete + re-add of the
session task), so the new value is negotiated right away rather than
waiting for a natural flap. The matrix calls this out per row as
"live (effective next session)"; `rustbgpd --diff` annotates these
fields "session reset".

Static-neighbor edits whose **every** changed field is hot-applied
(`description`, `max_prefixes`, `max_prefixes_ipv4`,
`max_prefixes_ipv6`, `max_prefixes_out_ipv4`,
`max_prefixes_out_ipv6`, `max_prefix_restart_seconds`,
`gr_peer_restart_time_max`, `gr_stale_routes_time`,
`local_ipv6_nexthop`, `remove_private_as`, `log_level`, and the
import/export policy and chain fields) are applied **in place**: the
session task, its TCP connection, and the FSM are untouched, and policy
edits trigger the usual Route Refresh / Adj-RIB-Out re-emit. Mixing a
hot-applied edit with a session-reset edit on the same neighbor applies
both through one session rebuild.

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
peer-group RPCs partition a group edit's changed fields by impact class: an
all-`live` change set is applied in place to every inheriting member, static
and dynamic, with no session reset, while a set mixing in any session-reset,
restart-required, or unclassified field reshapes as before. Session-shaping
peer-group edits on those paths still leave dynamic sessions on their running
config until reconnect. Dynamic-range
peer-group reassignments and mixed policy/session effective-impact candidates
remain rejected even though SIGHUP can hot-reconcile some of those shapes
best-effort.
Identical peer-group or peer-group-membership mutations are treated as runtime
no-ops: they return success without publishing a policy event or rebuilding
sessions.

For grouped export-only changes,
[ADR-0105](adr/0105-grouped-export-policy-transition.md) documents the
single-owner transaction, its one-cohort-plus-remainder partition, the
RIB-local atomic commit boundary, and the compensating rollback used across
session and RIB actors.

## `[[neighbors]]`

The diff key is the `(address, interface)` pair. Changing either is
treated as **delete + add** by the reconciler — the old neighbor is torn
down, the new one starts fresh. `remote_asn` is *not* part of the diff
key: an ASN edit flows through reconcile as an immediate session rebuild
under the new ASN (the same delete + re-add semantics, applied in one
reload).

| Field | Class | Notes |
|---|---|---|
| `address` | restart-required (identity) | Part of the diff key. Edit = delete + add. To change the peer address in place, delete the old neighbor (gRPC or remove from config + reload), then add the new one. |
| `interface` | restart-required (identity) | Part of the diff key. Same as `address`. Used by IPv6 link-local + BGP unnumbered peering. |
| `remote_asn` | live (session reset, identity) | Not part of the diff key: on SIGHUP the reconciler rebuilds the session immediately with the new ASN. Equivalent to delete + add of the neighbor — no daemon restart needed. Annotated "session reset: peer re-established with new ASN" by `rustbgpd --diff`. |
| `description` | live | Metadata only; hot-applied in place — session task untouched. |
| `peer_group` | live (session reset) | A reassignment changes the peer's effective inherited config, so SIGHUP reconcile (and the transaction session-reshape executor) rebuild the session. Group *field* edits on an unchanged membership hot-apply per the `[peer_groups.<name>]` table below. |
| `hold_time` | live (effective next session) | Negotiated in OPEN. On SIGHUP the reconciler rebuilds the session immediately, so the new value is negotiated right away. |
| `min_hold_time` | live (effective next session) | Validates the peer's next OPEN proposal. On SIGHUP the reconciler rebuilds the session immediately; existing sessions are not re-evaluated in place. |
| `send_hold_time` | live (effective next session) | RFC 9687 send hold timer. The per-peer writer task captures the value when its TCP connection is established, so a new value (including 0 = disable) guards the next session; the existing session keeps the old timer. |
| `slow_peer_threshold_pct` | live (session reset) | Slow-peer detection backlog threshold, percent of the outbound writer buffer. Captured into the session's transport config; on SIGHUP the reconciler rebuilds the session immediately, so the new value applies right away. Annotated "session reset: session re-establish" by `rustbgpd --diff`. |
| `slow_peer_duration` | live (session reset) | Seconds the backlog must persist before the slow-peer flag raises; 0 disables detection. Same capture and session-rebuild semantics as the threshold. |
| `slow_peer_isolation` | live (session reset) | Move a flagged-slow peer to the per-peer update path. Same capture and session-rebuild semantics as the threshold. |
| `max_prefixes` | live | Threshold re-evaluated on every received UPDATE. |
| `max_prefixes_ipv4` | live | Per-family IPv4-unicast inbound cap (ADR-0108), enforced independently of the aggregate `max_prefixes`. Hot-applied in place; the new threshold governs the next received UPDATE. |
| `max_prefixes_ipv6` | live | IPv6-unicast sibling of `max_prefixes_ipv4` (ADR-0108). |
| `max_prefixes_out_ipv4` | live | RIB-owned outbound capacity (ADR-0113). Applies without touching the session. Adding or lowering is accepted only when the peer currently advertises at or below the candidate: an over-limit family rejects the whole edit (SIGHUP abandons the reload; a config transaction fails its precondition) and leaves the running maxima, admission state, Adj-RIB-Out, and wire state untouched — lowering is not an implicit pruning policy. A valid raise or removal schedules one coalesced, family-scoped resync. Commit-confirmed transactions may only tighten, because their automatic undo only loosens. |
| `max_prefixes_out_ipv6` | live | IPv6-unicast sibling of `max_prefixes_out_ipv4`. |
| `max_prefix_restart_seconds` | live | Manager-owned hold-down policy. A successful value change hot-applies without touching the session and reschedules any armed countdown to now + the new duration (the superseded deadline never fires); removing the value cancels the countdown; a rejected change preserves it untouched. The field does not retroactively arm an indefinitely latched peer. |
| `md5_password` | live (effective next session) | **TCP-MD5 keys are per-socket.** On SIGHUP the reconciler rebuilds the session immediately, so the new key is installed on the rebuilt socket right away. |
| `tcp_ao` | live (ordered rotation generations) / otherwise restart-required | SIGHUP can append non-preferred successor MKTs, then on a later SIGHUP select an already-installed successor as local RNext. Selection is one-shot observed across the affected protected-session cohort; predecessor deprecation metadata commits in that same immutable generation only after verified successor traffic increases beyond each affected socket's baseline. A later SIGHUP may delete only deprecated, unselected MKTs while preserving the exact owner set, survivor order, key definitions, and selected key. Adding and selecting together, setting Current, key edits/reordering, non-deprecated/selected-key deletion, or owner changes are rejected/pinned. Runtime config transactions remain conservatively restart-required because they do not run the SIGHUP coordinator. |
| `bfd` | restart-required | Pinned by `pin_bfd_startup_only_runtime`. The ADR-0067 BFD actor resolves `[[bfd_profiles]]` plus per-neighbor/peer-group `bfd` once at startup. Logged at `ERROR` during reload. |
| `ttl_security` | live (effective next session) | New value passed through reconcile; takes effect on next TCP connect (GTSM is a socket option). |
| `families` | live (effective next session) | Address families to negotiate in OPEN. Negotiated capability set is fixed for the life of a session. |
| `required_families` | live (effective next session) | OPEN-time minimum negotiated family set. Static peers are rebuilt; accepted dynamic sessions keep their running config until reconnect unless a committed config transaction bounces the affected enabled range after persistence. |
| `graceful_restart` | live (effective next session) | GR capability advertised in OPEN. Toggling on an established session has no in-session effect. |
| `gr_restart_time` | live (effective next session) | Advertised in GR capability. |
| `gr_peer_restart_time_max` | live | Local-only cap on the received GR Restart Time. Hot-applied in place; the new value governs the next GR peer-down event and never changes the OPEN capability. |
| `gr_stale_routes_time` | live | Used by the local stale-route reaper for received GR routes. Hot-applied in place; the new value governs the next GR peer-down event. |
| `llgr_stale_time` | live (effective next session) | RFC 9494 LLGR capability stale time. |
| `local_ipv6_nexthop` | live | Used on outbound advertisements; new value applied on next route emission. |
| `route_reflector_client` | live (effective next session) | RFC 4456 RR-client flag affects iBGP best-path + reflection behavior. Toggling re-evaluates the existing Adj-RIB-Out on the next distribution pass. |
| `orr_vantage` | live (effective next session) | RFC 9107 ORR vantage point (the client's IGP location as a BGP-LS topology node). Registered with the RIB manager at session establishment, so a change takes effect on the next session. Currently drives the vantage registry, cached SPF state, and `rbgp orr` status only; the per-vantage best-path selection ships with the ORR distribution switch. |
| `route_server_client` | live (effective next session) | Transparent RS-client behavior on egress. |
| `per_client_best` | live (effective next session) | RFC 7947 §2.3.2 per-client best-path selection mode. Registered with the RIB manager at session establishment (like `orr_vantage`), so a change takes effect on the next session. |
| `next_hop_ownership` | live (effective next session) | ADR-0107 pre-policy `NEXT_HOP` ownership enforcement for route-server clients (RFC 7948 §4.8). Bound at session establishment; on SIGHUP the reconciler rebuilds the session so the new mode applies right away. Annotated "session reset: session re-establish" by `rustbgpd --diff`. |
| `interpret_rfc1997` | live (effective next session) | RFC 1997 `NO_EXPORT` egress enforcement (derived default: `true` unless `route_server_client` is set). Same session-re-establish bucket as `next_hop_ownership`. |
| `rs_control_communities` | live (effective next session) | RFC 7947 §2.3.2 / RFC 8195 route-server control-community enforcement (derived default: `true` when `route_server_client` is set). Same session-re-establish bucket as `next_hop_ownership`. |
| `role` | live (effective next session) | RFC 9234 BGP Role capability — advertised in OPEN. Compatibility check + NOTIFICATION 2/11 enforcement happen at OPEN time, so role changes require a session bounce to renegotiate. The §5 OTC procedures (driven by the local role) re-evaluate against the next received/emitted UPDATE. |
| `strict_role` | live (effective next session) | Strict-mode toggle. Without an OPEN renegotiation, the existing session keeps whatever it negotiated. |
| `prefix_orf_receive` | live (effective next session) | RFC 5291/5292 Address-Prefix ORF receive capability — advertised in OPEN. Like `add_path`/`role`, a toggle is reconciled by the ReconcilePeers delete/re-add path and takes effect on the next session; an established session keeps whatever ORF it negotiated. Reported by `describe_neighbor_changes`; a transaction-model edit is a supported `[[neighbors]] modify`. |
| `disable_ipv4_unicast` | live (effective next session) | IPv6-only peering: drops IPv4 unicast from the advertised MultiProtocol capability and suppresses the RFC 4760 §8 implicit-IPv4 fallback — both OPEN-time properties, so a toggle takes effect on the next session. Rejected at load when the effective `families` resolve to `ipv4_unicast` only. |
| `remove_private_as` | live | Applied to every outbound advertisement; the next distribution pass picks up the new value. |
| `add_path` | live (effective next session) | RFC 7911 Add-Path send/receive modes are negotiated in OPEN. Mid-session changes are no-ops until renegotiation. |
| `log_level` | live | Per-peer tracing filter, re-applied on SIGHUP via the tracing [`reload`](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/reload/index.html) handle: the reload rebuilds the full `EnvFilter` (the `RUST_LOG` base level plus every per-peer directive) and swaps it into the running subscriber, so a level edit takes effect without a restart. The global base level stays restart-required (read once from `RUST_LOG`). |
| `import_policy` | live | Inline import statements; re-evaluated against all received routes on reconcile. When `[global] ebgp_requires_policy` is on, an edit that moves this direction between explicit policy and the ADR-0112 reserved deny is a *policy-presence transition*: every affected peer is qualified for Route Refresh before any peer is modified, and one Established peer without the capability — or one down peer whose GR/LLGR stale routes the RIB still holds — rejects the whole edit with nothing mutated. |
| `export_policy` | live | Inline export statements; re-evaluated against the Adj-RIB-Out on next distribution. |
| `import_policy_chain` | live | Named-chain reference; same re-evaluation behavior, including the policy-presence qualification above. |
| `export_policy_chain` | live | Named-chain reference; same re-evaluation behavior. |

## `[peer_groups.<name>]`

Peer-group fields mirror `[[neighbors]]` minus the identity triple
(`address`, `interface`, `remote_asn`) and TCP-AO. Inheritance is resolved at
each reconcile. Neighbor-level policy fields override inherited peer-group
policy fields. TCP-AO is never inherited: static neighbors and dynamic ranges
configure their keyring directly.

| Field | Class | Notes |
|---|---|---|
| `hold_time` | live (effective next session) | Same as neighbor. |
| `min_hold_time` | live (effective next session) | Same as neighbor; static and dynamic group members are session-reshaped. |
| `send_hold_time` | live (effective next session) | Same as neighbor. |
| `slow_peer_threshold_pct` | live (session reset) | Same as neighbor; a group slow_peer edit is never all-hot, so static members are session-reshaped via the conservative fallback. |
| `slow_peer_duration` | live (session reset) | Same as neighbor; same conservative-reshape fallback as the threshold. |
| `slow_peer_isolation` | live (session reset) | Same as neighbor; same conservative-reshape fallback as the threshold. |
| `max_prefixes` | live | Same as neighbor. |
| `max_prefixes_ipv4` | live | Same as neighbor; per-family ADR-0108 cap inherited by group members. |
| `max_prefixes_ipv6` | live | Same as neighbor. |
| `max_prefixes_out_ipv4` | live | Same maxima semantics as neighbor, evaluated by effective value: one over-limit member — static or accepted dynamic — rejects a group-wide lowering before any sibling changes. An all-`live` group edit swaps the maximum in place on every inheriting member, static and dynamic, without touching a session; a change set that also moves a session-reset field reshapes static members as before. Down children inherit the committed value when they reconnect. |
| `max_prefixes_out_ipv6` | live | IPv6-unicast sibling of `max_prefixes_out_ipv4`. |
| `max_prefix_restart_seconds` | live | Inherited by group members. An all-`live` group edit applies in place to static and dynamic members without bouncing them; a mixed change set reshapes static members and manager-syncs dynamic ones. Committed config transactions also bounce enabled dynamic sessions; disabled dynamic peers retain admin state and adopt the new duration. An armed countdown reschedules to now + the new duration; removing the duration cancels it. |
| `md5_password` | live (effective next session) | Same as neighbor — pinned by group, applied to the inheriting peer's next socket. |
| `bfd` | restart-required | Pinned. |
| `ttl_security` | live (effective next session) | |
| `families` | live (effective next session) | |
| `required_families` | live (static session reset; dynamic next reconnect) | Non-empty neighbor value overrides; empty/absent inherits. A committed config transaction classifies the effective change as `SessionReshape` and bounces affected enabled dynamic ranges after persistence. |
| `graceful_restart` | live (effective next session) | |
| `gr_restart_time` | live (effective next session) | |
| `gr_peer_restart_time_max` | live | Inherited local helper cap. An all-`live` group edit swaps the cap in place on static and dynamic members alike; a change set that also moves a session-reset field rebuilds static members and leaves accepted dynamic members on their running cap until reconnect. A committed config transaction follows the transaction-overlay behavior above and bounces enabled dynamic members. |
| `gr_stale_routes_time` | live | |
| `llgr_stale_time` | live (effective next session) | |
| `local_ipv6_nexthop` | live | |
| `route_reflector_client` | live (effective next session) | |
| `orr_vantage` | live (effective next session) | Inherited RFC 9107 vantage; same semantics as the neighbor field. |
| `route_server_client` | live (effective next session) | |
| `per_client_best` | live (effective next session) | Inherited per-client best-path mode; same semantics as the neighbor field. |
| `next_hop_ownership` | live (effective next session) | Inherited ADR-0107 ownership enforcement; same semantics as the neighbor field. |
| `interpret_rfc1997` | live (effective next session) | Same as neighbor. |
| `rs_control_communities` | live (effective next session) | Same as neighbor. |
| `role` | live (effective next session) | |
| `strict_role` | live (effective next session) | |
| `prefix_orf_receive` | live (effective next session) | Group-level ORF toggle is caught by `diff_peer_groups` (whole-record compare) and named by `describe_peer_group_changes`; effective on the inheriting peer's next session. |
| `disable_ipv4_unicast` | live (effective next session) | Group-level IPv6-only toggle; same OPEN-time semantics as the neighbor field, effective on the inheriting peer's next session. |
| `remove_private_as` | live | |
| `add_path` | live (effective next session) | |
| `log_level` | live | Same as neighbor — inherited per-peer tracing filter, re-applied on SIGHUP via the tracing reload handle. |
| `import_policy` | live | Inline import statements inherited by peers that do not set their own import policy / chain. |
| `export_policy` | live | Inline export statements inherited by peers that do not set their own export policy / chain. |
| `import_policy_chain` | live | Named-chain reference inherited by peers that do not set their own import policy / chain; inheriting peers take the same ADR-0112 policy-presence qualification. |
| `export_policy_chain` | live | Named-chain reference inherited by peers that do not set their own export policy / chain. |

## `[[dynamic_neighbors]]`

Direct TOML edits are **reload-applied**: on SIGHUP the peer manager swaps the
runtime config snapshot and rebuilds the live inbound-accept matcher, so adding,
removing, or editing a `[[dynamic_neighbors]]` block changes which future
inbound connections are accepted without bouncing existing sessions. Runtime
gRPC CRUD — `rbgp dynamic-neighbor {add,delete}`
(`AddDynamicNeighbor` / `DeleteDynamicNeighbor`) — uses the same reload-applied
matcher-update path: it updates the runtime config snapshot and inbound-accept
matcher, then persists the accepted change back to the TOML. Runtime CRUD and
SIGHUP reload share a coordinator lock, held through the persistence
acknowledgement, so reload sees either the pre-mutation TOML or the committed
post-mutation TOML.

The exception is direct `tcp_ao` on a dynamic range. SIGHUP can append a
non-preferred successor to an unchanged protected prefix owner, then select
that installed successor in a later observation-gated immutable generation.
Adding and selecting together, moving, editing, or reordering protected
owners/keys remains restart-required and pinned. Deletion is live only for
deprecated, unselected MKTs in an otherwise identical owner/key order.
Disjoint unprotected range edits can still reload normally.

| Field | Class | Notes |
|---|---|---|
| `prefix` | reload-applied | Consulted on every inbound TCP accept. |
| `peer_group` | reload-applied | Inheritance resolves when a passive session promotes to a managed peer. |
| `remote_asn` | reload-applied | Validated against the OPEN's `my_as` at promotion. |
| `description` | reload-applied | Metadata. |
| `tcp_ao` | live (ordered rotation generations) / otherwise restart-required | Append-only non-preferred successors install on SIGHUP; a later SIGHUP may select an installed successor and observation-gate predecessor deprecation in the same generation; a still-later SIGHUP may delete deprecated, unselected MKTs without changing the owner or survivor order. Protected owner/auth/key-order edits and non-deprecated/selected-key deletion remain pinned. Runtime CRUD/transactions remain restart-required. |

## `[global]`

The `[global]` section is mostly restart-required because its values
feed daemon-wide subsystems (router-id, listen socket, telemetry sinks)
that are stood up once at startup. Two flags are hot-pluggable.

| Field | Class | Notes |
|---|---|---|
| root `config_epoch` | restart-required | ADR-0119 semantic epoch. Omission means epoch 1. A SIGHUP reports and pins raw/effective/source drift with the RFC 8212 boolean tuple. Before secure-default activation, epoch 2 with an omitted boolean is rejected at parse/validation time. |
| `asn` | restart-required | Identity. |
| `router_id` | restart-required | Identity. Advertised in every OPEN. |
| `listen_port` | restart-required | The listen socket is created at startup. |
| `cluster_id` | restart-required | RFC 4456 cluster identity; affects every iBGP advertisement. |
| `honor_graceful_shutdown` | live | Hot-applied by `reload.rs`. Re-evaluates the GShut LOCAL_PREF de-preference against existing Adj-RIB-In on toggle. |
| `honor_blackhole` | live (with FIB-discard caveat) | Hot-applied when `[global] install_blackhole_discard` is false. When the FIB-discard reconciler is configured (`install_blackhole_discard = true` and the FIB table is set up), `honor_blackhole` is **restart-required** — toggling it would change the discard-spawn-gate decision made at startup. Logged as `ERROR` during reload in that case. |
| `ebgp_requires_policy` | restart-required | ADR-0112/0119 RFC 8212 enforcement mode and raw-presence verdict. Pinned with `config_epoch` as one startup tuple: a SIGHUP reports value or representation drift in `--diff` and the v1 transaction rejection, logs an `ERROR`, and keeps the running import/export treatment and source verdict at startup. |
| `install_blackhole_discard` | restart-required | The RFC 7999 kernel-discard reconciler spawns once at startup. |
| `allow_blackhole_broad_prefixes` | restart-required | Same — feeds the discard-spawn gate. |
| `multipath_relax` | restart-required | RIB best-path tie-break behavior; reconciling mid-flight would require an Adj-RIB-Out rebuild. |
| `link_bandwidth_weighted` | restart-required | Weighted-multipath behavior (ADR-0068). |
| `dynamic_neighbor_limit` | restart-required | Pre-allocated cap on dynamic-neighbor slots. SIGHUP pins the runtime snapshot to the startup value while retaining the edited desired value for restart. |
| `worker_threads` | restart-required | Tokio runtime worker-thread count; the runtime is built once at startup. Unset caps to `min(CPU parallelism, 8)`; `RUSTBGPD_WORKER_THREADS` overrides. |
| `warm_cache_checkpoint_on_shutdown` | restart-required | The shutdown checkpoint writer and its pinned runtime-state directory are selected at startup. |
| `runtime_state_dir` | restart-required | File-system paths (`gr-restart.toml`, `fib-owned.json`, `grpc.sock`) are bound at startup. |

`apply_bum_enforcement` is **restart-required** but is a top-level
(document-root) key, **not** a `[global]` key — EVPN BUM-port enforcement is
pinned per ADR-0057.

### `[global.telemetry]`

| Field | Class | Notes |
|---|---|---|
| `prometheus_addr` | restart-required | The exporter listener binds at startup. |
| `log_format` | restart-required | The `tracing` subscriber is initialized at startup. |

### `[global.telemetry.grpc_tcp]` and `[global.telemetry.grpc_uds]`

Pinned by the reload path — both transports stand up once and don't
rebind on reload.

| Field | Class | Notes |
|---|---|---|
| `address` | restart-required | Listener address. |
| credential bytes behind unchanged token/TLS paths | reload-applied | Staged for all listeners, then one atomic generation; existing connections/streams survive. |
| token/TLS paths or auth mode | restart-required | Listener shape and configured paths remain pinned. |
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
| `import_chain` (named) | live | Reorder, add, or remove named imports. Removing the last entry while eBGP peers inherit it is a fleet-wide ADR-0112 policy-presence transition: it is qualified for Route Refresh across every affected peer first, and rejected whole if any peer cannot converge it. |
| `export_chain` (named) | live | Reorder, add, or remove named exports. |
| `rpol_files` | live | SIGHUP recompiles the referenced `.rpol` files and hot-applies materially changed chains to exactly the affected peers (Route Refresh for changed import chains). Config transactions reject a candidate whose compiled `.rpol` registry changed as unsupported — the files live outside the candidate TOML (`src/config/mod.rs`, transaction classification) — so apply `.rpol` changes via SIGHUP. |
| `rpol_roots` | live | Extra `import` resolution roots; a change takes effect through the same SIGHUP recompile path (it matters only when it changes the resolved module graph's content, which reloads as an rpol content change). |
| `rpol_max_graph_bytes` | live | Read from the incoming config on every load (`load_rpol_files` consumes it before compiling each unit), so the value in the reloaded file governs that same SIGHUP's recompile — no restart, no second reload. A candidate/reloaded config whose units exceed its own budget is rejected whole; the running generation is untouched. |
| `[policy.datasets]` | live | Snapshot files are re-read on every SIGHUP: content-equal re-reads are no-ops, changed content swaps atomically and refreshes only the referencing peers, and a file that fails to load keeps the prior snapshot (WARN + `bgp_policy_dataset_refresh_errors_total`). Introducing a dataset declaration (or a kind change) must load cleanly or the reload is rejected. |
| `[policy.explain] enabled` (ADR-0073) | restart-required (per peer) | Read by `build_transport_config` when a session is constructed, so the new value is adopted into the config snapshot (sessions established *after* the reload honour it) but live sessions keep their current import-explain write behaviour until they re-establish. Logged as `WARN` during reload when changed. Diagnostic retention only — never affects which routes are accepted. |
| `[policy.explain] cache_size` (ADR-0073) | restart-required (per peer) | Same — the per-session LRU is sized at session construction. A live session's cache is not resized in place; the new capacity applies on its next establishment. |
| `[policy.reject_retention] enabled` | restart-required (per peer) | Same contract as `[policy.explain]`: read by `build_transport_config` at session construction. Live sessions keep their current rejected-route retention behaviour until they re-establish. Diagnostic retention only — never affects which routes are accepted. |
| `[policy.reject_retention] capacity` | restart-required (per peer) | Same — the per-session rejected-route store is sized at session construction; the new capacity applies on the peer's next establishment. |

## `[rpki]`, `[bmp]`, `[mrt]`

| Section | Class | Notes |
|---|---|---|
| `[rpki]` | restart-required | RPKI VRP tables + cache connections stand up once at startup. |
| `[bmp]` | restart-required | BMP exporter binds once. |
| `[mrt]` | restart-required | MRT writer opens its output dir at startup. |

## `[gnmi_dialout]`

| Section | Class | Notes |
|---|---|---|
| `[gnmi_dialout]` (whole section) | reload-applied | SIGHUP reconciles the dial-out target set in place: removed targets stop (their `gnmi_dialout_connected{target}` series is reaped), added targets start, changed targets tear down and redial, unchanged targets keep their live collector connection. The new section is validated during reload preflight; a rejected config leaves the running targets untouched. TLS key/cert *file contents* rotate without any reload — the files are re-read on every (re)connection attempt. |

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
| `[security.grpc] enforcement` | restart-required | `tier` is the sole typed value, consumed by the gRPC interceptor at server bind time. Retired `legacy` is invalid config and receives migration guidance rather than a runtime class. |
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

## `[inbound_admission]` (ADR-0120)

The per-source accept-rate limiter is built once by the accept-path
owner at startup; hot-applying an aggregation-length or capacity change
would invalidate every live bucket and re-open a fresh burst allowance
for every source. v1 pins every field as restart-required and surfaces
the change as an `ERROR`-level log line during reload, matching the
sibling admission knob `dynamic_neighbor_limit`.

| Field | Class | Notes |
|---|---|---|
| `enabled` | restart-required | Off (default) ⇒ accept behavior unchanged; the limiter is never built. |
| `rate_per_minute` | restart-required | Token-bucket refill rate per source aggregate. |
| `burst` | restart-required | Token-bucket depth per source aggregate. |
| `v4_aggregation_len` | restart-required | IPv4 bucket-key prefix length (8–32). |
| `v6_aggregation_len` | restart-required | IPv6 bucket-key prefix length (16–128); default /64 because per-/128 accounting is trivially evadable. |
| `table_capacity` | restart-required | Fixed LRU tracking-table capacity (64–65536). |

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

# Compare the candidate file against the current on-disk config; print
# expected reload class per change (for a live-daemon comparison use
# `rbgp config diff`)
rustbgpd --diff /tmp/new-config.toml /etc/rustbgpd/config.toml

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
