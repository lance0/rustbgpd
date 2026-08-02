# gRPC API Reference

rustbgpd exposes eleven native `rustbgpd.v1` gRPC services (Global, Config,
Neighbor, Policy, PeerGroup, Rib, BFD, Event, Injection, Control, Evpn) plus the
`gnmi.gNMI` OpenConfig service over one or more configured listeners. The
gNMI surface is read-only telemetry (`Capabilities` / `Get` / `Subscribe`) plus an
operator-tier `Set` subset — transaction-backed create/update/delete for static
numbered BGP neighbors, peer-group catalog entries, dynamic-neighbor prefixes,
and the commit-confirmed extension through ADR-0076. Unsupported `Set` paths
return `UNIMPLEMENTED`. The default listener is a local Unix domain socket at
`/var/lib/rustbgpd/grpc.sock`.

For same-host administration, prefer UDS:

```bash
grpcurl -plaintext -unix /var/lib/rustbgpd/grpc.sock \
  -import-path . -proto proto/rustbgpd.proto \
  rustbgpd.v1.GlobalService/GetGlobal
```

The remaining examples below use
[grpcurl](https://github.com/fullstorydev/grpcurl) against an explicit local
TCP listener for readability. Those examples require `grpc_tcp` to be enabled:

```toml
[global.telemetry.grpc_tcp]
address = "127.0.0.1:50051"
```

The proto definition lives at `proto/rustbgpd.proto`.

The project-wide API remains alpha outside the explicit native-gRPC methods
listed in the narrow [v1 route-server / route-reflector contract](v1-stable-contract.md).
That machine inventory pins method names, streaming modes, and top-level
request/response messages; a service or RPC existing in this reference does
not by itself make it v1-stable.

## Service overview

| Service | RPCs | Purpose |
|---------|------|---------|
| `GlobalService` | `GetGlobal` | Daemon identity |
| `ConfigService` | `DiffRuntimeConfig`, `PlanConfigTransaction`, `ApplyConfigTransaction`, `ConfirmConfigTransaction`, `AbortConfigTransaction`, `GetConfigTransactionStatus`, `GetEffectiveConfig`, `ListConfigHistory`, `RollbackConfigTransaction` | Candidate-vs-live config diff, effective running config with defaults materialized and secrets redacted, plus the v1 config-transaction lifecycle: validate/plan, commit/apply (incl. commit-confirmed), confirm, abort, status, and the bounded recorded config history with Junos-style `rollback N` through the same transaction executor |
| `NeighborService` | `AddNeighbor`, `DeleteNeighbor`, `ListNeighbors`, `GetNeighborState`, `EnableNeighbor`, `DisableNeighbor`, `SoftResetIn`, `RefreshOutbound`, `SetGracefulShutdown`, `AddDynamicNeighbor`, `DeleteDynamicNeighbor`, `ListDynamicNeighbors` | Peer lifecycle, inbound soft reset, single-peer outbound re-advertisement, RFC 8326 graceful-shutdown toggle, and dynamic-neighbor CRUD — `AddDynamicNeighbor` / `DeleteDynamicNeighbor` add and remove `[[dynamic_neighbors]]` prefix ranges at runtime (queued to the config file), `ListDynamicNeighbors` for visibility |
| `PolicyService` | `ListPolicies`, `GetPolicy`, `SetPolicy`, `DeletePolicy`, `ListNeighborSets`, `GetNeighborSet`, `SetNeighborSet`, `DeleteNeighborSet`, `GetGlobalPolicyChains`, `GetNeighborPolicyChains`, `SetGlobalImportChain`, `SetGlobalExportChain`, `ClearGlobalImportChain`, `ClearGlobalExportChain`, `SetNeighborImportChain`, `SetNeighborExportChain`, `ClearNeighborImportChain`, `ClearNeighborExportChain`, `ExplainImportPolicy`, `ListRejectedRoutes`, `TestPolicy`, `GetPolicyStats` | Named policy CRUD, neighbor sets, global/per-neighbor chain attachment, import-policy decision explain (per-term traces for `.rpol` members), retained rejected-route views with reject reasons, read-only candidate-policy dry runs over the live RIB, and live per-term hit counters |
| `PeerGroupService` | `ListPeerGroups`, `GetPeerGroup`, `SetPeerGroup`, `DeletePeerGroup`, `SetNeighborPeerGroup`, `ClearNeighborPeerGroup` | Peer-group CRUD and neighbor membership assignment |
| `RibService` | `ListReceivedRoutes`, `ListBestRoutes`, `ListAdvertisedRoutes`, `ExplainAdvertisedRoute`, `ExplainBestPath`, `ListFlowSpecRoutes`, `ListEvpnRoutes`, `ListBgpLsRoutes`, `ListTopologyNodes`, `ListTopologyLinks`, `ListOrrStatus`, `ListVpnRoutes`, `ListRtcRoutes`, `ListLabeledRoutes`, `ListBlackholeDiscards`, `ListFibRoutes`, `ListFibTables`, `SetFibTable`, `DeleteFibTable`, `ListRouteEvents`, `WatchRoutes`, `WatchRouteEvents` | RIB queries (incl. EVPN, BGP-LS, VPNv4/v6, RT-Constrain, and labeled-unicast), the RFC 9107 ORR / BGP-LS topology read surface (`ListTopologyNodes` / `ListTopologyLinks` / `ListOrrStatus`), BLACKHOLE discard status, paginated FIB status, runtime FIB-table CRUD, explain, recent route-event history with per-prefix drilldown, and streaming |
| `BfdService` | `GetBfdSessions` | Single-hop BFD session inspection for configured static neighbors |
| `EventService` | `WatchEvents`, `SubscribeFromEvent`, `ListEvpnEvents`, `ListSessionEvents`, `ListPolicyEvents` | Unified live stream for route, session lifecycle, BGP NOTIFICATION metadata, policy mutation, EVPN route events, BFD session events, and FIB / BLACKHOLE dataplane status-row summary events, with `stream_lagged` warnings for bounded-source backpressure; durable cursor replay via `SubscribeFromEvent` when `[event_history].enabled = true`; plus bounded after-the-fact EVPN, session-lifecycle, and policy-mutation history. Per-MAC EVPN dataplane categories remain follow-up work |
| `InjectionService` | `AddPath`, `DeletePath`, `AddFlowSpec`, `DeleteFlowSpec`, `AddEvpnRoute`, `DeleteEvpnRoute` | Programmatic route, FlowSpec, and EVPN injection |
| `ControlService` | `GetHealth`, `GetMetrics`, `Shutdown`, `TriggerMrtDump` | Health, metrics, lifecycle, MRT dumps |
| `EvpnService` | `GetEvpnRuntime`, `ListEvpnInstances`, `ListEvpnNexthops`, `ListEthernetSegments`, `ListIpVrfs`, `ListManagedNetdevs`, `GetIpVrf`, `ClearDuplicateMacQuarantine`, `SetEthernetSegmentDrain`, `ApplyEvpnRuntime` | Local EVPN VTEP instance state, ADR-0059 FDB-nexthop ownership, ADR-0083/0085 Ethernet Segment multi-homing diagnose state, symmetric IRB (Type-5 / L3VNI) IP-VRF readiness / route counters, ADR-0091 managed-netdev lifecycle/status, duplicate-MAC quarantine clear, ADR-0084 Ethernet Segment drain for access-circuit maintenance, and ADR-0063 runtime model status / apply |
| `gnmi.gNMI` | `Capabilities`, `Get`, `Set`, `Subscribe` | OpenConfig BGP telemetry subset (`Get` / `Subscribe`) plus a transaction-backed `Set` subset (static numbered-neighbor create/update/delete + commit-confirmed via ADR-0076; unsupported paths `UNIMPLEMENTED`); served on UDS and mTLS TCP listeners |

## Authentication and TLS

The daemon supports three deployment patterns for the gRPC surface:

| Pattern | Config | Auth |
|---------|--------|------|
| Unix domain socket | `[global.telemetry.grpc_uds]` with `path` + `mode` | File-system permissions on the socket path |
| Plaintext TCP + bearer token | `[global.telemetry.grpc_tcp]` with `address` and optional `token_file` | Bearer token in the `authorization: bearer <value>` metadata header (when `token_file` is set) |
| **mTLS TCP** | `[global.telemetry.grpc_tcp]` with `tls_cert_file` + `tls_key_file` + `tls_client_ca_file` | Client certificate signed by the configured CA |

The mTLS path is the recommended default for any non-loopback gRPC
listener. All three TLS fields are required together; partial
configuration is rejected at `Config::load`. There is no
"TLS-without-mTLS" half-mode by design — when TLS is enabled the
daemon presents the server certificate, requires every client to
present a certificate signed by `tls_client_ca_file`, and rejects
unverified clients at the TLS layer before any gRPC handler runs.

PEM material is pre-flight-validated at config load and `--check`
time, so a successful `--check` rules out cert-rotation surprises
at startup. Valid credential bytes behind unchanged TLS paths rotate on SIGHUP.
Adding or removing TLS, changing a configured TLS path, or changing TLS/auth
mode remains **restart-required**; runtime config pins that drift to the live
values until the daemon is restarted.

Native gNMI is available on the local UDS listener and on TCP listeners only
when mTLS is configured. Plaintext or bearer-token-only TCP listeners serve the
native `rustbgpd.v1` API but do not register `gnmi.gNMI`. See
[GNMI.md](GNMI.md) for the operator-facing OpenConfig path list and `gnmic`
examples.

```bash
# mTLS client example with grpcurl
grpcurl \
  -cacert /etc/rustbgpd/server-ca.pem \
  -cert /etc/operator/client.pem -key /etc/operator/client.key \
  -import-path . -proto proto/rustbgpd.proto \
  rustbgpd.example.net:50051 \
  rustbgpd.v1.GlobalService/GetGlobal
```

```bash
# mTLS gNMI client example with gnmic
gnmic \
  --address rustbgpd.example.net:50051 \
  --tls-ca /etc/rustbgpd/server-ca.pem \
  --tls-cert /etc/operator/client.pem \
  --tls-key /etc/operator/client.key \
  --tls-server-name rustbgpd.example.net \
  capabilities
```

Per-listener `access_mode = "read_only"` rejects mutating RPCs
(neighbor add/delete, route injection, policy changes, peer-group
changes, shutdown, MRT trigger) with `PERMISSION_DENIED`. Use this
on a dedicated monitoring listener that exposes the read surface
without the mutating control plane.

Each configured listener can independently set `access_mode = "read_write"` or
`"read_only"`. Read-only listeners allow query and watch RPCs but reject all
mutating RPCs with `PERMISSION_DENIED`.

### Listener Access Matrix

`read_only` is a listener-level authorization boundary. It does not create
per-user roles: every client accepted by that listener gets the same read-only
surface. Use a separate `read_write` listener for automation that needs to
mutate daemon state.

`docs/grpc-method-inventory.md`, `docs/grpc-method-inventory.json`, and
`crates/api/src/authz.rs` classify every RPC into `read`, `sensitive_read`,
`mutating`, or `operator_only` for ADR-0064. The JSON file is the
machine-readable export for auditors and generated clients; the Rust `authz`
tests verify it against the source-of-truth matrix. The runtime records tier
decisions for every RPC via structured `grpc_authz` logs and
`bgp_grpc_authz_decisions_total{tier,result,authn,access_mode}`. Listener
`max_tier` caps are enforced in all modes. When
`[security.grpc].enforcement = "tier"` is enabled, the same runtime layer also
enforces the authenticated principal's configured role ceiling before the
handler runs; `"tier"` is the default since v0.24.0, and `"legacy"` is the
supported opt-out.
Forwarded calls emit result-aware labels such as `result="handler_ok"` or
`result="handler_invalid_argument"` after the handler returns. Rejected calls use
bounded pre-handler labels: `result="listener_tier_denied"` means the method was
rejected before the handler ran, and `result="authn_failed"` means an over-cap
bearer-token request failed authentication before tier details were disclosed.
Tier-mode denials use `result="principal_unmapped"` when the authenticated
principal has no role entry and `result="role_tier_denied"` when the principal's
role is below the method tier.
Credential-bearing request summaries are masked before entering `grpc_authz`
logs; `DiffRuntimeConfigRequest.candidate_toml`,
`PlanConfigTransactionRequest.candidate_toml`, and
`ApplyConfigTransactionRequest.candidate_toml` are always summarized as
redacted metadata, transaction apply comments are not logged verbatim, and
`SetPeerGroup` logs MD5 state without the MD5 value.
Operators can now predeclare `[security.grpc.roles]` and set explicit
listener `principal` labels for bearer-token TCP and UDS listeners. In legacy
mode those labels improve audit identity only; in tier mode they are the
principal strings looked up in `[security.grpc.roles]`.
Native mTLS listeners derive the audit principal from the client certificate
using ADR-0064 precedence: `rustbgpd:` URI SAN, then email SAN, then Subject
CN. A validated cert without those fields falls back to `mtls-unresolved` while
legacy mode remains active. Extracted principal values must fit the bounded
audit label form and must not contain embedded control characters; unsupported
values also fall back to `mtls-unresolved`.

Tier enforcement is the default since v0.24.0. When upgrading from an older
release (or from `enforcement = "legacy"`), stage `[security.grpc.roles]` plus
explicit listener principals, validate the candidate config with
`rustbgpd --check`, then move to `enforcement = "tier"` (or rely on the
default). The implicit default UDS listener is safe for local access under
legacy mode, but tier mode requires an explicit
`[global.telemetry.grpc_uds]` block with `principal` so requests can be mapped
to a role.
[`docs/SECURITY.md`](SECURITY.md) covers deployment hardening for this surface,
and [ADR-0064](adr/0064-grpc-authorization.md) records the tier model itself and
which of its slices remain open.
Operational collection, retention, query examples, and resource-abuse guardrails
for `grpc_authz` logs and the related Prometheus metrics live in
[`docs/OPERATIONS.md`](OPERATIONS.md#grpc-authorization-audit-and-resource-guardrails).

| Service | Read-only RPCs | Mutating RPCs rejected on `read_only` |
|---------|----------------|---------------------------------------|
| `GlobalService` | `GetGlobal` | — |
| `ConfigService` | `DiffRuntimeConfig`, `PlanConfigTransaction`, `GetConfigTransactionStatus`, `GetEffectiveConfig`, `ListConfigHistory` | `ApplyConfigTransaction` (pure `[[fib_tables]]`, pure `[[dynamic_neighbors]]`, static `[[neighbors]]` add/delete/modify, catalog-only policy/neighbor-set/peer-group/global-chain changes, pure live policy-chain impact for static neighbors and accepted dynamic peers, or peer-group/session reshape impact for static members and live dynamic sessions; mixed or unsupported candidates rejected without mutation), `ConfirmConfigTransaction`, `AbortConfigTransaction`, `RollbackConfigTransaction` |
| `NeighborService` | `ListNeighbors`, `GetNeighborState`, `ListDynamicNeighbors` | `AddNeighbor`, `DeleteNeighbor`, `EnableNeighbor`, `DisableNeighbor`, `SoftResetIn`, `RefreshOutbound`, `AddDynamicNeighbor`, `DeleteDynamicNeighbor`, `SetGracefulShutdown` |
| `PolicyService` | `ListPolicies`, `GetPolicy`, `ListNeighborSets`, `GetNeighborSet`, `GetGlobalPolicyChains`, `GetNeighborPolicyChains`, `ExplainImportPolicy`, `ListRejectedRoutes`, `TestPolicy`, `GetPolicyStats` | `SetPolicy`, `DeletePolicy`, `SetNeighborSet`, `DeleteNeighborSet`, `SetGlobalImportChain`, `SetGlobalExportChain`, `ClearGlobalImportChain`, `ClearGlobalExportChain`, `SetNeighborImportChain`, `SetNeighborExportChain`, `ClearNeighborImportChain`, `ClearNeighborExportChain` |
| `PeerGroupService` | `ListPeerGroups`, `GetPeerGroup` | `SetPeerGroup`, `DeletePeerGroup`, `SetNeighborPeerGroup`, `ClearNeighborPeerGroup` |
| `RibService` | All read/list/explain RPCs (incl. `ListFibTables`) | `SetFibTable`, `DeleteFibTable` |
| `EventService` | All RPCs | None |
| `EvpnService` | `GetEvpnRuntime`, `ListEvpnInstances`, `ListEvpnNexthops`, `ListEthernetSegments`, `ListIpVrfs`, `ListManagedNetdevs`, `GetIpVrf` | `ClearDuplicateMacQuarantine`, `SetEthernetSegmentDrain`, `ApplyEvpnRuntime` |
| `BfdService` | `GetBfdSessions` | None |
| `gnmi.gNMI` | `Capabilities`, `Get`, `Subscribe` | `Set` (operator-only; transaction-backed OpenConfig subset — static numbered-neighbor `neighbor-address`/`peer-as`/`description`/`peer-group` create/update/delete, peer-group catalog entries, dynamic-neighbor prefixes, and the commit-confirmed extension via ADR-0076; unsupported paths return `UNIMPLEMENTED`) |
| `InjectionService` | None | `AddPath`, `DeletePath`, `AddFlowSpec`, `DeleteFlowSpec`, `AddEvpnRoute`, `DeleteEvpnRoute` |
| `ControlService` | `GetHealth`, `GetMetrics` | `Shutdown`, `TriggerMrtDump` |

## Error Taxonomy

The API uses gRPC status codes consistently across services:

| Code | Meaning |
|------|---------|
| `UNAUTHENTICATED` | Listener authentication failed: missing bearer token, non-ASCII authorization metadata, or a token mismatch |
| `PERMISSION_DENIED` | The request reached a read-only listener but called a mutating RPC, the RPC method tier exceeds the listener `max_tier` ceiling, the principal is unmapped in tier mode, or the principal's role is below the method tier |
| `INVALID_ARGUMENT` | Client-supplied request data is malformed, missing, out of range, uses an unsupported enum value, or combines incompatible filters |
| `NOT_FOUND` | A named or targeted resource does not exist: peer, policy, neighbor set, peer group, IP-VRF, route-event target, or injected route |
| `ALREADY_EXISTS` | A create request targets an existing resource, such as duplicate neighbor creation or an exact-duplicate dynamic-neighbor range |
| `FAILED_PRECONDITION` | The request is valid but the daemon is not in a state where it can complete it, such as MRT export being disabled or a policy object still being referenced |
| `DEADLINE_EXCEEDED` | A bounded actor or session read did not complete before its operation deadline; this does not mean the targeted runtime state is absent |
| `UNAVAILABLE` | A required actor or session task exited, or a required actor, command channel, or persistence queue is unavailable, closed, or back-pressured |
| `UNIMPLEMENTED` | The RPC is reserved in the protobuf but runtime support has not shipped yet |
| `INTERNAL` | An internal daemon actor, metrics encoder, or RIB boundary failed unexpectedly after the request passed validation |

---

## gnmi.gNMI

OpenConfig BGP telemetry surface (ADR-0070). The supported subset is
deliberately narrow: `Capabilities`, `Get`, and `Subscribe` (`ONCE`, `POLL`,
`STREAM SAMPLE`, and `STREAM ON_CHANGE` — the last is scoped to the neighbor
session-state leaf, requires `[event_history]` enabled, and returns
`FAILED_PRECONDITION` otherwise) for global and neighbor `state` under the
default network instance. `Set` is operator-only and supports the first durable
config subset: static, numbered BGP neighbor create/update/delete for
`neighbor-address`, `peer-as`, `description`, and `peer-group`, peer-group
catalog entries, and dynamic-neighbor prefixes, plus graceful-restart config
leaves. Supported Set edits are
translated into full candidate TOML and fed through `PlanConfigTransaction` /
`ApplyConfigTransaction`; the standard gNMI commit-confirmed extension maps to
the same confirm / abort lifecycle as native config transactions. Unsupported
paths return `UNIMPLEMENTED` instead of bypassing the transaction model. See
[GNMI.md](GNMI.md) for the full `ON_CHANGE` v1 scope (initial sync,
reconnect-no-replay, lag → `DATA_LOSS`) and Set path matrix.

Network gNMI is served only on mTLS TCP listeners. The UDS listener also exposes
the service as a local-only extension.

For the full supported path list, setup guidance, troubleshooting table, and
tested `gnmic` commands, see [GNMI.md](GNMI.md).

```bash
gnmic \
  --address rustbgpd.example.net:50051 \
  --tls-ca /etc/rustbgpd/server-ca.pem \
  --tls-cert /etc/operator/client.pem \
  --tls-key /etc/operator/client.key \
  --tls-server-name rustbgpd.example.net \
  get \
  --encoding json_ietf \
  --type STATE \
  --path '/network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp/global/state'
```

---

## GlobalService

Daemon identity and configuration.

| RPC | Description |
|-----|-------------|
| `GetGlobal` | Returns ASN, router ID, listen port, and host TCP-AO capability probe status |

```bash
# Get daemon identity
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.GlobalService/GetGlobal
```

`tcp_ao_support` is a read-only Linux capability probe for RFC 5925 TCP-AO. It
reports whether the host kernel accepts the TCP-AO socket primitive that
rustbgpd uses for static-neighbor and dynamic-prefix startup key installation.
If a `tcp_ao` key is configured on a host where the primitive fails,
listener setup aborts startup, and active-open setup rejects that connect
attempt without falling back to unauthenticated TCP. Dynamic-range keys are
config-file-only: runtime range CRUD rejects protected ranges and overlaps.
SIGHUP can append a non-preferred successor generation; selection,
deprecation, deletion, and protected-owner CRUD are not exposed.

`NeighborState.authentication` reports the effective protected transport as
`PLAINTEXT`, `MD5`, or `TCP_AO`. For direct dynamic-prefix TCP-AO sessions,
that identity comes from the validated accepted socket rather than a synthesized
per-neighbor key configuration. When socket inspection succeeds for a connected
TCP-AO session, `NeighborState.tcp_ao` contains current/RNext KeyIDs,
Linux verification/error counters, and an ordered `keys` inventory. Each key
row is deliberately redacted: it contains only peer/prefix, directional IDs,
algorithm, current/RNext and local rollover flags, optional Linux VRF
L3-master ifindex, and per-key counters. The VRF ifindex is not an IPv6
link-local scope ID; absence means the MKT is VRF-unbound, not default-VRF
bound. The inventory never contains key material, key length, a hash, or a
fingerprint. The daemon
refreshes `TCP_AO_INFO` and `TCP_AO_GET_KEYS` from the live socket for each
neighbor state query, publishes them only as one internally consistent result,
and clears it on disconnect or inspection failure; it never serves an older healthy snapshot as
a fallback. The counters are cumulative for the lifetime of that TCP socket,
so any non-zero error counter keeps the socket `DEGRADED` until reconnect.
`NeighborState.tcp_ao_health` is `NOT_APPLICABLE` for plaintext and MD5 peers,
`UNAVAILABLE` when TCP-AO protects the session but there is no socket snapshot
(including disconnect, inspection failure, or persistent INFO/inventory
inconsistency), `HEALTHY` when the published snapshot has both current/RNext
key-validity flags mapped to a nonempty, internally consistent live inventory,
neither active key is deprecated, and no error counters, and `DEGRADED` when
either key-validity flag is absent, an active key is deprecated, or any bad,
key-not-found, unsigned-required, or dropped-ICMP counter is non-zero. An
inconsistent INFO/inventory pair is never published as degraded state.

For TCP-AO peers, `NeighborState.tcp_ao_desired_generation`,
`tcp_ao_applied_generation`, `tcp_ao_rotation_phase`, and
`tcp_ao_rotation_error` expose the secret-free ordered-rotation state. A phase
of `add_only_failed` retains the prior selectable keys and is retryable with
another SIGHUP. During `add_only`, protected accepts may carry either the
globally applied generation or the exactly proved desired generation. During
`add_only_failed`, only the applied generation may enter the peer manager;
fully installed but uncommitted children remain fail-closed. A partial listener
mutation may reject affected passive accepts until retry or restart.
During `selecting` and `awaiting_peer`, the applied or exactly adjacent desired
generation may enter; `selection_failed` admits only the applied generation.
`awaiting_peer` is a one-shot result, not actor polling: the next identical
SIGHUP re-observes the same generation. Selection sets only local RNext, never
Linux Current, and predecessor deprecation metadata commits only after the
whole affected session cohort has observed verified successor traffic beyond its
per-socket pre-selection baseline.
During `deleting`, the applied or exactly adjacent desired generation may
enter; a desired-generation accept is projected from the coordinator's retained
immutable survivor inventory. `delete_failed` admits only the applied
generation. Deletion removes only deprecated MKTs that are neither Current nor
RNext; an ambiguous partial session mutation discards the complete changed
cohort before the failure is exposed.

`NeighborState.effective_distribution_mode` reports the live RIB selection
surface. When multiple mechanisms apply, its primary-label precedence is
`ADD_PATH` > `PER_CLIENT_BEST` > `ORR` > `SINGLE_BEST`. It is `UNKNOWN` when the
peer has no active outbound registration; `UNSPECIFIED` remains the
backward-compatible value returned by older servers. This field is independent
of the diagnostic `update_group` label. A peer eligible for both per-client-best
and ORR reports `PER_CLIENT_BEST` because it is the primary label; that value
does not mean its configured ORR vantage is inactive.

`NeighborState.selection_deferral` is empty on a cold start. During a planned,
marker-backed RFC 4724 restart it reports one row per frozen address-family
gate: whether the gate is active, this peer's waiter state and stamped session,
the process-wide blocking-waiter count, and remaining time. Released rows are
retained for the daemon lifetime with reason `all_eor`, `all_excluded`, or
`timer`, so an operator can distinguish complete convergence from timer-driven
release.

`NeighborState.paths_limits` is sorted by numeric AFI then SAFI. Legacy field
`effective_send_max` retains raw semantics (`UINT32_MAX` unlimited, zero
inactive). Optional `effective_send_limit` is the normalized view: presence
means active, with zero unlimited and non-zero finite; absence means inactive.
New clients fall back to the legacy field when reading an older server.

`NeighborState.slow_peer` is `true` while the peer is flagged slow: the
session is Established and alive but its outbound queue has stayed above
the configured backlog threshold for the configured duration
(`slow_peer_threshold_pct` / `slow_peer_duration` in the neighbor
config). It clears when the queue drains and on session teardown, and
mirrors the `bgp_peer_slow{peer}` gauge. See the "Slow peers" section
in `OPERATIONS.md` for interpretation.

`NeighborState.negotiation_available` and `negotiated_session` expose the
actor-authoritative capability outcome of the current Established session:
hold time, remote router ID, four-octet AS, negotiated families,
graceful-restart coverage, the peer's Route Refresh / Enhanced Route
Refresh / Extended Message capabilities, and the resulting outbound
message-size ceiling. Presence of `negotiation_available` distinguishes an
older daemon that does not expose negotiation state from a current daemon
reporting no Established session; `negotiated_session` is absent while the
session is down, during OpenConfirm, or when the actor query is stale. The
scalars inside it are optional so genuinely negotiated false/zero values
stay distinct from fields an older daemon never sent during a rolling
upgrade.

`NeighborState.rfc8212_import_policy` and `rfc8212_export_policy` report
the RFC 8212 explicit-policy status of each direction (ADR-0112); a
one-sided configuration is never collapsed into a single "policy present"
answer. `PRESENT` means enforcement applies and explicit operator policy is
installed. `MISSING` means enforcement applies and the reserved internal
deny is installed on that direction of this peer — no route crosses it, in
any negotiated family. `NOT_REQUIRED` covers process-wide disabled
enforcement and iBGP sessions. Clients must render `UNSPECIFIED` (a daemon
that predates the field) and any unrecognized future value as "unknown",
never as `NOT_REQUIRED`.

`NeighborState.outbound_prefix_limits` reports ADR-0113 outbound unicast
capacity, one `OutboundPrefixLimitState` per family: the `family` name
(`ipv4_unicast` / `ipv6_unicast`), `usage` — distinct prefixes currently
admitted into this peer's advertised state, post-policy, post-OTC, and
post-exact-export, agreeing with advertised-route queries and never the
shared update-group table's count — the optional configured `limit`
(absence means unlimited, never zero), the saturating `headroom` (absent
while the family is unlimited), a `blocking` flag for an open blocking
episode, and the stable `reason` `outbound_prefix_limit_reached` while
blocking. The list is empty from a daemon that does not expose it and from
a peer with no outbound registration; a registered peer always reports
both unicast families.

`NeighborState.effective_posture` is a read-only snapshot of the resolved
running neighbor posture: NEXT_HOP ownership enforcement, RFC 1997
interpretation, route-server control-community handling, and the optional ORR
vantage. The containing message is always present from a current daemon, so
explicit `false` remains distinguishable from an older daemon that omitted the
field. Clients must render an absent message, `UNSPECIFIED`, and unrecognized
future ownership modes as unknown rather than disabled.

---

## ConfigService

Live runtime config diagnostics and transaction planning. Diff / plan
callers submit candidate TOML and receive only redacted diff / plan
output; `GetEffectiveConfig` is the one deliberate full-document export
— it returns the effective running config as normalized TOML with
defaults materialized and secret material replaced with `<redacted>`
before it leaves the daemon (`rbgp config effective`).

| RPC | Description |
|-----|-------------|
| `DiffRuntimeConfig` | Validate candidate TOML and compare it against the daemon's live runtime config snapshot |
| `PlanConfigTransaction` | Validate candidate TOML, return a runtime snapshot token, and classify v1 transaction support without mutating daemon state |
| `ApplyConfigTransaction` | Operator-tier commit entry point for ADR-0076 config transactions; currently commits one pure runtime family at a time: full-set `[[fib_tables]]`, full-set `[[dynamic_neighbors]]`, static `[[neighbors]]` add/delete/modify changes, catalog-only policy/neighbor-set/peer-group/global-chain changes, pure live policy-chain impact for static neighbors and accepted dynamic peers, or peer-group/session reshape impact for static members with post-persist best-effort reset of live dynamic sessions |
| `ConfirmConfigTransaction` | Confirm a pending confirmed transaction before its timer expires |
| `AbortConfigTransaction` | Abort a pending confirmed transaction and roll back immediately |
| `GetConfigTransactionStatus` | Return redacted confirmed-transaction lifecycle state |
| `GetEffectiveConfig` | Return the effective running config as normalized TOML — defaults materialized, secrets redacted (`rbgp config effective`) |
| `ListConfigHistory` | List the bounded on-disk recorded config history — newest recorded config at index 0, then older entries; per-entry timestamp, SHA-256, one-line summary; never config documents (`rbgp config history`) |
| `RollbackConfigTransaction` | Restore a retained recorded config snapshot through the same transaction executor as apply — same plan/impact classification, receipts, and optional confirmed-commit window (`rbgp config rollback N`) |

Config-history payloads and their SHA-256 values cover normalized TOML only.
Index 0 means newest recorded, not necessarily the running or currently
persisted config. Referenced external `.rpol` main/import sources and policy
dataset contents are not archived or hashed; rollback re-reads their current
filesystem contents and can therefore produce different policy or fail
validation if those inputs changed or disappeared.

`DiffRuntimeConfigResponse` contains boolean summary fields, a
plain-text `human_text` rendering, and `diff_json` using the
`rustbgpd --diff --json` schema. Secret-bearing fields such as
neighbor `md5_password` and `tcp_ao.key` material are redacted in renderings.
The corresponding `grpc_authz` request summaries never log `candidate_toml`
content; they record only redacted metadata such as request body size and token
presence.

`ConfigTransactionPlanResponse` wraps the same redacted diff with:

- `runtime_snapshot_token`: an optimistic-concurrency token for the live runtime
  snapshot used during planning. It is an opaque, process-local change detector,
  not a cryptographic commitment or authorization credential; re-plan after a
  daemon restart.
- `supported_sections`: sections the v1 transaction model can commit
  (`[[fib_tables]]`, `[[dynamic_neighbors]]`, static neighbor add/delete/modify,
  catalog-only `[policy]` / `[peer_groups]` changes with no effective impact on
  static neighbors or dynamic ranges, pure live policy-chain impact for
  static neighbors or accepted dynamic peers, and peer-group/session
  reshape impact — static members and live dynamic sessions).
- `unsupported_sections`: hot-reloadable sections v1 refuses until an atomic
  executor exists. Mixed policy/session effective impact and dynamic-range
  peer-group reassignments continue to report
  `effective neighbor inheritance impact`.
- `restart_required_sections`: sections that still require daemon restart.

`redacted_diff.reload_applied.effective_neighbor_impact[]` includes a
machine-readable `kind`: `policy_chain` for a pure resolved import/export chain
move that the live-policy executor can commit, or `session_reshape` when
inherited peer-group/session state changes — committed by the session reshape
executor (static members reconfigured in place; live dynamic sessions
gracefully reset post-persist).

The planner is intentionally stricter than SIGHUP: "reload-applied" does not
mean "transaction-committable" unless the section appears in
`supported_sections`. `ApplyConfigTransaction` commits one pure runtime family
at a time. Cross-family candidates, mixed policy/session effective impacts,
and other valid-but-unsupported sections return `REJECTED` without mutation
until their section executor lands.

Native apply and rollback reject any supported family that would stage and
adopt the full candidate snapshot when either side references external
`.rpol` main/import files or `[policy.datasets]` snapshots. Those bytes are not
covered by the transaction token and cannot be rolled back atomically with the
TOML. Deploy the TOML, `.rpol` graph, and dataset snapshots together, then send
SIGHUP. A true no-op remains `NOOP`; a pure `[[fib_tables]]` transaction with
unchanged external inputs remains committable because that executor substitutes
only the targeted table set rather than adopting the full candidate config.
`diff_json.reload_applied.datasets_changed` reports dataset binding/path edits.

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d @ localhost:50051 rustbgpd.v1.ConfigService/DiffRuntimeConfig <<'JSON'
{
  "candidate_toml": "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\nlisten_port = 179\n\n[global.telemetry]\nlog_format = \"json\"\n"
}
JSON
```

Plan a transaction without mutation:

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d @ localhost:50051 rustbgpd.v1.ConfigService/PlanConfigTransaction <<'JSON'
{
  "candidate_toml": "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\nlisten_port = 179\n\n[[fib_tables]]\nname = \"edge\"\ntable_id = 1000\nmetric = 200\n"
}
JSON
```

Use the returned `runtime_snapshot_token` on the apply request. The daemon
re-plans under the shared runtime-config coordinator before committing; a stale
token fails without mutation. `client_request_id` and `comment` are audit
metadata only and are not logged verbatim.
To use a commit-confirmed workflow, include `confirm_id` on
`ApplyConfigTransaction`; `confirm_timeout_seconds` defaults to 600 when omitted
and is capped at 86400. While a confirmed transaction is applying or awaiting
confirmation, other persisted runtime config mutators fail with
`FAILED_PRECONDITION`. Call `ConfirmConfigTransaction` with the same
`confirm_id` to make the change permanent, or `AbortConfigTransaction` to roll
back immediately. If the timer expires first, the daemon re-applies the
pre-commit runtime snapshot through the same transaction executor and persists
the rollback. The confirm window is durable. Before commit, the daemon journals the
pre-commit config to `<runtime_state_dir>/commit-confirm-journal.json`; a
restart that finds an unconfirmed journal reverts at boot before adopting the
on-disk config, saves the unconfirmed candidate as `<config>.unconfirmed`, and
fails closed on torn, unusable, or unremovable journal state. `GetConfigTransactionStatus`
reports the current pending transaction or the last terminal lifecycle result.
A failed abort/auto-revert rollback is not terminal: the transaction stays
pending with an `ABORT_FAILED`/`AUTO_REVERT_FAILED` status and the mutation
fence stays closed until the abort is retried successfully, the candidate is
confirmed, or a restart boot-reverts from the retained journal.

`GetConfigTransactionStatus` (and the apply response) carries a
`ConfigTransactionConfirmation`:

| Field | Type | Meaning |
|-------|------|---------|
| `status` | `ConfigTransactionConfirmationStatus` | Lifecycle state (see below). |
| `confirm_id` | string | The operator-supplied handle for the transaction. |
| `timeout_seconds` | uint32 | Effective confirm timeout applied (echoed). |
| `deadline_unix_seconds` | uint64 | Absolute auto-revert deadline; `0` when not pending. |
| `committed_sections` | repeated string | Sections the confirmed apply committed. |
| `runtime_snapshot_token` | string | Post-commit token for the pending change. |
| `human_text` | string | Redacted human-readable summary. |

`ConfigTransactionConfirmationStatus` values:

| Value | Meaning |
|-------|---------|
| `..._UNSPECIFIED` | Default zero value; not emitted in normal responses. |
| `..._NONE` | No confirmed transaction is currently tracked. |
| `..._PENDING` | Applied and awaiting confirmation before the timer expires. |
| `..._CONFIRMED` | Made permanent by `ConfirmConfigTransaction`. |
| `..._ABORTED` | Rolled back by `AbortConfigTransaction`. |
| `..._AUTO_REVERTED` | Timer expired; the pre-commit snapshot was re-applied. |
| `..._AUTO_REVERT_FAILED` | Timer expired but the rollback re-apply failed; manual correction required. |
| `..._ABORT_FAILED` | Abort requested but the rollback re-apply failed; manual correction required. |

(Each value is prefixed `CONFIG_TRANSACTION_CONFIRMATION_STATUS_` in the proto.)
Confirmed lifecycle transitions are also exposed through the bounded Prometheus
counter `bgp_config_transaction_lifecycle_total{operation, outcome}`:
`operation` is `confirm`, `abort`, or `auto_revert`; `outcome` is `success` or
`failure`. The metric deliberately does not include `confirm_id`, candidate
TOML, peer labels, or error strings.

Apply a pure full-set `[[fib_tables]]` transaction:

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d @ localhost:50051 rustbgpd.v1.ConfigService/ApplyConfigTransaction <<'JSON'
{
  "candidate_toml": "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\nlisten_port = 179\n\n[[fib_tables]]\nname = \"edge\"\ntable_id = 1000\nmetric = 200\n",
  "expected_runtime_snapshot_token": "kv1:...",
  "client_request_id": "deploy-2026-06-03-001",
  "comment": "roll edge FIB table definition"
}
JSON
```

Apply a pure static-neighbor modify transaction:

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d @ localhost:50051 rustbgpd.v1.ConfigService/ApplyConfigTransaction <<'JSON'
{
  "candidate_toml": "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\nlisten_port = 179\n\n[[neighbors]]\naddress = \"192.0.2.10\"\nremote_asn = 65010\nhold_time = 45\n",
  "expected_runtime_snapshot_token": "kv1:...",
  "client_request_id": "deploy-2026-06-03-002",
  "comment": "adjust neighbor hold timer"
}
JSON
```

Apply a transaction with a confirm timer:

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d @ localhost:50051 rustbgpd.v1.ConfigService/ApplyConfigTransaction <<'JSON'
{
  "candidate_toml": "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\nlisten_port = 179\n\n[[neighbors]]\naddress = \"192.0.2.10\"\nremote_asn = 65010\nhold_time = 45\n",
  "expected_runtime_snapshot_token": "kv1:...",
  "client_request_id": "deploy-2026-06-03-003",
  "comment": "safe neighbor timer deploy",
  "confirm_id": "deploy-2026-06-03-003",
  "confirm_timeout_seconds": 120
}
JSON
```

Inspect and confirm the pending transaction:

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{}' localhost:50051 rustbgpd.v1.ConfigService/GetConfigTransactionStatus

grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"confirm_id":"deploy-2026-06-03-003"}' \
  localhost:50051 rustbgpd.v1.ConfigService/ConfirmConfigTransaction
```

Abort instead of waiting for the timer:

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"confirm_id":"deploy-2026-06-03-003"}' \
  localhost:50051 rustbgpd.v1.ConfigService/AbortConfigTransaction
```

The transaction executors share the same coordinator and persistence ordering
as the targeted runtime CRUD paths: re-plan under the runtime snapshot token,
stage the live config snapshot, apply the live runtime change, persist the
exact accepted candidate with an acknowledgement, roll back on failure, and
only then release the coordinator lock. FIB transactions still require the FIB
reconciler to already be running, so adding the first `[[fib_tables]]` entry to
a daemon that started without any tables requires a restart.

Dynamic-neighbor transactions replace the complete `[[dynamic_neighbors]]` set
from the candidate TOML. Static-neighbor transactions support add/delete/modify:
modifies use the same delete/re-add session-reconfigure semantics as SIGHUP,
then roll back on apply or persistence failure.

Catalog-only transactions can stage named policy definitions, policy
`neighbor_sets`, peer groups, and global named policy-chain assignments before a
static neighbor or dynamic range depends on them. They are full-snapshot commits:
the daemon updates the live runtime config snapshot and persists the accepted
TOML, but does not run `SetPolicy` / `SetPeerGroup` live mutation commands.

Policy/neighbor-set/peer-group/global-chain transactions that move an existing
static neighbor's or accepted dynamic peer's resolved import/export
`PolicyChain` are also committable when the impact is purely a chain move. The
executor stages the snapshot, re-applies the resolved chains to affected live
sessions, captures prior chains for rollback, persists with an acknowledgement,
and restores both live policy chains and the snapshot on failure. Dynamic peers
are selected by the canonical `[[dynamic_neighbors]]` range that accepted them,
not by a public API field. Re-evaluating already-received routes under a new
import chain requires Route Refresh, so every impacted Established peer must
have negotiated the Route Refresh capability; otherwise the apply is rejected
and rolled back without committing the candidate.

Peer-group/session reshape transactions commit peer-group field edits or
static-neighbor peer-group reassignments that rebuild existing sessions. The
executor stages the snapshot, reconfigures affected static peers with the same
delete/re-add semantics as SIGHUP, captures prior peer configs for rollback,
persists with an acknowledgement, and restores both live peers and the snapshot
on failure. Live dynamic sessions accepted by an affected
`[[dynamic_neighbors]]` range cannot be delete/re-added (they exist only
because the remote dialed in), so after a successful persist the executor
gracefully resets them with a Cease NOTIFICATION carrying an RFC 8203 shutdown
communication; each remote's reconnect is re-accepted under the committed
config, and the `dynamic_neighbor_limit` slot accounting stays owned by the
normal session-idle reaping. The dynamic reset is post-persist and best-effort
by contract: a failed transaction never flaps a dynamic peer, and a session
that could not be signaled keeps its running config until it reconnects
(reported in the apply response, never silently swallowed). Reassigning a
range to a different peer group remains a `[[dynamic_neighbors]]` record edit
outside the reshape family (ADR-0086).

CLI equivalent:

```bash
rbgp config diff /tmp/new-config.toml
rbgp --json config diff /tmp/new-config.toml
rbgp config plan /tmp/new-config.toml
rbgp config apply /tmp/new-config.toml \
  --expected-runtime-snapshot-token kv1:...
rbgp config apply /tmp/new-config.toml \
  --expected-runtime-snapshot-token kv1:... \
  --client-request-id deploy-2026-06-03-003 \
  --confirm-id deploy-2026-06-03-003 \
  --confirm-timeout 120
rbgp config status
rbgp config confirm deploy-2026-06-03-003
rbgp config abort deploy-2026-06-03-003
```

---

## NeighborService

Peer lifecycle management. Supports static peers from config and dynamic peers
added at runtime.

| RPC | Description |
|-----|-------------|
| `AddNeighbor` | Add a peer dynamically through the legacy or presence-aware carrier (starts session immediately); waits for the atomic config-file update and leaves no runtime change on persistence failure |
| `DeleteNeighbor` | Remove a peer and tear down its session; waits for the atomic config-file update and rolls runtime back on persistence failure |
| `ListNeighbors` | List all peers with session state and counters |
| `GetNeighborState` | Get detailed state for a single peer |
| `EnableNeighbor` | Re-enable a previously disabled peer |
| `DisableNeighbor` | Administratively disable a peer (sends NOTIFICATION) |
| `SoftResetIn` | Request inbound route refresh (RFC 2918/7313) for one or more families |
| `RefreshOutbound` | Re-emit one peer's current exportable outbound inventory across all negotiated families, without resetting the session |
| `AddDynamicNeighbor` | Add a `[[dynamic_neighbors]]` prefix range at runtime; persists the accepted change atomically before returning and rolls back runtime on persistence failure |
| `DeleteDynamicNeighbor` | Remove a dynamic-neighbor range at runtime (stops future accepts; established peers drain on Idle); waits for the atomic config-file update and rolls runtime back on persistence failure |
| `ListDynamicNeighbors` | List configured dynamic-neighbor ranges (prefix, peer group, remote ASN, description) |
| `SetGracefulShutdown` | RFC 8326 initiator toggle — attach the `GRACEFUL_SHUTDOWN` community to outbound updates for one peer (or all peers when `address` is empty) and clear with `clear = true` |

`ListNeighbors` and `GetNeighborState` set `is_dynamic` and, for a dynamic
peer, include `accepted_dynamic_range` with the canonical prefix and peer group
captured when the connection was accepted. This is session provenance, not a
query against the current matcher: deleting or editing that range does not
rewrite the answer for an already-live session. The nested message is absent
for static peers and from older daemons.

### Add a neighbor

`AddNeighborRequest.config` remains the legacy field 1 payload. The additive
`intent` wrapper is field 2 and carries an inner `NeighborConfig` plus a
required `google.protobuf.FieldMask override_mask`. A current server requires
exactly one carrier. Both, neither, a missing inner config, or a missing mask
returns `INVALID_ARGUMENT` before persistence or runtime mutation. An old
server skips wrapper field 2 and rejects the request because legacy field 1 is
absent; clients must not retry or send both.

The bundled `rbgp neighbor add` command always sends `intent` only, with a
present mask even when no overrides are selected. It never sends both carriers
or retries legacy config. An old server's exact `config is required` response
becomes `daemon does not support presence-aware neighbor creation; upgrade
rustbgpd before adding this neighbor`; other errors remain unchanged.

The create override mask has a closed top-level path set:
`families`, `required_families`, `route_server_client`, `per_client_best`,
`strict_role`, `add_path_receive`, `add_path_send`, `add_path_send_max`, and
`paths_limit_receive_max`. Wildcards, nested, duplicate, unknown, or partial
Add-Path paths are rejected. The four Add-Path paths are one atomic block.
Masked booleans preserve explicit `false`; masked family lists replace
inherited lists and must be non-empty. Values outside the mask must retain
their protobuf defaults.

CLI positive/negative pairs are mutually exclusive:
`--[no-]route-server-client`, `--[no-]per-client-best`, and
`--[no-]strict-role`. Any Add-Path option selects the quartet; explicit numeric
zero remains an override, and `--no-add-path` emits the all-disabled tuple.
Effective inherited prerequisites are validated by the server.

Unmasked fields stay absent in the persisted neighbor and inherit through the
normal config resolver. This includes peer-group TTL security, Graceful
Restart, route-reflector mode, prefix ORF, IPv6-only behavior, policies, and
the complete Add-Path block. With no group and no family override, IPv4
neighbors resolve to IPv4 unicast while IPv6 neighbors resolve to IPv4 and
IPv6 unicast. The legacy carrier retains its existing empty-list-to-IPv4 and
implicit-false behavior.

`NeighborConfig.required_families` must be a subset of `families`; otherwise
`AddNeighbor` returns `INVALID_ARGUMENT`. Empty inherits a non-empty peer-group
list; when both are empty, partial negotiation is preserved.
`NeighborState.config.required_families` reports the effective inherited list.

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"config": {"address": "10.0.0.2", "remote_asn": 65002, "description": "peer-2"}}' \
  localhost:50051 rustbgpd.v1.NeighborService/AddNeighbor
```

For an IPv6 link-local / unnumbered peer, include `interface` in
`NeighborConfig`. Follow-up operations that address a scoped peer use the same
`address` + `interface` pair.

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"config": {"address": "fe80::5054:ff:fe00:1", "interface": "eth1", "remote_asn": 65101}}' \
  localhost:50051 rustbgpd.v1.NeighborService/AddNeighbor
```

### List all neighbors

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.NeighborService/ListNeighbors
```

### Get a single neighbor's state

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"address": "10.0.0.2"}' \
  localhost:50051 rustbgpd.v1.NeighborService/GetNeighborState
```

### Disable a neighbor

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"address": "10.0.0.2", "reason": "maintenance"}' \
  localhost:50051 rustbgpd.v1.NeighborService/DisableNeighbor
```

### Enable a neighbor

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"address": "10.0.0.2"}' \
  localhost:50051 rustbgpd.v1.NeighborService/EnableNeighbor
```

### Delete a neighbor

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"address": "10.0.0.2"}' \
  localhost:50051 rustbgpd.v1.NeighborService/DeleteNeighbor
```

### Trigger SoftResetIn

```bash
# Refresh all configured families (empty families list)
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"address": "10.0.0.2"}' \
  localhost:50051 rustbgpd.v1.NeighborService/SoftResetIn

# Refresh only IPv4 unicast
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"address": "10.0.0.2", "families": ["ipv4_unicast"]}' \
  localhost:50051 rustbgpd.v1.NeighborService/SoftResetIn
```

### Refresh one peer's outbound routes

```bash
rbgp neighbor 10.0.0.2 refresh-out

grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"address": "10.0.0.2"}' \
  localhost:50051 rustbgpd.v1.NeighborService/RefreshOutbound
```

`scheduled: true` means the RIB accepted the refresh pass; resulting updates
were enqueued or retained for the ordinary dirty-retry path. It does not
confirm writer drain or remote receipt.
Unknown peers return `NOT_FOUND`; managed peers without an active outbound RIB
registration return `FAILED_PRECONDITION`.

This is an O(table) operation for the selected peer and can create a full-table
UPDATE burst on a production session. Serialize operational use; the API
intentionally has no all-peer or batch form.

---

## PolicyService

Named policy definition CRUD plus global and per-neighbor chain assignment.
Chain changes apply immediately for future route processing. Import-policy
changes do not retroactively re-evaluate existing Adj-RIB-In state; use
`SoftResetIn` if you need a full inbound refresh.

| RPC | Description |
|-----|-------------|
| `ListPolicies` | List all named policy definitions |
| `GetPolicy` | Return one named policy definition |
| `SetPolicy` | Create or replace a named policy definition |
| `DeletePolicy` | Delete a named policy definition (rejected while referenced) |
| `ListNeighborSets` / `GetNeighborSet` | List or fetch a named neighbor set |
| `SetNeighborSet` / `DeleteNeighborSet` | Create/replace or delete a named neighbor set |
| `GetGlobalPolicyChains` | Return global import/export chain assignments |
| `SetGlobalImportChain` / `SetGlobalExportChain` | Replace global chain assignment |
| `ClearGlobalImportChain` / `ClearGlobalExportChain` | Remove the global chain assignment |
| `GetNeighborPolicyChains` | Return one neighbor's import/export chain assignments |
| `SetNeighborImportChain` / `SetNeighborExportChain` | Replace one neighbor's chain assignment |
| `ClearNeighborImportChain` / `ClearNeighborExportChain` | Remove one neighbor's chain assignment |
| `ExplainImportPolicy` | Explain why a prefix was permitted / denied / withdrawn / evicted / stale / not-seen on import for a given neighbor, reading the per-session import-decision cache (ADR-0073). For `.rpol` chain members the statement trace names the deciding term and carries per-term trace lines (ADR-0096). A bounded read timeout returns `DEADLINE_EXCEEDED`, not synthetic `NO_SESSION`. Side-effect-free; IPv4/IPv6 unicast only. `SensitiveRead` tier. |
| `ListRejectedRoutes` | List every rejected inbound route a peer's session has retained, each tagged with its canonical reject-reason token (`policy_reject`, `otc_route_leak`, `next_hop_ownership`, `as_path_loop`, `rr_loop`, `treat_as_withdraw`), a sub-reason detail, and a best-effort attribute summary. The enumeration complement to `ExplainImportPolicy`'s point lookup. Retention is a bounded per-peer LRU (`[policy.reject_retention]`); the response reports `retention_enabled` and `capacity` so an empty listing is distinguishable from retention being off. A bounded read timeout returns `DEADLINE_EXCEEDED`, not `NOT_FOUND`. Side-effect-free; IPv4/IPv6 unicast only. CLI: `rbgp rib received <peer> --rejected`. `SensitiveRead` tier. |
| `TestPolicy` | Dry-run a candidate `.rpol` policy (source sent in the request, compiled server-side) read-only over a live Adj-RIB-In / Loc-RIB snapshot: accepted/rejected/modified counts, per-term hit counters, before/after attribute diff samples. No route, session, or counter impact; IPv4/IPv6 unicast (ADR-0096). CLI: `rbgp policy test`. `SensitiveRead` tier. |
| `GetPolicyStats` | Read the live per-term hit counters of the installed policy chains (since chain install; direction `import`, `export`, or `both` — import chains also report their install generation). All backend waits across explicit-peer validation plus export, import, and dataset reads share one absolute 500 ms deadline; timeout returns `DEADLINE_EXCEEDED` with no partial rows. Fleet import reads use bounded per-RPC concurrency, do not park the peer-manager actor awaiting sessions, and cancel outstanding session queries when the caller disconnects. An explicit unknown peer returns `NOT_FOUND`; a selected session exit returns `UNAVAILABLE`; a session that answers with no import chain legitimately contributes no row. CLI: `rbgp policy stats`. `SensitiveRead` tier. |

Policy statements support the same match surface as TOML config:
`prefix`, `ge`, `le`, `match_community`, `match_as_path`,
`match_neighbor_set`, `match_route_type`, `match_as_path_length_ge/le`,
`match_local_pref_ge/le`, `match_med_ge/le`, `match_next_hop`,
`match_rpki_validation`, `match_aspa_validation`, and
`match_evpn_route_type`.

### Explain an import decision

Answer "why didn't this prefix come in?" (or "what did the chain do to it?")
from the per-session import-decision cache (ADR-0073). Side-effect-free —
no RIB touch, no counter movement. Omit `path_id` to return every matching
path. The cache is **opt-in**: without `[policy.explain] enabled = true`
on the daemon the outcome is `CACHE_DISABLED`, which is deliberately
distinct from `NOT_SEEN`. If the peer has no current session actor, the
outcome is `NO_SESSION`; this is also distinct from a session that answered
without a cached decision. `CACHE_DISABLED` and `NO_SESSION` are normal
explain outcomes, not transport errors.

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{
    "peer_address": "10.0.0.2",
    "afi_safi": "IPV4_UNICAST",
    "prefix": "192.0.2.0",
    "prefix_length": 24
  }' \
  localhost:50051 rustbgpd.v1.PolicyService/ExplainImportPolicy
```

Each `matches` entry carries an outcome — `PERMIT` / `DENY` / `WITHDRAWN` /
`EVICTED` / `STALE` / `NOT_SEEN` — and, when a chain matched, the matched
policy plus the modifications it applied. Compare a match's
`policy_generation` to the response's `current_policy_generation` to spot a
`STALE` decision recorded before a policy reload.

### List a peer's rejected routes

Answer "show me everything of mine you filtered, and why" without knowing a
prefix in advance — the looking-glass filtered-route surface. Side-effect-free.
Returns `NOT_FOUND` when the peer has no live session (the session-local
retention store is gone, which is honestly distinct from "nothing rejected").

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"peer_address": "10.0.0.2"}' \
  localhost:50051 rustbgpd.v1.PolicyService/ListRejectedRoutes
```

Each retained rejection carries the prefix identity, the canonical reason
token with its sub-reason detail (e.g. the matched policy name for
`policy_reject`), the announcement's next hop, AS_PATH, communities, RPKI/ASPA
validation states, and the rejection timestamp. `retention_enabled: false`
means the empty listing is a configuration fact; when the route count equals
`capacity`, the listing shows the most recent rejections only. CLI:
`rbgp rib received <peer> --rejected`.

### Create or replace a named policy

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{
    "name": "tag-internal",
    "definition": {
      "default_action": "permit",
      "statements": [
        {
          "action": "permit",
          "prefix": "10.0.0.0/8",
          "le": 16,
          "set_community_add": ["65001:100"]
        }
      ]
    }
  }' \
  localhost:50051 rustbgpd.v1.PolicyService/SetPolicy
```

### Attach a global import chain

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"policy_names": ["reject-bogons", "tag-internal"]}' \
  localhost:50051 rustbgpd.v1.PolicyService/SetGlobalImportChain
```

### Attach a per-neighbor export chain

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"address": "10.0.0.2", "policy_names": ["tag-ixp"]}' \
  localhost:50051 rustbgpd.v1.PolicyService/SetNeighborExportChain
```

### Create a named neighbor set

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{
    "name": "ix-clients",
    "definition": {
      "addresses": ["10.0.0.2", "10.0.0.3"],
      "remote_asns": [65002, 65003],
      "peer_groups": ["rs-clients"]
    }
  }' \
  localhost:50051 rustbgpd.v1.PolicyService/SetNeighborSet
```

### Delete a named policy

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"name": "tag-internal"}' \
  localhost:50051 rustbgpd.v1.PolicyService/DeletePolicy
```

---

## PeerGroupService

Peer-group CRUD plus neighbor membership assignment. Group definitions are
full-replace and persist back to TOML. When an inherited setting changes, the
daemon recomputes effective per-neighbor config and reconciles only the peers
that reference that group. Read responses redact `md5_password` and expose
only the non-secret `has_md5_password` presence flag. `SetPeerGroup` preserves
the existing stored MD5 password when the field is omitted or set to `true`
without a new `md5_password`; set `has_md5_password = false` with no
`md5_password` to clear it explicitly. Use the configuration file or write-side
source of truth to inspect credential material.

`PeerGroupDefinition.required_families` is the raw group list returned by
peer-group CRUD. An empty neighbor list inherits it and cannot clear it; a
non-empty neighbor list overrides it. Every effective requirement must be a
subset of the member's effective configured families.

| RPC | Description |
|-----|-------------|
| `ListPeerGroups` | List all peer-group definitions |
| `GetPeerGroup` | Return one peer-group definition |
| `SetPeerGroup` | Create or replace a peer-group definition |
| `DeletePeerGroup` | Delete a peer-group definition (rejected while referenced) |
| `SetNeighborPeerGroup` | Assign one neighbor to a peer group |
| `ClearNeighborPeerGroup` | Remove a neighbor's peer-group reference |

### Create or replace a peer group

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{
    "name": "rs-clients",
    "definition": {
      "families": ["ipv4_unicast", "ipv6_unicast"],
      "required_families": ["ipv6_unicast"],
      "hold_time": 90,
      "route_server_client": true,
      "export_policy_chain": ["tag-ixp", "suppress-leaks"]
    }
  }' \
  localhost:50051 rustbgpd.v1.PeerGroupService/SetPeerGroup
```

### Assign a neighbor to a peer group

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"address": "10.0.0.2", "peer_group": "rs-clients"}' \
  localhost:50051 rustbgpd.v1.PeerGroupService/SetNeighborPeerGroup
```

---

## RibService

Query the routing information base and subscribe to real-time route changes.

| RPC | Description |
|-----|-------------|
| `ListReceivedRoutes` | Adj-RIB-In: all routes received from peers |
| `ListBestRoutes` | Loc-RIB: best route per prefix after path selection |
| `ListAdvertisedRoutes` | Adj-RIB-Out: routes advertised to a specific peer |
| `ExplainAdvertisedRoute` | Dry-run export decision for one prefix (or, with `rd`, one VPN identity) to one peer: the full gate ladder in live evaluation order (split horizon, RFC 4456 reflection, family, RFC 9494 LLGR, RFC 5291 ORF, RFC 4684 RT membership, export policy with per-term labels, Adj-RIB-Out diff), produced by a dry run of the live staging body. For negotiated unicast Add-Path send, optional `source { peer_address, path_id }` selects one exact Adj-RIB-In candidate. |
| `ExplainBestPath` | Show all candidates for a prefix with decisive comparison reasons; optional `peer_address` field scopes to that peer's Add-Path send view |
| `ListFlowSpecRoutes` | FlowSpec routes in Adj-RIB-In / Loc-RIB view |
| `ListEvpnRoutes` | EVPN routes (RFC 7432) in Loc-RIB view, filterable by route type / peer / RD |
| `ListBgpLsRoutes` | BGP-LS / BGP-LS VPN routes (RFC 9552) in Loc-RIB view, exposed as opaque NLRI/TLV bytes and filterable by family, peer, and NLRI type |
| `ListVpnRoutes` | RFC 4364/4659 VPNv4/VPNv6 routes — RD-scoped customer prefixes, Route Targets, and MPLS labels |
| `ListLabeledRoutes` | RFC 8277 labeled-unicast (SAFI 4) routes in Loc-RIB view — MPLS label stack plus prefix reachability |
| `ListRtcRoutes` | RFC 4684 RT-Constrain membership NLRI — which Route Targets each peer imports |
| `ListTopologyNodes` | RFC 9107 ORR topology nodes built from the BGP-LS Adj-RIB-In union |
| `ListTopologyLinks` | RFC 9107 ORR topology links — IGP adjacencies, link addresses, and metrics (the SPF input) |
| `ListOrrStatus` | RFC 9107 ORR per-vantage status — configured vantages, their resolved topology nodes, and the peers bound to them |
| `ListBlackholeDiscards` | RFC 7999 BLACKHOLE kernel-discard install status when `[global] honor_blackhole = true` and `[global] install_blackhole_discard = true` |
| `ListFibRoutes` | ADR-0061 general unicast Linux FIB route status for configured `[[fib_tables]]` |
| `ListFibTables` | List the configured `[[fib_tables]]` and whether the FIB reconciler is running (`sensitive_read`) |
| `SetFibTable` | Create-or-replace a `[[fib_tables]]` entry by name (upsert; full definition, not a patch) at runtime; hot-applies through the reconciler and persists. Requires the reconciler running (≥1 table at startup) else `FAILED_PRECONDITION` (`mutating`) |
| `DeleteFibTable` | Remove a `[[fib_tables]]` entry by name at runtime; `NOT_FOUND` if absent (`mutating`) |
| `ListRouteEvents` | Recent unicast route add / withdraw / best-change / export-policy-filtered event history from the bounded in-memory RIB ring |
| `WatchRoutes` | Server-streaming: real-time route add / withdraw / best-change / export-policy-filtered events |
| `WatchRouteEvents` | Server-streaming: real-time route add / withdraw / best-change / export-policy-filtered events wrapped as `BgpEvent`, including explicit lag warnings |

The three unicast route-listing RPCs return raw ordered
`extended_communities`, the ASPA verification string in `aspa_state`, and
`received_at_epoch_seconds` on every `Route` (`0` means unknown). Native
`rbgp --json rib` preserves the raw extended-community values, omits an empty
`aspa_state` from an older daemon but retains a genuine `"unknown"` state, and
retains the zero receive-time sentinel. The same native route serializer is
used by best, received, advertised, and embedded `ExplainBestPath` routes.

### Runtime observability surfaces

Runtime visibility is intentionally split by access pattern rather than forced
through one RPC shape.

| Need | Surface | Shape | Retention / loss behavior |
|------|---------|-------|---------------------------|
| Live unicast route deltas | `WatchRoutes`, `WatchRouteEvents`, or `EventService.WatchEvents` with `EVENT_CATEGORY_ROUTE` | Streaming event feed | Live-only; `WatchRouteEvents` / `WatchEvents` emit `stream_lagged` when slow subscribers miss events |
| Recent unicast route timeline | `ListRouteEvents` / `rbgp events` | Bounded history query | In-memory 4096-event ring, process-local, oldest entries evicted |
| Live session lifecycle | `EventService.WatchEvents` with `EVENT_CATEGORY_SESSION` | Streaming event feed | Live-only; no replay after reconnect |
| Recent session lifecycle | `EventService.ListSessionEvents` / `rbgp events sessions` | Bounded history query | In-memory 4096-event ring, process-local, oldest entries evicted |
| Live policy mutation summaries | `EventService.WatchEvents` with `EVENT_CATEGORY_POLICY` | Streaming event feed | Live-only; slow subscribers can lag and miss events |
| Recent policy mutation summaries | `EventService.ListPolicyEvents` / `rbgp events policy` | Bounded history query | In-memory 4096-event ring, process-local, oldest entries evicted |
| Live EVPN route best-path deltas | `EventService.WatchEvents` with `EVENT_CATEGORY_EVPN` | Streaming event feed | Live-only; slow subscribers can lag and miss events |
| Recent EVPN route timeline | `EventService.ListEvpnEvents` / `rbgp events evpn` | Bounded history query | In-memory 4096-event ring, process-local, oldest entries evicted |
| RFC 7999 discard programming | `ListBlackholeDiscards` / `rbgp rib blackholes` | Snapshot | Current reconcile snapshot only |
| ADR-0061 general Linux FIB programming | `ListFibRoutes` / `rbgp rib fib` | Snapshot | Current reconcile snapshot plus persisted owned-state semantics |
| ADR-0061 FIB route apply outcomes | `EventService.WatchEvents` with `EVENT_CATEGORY_DATAPLANE` and `BGP_EVENT_TYPE_DATAPLANE_ROUTE_*` / `rbgp events watch --category dataplane` | Streaming event feed | Live via `WatchEvents`; durable replay via `SubscribeFromEvent` when `[event_history].enabled = true`; no bounded `List*` history API |
| EVPN L2/L3 dataplane readiness and managed-netdev ownership status | `EvpnService` (`ListEvpnInstances`, `ListEvpnNexthops`, `ListEthernetSegments`, `ListIpVrfs`, `ListManagedNetdevs`) / `rbgp evpn ...` | Snapshot | Latest daemon or dataplane report snapshot |
| BGP-LS topology objects | `ListBgpLsRoutes` / `rbgp rib bgpls` | Snapshot | Current Loc-RIB only; raw BGP-LS NLRI/TLV bytes preserved |
| ADR-0067 BFD session state | `BfdService.GetBfdSessions` / `rbgp bfd` | Snapshot | Current BFD actor snapshot |
| Live BFD session state changes | `EventService.WatchEvents` with `EVENT_CATEGORY_BFD` and `BGP_EVENT_TYPE_BFD_SESSION_*` / `rbgp events watch --category bfd` | Streaming event feed | Live-only; opt-in (not in the default route+session set); slow subscribers can lag |
| Alerting / counters | Prometheus `/metrics` | Cumulative counters and gauges | Process lifetime, scrape-dependent |

Use a live stream when you need a tail, `ListRouteEvents` when you need recent
route context after the fact, and status RPCs for current ownership/readiness
state. `WatchEvents` does not replay `ListRouteEvents`; clients that need both
context and a live tail should query history first, then subscribe.

### List received routes (Adj-RIB-In)

```bash
# All received routes
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.RibService/ListReceivedRoutes

# From a specific peer
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"neighbor_address": "10.0.0.2"}' \
  localhost:50051 rustbgpd.v1.RibService/ListReceivedRoutes
```

### List best routes (Loc-RIB)

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.RibService/ListBestRoutes
```

### List advertised routes (Adj-RIB-Out)

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"neighbor_address": "10.0.0.2"}' \
  localhost:50051 rustbgpd.v1.RibService/ListAdvertisedRoutes
```

### Explain one advertised route decision

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"peer_address": "10.0.0.2", "prefix": "203.0.113.0", "prefix_length": 24}' \
  localhost:50051 rustbgpd.v1.RibService/ExplainAdvertisedRoute
```

This dry-runs the current export decision for a single prefix and peer. The
response includes the final decision, decisive reasons, selected best-route
identity, and any export modifications that would be applied.

For an IPv4/IPv6 unicast peer with negotiated Add-Path send, set the optional
presence-bearing `source` message to explain one exact Adj-RIB-In candidate:

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"peer_address":"10.0.0.2","prefix":"203.0.113.0","prefix_length":24,"source":{"peer_address":"198.51.100.7","path_id":0}}' \
  localhost:50051 rustbgpd.v1.RibService/ExplainAdvertisedRoute
```

The echoed `source.path_id` remains the inbound Add-Path identity. The
top-level response `path_id` is the independent, compact outbound rank
rustbgpd would assign after eligibility and export policy. That outbound rank
is 0 for a pre-selection/policy denial or a candidate
beyond `add_path_send_max`. A later OTC or exact-wire denial retains the
attempted non-zero rank, and the `adj_rib_out` rung compares that exact rank.
Inbound ID 0 remains selectable because message presence, not a sentinel,
distinguishes selection from the legacy winner-oriented query. Unknown source
identity returns `NOT_FOUND`; a source selector without negotiated unicast
Add-Path send returns `FAILED_PRECONDITION`. `source` is mutually exclusive
with `rd` and `labeled`.

Best-path explain is also available via `ExplainBestPath` RPC — it returns all
candidates for a prefix with the decisive comparison reason for each. Set
`peer_address` on the request to scope the response to that peer's Add-Path
send view: candidates that the peer would actually receive (export-policy
permitted + sendable-family + not suppressed by split-horizon or iBGP /
RFC 4456 route-reflector rules + within the peer's effective
`add_path_send_max`) get a non-zero `advertised_path_id` reflecting the rank
they would carry on the wire; everything else stays at `advertised_path_id =
0`. The response echoes `peer_address` and the effective `add_path_send_max`
so the operator can read advertisement intent without cross-referencing the
peer config. Empty `peer_address` returns the v0.7.0 global Loc-RIB view
unchanged. Unknown `peer_address` → `NOT_FOUND`. Import explain is available via
`PolicyService.ExplainImportPolicy` (ADR-0073), including structured
statement/term traces for matched policies.

### Address family filtering

Route-listing RPCs and route-event streams (`ListReceivedRoutes`,
`ListBestRoutes`, `ListAdvertisedRoutes`, `WatchRoutes`, and
`WatchRouteEvents`) accept an
`afi_safi` field to filter by address family. Supported values are
`IPV4_UNICAST` (1), `IPV6_UNICAST` (2), or unspecified (0, returns both
unicast families). Route watch events include the address family of each route
change. FlowSpec routes use `ListFlowSpecRoutes` with
`IPV4_FLOWSPEC` (3), `IPV6_FLOWSPEC` (4), or unspecified (0). EVPN routes
use `ListEvpnRoutes` and its EVPN-specific filters. BGP-LS routes use
`ListBgpLsRoutes` with `ADDRESS_FAMILY_BGP_LS` (6),
`ADDRESS_FAMILY_BGP_LS_VPN` (7), or unspecified (0).

### Pagination

The unicast route-listing RPCs `ListReceivedRoutes`, `ListBestRoutes`, and
`ListAdvertisedRoutes` support pagination via `page_size` and `page_token`.
`ListFibRoutes` also supports optional pagination; unlike the route-listing
RPCs, `page_size = 0` preserves the legacy behavior and returns the full
filtered FIB status snapshot. `ListBlackholeDiscards`, `ListFlowSpecRoutes`,
and `ListBgpLsRoutes` do not support pagination.

```bash
# First page (2 routes)
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"page_size": 2}' \
  localhost:50051 rustbgpd.v1.RibService/ListBestRoutes

# Next page (pass the previous response's next_page_token verbatim)
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"page_size": 2, "page_token": "<next_page_token>"}' \
  localhost:50051 rustbgpd.v1.RibService/ListBestRoutes
```

`page_token` is opaque: always pass the `next_page_token` from the previous
response (empty = listing complete), and only reuse it with the same RPC,
neighbor, route scope, and semantically equivalent route filters. Changing a
scope or filter returns gRPC `INVALID_ARGUMENT`; changing only `page_size` is
safe. Tokens are process-local and mutation-fenced by one conservative
generation for the Received, Best, or Advertised scope class. Any mutation in
that class makes the next request fail with gRPC `ABORTED`; a peer-specific
listing can therefore restart after an unrelated peer in the same class
changes. The server retains no route snapshot or cursor registry. `page_size`
is capped server-side at 1000 rows per page (0 = default of 100).

Every `ListRoutesResponse`, including an empty or terminal page, carries a
`page_version` message with an `epoch` and `generation`. The pair exposes the
same process-local consistency fence used by continuation tokens. A client may
compare the complete pair for equality across the pages and peer walks of one
logical capture; a changed value means the capture must be discarded. The
values are opaque, may repeat after daemon restart, and are not a RIB snapshot
generation. In particular, `page_version.generation` must never be compared
with or substituted for a producer-local `rbgp-ribsnap/1` header generation.
Older daemons omit this additive message field.

Every response also carries `total_count`: the exact filtered count for the
whole selected view, regardless of page size. This is the contract behind
`rbgp rib --count` and
`rbgp rib received|advertised <PEER> --count`, which request a single-row
page and read only `total_count`.

### Watch route changes (streaming)

```bash
# Legacy bare RouteEvent stream (streams until interrupted)
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.RibService/WatchRoutes

# Watch changes for a specific peer
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"neighbor_address": "10.0.0.2"}' \
  localhost:50051 rustbgpd.v1.RibService/WatchRoutes

# Lag-aware BgpEvent route stream
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.RibService/WatchRouteEvents
```

Both `WatchRoutes` and `WatchRouteEvents` use `WatchRoutesRequest`, which
accepts an `afi_safi` field to filter the stream by address family.

Event types: `ROUTE_EVENT_TYPE_ADDED`, `ROUTE_EVENT_TYPE_WITHDRAWN`,
`ROUTE_EVENT_TYPE_BEST_CHANGED`, and `ROUTE_EVENT_TYPE_POLICY_FILTERED`.
Policy-filtered events are route-level export-policy denials: `peer_address`
is the source route peer, `target_peer_address` is the outbound peer whose
export policy denied the route, and `reason` is currently `policy_denied`.

Each `RouteEvent` carries an `event_id`, a monotonic process-local cursor that
is assigned before the event is written to history and broadcast to live
subscribers. The cursor resets on daemon restart and is not reused within one
process.

`WatchRoutes` and `WatchRouteEvents` do not backfill recent events for new
subscribers. Clients that need both context and a live tail should call
`ListRouteEvents` first, then open a live stream for subsequent deltas.
`WatchRoutes` preserves its legacy bare `RouteEvent` response shape and does
not emit explicit lag warnings. `WatchRouteEvents` returns the same route
deltas wrapped in `BgpEvent` and emits `BGP_EVENT_TYPE_STREAM_LAGGED` with a
`StreamLagEvent` payload when this subscriber falls behind the bounded route
broadcast. `EventService.WatchEvents` provides the same lag-aware route events
alongside session, policy, and dataplane categories.

### List recent route events

```bash
# Return the recent route-event timeline (oldest-to-newest within the window)
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"limit": 100}' \
  localhost:50051 rustbgpd.v1.RibService/ListRouteEvents

# Filter by peer and IPv4 unicast
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"neighbor_address": "10.0.0.2", "afi_safi": "IPV4_UNICAST", "limit": 50}' \
  localhost:50051 rustbgpd.v1.RibService/ListRouteEvents

# Drill into one exact prefix
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"prefix": "203.0.113.0", "prefix_length": 24, "limit": 20}' \
  localhost:50051 rustbgpd.v1.RibService/ListRouteEvents
```

`ListRouteEvents` reads the same unicast route events that feed
`WatchRoutes`, but from a bounded 4096-event in-memory ring. Peer filters
match `peer_address`, `previous_peer_address`, and `target_peer_address`, so a
peer-scoped query includes withdraws, best-path moves away from that peer, and
routes filtered by that peer's export policy. Prefix filters are exact-match
only and can be combined with peer, family, and limit filters. The
filter does not do containment or longest-prefix matching, so a query for
`203.0.113.0/16` will not return an event recorded for `203.0.113.0/24`.
`event_id` values are monotonic within the running daemon and can be used by
clients to de-duplicate a history window against a live stream. They are not
persisted or reused within one process. The history is process-local and
resets on daemon restart.

### List FlowSpec routes

```bash
# List all FlowSpec routes
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.RibService/ListFlowSpecRoutes

# List only IPv6 FlowSpec routes
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"afi_safi": "ADDRESS_FAMILY_IPV6_FLOWSPEC"}' \
  localhost:50051 rustbgpd.v1.RibService/ListFlowSpecRoutes
```

### List EVPN routes

```bash
# All EVPN routes in Loc-RIB
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.RibService/ListEvpnRoutes

# Only Type 2 (MAC/IP) routes
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"route_type_filter": 2}' \
  localhost:50051 rustbgpd.v1.RibService/ListEvpnRoutes

# Filter by Route Distinguisher
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"rd_filter": "65000:100"}' \
  localhost:50051 rustbgpd.v1.RibService/ListEvpnRoutes
```

`route_type_filter` accepts 0 (no filter) or `1..=5` matching the RFC 7432
route type numbers. `peer_filter` is an optional typed IP-address match (for
example, expanded and compressed IPv6 spellings are equivalent); `rd_filter`
is an optional typed route-distinguisher match (for example, `"65000:100"`,
`"10.0.0.1:100"`, or `"4200000000:100"` per RFC 4364 RD types 0/1/2, plus
the displayed `0x`/16-hex-digit fallback for unknown types). Empty strings
disable each filter. Invalid filters fail with `INVALID_ARGUMENT` before the
RIB actor is queried.

### List BGP-LS routes

```bash
# All BGP-LS and BGP-LS VPN routes in Loc-RIB
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.RibService/ListBgpLsRoutes

# BGP-LS only, from one peer, for Node NLRI
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"afi_safi": "ADDRESS_FAMILY_BGP_LS", "peer_filter": "10.0.0.2", "nlri_type_filter": 1}' \
  localhost:50051 rustbgpd.v1.RibService/ListBgpLsRoutes
```

`ListBgpLsRoutes` is the ADR-0077 controller-facing BGP-LS surface. It
preserves BGP-LS routes as opaque RFC 9552 objects: raw Route Distinguisher
bytes for BGP-LS VPN, raw NLRI descriptor/payload bytes, and raw BGP-LS
Attribute (type 29) bytes when present. Negotiated BGP-LS routes can also be
reflected to eligible peers through the normal route-reflector pipeline and feed
the RFC 9107 ORR topology used for per-vantage best-path selection. The daemon
does not synthesize BGP-LS from a local LSDB or negotiate BGP-LS Add-Path. GR /
LLGR stale preservation for BGP-LS and BGP-LS VPN is implemented as part of the
RR-family stale pipeline.
Its `afi_safi` filter accepts only unspecified, BGP-LS, or BGP-LS VPN.
As with EVPN, VPN, labeled-unicast, and RT-Constrain route listings, a
non-empty `peer_filter` must parse as an IP address and matches by address
identity rather than display spelling.

### List BLACKHOLE discard status

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.RibService/ListBlackholeDiscards
```

Returns one row per currently observed best route carrying the RFC 7999
`BLACKHOLE` community when the opt-in FIB reconciler is active. `state` is a
`BlackholeDiscardState` enum (`BLACKHOLE_DISCARD_STATE_INSTALLED`,
`BLACKHOLE_DISCARD_STATE_REJECTED`, or `BLACKHOLE_DISCARD_STATE_FAILED`);
`reason` carries values such as `installed`, `owned`, `broad_prefix`,
`not_ebgp`, `foreign_route_exists`, `lookup_failed`, `remove_failed`, or
the kernel install error string.
An empty list means either the reconciler is disabled or no BLACKHOLE-marked
best routes are currently visible.

### List general FIB route status

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.RibService/ListFibRoutes

rbgp rib fib          # human table
rbgp rib fib --json   # JSON array for scripts
rbgp rib fib --table edge --state rejected --reason route_limit_exceeded
rbgp rib fib --prefix 203.0.113.0/24 --neighbor 198.51.100.2
rbgp rib fib --page-size 100
```

Returns one row per desired route, daemon-owned route, or one-pass
reconciliation outcome in the ADR-0061 general unicast Linux FIB runtime.
The runtime is default-off and only starts when at least one `[[fib_tables]]`
block is configured. `state` is a `FibRouteState` enum (`FIB_ROUTE_STATE_INSTALLED`,
`FIB_ROUTE_STATE_REJECTED`, or `FIB_ROUTE_STATE_FAILED`); `reason`
carries values such as `owned`, `foreign_route_exists`,
`next_hop_family_unsupported`, `peer_not_allowed`,
`route_limit_exceeded`, `owned_route_drifted`, `dump_failed:DETAIL`,
`rib_query_failed:DETAIL`, or a kernel apply error such as
`install_failed:DETAIL`.

`ListFibRoutesRequest` supports optional filters for `table_name`, `state`,
`reason`, exact `prefix` + `prefix_length`, and `peer_address`; filters compose
with AND semantics. The prefix filter is an exact route-key match, not
longest-prefix or containment matching, so `203.0.113.0/24` does not match
`203.0.113.128/25`. Empty strings and `FIB_ROUTE_STATE_UNSPECIFIED` mean "no
filter"; for direct gRPC callers, `prefix_length` must be `0` when `prefix` is
empty. `rbgp rib fib` exposes the same filters as `--table`, `--state`,
`--reason`, `--prefix`, and `--neighbor`. `page_size` and `page_token` enable
optional pagination over the filtered status rows; `page_size = 0` keeps the
legacy full-snapshot response, and `page_token` is valid only when
`page_size > 0`. The response includes `next_page_token` and `total_count`;
CLI JSON output remains a route array unless `--page-size` is greater than
`0`, in which case it emits an object with `routes`,
`next_page_token`, `total_count`, and optional `sampling` metadata.

`table_id`, `metric`, `prefix`, `prefix_length`, `next_hop`, and `next_hops`
describe the route identity and forwarding value. `next_hop` is the selected
best route's representative gateway; `next_hops` is the canonical installed
set for ECMP / multipath rows. The CLI human table renders `Table`, `Metric`,
`Prefix`, `Next hop`, `State`, and `Reason`; JSON output uses `table_name`,
`table_id`, `metric`, `prefix`, `next_hop`, `next_hops`, `peer_address`,
`state`, `reason`, and optional `sampling`. Sampling is present
on high-cardinality rows such as `route_limit_exceeded`; it reports the number
of surfaced sample rows, suppressed rows, total rows in that table/metric/reason
set, the configured `max_routes`, the status sample cap, and whether the sample
is complete. Pagination still applies only to surfaced rows: `total_count` does
not include suppressed rows. A pre-existing kernel row in a
configured table is reported as `foreign_route_exists`; `RTPROT_BGP` is not
ownership proof by itself because another daemon can use the same protocol
marker. A row rustbgpd previously owned but later finds changed by another
writer is reported as `owned_route_drifted`; the daemon releases ownership and
does not delete that replacement on a later withdraw.

---

## EventService

Unified typed live event stream. Current categories are route events, session
events (peer lifecycle plus BGP NOTIFICATION sent/received metadata), policy
mutation summary events, EVPN route best-path events, dataplane status-row
summary changes for the daemon-owned FIB / BLACKHOLE discard reconcilers, live
ADR-0061 per-route FIB apply outcomes, and BFD session state changes.

| RPC | Description |
|-----|-------------|
| `WatchEvents` | Server-streaming: unified typed event stream sourced from structured daemon events |
| `SubscribeFromEvent` | Server-streaming: durable event-history cursor replay from the local outbox, then live |
| `ListSessionEvents` | Unary: recent session lifecycle events from the peer manager's bounded in-memory history |
| `ListPolicyEvents` | Unary: recent policy / neighbor-set / peer-group / chain mutation events from the peer manager's bounded in-memory history |
| `ListEvpnEvents` | Unary: recent EVPN route add / withdraw / best-change events from the RIB's bounded in-memory history |

### Watch unified events

```bash
# Watch the default live route + session events
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.EventService/WatchEvents

# Watch only route adds for one exact prefix
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"categories": ["EVENT_CATEGORY_ROUTE"], "event_types": ["BGP_EVENT_TYPE_ROUTE_ADDED"], "prefix": "203.0.113.0", "prefix_length": 24}' \
  localhost:50051 rustbgpd.v1.EventService/WatchEvents

# Watch session establishment/loss for one peer
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"categories": ["EVENT_CATEGORY_SESSION"], "event_types": ["BGP_EVENT_TYPE_SESSION_ESTABLISHED", "BGP_EVENT_TYPE_SESSION_LOST"], "neighbor_address": "10.0.0.2"}' \
  localhost:50051 rustbgpd.v1.EventService/WatchEvents

# Watch BGP NOTIFICATIONs for one peer
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"categories": ["EVENT_CATEGORY_SESSION"], "event_types": ["BGP_EVENT_TYPE_NOTIFICATION_SENT", "BGP_EVENT_TYPE_NOTIFICATION_RECEIVED"], "neighbor_address": "10.0.0.2"}' \
  localhost:50051 rustbgpd.v1.EventService/WatchEvents

# Watch policy / peer-group / chain mutation summaries
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"categories": ["EVENT_CATEGORY_POLICY"], "event_types": ["BGP_EVENT_TYPE_POLICY_CHANGED"]}' \
  localhost:50051 rustbgpd.v1.EventService/WatchEvents

# Query recent session establishment/loss history for one peer
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"event_types": ["BGP_EVENT_TYPE_SESSION_ESTABLISHED", "BGP_EVENT_TYPE_SESSION_LOST"], "neighbor_address": "10.0.0.2", "limit": 20}' \
  localhost:50051 rustbgpd.v1.EventService/ListSessionEvents

# Query recent peer-scoped policy mutation history
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"event_types": ["BGP_EVENT_TYPE_POLICY_CHANGED"], "neighbor_address": "10.0.0.2", "limit": 20}' \
  localhost:50051 rustbgpd.v1.EventService/ListPolicyEvents

# Watch FIB / BLACKHOLE dataplane status-row summary changes
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"categories": ["EVENT_CATEGORY_DATAPLANE"], "event_types": ["BGP_EVENT_TYPE_DATAPLANE_STATUS_CHANGED"]}' \
  localhost:50051 rustbgpd.v1.EventService/WatchEvents

# Watch per-route FIB install failures for one prefix
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"categories": ["EVENT_CATEGORY_DATAPLANE"], "event_types": ["BGP_EVENT_TYPE_DATAPLANE_ROUTE_FAILED"], "prefix": "203.0.113.0", "prefix_length": 24}' \
  localhost:50051 rustbgpd.v1.EventService/WatchEvents

# Watch EVPN route best-path changes for one peer
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"categories": ["EVENT_CATEGORY_EVPN"], "event_types": ["BGP_EVENT_TYPE_EVPN_ROUTE_ADDED", "BGP_EVENT_TYPE_EVPN_ROUTE_WITHDRAWN", "BGP_EVENT_TYPE_EVPN_ROUTE_BEST_CHANGED"], "neighbor_address": "10.0.0.2"}' \
  localhost:50051 rustbgpd.v1.EventService/WatchEvents

# Replay all retained durable events, then continue live
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"from_event_id": 0}' \
  localhost:50051 rustbgpd.v1.EventService/SubscribeFromEvent

# Query recent Type 2 EVPN route events for one RD
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"route_type_filter": 2, "rd_filter": "65000:100", "limit": 20}' \
  localhost:50051 rustbgpd.v1.EventService/ListEvpnEvents
```

`WatchEvents` is a live stream only: it does not replay the bounded
`ListRouteEvents` history and it does not persist events. The `rbgp
events watch --backfill N` command composes both RPCs client-side for route
events by subscribing live first, printing recent `ListRouteEvents` results
through the same `BgpEvent` renderer used by the live stream, and suppressing
live route events whose `event_id` was already printed. The command prints a
history block followed by the live tail; it does not server-side merge the two
streams by wall-clock timestamp.

`SubscribeFromEvent` is the restart-safe durable cursor surface backed by
`[event_history]`'s local SQLite outbox. Its `from_event_id` field uses explicit
presence: absent means live-only, `0` replays every retained event before
joining live, and `N > 0` replays events with `event_id > N` before joining
live. If `N` is older than the retention floor, the first response is a
`BGP_EVENT_TYPE_STREAM_LAGGED` event whose `missed_count` describes the global
outbox gap; the stream then continues from the earliest retained event. Empty
category and type filters select every EHM-fed category on this RPC: route,
EVPN, session lifecycle, session notifications, policy, dataplane, and BFD.
Dataplane summary and per-route FIB apply events remain live on `WatchEvents`
and are also replayable through `SubscribeFromEvent` when event history is
enabled. When event history is disabled or unavailable, the RPC returns
`FAILED_PRECONDITION`; legacy live and `List*Events` RPCs are unaffected.
That availability result takes precedence over filter validation.

Filters compose AND-wise across category, type, peer, family, and exact prefix.
Repeated categories are ORed, repeated types are ORed, and the two dimensions
are ANDed. A request is accepted when any selected category/type pair is real;
no intersection returns `INVALID_ARGUMENT`. An empty category or type dimension
is a wildcard for compatibility validation (the live default/opt-in selection
rules below still apply).

Synthetic `BGP_EVENT_TYPE_STREAM_LAGGED` control frames bypass ordinary
category, type, peer, family, and prefix filters after compatibility validation.

Live `WatchEvents` compatibility:

| Category | Compatible event types |
|----------|------------------------|
| Route | `BGP_EVENT_TYPE_ROUTE_ADDED`, `BGP_EVENT_TYPE_ROUTE_WITHDRAWN`, `BGP_EVENT_TYPE_ROUTE_BEST_CHANGED`, `BGP_EVENT_TYPE_ROUTE_POLICY_FILTERED`, `BGP_EVENT_TYPE_STREAM_LAGGED` |
| Session | `BGP_EVENT_TYPE_SESSION_STATE_CHANGED`, `BGP_EVENT_TYPE_SESSION_ESTABLISHED`, `BGP_EVENT_TYPE_SESSION_LOST`, `BGP_EVENT_TYPE_PEER_ADDED`, `BGP_EVENT_TYPE_PEER_REMOVED`, `BGP_EVENT_TYPE_PEER_ENABLED`, `BGP_EVENT_TYPE_PEER_DISABLED`, `BGP_EVENT_TYPE_NOTIFICATION_SENT`, `BGP_EVENT_TYPE_NOTIFICATION_RECEIVED`, `BGP_EVENT_TYPE_STREAM_LAGGED` |
| Policy | `BGP_EVENT_TYPE_POLICY_CHANGED` (never `BGP_EVENT_TYPE_STREAM_LAGGED`) |
| Dataplane | `BGP_EVENT_TYPE_DATAPLANE_STATUS_CHANGED`, `BGP_EVENT_TYPE_DATAPLANE_ROUTE_INSTALLED`, `BGP_EVENT_TYPE_DATAPLANE_ROUTE_WITHDRAWN`, `BGP_EVENT_TYPE_DATAPLANE_ROUTE_FAILED`, plus `BGP_EVENT_TYPE_STREAM_LAGGED` only for the per-route source (not the peerless summary source) |
| EVPN | `BGP_EVENT_TYPE_EVPN_ROUTE_ADDED`, `BGP_EVENT_TYPE_EVPN_ROUTE_WITHDRAWN`, `BGP_EVENT_TYPE_EVPN_ROUTE_BEST_CHANGED`, `BGP_EVENT_TYPE_STREAM_LAGGED` |
| BFD | `BGP_EVENT_TYPE_BFD_SESSION_UP`, `BGP_EVENT_TYPE_BFD_SESSION_DOWN`, `BGP_EVENT_TYPE_BFD_SESSION_STATE_CHANGED`, `BGP_EVENT_TYPE_STREAM_LAGGED` |

Durable `SubscribeFromEvent` compatibility:

| Category | Compatible event types |
|----------|------------------------|
| Route | `BGP_EVENT_TYPE_ROUTE_ADDED`, `BGP_EVENT_TYPE_ROUTE_WITHDRAWN`, `BGP_EVENT_TYPE_ROUTE_BEST_CHANGED`, `BGP_EVENT_TYPE_ROUTE_POLICY_FILTERED`, global `BGP_EVENT_TYPE_STREAM_LAGGED` |
| Session | `BGP_EVENT_TYPE_SESSION_STATE_CHANGED`, `BGP_EVENT_TYPE_SESSION_ESTABLISHED`, `BGP_EVENT_TYPE_SESSION_LOST`, `BGP_EVENT_TYPE_PEER_ADDED`, `BGP_EVENT_TYPE_PEER_REMOVED`, `BGP_EVENT_TYPE_PEER_ENABLED`, `BGP_EVENT_TYPE_PEER_DISABLED`, `BGP_EVENT_TYPE_NOTIFICATION_SENT`, `BGP_EVENT_TYPE_NOTIFICATION_RECEIVED`, global `BGP_EVENT_TYPE_STREAM_LAGGED` |
| Policy | `BGP_EVENT_TYPE_POLICY_CHANGED`, `BGP_EVENT_TYPE_OTC_ROUTE_BLOCKED`, global `BGP_EVENT_TYPE_STREAM_LAGGED` |
| Dataplane | `BGP_EVENT_TYPE_DATAPLANE_STATUS_CHANGED`, `BGP_EVENT_TYPE_DATAPLANE_ROUTE_INSTALLED`, `BGP_EVENT_TYPE_DATAPLANE_ROUTE_WITHDRAWN`, `BGP_EVENT_TYPE_DATAPLANE_ROUTE_FAILED`, global `BGP_EVENT_TYPE_STREAM_LAGGED` |
| EVPN | `BGP_EVENT_TYPE_EVPN_ROUTE_ADDED`, `BGP_EVENT_TYPE_EVPN_ROUTE_WITHDRAWN`, `BGP_EVENT_TYPE_EVPN_ROUTE_BEST_CHANGED`, global `BGP_EVENT_TYPE_STREAM_LAGGED` |
| BFD | `BGP_EVENT_TYPE_BFD_SESSION_UP`, `BGP_EVENT_TYPE_BFD_SESSION_DOWN`, `BGP_EVENT_TYPE_BFD_SESSION_STATE_CHANGED`, global `BGP_EVENT_TYPE_STREAM_LAGGED` |

`OTC_ROUTE_BLOCKED` is durable Policy only. Durable `STREAM_LAGGED` describes a
global committed-stream gap and is therefore compatible with every category.
Route events are sourced from the same structured RIB broadcast as `WatchRoutes`,
including export-policy denial events (`route_policy_filtered`) for unicast
routes present in Loc-RIB but filtered from an outbound peer;
session events are sourced from the peer manager's session broadcast and cover
both lifecycle transitions and metadata-only BGP NOTIFICATION sent/received
events; policy events are sourced from the peer manager after a runtime policy
/ neighbor-set / peer-group / chain mutation is accepted and are also retained
in the bounded `ListPolicyEvents` process-local history ring; dataplane summary
events are status-row count changes from the existing `ListFibRoutes` and
`ListBlackholeDiscards` snapshots. ADR-0061 per-route FIB dataplane events are
emitted directly by the FIB runtime when a route is installed, withdrawn, or
fails to apply, and are replayable through `SubscribeFromEvent` when
`[event_history].enabled = true` (they are not replayed by `ListFibRoutes`).
EVPN events are sourced from the RIB's EVPN best-path broadcast and are also
retained in a bounded `ListEvpnEvents` process-local history ring.
The FIB `rejected` count reflects surfaced status rows; high-cardinality
`route_limit_exceeded` rows carry `ListFibRoutes` sampling metadata with
suppressed-row totals, so the event count itself is not a global
suppressed-route total. Empty category and type filters subscribe to
the default route + session live stream. A non-empty type filter narrows the
stream; `BGP_EVENT_TYPE_POLICY_CHANGED`,
`BGP_EVENT_TYPE_DATAPLANE_STATUS_CHANGED`, an ADR-0061 per-route dataplane
event type, an EVPN route event type, or a `BGP_EVENT_TYPE_BFD_SESSION_*` type
with empty categories selects the corresponding opt-in stream, and
`EVENT_CATEGORY_POLICY`, `EVENT_CATEGORY_DATAPLANE`, `EVENT_CATEGORY_EVPN`, or
`EVENT_CATEGORY_BFD` selects those streams explicitly. Transport sessions send ordinary
state-change lifecycle events over
a bounded channel that is separate from the lossless TCP collision-coordination
path, so high churn can drop observability events without risking collision
handling. Live lag warnings emit for route, session, per-route dataplane, EVPN,
and BFD sources, but not policy or peerless dataplane; durable lag is global.
Prefix and family
filters match unicast route events and per-route FIB dataplane events; session,
policy, EVPN, BFD, and peerless dataplane summary events do not match requests
that set `prefix` or `afi_safi`. Peer filters match route, session, EVPN, BFD,
and per-route FIB dataplane events; route events also match
`target_peer_address` for `route_policy_filtered`. Peer filters do not match
peerless dataplane summary events. `BgpEvent` repeats common fields such as peer, target peer,
prefix, type, and severity at the top level even when the payload also carries
them so category-agnostic clients can render or filter events without unpacking
the `oneof`.

`ListSessionEvents` accepts `neighbor_address`, lifecycle-only `event_types`,
and `limit` filters. Valid `event_types` are the seven session lifecycle types:
`BGP_EVENT_TYPE_SESSION_STATE_CHANGED`, `BGP_EVENT_TYPE_SESSION_ESTABLISHED`,
`BGP_EVENT_TYPE_SESSION_LOST`, `BGP_EVENT_TYPE_PEER_ADDED`,
`BGP_EVENT_TYPE_PEER_REMOVED`, `BGP_EVENT_TYPE_PEER_ENABLED`, and
`BGP_EVENT_TYPE_PEER_DISABLED`. Empty `event_types` means all seven lifecycle
types. NOTIFICATION sent/received types are not retained in the history ring
and are rejected here with `INVALID_ARGUMENT`; subscribe to `WatchEvents` with
`BGP_EVENT_TYPE_NOTIFICATION_SENT` / `BGP_EVENT_TYPE_NOTIFICATION_RECEIVED`
for live NOTIFICATION metadata. Route event types are likewise rejected; use
`RibService.ListRouteEvents` for route history. The history ring holds at most
4096 events; `limit = 0` requests that full bounded daemon window, and larger
values are clamped to the same ceiling. Responses contain the most recent
matching events, ordered oldest-to-newest within that selected recent window.

`ListPolicyEvents` accepts `neighbor_address`,
`BGP_EVENT_TYPE_POLICY_CHANGED`, and `limit` filters. Empty `event_types`
means all policy event types, which is currently equivalent to
`BGP_EVENT_TYPE_POLICY_CHANGED`; route, session, dataplane, and
`stream_lagged` event types are rejected with `INVALID_ARGUMENT`. A peer
filter matches only peer-scoped policy mutations such as neighbor import/export
chain changes; global policy, neighbor-set, peer-group, and global-chain
mutations are peerless and do not match a `neighbor_address` filter. The
history ring holds at most 4096 events, is process-local, and resets on daemon
restart.

`ListEvpnEvents` accepts `neighbor_address`, EVPN route-event `event_types`,
`route_type_filter`, `rd_filter`, and `limit`. Valid event types are
`BGP_EVENT_TYPE_EVPN_ROUTE_ADDED`,
`BGP_EVENT_TYPE_EVPN_ROUTE_WITHDRAWN`, and
`BGP_EVENT_TYPE_EVPN_ROUTE_BEST_CHANGED`; empty `event_types` means all three.
The peer filter matches both the current and previous best-path peer so
withdrawals and best-path moves away from a peer remain visible to
peer-scoped dashboards. `route_type_filter` accepts RFC 7432 / RFC 9136 route
types 1 through 5, and `rd_filter` uses the same display format as
`ListEvpnRoutes`. The history ring holds at most 4096 events, is process-local,
and resets on daemon restart.

Slow live-stream consumers do not block the daemon. If a `WatchEvents`,
`WatchRouteEvents`, or `WatchRoutes` subscriber falls behind the bounded
broadcast channel, missed events are skipped and
`bgp_event_stream_lagged_total{service,source}` records the missed count.
`WatchRouteEvents` emits an in-band `stream_lagged` warning; `WatchEvents`
emits one for route, session, per-route dataplane, EVPN, and BFD sources.
Policy and peerless dataplane lag is metric-only and discarded without an
in-band warning. Use
`bgp_event_stream_subscribers{service,source}` to see active stream readers and
`bgp_route_event_history_depth` /
`bgp_route_event_history_capacity` to understand how much recent unicast route
history is available through `ListRouteEvents`. See
[`docs/OPERATIONS.md`](OPERATIONS.md#grpc-authorization-audit-and-resource-guardrails)
for alerting guidance that combines these stream metrics with ADR-0064
authorization decision volume.

Unified event types:

| Type | Meaning |
|------|---------|
| `BGP_EVENT_TYPE_ROUTE_ADDED` | Best path for a prefix was added |
| `BGP_EVENT_TYPE_ROUTE_WITHDRAWN` | Best path for a prefix was withdrawn |
| `BGP_EVENT_TYPE_ROUTE_BEST_CHANGED` | Best path for a prefix changed |
| `BGP_EVENT_TYPE_SESSION_STATE_CHANGED` | BGP FSM state changed; payload carries old/new state and session role |
| `BGP_EVENT_TYPE_SESSION_ESTABLISHED` | FSM reached `Established` |
| `BGP_EVENT_TYPE_SESSION_LOST` | FSM left `Established`; severity is `WARNING` |
| `BGP_EVENT_TYPE_PEER_ADDED` | Peer entered the authoritative managed set; payload carries new state `idle` and the exact scoped peer label |
| `BGP_EVENT_TYPE_PEER_REMOVED` | Peer left the authoritative managed set after session retirement; payload carries no FSM state or role and preserves the exact scoped peer label |
| `BGP_EVENT_TYPE_PEER_ENABLED` | Operator enabled a configured peer |
| `BGP_EVENT_TYPE_PEER_DISABLED` | Operator disabled a configured peer |
| `BGP_EVENT_TYPE_NOTIFICATION_SENT` | rustbgpd sent a BGP NOTIFICATION; payload carries direction, code, subcode, description, session role, and optional RFC 8203 shutdown reason |
| `BGP_EVENT_TYPE_NOTIFICATION_RECEIVED` | rustbgpd received a BGP NOTIFICATION from the peer; payload carries the same metadata |
| `BGP_EVENT_TYPE_BFD_SESSION_UP` | BFD session transitioned to Up |
| `BGP_EVENT_TYPE_BFD_SESSION_DOWN` | BFD session transitioned to Down |
| `BGP_EVENT_TYPE_BFD_SESSION_STATE_CHANGED` | BFD session changed state; payload carries peer, state, diagnostic, and strict flag |

NOTIFICATION events are metadata-only. Raw NOTIFICATION packet data remains
limited to BMP peer-down handling; `WatchEvents` does not retain or replay it.
`NotificationEvent.shutdown_reason` (RFC 9003) is peer-supplied free text
delivered verbatim over the API — it can legally contain ANSI escape sequences
as valid UTF-8, so consumers rendering it to a terminal must sanitize it;
rustbgpd's own CLI and log paths already escape it.

Stream health event types:

| Type | Meaning |
|------|---------|
| `BGP_EVENT_TYPE_STREAM_LAGGED` | Live: source-scoped route, session, per-route dataplane, EVPN, or BFD loss. Durable: a global outbox gap compatible with every category. |

Policy event types:

| Type | Meaning |
|------|---------|
| `BGP_EVENT_TYPE_POLICY_CHANGED` | Runtime policy, neighbor-set, peer-group, or chain mutation accepted by the peer manager. Payload carries operation, target type, target, optional peer address, and affected peer count. This is a runtime-applied audit signal; config-file persistence is a separate path. |

Dataplane event types:

| Type | Meaning |
|------|---------|
| `BGP_EVENT_TYPE_DATAPLANE_STATUS_CHANGED` | FIB / BLACKHOLE installed, rejected, or failed status-row count changed |
| `BGP_EVENT_TYPE_DATAPLANE_ROUTE_INSTALLED` | ADR-0061 FIB runtime successfully installed or replaced one route |
| `BGP_EVENT_TYPE_DATAPLANE_ROUTE_WITHDRAWN` | ADR-0061 FIB runtime successfully removed one owned route |
| `BGP_EVENT_TYPE_DATAPLANE_ROUTE_FAILED` | ADR-0061 FIB runtime failed to apply one route operation; severity is `WARNING` |

---

## InjectionService

Programmatic route injection and withdrawal. Injected routes appear as locally
originated (peer address `0.0.0.0`) and are advertised to all peers (subject to
export policy).

| RPC | Description |
|-----|-------------|
| `AddPath` | Inject a route with specified attributes |
| `DeletePath` | Withdraw a previously injected route |
| `AddFlowSpec` | Inject a FlowSpec rule with actions |
| `DeleteFlowSpec` | Withdraw a previously injected FlowSpec rule |
| `AddEvpnRoute` | Inject an EVPN Type 2 (MAC/IP), Type 3 (IMET), or Type 5 (IP Prefix) route; Type 5 may be interface-less or carry an overlay-index gateway |
| `DeleteEvpnRoute` | Withdraw a previously injected EVPN route by its EVPN route key |

### Inject an IPv4 route

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{
    "prefix": "10.99.0.0",
    "prefix_length": 24,
    "next_hop": "10.0.0.1",
    "communities": [4259905793]
  }' \
  localhost:50051 rustbgpd.v1.InjectionService/AddPath
```

### Inject an IPv6 route

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{
    "prefix": "2001:db8:ff::",
    "prefix_length": 48,
    "next_hop": "fd00::1",
    "origin": 0,
    "as_path": [65001],
    "local_pref": 100
  }' \
  localhost:50051 rustbgpd.v1.InjectionService/AddPath
```

Optional fields: `as_path`, `origin`, `local_pref`, `med`, `communities`, `extended_communities`, `large_communities`, `path_id`.

The `prefix` and `next_hop` fields accept both IPv4 and IPv6 addresses. Prefix
length is validated against the address family (max 32 for IPv4, 128 for IPv6).
`path_id` defaults to `0` (default path) when omitted.

### Withdraw a route

```bash
# IPv4
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"prefix": "10.99.0.0", "prefix_length": 24}' \
  localhost:50051 rustbgpd.v1.InjectionService/DeletePath

# IPv6
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"prefix": "2001:db8:ff::", "prefix_length": 48}' \
  localhost:50051 rustbgpd.v1.InjectionService/DeletePath
```

### Inject a FlowSpec rule

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{
    "afi_safi": "ADDRESS_FAMILY_IPV4_FLOWSPEC",
    "components": [
      { "type": 1, "prefix": "203.0.113.0/24" },
      { "type": 4, "value": "=80" }
    ],
    "actions": [
      { "traffic_rate": { "rate": 0.0 } }
    ]
  }' \
  localhost:50051 rustbgpd.v1.InjectionService/AddFlowSpec
```

### Withdraw a FlowSpec rule

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{
    "afi_safi": "ADDRESS_FAMILY_IPV4_FLOWSPEC",
    "components": [
      { "type": 1, "prefix": "203.0.113.0/24" },
      { "type": 4, "value": "=80" }
    ]
  }' \
  localhost:50051 rustbgpd.v1.InjectionService/DeleteFlowSpec
```

FlowSpec component lists must be non-empty, in ascending type-code order,
and limited to the supported RFC 8955 / RFC 8956 unicast component set.
Each injected or withdrawn rule must also encode to at most 4095 NLRI
payload bytes; larger rules are rejected with `InvalidArgument`.

### Inject an EVPN Type 2 (MAC/IP) route

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{
    "route_type": 2,
    "rd": "65000:100",
    "ethernet_tag": 0,
    "mac": "02:00:00:aa:bb:cc",
    "ip": "10.0.0.5",
    "label": 100,
    "next_hop": "10.0.0.2",
    "route_targets": ["65000:100"]
  }' \
  localhost:50051 rustbgpd.v1.InjectionService/AddEvpnRoute
```

`disable_vxlan_encap` defaults to `false` — the RFC 8365 §5.1.2 VXLAN
Encapsulation extended community (tunnel-type=8) is attached
automatically. Set `disable_vxlan_encap: true` for MPLS-over-GRE
deployments. The injection API supports `route_type` 2 (MAC/IP), 3
(IMET), and 5 (IP Prefix). Type 5 injection can use the default
interface-less gateway-zero shape or an explicit overlay-index
Gateway Address. Native Gate 9 Type 5
origination from `[[evpn_ip_vrfs]]` shipped in v0.18.0 (slice 6 PR A
#77): the daemon dumps kernel routes per
IP-VRF `table_id`, classifies them (connected/static/manual only —
routes installed by other routing daemons or whose output device is
the L3 VXLAN are filtered), and originates a Type 5 per surviving
prefix when the IP-VRF's readiness probe says `Ready`. Remote
Type 5 import + L3 FIB programming (kernel route + neighbor +
L3VXLAN FDB) shipped in v0.18.0 (slice 6 PR B #78) through the
transactional `L3OwnedState` model with four-phase apply ordering,
Router MAC conflict detection, and foreign-state preservation;
`RTNLGRP_IPV4_ROUTE` / `RTNLGRP_IPV6_ROUTE` multicast (#79) drives
sub-second withdraw on tenant `ip addr del`.
Native Type 1/4 multi-homing origination is driven by
`[[ethernet_segments]]`; the injection API does not expose those route
types yet (the RR still reflects them when received from peers).

### Inject an EVPN Type 3 (IMET) route

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{
    "route_type": 3,
    "rd": "65000:100",
    "ethernet_tag": 0,
    "ip": "10.0.0.2",
    "next_hop": "10.0.0.2"
  }' \
  localhost:50051 rustbgpd.v1.InjectionService/AddEvpnRoute
```

### Inject an EVPN Type 5 (IP Prefix) route

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{
    "route_type": 5,
    "rd": "65000:5000",
    "ethernet_tag": 0,
    "prefix": "10.50.0.0",
    "prefix_length": 24,
    "label": 5000,
    "next_hop": "192.0.2.10",
    "router_mac": "02:00:00:00:50:00",
    "route_targets": ["65000:5000"]
  }' \
  localhost:50051 rustbgpd.v1.InjectionService/AddEvpnRoute
```

By default, Type 5 injection is interface-less: ESI and Gateway IP are
encoded as zero, `label` carries the L3VNI in the RFC 8365 VXLAN label
slot, `ethernet_tag` must be 0, and `next_hop` is the VTEP loopback.
Set optional `gateway` to inject a controller-supplied overlay-index
Type 5 route with a non-zero **unicast** Gateway Address; the prefix,
gateway, and next-hop must use the same IP family. Non-zero ESI
overlay-index injection is not exposed. `router_mac` is required when VXLAN
encapsulation is enabled (the default) and is advertised as the RFC
9135 Router MAC extended community. Omit it when
`disable_vxlan_encap` is true. At least one `route_targets` entry is
required for Type 5 injection.

### Withdraw an EVPN route

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{
    "route_type": 2,
    "rd": "65000:100",
    "ethernet_tag": 0,
    "mac": "02:00:00:aa:bb:cc",
    "ip": "10.0.0.5"
  }' \
  localhost:50051 rustbgpd.v1.InjectionService/DeleteEvpnRoute
```

The withdrawal key (route type + RD + ethernet tag + MAC + optional IP
for Type 2; route type + RD + ethernet tag + originator IP for Type 3;
route type + RD + `ethernet_tag=0` + prefix/prefix length for Type 5)
matches the EVPN route identity used by rustbgpd. Type 5 gateway is
payload, not part of the local route key.
Omit `ip` when withdrawing a MAC-only Type 2 route or the key will not
match. Requests that include key fields from another route type are
rejected with `INVALID_ARGUMENT`. Returns `NOT_FOUND` if no such route
was previously injected.

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{
    "route_type": 5,
    "rd": "65000:5000",
    "ethernet_tag": 0,
    "prefix": "10.50.0.0",
    "prefix_length": 24
  }' \
  localhost:50051 rustbgpd.v1.InjectionService/DeleteEvpnRoute
```

---

## ControlService

Daemon lifecycle, health checks, and metrics.

| RPC | Description |
|-----|-------------|
| `GetHealth` | Returns health status, uptime, active peers, total routes; core actor probes are bounded by the same 200 ms deadline as HTTP `/readyz` |
| `GetMetrics` | Returns Prometheus metrics as text |
| `Shutdown` | Initiates graceful shutdown |
| `TriggerMrtDump` | Triggers an on-demand MRT TABLE_DUMP_V2 dump |

### Health check

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.ControlService/GetHealth
```

If `[global.telemetry] prometheus_addr` is configured, the same HTTP listener
also exposes unauthenticated probe endpoints:

```bash
curl -fsS http://127.0.0.1:9179/livez
curl -fsS http://127.0.0.1:9179/readyz
```

`/livez` only proves the process is accepting HTTP connections. `/readyz`
returns `200 ready` when PeerManager and RIB respond within 200 ms total, or
`503 not ready: <reason>` when either core actor is unavailable, drops its
reply, or times out. During an actor-owned export-policy transition the
dedicated read-only RIB lane stays healthy for bounded progress, then returns
`503 not ready: RIB export-policy transition stalled` if ownership reaches 30
seconds; commit or cleaned-up fallback restores readiness immediately. It does
not require peers or routes to exist.

### Get Prometheus metrics via gRPC

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.ControlService/GetMetrics
```

### Graceful shutdown

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"reason": "maintenance window"}' \
  localhost:50051 rustbgpd.v1.ControlService/Shutdown
```

### Trigger MRT dump

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.ControlService/TriggerMrtDump
```

---

## EvpnService

Local EVPN state and bounded controls for this VTEP. Empty read
responses are normal when the daemon is acting purely as an EVPN
route reflector — RR mode does not declare local instances. The same
`[[evpn_instances]]` table that this service exposes is the input to the Linux kernel
reconciler (Gate 7b, ADR-0054 — programs remote-MAC FDB entries
downward), the local-MAC originator + Type 3 IMET emitter (Gate 7b+1,
ADR-0055 — emits Type 2 / Type 3 routes upward from kernel-learned
state), the Gate 8 segment/DF orchestrator, and the Gate 9 Type 5 /
IP-VRF path. The originators and dataplane actors bypass this gRPC
surface; they translate kernel/RIB events directly into reconcile
inputs and `RibUpdate::InjectEvpn` / `WithdrawEvpn` against the RIB.
See ADR-0052 for the original boundary, ADR-0054/ADR-0055 for the
dataplane + origination boundaries, and ADR-0063 for the runtime mutation
semantics used by both `ApplyEvpnRuntime` and SIGHUP reload.

| RPC | Description |
|-----|-------------|
| `GetEvpnRuntime` | Return the committed EVPN runtime generation, lifecycle, mutation state, configured EVI/IP-VRF/ES counts, and a concise status message |
| `ListEvpnInstances` | List configured local EVPN instances sorted by VNI (vni, rd, resolved route_targets including any auto-derived RT, local_vtep_ip, optional bridge, optional local `bridge_vlan`, advertise_svi_mac flag, originated_local_macs_count, L2 dataplane `readiness_state`, and `not_ready_reason` when NotReady) |
| `ListEvpnNexthops`  | List Linux dataplane reconciler-owned ADR-0059 FDB nexthop groups (per-VNI groups with ESI / Ethernet Tag / kernel group ID, per-VTEP member nexthop IDs + gateways, MAC refs) plus top-level orphan-NH count, pending-delete count, and the `drift_recovery_disabled` latch — read-only operator visibility |
| `ListEthernetSegments` | List configured Ethernet Segments sorted by ESI, joined with live multi-homing state: composed drain reasons, per-member DF role and BUM forwarding action, same-ESI local-bias eligibility, whole-port AC-gate state/interface, and matching FDB-NHG group / MAC-ref counts — read-only ADR-0083/0085 diagnose visibility |
| `ListIpVrfs`        | List configured IP-VRFs / L3VNI tenants (name, l3vni, rd, resolved route_targets including any auto-derived RT, local_vtep_ip, router_mac, optional `evpn_instance` link, readiness state, originated_routes_count, installed_routes_count, remote_prefix_drop_counts) — Gate 9 / ADR-0058 |
| `ListManagedNetdevs` | List configured ADR-0091 managed EVPN bridge, fixed-VNI VXLAN, SVD / collect-metadata VXLAN, VLAN upper, VRF, and L3VXLAN rows joined with the latest Linux link snapshot, plus rustbgpd-stamped orphan/unsafe rows for the configured owner. Reports class, name, desired flag, ownership stamp, state (`desired-absent`, `owned-safe`, `foreign-present`, `owned-unsafe`, `orphaned`, or `unknown`), observed ifindex, bridge `vlan_filtering`, VXLAN/SVD/L3VXLAN `vni` / `local` / `dstport` / `learning` / `collect-metadata` / `vnifilter` / master attributes, VLAN upper `vlan`, VRF `table_id`, L3VXLAN `router_mac`, observed rustbgpd ownership stamps, and reason text. Bridge, fixed-VNI VXLAN, SVD VXLAN, VLAN upper, VRF, and L3VXLAN lifecycle execution is active in the dataplane actor; this RPC remains read-only status. |
| `GetIpVrf`          | Detail view of a single IP-VRF including the seven readiness predicates (`not_ready_reasons`) when `readiness_state != Ready` and scoped remote Type 5 projection-drop counts |
| `ClearDuplicateMacQuarantine` | Clear one RFC 7432 §15.1 duplicate-MAC local-origin quarantine by `(vni, mac)`. Returns `cleared=false` when no active quarantine exists; read-only listeners reject it. |
| `ApplyEvpnRuntime` | Validate or apply a full candidate EVPN runtime model through the ADR-0063 coordinator. `validate_only=true` returns the plan without mutation; no-op applies succeed. Supported live changes include single L2VNI/IP-VRF/Ethernet-Segment add/delete/redefine, additive build-up, atomic tenant teardown, `ip_vrf` relink, and decomposable mixed edits ordered as deletes -> redefines -> `ip_vrf` relinks -> adds. When a segment actor already exists, L2VNI add/delete republishes the current instance table so later ES add/redefine can bind a VNI added at runtime; ES-member L2VNI redefine rebuilds the segment actor's Type 1/4 routes from the candidate instance snapshot. L3VNI/device/table IP-VRF identity changes remain restart-required by design. Unsupported dependency cycles fail closed before commit; residual mid-sequence convergence failures fail-stop after already committed generations and are surfaced by `evpn_runtime_decomposed_fail_stops_total`. |

Instance mutation (`AddEvpnInstance` / `DeleteEvpnInstance`) remains out
of scope. `GetEvpnRuntime` now reports the daemon-owned ADR-0063
coordinator generation. At startup this is generation `1`, lifecycle
`active`, and mutation state `idle` when the coordinator is available.
`ApplyEvpnRuntime` accepts a full candidate rustbgpd TOML document so the
daemon can reuse the normal config parser, validator, and EVPN table
resolution. Because that TOML may contain unrelated credentials, audit
logs record only its byte length and mode. Runtime mutation is not a
shared-table swap: it drives the live IMET controller, the
MAC-only/MAC+IP/SVI Type 2 originators, the Type 5/IP-VRF originator, and
the Linux dataplane supervisor through ordered convergence commands with
rollback on partial failure.

Supported non-noop shapes converge live and commit the next generation:
single L2VNI/IP-VRF/Ethernet-Segment add/delete/redefine, additive build-up,
atomic tenant teardown, `ip_vrf` relink, and decomposable mixed edits. The
mixed-edit decomposer applies primitive commits in a fixed order — deletes,
redefines, `ip_vrf` relinks, then adds — so operators may observe multiple
runtime generations for one SIGHUP or `ApplyEvpnRuntime` request. ES
add/redefine can reference a member VNI added by an earlier live L2VNI add when
the segment actor is already running; ES-member L2VNI redefine rebuilds Type 4 /
EAD-per-ES / EAD-per-EVI routes from the candidate instance snapshot while
retaining the stable ESI label. L3VNI/device/table IP-VRF identity changes
remain restart-required by design. Unsupported dependency cycles fail closed
before commit. If a later primitive step or actor command fails after earlier
steps committed, the sequence fail-stops there: the committed generations stay
visible, the coordinator pins `mutation_state=Failed`, an ERROR log names the
step, and `evpn_runtime_decomposed_fail_stops_total` increments for the
mid-sequence stop.

Operators configure instances via the `[[evpn_instances]]` TOML block.
SIGHUP reload submits EVPN table edits through the same coordinator for
supported ADR-0063 shapes. Unsupported dependency cycles, L3VNI/device/table
IP-VRF identity changes, or missing EVPN actors fail closed before commit.
Actor convergence failures inside a decomposed sequence fail-stop on the last
committed generation and keep the drift visible instead of silently advancing
the config snapshot.

### Get EVPN runtime status

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.EvpnService/GetEvpnRuntime
```

Or via CLI:

```bash
rbgp evpn runtime           # human format
rbgp evpn runtime --json    # JSON output
```

### List local EVPN instances

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.EvpnService/ListEvpnInstances
```

Or via CLI:

```bash
rbgp evpn instances           # human format
rbgp evpn instances --json    # JSON output
rbgp evpn diagnose            # instance / Type 2 / Type 3 / metric summary
```

The human CLI includes `readiness=ready|not-ready|unbound|unknown`,
`originated-local-macs=N`, and `bridge-vlan=N` when the instance has a
local bridge VLAN binding; `not-ready` rows include the single L2
readiness probe reason. JSON exposes the same fields as `readiness`,
`originated_local_macs_count`, `not_ready_reason`, and `bridge_vlan`
(`null` when absent); gRPC exposes the enum as `readiness_state` and the
local VLAN binding as optional `bridge_vlan`. `Unbound` means no
`bridge` is configured for that L2VNI. `Unknown` means the instance is
bridge-bound but no dataplane verdict is on file yet, usually cold start
before the first reconcile report or an RR-only / dataplane-disabled
deployment. `originated_local_macs_count` counts MAC-only Type 2 routes
currently originated by this daemon for the instance and accepted by the
RIB. `bridge_vlan` is local Linux attribution only: EVPN Type 2 / Type 3 /
EAD-per-EVI routes still use Ethernet Tag ID `0`. When present, it
selects ADR-0089's traditional VNI-per-broadcast-domain VLAN-aware path:
the probe requires `vlan_filtering=1`, exactly one VXLAN member for the
instance VNI, and the configured VLAN on both the bridge and that VXLAN
member; remote-MAC FDB rows are then programmed with `NDA_VLAN`. A
`vlan_filtering=1` bridge without `bridge_vlan` remains `NotReady`.

### List EVPN FDB nexthop groups

ADR-0059 operator-visibility surface. Returns the Linux dataplane
reconciler's owned FDB nexthop-group state: one row per group with
VNI, ESI, Ethernet Tag, kernel group ID, per-VTEP member nexthop IDs,
and MAC refs. The response also includes orphan tagged nexthop count,
pending-delete count, and whether periodic drift recovery latched off
after a permanent dump failure.

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.EvpnService/ListEvpnNexthops
```

Or via CLI:

```bash
rbgp evpn nexthops          # human format
rbgp evpn nexthops --json   # JSON output
```

An empty `groups` list is normal on RR-only deployments, single-homed
VTEPs, or multi-homed VNIs with `apply_aliasing_ecmp = false` — the
top-level `orphan_nexthops_count`, `pending_delete_count`, and
`drift_recovery_disabled` fields are always populated regardless.

### List Ethernet Segments / multi-homing state

ADR-0083 / ADR-0085 diagnose surface. Returns one row per configured
`[[ethernet_segments]]` entry, optionally filtered by ESI. Each row
joins the committed ES config with the latest segment/dataplane
snapshots: drain reasons (`operator` / `link`), DF role and BUM action
per member VNI, same-ESI local-bias eligibility, the single-active
whole-port AC-gate state/interface, and matching owned FDB-NHG group /
MAC-ref counts. Empty runtime fields mean the segment actor or
dataplane has not published that snapshot yet; the RPC itself is
read-only.

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"esi":"00:11:22:33:44:55:66:77:88:99"}' \
  localhost:50051 rustbgpd.v1.EvpnService/ListEthernetSegments
```

Or via CLI:

```bash
rbgp evpn es list
rbgp evpn es list 00:11:22:33:44:55:66:77:88:99 --json
```

### List IP-VRFs / L3VNI tenants

Gate 9 / ADR-0058 surface. Returns one row per `[[evpn_ip_vrfs]]`
entry with the readiness verdict the EVPN reconcile actor most
recently published, plus the Type 5 origination / install counters and
current scoped remote Type 5 projection-drop counts. The drop counts
reuse the bounded reason labels from
`evpn_ip_vrf_remote_prefix_drops{vrf,reason}` and omit per-route
prefixes, gateways, next-hops, MACs, RDs, and RTs.

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.EvpnService/ListIpVrfs
```

Or via CLI:

```bash
rbgp evpn vrfs                  # human format
rbgp evpn vrfs --json           # JSON output
rbgp evpn vrfs vrf1             # single-VRF detail (matches GetIpVrf)
```

### List managed EVPN netdevs

ADR-0091 managed-netdev lifecycle/status surface. Returns configured
`[managed_netdevs]` bridge, fixed-VNI VXLAN, SVD / collect-metadata VXLAN,
VLAN upper, VRF, and L3VXLAN rows joined with the latest Linux link snapshot,
plus rustbgpd-stamped orphan links observed by the dataplane actor. This is
read-only status: a row can be `desired-absent`, `foreign-present`,
`owned-unsafe`, `owned-safe`, `orphaned`, or `unknown`. Bridge, fixed-VNI
VXLAN, SVD VXLAN, VLAN upper, VRF, and L3VXLAN rows are active lifecycle
intent inside the dataplane reconciler. The RPC itself never mutates links.

Bridge rows expose observed `vlan_filtering`. Fixed-VNI and SVD VXLAN rows
expose observed `vni`, `local`, `dstport`, `learning-disabled`,
`collect-metadata`, `vnifilter`, and bridge-master fields when the Linux link
snapshot reports them. VRF rows expose observed `table_id` and `up`. L3VXLAN
rows expose observed `vni`, `local`, `dstport`, `learning-disabled`,
`collect-metadata`, `vnifilter`, `vrf` master, `up`, and `router_mac`. VLAN
upper rows expose observed parent bridge, VLAN id, and link-up state.

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.EvpnService/ListManagedNetdevs
```

Or via CLI:

```bash
rbgp evpn managed-netdevs
rbgp evpn managed-netdevs --json
```

### Get IP-VRF detail

Returns the same row as `ListIpVrfs` plus, when `readiness_state` is
not `Ready`, the `not_ready_reasons` list — one entry per failing
ADR-0058 §3 predicate (e.g., `vrf_table_id_mismatch`,
`l3vxlan_router_mac_mismatch`). `remote_prefix_drop_counts` reports the
current bounded receive-side Type 5 projection drops for this IP-VRF.

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"name": "vrf1"}' \
  localhost:50051 rustbgpd.v1.EvpnService/GetIpVrf
```

### Clear duplicate-MAC quarantine

Clears local-origin suppression for one `(VNI, MAC)` after an operator
has confirmed the loop condition is gone. The RPC does not clear every
quarantine and does not remove Loc-RIB/RR visibility; if the MAC is
still locally present, the originator immediately replays the live
MAC-only or MAC+IP state through the normal recovery path.

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"vni": 100, "mac": "aa:bb:cc:dd:ee:ff"}' \
  localhost:50051 rustbgpd.v1.EvpnService/ClearDuplicateMacQuarantine
```

Or via CLI:

```bash
rbgp evpn clear-duplicate-mac --vni 100 --mac aa:bb:cc:dd:ee:ff
rbgp evpn clear-duplicate-mac --vni 100 --mac aa:bb:cc:dd:ee:ff --json
```

### Apply EVPN runtime candidate

Validates a full candidate rustbgpd TOML document against the committed
EVPN runtime model and returns a plan summary. Use `validate_only=true`
to inspect added/deleted/redefined/unchanged EVPN instances, IP-VRFs,
and Ethernet Segments — plus the `ip_vrf_references_changed` flag, which is
the only non-empty plan signal for a pure `ip_vrf` relink — without changing
the committed generation.

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d @ localhost:50051 rustbgpd.v1.EvpnService/ApplyEvpnRuntime <<'JSON'
{
  "candidate_toml": "[global]\nasn = 65000\nrouter_id = \"10.0.0.1\"\nlisten_port = 179\n\n[global.telemetry]\nlog_format = \"json\"\n\n[security.grpc]\nenforcement = \"legacy\"\n\n[[evpn_instances]]\nvni = 100\nrd = \"65000:100\"\nroute_targets = [\"65000:100\"]\nlocal_vtep_ip = \"10.0.0.1\"\n",
  "validate_only": true
}
JSON
```

A non-`validate_only` request commits when the candidate is a no-op, a
single L2VNI add, a single L2VNI delete that is not an Ethernet Segment member,
a single L2VNI redefine with unchanged `ip_vrf` link metadata, a single IP-VRF
add, a single standalone
IP-VRF delete with no L2VNI links, a single IP-VRF redefine with unchanged
L3VNI/device/table identity, a single Ethernet Segment add/delete/redefine,
additive build-up, an atomic tenant teardown, or an `ip_vrf` relink
against the committed model; the response
carries the committed generation and outcome. L3VNI/device/table IP-VRF identity changes remain restart-required by design.
Unsupported dependency cycles, an ES referencing an unknown member VNI, or an ES
apply with no running segment actor are rejected with `FAILED_PRECONDITION`
before commit; decomposable mixed edits may commit multiple generations and
fail-stop on a later primitive convergence failure as described above.

---

## BfdService

Read-only inspection of single-hop BFD sessions (ADR-0067, RFC 5880/5881).
Sessions themselves are configured via `[[bfd_profiles]]` + `[neighbors.bfd]`
(see [CONFIGURATION.md](CONFIGURATION.md)) — BFD config is restart-required, so
there is no mutating RPC here.

| RPC | Description |
|-----|-------------|
| `GetBfdSessions` | List BFD sessions (peer address, state, last diagnostic, strict flag, remote-AdminDown cause), optionally filtered to one `peer_address` |

```bash
# All BFD sessions
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.BfdService/GetBfdSessions

# One peer
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"peer_address": "10.0.0.2"}' \
  localhost:50051 rustbgpd.v1.BfdService/GetBfdSessions
```

`state` is a `BfdSessionState` (`BFD_SESSION_STATE_{ADMIN_DOWN,DOWN,INIT,UP}`).
`remote_administrative_down` is an explicit-presence boolean: `true` explains
that the peer disabled BFD and RFC 5882 section 4.1 permits BGP even though the
local BFD `state` remains `DOWN`; `false` means a current daemon observed no
such cause. An absent field means the serving daemon predates this visibility
and the cause is unknown—clients must not default absence to `false`.
Live state-change events are available on `EventService.WatchEvents` with
`EVENT_CATEGORY_BFD` (opt-in). RFC 5882 BGP coupling — strict (withhold BGP
until BFD Up) and non-strict (tear BGP down on BFD-down before the hold timer) —
is driven by `PeerManager` from these sessions; it is not exposed as a separate
RPC.

---

## Proto File

The full proto definition is at [`proto/rustbgpd.proto`](../proto/rustbgpd.proto).
You can generate typed clients for Python, Go, Rust, Node.js, or any language
with protobuf/gRPC support.
