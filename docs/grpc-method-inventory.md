# gRPC Method Inventory and Authorization Classification

**Status:** Accepted. Input artifact for ADR-0064 (gRPC authorization)
and mirrored in `crates/api/src/authz.rs`.
**Source:** `proto/rustbgpd.proto`.
**Machine-readable export:** `docs/grpc-method-inventory.json`.
**Maintenance:** Re-derive whenever an RPC is added, renamed, or
removed; the ADR's enforcement model assumes every method has a tier
assignment.

## Purpose

Today, gRPC authorization is listener-level. A configured
`access_mode = "read_only"` listener rejects mutating handlers, while
`access_mode = "read_write"` exposes the full service surface to any
client accepted by that listener's transport authentication (UDS
permissions, bearer token, and/or mTLS). ROADMAP P0 ("gRPC security
audit + authorization split") needs a method-level risk boundary, and
the v1.0 external security review needs a documented per-method
classification to audit.

This document is the inventory the ADR-0064 enforcement model maps
against. It does not pick the enforcement mechanism (RBAC vs.
capability tokens vs. proto-annotation tags vs. listener-tier split)
— that is the ADR's job. It only fixes the classification of each
RPC so the model has something concrete to assign roles to.

For external review, read this inventory together with
`docs/adr/0064-grpc-authorization.md` and
`docs/adr/0064-threat-model.md`. The threat model explains the
management-plane assets, trust boundaries, abuse paths, current controls,
and residual enforcement gaps behind the tier assignments.
Auditors and generated-client authors can consume the same classification from
`docs/grpc-method-inventory.json`; CI checks that JSON artifact against the
Rust source-of-truth table.

## Classification scheme

Every RPC is tagged with exactly one of four tiers. The criteria are
**worst-case effect on any accepted gRPC credential or principal**, not
nominal use.

| Tier | Definition | Worst-case if compromised |
|------|------------|---------------------------|
| `read` | Pure observability. No state change. No sensitive data exposed beyond what a peer in the same BGP mesh would already see. | Health-check spam. |
| `sensitive_read` | Read-only, but exposes operational topology, RIB contents, policy structure, metrics shape, or other data a defender would not want a tenant or untrusted automation to see. | Reconnaissance: peer addresses, AS topology, policy structure, route counts, RIB content, MAC tables. |
| `mutating` | Changes daemon config, peer state, or routing decisions. Reversible. Per-peer or per-object scope. | Route policy tampering, single-peer disable/flap, individual route injection. |
| `operator_only` | High-blast-radius operation: network-wide impact, process lifecycle, dataplane-affecting injection at scale, or persistent side effects (disk I/O, drain-all-peers). | Network-wide outage, traffic-filter installation at line rate, blackhole community injection, daemon shutdown. |

A method that fits two tiers takes the **higher** one. Streaming RPCs
inherit the tier of the underlying read or mutation; the streaming
shape itself does not raise the tier.

## Per-service inventory

### GlobalService (2 RPCs)

| RPC | Tier | Notes |
|-----|------|-------|
| `GetGlobal` | `sensitive_read` | Returns `GlobalState`: `asn`, `router_id`, `listen_port`, TCP-AO kernel-support probe. Topology disclosure. |
| `SetGlobal` | `operator_only` | Reserved; currently `UNIMPLEMENTED`. Future implementation would touch global daemon state, so classify defensively now to avoid the "we'll tag it later" trap. |

### ConfigService (1 RPC)

| RPC | Tier | Notes |
|-----|------|-------|
| `DiffRuntimeConfig` | `sensitive_read` | Response is redacted by design (per RPC comment), but the diff structure exposes policy layout, peer-group inheritance, and which fields differ between candidate and runtime. Request `candidate_toml` can contain credentials and must be omitted or masked by future audit logging. |

### NeighborService (11 RPCs)

| RPC | Tier | Notes |
|-----|------|-------|
| `AddNeighbor` | `mutating` | Reversible per-peer. Runtime neighbor creation does not currently accept TCP MD5 or TCP-AO key material over gRPC. |
| `DeleteNeighbor` | `mutating` | Single-peer scope. |
| `ListNeighbors` | `sensitive_read` | Returns full topology: addresses, ASNs, families, peer-group memberships, route-server flags, counters. No credentials in response. |
| `GetNeighborState` | `sensitive_read` | Single-peer detail; same shape as `ListNeighbors` element. |
| `EnableNeighbor` | `mutating` | Single-peer. |
| `DisableNeighbor` | `mutating` | Single-peer; causes one session flap. |
| `SoftResetIn` | `mutating` | Triggers RFC 7313 Route Refresh on one peer — heavy CPU + RIB churn but bounded. |
| `ListDynamicNeighbors` | `sensitive_read` | Topology disclosure for the dynamic-prefix accepted peers. |
| `AddDynamicNeighbor` | `mutating` | Adds an accept-prefix range. Wider than `AddNeighbor` (multi-peer effective), but still per-prefix scope. |
| `DeleteDynamicNeighbor` | `mutating` | Removes a prefix range; existing sessions inside the range tear down. |
| `SetGracefulShutdown` | `operator_only` | Network-wide when `address` is empty; listed here because the proto puts it in `NeighborService`. |

### PolicyService (18 RPCs)

| RPC | Tier | Notes |
|-----|------|-------|
| `ListPolicies` | `sensitive_read` | Exposes named policies, statements, actions, communities. |
| `GetPolicy` | `sensitive_read` | Single-policy detail. |
| `SetPolicy` | `operator_only` | Replaces a named policy and hot-applies every affected peer; a widely referenced policy can change routing decisions network-wide. |
| `DeletePolicy` | `mutating` | Per-name. Will fail if still referenced (typed error in the works). |
| `ListNeighborSets` | `sensitive_read` | Topology grouping disclosure. |
| `GetNeighborSet` | `sensitive_read` | Single-set detail. |
| `SetNeighborSet` | `operator_only` | Replaces a named match set and hot-applies every affected peer; a globally referenced set has network-wide policy impact. |
| `DeleteNeighborSet` | `mutating` | Per-name. |
| `GetGlobalPolicyChains` | `sensitive_read` | Global import/export chain structure. |
| `SetGlobalImportChain` | `operator_only` | Affects every neighbor without a per-peer override. Inbound-policy at the daemon scope. |
| `SetGlobalExportChain` | `operator_only` | Same shape, outbound side. |
| `ClearGlobalImportChain` | `operator_only` | Same scope, removal direction. |
| `ClearGlobalExportChain` | `operator_only` | Same. |
| `GetNeighborPolicyChains` | `sensitive_read` | Per-neighbor chain readout. |
| `SetNeighborImportChain` | `mutating` | Per-neighbor scope. |
| `SetNeighborExportChain` | `mutating` | Per-neighbor. |
| `ClearNeighborImportChain` | `mutating` | Per-neighbor. |
| `ClearNeighborExportChain` | `mutating` | Per-neighbor. |

### PeerGroupService (6 RPCs)

| RPC | Tier | Notes |
|-----|------|-------|
| `ListPeerGroups` | `sensitive_read` | Exposes group templates including inherited policy chain names; `md5_password` is redacted from read responses and represented by `has_md5_password`. |
| `GetPeerGroup` | `sensitive_read` | Single-group; `md5_password` is redacted from read responses and represented by `has_md5_password`. |
| `SetPeerGroup` | `operator_only` | Edits propagate to every neighbor inheriting the group — blast radius is N peers, not one. This is also the current gRPC-visible credential ingress for `md5_password`. |
| `DeletePeerGroup` | `operator_only` | Same propagation; will fail if any neighbor still references the group. |
| `SetNeighborPeerGroup` | `mutating` | Single-neighbor reassignment. |
| `ClearNeighborPeerGroup` | `mutating` | Single-neighbor. |

### RibService (12 RPCs)

| RPC | Tier | Notes |
|-----|------|-------|
| `ListReceivedRoutes` | `sensitive_read` | Per-peer received RIB — exposes upstream routing topology and reachability. |
| `ListBestRoutes` | `sensitive_read` | Daemon-level best paths. |
| `ListAdvertisedRoutes` | `sensitive_read` | Per-peer advertised RIB. |
| `ExplainAdvertisedRoute` | `sensitive_read` | Per-route policy evaluation trace; exposes policy decision logic. |
| `ExplainBestPath` | `sensitive_read` | Per-route best-path tie-break trace. |
| `ListBlackholeDiscards` | `sensitive_read` | Per-discard reasons; exposes RFC 7999 BLACKHOLE community installations. |
| `ListFibRoutes` | `sensitive_read` | ADR-0061 FIB status snapshot — exposes which routes are installed in the kernel. |
| `ListRouteEvents` | `sensitive_read` | Bounded route-event history. |
| `WatchRoutes` (stream) | `sensitive_read` | Live route-event stream. Streaming shape; same data as `ListRouteEvents`. |
| `WatchRouteEvents` (stream) | `sensitive_read` | Enveloped live route-event stream with explicit `stream_lagged` signals. |
| `ListFlowSpecRoutes` | `sensitive_read` | RFC 5575 flow-spec routes — discloses traffic filter installations. |
| `ListEvpnRoutes` | `sensitive_read` | EVPN Type 1/2/3/4/5 routes — MAC/IP topology, multi-homing ES layout. |

### EventService (4 RPCs)

| RPC | Tier | Notes |
|-----|------|-------|
| `WatchEvents` (stream) | `sensitive_read` | Unified stream — route events, session lifecycle, NOTIFICATION metadata, policy mutation summaries, EVPN route changes, FIB / BLACKHOLE dataplane status. Discloses operational state in real time. |
| `ListSessionEvents` | `sensitive_read` | Bounded session lifecycle history per peer. |
| `ListPolicyEvents` | `sensitive_read` | Bounded policy mutation history. |
| `ListEvpnEvents` | `sensitive_read` | Bounded EVPN route add / withdraw / best-change history. |

### InjectionService (6 RPCs)

| RPC | Tier | Notes |
|-----|------|-------|
| `AddPath` | `operator_only` | Originates a unicast route from the daemon. Can pollute the global table; can inject community-tagged routes (BLACKHOLE, GRACEFUL_SHUTDOWN, custom). |
| `DeletePath` | `operator_only` | Withdraws an originated route. Lower-impact than Add, but classifying the inverse separately gives a misleading defense surface — treat as the same risk class. |
| `AddFlowSpec` | `operator_only` | Installs RFC 5575 traffic-filter rules. Dataplane impact at line rate; one rule can drop or rate-limit arbitrary traffic. |
| `DeleteFlowSpec` | `operator_only` | Same risk class as Add. |
| `AddEvpnRoute` | `operator_only` | Originates EVPN Type 2/3/5; can blackhole an L2 segment by hijacking a MAC, or steer Type 5 traffic. |
| `DeleteEvpnRoute` | `operator_only` | Same risk class. |

### ControlService (4 RPCs)

| RPC | Tier | Notes |
|-----|------|-------|
| `Shutdown` | `operator_only` | Process termination. Worst-case outage primitive on the daemon. |
| `GetHealth` | `sensitive_read` | Liveness plus `active_peers` and `total_routes`; the counts reveal operational state and route volume. |
| `GetMetrics` | `sensitive_read` | Returns Prometheus-shaped counters; volumetric metadata leaks RIB size, peer count, churn rate. |
| `TriggerMrtDump` | `operator_only` | Writes a TABLE_DUMP_V2 snapshot to disk. Disk-I/O burst, potentially very large; also exposes RIB content to whoever can read the dump file later. |

### EvpnService (7 RPCs)

| RPC | Tier | Notes |
|-----|------|-------|
| `GetEvpnRuntime` | `sensitive_read` | ADR-0063 committed runtime generation, lifecycle, mutation state, and EVPN table counts. Exposes topology size and no mutating surface. |
| `ListEvpnInstances` | `sensitive_read` | Per-VNI state — VTEP addresses, RT/RD, originated MAC counts. |
| `ListEvpnNexthops` | `sensitive_read` | ADR-0059 FDB nexthop groups — exposes multi-homing topology, ES layout, drift-recovery status. |
| `ListIpVrfs` | `sensitive_read` | Gate 9 IP-VRF table. |
| `GetIpVrf` | `sensitive_read` | Single-VRF detail. |
| `ClearDuplicateMacQuarantine` | `mutating` | Clears one local duplicate-MAC suppression key and may replay still-live local MAC state. Reversible, per-`(VNI, MAC)` scope; not a route-injection primitive and not a clear-all. |
| `ApplyEvpnRuntime` | `mutating` | ADR-0063 full-candidate EVPN runtime validation/apply entry point. `validate_only` and no-op applies are bounded; the supported shapes converge live and commit a new generation (single L2VNI add/delete/redefine, single IP-VRF add/standalone-delete/redefine with unchanged L3VNI/device/table identity, single Ethernet Segment add/delete/redefine, atomic tenant teardown of an ES-member L2VNI + Ethernet Segment and/or linked IP-VRF in one pass, and `ip_vrf` relink), while L3VNI/device/table IP-VRF identity redefine (restart-required by design) and non-teardown mixed edits fail closed (issue #210). Request TOML can contain credentials and must be audit-redacted. |

## Totals

| Tier | Count | % |
|------|------:|--:|
| `read` | 0 | 0.0% |
| `sensitive_read` | 36 | 50.7% |
| `mutating` | 17 | 23.9% |
| `operator_only` | 18 | 25.4% |
| **Total** | **71** | **100%** |

(Counts treat `SetGracefulShutdown` as one RPC even though it appears once in `NeighborService`.)

## Notes for ADR-0064

These are the open questions the inventory surfaces that the ADR needs
to answer. The classification above is deliberately defensive ("when
in doubt, raise the tier") so the ADR can negotiate a lower tier for a
specific method if the model warrants it.

1. **Tier vs. service granularity.** Every service has at least one
   `sensitive_read` method, and there are currently no true `read`
   methods because even `GetHealth` returns peer and route counts.
   `RibService` and `EventService` are
   pure observability (no mutations at all). The minimum-viable
   enforcement could be a per-service listener split: read-only
   listener for those two plus lightweight health checks elsewhere,
   mutating listener for everything else. The 4-tier scheme allows
   richer enforcement (e.g., per-method capability tokens) but the
   per-service split is the cheapest first step.
2. **`operator_only` is small enough to gate by principal role.** 18
   methods total; carving these out into a separate listener or
   requiring a distinct principal role (`operator` vs. `automation`) has
   low operational cost and high blast-radius reduction.
3. **InjectionService is uniformly `operator_only`.** Six of the
   eighteen `operator_only` methods live here. The simplest model is
   to make the whole service gated behind an `inject` capability or a
   dedicated listener — operators rarely use it for automation, and
   when they do it should be a deliberate channel.
4. **Streaming methods need session-establishment authorization, not
   per-message.** `WatchEvents`, `WatchRouteEvents`, and `WatchRoutes` open once and live
   for the connection lifetime. The enforcement model needs to
   reject at handshake, not pretend to filter per-event.
5. **Credential ingress is narrow but not `AddNeighbor`.** The
   gRPC-visible credential-bearing field today is
   `PeerGroupDefinition.md5_password` through `SetPeerGroup`; static
   neighbor TCP-AO is TOML/runtime-only and is not exposed through
   gRPC. Read paths never echo secret material back:
   `ListPeerGroups` and `GetPeerGroup` redact `md5_password` instead
   of returning the stored value, while preserving a non-secret
   optional `has_md5_password` signal for safe read/modify/write
   preservation. `DiffRuntimeConfig` also accepts
   candidate TOML that may contain `md5_password` or `tcp_ao.key`;
   audit logging must omit or mask that request body. The model does
   not need a separate "credential-write" tier yet — `operator_only`
   plus mandatory audit redaction covers the current surface.
6. **Backwards compatibility.** Today's coarse listener access is
   what existing operators rely on. The ADR needs a migration mode
   (for example a `[security.grpc]` block that defaults to
   legacy-permissive but can opt into per-tier enforcement) so the
   cut-over is not a breaking change for everyone on the same
   release. That opt-in path shipped as slice-5a, and the production
   default flipped to `tier` in v0.24.0 (legacy is now the opt-out).
7. **`SetGlobal` is `UNIMPLEMENTED` today.** Classifying it
   `operator_only` now sets the design constraint for whoever lands
   the implementation — otherwise the natural temptation is to ship
   it as `mutating` because "it's just a write." Catching this
   pre-implementation is cheap; catching it post-CVE is not.
8. **Audit logging.** The runtime now emits tier-decision logs and the
   low-cardinality `bgp_grpc_authz_decisions_total` metric for every RPC;
   listener `max_tier` denials use the bounded
   `result="listener_tier_denied"` label, and unauthenticated over-cap probes
   use `result="authn_failed"` without exposing tier details. Forwarded calls
   emit result-aware bounded labels such as `handler_ok` and
   `handler_invalid_argument`. mTLS listeners derive the audit principal from
   the client certificate (URI SAN → email SAN → Subject CN); non-mTLS
   listeners still emit operator-controlled principal labels.
   In opt-in tier mode, `principal_unmapped` and `role_tier_denied`
   distinguish role-map denials from listener caps. `DiffRuntimeConfig`
   and `SetPeerGroup` request summaries mask
   credential-bearing fields, including candidate TOML that may contain
   `md5_password` or `tcp_ao.key`. The default enforcement flip shipped in
   v0.24.0; the external review still needs durable audit sink / retention
   guidance and optional proto credential markers.

## Code matrix

`crates/api/src/authz.rs` contains the same 71-method classification
as a static Rust table. `docs/grpc-method-inventory.json` is the
machine-readable export for auditors, tooling, and generated clients. The
`authz` tests parse `proto/rustbgpd.proto` and fail if a new RPC is added
without a tier assignment; they also parse the JSON export and fail if it drifts
from `crates/api/src/authz.rs`.

## Maintenance

When adding a new RPC:

1. Add the row to the appropriate per-service table.
2. Pick the tier defensively (higher when in doubt; the ADR will
   negotiate down if warranted).
3. Add the corresponding row to `docs/grpc-method-inventory.json` and bump
   `method_count` / `tier_counts`.
4. Run `cargo test -p rustbgpd-api authz --no-fail-fast`; this verifies proto
   coverage and JSON drift.
5. Open a follow-up review-PR against ADR-0064 if the new RPC
   doesn't fit cleanly in one tier — that signals the model needs an
   extension, not just a row addition.
