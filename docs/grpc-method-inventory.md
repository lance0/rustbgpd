# gRPC Method Inventory and Authorization Classification

**Status:** Accepted. Input artifact for ADR-0064 (gRPC authorization)
and mirrored in `crates/api/src/authz.rs`.
**Source:** `crates/api/src/authz.rs`, covering `proto/rustbgpd.proto`
plus vendored OpenConfig gNMI service definitions.
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

### GlobalService (1 RPC)

| RPC | Tier | Notes |
|-----|------|-------|
| `GetGlobal` | `sensitive_read` | Returns `GlobalState`: `asn`, `router_id`, `listen_port`, TCP-AO kernel-support probe. Topology disclosure. |

### ConfigService (7 RPCs)

| RPC | Tier | Notes |
|-----|------|-------|
| `DiffRuntimeConfig` | `sensitive_read` | Response is redacted by design (per RPC comment), but the diff structure exposes policy layout, peer-group inheritance, and which fields differ between candidate and runtime. Request `candidate_toml` can contain credentials and is audit-redacted (size and presence only, never the body) by `diff_runtime_config_summary`. |
| `PlanConfigTransaction` | `sensitive_read` | Validate-only transaction planner. It returns a redacted diff, runtime snapshot token, v1 section classification, and `update_group_impact` topology projection without mutating daemon state. Request `candidate_toml` can contain credentials and must be audit-redacted. |
| `ApplyConfigTransaction` | `operator_only` | Commit entry point for ADR-0076 config transactions. Currently commits one pure runtime family at a time: full-set `[[fib_tables]]`, full-set `[[dynamic_neighbors]]`, static `[[neighbors]]` add/delete/modify, catalog-only policy/neighbor-set/peer-group/global-chain changes, or pure live policy-chain impact for static neighbors and accepted dynamic peers. Live policy-chain impact requires impacted Established peers to have negotiated Route Refresh. Mixed-family and unsupported candidates are rejected without mutation. Request TOML and comment are audit-redacted. |
| `ConfirmConfigTransaction` | `operator_only` | Confirm a pending confirmed config transaction before its timeout expires. Confirms deployment reachability rather than reading config contents. |
| `AbortConfigTransaction` | `operator_only` | Abort a pending confirmed config transaction and roll back immediately through the transaction executor. |
| `GetConfigTransactionStatus` | `sensitive_read` | Returns redacted confirmed-transaction lifecycle status: pending/last state, confirm id, deadline, committed sections, and snapshot token, but never candidate TOML. |
| `GetEffectiveConfig` | `sensitive_read` | Returns the full effective running config as normalized TOML with defaults materialized (`rbgp config effective`). Whole-config disclosure: peer lists, policy structure, topology. Secret material (`md5_password`, `tcp_ao.key`) is replaced with `<redacted>` before the document leaves the daemon. |

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
| `DeleteDynamicNeighbor` | `mutating` | Removes a prefix range; stops future accepts only — established dynamic peers keep running and drain when they next return to Idle. |
| `SetGracefulShutdown` | `operator_only` | Network-wide when `address` is empty; listed here because the proto puts it in `NeighborService`. |

### PolicyService (22 RPCs)

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
| `ExplainImportPolicy` | `sensitive_read` | ADR-0073. Reads the per-session import-decision cache to explain why a prefix was permitted / denied / withdrawn on import. Side-effect-free; no RIB or counter mutation. |
| `ListRejectedRoutes` | `sensitive_read` | Enumerates a peer's retained rejected inbound routes with their reject-reason tokens and a compact attribute summary (`[policy.reject_retention]`, bounded per-peer LRU). Discloses policy structure and what a member announced. Side-effect-free; no RIB or counter mutation. |
| `TestPolicy` | `sensitive_read` | ADR-0096. Compiles a submitted .rpol policy server-side and dry-runs it read-only over a live-RIB snapshot (counts, per-term hits, before/after diffs). Side-effect-free; no RIB, session, or counter mutation. |
| `GetPolicyStats` | `sensitive_read` | ADR-0096 Decision 3.3. Snapshots the live per-term guard-hit counters of installed import/export chains (since chain install; reset on chain replace — import chains also report their install generation). Discloses policy structure and traffic shape. Side-effect-free; does not reset counters. |
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

### RibService (22 RPCs)

| RPC | Tier | Notes |
|-----|------|-------|
| `ListReceivedRoutes` | `sensitive_read` | Per-peer received RIB — exposes upstream routing topology and reachability. |
| `ListBestRoutes` | `sensitive_read` | Daemon-level best paths. |
| `ListAdvertisedRoutes` | `sensitive_read` | Per-peer advertised RIB. |
| `ExplainAdvertisedRoute` | `sensitive_read` | Per-route policy evaluation trace; exposes policy decision logic. |
| `ExplainBestPath` | `sensitive_read` | Per-route best-path tie-break trace. |
| `ListBlackholeDiscards` | `sensitive_read` | Per-discard reasons; exposes RFC 7999 BLACKHOLE community installations. |
| `ListFibRoutes` | `sensitive_read` | ADR-0061 FIB status snapshot — exposes which routes are installed in the kernel. |
| `SetFibTable` | `mutating` | Create-or-replace a `[[fib_tables]]` entry by name; hot-applies via the reconciler and persists. Programs kernel route tables. |
| `DeleteFibTable` | `mutating` | Remove a `[[fib_tables]]` entry by name; withdraws its kernel rows. |
| `ListFibTables` | `sensitive_read` | Configured FIB table set + runtime availability. |
| `ListRouteEvents` | `sensitive_read` | Bounded route-event history. |
| `WatchRoutes` (stream) | `sensitive_read` | Live route-event stream. Streaming shape; same data as `ListRouteEvents`. |
| `WatchRouteEvents` (stream) | `sensitive_read` | Enveloped live route-event stream with explicit `stream_lagged` signals. |
| `ListFlowSpecRoutes` | `sensitive_read` | RFC 5575 flow-spec routes — discloses traffic filter installations. |
| `ListEvpnRoutes` | `sensitive_read` | EVPN Type 1/2/3/4/5 routes — MAC/IP topology, multi-homing ES layout. |
| `ListBgpLsRoutes` | `sensitive_read` | RFC 9552 BGP-LS / BGP-LS VPN routes — controller-facing topology graph objects exposed as opaque NLRI/TLV bytes. |
| `ListVpnRoutes` | `sensitive_read` | RFC 4364/4659 VPNv4/VPNv6 routes — RD-scoped customer prefixes, Route Targets, MPLS labels. |
| `ListLabeledRoutes` | `sensitive_read` | RFC 8277 labeled-unicast (SAFI 4) routes in Loc-RIB view — MPLS label stack plus prefix reachability. |
| `ListRtcRoutes` | `sensitive_read` | RFC 4684 RT-Constrain membership NLRI — reveals which Route Targets each peer imports (VPN topology metadata). |
| `ListTopologyNodes` | `sensitive_read` | RFC 9107 ORR topology nodes built from the BGP-LS Adj-RIB-In union — discloses IGP node identity (AS, router-IDs). |
| `ListTopologyLinks` | `sensitive_read` | RFC 9107 ORR topology links — discloses IGP adjacencies, link addresses, and metrics (the SPF input). |
| `ListOrrStatus` | `sensitive_read` | RFC 9107 ORR per-vantage status — discloses configured vantage IPs (IGP locations), their resolved topology nodes, and the peers bound to them. |

### BfdService (1 RPC)

| RPC | Tier | Notes |
|-----|------|-------|
| `GetBfdSessions` | `sensitive_read` | ADR-0067 BFD session snapshot — peer addresses, state, diagnostics, and strict flag. |

### EventService (5 RPCs)

| RPC | Tier | Notes |
|-----|------|-------|
| `WatchEvents` (stream) | `sensitive_read` | Unified stream — route events, session lifecycle, NOTIFICATION metadata, policy mutation summaries, EVPN route changes, FIB / BLACKHOLE dataplane status. Discloses operational state in real time. |
| `ListSessionEvents` | `sensitive_read` | Bounded session lifecycle history per peer. |
| `ListPolicyEvents` | `sensitive_read` | Bounded policy mutation history. |
| `ListEvpnEvents` | `sensitive_read` | Bounded EVPN route add / withdraw / best-change history. |
| `SubscribeFromEvent` (stream) | `sensitive_read` | ADR-0072 durable cursor replay + live. Same disclosure scope as `WatchEvents` plus historical events from the durable outbox. Returns `FAILED_PRECONDITION` when `[event_history].enabled = false` or EHM is in pass-through mode; the legacy `WatchEvents` / `WatchRoutes` / `List*Events` surfaces are unaffected. |

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

### EvpnService (10 RPCs)

| RPC | Tier | Notes |
|-----|------|-------|
| `GetEvpnRuntime` | `sensitive_read` | ADR-0063 committed runtime generation, lifecycle, mutation state, and EVPN table counts. Exposes topology size and no mutating surface. |
| `ListEvpnInstances` | `sensitive_read` | Per-VNI state — VTEP addresses, RT/RD, optional local bridge / `bridge_vlan` binding, L2 dataplane readiness, and originated MAC counts. |
| `ListEvpnNexthops` | `sensitive_read` | ADR-0059 FDB nexthop groups — exposes multi-homing topology, ES layout, drift-recovery status. |
| `ListEthernetSegments` | `sensitive_read` | ADR-0083/0085 Ethernet Segment diagnose state — exposes configured ES membership, composed drain reasons, DF/BUM role rows, AC-gate state, same-ESI local-bias eligibility, and FDB-NHG refs. |
| `ListIpVrfs` | `sensitive_read` | Gate 9 IP-VRF table. |
| `ListManagedNetdevs` | `sensitive_read` | ADR-0091 managed EVPN netdev status — exposes desired bridge, fixed-VNI VXLAN, VLAN upper, VRF, and L3VXLAN names, ownership stamps, observed protected attributes, and orphan/foreign/unsafe state. |
| `GetIpVrf` | `sensitive_read` | Single-VRF detail. |
| `ClearDuplicateMacQuarantine` | `mutating` | Clears one local duplicate-MAC suppression key and may replay still-live local MAC state. Reversible, per-`(VNI, MAC)` scope; not a route-injection primitive and not a clear-all. |
| `SetEthernetSegmentDrain` | `operator_only` | ADR-0084 manual Ethernet Segment drain/undrain. Draining withdraws the ES's Type 4/EAD routes and the member VNIs' local Type 2 routes and suppresses new local-MAC origination — traffic-impacting origination control that redirects live customer traffic onto remote PEs' backup paths (a step above the per-key, restorative duplicate-MAC clear). Owns the `operator` drain reason only (ADR-0085): reasons compose, so the response's `drained` is the composed state and `reasons` lists what holds (an operator undrain does not override a `link` drain from the interface binding). Runtime-only and in-memory; restart clears it (bound segments re-evaluate carrier at startup). |
| `ApplyEvpnRuntime` | `mutating` | ADR-0063 full-candidate EVPN runtime validation/apply entry point. `validate_only` and no-op applies are bounded; supported shapes converge live and commit a new generation (single L2VNI/IP-VRF/Ethernet-Segment add/delete/redefine, additive build-up, atomic tenant teardown, `ip_vrf` relink, and decomposable mixed edits ordered as deletes -> redefines -> `ip_vrf` relinks -> adds). L3VNI/device/table IP-VRF identity redefine remains restart-required by design; unsupported dependency cycles fail closed before commit and later convergence failures fail-stop on the last committed generation. Request TOML can contain credentials and must be audit-redacted. |

### gnmi.gNMI (4 RPCs)

| RPC | Tier | Notes |
|-----|------|-------|
| `Capabilities` | `sensitive_read` | OpenConfig/gNMI model inventory and supported encodings. Discloses management-plane capabilities and telemetry shape. |
| `Get` | `sensitive_read` | Read-only OpenConfig BGP telemetry subset. Exposes AS/router-id, neighbor identity/state, counters, and other operational topology. |
| `Set` | `operator_only` | Transaction-backed OpenConfig config subset for static numbered-neighbor create/update/delete plus commit-confirmed control; unsupported paths and extensions return `UNIMPLEMENTED`. Operator-only because successful calls mutate durable config. |
| `Subscribe` (stream) | `sensitive_read` | Read-only OpenConfig BGP telemetry stream. Streaming shape; same disclosure class as `Get`. |

## Totals

| Tier | Count | % |
|------|------:|--:|
| `read` | 0 | 0.0% |
| `sensitive_read` | 58 | 58.6% |
| `mutating` | 19 | 19.2% |
| `operator_only` | 22 | 22.2% |
| **Total** | **99** | **100%** |

(Counts include `SetGracefulShutdown` as one `NeighborService` RPC; the 99
total is 95 native `rustbgpd.v1` RPCs plus 4 `gnmi.gNMI` RPCs.)

## Notes for ADR-0064

These are the open questions the inventory surfaces that the ADR needs
to answer. The classification above is deliberately defensive ("when
in doubt, raise the tier") so the ADR can negotiate a lower tier for a
specific method if the model warrants it.

1. **Tier vs. service granularity.** Every service has at least one
   `sensitive_read` method, and there are currently no true `read`
   methods because even `GetHealth` returns peer and route counts.
   `EventService` is pure observability (no mutations at all);
   `RibService` is read-only apart from the mutating `SetFibTable` /
   `DeleteFibTable` FIB-table CRUD pair (ADR-0074). The minimum-viable
   enforcement could be a per-service listener split: read-only
   listener for `EventService` plus the `RibService` read subset and
   lightweight health checks, mutating listener for everything else
   (including `SetFibTable` / `DeleteFibTable`). The 4-tier scheme allows
   richer enforcement (e.g., per-method capability tokens) but the
   per-service split is the cheapest first step.
2. **`operator_only` is small enough to gate by principal role.** 22
   methods total; carving these out into a separate listener or
   requiring a distinct principal role (`operator` vs. `automation`) has
   low operational cost and high blast-radius reduction.
3. **InjectionService is uniformly `operator_only`.** Six of the
   twenty-two `operator_only` methods live here. The simplest model is
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
   preservation. `DiffRuntimeConfig`, `PlanConfigTransaction`, and
   `ApplyConfigTransaction` also accept candidate TOML that may contain
   `md5_password` or `tcp_ao.key`; audit logging must omit or mask that
   request body. `ApplyConfigTransaction` also accepts a free-form comment
   that is not logged verbatim. The model does
   not need a separate "credential-write" tier yet — `operator_only`
   plus mandatory audit redaction covers the current surface.
6. **Backwards compatibility.** Today's coarse listener access is
   what existing operators rely on. The ADR needs a migration mode
   (for example a `[security.grpc]` block that defaults to
   legacy-permissive but can opt into per-tier enforcement) so the
   cut-over is not a breaking change for everyone on the same
   release. That opt-in path shipped as slice-5a, and the production
   default flipped to `tier` in v0.24.0 (legacy is now the opt-out).
7. **Audit logging.** The runtime now emits tier-decision logs and the
   low-cardinality `bgp_grpc_authz_decisions_total` metric for every RPC;
   listener `max_tier` denials use the bounded
   `result="listener_tier_denied"` label, and unauthenticated over-cap probes
   use `result="authn_failed"` without exposing tier details. Forwarded calls
   emit result-aware bounded labels such as `handler_ok` and
   `handler_invalid_argument`. mTLS listeners derive the audit principal from
   the client certificate (URI SAN → email SAN → Subject CN); non-mTLS
   listeners still emit operator-controlled principal labels.
   In opt-in tier mode, `principal_unmapped` and `role_tier_denied`
   distinguish role-map denials from listener caps. `DiffRuntimeConfig`,
   `PlanConfigTransaction`, `ApplyConfigTransaction`, and `SetPeerGroup`
   request summaries mask credential-bearing fields, including candidate TOML
   that may contain `md5_password` or `tcp_ao.key`. The default enforcement flip shipped in
   v0.24.0; the external review still needs durable audit sink / retention
   guidance and optional proto credential markers.

## Code matrix

`crates/api/src/authz.rs` contains the same 99-method classification
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
