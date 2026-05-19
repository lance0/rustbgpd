# gRPC API Reference

rustbgpd exposes ten gRPC services (Global, Config, Neighbor, Policy,
PeerGroup, Rib, Event, Injection, Control, Evpn) over one or more configured listeners. The
default listener is a local Unix domain socket at `/var/lib/rustbgpd/grpc.sock`.

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
at startup. Adding, removing, or rotating the TLS files is
**restart-required** — SIGHUP reload pins the runtime listener
config back to the live values and surfaces the drift in
`rustbgpd --diff` until the daemon is restarted.

```bash
# mTLS client example with grpcurl
grpcurl \
  -cacert /etc/rustbgpd/server-ca.pem \
  -cert /etc/operator/client.pem -key /etc/operator/client.key \
  -import-path . -proto proto/rustbgpd.proto \
  rustbgpd.example.net:50051 \
  rustbgpd.v1.GlobalService/GetGlobal
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
handler runs; the default remains `"legacy"` until the dedicated migration
slice flips it.
Forwarded calls emit result-aware labels such as `result="handler_ok"` or
`result="handler_invalid_argument"` after the handler returns. Rejected calls use
bounded pre-handler labels: `result="listener_tier_denied"` means the method was
rejected before the handler ran, and `result="authn_failed"` means an over-cap
bearer-token request failed authentication before tier details were disclosed.
Tier-mode denials use `result="principal_unmapped"` when the authenticated
principal has no role entry and `result="role_tier_denied"` when the principal's
role is below the method tier.
Credential-bearing request summaries are masked before entering `grpc_authz`
logs; `DiffRuntimeConfigRequest.candidate_toml` is always summarized as
redacted metadata, and `SetPeerGroup` logs MD5 state without the MD5 value.
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

Before the future default flip to tier enforcement, operators should stage
`[security.grpc.roles]` plus explicit listener principals while still running
`enforcement = "legacy"`, validate the candidate config with `rustbgpd --check`,
then opt into `enforcement = "tier"`. The implicit default UDS listener is safe
for local access under legacy mode, but tier mode requires an explicit
`[global.telemetry.grpc_uds]` block with `principal` so requests can be mapped
to a role.
`docs/adr/0064-threat-model.md` is the external-review packet for this surface:
it maps trust boundaries, abuse paths, residual risks, and the evidence an
auditor should collect.
Operational collection, retention, query examples, and resource-abuse guardrails
for `grpc_authz` logs and the related Prometheus metrics live in
[`docs/OPERATIONS.md`](OPERATIONS.md#grpc-authorization-audit-and-resource-guardrails).

| Service | Read-only RPCs | Mutating RPCs rejected on `read_only` |
|---------|----------------|---------------------------------------|
| `GlobalService` | `GetGlobal` | `SetGlobal` |
| `ConfigService` | `DiffRuntimeConfig` | None |
| `NeighborService` | `ListNeighbors`, `GetNeighborState`, `ListDynamicNeighbors` | `AddNeighbor`, `DeleteNeighbor`, `EnableNeighbor`, `DisableNeighbor`, `SoftResetIn`, `AddDynamicNeighbor`, `DeleteDynamicNeighbor`, `SetGracefulShutdown` |
| `PolicyService` | `ListPolicies`, `GetPolicy`, `ListNeighborSets`, `GetNeighborSet`, `GetGlobalPolicyChains`, `GetNeighborPolicyChains` | `SetPolicy`, `DeletePolicy`, `SetNeighborSet`, `DeleteNeighborSet`, `SetGlobalImportChain`, `SetGlobalExportChain`, `ClearGlobalImportChain`, `ClearGlobalExportChain`, `SetNeighborImportChain`, `SetNeighborExportChain`, `ClearNeighborImportChain`, `ClearNeighborExportChain` |
| `PeerGroupService` | `ListPeerGroups`, `GetPeerGroup` | `SetPeerGroup`, `DeletePeerGroup`, `SetNeighborPeerGroup`, `ClearNeighborPeerGroup` |
| `RibService` | All RPCs | None |
| `EventService` | All RPCs | None |
| `EvpnService` | All RPCs | None |
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
| `ALREADY_EXISTS` | A create request targets an existing resource, currently duplicate neighbor creation |
| `FAILED_PRECONDITION` | The request is valid but the daemon is not in a state where it can complete it, such as MRT export being disabled or a policy object still being referenced |
| `UNIMPLEMENTED` | The RPC is reserved in the protobuf but runtime support has not shipped yet |
| `INTERNAL` | An internal daemon actor, persistence queue, metrics encoder, or RIB boundary failed unexpectedly |

---

## GlobalService

Daemon identity and configuration.

| RPC | Description |
|-----|-------------|
| `GetGlobal` | Returns ASN, router ID, listen port, and host TCP-AO capability probe status |
| `SetGlobal` | Reserved mutating RPC for future runtime global config changes; read-only listeners reject it with `PERMISSION_DENIED`, read-write listeners return `UNIMPLEMENTED` until the feature ships |

```bash
# Get daemon identity
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.GlobalService/GetGlobal
```

`tcp_ao_support` is a read-only Linux capability probe for RFC 5925 TCP-AO. It
reports whether the host kernel accepts the TCP-AO socket primitive that
rustbgpd uses for static-neighbor startup key installation. If a static
`[[neighbors]].tcp_ao` key is configured on a host where the primitive fails,
listener setup aborts startup, and active-open setup rejects that connect
attempt without falling back to unauthenticated TCP. Runtime key rotation and
dynamic neighbor wildcard-MKT support are not exposed through the API yet.

---

## ConfigService

Read-only live runtime config diagnostics. This service never exports
the daemon's full live config snapshot; callers submit candidate TOML
and receive only the same redacted diff buckets used by
`rustbgpd --diff`.

| RPC | Description |
|-----|-------------|
| `DiffRuntimeConfig` | Validate candidate TOML and compare it against the daemon's live runtime config snapshot |

`DiffRuntimeConfigResponse` contains boolean summary fields, a
plain-text `human_text` rendering, and `diff_json` using the
`rustbgpd --diff --json` schema. Secret-bearing fields such as
neighbor `md5_password` and `tcp_ao.key` material are redacted in both
renderings. The corresponding `grpc_authz` request summary never logs
`candidate_toml` content; it records only redacted metadata such as the request
body size.

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d @ localhost:50051 rustbgpd.v1.ConfigService/DiffRuntimeConfig <<'JSON'
{
  "candidate_toml": "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\nlisten_port = 179\n\n[global.telemetry]\nlog_format = \"json\"\n"
}
JSON
```

CLI equivalent:

```bash
rustbgpctl config diff --from-file /tmp/new-config.toml
rustbgpctl --json config diff --from-file /tmp/new-config.toml
```

---

## NeighborService

Peer lifecycle management. Supports static peers from config and dynamic peers
added at runtime.

| RPC | Description |
|-----|-------------|
| `AddNeighbor` | Add a peer dynamically (starts session immediately) |
| `DeleteNeighbor` | Remove a peer and tear down its session |
| `ListNeighbors` | List all peers with session state and counters |
| `GetNeighborState` | Get detailed state for a single peer |
| `EnableNeighbor` | Re-enable a previously disabled peer |
| `DisableNeighbor` | Administratively disable a peer (sends NOTIFICATION) |
| `SoftResetIn` | Request inbound route refresh (RFC 2918/7313) for one or more families |
| `AddDynamicNeighbor` | Add a `[[dynamic_neighbors]]` range — auto-accept peers from a CIDR with a configured AS / peer-group |
| `DeleteDynamicNeighbor` | Remove a dynamic-neighbor range; in-flight sessions stay until they go Idle |
| `ListDynamicNeighbors` | List configured dynamic-neighbor ranges with active peer counts |
| `SetGracefulShutdown` | RFC 8326 initiator toggle — attach the `GRACEFUL_SHUTDOWN` community to outbound updates for one peer (or all peers when `address` is empty) and clear with `clear = true` |

### Add a neighbor

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"config": {"address": "10.0.0.2", "remote_asn": 65002, "description": "peer-2"}}' \
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

Policy statements support the same match surface as TOML config:
`prefix`, `ge`, `le`, `match_community`, `match_as_path`,
`match_neighbor_set`, `match_route_type`, `match_as_path_length_ge/le`,
`match_local_pref_ge/le`, `match_med_ge/le`, `match_next_hop`,
`match_rpki_validation`, `match_aspa_validation`, and
`match_evpn_route_type`.

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
| `ExplainAdvertisedRoute` | Dry-run export decision for one prefix to one peer |
| `ExplainBestPath` | Show all candidates for a prefix with decisive comparison reasons; optional `peer_address` field scopes to that peer's Add-Path send view |
| `ListFlowSpecRoutes` | FlowSpec routes in Adj-RIB-In / Loc-RIB view |
| `ListEvpnRoutes` | EVPN routes (RFC 7432) in Loc-RIB view, filterable by route type / peer / RD |
| `ListBlackholeDiscards` | RFC 7999 BLACKHOLE kernel-discard install status when `[global] honor_blackhole = true` and `[global] install_blackhole_discard = true` |
| `ListFibRoutes` | ADR-0061 general unicast Linux FIB route status for configured `[[fib_tables]]` |
| `ListRouteEvents` | Recent unicast best-path event history from the bounded in-memory RIB ring |
| `WatchRoutes` | Server-streaming: real-time route add/withdraw/best-change events |

### Runtime observability surfaces

Runtime visibility is intentionally split by access pattern rather than forced
through one RPC shape.

| Need | Surface | Shape | Retention / loss behavior |
|------|---------|-------|---------------------------|
| Live unicast route deltas | `WatchRoutes` or `EventService.WatchEvents` with `EVENT_CATEGORY_ROUTE` | Streaming event feed | Live-only; slow subscribers can lag and miss events |
| Recent unicast route timeline | `ListRouteEvents` / `rustbgpctl events` | Bounded history query | In-memory 4096-event ring, process-local, oldest entries evicted |
| Live session lifecycle | `EventService.WatchEvents` with `EVENT_CATEGORY_SESSION` | Streaming event feed | Live-only; no replay after reconnect |
| Recent session lifecycle | `EventService.ListSessionEvents` / `rustbgpctl events sessions` | Bounded history query | In-memory 4096-event ring, process-local, oldest entries evicted |
| Live policy mutation summaries | `EventService.WatchEvents` with `EVENT_CATEGORY_POLICY` | Streaming event feed | Live-only; slow subscribers can lag and miss events |
| Recent policy mutation summaries | `EventService.ListPolicyEvents` / `rustbgpctl events policy` | Bounded history query | In-memory 4096-event ring, process-local, oldest entries evicted |
| RFC 7999 discard programming | `ListBlackholeDiscards` / `rustbgpctl rib blackholes` | Snapshot | Current reconcile snapshot only |
| ADR-0061 general Linux FIB programming | `ListFibRoutes` / `rustbgpctl rib fib` | Snapshot | Current reconcile snapshot plus persisted owned-state semantics |
| EVPN L2/L3 dataplane readiness | `EvpnService` (`ListEvpnInstances`, `ListEvpnNexthops`, `ListIpVrfs`) / `rustbgpctl evpn ...` | Snapshot | Latest daemon or dataplane report snapshot |
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
unchanged. Unknown `peer_address` → `NOT_FOUND`. Import explain and exact
policy/statement attribution are deferred.

### Address family filtering

Route-listing RPCs that return RIB routes (`ListReceivedRoutes`,
`ListBestRoutes`, `ListAdvertisedRoutes`, and `WatchRoutes`) accept an
`afi_safi` field to filter by address family. Supported values are
`IPV4_UNICAST` (1), `IPV6_UNICAST` (2), or unspecified (0, returns both
unicast families). `WatchRoutes` events include the address family of each
route change. FlowSpec routes use `ListFlowSpecRoutes` with
`IPV4_FLOWSPEC` (3), `IPV6_FLOWSPEC` (4), or unspecified (0). EVPN routes
use `ListEvpnRoutes` and its EVPN-specific filters.

### Pagination

The unicast route-listing RPCs `ListReceivedRoutes`, `ListBestRoutes`, and
`ListAdvertisedRoutes` support pagination via `page_size` and `page_token`.
Status RPCs such as `ListBlackholeDiscards` and `ListFibRoutes` return
unfiltered snapshots. `ListFlowSpecRoutes` does not support pagination.

```bash
# First page (2 routes)
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"page_size": 2}' \
  localhost:50051 rustbgpd.v1.RibService/ListBestRoutes

# Next page
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"page_size": 2, "page_token": "2"}' \
  localhost:50051 rustbgpd.v1.RibService/ListBestRoutes
```

### Watch route changes (streaming)

```bash
# Watch all route changes (streams until interrupted)
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.RibService/WatchRoutes

# Watch changes for a specific peer
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"neighbor_address": "10.0.0.2"}' \
  localhost:50051 rustbgpd.v1.RibService/WatchRoutes
```

The `WatchRoutesRequest` also accepts an `afi_safi` field to filter the stream
by address family.

Event types: `ROUTE_EVENT_TYPE_ADDED`, `ROUTE_EVENT_TYPE_WITHDRAWN`,
`ROUTE_EVENT_TYPE_BEST_CHANGED`.

Each `RouteEvent` carries an `event_id`, a monotonic process-local cursor that
is assigned before the event is written to history and broadcast to live
subscribers. The cursor resets on daemon restart and is not reused within one
process.

`WatchRoutes` does not backfill recent events for new subscribers. Clients that
need both context and a live tail should call `ListRouteEvents` first, then
open `WatchRoutes` for subsequent deltas. `WatchRoutes` also preserves its
legacy bare `RouteEvent` response shape and does not emit explicit lag
warnings; clients that need a live missed-event signal should use
`EventService.WatchEvents`.

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

`ListRouteEvents` reads the same unicast best-path events that feed
`WatchRoutes`, but from a bounded 4096-event in-memory ring. Peer filters
match both `peer_address` and `previous_peer_address`, so a peer-scoped query
includes withdraws and best-path moves away from that peer. Prefix filters are
exact-match only and can be combined with peer, family, and limit filters. The
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
route type numbers. `peer_filter` is an optional **exact** match against the
peer IP address (e.g. `"10.0.0.2"`); `rd_filter` is an optional **exact**
match against the route distinguisher in display form (e.g. `"65000:100"`,
`"10.0.0.1:100"`, or `"4200000000:100"` per RFC 4364 RD types 0/1/2). Empty
strings disable each filter.

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

rustbgpctl rib fib          # human table
rustbgpctl rib fib --json   # JSON array for scripts
rustbgpctl rib fib --table edge --state rejected --reason route_limit_exceeded
rustbgpctl rib fib --prefix 203.0.113.0/24 --peer 198.51.100.2
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
empty. `rustbgpctl rib fib` exposes the same filters as `--table`, `--state`,
`--reason`, `--prefix`, and `--peer`.

`table_id`, `metric`, `prefix`, `prefix_length`, and `next_hop` describe
the route identity and forwarding value. The CLI human table renders
`Table`, `Metric`, `Prefix`, `Next hop`, `State`, and `Reason`; JSON output
uses `table_name`, `table_id`, `metric`, `prefix`, `next_hop`,
`peer_address`, `state`, and `reason`. A pre-existing kernel row in a
configured table is reported as `foreign_route_exists`; `RTPROT_BGP` is not
ownership proof by itself because another daemon can use the same protocol
marker. A row rustbgpd previously owned but later finds changed by another
writer is reported as `owned_route_drifted`; the daemon releases ownership and
does not delete that replacement on a later withdraw.

---

## EventService

Unified typed live event stream. Current categories are route events, session
events (peer lifecycle plus BGP NOTIFICATION sent/received metadata), policy
mutation summary events, and dataplane status-row summary changes for the
daemon-owned FIB / BLACKHOLE discard reconcilers. EVPN events are reserved for
follow-up slices until their subsystems expose one complete structured event
source.

| RPC | Description |
|-----|-------------|
| `WatchEvents` | Server-streaming: unified typed event stream sourced from structured daemon events |
| `ListSessionEvents` | Unary: recent session lifecycle events from the peer manager's bounded in-memory history |
| `ListPolicyEvents` | Unary: recent policy / neighbor-set / peer-group / chain mutation events from the peer manager's bounded in-memory history |

### Watch unified events

```bash
# Watch all live route + session + dataplane-summary events
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
```

`WatchEvents` is a live stream only: it does not replay the bounded
`ListRouteEvents` history and it does not persist events. The `rustbgpctl
events watch --backfill N` command composes both RPCs client-side for route
events by subscribing live first, printing recent `ListRouteEvents` results
through the same `BgpEvent` renderer used by the live stream, and suppressing
live route events whose `event_id` was already printed. The command prints a
history block followed by the live tail; it does not server-side merge the two
streams by wall-clock timestamp.
Filters compose
AND-wise across category, type, peer, family, and exact prefix. Repeated
category and type filters are OR-matched within their own dimension. Route
events are sourced from the same structured RIB broadcast as `WatchRoutes`;
session events are sourced from the peer manager's session broadcast and cover
both lifecycle transitions and metadata-only BGP NOTIFICATION sent/received
events; policy events are sourced from the peer manager after a runtime policy
/ neighbor-set / peer-group / chain mutation is accepted and are also retained
in the bounded `ListPolicyEvents` process-local history ring; dataplane events
are status-row count changes from the existing `ListFibRoutes` and
`ListBlackholeDiscards` snapshots, not per-route or per-MAC dataplane streams.
The FIB `rejected` count reflects surfaced status rows; high-cardinality
`route_limit_exceeded` rows are sampled in `ListFibRoutes`, so this is not a
global suppressed-route total. Empty category and type filters subscribe to
the default route + session live stream. A non-empty type filter narrows the
stream; `BGP_EVENT_TYPE_POLICY_CHANGED` or
`BGP_EVENT_TYPE_DATAPLANE_STATUS_CHANGED` with empty categories selects those
streams, and `EVENT_CATEGORY_POLICY` or `EVENT_CATEGORY_DATAPLANE` selects them
explicitly. Transport sessions send ordinary state-change lifecycle events over
a bounded channel that is separate from the lossless TCP collision-coordination
path, so high churn can drop observability events without risking collision
handling. If a subscriber falls behind either bounded broadcast, the stream
emits a `stream_lagged` warning event with the source category and missed
count; lag warnings are delivered for subscribed source categories even when
the request's event-type filter is otherwise restrictive. Prefix and family
filters are route-only: session, policy, and dataplane events do not match
requests that set `prefix` or `afi_safi`. Peer filters do not match peerless
dataplane summary events. `BgpEvent` repeats common fields such as peer,
prefix, type, and severity at the top level even when the payload also carries
them so category-agnostic clients can render or filter events without unpacking
the `oneof`.

`ListSessionEvents` accepts `neighbor_address`, lifecycle-only `event_types`,
and `limit` filters. Valid `event_types` are the five session lifecycle types:
`BGP_EVENT_TYPE_SESSION_STATE_CHANGED`, `BGP_EVENT_TYPE_SESSION_ESTABLISHED`,
`BGP_EVENT_TYPE_SESSION_LOST`, `BGP_EVENT_TYPE_PEER_ENABLED`, and
`BGP_EVENT_TYPE_PEER_DISABLED`. Empty `event_types` means all five lifecycle
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

Slow live-stream consumers do not block the daemon. If a `WatchEvents` or
`WatchRoutes` subscriber falls behind the bounded broadcast channel, missed
events are skipped and `bgp_event_stream_lagged_total{service,source}` records
the missed count. Use `bgp_event_stream_subscribers{service,source}` to see
active stream readers and `bgp_route_event_history_depth` /
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
| `BGP_EVENT_TYPE_PEER_ENABLED` | Operator enabled a configured peer |
| `BGP_EVENT_TYPE_PEER_DISABLED` | Operator disabled a configured peer |
| `BGP_EVENT_TYPE_NOTIFICATION_SENT` | rustbgpd sent a BGP NOTIFICATION; payload carries direction, code, subcode, description, session role, and optional RFC 8203 shutdown reason |
| `BGP_EVENT_TYPE_NOTIFICATION_RECEIVED` | rustbgpd received a BGP NOTIFICATION from the peer; payload carries the same metadata |

NOTIFICATION events are metadata-only. Raw NOTIFICATION packet data remains
limited to BMP peer-down handling; `WatchEvents` does not retain or replay it.

Stream health event types:

| Type | Meaning |
|------|---------|
| `BGP_EVENT_TYPE_STREAM_LAGGED` | This subscriber missed one or more route or session events from a bounded source stream. See `StreamLagEvent.source_category` and `missed_count`. |

Policy event types:

| Type | Meaning |
|------|---------|
| `BGP_EVENT_TYPE_POLICY_CHANGED` | Runtime policy, neighbor-set, peer-group, or chain mutation accepted by the peer manager. Payload carries operation, target type, target, optional peer address, and affected peer count. This is a runtime-applied audit signal; config-file persistence is a separate path. |

Dataplane event types:

| Type | Meaning |
|------|---------|
| `BGP_EVENT_TYPE_DATAPLANE_STATUS_CHANGED` | FIB / BLACKHOLE installed, rejected, or failed status-row count changed |

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
| `AddEvpnRoute` | Inject an EVPN Type 2 (MAC/IP) or Type 3 (IMET) route |
| `DeleteEvpnRoute` | Withdraw a previously injected EVPN route by its RFC 7432 key |

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
deployments. Phase 1 supports `route_type` 2 (MAC/IP) and 3 (IMET);
Type 5 IP-Prefix injection is not exposed via the injection API.
Native Gate 9 Type 5 origination from `[[evpn_ip_vrfs]]` shipped in
v0.18.0 (slice 6 PR A #77): the daemon dumps kernel routes per
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

The withdrawal key (route type + RD + ethernet tag + MAC + IP for
Type 2; route type + RD + ethernet tag + originator IP for Type 3)
matches the RFC 7432 route identity. Returns `NOT_FOUND` if no such
route was previously injected.

---

## ControlService

Daemon lifecycle, health checks, and metrics.

| RPC | Description |
|-----|-------------|
| `GetHealth` | Returns health status, uptime, active peers, total routes |
| `GetMetrics` | Returns Prometheus metrics as text |
| `Shutdown` | Initiates graceful shutdown |
| `TriggerMrtDump` | Triggers an on-demand MRT TABLE_DUMP_V2 dump |

### Health check

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.ControlService/GetHealth
```

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

Read-only view of local EVPN instances configured on this VTEP. Empty
when the daemon is acting purely as an EVPN route reflector — RR mode
does not declare local instances. The same `[[evpn_instances]]` table
that this service exposes is the input to the Linux kernel
reconciler (Gate 7b, ADR-0054 — programs remote-MAC FDB entries
downward), the local-MAC originator + Type 3 IMET emitter (Gate 7b+1,
ADR-0055 — emits Type 2 / Type 3 routes upward from kernel-learned
state), the Gate 8 segment/DF orchestrator, and the Gate 9 Type 5 /
IP-VRF path. The originators and dataplane actors bypass this gRPC
surface; they translate kernel/RIB events directly into reconcile
inputs and `RibUpdate::InjectEvpn` / `WithdrawEvpn` against the RIB.
See ADR-0052 for the original boundary, ADR-0054/ADR-0055 for the
dataplane + origination boundaries, and ADR-0063 for the required
future runtime mutation semantics.

| RPC | Description |
|-----|-------------|
| `ListEvpnInstances` | List configured local EVPN instances sorted by VNI (vni, rd, route_targets, local_vtep_ip, optional bridge, advertise_svi_mac flag, originated_local_macs_count) |
| `ListEvpnNexthops`  | List Linux dataplane reconciler-owned ADR-0059 FDB nexthop groups (per-VNI groups with ESI / Ethernet Tag / kernel group ID, per-VTEP member nexthop IDs + gateways, MAC refs) plus top-level orphan-NH count, pending-delete count, and the `drift_recovery_disabled` latch — read-only operator visibility |
| `ListIpVrfs`        | List configured IP-VRFs / L3VNI tenants (name, l3vni, rd, route_targets, local_vtep_ip, router_mac, optional `evpn_instance` link, readiness state, originated_routes_count, installed_routes_count) — Gate 9 / ADR-0058 |
| `GetIpVrf`          | Detail view of a single IP-VRF including the seven readiness predicates (`not_ready_reasons`) when `readiness_state != Ready` |

Mutation (`AddEvpnInstance` / `DeleteEvpnInstance`) is still out of
scope. Runtime mutation is not just a shared-table swap: delete and
redefine must coordinate IMET, MAC-only/MAC+IP/SVI Type 2 originators,
DF/ES state, Type 5/IP-VRF state, and Linux owned dataplane state. ADR-0063
therefore requires a single command-driven EVPN runtime coordinator
with validation-first model updates and explicit drain/replay semantics
before any mutating API is added. Tracked in
[issue #133](https://github.com/lance0/rustbgpd/issues/133).

Operators configure instances via the `[[evpn_instances]]` TOML
block; SIGHUP that edits any instance is restart-required (see
[KNOWN_ISSUES.md](../KNOWN_ISSUES.md)).

### List local EVPN instances

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.EvpnService/ListEvpnInstances
```

Or via CLI:

```bash
rustbgpctl evpn instances           # human format
rustbgpctl evpn instances --json    # JSON output
rustbgpctl evpn diagnose            # instance / Type 2 / Type 3 / metric summary
```

The human CLI includes `originated-local-macs=N` per instance. JSON and
gRPC expose the same value as `originated_local_macs_count`; it counts
MAC-only Type 2 routes currently originated by this daemon for the
instance and accepted by the RIB.

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
rustbgpctl evpn nexthops          # human format
rustbgpctl evpn nexthops --json   # JSON output
```

An empty `groups` list is normal on RR-only deployments, single-homed
VTEPs, or multi-homed VNIs with `apply_aliasing_ecmp = false` — the
top-level `orphan_nexthops_count`, `pending_delete_count`, and
`drift_recovery_disabled` fields are always populated regardless.

### List IP-VRFs / L3VNI tenants

Gate 9 / ADR-0058 surface. Returns one row per `[[evpn_ip_vrfs]]`
entry with the readiness verdict the EVPN reconcile actor most
recently published, plus the Type 5 origination + install counters.

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.EvpnService/ListIpVrfs
```

Or via CLI:

```bash
rustbgpctl evpn vrfs                  # human format
rustbgpctl evpn vrfs --json           # JSON output
rustbgpctl evpn vrfs vrf1             # single-VRF detail (matches GetIpVrf)
```

### Get IP-VRF detail

Returns the same row as `ListIpVrfs` plus, when `readiness_state` is
not `Ready`, the `not_ready_reasons` list — one entry per failing
ADR-0058 §3 predicate (e.g., `vrf_table_id_mismatch`,
`l3vxlan_router_mac_mismatch`).

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"name": "vrf1"}' \
  localhost:50051 rustbgpd.v1.EvpnService/GetIpVrf
```

---

## Proto File

The full proto definition is at [`proto/rustbgpd.proto`](../proto/rustbgpd.proto).
You can generate typed clients for Python, Go, Rust, Node.js, or any language
with protobuf/gRPC support.
