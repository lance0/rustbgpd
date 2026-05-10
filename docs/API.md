# gRPC API Reference

rustbgpd exposes eight gRPC services (Global, Neighbor, Policy, PeerGroup, Rib,
Injection, Control, Evpn) over one or more configured listeners. The default
listener is a local Unix domain socket at `/var/lib/rustbgpd/grpc.sock`.

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

---

## GlobalService

Daemon identity and configuration.

| RPC | Description |
|-----|-------------|
| `GetGlobal` | Returns ASN, router ID, and listen port |
| `SetGlobal` | Updates daemon configuration (currently a no-op placeholder) |

```bash
# Get daemon identity
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.GlobalService/GetGlobal
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
that reference that group.

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
| `WatchRoutes` | Server-streaming: real-time route add/withdraw/best-change events |

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
permitted + sendable-family + split-horizon + within the peer's effective
`add_path_send_max`) get a non-zero `advertised_path_id` reflecting the rank
they would carry on the wire; everything else stays at `advertised_path_id =
0`. The response echoes `peer_address` and the effective `add_path_send_max`
so the operator can read advertisement intent without cross-referencing the
peer config. Empty `peer_address` returns the v0.7.0 global Loc-RIB view
unchanged. Unknown `peer_address` → `NOT_FOUND`. Import explain and exact
policy/statement attribution are deferred.

### Address family filtering

All `List*` RPCs accept an `afi_safi` field to filter by address family.
Supported values: `IPV4_UNICAST` (1), `IPV6_UNICAST` (2), `IPV4_FLOWSPEC` (3),
`IPV6_FLOWSPEC` (4), `L2VPN_EVPN` (5), or unspecified (0, returns all
families). `WatchRoutes` events include the address family of each route
change.

### Pagination

All unicast `List*` RPCs support pagination via `page_size` and `page_token` (`ListFlowSpecRoutes` does not support pagination):

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
Type 5 IP-Prefix injection is not yet exposed. Native Type 1/4
multi-homing origination is driven by `[[ethernet_segments]]`; the
injection API does not expose those route types yet (the RR still
reflects them when received from peers).

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
downward) and the local-MAC originator + Type 3 IMET emitter (Gate 7b+1,
ADR-0055 — emits Type 2 / Type 3 routes upward from kernel-learned
state). The originator and IMET emitter bypass this gRPC surface;
they translate kernel events directly into `RibUpdate::InjectEvpn` /
`WithdrawEvpn` against the RIB. See ADR-0052 for the original
boundary, ADR-0054/ADR-0055 for the dataplane + origination
boundaries.

| RPC | Description |
|-----|-------------|
| `ListEvpnInstances` | List configured local EVPN instances sorted by VNI (vni, rd, route_targets, local_vtep_ip, optional bridge, advertise_svi_mac flag, originated_local_macs_count) |

Mutation (`AddEvpnInstance` / `DeleteEvpnInstance`) is still out of
scope. With the kernel reconciler and originator now live (Gates
7b / 7b+1), runtime mutation needs a swap surface (`ArcSwap` /
`RwLock`) plus careful interaction with the per-VNI
`LocalMacOriginator` state — delete must drain its outstanding
Withdraws before the table swap to avoid leaking advertised MACs.
Tracked as alpha-soak follow-up — see
[`docs/evpn-alpha-soak.md`](evpn-alpha-soak.md).

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

---

## Proto File

The full proto definition is at [`proto/rustbgpd.proto`](../proto/rustbgpd.proto).
You can generate typed clients for Python, Go, Rust, Node.js, or any language
with protobuf/gRPC support.
