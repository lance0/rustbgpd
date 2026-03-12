# gRPC API Reference

rustbgpd exposes seven gRPC services over one or more configured listeners. The
default listener is a local Unix domain socket at
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
`match_local_pref_ge/le`, `match_med_ge/le`, `match_next_hop`, and
`match_rpki_validation`.

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
| `ListFlowSpecRoutes` | FlowSpec routes in Adj-RIB-In / Loc-RIB view |
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

Current scope is export explain only. Best-path explain, import explain, and
exact policy/statement attribution are deferred.

### Address family filtering

All `List*` RPCs accept an `afi_safi` field to filter by address family.
Supported values: `IPV4_UNICAST` (1), `IPV6_UNICAST` (2), `IPV4_FLOWSPEC` (3),
`IPV6_FLOWSPEC` (4), or unspecified (0, returns all families). `WatchRoutes`
events include the address family of each route change.

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

## Proto File

The full proto definition is at [`proto/rustbgpd.proto`](../proto/rustbgpd.proto).
You can generate typed clients for Python, Go, Rust, Node.js, or any language
with protobuf/gRPC support.
