# rustbgpd-api

gRPC API server for rustbgpd, built on tonic.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Services

| Service | Scope |
|---------|-------|
| **GlobalService** | Read daemon identity and bootstrap config |
| **ConfigService** | Diff, plan, apply, confirm, abort, and inspect runtime config transactions |
| **NeighborService** | Dynamic peer CRUD, enable/disable, inbound soft reset, single-peer outbound refresh, dynamic-neighbor range CRUD (`ListDynamicNeighbors` / `AddDynamicNeighbor` / `DeleteDynamicNeighbor`), and the RFC 8326 graceful-shutdown toggle (`SetGracefulShutdown`) |
| **PolicyService** | Named policy CRUD, neighbor-set CRUD, global/per-neighbor chain assignment, import-policy explain (`ExplainImportPolicy`), rejected-route listing (`ListRejectedRoutes`), live-RIB dry-run (`TestPolicy`), and per-term hit counters (`GetPolicyStats`) |
| **PeerGroupService** | Peer-group CRUD, neighbor-to-group assignment |
| **RibService** | Received/best/advertised route queries (incl. EVPN), BLACKHOLE discard status, FIB route status, BGP-LS route queries (ListBgpLsRoutes, RFC 9552), and watch stream |
| **BfdService** | BFD session queries (RFC 5880/5881/5882) |
| **EventService** | Live event stream (`WatchEvents`), recent session/policy/EVPN history, and the durable `SubscribeFromEvent` cursor (ADR-0072) |
| **InjectionService** | Inject/withdraw unicast, FlowSpec, and EVPN routes |
| **ControlService** | Health, metrics, shutdown, MRT trigger |
| **EvpnService** | EVPN runtime read + L2VNI / next-hop / IP-VRF queries, duplicate-MAC quarantine clear, and the mutating `ApplyEvpnRuntime` (no longer read-only) |
| **gnmi.gNMI** | OpenConfig gNMI: read-only telemetry (Capabilities/Get/Subscribe) plus a transaction-backed Set subset |

See [docs/API.md](../../docs/API.md) for the full RPC reference and examples.

## Proto

Protocol buffer definitions are in [proto/rustbgpd.proto](../../proto/rustbgpd.proto).
Code generation runs via `tonic-build` in `build.rs`.

## License

MIT OR Apache-2.0
