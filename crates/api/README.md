# rustbgpd-api

gRPC API server for rustbgpd, built on tonic.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Services

| Service | Scope |
|---------|-------|
| **GlobalService** | Read daemon identity and bootstrap config |
| **ConfigService** | Diff, plan, apply, confirm, abort, and inspect runtime config transactions |
| **NeighborService** | Dynamic peer CRUD, enable/disable, inbound soft reset, single-peer outbound refresh, dynamic-neighbor range CRUD (`ListDynamicNeighbors` / `AddDynamicNeighbor` / `DeleteDynamicNeighbor`), and the RFC 8326 graceful-shutdown toggle (`SetGracefulShutdown`) |
| **PolicyService** | Named policy CRUD, neighbor-set CRUD, global/per-neighbor chain assignment, import-policy explain (`ExplainImportPolicy`), rejected-route listing (`ListRejectedRoutes`), live-RIB dry-run (`TestPolicy`), per-term hit counters (`GetPolicyStats`), and bounded invalid-validation disposition posture (`GetValidationPolicyPosture`) |
| **PeerGroupService** | Peer-group CRUD, neighbor-to-group assignment |
| **RibService** | Received/best/advertised route queries (incl. EVPN), BLACKHOLE discard status, FIB route status, and BGP-LS route queries (ListBgpLsRoutes, RFC 9552); all unary — live route deltas stream through `EventService.WatchEvents` |
| **BfdService** | BFD session queries (RFC 5880/5881/5882) |
| **EventService** | Live event stream (`WatchEvents`), recent session/policy/EVPN history, and the durable `SubscribeFromEvent` cursor (ADR-0072) |
| **InjectionService** | Inject/withdraw unicast, FlowSpec, and EVPN routes |
| **ControlService** | Health, metrics, shutdown, MRT trigger |
| **EvpnService** | EVPN runtime read + L2VNI / next-hop / IP-VRF queries, duplicate-MAC quarantine clear, and the mutating `ApplyEvpnRuntime` (no longer read-only) |
| **gnmi.gNMI** | OpenConfig gNMI: read-only telemetry (Capabilities/Get/Subscribe) plus a transaction-backed Set subset |

The crate also provides the device-initiated
`gnmi_dialout::DialoutManager`, which publishes configured gNMI subscriptions
to external collectors and reports per-target connection state through
`gnmi_dialout_connected{target}`.

See [docs/API.md](../../docs/API.md) for the full RPC reference and examples.

## Proto

Protocol buffer definitions live under [proto/](../../proto/):
`rustbgpd.proto` defines the eleven native services,
`rustbgpd_dialout.proto` defines the gNMI dial-out publish stream, and the
vendored OpenConfig `gnmi.proto` / `gnmi_ext.proto` define the gNMI service,
messages, and extensions. Code generation runs from `build.rs`.

## License

MIT OR Apache-2.0
