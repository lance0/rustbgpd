# rustbgpd-api

gRPC API server for rustbgpd, built on tonic.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Services

| Service | Scope |
|---------|-------|
| **GlobalService** | Read daemon identity and bootstrap config |
| **NeighborService** | Dynamic peer CRUD, enable/disable, soft reset |
| **PolicyService** | Named policy CRUD and global/per-neighbor chain assignment |
| **PeerGroupService** | Peer-group CRUD, neighbor-to-group assignment |
| **RibService** | Received/best/advertised route queries (incl. EVPN), BLACKHOLE discard status, and watch stream |
| **InjectionService** | Inject/withdraw unicast, FlowSpec, and EVPN routes |
| **ControlService** | Health, metrics, shutdown, MRT trigger |
| **EvpnService** | List configured local EVPN instances (Phase-2 VTEP foundation; read-only) |

See [docs/API.md](../../docs/API.md) for the full RPC reference and examples.

## Proto

Protocol buffer definitions are in [proto/rustbgpd.proto](../../proto/rustbgpd.proto).
Code generation runs via `tonic-build` in `build.rs`.

## License

MIT OR Apache-2.0
