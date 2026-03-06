# rustbgpd-api

gRPC API server for rustbgpd, built on tonic.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Services

| Service | RPCs |
|---------|------|
| **Global** | `GetGlobal` — ASN, router ID, listen port |
| **Neighbor** | `ListNeighbors`, `GetNeighbor`, `AddNeighbor`, `DeleteNeighbor`, `EnableNeighbor`, `DisableNeighbor`, `SoftResetIn` |
| **RIB** | `GetRoutes` (received/best/advertised), `GetRouteCount` |
| **Injection** | `AddPath`, `DeletePath`, `AddFlowSpec`, `DeleteFlowSpec`, `ListFlowSpecRoutes` |
| **Control** | `Health`, `Shutdown`, `WatchRoutes` (server-streaming), `TriggerMrtDump` |

## Proto

Protocol buffer definitions are in `proto/bgp.proto`. Code generation
runs via `tonic-build` in `build.rs`.

## License

MIT OR Apache-2.0
