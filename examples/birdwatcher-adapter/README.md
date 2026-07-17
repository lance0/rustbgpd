# birdwatcher-adapter — external looking glass REST adapter

Standalone HTTP server that exposes a **Birdwatcher-shaped read-only subset**
for [Alice-LG](https://github.com/alice-lg/alice-lg) and similar looking glass
frontends. It serves status, peer, and accepted-route views from a running
rustbgpd over gRPC. The four endpoint paths and response shapes match the
removed in-daemon `[global.telemetry.looking_glass]` server this adapter
replaces; this is not a complete Alice-LG backend.

Rationale: the daemon's durable API identity is **gRPC + `rbgp`**.
Partial compatibility with someone else's REST API inside daemon core
is a permanent source of misunderstanding, so the birdwatcher surface
lives here as a maintained adapter instead. It is a workspace member
but not part of the default `cargo build`, release tarballs, or
container images; it builds with `--workspace` or an explicit
`-p birdwatcher-adapter`.

## Build + run

```sh
cargo run --release -p birdwatcher-adapter -- \
    --grpc-addr http://127.0.0.1:50051 \
    --listen 0.0.0.0:8080
```

Flags (also settable via env):

| Flag          | Env                             | Default          | Meaning                          |
|---------------|---------------------------------|------------------|----------------------------------|
| `--grpc-addr` | `BIRDWATCHER_ADAPTER_GRPC_ADDR` | (required)       | rustbgpd gRPC endpoint (TCP)     |
| `--listen`    | `BIRDWATCHER_ADAPTER_LISTEN`    | `127.0.0.1:8080` | REST listen address              |

The daemon needs a gRPC TCP listener the adapter can reach
(`[global.telemetry.grpc_tcp]`); read-only access is sufficient —
every RPC the adapter calls is a read.

## Endpoint → gRPC mapping

| REST endpoint (birdwatcher)  | Backing gRPC RPC(s)                                            |
|------------------------------|----------------------------------------------------------------|
| `GET /status`                | `GlobalService.GetGlobal` + `ControlService.GetHealth`         |
| `GET /protocols/bgp`         | `NeighborService.ListNeighbors`                                |
| `GET /routes/protocol/{id}`  | `RibService.ListReceivedRoutes` (paged, all unicast families)  |
| `GET /routes/peer/{peer}`    | `RibService.ListReceivedRoutes` (paged, all unicast families)  |

All four endpoints from the removed in-daemon server are servable over today's
gRPC API — there are no placeholder 501 responses. Route `age` is served from
the `Route.received_at_epoch_seconds` proto field (RIB receive time), the same
source the in-daemon server used.

The scope is status, peer, and accepted-route views only. Alice-LG's
filtered/noexport views are not implemented in this adapter yet. The
structured per-route reject reasons they need are now available from
`PolicyService.ListRejectedRoutes` (per-peer retained rejects with
canonical reason tokens; see `[policy.reject_retention]` in
`docs/CONFIGURATION.md`), so a real `routes.filtered` count and a
filtered view are implementable — wiring them into this adapter is
future work.

### Field-level gaps

| Field | Adapter value | Limitation |
|---|---|---|
| status `last_reconfig` | `""` | Reconfiguration time is not tracked. |
| protocol `routes.filtered` | `0` | Sentinel only; this is not a filtered-route count. |
| protocol `routes.preferred` | `0` | Sentinel only; preferred-route count is not exposed. |
| route `interface` | `""` | Interface identity is not exposed for these routes. |
| route `metric` | `0` | Sentinel only; this is not an IGP metric. |
| route `primary` | `false` | Sentinel only; primary-route status is not exposed. |

Error behavior differs only on failure: when the daemon is unreachable
the adapter returns `502 Bad Gateway` (the in-daemon server returned
`500` when its internal channels failed).

## Testing

- Unit tests: `cargo test -p birdwatcher-adapter`
- End-to-end smoke test of the status/peer/accepted-route subset:
  `cargo test --test birdwatcher_adapter_smoke` (root package; spawns a real
  daemon plus this adapter).
