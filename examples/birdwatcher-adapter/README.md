# birdwatcher-adapter — external looking glass REST adapter

Standalone HTTP server that exposes rustbgpd through the
**birdwatcher-compatible REST contract** consumed by
[Alice-LG](https://github.com/alice-lg/alice-lg) and similar looking
glass frontends. All data is sourced from a running rustbgpd over
gRPC; endpoint paths and response shapes are identical to the
deprecated in-daemon `[global.telemetry.looking_glass]` server this
adapter replaces.

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

Every endpoint of the in-daemon server is fully servable over today's
gRPC API — there are no 501 endpoints. Route `age` is served from the
`Route.received_at_epoch_seconds` proto field (RIB receive time), the
same source the in-daemon server reads.

### Field-level gaps

| Field                  | In-daemon server                  | Adapter                              |
|------------------------|-----------------------------------|--------------------------------------|
| status `last_reconfig` | `""` (not tracked)                | `""` (unchanged)                     |

Error behavior differs only on failure: when the daemon is unreachable
the adapter returns `502 Bad Gateway` (the in-daemon server returned
`500` when its internal channels failed).

## Testing

- Unit tests: `cargo test -p birdwatcher-adapter`
- End-to-end smoke test comparing adapter output against the in-daemon
  server for the same state: `cargo test --test birdwatcher_adapter_smoke`
  (root package; spawns a real daemon plus this adapter).
