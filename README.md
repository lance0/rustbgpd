# rustbgpd

A modern, API-first BGP daemon in Rust.

gRPC is the primary interface for all configuration and operations. The config
file is a convenience for initial boot state — once the daemon is running,
gRPC owns the truth.

## Status

**Pre-release.** Milestone 3 ("Speak") is complete — outbound UPDATE
generation, route injection via gRPC, global prefix-list policy,
max-prefix enforcement, TCP MD5 authentication, and GTSM/TTL security.
284 unit/integration tests pass. Interop validated against FRR 10.3.1
(3-node topology: route redistribution, split horizon, injection,
withdrawal propagation, DeletePath).

## Goals

- **API-first routing control plane.** gRPC with typed clients in Python, Go, Rust, and Node.
- **Interop correctness over feature breadth.** RFC-compliant, validated against real peers.
- **Observable by default.** Prometheus metrics, structured logs, machine-parseable errors.
- **Safe, boring, maintainable.** No `unsafe`. Fuzzed wire decoder. Explicit resource limits.

## Architecture

```
transport ──► fsm ──► wire
    │
    ▼
   rib ◄── policy
    │
    ▼
   api ──► telemetry
```

Seven crates with strict dependency rules:

| Crate | Description |
|-------|-------------|
| `rustbgpd-wire` | BGP message codec. Zero internal deps. Independently publishable. |
| `rustbgpd-fsm` | RFC 4271 state machine. Pure — no tokio, no sockets, no tasks. |
| `rustbgpd-transport` | Tokio TCP glue. The only crate that touches async I/O. |
| `rustbgpd-rib` | Adj-RIB-In, Loc-RIB best-path, Adj-RIB-Out. |
| `rustbgpd-policy` | Prefix allow/deny, max-prefix enforcement. |
| `rustbgpd-api` | gRPC server (tonic). Five separate services. |
| `rustbgpd-telemetry` | Prometheus metrics + structured tracing. |

## Milestones

- **M0 — "Establish"** `[complete]` — OPEN/KEEPALIVE/NOTIFICATION, FSM, session stability
- **M1 — "Hear"** `[complete]` — UPDATE decode, Adj-RIB-In, `ListReceivedRoutes` gRPC
- **M2 — "Decide"** `[complete]` — Loc-RIB best-path selection, `ListBestRoutes` gRPC
- **M3 — "Speak"** `[complete]` — Route injection, Adj-RIB-Out, policy, TCP MD5
- **M4 — "Route Server"** — Many peers, per-peer policy, scale testing

See [ROADMAP.md](ROADMAP.md) for detailed build order.

## Building

```
cargo build
cargo test --workspace
```

Requires Rust 1.85+ (edition 2024).

## Running

```bash
# With a config file
./target/debug/rustbgpd path/to/config.toml

# Default config path: /etc/rustbgpd/config.toml
./target/debug/rustbgpd
```

See `tests/interop/configs/` for example TOML configs. The daemon exposes
a Prometheus metrics endpoint at the address configured in
`[global.telemetry].prometheus_addr` and a gRPC API server at
`[global.telemetry].grpc_addr` (default `127.0.0.1:50051`).
Ctrl+C triggers graceful shutdown.

### Querying Routes via gRPC

```bash
# All received routes (Adj-RIB-In)
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.RibService/ListReceivedRoutes

# Best routes (Loc-RIB)
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.RibService/ListBestRoutes

# Advertised routes (Adj-RIB-Out) for a specific peer
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"neighbor_address": "10.0.0.2"}' \
  localhost:50051 rustbgpd.v1.RibService/ListAdvertisedRoutes

# Inject a route
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"prefix": "10.99.0.0", "prefix_length": 24, "next_hop": "10.0.0.1"}' \
  localhost:50051 rustbgpd.v1.InjectionService/AddPath

# Withdraw an injected route
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"prefix": "10.99.0.0", "prefix_length": 24}' \
  localhost:50051 rustbgpd.v1.InjectionService/DeletePath
```

## Interop Testing

Interop tests run via [containerlab](https://containerlab.dev/). Topologies
are in `tests/interop/`.

```
containerlab deploy -t tests/interop/m0-frr.clab.yml
containerlab deploy -t tests/interop/m0-bird.clab.yml
containerlab deploy -t tests/interop/m1-frr.clab.yml
containerlab deploy -t tests/interop/m3-frr.clab.yml
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
