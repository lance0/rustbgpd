# rustbgpd

An API-first BGP daemon written in Rust. rustbgpd brings the programmable,
gRPC-driven operating model pioneered by GoBGP to a memory-safe runtime with
no garbage collector. It targets network automation teams, IX operators, and
anyone who wants to drive BGP sessions from code rather than CLI commands.

## Highlights

- **gRPC-native** -- five services covering peer lifecycle, RIB queries, route injection, streaming events, and daemon control. Config file bootstraps; gRPC owns the truth at runtime.
- **RFC 4271 compliant** -- full FSM, path attribute validation, best-path selection (always-compare MED), split horizon, Adj-RIB-In / Loc-RIB / Adj-RIB-Out.
- **Dynamic peer management** -- add, delete, enable, and disable neighbors at runtime via gRPC. Zero-neighbor boot is valid.
- **Per-peer policy** -- import/export prefix lists at global or neighbor level. Neighbor policy overrides global.
- **Typed communities** -- RFC 1997 community encoding and propagation.
- **Real-time streaming** -- `WatchRoutes` delivers add/withdraw/best-change events over a server-streaming RPC.
- **Observable by default** -- Prometheus metrics endpoint, structured JSON logging, per-peer counters.
- **TCP MD5 and GTSM** -- session security via `setsockopt` (Linux).
- **Interop validated** -- automated test suites against FRR 10.3.1 and BIRD 2.0.12 via containerlab.
- **306 tests** -- unit, integration, and property tests across all crates.

## Quick Start

### Prerequisites

- **Rust 1.93+** (edition 2024)
- **protobuf-compiler** (`apt-get install protobuf-compiler` on Debian/Ubuntu)
- **grpcurl** (optional, for verifying the gRPC API)

### Build

```bash
cargo build --release
cargo test --workspace
```

### Configure

Create a TOML config file. A minimal two-peer setup:

```toml
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
grpc_addr = "127.0.0.1:50051"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "upstream-1"
hold_time = 90

[[neighbors]]
address = "10.0.1.2"
remote_asn = 65003
description = "upstream-2"
hold_time = 90
```

See [Configuration Reference](#configuration-reference) for all options.

### Run

```bash
./target/release/rustbgpd config.toml
```

The daemon starts the BGP sessions, gRPC server, and Prometheus endpoint. Ctrl+C triggers graceful shutdown with NOTIFICATION to all peers.

### Verify

```bash
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.NeighborService/ListNeighbors
```

## Architecture

```
               +-----------+
               | transport |----> fsm ----> wire
               +-----------+
                   |
                   v
    policy ----> +-----+
                 | rib |
                 +-----+
                   |
                   v
               +-----+       +-----------+
               | api |-----> | telemetry |
               +-----+       +-----------+
```

Seven crates with strict dependency rules:

| Crate | Description |
|-------|-------------|
| `rustbgpd-wire` | BGP message codec. Zero internal deps. Independently publishable and fuzzed. |
| `rustbgpd-fsm` | RFC 4271 state machine. Pure -- no tokio, no sockets, no tasks. |
| `rustbgpd-transport` | Tokio TCP glue. The only crate that touches async I/O. |
| `rustbgpd-rib` | Adj-RIB-In, Loc-RIB best-path, Adj-RIB-Out. Single-task ownership, no locks. |
| `rustbgpd-policy` | Prefix allow/deny lists, per-peer or global, with ge/le matching. |
| `rustbgpd-api` | gRPC server (tonic). Five services, proto codegen at build time. |
| `rustbgpd-telemetry` | Prometheus metrics + structured tracing. |

Key design decisions: the FSM is a pure function `(State, Event) -> (State, Vec<Action>)` with no I/O. The RIB runs as a single tokio task with channel-based access -- no `Arc<RwLock>`. One tokio task per peer session. See [docs/DESIGN.md](docs/DESIGN.md) and [docs/adr/](docs/adr/) for detailed rationale.

## gRPC API

Five services cover the full operational surface:

| Service | RPCs | Purpose |
|---------|------|---------|
| `GlobalService` | `GetGlobal`, `SetGlobal` | Daemon identity and configuration |
| `NeighborService` | `AddNeighbor`, `DeleteNeighbor`, `ListNeighbors`, `GetNeighborState`, `EnableNeighbor`, `DisableNeighbor` | Peer lifecycle |
| `RibService` | `ListReceivedRoutes`, `ListBestRoutes`, `ListAdvertisedRoutes`, `WatchRoutes` | RIB queries and streaming |
| `InjectionService` | `AddPath`, `DeletePath` | Programmatic route injection |
| `ControlService` | `GetHealth`, `GetMetrics`, `Shutdown` | Health, metrics, lifecycle |

```bash
# Check daemon health
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.ControlService/GetHealth

# Stream route changes in real time
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.RibService/WatchRoutes
```

Full API reference with examples for every RPC: [docs/API.md](docs/API.md)

## Configuration Reference

The config file is TOML. All runtime changes go through gRPC -- the file is only read at startup.

**`[global]`** -- ASN, router ID, listen port.

**`[global.telemetry]`** -- Prometheus bind address, log format (`json`), gRPC bind address (default `127.0.0.1:50051`).

**`[[neighbors]]`** -- One block per peer: `address`, `remote_asn`, optional `description`, `hold_time` (default 90), `max_prefixes`, `md5_password`, `ttl_security`.

**`[policy]`** -- Global import/export prefix lists. Each entry has `action` (`permit`/`deny`), `prefix` (CIDR), optional `ge`/`le`.

**`[[neighbors.import_policy]]` / `[[neighbors.export_policy]]`** -- Per-neighbor policy overrides. Same format as global policy entries.

Example with policy:

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "transit"

# Block RFC 1918 from this peer
[[neighbors.import_policy]]
action = "deny"
prefix = "10.0.0.0/8"
ge = 8
le = 32

[[neighbors.import_policy]]
action = "deny"
prefix = "172.16.0.0/12"
ge = 12
le = 32

[[neighbors.import_policy]]
action = "deny"
prefix = "192.168.0.0/16"
ge = 16
le = 32
```

Full reference: [docs/CONFIGURATION.md](docs/CONFIGURATION.md). Working examples: `tests/interop/configs/`.

## Docker

### Build the image

```bash
docker build -t rustbgpd:dev .
```

The multi-stage Dockerfile uses `rust:1.93-bookworm` with `protobuf-compiler` for the build stage and `debian:bookworm-slim` for the runtime.

### Run

```bash
docker run -d --name rustbgpd \
  -v $(pwd)/config.toml:/etc/rustbgpd/config.toml \
  -p 179:179 \
  -p 50051:50051 \
  -p 9179:9179 \
  rustbgpd:dev /usr/local/bin/rustbgpd /etc/rustbgpd/config.toml
```

Set `grpc_addr = "0.0.0.0:50051"` in the config so the gRPC port is reachable from outside the container.

## Interop Testing

Interop tests run via [containerlab](https://containerlab.dev/) against FRR 10.3.1 and BIRD 2.0.12. Topologies and automated test scripts live in `tests/interop/`.

```bash
# Deploy the 10-peer M4 topology
sudo containerlab deploy -t tests/interop/m4-frr.clab.yml

# Run the automated test suite (17 tests)
bash tests/interop/scripts/test-m4-frr.sh
```

See [docs/INTEROP.md](docs/INTEROP.md) for full test procedures, results, and troubleshooting.

## Project Status

**Pre-release.** All five milestones are complete. 306 tests pass. Interop validated against FRR 10.3.1 and BIRD 2.0.12.

| Milestone | Status | Scope |
|-----------|--------|-------|
| M0 -- Establish | Complete | OPEN/KEEPALIVE/NOTIFICATION, FSM, session stability |
| M1 -- Hear | Complete | UPDATE decode, Adj-RIB-In, `ListReceivedRoutes` gRPC |
| M2 -- Decide | Complete | Loc-RIB best-path selection, `ListBestRoutes` gRPC |
| M3 -- Speak | Complete | Route injection, Adj-RIB-Out, export policy, TCP MD5 |
| M4 -- Route Server | Complete | Dynamic peers, per-peer policy, communities, WatchRoutes |

Next: MP-BGP (IPv6), extended communities, graceful restart, BMP, RPKI. See [ROADMAP.md](ROADMAP.md) for the full plan.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
