# rustbgpd

[![Build](https://github.com/lance0/rustbgpd/actions/workflows/ci.yml/badge.svg)](https://github.com/lance0/rustbgpd/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-1.88+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

An API-first BGP daemon written in Rust. rustbgpd brings the programmable,
gRPC-driven operating model pioneered by GoBGP to a memory-safe runtime with
no garbage collector. It targets network automation teams, IX operators, and
anyone who wants to drive BGP sessions from code rather than CLI commands.

## Why rustbgpd?

If you're automating BGP -- injecting routes, managing peers, reacting to events -- you need an API, not a CLI. GoBGP proved this model works. rustbgpd takes the same idea and rebuilds it in Rust:

| | FRR / BIRD | GoBGP | rustbgpd |
|---|---|---|---|
| **Primary interface** | CLI | gRPC | gRPC |
| **Runtime** | C | Go (GC) | Rust (no GC) |
| **Scope** | Full routing suite | BGP-only | BGP-only |
| **Dynamic peers** | Config reload | gRPC | gRPC |
| **Real-time events** | Log parsing | BMP/MRT | gRPC streaming |
| **Observability** | SNMP, CLI | Prometheus | Prometheus + structured logs |
| **Wire codec reuse** | No | No | `rustbgpd-wire` standalone crate |

**Key idea:** Config file bootstraps initial state, then gRPC owns the truth at runtime. No restarts to add peers, change policy, or inject routes.

## Highlights

- **gRPC-native** -- five services covering peer lifecycle, RIB queries, route injection, streaming events, and daemon control
- **RFC 4271 compliant** -- full FSM, path attribute validation, best-path selection, split horizon, Adj-RIB-In / Loc-RIB / Adj-RIB-Out
- **Inbound + outbound peering** -- accepts incoming TCP connections and initiates outbound; passive peering supported
- **Dynamic peer management** -- add, delete, enable, and disable neighbors at runtime via gRPC
- **Per-peer policy** -- import/export prefix lists at global or neighbor level
- **Real-time streaming** -- `WatchRoutes` delivers add/withdraw/best-change events over server-streaming RPC
- **Observable by default** -- Prometheus metrics, structured JSON logging, per-peer counters
- **Interop validated** -- automated test suites against FRR 10.3.1 and BIRD 2.0.12 via containerlab
- **367 tests** -- unit, integration, property tests, and fuzzed wire decoder

## Quick Start

### Prerequisites

- **Rust 1.88+** (edition 2024)
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

### How data flows

1. **Peer connects** -- transport opens TCP, drives the pure FSM through OPEN/KEEPALIVE handshake
2. **UPDATEs arrive** -- transport decodes wire bytes, validates attributes per RFC 4271, inserts into RIB
3. **Best-path runs** -- RIB recomputes affected prefixes, updates Loc-RIB, emits route events
4. **Peers notified** -- RIB distributes changes to per-peer Adj-RIB-Out channels (split horizon, export policy)
5. **gRPC serves** -- API queries RIB snapshots, streams events, accepts route injections and peer commands

The FSM is a pure function `(State, Event) -> (State, Vec<Action>)` with no I/O. The RIB runs as a single tokio task with channel-based access -- no `Arc<RwLock>`. See [docs/DESIGN.md](docs/DESIGN.md) and [docs/adr/](docs/adr/) for detailed rationale.

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

The multi-stage Dockerfile uses `rust:1.88-bookworm` with `protobuf-compiler` for the build stage and `debian:bookworm-slim` for the runtime.

### Run

```bash
docker run -d --name rustbgpd \
  -v $(pwd)/config.toml:/etc/rustbgpd/config.toml \
  -p 179:179 \
  -p 50051:50051 \
  -p 9179:9179 \
  rustbgpd:dev /usr/local/bin/rustbgpd /etc/rustbgpd/config.toml
```

Set `grpc_addr = "0.0.0.0:50051"` in the config so the gRPC port is reachable from outside the container. **Note:** this exposes the unauthenticated gRPC API on all interfaces. For production, bind to a management interface or front with an mTLS proxy. See [docs/SECURITY.md](docs/SECURITY.md).

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

**Pre-release.** Nine milestones complete. 367 tests pass. Interop validated against FRR 10.3.1 and BIRD 2.0.12.

| Milestone | Status | Scope |
|-----------|--------|-------|
| M0 -- Establish | Complete | OPEN/KEEPALIVE/NOTIFICATION, FSM, session stability |
| M1 -- Hear | Complete | UPDATE decode, Adj-RIB-In, `ListReceivedRoutes` gRPC |
| M2 -- Decide | Complete | Loc-RIB best-path selection, `ListBestRoutes` gRPC |
| M3 -- Speak | Complete | Route injection, Adj-RIB-Out, export policy, TCP MD5 |
| M4 -- Route Server | Complete | Dynamic peers, per-peer policy, communities, WatchRoutes |
| M5 -- Polish | Complete | Inbound listener, session counters, NLRI batching, API hardening |
| M6 -- Compliance | Complete | Wire RFC compliance, GlobalService, ControlService, coordinated shutdown |
| M7 -- Wire & RIB Correctness | Complete | Adj-RIB-Out divergence fix, NLRI subcode, PARTIAL bit, policy validation, eBGP best-path |
| M8 -- API & Observability | Complete | IPv6 rejection, Prometheus gauges, WatchRoutes events, health counters |
| M9 -- Production Hardening | Complete | Metrics server hardening, gRPC security, TCP collision detection, gRPC supervision |

Next: MP-BGP (IPv6), graceful restart, BMP, RPKI. See [ROADMAP.md](ROADMAP.md) for the full plan.

## Documentation

| Topic | Link |
|-------|------|
| Design document | [docs/DESIGN.md](docs/DESIGN.md) |
| gRPC API reference | [docs/API.md](docs/API.md) |
| Configuration reference | [docs/CONFIGURATION.md](docs/CONFIGURATION.md) |
| Interop test results | [docs/INTEROP.md](docs/INTEROP.md) |
| Architecture decisions | [docs/adr/](docs/adr/) |
| Roadmap | [ROADMAP.md](ROADMAP.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
