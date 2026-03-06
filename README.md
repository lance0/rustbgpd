# rustbgpd

[![Build](https://github.com/lance0/rustbgpd/actions/workflows/ci.yml/badge.svg)](https://github.com/lance0/rustbgpd/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-1.88+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

An API-first BGP daemon in Rust, built for programmable route-server and
control-plane use cases. gRPC is the primary interface for all peer lifecycle,
routing, and policy operations. The config file bootstraps initial state; after
startup, gRPC owns the truth. No restarts to add peers, change policy, or
inject routes.

**Status:** feature-complete for the initial route-server and control-plane
target. Dual-stack BGP/MP-BGP, Add-Path, GR/LLGR, RPKI/RTR, FlowSpec, BMP,
MRT, and full gRPC/CLI management are implemented. Kernel FIB integration and
broader router features remain future work. Validated with workspace tests,
fuzz targets, and automated interop suites against FRR 10.3.1 and BIRD 2.0.12.

## Why rustbgpd

- **API-first control plane** -- full gRPC control surface across 5 services plus a thin CLI (`rustbgpctl`). Dynamic peer management, route injection, policy, streaming events, and daemon control without restarts.
- **Explicit architecture** -- pure FSM with no I/O, single-owner RIB with no locks, bounded channels between tasks. No `Arc<RwLock>` on routing state. See [ARCHITECTURE.md](ARCHITECTURE.md).
- **Dual-stack and modern protocol support** -- MP-BGP, Add-Path, Extended Next Hop, Extended Messages, GR/LLGR/Notification GR, Route Refresh/Enhanced Route Refresh, FlowSpec, Route Reflector, large and extended communities.
- **Operational visibility** -- Prometheus metrics, BMP export to collectors, MRT TABLE_DUMP_V2 snapshots, structured JSON logging, per-peer counters.
- **Evidence-driven correctness** -- fuzz targets on the wire decoder, property tests on the FSM, automated containerlab interop against FRR and BIRD, extensive workspace tests, architecture decision records for every protocol and design choice.
- **Reusable wire codec** -- `rustbgpd-wire` has zero internal dependencies and is independently publishable. Anyone building BGP tooling in Rust can use it without the daemon.

## Good fit

- Internet exchange route-server deployments
- Programmable BGP control planes driven from automation
- Lab and test environments where API-driven peering matters
- Teams that want a well-factored Rust codebase they can extend

## Not the best fit today

- Full general-purpose router deployments requiring FIB integration
- Environments that need the breadth of FRR's multi-decade feature surface
- Operators who want a CLI-first operational model

## Quick start

### Prerequisites

- **Rust 1.88+** (edition 2024)
- **protobuf-compiler** (`apt-get install protobuf-compiler` on Debian/Ubuntu)
- **grpcurl** (optional, for direct gRPC verification)

### Build and test

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

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "upstream-1"
hold_time = 90
families = ["ipv4_unicast", "ipv6_unicast"]

[[neighbors]]
address = "10.0.1.2"
remote_asn = 65003
description = "upstream-2"
hold_time = 90
```

Full reference: [docs/CONFIGURATION.md](docs/CONFIGURATION.md). Working examples: `tests/interop/configs/`.

By default, gRPC listens on a local Unix domain socket at
`/var/lib/rustbgpd/grpc.sock`. Preferred operator posture is that UDS for
same-host administration and an mTLS proxy for remote access. If you need TCP,
configure `[global.telemetry.grpc_tcp]` explicitly. See
[docs/SECURITY.md](docs/SECURITY.md) and
[`examples/envoy-mtls/`](examples/envoy-mtls/).

### Run

```bash
./target/release/rustbgpd config.toml
```

### Verify

```bash
# Using rustbgpctl (recommended)
rustbgpctl health
rustbgpctl neighbor
rustbgpctl rib

# Or using grpcurl directly against the default UDS
grpcurl -plaintext -unix /var/lib/rustbgpd/grpc.sock \
  -import-path . -proto proto/rustbgpd.proto \
  rustbgpd.v1.NeighborService/ListNeighbors
```

## gRPC API

Five services cover the full operational surface:

| Service | RPCs | Purpose |
|---------|------|---------|
| `GlobalService` | `GetGlobal`, `SetGlobal` | Daemon identity and configuration |
| `NeighborService` | `AddNeighbor`, `DeleteNeighbor`, `ListNeighbors`, `GetNeighborState`, `EnableNeighbor`, `DisableNeighbor`, `SoftResetIn` | Peer lifecycle + inbound soft reset |
| `RibService` | `ListReceivedRoutes`, `ListBestRoutes`, `ListAdvertisedRoutes`, `ListFlowSpecRoutes`, `WatchRoutes` | RIB queries and streaming |
| `InjectionService` | `AddPath`, `DeletePath`, `AddFlowSpec`, `DeleteFlowSpec` | Programmatic route and FlowSpec injection |
| `ControlService` | `GetHealth`, `GetMetrics`, `Shutdown`, `TriggerMrtDump` | Health, metrics, lifecycle, MRT dumps |

```bash
# Stream route changes in real time
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.RibService/WatchRoutes
```

Full API reference: [docs/API.md](docs/API.md)

## Design choices

rustbgpd is intentionally built around:

- **gRPC-driven control** instead of a large interactive CLI surface
- **A pure FSM crate** with no I/O -- `(State, Event) -> (State, Vec<Action>)`
- **Single-owner routing state** instead of shared mutable state across tasks
- **Bounded channels** for all inter-task communication -- backpressure, not locks
- **Explicit protocol feature boundaries** with ADRs and test-backed development

Designed around an API-first operating model similar to GoBGP, with a smaller
and more explicit internal architecture.

## Docker

```bash
docker build -t rustbgpd:dev .
docker run -d --name rustbgpd \
  -v $(pwd)/config.toml:/etc/rustbgpd/config.toml \
  -v rustbgpd-state:/var/lib/rustbgpd \
  -p 179:179 -p 50051:50051 -p 9179:9179 \
  rustbgpd:dev /usr/local/bin/rustbgpd /etc/rustbgpd/config.toml
```

Add an explicit TCP listener if gRPC needs to be reachable from outside the
container:

```toml
[global.telemetry.grpc_tcp]
address = "0.0.0.0:50051"
```

That exposes the privileged gRPC API on all interfaces. For production, prefer
leaving the backend on the default UDS and fronting remote access with an mTLS
proxy. See [docs/SECURITY.md](docs/SECURITY.md).

## Security posture

- Same-host administration: prefer a Unix domain socket when your deployment
  exposes one; that is the default listener.
- Remote administration: prefer an mTLS proxy or sidecar in front of rustbgpd,
  with the backend still bound to loopback or a local socket.
- Network controls still matter: put gRPC on a management VLAN/interface and
  firewall it to known management hosts.
- Example Envoy deployment: [`examples/envoy-mtls/`](examples/envoy-mtls/)

## Testing and correctness

| Evidence | Details |
|----------|---------|
| Workspace tests | Unit, integration, and property tests (`cargo test --workspace`) |
| Wire fuzzing | libFuzzer harnesses on message and attribute decoders, CI smoke + nightly extended |
| Interop suites | Automated containerlab tests against FRR 10.3.1 and BIRD 2.0.12 |
| Protocol coverage | RFC 4271 FSM + UPDATE validation, MP-BGP, GR/LLGR, Add-Path, FlowSpec, RPKI, Extended Messages, Extended Next Hop, Route Refresh/ERR |
| Architecture decisions | ADRs documenting every protocol and design choice ([docs/adr/](docs/adr/)) |

```bash
# Run interop tests
containerlab deploy -t tests/interop/m4-frr.clab.yml
bash tests/interop/scripts/test-m4-frr.sh
```

See [docs/INTEROP.md](docs/INTEROP.md) for full procedures and results.

## Current limitations

- No kernel FIB integration -- rustbgpd is a control-plane daemon, not a forwarding engine
- No EVPN, VPNv4/v6, or Confederation support
- No native gRPC TLS termination yet (prefer local UDS access or an mTLS proxy)
- No TCP-AO (RFC 5925) -- TCP MD5 and GTSM are supported
- Performance benchmarks not yet published (P3 roadmap)

## Documentation

| Document | Content |
|----------|---------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | How the daemon is structured: crate graph, runtime model, ownership, data flow |
| [docs/DESIGN.md](docs/DESIGN.md) | Why it was built this way: tradeoffs, protocol scope, rationale |
| [docs/API.md](docs/API.md) | gRPC API reference with examples for every RPC |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Config reference and examples |
| [docs/INTEROP.md](docs/INTEROP.md) | Interop test coverage and notes |
| [docs/adr/](docs/adr/) | Architecture decision records |
| [ROADMAP.md](ROADMAP.md) | Remaining gaps and planned work |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup, code style, PR process |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
