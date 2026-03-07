# rustbgpd

[![Build](https://github.com/lance0/rustbgpd/actions/workflows/ci.yml/badge.svg)](https://github.com/lance0/rustbgpd/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-1.88+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

An API-first BGP daemon in Rust, built for programmable route-server and
control-plane use cases. gRPC is the primary interface for all peer lifecycle,
routing, and policy operations. The config file bootstraps initial state; after
startup, gRPC owns the truth. No restarts to add peers, change policy, or
inject routes.

**Status: public alpha.** Feature-complete for the initial route-server and
control-plane target. Dual-stack BGP/MP-BGP, Add-Path, GR/LLGR, RPKI/RTR,
FlowSpec, BMP, MRT, and full gRPC/CLI management are implemented. Kernel FIB
integration and broader router features remain future work. Validated with
950+ workspace tests, fuzz targets, and 10 automated interop suites against
FRR 10.3.1 and BIRD 2.0.12.

> **Alpha expectations:** The config format and gRPC API are not yet frozen.
> Breaking changes are possible between minor versions. The daemon runs on
> Linux (the primary target); other platforms are not tested. See
> [Project Status](#project-status) for details.

## Why rustbgpd

- **API-first control plane** -- full gRPC control surface across 7 services plus a thin CLI (`rustbgpctl`). Dynamic peer management, route injection, policy CRUD, peer groups, streaming events, and daemon control without restarts.
- **Explicit architecture** -- pure FSM with no I/O, single-owner RIB with no locks, bounded channels between tasks. No `Arc<RwLock>` on routing state. See [ARCHITECTURE.md](ARCHITECTURE.md).
- **Dual-stack and modern protocol support** -- MP-BGP, Add-Path, Extended Next Hop, Extended Messages, GR/LLGR/Notification GR, Route Refresh/Enhanced Route Refresh, FlowSpec, Route Reflector, large and extended communities.
- **Operational visibility** -- Prometheus metrics, BMP export to collectors, MRT TABLE_DUMP_V2 snapshots, structured JSON logging, per-peer counters.
- **Evidence-driven correctness** -- fuzz targets on the wire decoder, property tests on the FSM, automated containerlab interop against FRR and BIRD, extensive workspace tests, architecture decision records for every protocol and design choice.
- **Reusable wire codec** -- `rustbgpd-wire` has zero internal dependencies and is independently publishable. Anyone building BGP tooling in Rust can use it without the daemon.

## Good fit

- **DDoS mitigation platforms** — FlowSpec + RTBH route injection from automation
- **Hosting provider prefix management** — API-driven customer prefix announcements
- **Internet exchange route servers** — transparent mode, Add-Path, RPKI, per-member policy
- **SDN / network automation controllers** — programmable BGP control plane
- **Route collectors and looking glasses** — structured data via gRPC, MRT, BMP
- **Lab and test environments** — clean API, structured logs, containerlab interop

See [docs/USE_CASES.md](docs/USE_CASES.md) for detailed deployment scenarios with
architecture diagrams, example configs, and API workflows.

## Not the best fit today

- Full general-purpose router deployments requiring FIB integration
- EVPN / VPN datacenter fabric overlays
- Environments that need the breadth of FRR's multi-decade feature surface
- Operators who want a CLI-first operational model

## Quick start (5 minutes)

### 1. Build

```bash
# Prerequisites: Rust 1.88+, protobuf-compiler
sudo apt-get install -y protobuf-compiler   # Debian/Ubuntu
cargo build --workspace --release
```

### 2. Configure

```bash
# Copy and edit the minimal example
cp examples/minimal/config.toml config.toml
$EDITOR config.toml   # set your ASN, router ID, and peer address
```

The minimal example sets `runtime_state_dir` to a user-writable path. For a
route-server deployment, start from `examples/route-server/config.toml`
instead. Full reference: [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

### 3. Validate and run

```bash
# Validate config without starting the daemon
./target/release/rustbgpd --check config.toml

# Start the daemon
./target/release/rustbgpd config.toml
```

Or with Docker:

```bash
docker build -t rustbgpd .
docker run -d --name rustbgpd \
  -v $(pwd)/config.toml:/etc/rustbgpd/config.toml:ro \
  -v rustbgpd-state:/var/lib/rustbgpd \
  -p 179:179 -p 9179:9179 \
  rustbgpd
```

Or with systemd (see `examples/systemd/rustbgpd.service`).

### 4. Verify

```bash
# The minimal example uses /tmp/rustbgpd as state dir, so point the CLI there:
export RUSTBGPD_ADDR=unix:///tmp/rustbgpd/grpc.sock

rustbgpctl health
rustbgpctl neighbor
rustbgpctl rib

# Or grpcurl directly
grpcurl -plaintext -unix /tmp/rustbgpd/grpc.sock \
  -import-path . -proto proto/rustbgpd.proto \
  rustbgpd.v1.NeighborService/ListNeighbors
```

In production with the systemd unit, the default UDS path
(`/var/lib/rustbgpd/grpc.sock`) matches the CLI default — no env var needed.

### 5. Operate

```bash
# Add a peer at runtime (persisted to config file automatically)
rustbgpctl neighbor 10.0.0.5 add --asn 65005

# Reload config after editing the file
kill -HUP $(pidof rustbgpd)

# Graceful shutdown (writes GR marker, notifies peers)
rustbgpctl shutdown

# Enable shell completions (bash example)
rustbgpctl completions bash > /etc/bash_completion.d/rustbgpctl
# Or use pre-generated: examples/completions/
```

gRPC defaults to a local Unix domain socket. For remote access, prefer an
mTLS proxy — see [`examples/envoy-mtls/`](examples/envoy-mtls/) and
[docs/SECURITY.md](docs/SECURITY.md).

## gRPC API

Seven services cover the full operational surface:

| Service | RPCs | Purpose |
|---------|------|---------|
| `GlobalService` | `GetGlobal`, `SetGlobal` | Daemon identity and configuration |
| `NeighborService` | `AddNeighbor`, `DeleteNeighbor`, `ListNeighbors`, `GetNeighborState`, `EnableNeighbor`, `DisableNeighbor`, `SoftResetIn` | Peer lifecycle + inbound soft reset |
| `PolicyService` | `ListPolicies`, `GetPolicy`, `SetPolicy`, `DeletePolicy`, `List/Get/Set/DeleteNeighborSet`, `Get*Chain`, `Set*Chain`, `Clear*Chain` | Named policy CRUD, neighbor sets, and global/per-neighbor chain attachment |
| `PeerGroupService` | `ListPeerGroups`, `GetPeerGroup`, `SetPeerGroup`, `DeletePeerGroup`, `SetNeighborPeerGroup`, `ClearNeighborPeerGroup` | Peer-group CRUD and neighbor membership assignment |
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

## Deployment examples

| Example | Description |
|---------|-------------|
| [`examples/minimal/`](examples/minimal/) | Smallest working config — single eBGP peer |
| [`examples/route-server/`](examples/route-server/) | IXP route server with RPKI, Add-Path, policy chains |
| [`examples/ddos-mitigation/`](examples/ddos-mitigation/) | FlowSpec + RTBH for automated DDoS mitigation |
| [`examples/hosting-provider/`](examples/hosting-provider/) | iBGP route injector for customer prefix management |
| [`examples/route-collector/`](examples/route-collector/) | Passive collector with MRT dumps and BMP export |
| [`examples/envoy-mtls/`](examples/envoy-mtls/) | Remote gRPC access via Envoy mTLS proxy |
| [`examples/systemd/`](examples/systemd/) | systemd unit file with security hardening |

## Security posture

- **Default listener:** Unix domain socket at `/var/lib/rustbgpd/grpc.sock` — local-only, no TCP exposure
- **Remote access:** prefer an mTLS proxy (Envoy example provided) over direct TCP
- **Network controls:** put gRPC on a management VLAN/interface and firewall it to known hosts

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

## Project status

**Alpha — suitable for lab, IX route-server pilots, and programmable
control-plane deployments where you are comfortable with an evolving API.**

| Dimension | Current state |
|-----------|---------------|
| **Target use case** | IXP route servers, programmable BGP control planes, lab/test environments |
| **Maturity** | Public alpha (v0.4.x) |
| **Supported OS** | Linux (primary target). Requires `CAP_NET_BIND_SERVICE` for port 179. |
| **Runtime** | Rust 1.88+, single binary, no external dependencies except optional RPKI/BMP/MRT backends |
| **Config stability** | TOML format may change between minor versions; migrations documented in CHANGELOG |
| **API stability** | gRPC proto may add fields/RPCs; breaking changes documented in CHANGELOG |
| **Not yet supported** | Kernel FIB integration, EVPN, VPNv4/v6, Confederation, native gRPC TLS, TCP-AO |
| **Tests** | 950+ workspace tests, fuzz targets, 10 automated interop suites (130 assertions) |

## Documentation

| Document | Content |
|----------|---------|
| [docs/USE_CASES.md](docs/USE_CASES.md) | Deployment scenarios: DDoS, hosting, IX, SDN, collector |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Crate graph, runtime model, ownership, data flow |
| [docs/DESIGN.md](docs/DESIGN.md) | Tradeoffs, protocol scope, rationale |
| [docs/API.md](docs/API.md) | gRPC API reference with examples for every RPC |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Config reference and examples |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Running in production: reload, upgrade, failure modes, debugging |
| [docs/SECURITY.md](docs/SECURITY.md) | Security posture, firewall guidance, deployment tiers |
| [docs/INTEROP.md](docs/INTEROP.md) | Interop test coverage and results |
| [docs/adr/](docs/adr/) | Architecture decision records (46 ADRs) |
| [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md) | Pre-release smoke matrix and release steps |
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
