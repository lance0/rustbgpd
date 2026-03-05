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
| **Real-time events** | Log parsing | BMP/MRT | gRPC streaming + BMP |
| **Observability** | SNMP, CLI | Prometheus | Prometheus + structured logs |
| **Wire codec reuse** | No | No | `rustbgpd-wire` standalone crate |

**Key idea:** Config file bootstraps initial state, then gRPC owns the truth at runtime. No restarts to add peers, change policy, or inject routes.

## Highlights

- **Dual-stack (IPv4 + IPv6)** -- MP-BGP (RFC 4760) with `MP_REACH_NLRI` / `MP_UNREACH_NLRI` for IPv6 unicast; IPv4 backward compatible
- **gRPC-native** -- five services covering peer lifecycle, RIB queries, route injection, streaming events, and daemon control
- **RFC 4271 compliant** -- full FSM, path attribute validation, best-path selection, split horizon, Adj-RIB-In / Loc-RIB / Adj-RIB-Out
- **Inbound + outbound peering** -- accepts incoming TCP connections and initiates outbound; passive peering supported
- **Dynamic peer management** -- add, delete, enable, and disable neighbors at runtime via gRPC
- **Policy engine** -- match + modify + filter with named policies and chaining: prefix, community, AS_PATH regex matching; set LOCAL_PREF, MED, communities, AS_PATH prepend, next-hop on import/export
- **Real-time streaming** -- `WatchRoutes` delivers add/withdraw/best-change events over server-streaming RPC
- **Observable by default** -- Prometheus metrics, structured JSON logging, per-peer counters
- **Interop validated** -- automated test suites against FRR 10.3.1 and BIRD 2.0.12 via containerlab
- **Graceful Restart** -- RFC 4724 helper mode plus minimal restarting-speaker signaling: stale route preservation, per-family End-of-RIB, timer-based sweep, `R=1` after coordinated restart, enabled by default
- **Large communities** -- RFC 8092 wire codec, RIB, gRPC API, and policy matching for 4-byte ASN operators
- **Route Reflector** -- RFC 4456 client/non-client reflection, ORIGINATOR_ID/CLUSTER_LIST, loop detection
- **Extended Messages** -- RFC 8654 raises the 4096-byte message limit to 65535 bytes
- **Extended Next Hop** -- RFC 8950 advertises and accepts IPv4 unicast NLRI over IPv6 next hop for dual-stack peers
- **Enhanced Route Refresh** -- RFC 7313 `BoRR` / `EoRR` markers with inbound family replacement semantics for `SoftResetIn`
- **Add-Path** -- RFC 7911 dual-stack receive + multi-path send (route server mode) for IPv4 and IPv6 unicast
- **Transparent route server mode** -- config-driven eBGP unicast transparency preserves original next hop and skips automatic local-AS prepend for IX route-server clients
- **RPKI origin validation** -- RFC 6811: persistent RTR client (RFC 8210) keeps sessions open, honors `SerialNotify`, enforces expiry, stamps routes Valid/Invalid/NotFound, and integrates into best-path and policy
- **FlowSpec** -- RFC 8955/8956: IPv4 and IPv6 traffic filtering rules distributed via BGP; 13 match component types, rate-limit/redirect/mark actions via extended communities
- **BMP export** -- RFC 7854: stream peer state and route monitoring to collectors (OpenBMP, pmacct); per-collector TCP with reconnect, Peer Up replay, periodic Stats Report
- **Extended Communities** -- RFC 4360: route target, route origin, 4-byte AS subtypes; policy matching with logical RT/RO equivalence
- **Route Refresh** -- RFC 2918: inbound re-advertisement on demand via gRPC `SoftResetIn`
- **Admin Shutdown** -- RFC 8203: human-readable reason text in Cease NOTIFICATION; threaded from gRPC `DisableNeighbor`
- **CLI tool** -- `rustbgpctl` wraps the gRPC API with human-readable tables and `--json` structured output
- **909 tests** -- unit, integration, property tests, and fuzzed wire decoder

## Quick Start

### Prerequisites

- **Rust 1.88+** (edition 2024)
- **protobuf-compiler** (`apt-get install protobuf-compiler` on Debian/Ubuntu)
- **grpcurl** (optional, for verifying the gRPC API directly)

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
families = ["ipv4_unicast", "ipv6_unicast"]

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
# Using rustbgpctl (recommended)
rustbgpctl health
rustbgpctl neighbor
rustbgpctl rib

# Or using grpcurl directly
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  localhost:50051 rustbgpd.v1.NeighborService/ListNeighbors
```

## Architecture

```
              +-----------+
              | transport |──► fsm ──► wire
              +-----------+        ◄── policy
                  │   │
                  │   └──► bmp
                  ▼
  rpki ──►    +-----+
              | rib | ◄── policy
              +-----+
                  │
                  ▼
              +-----+       +-----------+
              | api |──────►| telemetry |
              +-----+       +-----------+
```

Ten crates with strict dependency rules:

| Crate | Description |
|-------|-------------|
| `rustbgpd-wire` | BGP message codec. Zero internal deps. Independently publishable and fuzzed. |
| `rustbgpd-fsm` | RFC 4271 state machine. Pure -- no tokio, no sockets, no tasks. |
| `rustbgpd-transport` | Tokio TCP glue. The only crate that touches async I/O. |
| `rustbgpd-rib` | Adj-RIB-In, Loc-RIB best-path, Adj-RIB-Out. Single-task ownership, no locks. |
| `rustbgpd-policy` | Policy engine: prefix/community/AS_PATH matching, route modifications. |
| `rustbgpd-rpki` | RPKI origin validation: RTR client, VRP table, multi-cache aggregation. |
| `rustbgpd-bmp` | BMP exporter: RFC 7854 codec, collector clients, manager fan-out. |
| `rustbgpd-api` | gRPC server (tonic). Five services, proto codegen at build time. |
| `rustbgpd-telemetry` | Prometheus metrics + structured tracing. |
| `rustbgpctl` | CLI tool. Client-only gRPC stubs, no internal crate deps. |

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
| `NeighborService` | `AddNeighbor`, `DeleteNeighbor`, `ListNeighbors`, `GetNeighborState`, `EnableNeighbor`, `DisableNeighbor`, `SoftResetIn` | Peer lifecycle + inbound soft reset |
| `RibService` | `ListReceivedRoutes`, `ListBestRoutes`, `ListAdvertisedRoutes`, `ListFlowSpecRoutes`, `WatchRoutes` | RIB queries and streaming |
| `InjectionService` | `AddPath`, `DeletePath`, `AddFlowSpec`, `DeleteFlowSpec` | Programmatic route and FlowSpec injection |
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

`[global.runtime_state_dir]` defaults to `/var/lib/rustbgpd` and must be
writable by the daemon process. In containers or non-root deployments, point it
at a writable mounted path.

**`[global.telemetry]`** -- Prometheus bind address, log format (`json`), gRPC bind address (default `127.0.0.1:50051`).

**`[[neighbors]]`** -- One block per peer: `address`, `remote_asn`, optional `description`, `hold_time` (default 90), `max_prefixes`, `md5_password`, `ttl_security`, `families` (address families to negotiate, default `["ipv4_unicast"]`), `graceful_restart` (default `true`), `gr_restart_time` (default 120), `gr_stale_routes_time` (default 360).

**`[rpki]`** -- RPKI origin validation. Connect to one or more RTR cache validators. Routes stamped Valid/Invalid/NotFound, integrated into best-path selection and policy matching.

**`[policy]`** -- Global import/export policy. Inline entries or named definitions with chain references. Each entry has `action` (`permit`/`deny`), match conditions (`prefix`, `match_community`, `match_as_path`, `match_rpki_validation`), and optional route modifications (`set_local_pref`, `set_med`, `set_next_hop`, `set_community_add`/`remove`, `set_as_path_prepend`). Named policies are defined under `[policy.definitions.*]` and chained via `import_chain`/`export_chain`.

**`[[neighbors.import_policy]]` / `[[neighbors.export_policy]]`** -- Per-neighbor policy overrides. Same format as global policy entries.

Example with policy actions:

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "transit"

# Prefer routes from AS 65100
[[neighbors.import_policy]]
action = "permit"
match_as_path = "^65100_"
set_local_pref = 200

# Block RFC 1918
[[neighbors.import_policy]]
action = "deny"
prefix = "10.0.0.0/8"
le = 32

# Prepend on export
[[neighbors.export_policy]]
action = "permit"
prefix = "192.168.0.0/16"
set_as_path_prepend = { asn = 65001, count = 2 }
set_community_add = ["65001:100"]
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
containerlab deploy -t tests/interop/m4-frr.clab.yml

# Run the automated test suite (17 tests)
bash tests/interop/scripts/test-m4-frr.sh
```

See [docs/INTEROP.md](docs/INTEROP.md) for full test procedures, results, and troubleshooting.

## Project Status

**Pre-release.** 909 tests pass. P0+P1+P2 complete. Extended Messages (RFC 8654), Extended Next Hop (RFC 8950), Enhanced Route Refresh (RFC 7313), minimal restarting-speaker Graceful Restart, dual-stack Add-Path receive + family-aware multi-path send (RFC 7911), RPKI origin validation (RFC 6811, persistent RTR with `SerialNotify` + expiry), dual-stack FlowSpec (RFC 8955/8956), BMP export (RFC 7854), and `rustbgpctl` CLI shipped. Interop validated against FRR 10.3.1 and BIRD 2.0.12.

| Feature | Version | Scope |
|---------|---------|-------|
| Core BGP | v0.1.0 | OPEN/KEEPALIVE/NOTIFICATION, RFC 4271 FSM, UPDATE decode/encode |
| RIB | v0.1.0 | Adj-RIB-In, Loc-RIB best-path (RFC 4271 §9.1.2), Adj-RIB-Out, split horizon |
| gRPC API | v0.1.0 | 5 services: Global, Neighbor, RIB, Injection, Control |
| Dynamic peers | v0.1.0 | Add/delete/enable/disable neighbors at runtime |
| Transport | v0.1.0 | Inbound listener, TCP MD5/GTSM, NLRI batching, collision detection |
| Operations | v0.1.0 | Coordinated shutdown, gRPC supervision, Prometheus metrics |
| MP-BGP (IPv6) | v0.2.0 | RFC 4760: MP_REACH/UNREACH, dual-stack, AFI/SAFI negotiation |
| Graceful Restart | v0.3.0 | RFC 4724: helper mode, stale route demotion, End-of-RIB, timer sweep, minimal restarting-speaker `R=1` after coordinated restart |
| Extended Communities | unreleased | RFC 4360: route target, route origin, policy matching (ADR-0025/0026) |
| Route Refresh | unreleased | RFC 2918 + RFC 7313: inbound re-advertisement, BoRR/EoRR (ADR-0027/0038) |
| Policy engine | unreleased | Named policies, chaining, match + modify + filter, AS_PATH regex (ADR-0030/0036) |
| Large communities | unreleased | RFC 8092: wire codec, RIB, gRPC API, policy matching (ADR-0031) |
| Route Reflector | unreleased | RFC 4456: client/non-client reflection, ORIGINATOR_ID/CLUSTER_LIST (ADR-0029) |
| Extended Messages | unreleased | RFC 8654: raise 4096-byte limit to 65535 bytes (ADR-0032) |
| Add-Path | unreleased | RFC 7911: dual-stack receive + multi-path send (ADR-0033) |
| Extended Next Hop | unreleased | RFC 8950: IPv4 unicast over IPv6 next hop (ADR-0037) |
| RPKI validation | unreleased | RFC 6811 + RFC 8210: RTR client, VRP table, best-path integration (ADR-0034) |
| FlowSpec | unreleased | RFC 8955/8956: IPv4 and IPv6 traffic filtering rules (ADR-0035) |
| Transparent route server | unreleased | Config-driven eBGP unicast transparency for IX (ADR-0039) |
| Admin Shutdown | unreleased | RFC 8203: human-readable reason text in Cease NOTIFICATION |
| BMP export | unreleased | RFC 7854: peer state and route monitoring to collectors (ADR-0041) |
| CLI tool | unreleased | `rustbgpctl`: human-readable tables and `--json` output |

Next: config persistence, MRT dump, and benchmark hardening. See [ROADMAP.md](ROADMAP.md) for the full plan.

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
