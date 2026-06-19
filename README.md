<p align="center">
  <img src="rustbgpd-logo.png" alt="rustbgpd logo" width="250">
</p>

# rustbgpd

[![Build](https://github.com/lance0/rustbgpd/actions/workflows/ci.yml/badge.svg)](https://github.com/lance0/rustbgpd/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-1.95+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

An API-first BGP daemon in Rust, built for programmable data-center fabric,
route-server, and automation-heavy control-plane use cases. gRPC is the primary
interface for all peer lifecycle, routing, and policy operations. The config
file bootstraps initial state; after startup, gRPC owns the truth. No restarts
to add peers, change policy, or inject routes.

**Status: public alpha.** Feature-complete for the initial programmable
control-plane target and expanding toward cloud / AI-scale data-center fabric
use. Dual-stack BGP/MP-BGP, Add-Path, GR/LLGR, RPKI/RTR, ASPA path
verification, FlowSpec, BMP, MRT, BFD, EVPN/VXLAN alpha, and full gRPC/CLI
management are implemented. Default-off Linux FIB integration exists for RFC
7999 discard routes and configured unicast FIB tables, including ECMP and
weighted multipath; broader routing-suite features remain future work.
Validated with a workspace test suite, fuzz targets, and an automated interop
suite — primarily against FRR 10.3.1, plus GoBGP 4.3.0 and StayRTR-backed RTR
coverage; BIRD 2.0.12 has documented M0 validation and BIRD 3.2.1 backs the
TCP-AO smoke. A foundation tier runs on every PR, and the privileged Linux
dataplane smokes run in hosted kernel-dataplane CI; longer soaks and platform
diversity scripts remain local / manual gates. See
`docs/INTEROP.md` for the full matrix.

> **Alpha expectations:** The config format and gRPC API are not yet frozen.
> Breaking changes are possible between minor versions. The daemon runs on
> Linux (the primary target); other platforms are not tested. See
> [Project Status](#project-status) for details.

## Why rustbgpd

- **API-first control plane** -- full gRPC control surface across 11 services plus a thin CLI (`rbgp`; compatible `rustbgpctl` spelling also ships) with colored tables, dynamic column alignment, and human-readable uptimes. Dynamic peer management, dynamic-neighbor and FIB-table CRUD, route injection, policy CRUD, peer groups, BFD inspection, EVPN instance queries, streaming events, and daemon control without restarts.
- **Explicit architecture** -- pure FSM with no I/O, single-owner RIB with no locks, bounded channels between tasks. No `Arc<RwLock>` on routing state. See [ARCHITECTURE.md](ARCHITECTURE.md).
- **Dual-stack and modern protocol support** -- MP-BGP, Add-Path, Extended Next Hop, Extended Messages, GR/LLGR/Notification GR, Route Refresh/Enhanced Route Refresh, receive-side Prefix ORF, FlowSpec, Route Reflector, large and extended communities.
- **Operational visibility** -- Prometheus metrics, gNMI / OpenConfig BGP telemetry (`Capabilities` / `Get` / `Subscribe`, RFC 7951 JSON over mTLS) plus a transaction-backed `Set` subset for static numbered-neighbor config, BMP export to collectors, MRT TABLE_DUMP_V2 snapshots, birdwatcher-compatible looking glass REST API, structured JSON logging, per-peer counters, best-path explain.
- **Evidence-driven correctness** -- fuzz targets on the wire decoder, property tests on the FSM, automated containerlab interop primarily against FRR plus GoBGP / StayRTR and documented BIRD coverage, extensive workspace tests, architecture decision records for every protocol and design choice.
- **Reusable wire codec** -- `rustbgpd-wire` has zero internal dependencies and is independently publishable. Anyone building BGP tooling in Rust can use it without the daemon.

## Good fit

- **DDoS mitigation platforms** — FlowSpec + RTBH route injection from automation
- **Cloud / AI-scale data-center fabrics** — API-first BGP control, BFD, ECMP,
  EVPN/VXLAN alpha, and whitebox-friendly interop surfaces
- **Hosting provider prefix management** — API-driven customer prefix announcements
- **Internet exchange route servers** — transparent mode, Add-Path, RPKI, Prefix ORF, per-member policy
- **SDN / network automation controllers** — programmable BGP control plane
- **Route collectors and looking glasses** — structured data via gRPC, MRT, BMP, birdwatcher-compatible REST API
- **Lab and test environments** — clean API, structured logs, containerlab interop

Future BGP-LS, VPNv4/v6, RTC, and labeled-unicast work is scoped by
[ADR-0077](docs/adr/0077-mpls-vpn-bgpls-address-family-boundary.md): those
families must land as typed route-family slices or unreachable substrate, not as
unicast `Prefix` shortcuts or MPLS dataplane creep.

See [docs/USE_CASES.md](docs/USE_CASES.md) for detailed deployment scenarios with
architecture diagrams, example configs, and API workflows.

## Not the best fit today

- Full general-purpose router deployments expecting default-on,
  fully policy-guarded FIB integration
- Large-scale production EVPN fabrics that need the full feature
  surface — VXLAN EVPN is functional and FRR-interop-tested but still
  **alpha**. VXLAN local-bias split-horizon remains the one open
  all-active correctness gate (ASIC/offload-dependent on the Linux
  softswitch — see ADR-0065); service-provider EVPN families such as
  MPLS / PBB / MVPN are deliberately out of the current VXLAN/Linux
  lane. See [Current limitations](#current-limitations) for the alpha
  boundary and [docs/evpn-enablement.md](docs/evpn-enablement.md) for
  the shipped feature ladder and standards-tail map
- VPNv4 / VPNv6 overlays
- Environments that need the breadth of FRR's multi-decade feature surface
- Operators who want a CLI-first operational model

See [docs/COMPARISON.md](docs/COMPARISON.md) for a detailed feature comparison
with FRR, BIRD, GoBGP, and OpenBGPd.

## Try it (60 seconds)

The fastest way to see rustbgpd in action. Spins up the daemon with an FRR
peer that advertises sample IPv4 and IPv6 prefixes — no real routers needed.

```bash
cd examples/docker-compose
docker compose up -d
```

Once both containers are running (a few seconds):

```bash
# See the FRR peer come up
docker compose exec rustbgpd rbgp -s http://127.0.0.1:50051 neighbor

# Browse the RIB
docker compose exec rustbgpd rbgp -s http://127.0.0.1:50051 rib

# Live TUI dashboard — sessions, prefix counts, message rates
docker compose exec rustbgpd rbgp -s http://127.0.0.1:50051 top
```

![rbgp top — live TUI dashboard](docs/images/tui-screenshot.png)

Press `q` to exit the TUI. When you're done: `docker compose down`.

## Install

### From source

```bash
# Prerequisites: Rust 1.95+, protobuf-compiler
sudo apt-get install -y protobuf-compiler   # Debian/Ubuntu
cargo build --workspace --release

# Binaries are at target/release/rustbgpd, target/release/rbgp,
# and the compatible long-form target/release/rustbgpctl
```

### Docker

```bash
docker build -t rustbgpd .
```

## Quick start (bare metal)

For running rustbgpd on a real host with real peers.

### 1. Configure

Generate a starter config from a built-in profile — nothing to copy or hunt
down:

```bash
# `lab` = minimal single-box setup (gRPC over a local UDS, state in /tmp).
./target/release/rustbgpd --init-config lab --stdout > config.toml
$EDITOR config.toml   # set your ASN, router ID, and peer address
```

`edge` is an eBGP edge skeleton with a default-route-dropping import chain.
Each profile is validated through the real config loader before it is
printed, so the output always loads. Prefer a worked example? Copy one
instead:

```bash
cp examples/minimal/config.toml config.toml
```

The `lab` profile and the minimal example both set `runtime_state_dir` to a
user-writable path under `/tmp` and include `prometheus_addr` for metrics. For
a route-server deployment, start from `examples/route-server/config.toml`. Full
reference: [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

### 2. Validate and run

```bash
# Validate config without starting the daemon
./target/release/rustbgpd --check config.toml

# Preview what a config reload (SIGHUP) would change
./target/release/rustbgpd --diff new-config.toml config.toml

# Start the daemon
./target/release/rustbgpd config.toml
```

### 3. Verify

```bash
# The minimal example uses /tmp/rustbgpd as state dir, so point the CLI there:
export RUSTBGPD_ADDR=unix:///tmp/rustbgpd/grpc.sock

rbgp health
rbgp neighbor
rbgp rib
rbgp bfd       # BFD sessions, if configured
rbgp top       # live TUI dashboard

# If prometheus_addr is configured, HTTP probes share that listener:
curl -fsS http://127.0.0.1:9179/livez
curl -fsS http://127.0.0.1:9179/readyz
```

In production with the systemd unit, the default UDS path
(`/var/lib/rustbgpd/grpc.sock`) matches the CLI default — no env var needed.

### 4. Operate

```bash
# Add a peer at runtime (persisted to config file automatically)
rbgp neighbor 10.0.0.5 add --asn 65005
rbgp neighbor 203.0.113.2 add --asn 65002 --role provider --strict-role
rbgp neighbor fe80::5054:ff:fe00:1%eth1 add --asn 65101

# Add a dynamic-neighbor accept range at runtime (queued to config when --config is used)
rbgp dynamic-neighbor add 10.0.0.0/24 --peer-group ix-members

# Manage Linux unicast FIB-export tables at runtime (ADR-0061)
rbgp fib-table list

# Explain why a route was selected as best
rbgp rib --prefix 10.0.0.0/24 --explain

# Reload config after editing the file
kill -HUP $(pidof rustbgpd)

# Graceful shutdown (writes GR marker, notifies peers)
rbgp shutdown

# Enable shell completions (bash example)
rbgp completions bash > /etc/bash_completion.d/rbgp
# Or use pre-generated: examples/completions/
```

gRPC defaults to a local Unix domain socket. For remote access, configure
native mTLS on the TCP listener (`tls_cert_file` / `tls_key_file` /
`tls_client_ca_file` — all three required together; partial config is
rejected at load time and there is no TLS-without-mTLS half-mode). An
Envoy proxy front-end is also a valid pattern for multi-host fan-out;
see [`examples/envoy-mtls/`](examples/envoy-mtls/) and
[docs/SECURITY.md](docs/SECURITY.md).

### Docker (standalone)

```bash
docker run -d --name rustbgpd \
  -v $(pwd)/config.toml:/etc/rustbgpd/config.toml:ro \
  -v rustbgpd-state:/var/lib/rustbgpd \
  -p 179:179 -p 9179:9179 \
  rustbgpd
```

Or use systemd with [`examples/systemd/rustbgpd.service`](examples/systemd/rustbgpd.service).

## gRPC API

Eleven native `rustbgpd.v1` services cover the daemon's operational surface,
with a separate `gnmi.gNMI` service for OpenConfig BGP telemetry and the first
transaction-backed config subset:

| Service | RPCs | Purpose |
|---------|------|---------|
| `GlobalService` | `GetGlobal`, `SetGlobal` | Daemon identity and configuration |
| `ConfigService` | `DiffRuntimeConfig`, `PlanConfigTransaction`, `ApplyConfigTransaction`, `ConfirmConfigTransaction`, `AbortConfigTransaction`, `GetConfigTransactionStatus` | Candidate-vs-live config diff, plus the v1 config-transaction lifecycle: validate/plan, commit/apply (incl. commit-confirmed), confirm, abort, and status |
| `NeighborService` | `AddNeighbor`, `DeleteNeighbor`, `ListNeighbors`, `GetNeighborState`, `EnableNeighbor`, `DisableNeighbor`, `SoftResetIn`, `SetGracefulShutdown`, `AddDynamicNeighbor`, `DeleteDynamicNeighbor`, `ListDynamicNeighbors` | Peer lifecycle, inbound soft reset, RFC 8326 graceful-shutdown toggle, and dynamic-neighbor CRUD — `AddDynamicNeighbor` / `DeleteDynamicNeighbor` add and remove `[[dynamic_neighbors]]` prefix ranges at runtime (queued to config when started with `--config`), `ListDynamicNeighbors` for visibility |
| `PolicyService` | `ListPolicies`, `GetPolicy`, `SetPolicy`, `DeletePolicy`, `List/Get/Set/DeleteNeighborSet`, `Get*Chain`, `Set*Chain`, `Clear*Chain`, `ExplainImportPolicy` | Named policy CRUD, neighbor sets, global/per-neighbor chain attachment, and import-policy decision explain |
| `PeerGroupService` | `ListPeerGroups`, `GetPeerGroup`, `SetPeerGroup`, `DeletePeerGroup`, `SetNeighborPeerGroup`, `ClearNeighborPeerGroup` | Peer-group CRUD and neighbor membership assignment |
| `RibService` | `ListReceivedRoutes`, `ListBestRoutes`, `ListAdvertisedRoutes`, `ExplainAdvertisedRoute`, `ExplainBestPath`, `ListFlowSpecRoutes`, `ListEvpnRoutes`, `ListBlackholeDiscards`, `ListFibRoutes`, `ListFibTables`, `SetFibTable`, `DeleteFibTable`, `ListRouteEvents`, `WatchRoutes`, `WatchRouteEvents` | RIB queries (incl. EVPN), BLACKHOLE discard status, paginated FIB status, runtime FIB-table CRUD, explain, recent route-event history with per-prefix drilldown, and streaming |
| `BfdService` | `GetBfdSessions` | Single-hop BFD session inspection for configured static neighbors |
| `EventService` | `WatchEvents`, `SubscribeFromEvent`, `ListEvpnEvents`, `ListSessionEvents`, `ListPolicyEvents` | Unified live stream for route, session lifecycle, BGP NOTIFICATION metadata, policy mutation, EVPN route events, BFD session events, and FIB / BLACKHOLE dataplane status-row summary events, with `stream_lagged` warnings for bounded-source backpressure; durable cursor replay via `SubscribeFromEvent` when `[event_history].enabled = true`; plus bounded after-the-fact EVPN, session-lifecycle, and policy-mutation history. Per-MAC EVPN dataplane categories remain follow-up work |
| `InjectionService` | `AddPath`, `DeletePath`, `AddFlowSpec`, `DeleteFlowSpec`, `AddEvpnRoute`, `DeleteEvpnRoute` | Programmatic route, FlowSpec, and EVPN injection |
| `ControlService` | `GetHealth`, `GetMetrics`, `Shutdown`, `TriggerMrtDump` | Health, metrics, lifecycle, MRT dumps |
| `EvpnService` | `GetEvpnRuntime`, `ListEvpnInstances`, `ListEvpnNexthops`, `ListEthernetSegments`, `ListIpVrfs`, `GetIpVrf`, `ClearDuplicateMacQuarantine`, `SetEthernetSegmentDrain`, `ApplyEvpnRuntime` | Local EVPN VTEP instance state, ADR-0059 FDB-nexthop ownership, ADR-0083/0085 Ethernet Segment multi-homing diagnose state, symmetric IRB (Type-5 / L3VNI) IP-VRF readiness / route counters, duplicate-MAC quarantine clear, ADR-0084 Ethernet Segment drain for access-circuit maintenance, and ADR-0063 runtime model status / apply |
| `gnmi.gNMI` | `Capabilities`, `Get`, `Set`, `Subscribe` | OpenConfig BGP telemetry subset (`Get` / `Subscribe`) plus a transaction-backed `Set` subset (static numbered-neighbor create/update/delete + commit-confirmed via ADR-0076; unsupported paths `UNIMPLEMENTED`); served on UDS and mTLS TCP listeners |

```bash
# Stream route changes in real time over the default UDS listener
grpcurl -plaintext -unix /var/lib/rustbgpd/grpc.sock \
  -import-path . -proto proto/rustbgpd.proto \
  rustbgpd.v1.RibService/WatchRoutes
```

Full API reference: [docs/API.md](docs/API.md). gNMI operator guide:
[docs/GNMI.md](docs/GNMI.md).

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
| [`examples/docker-compose/`](examples/docker-compose/) | Quick-start with Docker Compose — rustbgpd + FRR peer with sample routes |
| [`examples/minimal/`](examples/minimal/) | Smallest working config — single eBGP peer |
| [`examples/route-server/`](examples/route-server/) | IXP route server with RPKI, Add-Path, policy chains |
| [`examples/ddos-mitigation/`](examples/ddos-mitigation/) | FlowSpec + RTBH for automated DDoS mitigation |
| [`examples/hosting-provider/`](examples/hosting-provider/) | iBGP route injector for customer prefix management |
| [`examples/linux-edge-fib/`](examples/linux-edge-fib/) | Linux edge host with explicit ADR-0061 `[[fib_tables]]` unicast FIB programming |
| [`examples/route-collector/`](examples/route-collector/) | Passive collector with MRT dumps and BMP export |
| [`examples/rr-evpn-fabric/`](examples/rr-evpn-fabric/) | EVPN Route Reflector for a VXLAN-EVPN DC fabric (RFC 7432, RR role) |
| [`examples/evpn-vtep-leaf/`](examples/evpn-vtep-leaf/) | Leaf VTEP with local `[[evpn_instances]]` declarations (declarative EVPN instance schema) |
| [`examples/envoy-mtls/`](examples/envoy-mtls/) | Remote gRPC access via Envoy mTLS proxy |
| [`examples/systemd/`](examples/systemd/) | systemd unit file with security hardening |

## Security posture

- **Default listener:** Unix domain socket at `/var/lib/rustbgpd/grpc.sock` — local-only, no TCP exposure
- **Optional read-only listeners:** expose monitoring/query RPCs without exposing mutating control RPCs
- **Remote access:** native gRPC mTLS on the TCP listener (`tls_cert_file` / `tls_key_file` / `tls_client_ca_file`), or an Envoy mTLS proxy front-end for multi-host fan-out — never plaintext TCP off-host
- **Network controls:** put gRPC on a management VLAN/interface and firewall it to known hosts

## Testing and correctness

| Evidence | Details |
|----------|---------|
| Workspace tests | Unit, integration, and property tests (`cargo test --workspace`) |
| Wire fuzzing | libFuzzer harnesses on message and attribute decoders, CI smoke + nightly extended |
| Interop suites | Automated interop suite (see `docs/INTEROP.md` for the full matrix), primarily against FRR 10.3.1 plus GoBGP 4.3.0 and StayRTR-backed RTR coverage; BIRD 2.0.12 covers M0 and BIRD 3.2.1 covers the TCP-AO smoke. A foundation tier is gated on every PR, privileged Linux dataplane smokes run in hosted kernel-dataplane CI, and longer soaks / platform-diversity scripts remain local. |
| Operational proof | Consolidated receipts for CI interop, hosted kernel dataplane, benchmarks, memory profiles, and archived 24 h soaks live in [docs/OPERATIONAL_PROOF.md](docs/OPERATIONAL_PROOF.md). |
| Protocol coverage | RFC 4271 FSM + UPDATE validation, MP-BGP, GR/LLGR, Add-Path, FlowSpec, RPKI, ASPA, Extended Messages, Extended Next Hop, Route Refresh/ERR, receive-side Prefix ORF, RFC 7999 BLACKHOLE receiver scoping + opt-in FIB discard, ADR-0061/0066/0068 configured-table unicast Linux FIB programming with ECMP / weighted multipath, RFC 5880/5881/5882 BFD, RFC 8326 Graceful Shutdown |
| Architecture decisions | ADRs documenting every protocol and design choice ([docs/adr/](docs/adr/)) |

```bash
# Run interop tests
containerlab deploy -t tests/interop/m4-frr.clab.yml
bash tests/interop/scripts/test-m4-frr.sh
```

See [docs/INTEROP.md](docs/INTEROP.md) for full procedures and results.

## Current limitations

- Linux FIB integration is opt-in and scoped: RFC 7999 BLACKHOLE
  discard routes and configured `[[fib_tables]]` unicast route
  installation are available, with per-peer / peer-group allow-lists
  and per-table route-count caps for the general FIB path. ADR-0066/0068
  add opt-in unicast ECMP via `maximum_paths`, per-class
  `maximum_paths_ebgp` / `maximum_paths_ibgp`, `multipath_relax`, and Link
  Bandwidth weighted multipath. The general FIB actor persists exact owned-state
  receipts for crash-restart recovery without adopting `RTPROT_BGP` by protocol
  alone. Full router parity still needs broader redistribution policy and
  non-BGP route-manager scope
- EVPN (RFC 7432 / RFC 9136) is **alpha** and Linux / VXLAN-only.
  Shipped and FRR-interop-tested: the Route Reflector role (all five
  route types reflected end-to-end), a bidirectional single-homed L2VNI
  VTEP (remote-MAC FDB programming, local MAC-only / MAC+IP / SVI Type 2
  origination with RFC 7432 §15.1 mobility, Type 3 IMET, push-notified
  sub-second convergence), symmetric Interface-less IRB / Type 5
  (RFC 9136, transactional L3 FIB programming), opt-in active-active
  multi-homing (DF election, Type 1/4, BUM suppression, aliasing ECMP via
  FDB nexthop groups), duplicate-MAC detection with quarantine + manual
  clear, and gRPC controller injection for Types 2 / 3 / 5. See
  ADR-0052 / 0054–0059 / 0063 and
  [docs/evpn-enablement.md](docs/evpn-enablement.md) for the full gate
  ladder. Known gaps: runtime `[[evpn_instances]]` mutation is
  alpha-complete with two by-design exceptions — `ApplyEvpnRuntime`
  commits L2VNI / IP-VRF / Ethernet-Segment add/delete/redefine, atomic
  tenant teardown, `ip_vrf` relink, and L2VNI-only mixed compositions live,
  while L3VNI/device/table IP-VRF identity changes (restart-required) and
  ES/IP-VRF row mixed edits fail closed ([#268](https://github.com/lance0/rustbgpd/issues/268));
  ESI overlay-index origination plus single-active and all-active
  ESI overlay-index receive now ship, with M71/M72 proving the receive
  paths against GoBGP route sources.
  VLAN-aware bridge support now covers VNI-per-broadcast-domain Linux
  topologies, including SVD / collect-metadata VXLAN; opt-in bridge
  netdev creation now ships under
  [ADR-0091](docs/adr/0091-evpn-managed-netdev-creation.md)
  (`[managed_netdevs]`), while VXLAN / VRF netdev creation remains
  operator-provisioned per
  [ADR-0088](docs/adr/0088-evpn-vlan-aware-bridge-managed-netdev-boundary.md);
  [ADR-0089](docs/adr/0089-evpn-vni-per-bd-vlan-aware-bridge-support.md)
  scopes the first VLAN-aware bridge support to VNI-per-broadcast-domain
  service with Ethernet Tag ID `0`.
  Service-provider EVPN breadth (route types 6-11, PBB-EVPN, multicast
  EVPN, MPLS/SRv6 encapsulation, VPWS/E-Tree) is demand-shaped rather than
  part of the current VXLAN/Linux alpha lane
- No VPNv4 / VPNv6 or Confederation support
- TCP-AO (RFC 5925) static-neighbor startup keys are supported on Linux;
  dynamic-neighbor TCP-AO, runtime key rotation, and multi-key rollover remain
  follow-up work. TCP MD5 and GTSM are also supported.
- BFD (RFC 5880 / 5881 / 5882) single-hop **asynchronous** sessions are
  supported: an in-process, no-GC actor runs sessions over UDP/3784, config via
  `[[bfd_profiles]]` + `[neighbors.bfd]`, observable through
  `BfdService.GetBfdSessions` / `rbgp bfd` / events + Prometheus, with
  RFC 5882 BGP coupling in both strict (withhold BGP until BFD Up) and
  non-strict (tear BGP down on BFD-down before the hold timer) modes —
  FRR-`bfdd`-interop-tested (M51). IPv4 + IPv6 global, static neighbors only;
  multihop (RFC 5883), echo / demand, authentication, dynamic-neighbor BFD, and
  IPv6 link-local (v1.1) remain follow-up work.
- BGP unnumbered (ADR-0069) static IPv6 link-local neighbors are supported for
  IPv4 unicast: TOML uses `address` plus `interface`, while gRPC and
  `rbgp` also render `fe80::...%ifname`; RFC 8950 route exchange uses the
  FRR-proven link-local MP_REACH shape; and opt-in Linux FIB install carries the
  egress device for `fe80::/10` next-hops. M53 validates this against FRR.
  Interface-neighbor autodiscovery, capability 77, and link-local BFD remain
  follow-up work.
- BGP Roles + Only-to-Customer (RFC 9234, ADR-0071) are supported for static
  eBGP IPv4/IPv6 unicast neighbors. `role` advertises the Role capability,
  incompatible pairs fail closed with OPEN 2/11, `strict_role` requires the peer
  to advertise a compatible Role, and OTC is set/checked on unicast UPDATEs
  while FlowSpec/EVPN stay untouched in v1. M55 validates FRR interop plus
  deliberate raw-BGP leak and malformed-OTC handling.
- Published benchmarks: bgperf2 covers IPv4 unicast at 10 peers × 1k, 2 peers × 10k, and 2 peers × 100k prefixes; the in-tree `bench/evpn-load` M33 scale gate covers 50,000 reflected Type 2 routes with 60 s of 1,000-rps churn (5.1 s initial convergence, post-churn distinct-key count exact). Capability-specific 24h soak harnesses now ship in-tree under `tests/soak/`: an EVPN BUM-flood-suppression BUM-state harness and a symmetric IRB (Type-5 / L3VNI) 24h Type 5 churn harness, both with post-mortems under `docs/soak-*.md`. Continuous / multi-day soak automation beyond those harnesses remains future work (see [docs/BENCHMARKS.md](docs/BENCHMARKS.md))

## Project status

**Alpha — suitable for lab, data-center fabric pilots, IX route-server pilots,
and programmable control-plane deployments where you are comfortable with an
evolving API.**

| Dimension | Current state |
|-----------|---------------|
| **Target use case** | Data-center fabric pilots, IXP route servers, programmable BGP control planes, lab/test environments |
| **Maturity** | Public alpha (v0.41.0) |
| **Supported OS** | Linux (primary target). Requires `CAP_NET_BIND_SERVICE` for port 179. |
| **Runtime** | Rust 1.95+ (workspace MSRV — set by the bundled SQLite build), single binary, no external dependencies except optional RPKI/BMP/MRT backends |
| **Config stability** | TOML format may change between minor versions; migrations documented in CHANGELOG |
| **API stability** | gRPC proto may add fields/RPCs; breaking changes documented in CHANGELOG |
| **Not yet supported** | EVPN runtime L3VNI/device/table IP-VRF identity changes (restart-required by design) and ES/IP-VRF row mixed edits outside the L2VNI-only composer, true RFC VLAN-aware bundle / non-zero Ethernet Tag service, rustbgpd-managed VXLAN / VRF netdev creation, EVPN route types 6-11 / PBB / MVPN / MPLS/SRv6 service encapsulation, VPNv4/v6, labeled-unicast, Route Target Constraints, BGP-LS, Confederation, TCP-AO dynamic-neighbor / runtime-rotation / multi-key rollover |
| **Tests** | Workspace test suite, fuzz targets, an automated interop suite (see `docs/INTEROP.md`) primarily against FRR plus GoBGP / StayRTR / documented BIRD coverage, and an in-tree EVPN load generator (foundation tier gated on every PR; privileged kernel dataplane smokes run on GitHub-hosted CI) |

## Documentation

| Document | Content |
|----------|---------|
| [docs/USE_CASES.md](docs/USE_CASES.md) | Deployment scenarios: DDoS, hosting, IX, SDN, collector |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Crate graph, runtime model, ownership, data flow |
| [docs/DESIGN.md](docs/DESIGN.md) | Tradeoffs, protocol scope, rationale |
| [docs/API.md](docs/API.md) | gRPC API reference with examples for every RPC |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Config reference and examples |
| [docs/deployment.md](docs/deployment.md) | End-to-end install + lifecycle walkthrough: systemd, Docker, containerlab quick-start, upgrade, sample profiles |
| [docs/reload-matrix.md](docs/reload-matrix.md) | Per-field reload classification: which keys hot-apply, which need a restart, which are rejected at parse time |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Running in production: reload, upgrade, failure modes, debugging |
| [docs/SECURITY.md](docs/SECURITY.md) | Security posture, firewall guidance, deployment tiers |
| [docs/BENCHMARKS.md](docs/BENCHMARKS.md) | Wire codec and RIB performance numbers, scaling analysis |
| [docs/OPERATIONAL_PROOF.md](docs/OPERATIONAL_PROOF.md) | Consolidated operational proof receipts: CI interop, dataplane, benchmarks, memory, soak |
| [docs/COMPARISON.md](docs/COMPARISON.md) | Feature comparison with FRR, BIRD, GoBGP, OpenBGPd |
| [docs/INTEROP.md](docs/INTEROP.md) | Interop test coverage and results |
| [docs/evpn-enablement.md](docs/evpn-enablement.md) | EVPN Phase 1-9 gate ladder: what each gate unlocks, work per gate, priority |
| [docs/evpn-vtep-setup.md](docs/evpn-vtep-setup.md) | EVPN VTEP kernel setup: `ip link` recipes for L2VNI / IP-VRF / multi-homing mapped to the ADR-0054 §4 + ADR-0058 §3 readiness checks (operator-provisioned netdevs) |
| [docs/evpn-vtep-troubleshooting.md](docs/evpn-vtep-troubleshooting.md) | EVPN VTEP alpha troubleshooting runbook |
| [docs/gobgp-parity.md](docs/gobgp-parity.md) | rustbgpd vs GoBGP feature parity by use case |
| [docs/adr/](docs/adr/) | Architecture decision records — one per protocol and design choice |
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
