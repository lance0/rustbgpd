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

The practical beachhead is explainable route-server and route-reflector
operation: per-peer received / best / advertised views, policy and export-gate
explain output, BMP/MRT/metrics, and receipt-backed interop around those roles.

**Status: public alpha.** Feature-complete for the initial programmable
control-plane target and expanding toward cloud / AI-scale data-center
fabric use.

- **Implemented:** dual-stack BGP/MP-BGP, Add-Path, GR/LLGR, RPKI/RTR, ASPA
  path verification, FlowSpec, BMP, MRT, BFD, EVPN/VXLAN (alpha), and full
  gRPC/CLI management. Linux FIB integration is default-off and scoped to
  RFC 7999 discard routes and configured unicast tables (including ECMP and
  weighted multipath); broader routing-suite features remain future work.
- **Validated** with a workspace test suite, fuzz targets, and an automated
  interop suite — primarily against FRR 10.3.1, plus GoBGP 3.37.0–4.6.0 and
  StayRTR-backed RTR coverage, with BIRD 2.0.12 (M0) and BIRD 3.3.1 (TCP-AO
  smoke). A foundation tier runs on every PR and the privileged Linux
  dataplane smokes run in hosted CI; longer soaks and platform-diversity
  scripts remain local. Full matrix: [`docs/INTEROP.md`](docs/INTEROP.md).

> **Alpha expectations:** The config format and gRPC API are not yet frozen.
> Breaking changes are possible between minor versions. The daemon runs on
> Linux (the primary target); other platforms are not tested. See
> [Project Status](#project-status) for details.

## Why rustbgpd

- **API-first control plane** -- full gRPC control surface across 11 services plus a thin CLI (`rbgp`) with colored tables, dynamic column alignment, and human-readable uptimes. Dynamic peer management, dynamic-neighbor and FIB-table CRUD, route injection, policy CRUD, peer groups, BFD inspection, EVPN instance queries, streaming events, and daemon control without restarts.
- **Native route explainability** -- answers "why is this route (not) here?" from the live RIB in one command: import explain, best-path explain with decisive-comparison attribution, export explain that dry-runs the real per-peer gate ladder, and a retained rejected-route view with machine-readable reasons -- where incumbents need an external looking-glass stack for less. See [docs/explain.md](docs/explain.md).
- **Explicit architecture** -- pure FSM with no I/O, single-owner RIB with no locks, bounded channels between tasks. No `Arc<RwLock>` on routing state. See [ARCHITECTURE.md](ARCHITECTURE.md).
- **Dual-stack and modern protocol support** -- MP-BGP, Add-Path, Extended Next Hop, Extended Messages, GR/LLGR/Notification GR, Route Refresh/Enhanced Route Refresh, receive-side Prefix ORF, FlowSpec, Route Reflector, large and extended communities.
- **Typed, compiled policy language** (`.rpol`, ADR-0096) -- named prefix/community sets compiled to indexed matchers, parameterized policies, policy composition, and in-language unit tests (`rbgp policy check`); candidate policies dry-run read-only against the live RIB (`rbgp policy test`), decisions explain themselves per term (`rbgp policy explain`), and installed chains expose live per-term hit counters (`rbgp policy stats`). Mixes freely with the existing TOML policy chains; FRR route-map parity proven route-for-route in interop (M80). See [docs/rpol-language.md](docs/rpol-language.md).
- **Full BMP monitoring trio** (RFC 7854/8671/9069, ADR-0097) -- per-collector selectable Adj-RIB-In (pre-policy), Adj-RIB-Out (post-policy, byte-exact wire PDUs), and Loc-RIB views on one exporter. Loc-RIB collectors get a chunked table dump + End-of-RIB when they connect; Adj-RIB-In/Out are live streams by design. Optional per-collector BMPv4 TLV framing plus the Path Marking TLV (draft-ietf-grow-bmp-tlv / draft-ietf-grow-bmp-path-marking-tlv, pre-IANA -- code points may renumber; default stays BMP v3). Validated against pmacct, gobmp, and tshark at once (M81).
- **Operational visibility** -- Prometheus metrics, gNMI / OpenConfig BGP telemetry (`Capabilities` / `Get` / `Subscribe`, RFC 7951 JSON over mTLS) plus a transaction-backed `Set` subset for static numbered-neighbor config, BMP export to collectors (all three RIB views), MRT TABLE_DUMP_V2 snapshots, a Birdwatcher-shaped status/peer/accepted-route REST subset via the external `examples/birdwatcher-adapter`, structured JSON logging, and per-peer counters. The explain surfaces have their own catalog: [docs/explain.md](docs/explain.md).
- **Update-group fanout** (ADR-0098, ADR-0099) -- peers whose staged output is provably identical automatically share one outbound staging pass and one Arc-shared announce payload; measured ~28x faster 100k-route convergence at 256 uniform RR clients (15.1 s to 0.54 s), and 1.8 s wire-measured convergence / 419 MiB process RSS at 1,000 uniform RR clients x 100k routes ([scale receipt](docs/perf/scale-receipt-2026-07.md)), with a structural per-peer fallback (no knob) and a differential oracle pinning identical wire behavior. v2 extends the sharing to VPNv4/VPNv6 with the RFC 4684 RT filter applied per member at emit: 1,000 clients x 100k VPNv4 converge in 12.6 s / 625 MiB uniform and 3.9 s / 636 MiB with heterogeneous ~10% RT memberships (vs ~73 s / ~31 GiB and ~12.5 s / ~5.7 GiB extrapolated per-peer), and a member's RT-membership flip at 100k staged routes hits the wire in ~15 ms with zero policy evaluations.
- **Evidence-driven correctness** -- fuzz targets on the wire decoder, property tests on the FSM, automated containerlab interop primarily against FRR plus GoBGP / StayRTR and documented BIRD coverage, extensive workspace tests, architecture decision records for every protocol and design choice.
- **Reusable wire codec and FSM** -- `rustbgpd-wire` has zero internal dependencies and `rustbgpd-fsm` depends only on `wire`; both are published as daemon-independent crates for Rust BGP tooling that does not need the full router.

## Good fit

- **DDoS mitigation platforms** — FlowSpec + RTBH route injection from automation
- **Cloud / AI-scale data-center fabrics** — API-first BGP control, BFD, ECMP,
  EVPN/VXLAN alpha, and whitebox-friendly interop surfaces
- **Hosting provider prefix management** — API-driven customer prefix announcements
- **Internet exchange route servers** — transparent mode, Add-Path, per-client best-path (RFC 7947 path-hiding mitigation), RPKI, Prefix ORF, per-member policy
- **SDN / network automation controllers** — programmable BGP control plane
- **Route collectors and looking glasses** — structured data via gRPC, MRT, BMP, plus a Birdwatcher-shaped status/peer/accepted-route subset via the external `examples/birdwatcher-adapter` (not yet a complete Alice-LG backend)
- **Lab and test environments** — clean API, structured logs, containerlab interop

BGP-LS receive/reflection/API export (RFC 9552), VPNv4/VPNv6 L3VPN
route-reflection (RFC 4364 / RFC 4659, SAFI 128 — RR/controller-feed with RD,
MPLS label stack, next-hop, and Route Targets preserved verbatim; no VRF import
or MPLS FIB), RT-Constrain (RFC 4684, SAFI 132 — strict per-peer VPN
reflection filtering), and IPv4/IPv6 labeled-unicast route-reflection
(RFC 8277, SAFI 4 — label stack and next-hop preserved verbatim) have shipped
under ADR-0077, and **Optimal Route
Reflection (RFC 9107, ADR-0095)** computes per-client best paths via SPF over
the BGP-LS-sourced topology — a capability no other open-source BGP daemon
ships; future BGP-LS local topology
production stays scoped by
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
- VPNv4 / VPNv6 PE roles — VRF import, MPLS label forwarding, and CE-facing
  attachment circuits are out of scope; the shipped SAFI-128 support is the
  route-reflector / controller-feed slice only
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
docker compose exec rustbgpd rbgp -s http://127.0.0.1:50051 summary

# Browse the RIB
docker compose exec rustbgpd rbgp -s http://127.0.0.1:50051 rib

# Live TUI dashboard — sessions, prefix counts, message rates
docker compose exec rustbgpd rbgp -s http://127.0.0.1:50051 top
```

![rbgp top — live TUI dashboard](docs/images/tui-screenshot.png)

Press `q` to exit the TUI. When you're done: `docker compose down`.

## Install

### Pre-built tarball (no toolchain required)

Every tagged release ships static-named per-arch tarballs, so
`releases/latest/download/` always fetches the current version:

```bash
SUFFIX=linux-amd64   # or linux-arm64
curl -fLO "https://github.com/lance0/rustbgpd/releases/latest/download/rustbgpd-${SUFFIX}.tar.gz"
curl -fLO "https://github.com/lance0/rustbgpd/releases/latest/download/checksums-${SUFFIX}.txt"
sha256sum -c "checksums-${SUFFIX}.txt"
tar -xzf "rustbgpd-${SUFFIX}.tar.gz"
sudo install -m 0755 rustbgpd rbgp /usr/local/bin/
```

The tarball also carries man pages and bash/zsh/fish completions under
`share/` — the [install walkthrough](docs/deployment.md#install) covers
installing those and pinning a specific version.

### From source

```bash
# Prerequisites: Rust 1.95+, protobuf-compiler
sudo apt-get install -y protobuf-compiler   # Debian/Ubuntu
cargo build --release -p rustbgpd -p rustbgpctl

# Binaries are at target/release/rustbgpd and target/release/rbgp
```

### Docker

Release images are published to GHCR (versioned tags, e.g.
`ghcr.io/lance0/rustbgpd:0.51.0`), or build locally:

```bash
docker build -t rustbgpd .                    # lean runtime: daemon + rbgp, nonroot
docker build --target dev -t rustbgpd:dev .   # dev/interop image (lab helpers, root)
```

## Quick start (bare metal)

For running rustbgpd on a real host with real peers, see
[docs/QUICKSTART.md](docs/QUICKSTART.md). It covers starter config generation,
`--check` / `--diff`, local UDS access, HTTP probes, runtime peer operations,
remote mTLS access, standalone Docker, and systemd.

The [cookbook](docs/cookbook/README.md) has complete receipt-proven recipes for
the common deployment shapes: iBGP route reflector at scale, L3VPN reflection,
IXP route server, BMP/event/MRT monitoring feed, EVPN fabric RR, and `.rpol`
policy. IXPs running arouteserver can render rustbgpd configuration from their
existing `general.yml`/`clients.yml` and wire up an Alice-LG looking glass —
the [IXP filter-pipeline tutorial](docs/cookbook/ixp-filter-pipeline.md) walks
it end to end.

For operators coming from FRR, BIRD, or ARouteServer, the CLI keeps familiar
entry points for the daily checks: `rbgp summary`, `rbgp rib recv <peer>`,
`rbgp rib sent <peer>`, `rbgp policy counters`, and `rbgp doctor` for a
redacted support bundle. See the [CLI command map](crates/cli/README.md).

## gRPC API

Eleven native `rustbgpd.v1` services cover the daemon's operational surface,
with a separate `gnmi.gNMI` service for OpenConfig BGP telemetry and the first
transaction-backed config subset:

| Service | RPCs | Purpose |
|---------|------|---------|
| `GlobalService` | `GetGlobal` | Daemon identity |
| `ConfigService` | `DiffRuntimeConfig`, `PlanConfigTransaction`, `ApplyConfigTransaction`, `ConfirmConfigTransaction`, `AbortConfigTransaction`, `GetConfigTransactionStatus`, `GetEffectiveConfig` | Candidate-vs-live config diff, effective running config with defaults materialized and secrets redacted, plus the v1 config-transaction lifecycle: validate/plan, commit/apply (incl. commit-confirmed), confirm, abort, and status |
| `NeighborService` | `AddNeighbor`, `DeleteNeighbor`, `ListNeighbors`, `GetNeighborState`, `EnableNeighbor`, `DisableNeighbor`, `SoftResetIn`, `SetGracefulShutdown`, `AddDynamicNeighbor`, `DeleteDynamicNeighbor`, `ListDynamicNeighbors` | Peer lifecycle, inbound soft reset, RFC 8326 graceful-shutdown toggle, and dynamic-neighbor CRUD — `AddDynamicNeighbor` / `DeleteDynamicNeighbor` add and remove `[[dynamic_neighbors]]` prefix ranges at runtime (queued to config when started with `--config`), `ListDynamicNeighbors` for visibility |
| `PolicyService` | `ListPolicies`, `GetPolicy`, `SetPolicy`, `DeletePolicy`, `ListNeighborSets`, `GetNeighborSet`, `SetNeighborSet`, `DeleteNeighborSet`, `GetGlobalPolicyChains`, `GetNeighborPolicyChains`, `SetGlobalImportChain`, `SetGlobalExportChain`, `ClearGlobalImportChain`, `ClearGlobalExportChain`, `SetNeighborImportChain`, `SetNeighborExportChain`, `ClearNeighborImportChain`, `ClearNeighborExportChain`, `ExplainImportPolicy`, `ListRejectedRoutes`, `TestPolicy`, `GetPolicyStats` | Named policy CRUD, neighbor sets, global/per-neighbor chain attachment, import-policy decision explain (per-term traces for `.rpol` members), retained rejected-route views with reject reasons, read-only candidate-policy dry runs over the live RIB, and live per-term hit counters |
| `PeerGroupService` | `ListPeerGroups`, `GetPeerGroup`, `SetPeerGroup`, `DeletePeerGroup`, `SetNeighborPeerGroup`, `ClearNeighborPeerGroup` | Peer-group CRUD and neighbor membership assignment |
| `RibService` | `ListReceivedRoutes`, `ListBestRoutes`, `ListAdvertisedRoutes`, `ExplainAdvertisedRoute`, `ExplainBestPath`, `ListFlowSpecRoutes`, `ListEvpnRoutes`, `ListBgpLsRoutes`, `ListTopologyNodes`, `ListTopologyLinks`, `ListOrrStatus`, `ListVpnRoutes`, `ListRtcRoutes`, `ListLabeledRoutes`, `ListBlackholeDiscards`, `ListFibRoutes`, `ListFibTables`, `SetFibTable`, `DeleteFibTable`, `ListRouteEvents`, `WatchRoutes`, `WatchRouteEvents` | RIB queries (incl. EVPN, BGP-LS, VPNv4/v6, RT-Constrain, and labeled-unicast), the RFC 9107 ORR / BGP-LS topology read surface (`ListTopologyNodes` / `ListTopologyLinks` / `ListOrrStatus`), BLACKHOLE discard status, paginated FIB status, runtime FIB-table CRUD, explain, recent route-event history with per-prefix drilldown, and streaming |
| `BfdService` | `GetBfdSessions` | Single-hop BFD session inspection for configured static neighbors |
| `EventService` | `WatchEvents`, `SubscribeFromEvent`, `ListEvpnEvents`, `ListSessionEvents`, `ListPolicyEvents` | Unified live stream for route, session lifecycle, BGP NOTIFICATION metadata, policy mutation, EVPN route events, BFD session events, and FIB / BLACKHOLE dataplane status-row summary events, with `stream_lagged` warnings for bounded-source backpressure; durable cursor replay via `SubscribeFromEvent` when `[event_history].enabled = true`; plus bounded after-the-fact EVPN, session-lifecycle, and policy-mutation history. Per-MAC EVPN dataplane categories remain follow-up work |
| `InjectionService` | `AddPath`, `DeletePath`, `AddFlowSpec`, `DeleteFlowSpec`, `AddEvpnRoute`, `DeleteEvpnRoute` | Programmatic route, FlowSpec, and EVPN injection |
| `ControlService` | `GetHealth`, `GetMetrics`, `Shutdown`, `TriggerMrtDump` | Health, metrics, lifecycle, MRT dumps |
| `EvpnService` | `GetEvpnRuntime`, `ListEvpnInstances`, `ListEvpnNexthops`, `ListEthernetSegments`, `ListIpVrfs`, `ListManagedNetdevs`, `GetIpVrf`, `ClearDuplicateMacQuarantine`, `SetEthernetSegmentDrain`, `ApplyEvpnRuntime` | Local EVPN VTEP instance state, ADR-0059 FDB-nexthop ownership, ADR-0083/0085 Ethernet Segment multi-homing diagnose state, symmetric IRB (Type-5 / L3VNI) IP-VRF readiness / route counters, ADR-0091 managed-netdev lifecycle/status, duplicate-MAC quarantine clear, ADR-0084 Ethernet Segment drain for access-circuit maintenance, and ADR-0063 runtime model status / apply |
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
| [`examples/route-server/`](examples/route-server/) | IXP route server with RPKI, Add-Path + per-client best-path, rpol hygiene policy |
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
| Wire fuzzing | libFuzzer harnesses on message and attribute decoders, run nightly in CI |
| Interop suites | Automated interop suite (see `docs/INTEROP.md` for the full matrix), primarily against FRR 10.3.1 plus GoBGP 3.37.0–4.6.0 across labs and StayRTR-backed RTR coverage; BIRD 2.0.12 covers M0 and BIRD 3.3.1 covers the TCP-AO smoke. A foundation tier is gated on every PR, privileged Linux dataplane smokes run in hosted kernel-dataplane CI, and longer soaks / platform-diversity scripts remain local. |
| Operational proof | Consolidated receipts for CI interop, hosted kernel dataplane, benchmarks, memory profiles, and archived 24 h soaks live in [docs/OPERATIONAL_PROOF.md](docs/OPERATIONAL_PROOF.md). |
| Protocol coverage | [Supported standards at a glance](docs/RFC_NOTES.md#supported-standards-at-a-glance) plus per-RFC conformance notes in [docs/RFC_NOTES.md](docs/RFC_NOTES.md); interop matrix in [docs/INTEROP.md](docs/INTEROP.md) and receipts in [docs/RECEIPTS.md](docs/RECEIPTS.md). |
| Architecture decisions | ADRs documenting every protocol and design choice ([docs/adr/](docs/adr/)) |

```bash
# Run interop tests
containerlab deploy -t tests/interop/m4-frr.clab.yml
bash tests/interop/scripts/test-m4-frr.sh
```

See [docs/INTEROP.md](docs/INTEROP.md) for full procedures and results.

## Current limitations

The short version: rustbgpd is still not a general-purpose router replacement.
Linux FIB integration is opt-in, EVPN is Linux/VXLAN alpha, VPNv4/VPNv6 is RR /
controller-feed only, and a few transport/runtime edges remain deliberately
scoped. See [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for the full boundary.

## Project status

**Alpha — suitable for lab, data-center fabric pilots, IX route-server pilots,
and programmable control-plane deployments where you are comfortable with an
evolving API.**

| Dimension | Current state |
|-----------|---------------|
| **Target use case** | Data-center fabric pilots, IXP route servers, programmable BGP control planes, lab/test environments |
| **Maturity** | Public alpha (v0.51.0) |
| **Narrow stable contract** | The machine-pinned [route-server / route-reflector v1 contract](docs/v1-stable-contract.md) covers only its inventoried control-plane roles and surfaces; the project and all unlisted features remain alpha. |
| **Supported OS** | Linux (primary target). Requires `CAP_NET_BIND_SERVICE` for port 179. |
| **Runtime** | Rust 1.95+ (workspace MSRV — set by the bundled SQLite build), single binary, no external dependencies except optional RPKI/BMP/MRT backends |
| **Config stability** | Inventoried RS/RR v1 fields follow the narrow compatibility policy; unlisted TOML may change between minor versions with migrations documented in CHANGELOG. |
| **API stability** | Inventoried native gRPC/CLI/JSON surfaces follow the narrow v1 policy; unlisted API remains alpha and may evolve between minor versions. |
| **Not yet supported** | EVPN runtime L3VNI/device/table IP-VRF identity changes (restart-required by design), true RFC VLAN-aware bundle VTEP origination + dataplane (non-zero Ethernet Tag RR receive/reflect shipped, M82), EVPN route types 6-11 / PBB / MVPN / MPLS/SRv6 service encapsulation, BGP-LS local topology production, Confederation, TCP-AO live selection/deprecation/deletion or runtime protected-range CRUD (ordered keyrings and add-only successor installation on SIGHUP are supported) |
| **Tests** | Workspace test suite, fuzz targets, an automated interop suite (see `docs/INTEROP.md`) primarily against FRR plus GoBGP / StayRTR / documented BIRD coverage, and an in-tree EVPN load generator (foundation tier gated on every PR; privileged kernel dataplane smokes run on GitHub-hosted CI) |

## Documentation

| Document | Content |
|----------|---------|
| [docs/cookbook/](docs/cookbook/README.md) | Scenario recipes with receipt-proven configs: RR at scale, L3VPN RR, IXP route server, monitoring feed, EVPN fabric RR, policy quickstart |
| [docs/USE_CASES.md](docs/USE_CASES.md) | Deployment scenarios: DDoS, hosting, IX, SDN, collector |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Crate graph, runtime model, ownership, data flow |
| [docs/DESIGN.md](docs/DESIGN.md) | Tradeoffs, protocol scope, rationale |
| [docs/API.md](docs/API.md) | gRPC API reference with examples for every RPC |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Config reference and examples, plus editor integration via the shipped JSON Schema (`docs/rustbgpd.schema.json`) |
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | Bare-metal first run: starter config, validate, run, verify, operate |
| [docs/LIMITATIONS.md](docs/LIMITATIONS.md) | Current product boundaries and known non-goals |
| [docs/deployment.md](docs/deployment.md) | End-to-end install + lifecycle walkthrough: systemd, Docker, containerlab quick-start, upgrade, sample profiles |
| [docs/reload-matrix.md](docs/reload-matrix.md) | Per-field reload classification: which keys hot-apply, which need a restart, which are rejected at parse time |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Running in production: reload, upgrade, failure modes, debugging |
| [docs/explain.md](docs/explain.md) | The explain surfaces: why a route was selected, advertised, imported, or rejected |
| [docs/SECURITY.md](docs/SECURITY.md) | Security posture, firewall guidance, deployment tiers |
| [docs/BENCHMARKS.md](docs/BENCHMARKS.md) | Wire codec and RIB performance numbers, scaling analysis |
| [docs/OPERATIONAL_PROOF.md](docs/OPERATIONAL_PROOF.md) | Consolidated operational proof receipts: CI interop, dataplane, benchmarks, memory, soak |
| [docs/RECEIPTS.md](docs/RECEIPTS.md) | Full receipts index: every M-series interop lab, perf/scale receipt, archived soak, and CI schedule |
| [docs/GRAFANA.md](docs/GRAFANA.md) | Grafana overview dashboard: import instructions and Prometheus scrape config |
| [docs/COMPARISON.md](docs/COMPARISON.md) | Feature comparison with FRR, BIRD, GoBGP, OpenBGPd |
| [docs/INTEROP.md](docs/INTEROP.md) | Interop test coverage and results |
| [docs/evpn-enablement.md](docs/evpn-enablement.md) | EVPN Phase 1-9 gate ladder: what each gate unlocks, work per gate, priority |
| [docs/evpn-vtep-setup.md](docs/evpn-vtep-setup.md) | EVPN VTEP kernel setup: `ip link` recipes for L2VNI / IP-VRF / multi-homing mapped to the ADR-0054 §4 + ADR-0058 §3 readiness checks (operator-provisioned netdevs) |
| [docs/evpn-vtep-troubleshooting.md](docs/evpn-vtep-troubleshooting.md) | EVPN VTEP alpha troubleshooting runbook |
| [docs/gobgp-parity.md](docs/gobgp-parity.md) | rustbgpd vs GoBGP feature parity by use case |
| [docs/adr/](docs/adr/) | Architecture decision records — one per protocol and design choice |
| [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md) | Pre-release smoke matrix and release steps |
| [docs/v1-stable-contract.md](docs/v1-stable-contract.md) | Narrow machine-pinned v1 compatibility contract for proven route-server / route-reflector roles |
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
