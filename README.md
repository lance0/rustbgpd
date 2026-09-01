<p align="center">
  <img src="rustbgpd-logo.png#gh-light-mode-only" alt="rustbgpd" width="420">
  <img src="rustbgpd-logo-dark.png#gh-dark-mode-only" alt="rustbgpd" width="420">
</p>

# rustbgpd

[![Build](https://github.com/lance0/rustbgpd/actions/workflows/ci.yml/badge.svg)](https://github.com/lance0/rustbgpd/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-1.95+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

Project site: <https://rbgp.rs>

An API-first BGP daemon in Rust for IXP route servers, route reflectors, and
automation-heavy control planes. gRPC is the primary interface for all peer
lifecycle, routing, and policy operations — the config file bootstraps initial
state, then gRPC owns the truth. No restarts to add peers, change policy, or
inject routes. And every route decision can explain itself from the live RIB:
per-peer received / best / advertised views, best-path and export-gate
explain, opt-in import-decision explain, retained rejected routes with
reasons, BMP/MRT/metrics — with receipt-backed interop behind each claimed
behavior.

## Choose your path

| I want to… | Start here |
|------------|------------|
| Run a local demo | [Try it in 60 seconds](#try-it-60-seconds) |
| Evaluate rustbgpd for an IXP route server | [IXP evaluation](docs/ixp-evaluation.md) |
| Deploy a proven topology | [Scenario cookbook](docs/cookbook/README.md) |
| Operate or troubleshoot a daemon | [Operations reference](docs/OPERATIONS.md) |
| Build against the gRPC API | [API reference](docs/API.md) |
| Check current boundaries and non-goals | [Limitations](docs/LIMITATIONS.md) |
| Audit a behavior or performance claim | [Evidence and receipts](docs/RECEIPTS.md) |

<details>
<summary>Performance evidence and current headline results</summary>

**Measured, not marketed** — every number below links to its published,
reproducible receipt:

- **Policy reload at IXP scale** (700 route-server clients × 400,400 routes,
  live churn, same harness / same host — the policy-file reload, not the IRR
  filter refresh below): new policy fully delivered to every member in
  **1.21–1.35 s p50** for rustbgpd v0.68.0 source-equivalent runs. The dated
  matrix retains BIRD and OpenBGPD context separately (historical matrix
  measured 2026-08-08; current rustbgpd rows measured 2026-08-30),
  [IXP receipt matrix](docs/perf/ixp-matrix-2026-07.md)
- **IRR-scale filter reload** (320 route-server members × 183,040 generated
  prefixes, same harness / same host): v0.68.0 source-equivalent completion p50
  **0.85–1.09 s** across 0%, 10%, and 50% received-view overlap, with 320/320
  sessions, zero parse errors, and the exact expected received-view delta in
  all twelve roots. BIRD completed in 11.86–15.21 s and OpenBGPD in
  42.94–61.96 s at this fixed shape — [current receipt](docs/perf/irr-reload-v0680-2026-08.md),
  measured 2026-08-30
- **Member-flap propagation** (50 members flap, 650 observers): re-announce
  p50 **0.36–0.39 s** in the current v0.68.0 source-equivalent rows. The
  dated matrix retains BIRD and OpenBGPD comparison rows separately — current
  rustbgpd measured 2026-08-30,
  [same matrix](docs/perf/ixp-matrix-2026-07.md#s3--flapstorm-member-down--member-up-propagation)
- **Cold start**: full 400,400-route table delivered to all 700 members in
  **3.4 s** in the current v0.68.0 source-equivalent rows. The dated matrix
  retains BIRD and OpenBGPD comparison rows — current rustbgpd measured
  2026-08-30,
  [same matrix](docs/perf/ixp-matrix-2026-07.md#s1--cold-convergence)
- **Route-reflector scale**: 1,000 RR clients × 100k routes converge on the
  wire in **0.32–0.34 s** at **383,176–404,892 KiB** direct-process RSS in
  three current source-equivalent v0.68.0 runs — historical receipt measured 2026-07-03;
  current rows measured 2026-08-30,
  [1000-peer scale receipt](docs/perf/scale-receipt-2026-07.md)
- **The losses, stated plainly**: OpenBGPD 9.2 holds a smaller reload stall
  (p50 0.213–0.238 s vs current rustbgpd's 0.384–0.529 s), and BIRD keeps the
  settled-RSS win under flap churn (337/328 MiB vs current rustbgpd's 440/449
  MiB at S3). Current rustbgpd withdraw p50 is 0.30–0.43 s. At S2, current
  rustbgpd settles at 373/372 MiB versus BIRD's dated 422/412 MiB — published in the
  [same receipt](docs/perf/ixp-matrix-2026-07.md#memory), methodology and
  fairness protocol included. Cross-daemon memory is not ranked in the current
  IRR receipt because daemon and container defaults differ.

The rustbgpd figures above are current v0.68.0 source-equivalent rows measured
2026-08-30. BIRD remains the v0.64.0 same-host refresh measured 2026-08-08;
OpenBGPD 9.2 is a supplemental comparator amendment measured 2026-08-30.
The mixed-date boundary and earlier bands are preserved in the receipt.

</details>

**Status: public alpha.** Feature-complete for the initial programmable
control-plane target and expanding toward cloud / AI-scale data-center
fabric use.

> **Alpha expectations:** The config format and gRPC API are not yet frozen.
> Breaking changes are possible between minor versions. The narrow daemon
> exception and separate compatibility boundaries are mapped in
> [Stability and compatibility](docs/stability.md). Supported daemon targets
> are Linux x86_64 and aarch64; see the canonical
> [platform support contract](SUPPORT.md#platform-support) and
> [Project Status](#project-status) for details.

## Try it (60 seconds)

The fastest way to see rustbgpd in action. Spins up the daemon with an FRR
peer that advertises sample IPv4 and IPv6 prefixes — no real routers needed.

```bash
cd examples/docker-compose
docker compose up -d --build
```

`--build` asks Compose to build from the current checkout before startup.
Without it, Compose may reuse an older `docker-compose-rustbgpd` image already
on the host. Cached layers keep unchanged repeat builds quick.

Once both containers are running (a few seconds):

The Compose service supplies its committed, public **test-only** bearer token
to in-container `rbgp` commands. It is for this runnable demo, not deployment.

```bash
# See the FRR peer come up
docker compose exec rustbgpd rbgp -s http://127.0.0.1:50051 summary

# Browse the RIB
docker compose exec rustbgpd rbgp -s http://127.0.0.1:50051 rib

# Live TUI dashboard — sessions, prefix counts, message rates, export explain
docker compose exec rustbgpd rbgp -s http://127.0.0.1:50051 top
```

![rbgp top — live TUI dashboard](docs/images/tui-screenshot.png)

Select a peer, open its detail, then press `r` to browse the point-in-time
unicast Best-RIB and explain export decisions for that peer. Press `q` to exit
the TUI. When you're done: `docker compose down`.

## Policy you can test before it touches a route

Policies are written in `.rpol` — a typed, compiled language with named
prefix/community sets (indexed matchers, not linear walks), parameterized
policies, composition, and unit tests **in the policy file itself**. From the
shipped [route-server example](examples/route-server/hygiene.rpol):

```rpol
policy ixp-hygiene {
    # AS_SETs are deprecated (RFC 9774); reject them like arouteserver does.
    term reject-as-set { if route.as-path matches "\\{" { reject } }
    term reject-aspa-invalid { if route.aspa == invalid { reject } }
    # Tag the RPKI outcome as an RFC 8097 extended community for members.
    term tag-ov-valid { if route.rpki == valid { add ext-community OV_VALID } }
}

test as-set-is-rejected {
    route { prefix 203.0.113.0/24; as-path "64501 {64502 64503}" }
    expect ixp-hygiene == reject
}
```

Then ask the daemon *what would happen* — before you commit anything:

<!-- rbgp-cli-conformance -->
```bash
rbgp policy check hygiene.rpol      # offline: compile + run the in-language tests
rbgp policy test hygiene.rpol --policy ixp-hygiene --direction import
                                    # read-only dry run against the LIVE RIB:
                                    # accept/reject/modify counts, per-term hits
rbgp rib --prefix 203.0.113.0/24 advertised 198.51.100.7 --explain
                                    # walk the real export gate ladder to one peer
rbgp policy stats                   # live per-term hit counters once installed
```

Edits hot-apply on SIGHUP, `.rpol` mixes freely with the existing TOML policy
chains, and FRR route-map parity is proven route-for-route in interop (M80).
Language reference: [docs/rpol-language.md](docs/rpol-language.md) · explain
surfaces: [docs/explain.md](docs/explain.md) · IXPs on arouteserver can render
config from their existing `general.yml`/`clients.yml`:
[IXP filter-pipeline tutorial](docs/cookbook/ixp-filter-pipeline.md).

## Why rustbgpd

- **API-first control plane** — full gRPC surface across thirteen services
  (twelve native `rustbgpd.v1` services plus the OpenConfig `gnmi.gNMI`
  service) and a thin CLI (`rbgp`): dynamic peer management, policy CRUD,
  route injection, streaming events, all without restarts
- **Native route explainability** — "why is this route (not) here?" answered
  from the live RIB in one command. Best-path, export-gate, and filtered-route
  views are always on; the **import**-decision surface is opt-in
  (`[policy.explain] enabled = true`), because it retains a decision cache
  per session. The TUI also exposes the unicast export-gate slice for a
  selected peer ([docs/explain.md](docs/explain.md))
- **Update-group fanout** — peers with provably identical staged output share
  one staging pass: ~27x faster 100k-route convergence at 256 uniform RR
  clients (15.1 s to 0.56 s), measured 2026-07-03; v2 extends sharing to
  VPNv4/v6 with per-member
  RT filtering at emit ([receipt](docs/perf/scale-receipt-2026-07.md))
- **Full BMP monitoring trio** — per-collector Adj-RIB-In / Adj-RIB-Out
  (byte-exact wire PDUs) / Loc-RIB on one exporter, validated against pmacct,
  gobmp, and tshark at once
- **Modern protocol surface** — MP-BGP, Add-Path, GR/LLGR, RPKI/RTR + ASPA,
  FlowSpec, Prefix ORF, large/extended communities — plus VPNv4/v6, RT-Constrain,
  labeled-unicast, and BGP-LS reflection, and **RFC 9107 Optimal Route
  Reflection** (per-client best paths via SPF over BGP-LS topology,
  [peer-proven against checksum-built GoBGP 4.8.0 in M76](docs/RECEIPTS.md#interop-labs--pr-gated-interopyml))
- **Explicit architecture** — pure FSM with no I/O, single-owner RIB with no
  locks, bounded channels; no `Arc<RwLock>` on routing state
  ([ARCHITECTURE.md](ARCHITECTURE.md))
- **Reusable crates** — `rustbgpd-wire` (zero internal deps) and
  `rustbgpd-fsm` are published for BGP tooling that doesn't need the router

The full-depth version of each item — the complete observability surface, the
BMP/BMPv4 details, the ADR-0077 route-reflector family boundary, the VPN
fanout numbers — is the [feature tour](docs/feature-tour.md).

## Good fit

- **Internet exchange route servers** — transparent mode, Add-Path, per-client
  best-path (RFC 7947 path-hiding mitigation), RPKI, Prefix ORF, per-member
  policy; start with the [IXP evaluation matrix](docs/ixp-evaluation.md)
- **Route reflectors** — including VPNv4/v6, RT-Constrain, labeled-unicast, and
  BGP-LS reflection, GR/LLGR, and RFC 9107 Optimal Route Reflection
- **DDoS mitigation platforms** — FlowSpec + RTBH route injection from automation
- **Cloud / AI-scale data-center fabrics** — API-first BGP control, BFD, ECMP,
  EVPN/VXLAN alpha, and whitebox-friendly interop surfaces
- **Hosting provider prefix management** — API-driven customer prefix announcements
- **SDN / network automation controllers** — programmable BGP control plane
- **Route collectors and looking glasses** — structured data via gRPC, MRT, BMP,
  plus a Birdwatcher-shaped status/peer/accepted/filtered/noexport subset via
  the shipped `birdwatcher-adapter` binary (`examples/birdwatcher-adapter`
  carries the source and deployment notes)
- **Lab and test environments** — clean API, structured logs, containerlab interop

See [docs/USE_CASES.md](docs/USE_CASES.md) for detailed deployment scenarios with
architecture diagrams, example configs, and API workflows, and the
[feature tour](docs/feature-tour.md#route-reflector-families-beyond-unicast)
for exactly which route-reflector families have shipped and where the
ADR-0077 scope boundary sits.

## Not the best fit today

- Full general-purpose router deployments expecting default-on,
  fully policy-guarded FIB integration — Linux FIB integration is default-off
  and scoped to RFC 7999 discard routes and configured unicast tables
  (including ECMP and weighted multipath)
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

## Install

### Pre-built tarball (no toolchain required)

Every tagged release ships static-named per-arch tarballs, so
`releases/latest/download/` always fetches the current version:

<!-- release-install-contract:root-install:start -->
```bash
SUFFIX=linux-amd64   # or linux-arm64
TARBALL="rustbgpd-${SUFFIX}.tar.gz"
curl -fLO "https://github.com/lance0/rustbgpd/releases/latest/download/${TARBALL}"
curl -fLO "https://github.com/lance0/rustbgpd/releases/latest/download/checksums-${SUFFIX}.txt"
awk -v file="$TARBALL" '$2 == file || $2 == "./" file { print }' "checksums-${SUFFIX}.txt" | sha256sum -c -
tar -xzf "$TARBALL"
sudo install -m 0755 rustbgpd rbgp rs-config-render birdwatcher-adapter /usr/local/bin/
```

Four binaries: the daemon, the `rbgp` CLI, `rs-config-render` (the
[IXP route-server config renderer](tools/rs-config-render/README.md) —
harmless if you don't run one), and the optional Alice-LG
`birdwatcher-adapter`. The tarball also carries man pages and
bash/zsh/fish completions under `share/`, plus the version-matched Grafana
overview and Alpha EVPN dashboards, Prometheus alert rules, and promtool test
suite under
`share/monitoring/` (`/usr/share/doc/rustbgpd/monitoring/` after a
`.deb`/`.rpm` install) — the
[install walkthrough](docs/deployment.md#install) covers installing those
and pinning a specific version.

### From source

```bash
# Prerequisites: Rust 1.95+, protobuf-compiler
sudo apt-get install -y protobuf-compiler   # Debian/Ubuntu
cargo build --release -p rustbgpd -p rustbgpctl -p rs-config-render -p birdwatcher-adapter

# Binaries are at target/release/{rustbgpd,rbgp,rs-config-render,birdwatcher-adapter}
```

### Docker

Tagged releases publish versioned images to GHCR (for this release,
`ghcr.io/lance0/rustbgpd:0.68.0`). The current release workflow can publish a
single multi-arch (amd64+arm64) manifest on a tagged release, but the existing
`:0.68.0` and `:0.68` images remain amd64-only; `:latest` inherits the newest
non-prerelease release's platform set. Alternatively, build locally:

```bash
docker build -t rustbgpd .                    # daemon + rbgp + birdwatcher-adapter, nonroot
docker build --target dev -t rustbgpd:dev .   # dev/interop image (lab helpers, root)
```
<!-- release-install-contract:root-install:end -->

## Quick start (bare metal)

For running rustbgpd on a real host with real peers, see
[docs/QUICKSTART.md](docs/QUICKSTART.md). It covers starter config generation,
`--check` / `--diff`, local UDS access, HTTP probes, runtime peer operations,
remote mTLS access, standalone Docker, and systemd.

Installed binaries include `--init-config route-server`, a self-contained
IPv4 two-member skeleton with fail-closed import policy. Replace its member
placeholders before use; the full route-server example and `rs-config-render`
cover production policy and generated inventories.

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

## Performance vs the incumbents

The [IXP route-server receipt matrix](docs/perf/ixp-matrix-2026-07.md) runs
rustbgpd, BIRD 3.3.1, and OpenBGPD 9.2 through **the same harness on the same
host** — 700 route-server clients × 400,400 routes with live churn, each
incumbent at its documented strongest configuration, receiver-side timestamps,
two independent campaign runs, losses published alongside wins:

| KPI (700 clients × 400,400 routes unless noted, p50) | rustbgpd | BIRD 3.3.1 | OpenBGPD 9.2 |
|---|---|---|---|
| Sessions Established | **0.7 s** | 18.2–20.5 s | 83.6–105.7 s |
| Cold start, full table to all members | **3.4 s** | 60.9–63.3 s | 326.0–347.8 s |
| Policy reload: UPDATE stall | 0.384–0.529 s | 1.70–2.70 s | **0.213–0.238 s** |
| Policy reload: new policy fully delivered | **1.21–1.35 s** | 64.3–84.5 s | 200.8–206.4 s |
| IRR-scale filter reload: completion (320 members × 183,040 generated prefixes) | **0.85–1.09 s** | 11.86–15.21 s (3.3.2) | 42.94–61.96 s (9.2) |
| Flapstorm: withdraw propagation | **0.30–0.43 s** | 0.47–0.61 s | 8.22–9.55 s |
| Flapstorm: re-announce | **0.36–0.39 s** | 2.85–3.74 s | 17.36–17.82 s |
| Settled RSS (S2, runs A/B) | 373 / 372 MiB | 422 / 412 MiB | 795 / 801 MiB |
| Settled RSS (S3, runs A/B) | 440 / 449 MiB | 337 / 328 MiB | 831 / 827 MiB |

The rustbgpd column uses the current source-equivalent v0.68.0 rows where
available; BIRD remains the v0.64.0 same-host refresh (2026-08-08), and
OpenBGPD is the 9.2 amendment measured 2026-08-30. OpenBGPD 9.2's repeated
flap reconnects also wait about 20 s and 50 s beyond the fixed 10 s hold in
rounds two and three before the re-announce clock begins; the receipt publishes
that pacing separately from fan-out.
rustbgpd is the only daemon in the matrix holding both a sub-second median
stall **and** single-digit-seconds completion; OpenBGPD has the smallest
stall in the current full-shape comparison. In the mixed-date settled-memory
rows, current rustbgpd S2 (373 / 372 MiB) is below dated BIRD (422 / 412 MiB),
while dated BIRD S3 (337 / 328 MiB) is below current rustbgpd (440 / 449 MiB).
These observations provide context, not a universal or cross-date ranking.
The receipt includes the full
method, configuration disclosure, honesty notes, raw artifacts — and a
post-publication note where the receipt's own tables exposed a rustbgpd
re-announce plateau that was root-caused, fixed, and rerun (9.5–9.8 s →
0.46–0.49 s).

The IRR-scale row is a separate, current
[v0.68.0 source-equivalent campaign](docs/perf/irr-reload-v0680-2026-08.md).
It retains all 96 verifier-approved rows across 0%, 10%, and 50% received-view
overlap, with 320/320 sessions, zero parse errors, and exact received-view
deltas. Historical IRR receipts remain linked from the current receipt.

At route-reflector shapes, the
[1000-peer scale receipt](docs/perf/scale-receipt-2026-07.md), measured 2026-07-03,
records 1,000 uniform RR clients × 100k routes converging on the
wire in 1.82 s at 419 MiB
whole-process RSS, and 1,000 clients × 100k VPNv4 in 12.60 s / 625 MiB uniform
and 3.92 s / 636 MiB with heterogeneous ~10% RT memberships (vs ~73 s / ~31 GiB
and ~12.5 s / ~5.7 GiB extrapolated per-peer), with a one-RT membership flip
delivering its 1600-route delta in ~15 ms with zero policy evaluations.

The freshest published [v0.68.0 cross-stack bgperf2
receipt](docs/perf/competitive-bgperf2-v0680-2026-08.md), measured 2026-08-30,
is the headline same-host IPv4 import/convergence comparison. All 80 cells
reached the exact expected route count across five fixed shapes; the largest is
two peers × 100,000 prefixes, not a full-table cell. Microbenchmarks and memory
scaling are in [docs/BENCHMARKS.md](docs/BENCHMARKS.md). That page also retains
the corrected July campaign as explicitly historical evidence; it supports no
cross-daemon ranking. Every receipt is indexed in
[docs/RECEIPTS.md](docs/RECEIPTS.md); GoBGP-specific parity is in
[docs/gobgp-parity.md](docs/gobgp-parity.md).

## gRPC API

Twelve native `rustbgpd.v1` services cover the daemon's operational surface —
Global, Config, Neighbor, Policy (23 RPCs including explain, dry-run, per-term
stats, and bounded validation-policy posture), PeerGroup, Rib, BFD, RPKI,
Event, Injection, Control, and Evpn —
plus a separate `gnmi.gNMI` service for OpenConfig BGP telemetry and the first
transaction-backed config subset.

```bash
# Stream route changes in real time over the default UDS listener
grpcurl -plaintext -unix /var/lib/rustbgpd/grpc.sock \
  -import-path . -proto proto/rustbgpd.proto \
  rustbgpd.v1.EventService/WatchEvents
```

Config changes get the full Junos-style transactional quartet: `rbgp config
plan` (commit check), `rbgp config diff` (show compare, annotated with live
reload impact), `rbgp config apply --confirm-id --confirm-timeout` (commit
confirmed, with a crash-safe boot revert), and `rbgp config rollback N`
against a bounded on-disk history of applied configs — rollback routes
through the same transaction engine as apply, so it gets the same impact
preview, receipts, and confirm window. Details:
[docs/OPERATIONS.md](docs/OPERATIONS.md).

The full service/RPC table and per-RPC examples: [docs/API.md](docs/API.md).
gNMI operator guide: [docs/GNMI.md](docs/GNMI.md).

## Design choices

rustbgpd is intentionally built around:

- **gRPC-driven control** instead of a large interactive CLI surface
- **A pure FSM crate** with no I/O — `(State, Event) -> (State, Vec<Action>)`
- **Single-owner routing state** instead of shared mutable state across tasks
- **Bounded channels** for all inter-task communication — backpressure, not locks
- **Explicit protocol feature boundaries** with ADRs and test-backed development

Designed around an API-first operating model similar to GoBGP, with a smaller
and more explicit internal architecture. Rationale:
[docs/DESIGN.md](docs/DESIGN.md); crate graph and runtime model:
[ARCHITECTURE.md](ARCHITECTURE.md).

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

Full guidance and deployment tiers: [docs/SECURITY.md](docs/SECURITY.md).

## Testing and correctness

Evidence-driven development: fuzz targets on the wire decoder, property tests
on the FSM, automated containerlab interop, extensive workspace tests, and an
architecture decision record for every protocol and design choice.

| Evidence | Details |
|----------|---------|
| Workspace tests | Unit, integration, and property tests (`cargo test --workspace`) |
| Wire fuzzing | libFuzzer harnesses on message and attribute decoders, run nightly in CI |
| Interop suites | Automated interop suite (see [docs/INTEROP.md](docs/INTEROP.md) for the full matrix), primarily against FRR 10.3.1 plus GoBGP 3.37.0 / 4.6.0 / 4.7.0 across established labs; M76/M77/M83/M103/M104 use GoBGP 4.8.0, which also appears in the local M105 observation, and M83 uses FRR 10.7.0. StayRTR backs RTR coverage; BIRD 2.0.12 anchors M0 and immutable legacy/differential labs, BIRD 2.19.2 covers M83/M85/M93/M95/M100/M104, and BIRD 3.3.2 covers the M43 TCP-AO smoke, M101, plus local M105. A foundation tier is gated on every PR, privileged Linux dataplane smokes run in hosted kernel-dataplane CI, and longer soaks / platform-diversity scripts remain local. |
| Operational proof | Consolidated receipts for CI interop, hosted kernel dataplane, benchmarks, memory profiles, and archived 24 h soaks live in [docs/OPERATIONAL_PROOF.md](docs/OPERATIONAL_PROOF.md) — including the 1,000-session flagship 24 h runs for the [route server](docs/soaks/soak-rs-flagship-24h.md) and the [route reflector](docs/soaks/soak-rr-flagship-24h.md). |
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
| **Maturity** | Public alpha (v0.68.0) |
| **Adopter support** | Reporting channels, compatibility boundaries, and proof limits are documented in [SUPPORT.md](SUPPORT.md). |
| **Narrow stable contract** | The machine-pinned [route-server / route-reflector v1 contract](docs/v1-stable-contract.md) covers only its inventoried control-plane roles and surfaces; the project and all unlisted features remain alpha. |
| **Implemented** | Dual-stack BGP/MP-BGP, Add-Path, GR/LLGR, RPKI/RTR, ASPA path verification, FlowSpec, BMP, MRT, BFD, EVPN/VXLAN (alpha), and full gRPC/CLI management. Linux FIB integration is default-off and scoped to RFC 7999 discard routes and configured unicast tables (including ECMP and weighted multipath); broader routing-suite features remain future work. |
| **Supported OS** | Linux x86_64 and aarch64 only; see the [platform support contract](SUPPORT.md#platform-support). Requires `CAP_NET_BIND_SERVICE` for port 179. |
| **Runtime** | Rust 1.95+ (workspace MSRV — set by the bundled SQLite build), single binary, no external dependencies except optional RPKI/BMP/MRT backends |
| **Config stability** | Inventoried RS/RR v1 fields follow the narrow compatibility policy; unlisted TOML may change between minor versions with migrations documented in CHANGELOG. |
| **API stability** | Inventoried native gRPC/CLI/JSON surfaces follow the narrow v1 policy; unlisted API remains alpha and may evolve between minor versions. |
| **Not yet supported** | EVPN runtime L3VNI/device/table IP-VRF identity changes (restart-required by design), true RFC VLAN-aware bundle VTEP origination + dataplane (non-zero Ethernet Tag RR receive/reflect shipped, M82), EVPN route types 6-11 / PBB / MVPN / MPLS/SRv6 service encapsulation, BGP-LS local topology production, Confederation, TCP-AO key edits/reordering or runtime protected-range CRUD (ordered keyrings, add-only successor installation, observation-gated successor selection/deprecation, and later deprecated/unselected-key deletion on SIGHUP are supported) |
| **Tests** | Workspace test suite, fuzz targets, an automated interop suite (see [docs/INTEROP.md](docs/INTEROP.md)) primarily against FRR plus GoBGP / StayRTR / documented BIRD coverage, and an in-tree EVPN load generator (foundation tier gated on every PR; privileged kernel dataplane smokes run on GitHub-hosted CI) |

## Documentation

Evaluating an IXP route server? Follow this path:

1. Review the [one-page capability matrix](docs/ixp-evaluation.md).
2. Choose the [hand-written](docs/cookbook/route-server.md),
   [ARouteServer-driven](docs/cookbook/ixp-filter-pipeline.md), or
   [IXP Manager-driven](docs/cookbook/ixp-manager-route-server.md)
   provisioning mode.
3. Apply the [shadow pilot's mode-specific zero-blast-radius
   boundary](docs/cookbook/route-server-shadow-pilot.md).

For all documentation, start with the task-oriented
[documentation index](docs/README.md). The table below remains a compact
root-level map.

| Document | Content |
|----------|---------|
| [docs/feature-tour.md](docs/feature-tour.md) | The full-depth feature tour behind the README highlights |
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
| [docs/stability.md](docs/stability.md) | Stability map: narrow daemon inventory, crate SemVer, authorization tiers, and adapter compatibility |
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
