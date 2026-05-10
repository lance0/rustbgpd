# Use Cases

Concrete deployment scenarios for rustbgpd, with architecture, example configs,
and API workflows.

rustbgpd is an API-first BGP daemon. It doesn't replace your edge router — it
sits alongside it as the programmable layer that your automation talks to. The
edge router (FRR, BIRD, Junos, EOS) handles forwarding. rustbgpd handles the
control plane logic that's too dynamic or too complex for static config files.

Note: rustbgpd defaults to a local UDS gRPC listener. The `grpcurl` examples
below that target `localhost:50051` are paired with config snippets that
explicitly enable `[global.telemetry.grpc_tcp]`.

---

## Origin Story: Why rustbgpd Exists

rustbgpd was born out of [prefixd](https://github.com/lance0/prefixd), an
open-source BGP FlowSpec policy daemon for automated DDoS mitigation. prefixd
receives attack signals from detectors (FastNetMon, Kentik, Prometheus alerts),
applies policy-driven playbooks, and announces FlowSpec rules to routers.

prefixd originally used GoBGP as its BGP backend — a separate container in
the docker-compose stack, managed via gRPC. This worked but had real pain
points:

- **No config persistence** — if the GoBGP container restarted, all FlowSpec
  rules were gone. prefixd needed a reconciliation loop to repair state drift
  every 30 seconds.
- **Extra failure domain** — a separate container that could crash, get OOM
  killed, or lose its gRPC connection independently.
- **Performance overhead** — Go's GC adds latency jitter; under DDoS
  conditions, you want predictable response times.
- **Go-flavored API** — GoBGP's protos use `google.protobuf.Any` extensively,
  making typed clients in other languages awkward.

After building and operating prefixd, the requirements for a better BGP backend
became clear. rustbgpd is that backend — designed from day one for the
API-driven, FlowSpec-heavy, persistence-required use case that prefixd
represents.

**Future integration:** rustbgpd is designed to be embeddable. The long-term
goal is for prefixd to link against rustbgpd's crates directly, eliminating the
GoBGP sidecar entirely:

```
Today:    Detector → prefixd → [gRPC] → GoBGP container → Routers
Future:   Detector → prefixd (with embedded rustbgpd) → Routers
```

This removes the separate container, the gRPC hop, the reconciliation loop, and
the "what if GoBGP restarts" failure mode. A single binary that detects attacks
and speaks BGP natively.

---

## 1. DDoS Mitigation (FlowSpec + RTBH)

**The problem:** Your detection system (FastNetMon, Kentik, Prometheus alerts)
identifies an attack. You need to push FlowSpec rules or blackhole routes to
your routers — in seconds, not minutes. Scripting ExaBGP or GoBGP works until
it doesn't: no state persistence, no guardrails, no audit trail.

**The architecture:**

```
Detection system
    |
    v  POST /v1/events (your mitigation platform)
Mitigation platform
    |
    v  gRPC: AddFlowSpec / AddPath
rustbgpd
    |
    v  eBGP with FlowSpec + unicast
Edge routers (Juniper MX, Arista 7xxx, Cisco ASR)
    |
    v  Hardware-rate filtering
Traffic dropped at line rate
```

**Why rustbgpd over GoBGP/ExaBGP:**
- Config persistence — injected FlowSpec rules survive daemon restart
- All 13 FlowSpec component types (destination, source, protocol, ports, ICMP,
  TCP flags, packet length, DSCP, fragment, flow label)
- Single binary, no sidecar container needed
- gRPC API designed for automation, not human CLI use

**Example config** ([`examples/ddos-mitigation/config.toml`](../examples/ddos-mitigation/config.toml)):

```toml
[global]
asn = 65500
router_id = "10.255.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "json"

# Enable TCP listener for mitigation platform to reach gRPC
[global.telemetry.grpc_tcp]
enabled = true
address = "127.0.0.1:50051"
# token_file = "/etc/rustbgpd/grpc-token"

# Edge routers that enforce FlowSpec rules
[[neighbors]]
address = "10.0.0.1"
remote_asn = 65001
description = "edge-router-1"
families = ["ipv4_unicast", "ipv4_flowspec", "ipv6_flowspec"]
hold_time = 30

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65001
description = "edge-router-2"
families = ["ipv4_unicast", "ipv4_flowspec", "ipv6_flowspec"]
hold_time = 30
```

**API workflow — inject a FlowSpec rate-limit rule:**

```bash
# Rate-limit UDP traffic to 203.0.113.10 port 53 at 10 Mbps
grpcurl -plaintext -d '{
  "family": "ipv4_flowspec",
  "rule": {
    "destination_prefix": "203.0.113.10/32",
    "protocols": [17],
    "destination_ports": [53]
  },
  "actions": {
    "traffic_rate_bytes": 1250000
  }
}' localhost:50051 rustbgpd.v1.InjectionService/AddFlowSpec
```

```bash
# Blackhole a /32 under attack (RTBH via unicast)
grpcurl -plaintext -d '{
  "prefix": "203.0.113.10/32",
  "next_hop": "192.0.2.1",
  "communities": ["65535:666"]
}' localhost:50051 rustbgpd.v1.InjectionService/AddPath
```

```bash
# Withdraw when the attack subsides
grpcurl -plaintext -d '{
  "prefix": "203.0.113.10/32"
}' localhost:50051 rustbgpd.v1.InjectionService/DeletePath
```

**Monitoring:** Prometheus metrics track FlowSpec rule counts per peer. BMP
export streams rule changes to collectors for audit. MRT dumps capture
point-in-time snapshots for post-incident analysis.

---

## 2. IXP Route Server

**The problem:** You operate an Internet exchange and need a route server that
distributes member routes with Add-Path, RPKI validation, and per-member policy
— all manageable via API as members join and leave.

**The architecture:**

```
IXP member A (AS 64501) ──┐
IXP member B (AS 64502) ──┤── eBGP ──► rustbgpd (route server, AS 65500)
IXP member C (AS 64503) ──┘
                                          |
                              ┌───────────┼───────────┐
                              v           v           v
                         Prometheus   BMP collector   MRT archive
```

**Key features for IXPs:**
- **Transparent mode** — preserves original NEXT_HOP, no AS prepend (members
  peer directly via the exchange fabric)
- **Add-Path send** — members see all candidate paths, not just the best,
  enabling their own best-path selection
- **RPKI validation** — drop RPKI-invalid routes, prefer valid over not-found
- **Policy chains** — per-member import/export filtering via named policies
- **Peer groups** — share config across members with the same policy profile
- **Dynamic member management** — add/remove members via gRPC without restart
- **GR/LLGR** — member sessions survive route server maintenance windows

**Example config:** [`examples/route-server/config.toml`](../examples/route-server/config.toml)

**API workflow — add a new IXP member at runtime:**

```bash
# Add member at runtime (persisted to config automatically)
rustbgpctl neighbor 198.51.100.10 add --asn 64510 \
  --description "new-member" \
  --families ipv4_unicast,ipv6_unicast \
  --max-prefixes 10000

# Assign to a peer group for shared policy via gRPC
grpcurl -plaintext -d '{
  "address": "198.51.100.10",
  "peer_group": "rs-members"
}' localhost:50051 rustbgpd.v1.PeerGroupService/SetNeighborPeerGroup

# Verify the session comes up
rustbgpctl neighbor 198.51.100.10
```

---

## 3. Hosting Provider Prefix Management

**The problem:** Customers buy IP space from you. Their prefixes need to be
announced to your upstreams and IX peers. Today this involves editing config
files, reloading daemons, and hoping nobody fat-fingers a prefix. Customer
churn means constant manual work.

**The architecture:**

```
Customer portal / billing system
    |
    v  gRPC: AddPath / DeletePath
rustbgpd (route injector)
    |
    v  iBGP
Edge routers (FRR/BIRD with FIB)
    |
    ├──► Transit provider A (eBGP)
    ├──► Transit provider B (eBGP)
    └──► IXP route server (eBGP)
```

rustbgpd doesn't replace the edge router — it's the **programmable route
injection layer**. Your provisioning system talks to rustbgpd via gRPC. rustbgpd
peers with your edge routers via iBGP. The edge routers install routes into the
kernel FIB and announce them upstream.

**Why this model works:**
- Customer signs up → automation calls `AddPath` → prefix is announced
  within seconds
- Customer cancels → automation calls `DeletePath` → prefix is withdrawn
- All injected routes persist across rustbgpd restarts (config persistence)
- RPKI validation prevents announcing prefixes you don't own
- Audit trail via BMP export to your collector
- No config file edits, no SIGHUP, no restart

**Example config** ([`examples/hosting-provider/config.toml`](../examples/hosting-provider/config.toml)):

```toml
[global]
asn = 65100
router_id = "10.255.0.1"
listen_port = 1179           # non-standard port (edge routers own 179)

[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "json"

[global.telemetry.grpc_tcp]
enabled = true
address = "127.0.0.1:50051"
# token_file = "/etc/rustbgpd/grpc-token"

# RPKI validation — don't announce prefixes we can't prove we hold
[rpki]
[[rpki.cache_servers]]
address = "127.0.0.1:3323"

# iBGP to edge routers
[[neighbors]]
address = "10.255.0.2"
remote_asn = 65100             # iBGP (same ASN)
description = "edge-router-1"
families = ["ipv4_unicast", "ipv6_unicast"]

[[neighbors]]
address = "10.255.0.3"
remote_asn = 65100
description = "edge-router-2"
families = ["ipv4_unicast", "ipv6_unicast"]
```

**API workflow — provision a customer prefix:**

```bash
# Customer buys 203.0.113.0/24 — announce it
rustbgpctl rib add 203.0.113.0/24 --nexthop 192.0.2.1

# Customer buys an IPv6 block
rustbgpctl rib add 2001:db8:1000::/36 --nexthop 2001:db8::1

# Customer cancels — withdraw
rustbgpctl rib delete 203.0.113.0/24

# List best routes
rustbgpctl rib
```

---

## 4. SDN / Network Automation Controller

**The problem:** Your SDN controller or network automation platform needs to
inject routes, apply traffic engineering policies, or react to network events
in real time. You need a BGP speaker that's driven entirely by API — not by
editing config files.

**The architecture:**

```
SDN controller / orchestrator
    |
    v  gRPC (AddPath, SetPolicy, WatchRoutes)
rustbgpd
    |
    ├──► eBGP to datacenter fabric (announce service IPs)
    ├──► eBGP to WAN edge (traffic engineering)
    └──► iBGP to route reflector (internal reachability)
```

**Key capabilities:**
- **Route injection** — announce/withdraw prefixes programmatically
- **Policy CRUD** — create/modify/delete policies at runtime without restart
- **WatchRoutes streaming** — receive real-time route change events
- **Community manipulation** — set communities for traffic engineering
- **AS_PATH prepend** — steer traffic across multiple upstreams

**API workflow — traffic engineering via communities:**

```bash
# Announce a prefix with traffic engineering communities
grpcurl -plaintext -d '{
  "prefix": "10.100.0.0/24",
  "next_hop": "10.255.0.1",
  "communities": ["65100:1000", "65100:2000"],
  "local_pref": 200
}' localhost:50051 rustbgpd.v1.InjectionService/AddPath

# Create an export policy that prepends to deprioritize a transit link
grpcurl -plaintext -d '{
  "name": "deprioritize-transit-b",
  "default_action": "permit",
  "statements": [{
    "action": "permit",
    "match_neighbor_set": "transit-b",
    "set_as_path_prepend": {"asn": 65100, "count": 2}
  }]
}' localhost:50051 rustbgpd.v1.PolicyService/SetPolicy

# Apply the policy to the export chain
grpcurl -plaintext -d '{
  "chain": ["deprioritize-transit-b"]
}' localhost:50051 rustbgpd.v1.PolicyService/SetGlobalExportChain

# Stream route changes in real time for the controller
grpcurl -plaintext localhost:50051 rustbgpd.v1.RibService/WatchRoutes
```

---

## 5. BGP Looking Glass / Route Collector

**The problem:** You need to collect routes from multiple peers for monitoring,
analysis, or a public looking glass. You want structured data via API, not
screen-scraping CLI output.

**The architecture:**

```
Upstream A ──┐
Upstream B ──┤── eBGP ──► rustbgpd (collector)
IX peer C  ──┘
                              |
                  ┌───────────┼───────────┐
                  v           v           v
             gRPC queries  MRT dumps   BMP stream
             (looking       (archive)   (OpenBMP /
              glass app)                 pmacct)
```

**Key capabilities:**
- **ListReceivedRoutes / ListBestRoutes** — query Adj-RIB-In and Loc-RIB
- **WatchRoutes** — stream route changes to a dashboard in real time
- **MRT TABLE_DUMP_V2** — periodic snapshots for offline analysis (compatible
  with bgpdump, BGPKIT parser, and RouteViews/RIPE RIS tooling)
- **BMP export** — stream to OpenBMP or pmacct for long-term archival
- **RPKI validation state** — each route annotated with Valid/Invalid/NotFound
- **Birdwatcher-compatible REST API** — optional HTTP server for Alice-LG and
  similar looking glass frontends (`[global.telemetry.looking_glass]`)
- **Best-path explain** — `rustbgpctl rib --prefix X --explain` shows why a
  route was selected over alternatives

**Example config** ([`examples/route-collector/config.toml`](../examples/route-collector/config.toml)):

```toml
[global]
asn = 65534
router_id = "10.255.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[global.telemetry.grpc_tcp]
enabled = true
address = "0.0.0.0:50051"

# Birdwatcher-compatible looking glass for Alice-LG
[global.telemetry.looking_glass]
addr = "0.0.0.0:8080"

# RPKI — annotate every route with validation state
[rpki]
[[rpki.cache_servers]]
address = "127.0.0.1:3323"

# MRT periodic dumps for archive
[mrt]
output_dir = "/var/lib/rustbgpd/mrt"
dump_interval = 7200           # every 2 hours
compress = true
file_prefix = "collector"

# BMP stream to OpenBMP
[bmp]
sys_name = "rustbgpd-collector"
[[bmp.collectors]]
address = "10.0.0.100:5000"

# Peers — import everything, export nothing
[policy]
[[policy.export]]
action = "deny"
prefix = "0.0.0.0/0"
le = 32
[[policy.export]]
action = "deny"
prefix = "::/0"
le = 128

[[neighbors]]
address = "10.0.0.1"
remote_asn = 64501
description = "upstream-a"
families = ["ipv4_unicast", "ipv6_unicast"]
max_prefixes = 1000000

[[neighbors]]
address = "10.0.0.2"
remote_asn = 64502
description = "upstream-b"
families = ["ipv4_unicast", "ipv6_unicast"]
max_prefixes = 1000000
```

**API workflow — looking glass queries:**

```bash
# Query best routes
rustbgpctl rib

# List all routes received from a specific peer
rustbgpctl rib received 10.0.0.1

# Explain why a route was selected as best
rustbgpctl rib --prefix 10.0.0.0/24 --explain

# Trigger an on-demand MRT dump
rustbgpctl mrt-dump

# Stream all route changes (pipe to your analysis tool)
grpcurl -plaintext localhost:50051 rustbgpd.v1.RibService/WatchRoutes
```

---

## 6. Lab and Testing

**The problem:** You're developing network automation, testing BGP policies, or
studying for a certification. You need a BGP speaker that's easy to set up,
has a clean API, and provides good visibility into what's happening.

**Why rustbgpd for labs:**
- Single binary — `cargo build && ./target/release/rustbgpd config.toml`
- Structured JSON logging — see every BGP message, FSM transition, and policy
  decision
- gRPC API — script interactions in Python, Go, or any gRPC-capable language
- Docker support — `docker compose up` for multi-node topologies
- Containerlab interop — tested topologies with FRR and BIRD included
- `--check` flag — validate configs before deploying

**Quick containerlab topology:**

```yaml
name: bgp-lab
topology:
  nodes:
    rustbgpd:
      kind: linux
      image: rustbgpd:latest
      binds:
        - config.toml:/etc/rustbgpd/config.toml:ro
    frr:
      kind: linux
      image: quay.io/frrouting/frr:10.3.1
      binds:
        - frr.conf:/etc/frr/frr.conf:ro
  links:
    - endpoints: ["rustbgpd:eth1", "frr:eth1"]
```

See [`tests/interop/`](../tests/interop/) for complete working topologies.

---

## 7. VXLAN-EVPN DC Fabric Route Reflector

**The problem:** You're operating a VXLAN-EVPN leaf/spine fabric — GPU
cluster, multi-tenant DC, container overlay — and you need an iBGP route
reflector that distributes EVPN routes (MAC advertisements, multicast
memberships, IP prefixes) between VTEPs. The VTEPs themselves (SONiC or
FRR leaves) handle local MAC learning, DF election, and VXLAN encap. You
want a control plane that's API-first (no vtysh scraping), scales to
thousands of VTEPs, and gives you structured observability.

**What rustbgpd does for you (Phase 1 RR bundle, Gates 0-6 of
[docs/evpn-enablement.md](evpn-enablement.md), ADR-0050):**

- **RFC 7432 route reflection for all 5 route types** — EAD per-ES,
  EAD per-EVI, MAC/IP, IMET, Ethernet Segment, IP Prefix (RFC 9136) —
  reflected between VTEPs per RFC 4456 with full tie-break ordering
  (stale → ORIGIN → CLUSTER_LIST length → ORIGINATOR_ID) and
  source-peer split horizon.
- **MAC Mobility handling** — Type 2 best-path honors the MAC Mobility
  sequence number and the sticky flag per RFC 7432 §15.1, so a MAC
  move converges deterministically and sticky MACs aren't displaced.
  Validated end-to-end against FRR via M30 (basic Type 2) and M31
  (mobility + sticky).
- **Multi-homing Type 4 ES reflection** — reflected unchanged with
  RFC 4456 ORIGINATOR_ID + CLUSTER_LIST so downstream VTEPs run DF
  election independently over the same inputs. Validated via M32
  (two FRR VTEPs sharing an ESI + observer). Type 1 EAD-per-EVI
  reflection is validated via M32 and the synthetic M32b sibling.
  As a local VTEP, Gate 8/8b now originates Type 1/4 routes, runs DF
  election, and can opt into BUM enforcement; the RR role still only
  reflects these routes.
- **GR / LLGR for EVPN** — VTEP restart no longer flaps the rest of
  the fabric: routes are marked stale on `PeerGracefulRestart`,
  promoted to `LLGR_STALE` on GR timer expiry per RFC 9494, and
  swept on EoR. Enhanced Route Refresh tracks unreplaced EVPN keys
  in `refresh_stale_evpn` and withdraws them on BoRR/EoRR.
- **VXLAN encapsulation via RFC 8365** — the BGP Encapsulation extended
  community is decoded and preserved across reflection; `rustbgpctl evpn`
  surfaces `encap=vxlan` for operator visibility.
- **Controller injection** — `InjectionService::AddEvpnRoute` /
  `DeleteEvpnRoute` cover Type 2 MAC/IP and Type 3 IMET, with display-
  form RDs (`65000:100`, `10.0.0.1:100`, `4200000000:100`); injected
  routes flow through the same reflection pipeline as iBGP-learned
  ones. CLI: `rustbgpctl evpn add-mac-ip / add-imet / delete-mac-ip /
  delete-imet`.
- **gRPC observability** — `ListEvpnRoutes(route_type, peer, rd)` for
  filtered EVPN RIB queries; Prometheus metrics per peer include
  `adj_rib_out_prefixes{family="evpn"}`. Max-prefix accounting counts
  EVPN keys alongside unicast prefixes.
- **RT-based policy** — existing `match_community` against Route Target
  extended communities filters EVPN routes the same way unicast RT
  matching works elsewhere. Type 5 IP-Prefix routes surface their
  prefix in the policy `RouteContext` so prefix-based clauses work
  on Type 5 too.

**What rustbgpd does for VTEP-mode operators:**

- **MAC-only Type 2 origination** — Gate 7b+1 (v0.15.0):
  `RTNLGRP_NEIGH AF_BRIDGE` subscription drives Type 2 origination
  per RFC 7432 §15.1 with full mobility-sequence handling. One
  Type 3 IMET (RFC 7432 §7.3) per L2VNI carries the PMSI Tunnel
  attribute (RFC 6514 §5) for ingress-replication BUM.
- **MAC-with-IP Type 2 origination via ARP/ND suppression** — Gate
  7b+2 ([Unreleased]): with `bridge link set dev vxlan<vni>
  neigh_suppress on`, ARP/ND-snooped `(IP, MAC)` bindings on the
  bridge's neighbour table drive MAC+IP Type 2 origination under
  the FRR-style replace model (one Type 2 per MAC at any time —
  `IpAdded` upgrades from MAC-only to MAC+IP, last `IpRemoved`
  downgrades back). SDN controllers can still inject MAC-with-IP
  routes directly via `InjectionService::AddEvpnRoute` (Gate 6).

**What rustbgpd doesn't do yet (and which VTEPs handle for you):**

- **EVPN multi-homing enforcement** — Gate 8 (`[Unreleased]`,
  ADR-0057) shipped the observation half: Type 4 ES + Type 1
  EAD-per-ES + Type 1 EAD-per-EVI origination, RFC 7432 §8.5
  service carving + RFC 8584 §3 algorithm negotiation, and the
  Prometheus `evpn_df_role` surface. Gate 8b follow-ups now add
  ESI Label / ES-Import RT origination, DF-role-aware Type 2 ESI
  attachment, opt-in BUM suppression via `apply_bum_enforcement`,
  aliasing projection, and receive-side EAD-per-ES mass-withdraw
  filtering. This is alpha: leave enforcement disabled in
  production until the churn soak closes.
- **VXLAN data plane** — kernel VXLAN interfaces + bridge setup is the
  VTEP's job.
- **IRB semantics** — rustbgpd preserves Type 2 `label2` and the Router
  MAC ext community across reflection, but doesn't interpret them.

**Why the API-first shape matters for DC fabric:**

- Spin up a VTEP with a templated FRR config + a gRPC call to register
  the new peer — no config-file write dance.
- Pipe EVPN route events into your SDN controller or fabric-observability
  tool via `WatchRoutes`. (BMP and MRT export carry unicast / FlowSpec
  today; typed EVPN extraction in those channels is on the roadmap.)
- Validate policy changes with `rustbgpctl rib explain-best-path` before
  pushing — routable-surface diffs, not CLI scraping.

**Example config:** `examples/rr-evpn-fabric/config.toml` — three VTEP
peers in AS 65000 with `families = ["l2vpn_evpn"]` and
`route_reflector_client = true`.

```toml
[global]
asn = 65000
router_id = "10.0.0.100"
cluster_id = "10.0.0.100"

[[neighbors]]
address = "10.0.0.1"
remote_asn = 65000
families = ["l2vpn_evpn"]
route_reflector_client = true
```

**Scale validated (M33):** 50,000 Type 2 routes reflected from two
originating peers to a third observer, plus 60 s of 1000/sec
withdraw+re-advertise churn, with no route loss and no session flap.
The load generator is the in-tree `bench/evpn-load` crate built
directly on `rustbgpd-wire` — no third-party daemon in the
measurement path.

**Known gaps:**

- VTEP role is now bidirectional but not feature-complete — the
  **declarative foundation slice landed (Gate 7a, ADR-0052)** with
  `[[evpn_instances]]` (vni / rd / route_targets / local_vtep_ip /
  optional bridge / advertise_svi_mac) and the read-only
  `EvpnService.ListEvpnInstances` surface. **Kernel reconciliation
  shipped in Gate 7b (v0.14.0, ADR-0054)** — rustbgpd programs
  remote-MAC FDB entries from received Type 2 routes via rtnetlink.
  **Local-MAC origination shipped in Gate 7b+1 (v0.15.0,
  ADR-0055)** — rustbgpd subscribes to `RTNLGRP_NEIGH`, classifies
  bridge FDB events, and originates Type 2 routes per RFC 7432 §15.1
  with full mobility sequencing, plus one Type 3 IMET per L2VNI
  carrying RFC 6514 §5 PMSI Tunnel. M37 validates the loop end-to-end
  (4/4 PASS, FRR 10.3.1 on Linux 6.17). VTEPs (SONiC / FRR leaves)
  still cover MAC-with-IP via ARP/ND suppression (Gate 7b+2 in
  rustbgpd; alpha-supported under the FRR-style replace model),
  observable DF election + Type 1/4 origination (Gate 8 — ADR-0057;
  shipped in `[Unreleased]`), opt-in DF forwarding enforcement
  foundation (Gate 8b, alpha), and symmetric IRB / L3VNI (Gate 9,
  RFC 9135). See
  [docs/evpn-enablement.md](evpn-enablement.md)
  for the full gate ladder and
  [docs/evpn-alpha-soak.md](evpn-alpha-soak.md) for the residual
  alpha-confidence checklist.
- Controller injection (Gate 6) covers Type 2 MAC/IP and Type 3 IMET
  via `InjectionService::AddEvpnRoute`; Type 5 IP-Prefix injection is
  deferred pending use-case signal. Native Type 1/4 multi-homing
  origination ships through `[[ethernet_segments]]`, but controller
  injection for those route types is not exposed.
- Live FRR VTEP flap with tcpdump validation of the reflected
  `LLGR_STALE` community on the wire is the one piece of GR/LLGR
  coverage still tracked as a follow-up — the unit + integration
  pipeline is wired (Gate 2), but the lab capture isn't part of CI yet.

---

## Deployment Patterns

### Pattern A: Sidecar route injector

rustbgpd runs alongside your edge router on the same host. Your automation
talks to rustbgpd via gRPC; rustbgpd peers with the edge router via iBGP on
loopback.

```
┌─────────────────────────────────────┐
│  Host                               │
│                                     │
│  Automation ──► rustbgpd ◄──iBGP──► FRR/BIRD (FIB)  ──► network
│                   :50051             :179              │
└─────────────────────────────────────┘
```

Best for: hosting providers, DDoS mitigation, SDN controllers.

### Pattern B: Standalone route server

rustbgpd is the only BGP speaker, peering directly with external neighbors.
No edge router needed — rustbgpd is the control plane.

```
Peer A ──┐
Peer B ──┤── eBGP ──► rustbgpd (route server)
Peer C ──┘              :179
```

Best for: IXP route servers, route collectors, looking glasses.

### Pattern C: Containerized microservice

rustbgpd runs as a container in your orchestration platform. Automation
talks to it via gRPC over the container network.

```
┌─────────────────────────────────────┐
│  Kubernetes / Docker Compose        │
│                                     │
│  ┌──────────┐    ┌──────────────┐   │
│  │ your app ├──► │ rustbgpd     │   │
│  │          │    │ (container)  │──────► eBGP to network
│  └──────────┘    └──────────────┘   │
└─────────────────────────────────────┘
```

Best for: DDoS platforms (like prefixd), Kubernetes service IP announcement,
SD-WAN controllers.

---

## Not a Good Fit

Be honest about where rustbgpd isn't the right tool:

- **Full router** — No FIB integration. Can't install routes into the Linux
  kernel. Use FRR or BIRD if you need a forwarding-plane router.
- **EVPN VTEP role — partial (v0.15.0).** rustbgpd-as-RR has been
  the supported deployment since Phase 1 (ADR-0050). Phase 2
  (Gates 7a / 7b / 7b+1 / 7b+2 / 7c, ADR-0052 / 0054 / 0055 /
  0056) added the **bidirectional VTEP loop**: kernel FDB
  programming from received Type 2 routes; local-MAC origination
  via `RTNLGRP_NEIGH` with RFC 7432 §15.1 mobility sequencing;
  Type 3 IMET per L2VNI carrying RFC 6514 §5 PMSI Tunnel for
  ingress-replication BUM; `advertise_svi_mac` originates the
  bridge's own MAC; `sticky_macs` (ADR-0056) marks origination
  with the RFC 7432 §15.4 sticky bit; sub-second mobility
  convergence via the EVPN-keyed `EvpnRouteEvent` broadcast (Gate
  7c); and MAC-with-IP Type 2 origination via ARP/ND suppression
  under the FRR-style replace model (Gate 7b+2 — requires
  `bridge link set dev vxlan<vni> neigh_suppress on`). M37 and
  M37+IP smokes validate the MAC-only and MAC+IP loops against
  FRR 10.3.1. Multi-homing **foundation** (observable DF election
  + Type 1/4 origination) shipped in Gate 8 (`[Unreleased]`,
  ADR-0057), validated by M38, with Gate 8b alpha enforcement
  slices now landed behind opt-in config. **Still missing for full
  VTEP parity:** aliasing dataplane ECMP, 24 h multi-homing churn
  soak before enabling BUM enforcement by default, optional
  import-side ES-Import RT filtering, symmetric IRB (Gate 9,
  RFC 9135), L3VNI / Type 5 dataplane (Gate 9), and duplicate-MAC
  quarantine action (ADR-0055 §9). For a single-homed L2VNI fabric
  where IRB isn't load-bearing, rustbgpd is a fit today; for full
  FRR-equivalent VTEP coverage the remaining gaps close in Gate 8b
  follow-ups and Gate 9.
- **VPLS fabrics** — No RFC 4761 VPLS address family support.
- **Service provider core** — No Confederation (RFC 5065), no labeled unicast,
  no VPNv4/v6. Use FRR or commercial NOS.
- **CLI-first operations** — The CLI is a thin gRPC wrapper, not a full
  interactive shell. If you want IOS-style CLI, use FRR.
- **BIRD replacement at established IXPs** — BIRD + ARouteServer + IXP Manager
  is a deep ecosystem. Migrating away requires tooling integration, not just
  a better daemon.
