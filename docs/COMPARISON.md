# BGP Implementation Comparison

A feature comparison of open-source BGP daemon implementations.

See [CHANGELOG.md](../CHANGELOG.md) for per-release feature deltas and
[evpn-enablement.md](evpn-enablement.md) for the EVPN gate ladder.

This matrix is a broad operator-facing comparison. Cells marked `Partial` or
with a footnote intentionally distinguish shipped subsets from a full routing-
suite implementation. GoBGP capability cells are reconciled with
[gobgp-parity.md](gobgp-parity.md), the canonical source for the
rustbgpd-vs-GoBGP comparison, which records the primary-source verification.

## Overview

| | rustbgpd | FRR (bgpd) | BIRD | GoBGP | OpenBGPd |
|---|:---:|:---:|:---:|:---:|:---:|
| Language | Rust | C | C | Go | C |
| License | MIT | GPL-2.0 | GPL-2.0+ | Apache-2.0 | ISC |
| Primary interface | gRPC | CLI (vtysh) | CLI (birdc) | gRPC | CLI (bgpctl) |
| First release | 2026 | 2017 | 1998 | 2014 | 2004 |
| Multithreaded | Yes (tokio) | No | Yes (BIRD 3) | Yes (goroutines) | Yes (3-process) |

## Address Families

| AFI/SAFI | rustbgpd | FRR | BIRD | GoBGP | OpenBGPd |
|---|:---:|:---:|:---:|:---:|:---:|
| IPv4 Unicast | Yes | Yes | Yes | Yes | Yes |
| IPv6 Unicast | Yes | Yes | Yes | Yes | Yes |
| IPv4 Multicast | No | Yes | Yes | Yes | No |
| IPv6 Multicast | No | Yes | Yes | Yes | No |
| IPv4 Labeled Unicast | Partial[^mpls-rr] | Yes | Yes | Yes | No |
| IPv6 Labeled Unicast | Partial[^mpls-rr] | Yes | Yes | Yes | No |
| VPNv4 (RFC 4364) | Partial[^mpls-rr] | Yes | Yes | Yes | Yes |
| VPNv6 | Partial[^mpls-rr] | Yes | Yes | Yes | Yes |
| RT-Constrain (RFC 4684) | Partial[^mpls-rr] | Yes | Yes | Yes | No |
| L2VPN EVPN (RFC 7432) | Partial[^evpn] | Yes | Yes | Yes | No |
| L2VPN VPLS | No | No | No | Yes | No |
| IPv4 FlowSpec (RFC 8955) | Yes | Yes | Yes | Yes | Yes |
| IPv6 FlowSpec | Yes | Yes | Yes | Yes | Yes |
| VPN FlowSpec | No | No | No | Yes | No |
| BGP-LS (RFC 9552) | Partial | Yes | No | Yes | No |
| SR Policy | No | No | No | Yes | No |

`Partial` for rustbgpd VPN/MPLS families means the route-reflector /
controller-feed slice has shipped, not a PE/MPLS dataplane role. VPNv4/VPNv6,
RT-Constrain, and IPv4/IPv6 labeled-unicast are negotiated as typed families,
stored with their native route identity, exposed through gRPC/CLI, and reflected
to eligible negotiated peers with labels / route targets / next-hop preserved.
VRF import, MPLS label forwarding, CE-facing attachment circuits, and MPLS FIB
programming remain out of scope. BGP-LS is also `Partial`: the receive/API slice
negotiates `linkstate` / `linkstate_vpn`, stores opaque RFC 9552 objects,
exposes them through gRPC/CLI, reflects them to eligible negotiated peers, and
feeds ORR topology input; local LSDB production remains deferred. The boundary
continues to avoid treating VPN, labeled, RTC, or BGP-LS NLRI as ordinary
IPv4/IPv6 `Prefix` routes.

[^mpls-rr]: RR/controller-feed only. No VRF import, MPLS label forwarding,
    CE-facing attachment, or MPLS FIB programming.

[^evpn]: rustbgpd EVPN is **alpha** and Linux/VXLAN-only. Shipped and
    FRR-interop-tested: the Route Reflector role (Types 1-5 reflection);
    a bidirectional single-homed VTEP (Type 2 local-MAC / MAC+IP
    origination from kernel FDB / neighbor events, Type 3 IMET per
    L2VNI); observable DF election + Type 1/4 origination with opt-in
    EVPN BUM-flood suppression + DF election (RFC 7432 §14 aliasing, §8.4
    mass-withdraw, §8.5 kernel BUM-port enforcement, ADR-0059
    FDB-nexthop-group ECMP for multi-homed Type 2, M40 FRR-validated);
    and symmetric Interface-less IRB / L3VNI / Type 5 (RFC 9136 §4.4.2)
    end-to-end with transactional L3 ownership, receive-side GW-IP
    overlay-index recursion, native GW-IP + ESI overlay-index Type 5
    origination, single-active ESI overlay-index receive proven by M71, and
    all-active ESI overlay-index receive proven by M72. Still ahead: Linux
    softswitch local-bias split-horizon, the remaining ADR-0063 runtime
    mixed-edit tail, true shared-VNI / non-zero Ethernet Tag service,
    managed netdev ergonomics, and demand-shaped route types 6-11, PBB-EVPN,
    multicast EVPN, MPLS/SRv6 service
    encapsulation, and VPWS/E-Tree remain demand-shaped service-provider
    breadth, not part of the current VXLAN/Linux alpha lane. See
    [evpn-enablement.md](evpn-enablement.md) for the full gate ladder.

## Core Protocol

| Feature | rustbgpd | FRR | BIRD | GoBGP | OpenBGPd |
|---|:---:|:---:|:---:|:---:|:---:|
| RFC 4271 FSM | Yes | Yes | Yes | Yes | Yes |
| 4-byte ASN (RFC 6793) | Yes | Yes | Yes | Yes | Yes |
| Capability negotiation | Yes | Yes | Yes | Yes | Yes |
| Route Refresh (RFC 2918) | Yes | Yes | Yes | Yes | Yes |
| Enhanced Route Refresh (RFC 7313) | Yes | Yes | Yes | Yes | Yes |
| Prefix ORF (RFC 5291/5292) | Receive | Yes | No | No | No |
| Graceful Restart (RFC 4724) | Yes | Yes | Yes | Yes | Yes |
| Long-Lived GR (RFC 9494) | Yes | Partial | Yes | Yes | No |
| Notification GR (RFC 8538) | Yes | Yes | No | Yes | Yes |
| Add-Path (RFC 7911) | Yes | Yes | Yes | Yes | Yes |
| Extended Messages (RFC 8654) | Yes | Yes | Yes | Yes[^gobgp-extmsg] | Yes |
| Extended Nexthop (RFC 8950) | Yes | Yes | Yes | Yes | Yes |
| BGP unnumbered (interface IPv6 link-local)[^unnum] | Yes | Yes | Yes | Yes | No |
| Route Reflector (RFC 4456) | Yes | Yes | Yes | Yes | Yes |
| Confederation (RFC 5065) | No | Yes | Yes | Yes | No |
| Admin Shutdown (RFC 8203) | Yes | Yes | Yes | Yes | Yes |
| BGP Roles + OTC (RFC 9234) | Yes[^roles] | Yes | Yes | No | Yes |

[^roles]: rustbgpd's v1 Roles + Only-to-Customer implementation covers static
    eBGP IPv4/IPv6 unicast sessions and is FRR-interop-tested by M55. FlowSpec,
    EVPN, iBGP roles, AS-confederation sub-AS roles, and operator overrides of
    OTC behavior are intentionally out of scope for v1.

[^gobgp-extmsg]: GoBGP upstream support was added in the exact `v4.7.0` tag,
    verified 2026-07-12 from the tagged
    [release notes](https://github.com/osrg/gobgp/releases/tag/v4.7.0). This
    records upstream support, not a rustbgpd/GoBGP interoperability receipt.

## Policy Engine

| Feature | rustbgpd | FRR | BIRD | GoBGP | OpenBGPd |
|---|:---:|:---:|:---:|:---:|:---:|
| Prefix matching (ge/le) | Yes | Yes | Yes | Yes | Yes |
| AS-path regex | Yes | Yes | Yes | Yes | Yes |
| Standard communities | Yes | Yes | Yes | Yes | Yes |
| Extended communities | Yes | Yes | Yes | Yes | Yes |
| Large communities (RFC 8092) | Yes | Yes | Yes | Yes | Yes |
| Community add/remove/replace | Yes | Yes | Yes | Yes | Yes |
| MED manipulation | Yes | Yes | Yes | Yes | Yes |
| LOCAL_PREF set | Yes | Yes | Yes | Yes | Yes |
| AS-path prepend | Yes | Yes | Yes | Yes | Yes |
| Next-hop set/self | Yes | Yes | Yes | Yes | Yes |
| RPKI validation match | Yes | Yes | Yes | Yes | Yes |
| Neighbor/peer matching | Yes | Yes | Yes | Yes | Yes |
| Named policy definitions | Yes | Yes | Yes | Yes | Yes |
| Policy chaining | Yes | Yes | Yes | Yes | Yes |
| Import-policy explain (per-prefix decision trace) | Yes (opt-in) | No | No | No | No |
| Custom filter language | Yes | No | Yes | No | Yes |
| Parameterized policies (templates) | Yes | No | Yes | No | Partial |
| In-language policy unit tests | Yes | No | No | No | No |
| Policy dry-run against the live RIB | Yes | No | No | No | No |
| Live per-term policy hit counters | Yes | No | No | No | No |
| RFC 8212 default eBGP policy | Opt-in | Profile-dependent[^rfc8212-frr] | Yes[^rfc8212-bird] | No[^rfc8212-gobgp] | Yes[^rfc8212-openbgpd] |

[^rfc8212-frr]: [FRR latest](https://docs.frrouting.org/en/latest/bgp.html#require-policy-on-ebgp)
    documents `bgp ebgp-requires-policy` as enabled by default in the
    traditional profile and disabled by default in the datacenter profile.
[^rfc8212-bird]: BIRD [3.3.1](https://bird.nic.cz/doc/bird-3.3.1.html) and
    [2.19.0](https://bird.nic.cz/doc/bird-2.19.0.html) require explicit import
    and export policy for external BGP; this claim is limited to those release
    lines.
[^rfc8212-gobgp]: GoBGP
    [v4.7.0 policy documentation](https://raw.githubusercontent.com/osrg/gobgp/v4.7.0/docs/sources/policy.md)
    says unmatched import and export policy defaults to `accept-route`.
[^rfc8212-openbgpd]: The
    [OpenBSD-current `bgpd.conf(5)` filter documentation](https://man.openbsd.org/bgpd.conf#FILTER)
    says BGP UPDATEs are blocked by default and the default filter action is
    deny.

## Security

| Feature | rustbgpd | FRR | BIRD | GoBGP | OpenBGPd |
|---|:---:|:---:|:---:|:---:|:---:|
| TCP MD5 (RFC 2385) | Yes | Yes | Yes | Yes | Yes |
| TCP-AO (RFC 5925) | Static + dynamic-prefix keyrings; observation-gated live rotation; deprecated/unselected-key deletion on SIGHUP | No | Yes | No | No |
| GTSM / TTL Security | Yes | Yes | Yes | Yes | Yes |
| RPKI origin validation | Yes | Yes | Yes | Yes | Yes |
| ASPA path verification | Yes[^aspa] | No | Yes | No | Yes |
| Private AS removal | Yes | Yes | Yes | Yes | Yes |
| Privilege separation | No | No | No | No | Yes |
| Memory-safe language | Yes | No | No | Yes | No |

CVE-2026-49943, a stack-based buffer overflow in BIRD's AS-path filter
matching reachable when RFC 8654 extended messages are enabled (affected
through 2.19.0), is a recent example of the vulnerability class the
memory-safe-language row refers to.

[^aspa]: rustbgpd ships RTR v2 ASPA input, role-aware upstream/downstream path
    verification selected by BGP Roles, best-path preference, policy matching
    for IPv4/IPv6 unicast, and targeted import-policy refresh when validation
    caches update.

## Monitoring & Observability

| Feature | rustbgpd | FRR | BIRD | GoBGP | OpenBGPd |
|---|:---:|:---:|:---:|:---:|:---:|
| Prometheus metrics | Yes | Via exporter[^prom-frr] | No | Yes | No |
| Structured logging (JSON) | Yes | No | No | No | No |
| BMP (RFC 7854) | Yes | Yes | Yes | Yes | No |
| BMP full trio (7854 + 8671 Adj-RIB-Out + 9069 Loc-RIB) | Yes | No | No | No | No |
| BMPv4 + Path Marking TLV (pre-IANA drafts) | Yes | No | No | No | No |
| MRT dump (RFC 6396) | Yes | Yes | Yes | Yes | Yes |
| Streaming route events | Yes | No | No | Yes | No |
| OpenConfig/gNMI telemetry | Subset[^gnmi] | Partial | No | No | No |

## API & Programmability

| Feature | rustbgpd | FRR | BIRD | GoBGP | OpenBGPd |
|---|:---:|:---:|:---:|:---:|:---:|
| gRPC API | Yes | Partial | No | Yes | No |
| OpenConfig/gNMI API | Subset[^gnmi] | Partial | No | No | No |
| REST API | Partial | Partial | No | No | No |
| YANG model | No | Partial | No | No | No |
| CLI tool | Yes | Yes | Yes | Yes | Yes |
| CLI JSON output | Yes | Yes | No | Yes | Yes |
| Runtime route injection | Yes | No | No | Yes | No |
| Config persistence (API mutations) | Yes | No | No | No | No |
| Hot reconfiguration (no restart) | Yes | Yes | Yes | Yes | Yes |
| Embeddable library | No | No | No | Yes | No |

## Operations

| Feature | rustbgpd | FRR | BIRD | GoBGP | OpenBGPd |
|---|:---:|:---:|:---:|:---:|:---:|
| Live TUI dashboard | Yes | No | No | No | No |
| Config error diagnostics | Yes | No | No | No | No |
| Docker image | Yes | Yes | Yes | Yes | No |
| Fuzz testing | Yes | No | No | No | No |
| Interop test suite | Yes | No | No | No | No |
| FIB/kernel integration | Partial[^fib] | Yes | Yes | Yes | Yes |
| Route server mode | Yes | Yes | Yes | Yes | Yes |
| Dynamic neighbors | Yes | Yes | Yes | Yes | Yes[^dyn-openbgpd] |
| Looking glass | Yes | No | Yes | No | Yes |
| BFD integration | Yes[^bfd] | Yes | Yes | Yes | No |

[^dyn-openbgpd]: Prefix-template neighbors: `neighbor 10.0.0.0/8` in
    bgpd.conf(5) accepts any connection from within the network as a cloned
    neighbor, optionally with any remote AS.

[^bfd]: Single-hop **asynchronous** BFD ships (RFC 5880/5881, ADR-0067): an
    in-process, no-GC actor runs sessions over UDP/3784 (TTL/Hop-Limit 255,
    discard-on-receive if ≠ 255), config via `[[bfd_profiles]]` +
    `[neighbors.bfd]`, observable through `GetBfdSessions` / `rbgp bfd` /
    events + Prometheus. RFC 5882 BGP coupling ships in both **strict** (withhold
    BGP until BFD Up) and **non-strict** (tear BGP down on BFD-down before the
    hold timer) modes; the non-strict path is cross-checked against FRR `bfdd` by
    interop test M51, and strict mode is covered by unit tests. v1 is IPv4 +
    IPv6 **global**, static neighbors only. Deferred: multihop (RFC 5883),
    echo / demand mode, authentication, C-bit / GR-aware nuance, static-route
    BFD tracking, dynamic-neighbor BFD, hardware / offload, and BFD over
    IPv6 link-local / unnumbered peers → v1.1 (BGP unnumbered itself shipped —
    ADR-0069 / M53).

[^fib]: rustbgpd's FIB integration is intentionally opt-in and scoped: RFC 7999
    BLACKHOLE discard install plus explicit `[[fib_tables]]` unicast table
    export through the ADR-0061 reconciler, including ECMP / weighted multipath
    and runtime `SetFibTable` / `DeleteFibTable` / `ListFibTables` CRUD. It is
    not a default-on full routing-suite FIB manager or Zebra replacement.

[^unnum]: Interface-scoped BGP over IPv6 link-local carrying IPv4 unicast via
    RFC 8950. rustbgpd ships static interface-bound neighbors (operator supplies
    `address` + `interface`) with scoped Linux FIB install (egress `dev`),
    validated against FRR by M53 (ADR-0069); FRR-style pure-interface
    autodiscovery and the same link-local address on multiple interfaces are
    deferred. FRR (`neighbor IFACE interface`), GoBGP (`neighbor-interface`),
    and BIRD (`fe80::x%iface`, plus RAdv-based AutoBGP added in 3.3.0 / 2.19.0
    on 2026-05-25) support interface autodiscovery. OpenBGPd has no interface /
    unnumbered neighbor model (numeric-IP neighbors only), although it does
    support the RFC 8950 next-hop encoding itself.

[^prom-frr]: FRR has no native Prometheus endpoint; metrics are
    scraped through the external `frr_exporter` (packaged in Debian as
    `prometheus-frr-exporter`), which polls the FRR vty sockets and
    serves `/metrics` itself. GoBGP's metrics are native: `gobgpd
    --pprof-host` serves Prometheus metrics on `/metrics`.

[^gnmi]: rustbgpd ships a native `gnmi.gNMI` target for a strict
    OpenConfig BGP operational-state subset: `Capabilities`, `Get`, and
    `Subscribe` (ONCE / POLL / STREAM SAMPLE, plus STREAM ON_CHANGE for
    neighbor `session-state` when `[event_history]` is enabled) over UDS or
    mTLS TCP, plus an operator-tier `Set` subset — transaction-backed static
    numbered-neighbor create/update/delete and the commit-confirmed extension
    via ADR-0076, with unsupported paths returning `Unimplemented`. Dial-out is
    also supported: `[gnmi_dialout]` pushes the same `SubscribeResponse` stream
    over a device-initiated gRPC connection to central collectors (TLS/mTLS,
    capped-backoff reconnect, per-target connection gauge). M54 verifies
    both read and Set with `gnmic`; M56 covers the ON_CHANGE flow. FRR's OpenConfig story is
    through broader management frameworks such as `mgmtd` / SONiC-style
    northbound layers rather than a clean per-`bgpd` gNMI service.

## Best-Path Selection

| Step | rustbgpd | FRR | BIRD | GoBGP | OpenBGPd |
|---|:---:|:---:|:---:|:---:|:---:|
| LOCAL_PREF | Yes | Yes | Yes | Yes | Yes |
| AS-path length | Yes | Yes | Yes | Yes | Yes |
| ORIGIN | Yes | Yes | Yes | Yes | Yes |
| MED | Yes | Yes | Yes | Yes | Yes |
| eBGP over iBGP | Yes | Yes | Yes | Yes | Yes |
| CLUSTER_LIST length | Yes | Yes | Yes | Yes | Yes |
| ORIGINATOR_ID | Yes | Yes | Yes | Yes | Yes |
| Stale route demotion (GR) | Yes | Yes | Yes | Yes | Yes |
| RPKI preference | Yes | Yes | Yes | Yes | Yes |
| AIGP | No | Yes | Yes | Yes | No |
| Multipath/ECMP | Yes[^multipath] | Yes | Yes | Yes | Yes |

[^multipath]: Classic unicast multipath/ECMP FIB install ships (ADR-0066):
    `[[fib_tables]].maximum_paths` selects N equal-cost BGP paths per prefix
    (homogeneous eBGP **or** iBGP) and installs them as a kernel `RTA_MULTIPATH`
    route — opt-in per table, default `1` (single next-hop). The global
    `[global].multipath_relax` knob relaxes the default exact-`AS_PATH` grouping
    to `AS_PATH`-length-only (FRR's `bgp bestpath as-path multipath-relax`).
    Per-class caps (`maximum_paths_ebgp` / `maximum_paths_ibgp`, FRR parity) let
    eBGP and iBGP groups carry different widths. The global
    `[global].link_bandwidth_weighted` knob (ADR-0068) weights ECMP next-hops by
    their lowest usable RFC 10005 Link Bandwidth Extended Community (receiver
    subset; exact type 0x00/0x40). Zero or unusable values use equal-cost
    fallback; FRR calls the weighting mode `bgp bestpath bandwidth`. Add-Path
    multi-path *send* (RFC 7911, route-server mode) and EVPN aliasing ECMP
    (ADR-0059 FDB nexthop groups, default-on) also ship.

## Performance Snapshot (bgperf2 — 2026-07-26)

Same host and harness, all targets run back to back on an idle machine,
medians of 3 runs per cell (6 at 10×1k). "Converged" is bgperf2's
elapsed-to-full-table figure; RSS is full-daemon max over the run, in MiB.

| Scenario | rustbgpd | BIRD 2.18 (master) | GoBGP 4.3.0 | FRR 10.7.0-dev |
|---|---|---|---|---|
| 10 peers × 1k prefixes | 2 s / 37.9 | 2 s / 8.2 | 3 s / 38.9 | 3 s / 27.6 |
| 2 peers × 10k prefixes | 2 s / 48.1 | 2 s / 9.2 | 3 s / 44.0 | 3 s / 36.9 |
| 2 peers × 100k prefixes | 3 s / 212.0 | 3 s / 27.6 | 6 s / 202.8 | 4 s / 228.4 |
| 30 peers × 1k prefixes | 3 s / 108.5 | 3 s / 11.3 | 4 s / 68.6 | 4 s / 51.2 |
| 100 peers × 1k prefixes | 3 s / 212.0 | 5 s / 32.8 | 20 s / 193.5 | 7 s / 134.1 |

rustbgpd is fastest on total time at all five shapes, and its convergence
lead widens with peer count: 3 s at 100 peers against 5 / 7 / 20 s.
**On memory it is last of the four at 100 peers × 1k — its own target
shape** — at 1.10× GoBGP, 1.58× FRR, and 6.46× BIRD; against BIRD the
ratio is 4.6×–9.6× at every shape. rustbgpd's RSS is also the noisiest
figure in the run (86.0 / 108.5 / 131.1 MiB across three runs at 30
peers), so treat it as a range. The campaign's 100 peers × 1k and
2 peers × 100k cells both measure 212.0 MiB, but that coincidence does
not isolate a scaling dimension. A controlled follow-up varies peers and
BASE routes independently under continuous churn: steady RSS grows by
118.200/142.844 KiB per peer at fixed 10k/100k BASE routes and
825.515/850.751 B per BASE route at fixed 10/100 peers. Both dimensions
are material; the old 1.93
MiB/peer value is a mixed-shape upper bound, not a sizing coefficient.
The same follow-up removes a 6,150,300-byte eager RFC 8654 receive-buffer
owner. It makes no RSS claim because the measured −0.324% falls below
its 0.645% floor, and no allocator-total or aggregate-DHAT claim because
continuous churn left different final route totals. A 2026-06-02
whole-daemon DHAT profile still attributes
the route-heavy shape primarily to the three-layer RIB model
(Adj-RIB-In + Loc-RIB + Adj-RIB-Out) and its route-map / prefix-index
storage. The durable event-history outbox is opt-in
(default off); enabling it adds RSS roughly proportional to event
volume. OpenBGPD is absent because a bgperf2 harness defect prevented it
from starting, not because of a daemon result. See
[BENCHMARKS.md](BENCHMARKS.md) for the full cross-stack tables and
[the cross-stack receipt](perf/competitive-bgperf2-2026-07.md) for
per-run values, plus the [controlled attribution
receipt](perf/per-peer-rss-attribution-2026-07.md) for the correction.

At route-server scale, the [IXP receipt
matrix](perf/ixp-matrix-2026-07.md) compares rustbgpd, BIRD 3.3.1, and
OpenBGPD 9.1 head-to-head at 700 peers × 400k prefixes under live churn
— policy-reload stall and completion, member-flap propagation,
convergence, and RSS — with identical wire inputs, config disclosure,
and the losses published alongside the wins.

A separate [1,000-peer retained receipt](perf/route-server-1000-2026-07.md)
exercises a uniform all-eBGP route-server fleet against the real daemon: 400k
routes, 399.6 million observer-NLRI cold deliveries, four generation-complete
export reloads, and continuous readiness/RSS/grouping checks. It is capacity
acceptance for that disclosed same-host shape, not another competitor result.

The exact v0.61.0 release tip also has an
[absolute baseline](perf/v0.61.0-final-performance-2026-07.md): three
1,000-peer × 400-BASE-route real-daemon runs measured steady process-tree RSS
medians of 441.760/441.215/441.131 MiB while all settled grouping,
registration, rejection, and writer gates held. Its 71-row Criterion archive
is likewise single-revision. Neither set is a competitor comparison or a
causal delta, and neither rewrites the pinned `515659b1` campaign above.

## Positioning

**rustbgpd** is an API-first BGP daemon targeting data-center fabric, IX
route-server, and automation-controller use cases. It trades full routing-suite
breadth for modern operational tooling (gRPC, Prometheus, structured logging,
TUI, config diagnostics) and memory safety guarantees.

**FRR** is the most feature-complete open-source routing suite, covering BGP plus
OSPF, IS-IS, PIM, and more. Best choice when you need a mature full routing stack
with broad AFI/SAFI coverage and production-default kernel FIB integration.

**BIRD** dominates IXP route server deployments. Best-in-class memory efficiency
and a powerful filter language. BIRD 3 adds multithreading for 5000+ peer scale.
Lacks a programmatic API — management is CLI/config-file only.

**GoBGP** pioneered the API-first model with gRPC as its primary interface. Broadest
AFI/SAFI coverage. Higher memory and CPU usage than C implementations at scale.
Best as an SDN controller or route injector rather than a high-performance router.

**OpenBGPd** is security-focused with privilege separation and OpenBSD heritage.
Deployed at major IXPs (LINX, Netnod). Lean, reliable, and standards-compliant
with strong RFC coverage including BGP Roles and Extended Messages. No
programmatic API beyond the CLI socket.

### Why reload behavior decided this market

The route-server segment has historically been won and lost on config-reload
behavior, not feature checklists. The published account of OpenBGPD's
route-server revival records both halves of that history. On the performance
half: the ruleset OpenBGPD needed for correct per-member filtering "negatively
impacted service performance during configuration reloads," and at YYCIX (the
Calgary IXP) a 370,000-rule configuration took over an hour to converge —
brought under two minutes only after the 2018 filter-performance overhaul and
an arouteserver ruleset reduction to under 6,000 rules
([RIPE Labs, 2018](https://labs.ripe.net/author/claudio_jeker/openbgpd-adding-diversity-to-the-route-server-landscape/);
[APNIC blog, 2019](https://blog.apnic.net/2019/01/28/openbgpd-adding-diversity-to-the-route-server-landscape/)).
On the diversity half: the same account states there was "effectively only a
single solution in the Route Server vendor market: the BIRD Internet routing
daemon," and that the RIPE NCC Community Projects Fund financed OpenBGPD's
revival because that monoculture was considered unhealthy for the IXP
ecosystem. Reload stall and completion under live churn is therefore the
metric this market has actually selected on — and it is exactly what the
[IXP receipt matrix](perf/ixp-matrix-2026-07.md) measures head-to-head at
700 peers × 400k prefixes: rustbgpd is the only daemon of the three tested
that holds both sub-second median UPDATE stall and single-digit-seconds
policy-reload completion (p50 1.5–2.2 s, vs ~80 s for BIRD 3.3.1 and ~250 s
for OpenBGPD 9.1 on the same host and wire inputs), with per-daemon wins and
losses — including OpenBGPD's smaller raw stall — published in the receipt.

Reload speed is only half the operator concern; the other half is what an
invalid config does to a running router. FRR's reload driver
(`frr-reload.py`, a text-diff over vtysh) at one point responded to an
invalid candidate file by applying a blank configuration — removing every
line of running config — as reported against FRR 8.1 in
[FRR issue #10453](https://github.com/FRRouting/frr/issues/10453) (January
2022) and addressed by
[FRR PR #10187](https://github.com/FRRouting/frr/pull/10187) (merged
December 2021, in releases after the reporter's). rustbgpd's
reload path makes that failure class structurally unreachable rather than
patched: a candidate config is parsed and validated in full before anything
is applied ([`rustbgpd --check`](CONFIGURATION.md), the `rejected` class in
the [reload matrix](reload-matrix.md)), a file that fails validation leaves
the running daemon untouched by construction, and
[commit-confirmed transactions](OPERATIONS.md) add an explicit
operator-confirmation window with automatic boot-revert if confirmation
never arrives.

Migration between daemons remains the segment's unsolved problem: no
open-source BGP daemon ships a config converter from any of the others, and
IXP practice sidesteps conversion by generating configs for each daemon from
a higher-level source such as
[arouteserver](https://github.com/pierky/arouteserver). Tooling *around* the
incumbents fills gaps the daemons leave open — native JSON output for
`birdc` was requested on
[bird-users in April 2020](https://bird.network.cz/pipermail/bird-users/2020-April/014524.html)
with a list of regex-based parser projects standing in for it, and BIRD
still has no JSON CLI output (see API & Programmability above). rustbgpd
ships JSON CLI output, a gRPC API, and `rbgp config import` — a bounded
BIRD 2 / FRR / GoBGP structural importer that translates the mechanical
subset (AS, router-id, neighbors, peer groups, families, timers,
max-prefix) and fail-stops with a line-numbered report of every policy
construct left for hand-translation to `.rpol`.
