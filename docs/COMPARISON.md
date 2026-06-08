# BGP Implementation Comparison

A feature comparison of open-source BGP daemon implementations.

See [CHANGELOG.md](../CHANGELOG.md) for per-release feature deltas and
[evpn-enablement.md](evpn-enablement.md) for the EVPN gate ladder.

This matrix is a broad operator-facing comparison. Cells marked `Partial` or
with a footnote intentionally distinguish shipped subsets from a full routing-
suite implementation.

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
| IPv4 Labeled Unicast | No | Yes | Yes | Yes | No |
| IPv6 Labeled Unicast | No | Yes | Yes | Yes | No |
| VPNv4 (RFC 4364) | No | Yes | Yes | Yes | Yes |
| VPNv6 | No | Yes | Yes | Yes | Yes |
| L2VPN EVPN (RFC 7432) | Partial[^evpn] | Yes | Yes | Yes | No |
| L2VPN VPLS | No | No | No | Yes | No |
| IPv4 FlowSpec (RFC 8955) | Yes | Yes | Yes | Yes | Yes |
| IPv6 FlowSpec | Yes | Yes | Yes | Yes | Yes |
| VPN FlowSpec | No | No | No | Yes | No |
| BGP-LS (RFC 9552) | No | Yes | No | Yes | No |
| SR Policy | No | No | No | Yes | No |

[^evpn]: rustbgpd EVPN is **alpha** and Linux/VXLAN-only. Shipped and
    FRR-interop-tested: the Route Reflector role (Types 1-5 reflection);
    a bidirectional single-homed VTEP (Type 2 local-MAC / MAC+IP
    origination from kernel FDB / neighbor events, Type 3 IMET per
    L2VNI); observable DF election + Type 1/4 origination with opt-in
    EVPN BUM-flood suppression + DF election (RFC 7432 §14 aliasing, §8.4
    mass-withdraw, §8.5 kernel BUM-port enforcement, ADR-0059
    FDB-nexthop-group ECMP for multi-homed Type 2, M40 FRR-validated);
    and symmetric Interface-less IRB / L3VNI / Type 5 (RFC 9136 §4.4.2)
    end-to-end with transactional L3 ownership plus receive-side
    overlay-index recursion. Still ahead: RFC 9135 overlay-index *local*
    origination, route types 6-11 / MPLS / PBB / MVPN. See
    [evpn-enablement.md](evpn-enablement.md) for the full gate ladder.

## Core Protocol

| Feature | rustbgpd | FRR | BIRD | GoBGP | OpenBGPd |
|---|:---:|:---:|:---:|:---:|:---:|
| RFC 4271 FSM | Yes | Yes | Yes | Yes | Yes |
| 4-byte ASN (RFC 6793) | Yes | Yes | Yes | Yes | Yes |
| Capability negotiation | Yes | Yes | Yes | Yes | Yes |
| Route Refresh (RFC 2918) | Yes | Yes | Yes | Yes | Yes |
| Enhanced Route Refresh (RFC 7313) | Yes | Yes | Yes | No | Yes |
| Prefix ORF (RFC 5291/5292) | Receive | Yes | No | No | No |
| Graceful Restart (RFC 4724) | Yes | Yes | Yes | Yes | Yes |
| Long-Lived GR (RFC 9494) | Yes | Partial | Yes | Yes | No |
| Notification GR (RFC 8538) | Yes | Yes | No | Yes | Yes |
| Add-Path (RFC 7911) | Yes | Yes | Yes | Yes | Yes |
| Extended Messages (RFC 8654) | Yes | Yes | Yes | No | Yes |
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
| Import-policy explain (per-prefix decision trace) | Yes | No | No | No | No |
| Custom filter language | No | No | Yes | No | Yes |

## Security

| Feature | rustbgpd | FRR | BIRD | GoBGP | OpenBGPd |
|---|:---:|:---:|:---:|:---:|:---:|
| TCP MD5 (RFC 2385) | Yes | Yes | Yes | Yes | Yes |
| TCP-AO (RFC 5925) | Static startup | No | Yes | No | No |
| GTSM / TTL Security | Yes | Yes | Yes | Yes | Yes |
| RPKI origin validation | Yes | Yes | Yes | Yes | Yes |
| ASPA path verification | Yes[^aspa] | No | Yes | No | Yes |
| Private AS removal | Yes | Yes | Yes | Yes | Yes |
| Privilege separation | No | No | No | No | Yes |
| Memory-safe language | Yes | No | No | Yes | No |

[^aspa]: rustbgpd ships RTR v2 ASPA input, role-aware upstream/downstream path
    verification selected by BGP Roles, best-path preference, policy matching
    for IPv4/IPv6 unicast, and targeted import-policy refresh when validation
    caches update.

## Monitoring & Observability

| Feature | rustbgpd | FRR | BIRD | GoBGP | OpenBGPd |
|---|:---:|:---:|:---:|:---:|:---:|
| Prometheus metrics | Yes | Yes | No | Yes | No |
| Structured logging (JSON) | Yes | No | No | No | No |
| BMP (RFC 7854) | Yes | Yes | Yes | Yes | No |
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
| Dynamic neighbors | Yes | Yes | Yes | Yes | No |
| Looking glass | Yes | No | Yes | No | Yes |
| BFD integration | Yes[^bfd] | Yes | Yes | Yes | No |

[^bfd]: Single-hop **asynchronous** BFD ships (RFC 5880/5881, ADR-0067): an
    in-process, no-GC actor runs sessions over UDP/3784 (TTL/Hop-Limit 255,
    discard-on-receive if ≠ 255), config via `[[bfd_profiles]]` +
    `[neighbors.bfd]`, observable through `GetBfdSessions` / `rustbgpctl bfd` /
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

[^gnmi]: rustbgpd ships a native `gnmi.gNMI` target for a strict
    OpenConfig BGP operational-state subset: `Capabilities`, `Get`, and
    `Subscribe` (ONCE / POLL / STREAM SAMPLE, plus STREAM ON_CHANGE for
    neighbor `session-state` when `[event_history]` is enabled) over UDS or
    mTLS TCP, plus an operator-tier `Set` subset — transaction-backed static
    numbered-neighbor create/update/delete and the commit-confirmed extension
    via ADR-0076, with unsupported paths returning `Unimplemented`. M54 verifies
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
    their Link Bandwidth Extended Community (draft-ietf-idr-link-bandwidth, FRR's
    `bgp bestpath bandwidth`) for unequal-cost load balancing. Add-Path
    multi-path *send* (RFC 7911, route-server mode) and EVPN aliasing ECMP
    (ADR-0059 FDB nexthop groups, default-on) also ship.

## Memory Snapshot (2 peers × 100k prefixes, bgperf2 — 2026-05-29, v0.32.0)

| Implementation | Max RSS |
|---|---|
| BIRD 2.18 | ~30 MB |
| GoBGP 4.3.0 | ~203 MB |
| rustbgpd (v0.32.0, default) | ~284 MB |
| rustbgpd (event-history enabled) | ~346 MB |

Full-daemon process RSS, same host and harness. rustbgpd's full-daemon RSS sits
above GoBGP here because route storage is less compact: a 2026-06-02
whole-daemon dhat profile attributes the live-at-peak heap primarily to the
three-layer RIB model (Adj-RIB-In + Loc-RIB + Adj-RIB-Out) and its route-map /
prefix-index storage, not operational surfaces. The first measured fix moved
the Adj-RIB-In / Adj-RIB-Out prefix indexes to trie-backed storage, lowering the
allocator-tracked RIB profile at this scale from 66.6 MB to 60.6 MB; the durable
event-history outbox is opt-in (default off) as of v0.32.0, and enabling it is
the ~284 → ~346 MB delta. FRR and OpenBGPd were not in this run. See
[BENCHMARKS.md](BENCHMARKS.md) for the full cross-stack tables, the RIB memory
profile, and methodology.

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
