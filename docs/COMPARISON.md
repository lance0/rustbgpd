# BGP Implementation Comparison

A feature comparison of open-source BGP daemon implementations.

Last updated: 2026-03-14

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
| IPv4 Labeled Unicast | No | Yes | No | Yes | No |
| IPv6 Labeled Unicast | No | Yes | No | Yes | No |
| VPNv4 (RFC 4364) | No | Yes | Yes | Yes | Yes |
| VPNv6 | No | Yes | Yes | Yes | Yes |
| L2VPN EVPN (RFC 7432) | No | Yes | Yes | Yes | No |
| L2VPN VPLS | No | No | No | Yes | No |
| IPv4 FlowSpec (RFC 8955) | Yes | Yes | Yes | Yes | Yes |
| IPv6 FlowSpec | Yes | Yes | Yes | Yes | Yes |
| VPN FlowSpec | No | No | No | Yes | No |
| BGP-LS (RFC 7752) | No | No | No | Yes | No |
| SR Policy | No | No | No | Yes | No |

## Core Protocol

| Feature | rustbgpd | FRR | BIRD | GoBGP | OpenBGPd |
|---|:---:|:---:|:---:|:---:|:---:|
| RFC 4271 FSM | Yes | Yes | Yes | Yes | Yes |
| 4-byte ASN (RFC 6793) | Yes | Yes | Yes | Yes | Yes |
| Capability negotiation | Yes | Yes | Yes | Yes | Yes |
| Route Refresh (RFC 2918) | Yes | Yes | Yes | Yes | Yes |
| Enhanced Route Refresh (RFC 7313) | Yes | Yes | Yes | No | Yes |
| Graceful Restart (RFC 4724) | Yes | Yes | Yes | Yes | Yes |
| Long-Lived GR (RFC 9494) | Yes | Partial | Yes | Yes | No |
| Notification GR (RFC 8538) | Yes | No | No | Yes | Yes |
| Add-Path (RFC 7911) | Yes | Yes | Yes | Yes | Yes |
| Extended Messages (RFC 8654) | Yes | Yes | Yes | No | Yes |
| Extended Nexthop (RFC 8950) | Yes | Yes | Yes | Yes | Yes |
| Route Reflector (RFC 4456) | Yes | Yes | Yes | Yes | Yes |
| Confederation (RFC 5065) | No | Yes | Yes | Yes | No |
| Admin Shutdown (RFC 8203) | Yes | Yes | Yes | Yes | Yes |
| BGP Roles (RFC 9234) | No | No | Yes | No | Yes |

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
| Custom filter language | No | No | Yes | No | Yes |

## Security

| Feature | rustbgpd | FRR | BIRD | GoBGP | OpenBGPd |
|---|:---:|:---:|:---:|:---:|:---:|
| TCP MD5 (RFC 2385) | Yes | Yes | Yes | Yes | Yes |
| TCP-AO (RFC 5925) | No | No | No | No | No |
| GTSM / TTL Security | Yes | Yes | Yes | Yes | Yes |
| RPKI/RTR (RFC 6810/8210) | Yes | Yes | Yes | Yes | Yes |
| ASPA verification | Yes | No | Yes | No | Yes |
| Private AS removal | Yes | Yes | Yes | Yes | Yes |
| Privilege separation | No | No | No | No | Yes |
| Memory-safe language | Yes | No | No | Yes | No |

## Monitoring & Observability

| Feature | rustbgpd | FRR | BIRD | GoBGP | OpenBGPd |
|---|:---:|:---:|:---:|:---:|:---:|
| Prometheus metrics | Yes | Yes | No | Yes | No |
| Structured logging (JSON) | Yes | No | No | No | No |
| BMP (RFC 7854) | Yes | Yes | Yes | Yes | No |
| MRT dump (RFC 6396) | Yes | Yes | Yes | Yes | Yes |
| Streaming route events | Yes | No | No | Yes | No |

## API & Programmability

| Feature | rustbgpd | FRR | BIRD | GoBGP | OpenBGPd |
|---|:---:|:---:|:---:|:---:|:---:|
| gRPC API | Yes | Partial | No | Yes | No |
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
| FIB/kernel integration | No | Yes | Yes | Yes | Yes |
| Route server mode | Yes | Yes | Yes | Yes | Yes |
| Dynamic neighbors | No | Yes | Yes | Yes | No |
| Looking glass | Yes | No | Yes | No | Yes |
| BFD integration | No | Yes | Yes | No | No |

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
| AIGP | No | Yes | No | Yes | No |
| Multipath/ECMP | Partial | Yes | Yes | Yes | Yes |

## Memory (200k prefixes, bgperf2)

| Implementation | Memory |
|---|---|
| BIRD | ~7 MB |
| FRR | ~30 MB |
| rustbgpd | ~257 MB |
| GoBGP | ~578 MB |

OpenBGPd was not tested in this benchmark.

## Positioning

**rustbgpd** is an API-first BGP daemon targeting IX route server and SDN controller
use cases. It trades address family breadth for modern operational tooling (gRPC,
Prometheus, structured logging, TUI, config diagnostics) and memory safety guarantees.

**FRR** is the most feature-complete open-source routing suite, covering BGP plus
OSPF, IS-IS, PIM, and more. Best choice when you need a full routing stack with
broad AFI/SAFI coverage and kernel FIB integration.

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
