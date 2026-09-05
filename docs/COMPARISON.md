# BGP Implementation Comparison

> **Document class: CURRENT.** This maintained page reflects the project as it is now; dated sections remain bounded to their stated scope.

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
| Latest release (verified 2026-09-01)[^versions] | v0.68.0 (2026-08-30) | 10.7.1 (2026-08-31) | 3.3.2 (2026-07-30) | v4.9.0 (2026-09-01) | 9.2 (2026-08-06) |

[^versions]: Dates are the upstream release announcements: FRR
    [frr-10.7.1](https://github.com/FRRouting/frr/releases/tag/frr-10.7.1),
    BIRD [3.3.2 `NEWS`](https://gitlab.nic.cz/labs/bird/-/blob/v3.3.2/NEWS),
    GoBGP [v4.9.0](https://github.com/osrg/gobgp/releases/tag/v4.9.0),
    OpenBGPD [9.2](https://www.mail-archive.com/announce@openbsd.org/msg00601.html),
    and the rustbgpd [changelog](../CHANGELOG.md). This row does not
    re-derive the dated footnotes below, which keep the exact version each
    claim was verified against. Route-server config generation still pins
    [arouteserver 1.23.2](https://github.com/pierky/arouteserver/releases/tag/v1.23.2)
    (2025-01-05), the latest release, whose
    [supported speakers](https://arouteserver.readthedocs.io/en/latest/SUPPORTED_SPEAKERS.html)
    page still labels BIRD v3 support alpha.

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
| L2VPN EVPN (RFC 7432) | Partial[^evpn] | Yes | Partial[^evpn-bird] | Yes | RIB only[^evpn-openbgpd] |
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
    all-active ESI overlay-index receive proven by M72. The VXLAN underlay
    runs on IPv4 or IPv6: against FRR 10.7.1 on Linux 7.0, an IPv6 VTEP
    carries the L2 path end to end (M109 — IPv6 tunnel source, IPv6 BGP
    transport, 16-octet Type 2 and Type 3 next hops, remote-MAC FDB rows
    programmed with an IPv6 `dst`), and symmetric IRB works over an IPv6
    underlay for IPv6 tenant prefixes (M110, manual). Interface-less IRB
    does not implement `RTA_VIA`, so the prefix and next-hop families must
    agree: an IPv4 tenant prefix under an IPv6 VTEP is refused at
    origination and dropped at import. IPv6 VTEPs are single-homed only —
    FRR documents IPv6 VTEP addresses as unsupported with EVPN
    multi-homing. Still ahead: Linux
    softswitch local-bias split-horizon, the remaining ADR-0063 runtime
    mixed-edit tail, true shared-VNI / non-zero Ethernet Tag service,
    managed netdev ergonomics, and demand-shaped route types 6-11, PBB-EVPN,
    multicast EVPN, MPLS/SRv6 service
    encapsulation, and VPWS/E-Tree remain demand-shaped service-provider
    breadth, not part of the current VXLAN/Linux alpha lane. See
    [evpn-enablement.md](evpn-enablement.md) for the full gate ladder.
[^evpn-bird]: BIRD [3.3.2](https://bird.nic.cz/doc/bird-3.3.2.html) describes
    its EVPN protocol as "a preliminary release limited to basic handling of
    MAC and IMET EVPN routes"; the same manual lists EAD and ES routes as
    "Currently not used by BIRD" and documents no IP Prefix (Type 5) route.
    This claim is limited to that release.
[^evpn-openbgpd]: OpenBGPD
    [8.8](https://marc.info/?l=openbsd-announce&m=173887198302373) announced
    "Preliminary support for EVPN in the RIB", and the
    [OpenBSD-current `bgpd.conf(5)`](https://man.openbsd.org/bgpd.conf)
    documents `announce EVPN [enforce]` per neighbor. The pinned 9.2 release
    postdates 8.8; the announcement scopes the support to the RIB.

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

[^gobgp-extmsg]: GoBGP upstream support was added in the exact `v4.7.0` tag
    and is retained in the exact `v4.9.0` tagged
    [capability definitions](https://github.com/osrg/gobgp/blob/v4.9.0/pkg/packet/bgp/bgp.go#L410-L424),
    verified 2026-09-01. This records upstream support, not a rustbgpd/GoBGP
    interoperability receipt.

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
    [v4.9.0 policy documentation](https://github.com/osrg/gobgp/blob/v4.9.0/docs/sources/policy.md#L886-L899)
    says unmatched import and export policy defaults to `accept-route`.
[^rfc8212-openbgpd]: The
    [OpenBSD-current `bgpd.conf(5)` filter documentation](https://man.openbsd.org/bgpd.conf#FILTER)
    says BGP UPDATEs are blocked by default and the default filter action is
    deny.

## Security

| Feature | rustbgpd | FRR | BIRD | GoBGP | OpenBGPd |
|---|:---:|:---:|:---:|:---:|:---:|
| TCP MD5 (RFC 2385) | Yes | Yes | Yes | Yes | Yes |
| TCP-AO (RFC 5925) | Static + dynamic-prefix keyrings; observation-gated live rotation; deprecated/unselected-key deletion on SIGHUP | No | Yes | Yes[^tcpao-gobgp] | No |
| GTSM / TTL Security | Configurable hops[^gtsm-distance] | Yes | Yes | Yes | Yes |
| eBGP multihop enablement | None needed[^multihop-rustbgpd] | Required[^multihop-frr] | Required[^multihop-bird] | Configurable[^multihop-gobgp] | Required[^multihop-openbgpd] |
| RPKI origin validation | Yes | Yes | Yes | Yes | Yes |
| ASPA path verification | Yes[^aspa] | No | Yes | No | Yes |
| Private AS removal | Yes | Yes | Yes | Yes | Yes |
| Privilege separation | No | No | No | No | Yes |
| Memory-safe language | Yes | No | No | Yes | No |

CVE-2026-49943, a stack-based buffer overflow in BIRD's AS-path filter
matching reachable when RFC 8654 extended messages are enabled (affected
through 2.19.0), is a recent example of the vulnerability class the
memory-safe-language row refers to.

[^gtsm-distance]: Both GTSM speakers must transmit TTL / Hop Limit 255. On each
    side, a maximum distance of `hops` sets that side's inbound floor to
    `255 - (hops - 1)`, equivalently `256 - hops`. rustbgpd's
    `ttl_security_hops` changes only its receive floor; it cannot make a peer
    transmitting an ordinary lower TTL compatible. Omission preserves the
    exact-255 one-hop policy, while a larger value supports bounded multihop.
    The other implementations
    document equivalent distance-aware forms: FRR
    [`neighbor PEER ttl-security hops NUMBER`](https://docs.frrouting.org/en/latest/bgp.html#clicmd-neighbor-PEER-ttl-security-hops-NUMBER)
    (documented as mutually exclusive with `ebgp-multihop`), BIRD
    [3.3.1](https://bird.nic.cz/doc/bird-3.3.1.html) `ttl security`, where "if
    both ttl security and multihop options are enabled, multihop option should
    specify proper hop value to compute expected TTL", and the
    [OpenBSD-current `bgpd.conf(5)` ttl-security documentation](https://man.openbsd.org/bgpd.conf#ttl-security),
    where "for multihop peers, incoming packets are required to have a TTL of
    256 minus multihop distance". GoBGP
    [v4.9.0](https://github.com/osrg/gobgp/blob/v4.9.0/docs/sources/configuration.md#L166-L171)
    exposes a configurable `ttl-min` but documents TTL security as mutually
    exclusive with `neighbors.ebgp-multihop.config`.

[^multihop-rustbgpd]: rustbgpd has no multihop knob because there is nothing
    to enable: it never lowers the outbound TTL / Hop Limit on a BGP socket and
    has no check refusing an eBGP peer for not being directly connected, so a
    non-adjacent peer is dialed with the kernel default TTL. That default path
    has no distance guard and does not fail fast on an off-subnet address typo.
    There is no separate `ebgp_multihop` path that disables GTSM: enable
    `ttl_security` with `ttl_security_hops` on a peer that also transmits GTSM
    TTL / Hop Limit 255 when the distance should be bounded. This describes the
    mechanism, not an interoperability receipt.
    See [CONFIGURATION.md](CONFIGURATION.md) and
    [LIMITATIONS.md](LIMITATIONS.md).

[^multihop-frr]: [FRR latest](https://docs.frrouting.org/en/latest/bgp.html#clicmd-neighbor-PEER-ebgp-multihop)
    documents `neighbor PEER ebgp-multihop` and states that "when the neighbor
    is not directly connected and this knob is not enabled, the session will
    not establish".

[^multihop-bird]: BIRD [3.3.1](https://bird.nic.cz/doc/bird-3.3.1.html)
    documents `direct` — the neighbor address "must be from a directly
    reachable IP range ... otherwise the BGP session wouldn't start" — as
    "Default: enabled for eBGP", and `multihop [number]` as its alternative
    for "a neighbor that isn't directly connected", where the "optional number
    argument can be used to specify the number of hops (used for TTL)". This
    claim is limited to that release line.

[^multihop-gobgp]: GoBGP
    [v4.9.0 configuration documentation](https://github.com/osrg/gobgp/blob/v4.9.0/docs/sources/configuration.md#L83-L85)
    documents `[neighbors.ebgp-multihop.config]` with `enabled` and
    `multihop-ttl`. The pinned document does not state what happens to a
    non-adjacent peer when the section is omitted, so this cell records the
    knob's existence rather than a requirement.

[^multihop-openbgpd]: The
    [OpenBSD-current `bgpd.conf(5)` multihop documentation](https://man.openbsd.org/bgpd.conf#multihop)
    says neighbors not in the same AS as the local `bgpd(8)` "normally have to
    be directly connected to the local machine", and that when this is not the
    case the `multihop` statement "defines the maximum hops the neighbor may be
    away".

[^tcpao-gobgp]: GoBGP
    [v4.9.0](https://github.com/osrg/gobgp/releases/tag/v4.9.0) (2026-09-01)
    adds a TCP-AO keychain configuration API, keychain management in the
    server, keychain loading from the configuration file, and HMAC-SHA256
    profiles, per its release notes; the implementation is Linux-specific
    with a stub elsewhere (`pkg/server/tcp_ao.go`,
    `internal/pkg/netutils/tcp_ao_linux.go`). Upstream support per release
    notes, not a rustbgpd/GoBGP interoperability receipt.

[^aspa]: rustbgpd ships RTR v2 ASPA input, role-aware upstream/downstream path
    verification selected by BGP Roles, best-path preference, policy matching
    for IPv4/IPv6 unicast, and targeted import-policy refresh when validation
    caches update.

## Monitoring & Observability

| Feature | rustbgpd | FRR | BIRD | GoBGP | OpenBGPd |
|---|:---:|:---:|:---:|:---:|:---:|
| Prometheus metrics | Yes | Via exporter[^prom-frr] | Via exporter[^prom-bird] | Yes | OpenMetrics[^prom-openbgpd] |
| Structured logging (JSON) | Yes | No | No | Yes[^log-gobgp] | No |
| BMP (RFC 7854) | Yes | Yes | Yes | Yes | No |
| BMP full trio (7854 + 8671 Adj-RIB-Out + 9069 Loc-RIB) | Yes | No | No | No | No |
| BMPv4 TLV framing (draft-21; Path Marking awaiting a non-colliding assignment) | Yes | No | No | No | No |
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
| Docker image | Yes | Yes | Yes | Yes | Yes[^docker-openbgpd] |
| Fuzz testing | Yes[^fuzz] | Partial[^fuzz] | No | Yes[^fuzz] | No |
| Interop test suite | Yes[^interop] | Partial[^interop] | No | Yes[^interop] | Partial[^interop] |
| FIB/kernel integration | Partial[^fib] | Yes | Yes | Yes | Yes |
| Route server mode | Yes | Yes[^rs-frr] | Yes | Yes | Yes |
| Dynamic neighbors | Yes | Yes | Yes | Yes | Yes[^dyn-openbgpd] |
| Looking glass | Yes[^lg] | Third-party[^lg] | Third-party[^lg] | Third-party[^lg] | Yes[^lg] |
| BFD integration | Yes[^bfd] | Yes | Yes | Yes | No |

[^docker-openbgpd]: The OpenBGPD project builds an OCI image from
    [openbgpd-portable/openbgpd-container](https://github.com/openbgpd-portable/openbgpd-container)
    and publishes it as
    [`openbgpd/openbgpd`](https://hub.docker.com/r/openbgpd/openbgpd) on
    Docker Hub and Quay; the `9.2` tag was pushed 2026-08-30.

[^lg]: This row records a looking-glass surface the project itself
    ships. rustbgpd's is the in-tree `examples/birdwatcher-adapter`, which
    serves Birdwatcher-shaped endpoints for Alice-LG from the gRPC API
    ([OPERATIONS.md](OPERATIONS.md#looking-glass-birdwatcher-shaped-rest-subset));
    OpenBGPD ships `bgplgd` in its portable tree. FRR, BIRD, and GoBGP
    rely on third-party frontends:
    [Alice-LG](https://github.com/alice-lg/alice-lg) has backends for
    BIRD (birdwatcher), GoBGP (gRPC), and OpenBGPD (`bgplgd` /
    `openbgpd-state-server`), and
    [hyperglass](https://hyperglass.dev/platforms) drives FRR, BIRD, and
    OpenBGPD over SSH.

[^dyn-openbgpd]: Prefix-template neighbors: `neighbor 10.0.0.0/8` in
    bgpd.conf(5) accepts any connection from within the network as a cloned
    neighbor, optionally with any remote AS.

[^rs-frr]: FRR 10.7.0's `route-server-client` preserves
    [NEXT_HOP](https://github.com/FRRouting/frr/blob/frr-10.7.0/bgpd/bgpd.c#L5847-L5858)
    and suppresses the
    [eBGP AS_PATH prepend](https://github.com/FRRouting/frr/blob/frr-10.7.0/bgpd/bgp_attr.c#L5491-L5496),
    but its source has [one RIB array per BGP
    instance](https://github.com/FRRouting/frr/blob/frr-10.7.0/bgpd/bgpd.h#L831-L838)
    rather than the per-client Loc-RIBs still described by the
    [10.7 route-server guide](https://docs.frrouting.org/en/stable-10.7/bgp.html#configuring-frr-as-a-route-server).
    FRR's [per-client RIB removal](https://github.com/FRRouting/frr/commit/2a3d57318)
    moved its path-hiding approach to Add-Path. With client-specific policy,
    operators must account for [RFC 7947 section 2.3 path
    hiding](https://www.rfc-editor.org/rfc/rfc7947.html#section-2.3) and use a
    supported mitigation.

[^bfd]: Single-hop **asynchronous** BFD ships (RFC 5880/5881, ADR-0067): an
    in-process, no-GC actor runs sessions over UDP/3784 (TTL/Hop-Limit 255,
    discard-on-receive if ≠ 255), config via `[[bfd_profiles]]` +
    `[neighbors.bfd]`, observable through `GetBfdSessions` / `rbgp bfd` /
    events + Prometheus. Multihop **asynchronous** BFD (RFC 5883) ships on the
    same actor: `bfd.multihop = true` moves the session to UDP/4784 with a
    fixed transmit TTL 255 and no receive minimum-TTL knob,
    cross-checked against FRR `bfdd` across a two-hop path by interop test
    M108. RFC 5882 BGP coupling ships in both **strict** (withhold
    BGP until BFD Up) and **non-strict** (tear BGP down on BFD-down before the
    hold timer) modes; M51 cross-checks both single-hop coupling modes against
    FRR `bfdd`, while M108 covers multihop non-strict coupling. IPv4, IPv6
    global, and interface-scoped IPv6 link-local static neighbors are
    supported; link-local RX is pinned to the configured interface through
    `IPV6_PKTINFO`, and M51 exercises it against FRR. Deferred: echo / demand
    mode, authentication, C-bit / GR-aware nuance, static-route BFD tracking,
    dynamic-neighbor BFD, and hardware / offload.

[^fuzz]: Every entry in this row means in-tree fuzz targets; the scope
    differs. rustbgpd carries libFuzzer targets in
    `crates/*/fuzz/fuzz_targets` covering the wire decoder along with the
    RPKI, MRT, BFD, EVPN, and policy crates, run nightly by `fuzz.yml`.
    GoBGP `v4.9.0` carries Go-native fuzz targets covering the BGP, BMP,
    MRT, RTR, and ZAPI decoders plus policy community matchers
    (`pkg/packet/*`, `pkg/zebra/`, `internal/pkg/table/`), with run
    instructions in its `CONTRIBUTING.md`; Go fuzz targets replay their
    seed corpus under the ordinary `go test` CI run and extend only under
    an explicit `-fuzz` invocation. FRR documents libFuzzer and AFL targets for the bgpd packet
    parser (and for ospfd, pimd, vrrpd, zebra) in
    [`doc/developer/fuzzing.rst`](https://github.com/FRRouting/frr/blob/frr-10.7.0/doc/developer/fuzzing.rst),
    but keeps the target patches on a separate
    [`fuzz` branch](https://github.com/FRRouting/frr/tree/fuzz) rather than in
    the release tree — at `frr-10.7.0` that tree carries fuzz harnesses only
    for `zlog` and the isisd TLV parser, not for bgpd. BIRD 3.3.1 and
    OpenBGPD 9.1 ship no fuzz targets.

[^interop]: Every entry in this row means a suite that runs the daemon
    against a foreign BGP speaker; the breadth differs. rustbgpd runs
    containerlab topologies in `tests/interop/` against FRR, GoBGP, BIRD,
    ExaBGP, and OpenBGPD, gated on every pull request by `interop.yml`. GoBGP
    `v4.9.0` ships
    [`test/scenario_test/`](https://github.com/osrg/gobgp/tree/v4.9.0/test/scenario_test)
    — docker-driven scenario modules with foreign-daemon drivers in
    [`test/lib/`](https://github.com/osrg/gobgp/tree/v4.9.0/test/lib) (ExaBGP,
    Quagga, YABGP, BIRD, bagpipe) — and its `ci.yml` runs each module as its
    own job on every push and pull request. FRR's `tests/topotests` drives
    bgpd against ExaBGP peers through `exabgp.env` / `exabgp.cfg` fixtures
    in a subset of its `bgp_*` topologies; ExaBGP is the only foreign
    speaker there. OpenBGPD's equivalent is OpenBSD's
    `regress/usr.sbin/bgpd/integrationtests`, which drives ExaBGP through an
    `api-exabgp` helper and is not part of the portable distribution. BIRD
    3.3.1 ships the `birdtest` unit framework only.

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

[^prom-bird]: BIRD has no native Prometheus endpoint; the external
    [`bird_exporter`](https://github.com/czerwonk/bird_exporter) (v1.6.2,
    2026-08-18) reads the BIRD control socket on the same host and serves
    `/metrics` itself, with BIRD 2 and BIRD 3 supported per its README —
    the same treatment as FRR's cell.

[^prom-openbgpd]: `bgpctl show metrics` dumps BGP statistics in
    OpenMetrics text ([bgpctl(8)](https://man.openbsd.org/bgpctl.8)) and the
    `bgplgd` daemon in the portable tree serves a `/metrics` endpoint; both
    arrived in
    [OpenBGPD 7.8](https://www.mail-archive.com/tech@openbsd.org/msg74147.html)
    (2023-03-17). `bgpd` itself has no scrape listener, so a scraper goes
    through `bgplgd` or wraps `bgpctl`.

[^log-gobgp]: `gobgpd` logs JSON by default and `--log-plain` selects the
    text format
    ([`cmd/gobgpd/main.go`](https://github.com/osrg/gobgp/blob/v4.9.0/cmd/gobgpd/main.go#L63)
    at v4.9.0; the same default was already present at v4.8.0).

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

## Performance Snapshot (bgperf2 — 2026-08-30)

The freshest published [v0.68.0 cross-stack
receipt](perf/competitive-bgperf2-v0680-2026-08.md) is an 80-cell,
counterbalanced same-host campaign against fresh pinned builds of BIRD 2.19.2,
FRR 10.7.0, and GoBGP 4.8.0. Values are successful-run medians of
**convergence seconds / total seconds**.

| Scenario | rustbgpd v0.68.0 | BIRD 2.19.2 | FRR 10.7.0 | GoBGP 4.8.0 |
|---|---:|---:|---:|---:|
| 10 peers × 1k prefixes | 2 / 8.25 | 2 / 9.21 | 3 / 10.30 | 4 / 11.36 |
| 2 peers × 10k prefixes | 2 / 8.24 | 2.5 / 9.81 | 3 / 9.33 | 3 / 10.39 |
| 2 peers × 100k prefixes | 3 / 12.45 | 3 / 13.47 | 4 / 13.56 | 4 / 14.59 |
| 30 peers × 1k prefixes | 2.5 / 9.31 | 3 / 9.75 | 4 / 10.91 | 4 / 10.93 |
| 100 peers × 1k prefixes | 3 / 11.95 | 5 / 14.02 | 7 / 16.55 | 16 / 24.78 |

Rustbgpd had the lowest median total time in all five shapes and tied or had the
lowest median convergence time. All 80 cells reached their exact expected
route count. These fixed shapes top out at two peers × 100,000 prefixes; this
is not a full-table campaign, and no CPU or memory ranking is claimed.

## Historical Performance Snapshot (bgperf2 — 2026-07-26)

> **Integrity correction (2026-08-28): Historical July harness output only; no current cross-daemon ranking is supported.** Targets ran in the fixed
> order rustbgpd → BIRD → GoBGP → FRR while one-second samplers from earlier
> cells continued polling during later cells. Only rustbgpd has a retained
> fresh no-cache build receipt; competitor provenance is incomplete, and FRR
> was gcov-instrumented. No ranking, ratio, or sampler-derived correction is
> assigned to these historical rows.

Same host and harness; targets ran back to back after the phase's initial
idle-host admission, with medians of 3 runs per cell (6 at 10×1k).
"Converged" is bgperf2's elapsed-to-full-table figure; memory is peak raw
container cgroup usage over
the run, in MiB. The source is Docker's `memory_stats.usage`, not process-tree
RSS or Docker working set, and may include anonymous, file/cache, kernel, and
socket memory.

| Scenario | rustbgpd | BIRD 2.18 (master) | GoBGP 4.3.0 | FRR 10.7.0-dev |
|---|---|---|---|---|
| 10 peers × 1k prefixes | 2 s / 37.9 | 2 s / 8.2 | 3 s / 38.9 | 3 s / 27.6 |
| 2 peers × 10k prefixes | 2 s / 48.1 | 2 s / 9.2 | 3 s / 44.0 | 3 s / 36.9 |
| 2 peers × 100k prefixes | 3 s / 212.0 | 3 s / 27.6 | 6 s / 202.8 | 4 s / 228.4 |
| 30 peers × 1k prefixes | 3 s / 108.5 | 3 s / 11.3 | 4 s / 68.6 | 4 s / 51.2 |
| 100 peers × 1k prefixes | 3 s / 212.0 | 5 s / 32.8 | 20 s / 193.5 | 7 s / 134.1 |

The raw rows are retained without comparative interpretation. Rustbgpd's own
raw-cgroup values span 86.0 / 108.5 / 131.1 MiB across the three 30-peer runs,
so quote that observation as a range. The campaign's 100 peers × 1k and
2 peers × 100k rustbgpd cells both record 212.0 MiB, but that coincidence does
not isolate a scaling dimension. A controlled rustbgpd-only follow-up varies
peers and BASE routes independently under continuous churn: steady RSS grows
by 118.200/142.844 KiB per peer at fixed 10k/100k BASE routes and
825.515/850.751 B per BASE route at fixed 10/100 peers.
The same follow-up removes a 6,150,300-byte eager RFC 8654 receive-buffer
owner. It makes no RSS claim because the measured −0.324% falls below
its 0.645% floor, and no allocator-total or aggregate-DHAT claim because
continuous churn left different final route totals. A 2026-06-02
independent whole-daemon DHAT profile attributes
the route-heavy shape primarily to the three-layer RIB model
(Adj-RIB-In + Loc-RIB + Adj-RIB-Out) and its route-map / prefix-index
storage. The durable event-history outbox is opt-in
(default off); enabling it adds raw cgroup usage roughly proportional to event
volume. OpenBGPD is absent because a bgperf2 harness defect prevented it
from starting, not because of a daemon result. See
[BENCHMARKS.md](BENCHMARKS.md) for the full cross-stack tables and
[the cross-stack receipt](perf/competitive-bgperf2-2026-07.md) for
per-run values, plus the [controlled attribution
receipt](perf/per-peer-rss-attribution-2026-07.md) for the correction.

At route-server scale, the [IXP receipt
matrix](perf/ixp-matrix-2026-07.md) compares rustbgpd, BIRD 3.3.1, and
OpenBGPD 9.2 head-to-head at 700 peers × 400k prefixes under live churn
— policy-reload stall and completion, member-flap propagation,
convergence, and RSS — with identical wire inputs, config disclosure,
and the losses published alongside the wins. Current rustbgpd
source-equivalent v0.68.0 rows were measured 2026-08-30; BIRD remains dated,
measured 2026-08-08, and the OpenBGPD 9.2 comparator amendment was measured
2026-08-30.

At IRR scale, the [current v0.68.0 receipt](perf/irr-reload-v0680-2026-08.md),
measured 2026-08-30, retains twelve source-equivalent roots at 320 members ×
183,040 generated IPv4 prefixes. rustbgpd completion p50 is 0.852–1.085
seconds across 0%, 10%, and 50% received-view overlap, against BIRD's
11.861–15.211 seconds and OpenBGPD's 42.939–61.959 seconds. Every retained row
has 320/320 sessions and zero parse errors, and each overlap quartet passes the
received-view delta verifier. The older IRR receipts are historical records.

A separate [1,000-peer retained receipt](perf/route-server-1000-2026-07.md),
measured 2026-07-20, exercises a uniform all-eBGP route-server fleet against
the real daemon: 400k routes, 399.6 million observer-NLRI cold deliveries, four
generation-complete export reloads, and continuous readiness/RSS/grouping
checks. It is capacity acceptance for that disclosed same-host shape, not
another competitor result.

The exact v0.61.0 release tip also has an
[absolute baseline](perf/v0.61.0-final-performance-2026-07.md),
measured 2026-07-26: three 1,000-peer × 400-BASE-route real-daemon runs
measured steady process-tree RSS medians of 441.760/441.215/441.131 MiB while
all settled grouping, registration, rejection, and writer gates held. Its
71-row Criterion archive is likewise single-revision. Neither set is a
competitor comparison or a causal delta, and neither rewrites the pinned
`515659b1` campaign above.

## Other Rust implementations

The following three open-source BGP daemons are examples written in Rust,
not an exhaustive inventory. None is a column in the matrix above; each
paragraph records capability, scope, license, and a pinned release from the
project's own release page and README, and makes no interoperability claim.

**zebra-rs** (AGPL-3.0) describes itself as a BGP, OSPF, and IS-IS
routing stack with SRv6, SR-MPLS, L3VPN, and EVPN extensions, configured
through YANG-modeled candidate/running configuration (`zebra-rs/yang/`)
and its own CLI, and shipped as prebuilt Ubuntu `.deb` packages with an
apt channel. Release
[v26.8.5](https://github.com/zebra-rs/zebra-rs/releases/tag/v26.8.5)
(2026-08-28) added RFC 7947 route-server mode
(`neighbor X route-server-client`) and RFC 9234 BGP Roles with
Only-to-Customer;
[v26.8.6](https://github.com/zebra-rs/zebra-rs/releases/tag/v26.8.6)
(2026-08-29) followed a day later, and the project tags releases
several times a month.

**Holo** (MIT) is a routing-protocol suite whose BGP is IPv4 and IPv6
unicast. Its README at
[v0.9.0](https://github.com/holo-routing/holo/blob/v0.9.0/README.md)
(2026-02-21) lists RFC 4271, RFC 4760 and RFC 2545, standard and large
communities, RFC 6793, RFC 7606, RFC 8212, and RFC 9774 for BGP, and
lists no route reflection (RFC 4456), graceful restart (RFC 4724),
Add-Path (RFC 7911), RPKI (RFC 6811 / RFC 8210), or BMP (RFC 7854).

**RustyBGP** (Apache-2.0) is the osrg project's Rust daemon. Its README
at [v0.2.0](https://github.com/osrg/rustybgp/blob/v0.2.0/README.md)
(2026-06-30) states that it supports most of GoBGP's features with the
same gRPC API and configuration file format, so `rustybgpd` reads a
`gobgpd.conf` and is managed with the `gobgp` CLI; the README lists
route reflector, route server, Add-Path, graceful restart, RPKI, BFD,
BMP, and MRT among its features.

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
programmatic API beyond the CLI socket. Its own release announcements
report an Adj-RIB-Out rewrite in
[9.0](https://marc.info/?l=openbsd-announce&m=176710395831597&w=2)
(2025-12-30) for which "a reduction in memory usage of more than 50%
should be feasible" on large IXP route servers, and filter changes in
[9.1](https://undeadly.org/cgi?action=article;sid=20260414025522)
(2026-04-13) that "reduce the initial sync duration of large route
servers by more than 25%"; those are upstream's figures, not
measurements from this project.

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
policy-reload completion (p50 1.3–1.6 s at the v0.64.0 refresh, vs 64–85 s
for BIRD 3.3.1 and 201–206 s for OpenBGPD 9.2 on the same host and wire
inputs), with per-daemon wins and losses — including OpenBGPD's smaller raw
stall and its repeated-reconnect IdleHold pacing — published in the receipt.

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
BIRD 2/3 / FRR / GoBGP structural importer that translates the mechanical
subset (AS, router-id, neighbors, peer groups, families, timers,
max-prefix) and fail-stops with a line-numbered report of every policy
construct left for hand-translation to `.rpol`.
