# Current Limitations

> **Document class: REFERENCE.**

Check support boundaries before choosing a deployment role.

rustbgpd is a public alpha. It is suitable for lab, data-center fabric pilots,
IX route-server pilots, and programmable control-plane deployments where the
operator is comfortable with an evolving config and gRPC API.

The exception is the deliberately narrow, machine-inventoried
[v1 route-server / route-reflector contract](v1-stable-contract.md). That
promise applies only to the listed IPv4/IPv6 unicast RS/RR and scoped RR-only
surfaces; it does not promote the rest of the project out of alpha.

## Routing role

- Linux FIB integration is opt-in and scoped. RFC 7999 BLACKHOLE discard routes
  and configured `[[fib_tables]]` unicast route installation are available, with
  per-peer / peer-group allow-lists and per-table route-count caps. ECMP,
  per-class ECMP caps, `multipath_relax`, and Link Bandwidth weighted multipath
  are opt-in. Full router parity still needs broader redistribution policy and
  non-BGP route-manager scope.
- VPNv4 / VPNv6 support is route-reflector / controller-feed only. VRF import,
  MPLS label forwarding, and CE-facing attachment are out of scope.
- BGP-LS support is receive, reflection, API export, and ORR topology input.
  rustbgpd does not synthesize local BGP-LS objects. ORR computes only the
  RFC 9552 default topology: non-default MT-ID and malformed topology inputs
  are excluded fail-closed, while Flex-Algorithm data is ignored and no
  selectable non-default/Flex SPF is implemented. The BGP-LS trust boundary
  is per-scope, not per-peer: ORR unions BGP-LS Adj-RIB-In across all peers
  into one default topology, so any negotiated BGP-LS speaker can inject
  well-formed default-topology nodes or links that shift another ORR client's
  best-path selection. This is inherent to the RFC 9107 union model — the
  MT/Flex isolation above scopes topology inputs, not speakers.
- Confederations are not implemented.
- RFC 5004 (prefer the existing external best path) is not implemented. Path
  selection is deterministic: below the eBGP-over-iBGP step, ties are broken
  by the lowest effective BGP Identifier, then the shorter CLUSTER_LIST, then
  the lowest peer address, so a newly learned external path that ties the
  current best down to the identifier and carries the lower identifier
  replaces it. BIRD and OpenBGPD default to the same behavior. If an operator
  asks, the change would take the shape of an opt-in preference for the
  existing external path; see the RFC 4271 §9.1.2.2 notes in
  [`docs/reference/rfc-notes.md`](rfc-notes.md).
- Transparent route-server export preserves the accepted route's next hop.
  Operators can opt into fail-closed pre-policy ownership validation with
  `next_hop_ownership = "strict_peer"`, which accepts unicast announcements
  only when the complete wire next-hop identity is the advertising session's
  own address. Same-AS alternate next hops and explicit authorization remain
  deferred; see [ADR-0107](../adr/0107-route-server-next-hop-ownership.md).
  SLAT-driven translation for mixed RFC 8950 client fleets is not implemented;
  [ADR-0128](../adr/0128-route-server-next-hop-translation.md) keeps it
  demand-gated. Implementation requires either working-group adoption or named
  IXP demand, plus a real SLAT producer and retained fixtures. A uniform IPv6
  fleet needs no translation: `rs-config-render` renders an arouteserver
  `rfc8950` IPv6 session as a dual-family session with `strict_peer`, and
  refuses the shape as soon as an IPv4-session member is present.

## EVPN

EVPN is Linux / VXLAN-only and remains alpha.

Shipped and interop-tested:

- Route-reflector mode for EVPN route types 1-5.
- Bidirectional single-homed L2VNI VTEP: remote-MAC FDB programming, local
  MAC-only / MAC+IP / SVI Type 2 origination, Type 3 IMET, and push-notified
  sub-second convergence.
- Symmetric Interface-less IRB / Type 5 with transactional L3 FIB programming.
- IPv6 VXLAN underlay: IPv6 VTEP addresses, IPv6 BGP transport, 16-octet EVPN
  next hops, and remote-VTEP FDB rows with an IPv6 `dst`.
- Active-active multi-homing building blocks: DF election, Type 1/4, BUM
  suppression, aliasing ECMP via FDB nexthop groups, and all-active Type 5
  receive.
- Duplicate-MAC detection with quarantine, bounded key-only status listing,
  and manual clear. The listing intentionally exposes no detector clocks or
  recovery durations and caps each atomic snapshot response at 4096 rows.
- Controller injection for EVPN route types 2, 3, and 5.
- VNI-per-broadcast-domain VLAN-aware bridge support, including SVD /
  collect-metadata VXLAN detection and programming.
- Opt-in managed bridge, fixed-VNI VXLAN, SVD / collect-metadata VXLAN, VLAN
  upper, VRF, and fixed-VNI L3VXLAN lifecycle under `[managed_netdevs]`.
- Non-zero Ethernet Tag VLAN-aware-bundle receive/reflect in RR mode.

Known EVPN gaps:

- L3VNI/device/table IP-VRF identity changes remain restart-required by design.
  Other decomposable EVPN runtime edits commit live in ordered primitive steps;
  unsupported dependency cycles fail closed before commit, and residual
  mid-sequence convergence failures fail-stop on the last committed generation.
- True RFC VLAN-aware bundle VTEP origination and dataplane for non-zero
  Ethernet Tag remains future work; RR receive/reflect is implemented.
- VXLAN local-bias split-horizon for all-active shared segments remains an
  ASIC/offload-dependent limitation of the Linux softswitch path. RFC 9746
  §2.2 makes local bias the only split-horizon mechanism for VXLAN (the ESI
  Label Split Horizon Type MUST be 00 for tunnel type 8), so there is no
  ESI-label alternative to implement for this lane.
- Symmetric Interface-less IRB does not implement `RTA_VIA`, so a Type 5
  prefix and its next hop must be the same address family. Under an IPv6
  VTEP only IPv6 tenant prefixes are carried: an IPv4 prefix is refused at
  origination and dropped at import rather than installed against a
  cross-family gateway. The same constraint applies with the families
  reversed. An IPv6 VXLAN underlay is otherwise supported for the L2 path
  and for same-family symmetric IRB. The receipts covering it are
  single-homed, so a multi-homed IPv6 underlay is untested rather than
  known unsupported.
- Route types 6-11, PBB-EVPN, multicast EVPN, MPLS/SRv6 encapsulation,
  VPWS, and E-Tree are demand-shaped rather than part of the current
  VXLAN/Linux lane.

See [`docs/project/evpn-enablement.md`](../project/evpn-enablement.md) and the EVPN ADRs for the
full gate ladder.

## Transport and session features

- TCP-AO supports ordered static-neighbor and direct dynamic-prefix keyrings on
  Linux. SIGHUP can append a non-preferred successor, later select it and
  observation-gate predecessor deprecation, and later delete deprecated MKTs
  that are neither Current nor RNext. Key edits/reordering, selected or
  non-deprecated-key deletion, and protected-owner CRUD require a daemon restart.
- TCP MD5 and GTSM are supported.
- BFD supports IPv4, IPv6 global, and interface-scoped IPv6 link-local
  single-hop asynchronous sessions, and IPv4 / IPv6 global multihop (RFC 5883)
  asynchronous sessions, for static neighbors. Multihop sessions apply no
  receive TTL bound (RFC 5883 leaves a GTSM-style check optional; none is
  configurable) and cannot target an IPv6 link-local neighbor. Echo, demand
  mode, authentication, and dynamic-neighbor BFD remain follow-up work. BGP
  sessions to non-adjacent peers require no separate enablement and can be
  distance-bounded with `ttl_security_hops`.
- BGP unnumbered supports static IPv6 link-local neighbors for IPv4 unicast.
  Interface-neighbor autodiscovery and capability 77 remain follow-up work.

## Configuration control

- The peer-manager private command lane and config-bridge replacement lane are
  lossless capacity-one FIFO channels. A planning, apply, rollback, or reload
  operation already using one of these lanes serializes later control work;
  callers wait instead of commands being dropped or an unbounded queue growing.
  Under a slow configuration operation this can increase concurrent management
  request latency even though routing-session work continues on its own actor
  paths.

## Operational proof

Published benchmarks and receipts cover the main protocol, interop, scale, and
memory surfaces. Multi-day soak automation beyond the archived harnesses remains
future work.

See:

- [`docs/operational-proof.md`](../operational-proof.md)
- [`docs/receipts.md`](../receipts.md)
- [`docs/benchmarks.md`](../benchmarks.md)
