# Current Limitations

rustbgpd is a public alpha. It is suitable for lab, data-center fabric pilots,
IX route-server pilots, and programmable control-plane deployments where the
operator is comfortable with an evolving config and gRPC API.

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
  selectable non-default/Flex SPF is implemented.
- Confederations are not implemented.

## EVPN

EVPN is Linux / VXLAN-only and remains alpha.

Shipped and interop-tested:

- Route-reflector mode for EVPN route types 1-5.
- Bidirectional single-homed L2VNI VTEP: remote-MAC FDB programming, local
  MAC-only / MAC+IP / SVI Type 2 origination, Type 3 IMET, and push-notified
  sub-second convergence.
- Symmetric Interface-less IRB / Type 5 with transactional L3 FIB programming.
- Active-active multi-homing building blocks: DF election, Type 1/4, BUM
  suppression, aliasing ECMP via FDB nexthop groups, and all-active Type 5
  receive.
- Duplicate-MAC detection with quarantine and manual clear.
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
  ASIC/offload-dependent limitation of the Linux softswitch path.
- Route types 6-11, PBB-EVPN, multicast EVPN, MPLS/SRv6 encapsulation,
  VPWS, and E-Tree are demand-shaped rather than part of the current
  VXLAN/Linux lane.

See [`docs/evpn-enablement.md`](evpn-enablement.md) and the EVPN ADRs for the
full gate ladder.

## Transport and session features

- TCP-AO supports static-neighbor and direct dynamic-prefix startup keys on
  Linux. Runtime key rotation and multi-key rollover remain follow-up work.
- TCP MD5 and GTSM are supported.
- BFD supports IPv4/IPv6 global-address single-hop asynchronous sessions for
  static neighbors. Multihop, echo, demand mode, authentication,
  dynamic-neighbor BFD, and IPv6 link-local BFD remain follow-up work.
- BGP unnumbered supports static IPv6 link-local neighbors for IPv4 unicast.
  Interface-neighbor autodiscovery and capability 77 remain follow-up work.

## Operational proof

Published benchmarks and receipts cover the main protocol, interop, scale, and
memory surfaces. Multi-day soak automation beyond the archived harnesses remains
future work.

See:

- [`docs/OPERATIONAL_PROOF.md`](OPERATIONAL_PROOF.md)
- [`docs/RECEIPTS.md`](RECEIPTS.md)
- [`docs/BENCHMARKS.md`](BENCHMARKS.md)
