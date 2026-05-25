# ADR-0069: BGP unnumbered and IPv6 link-local peering

**Status:** Accepted
**Date:** 2026-05-25

## Context

rustbgpd now targets cloud and whitebox data-center fabrics in addition to IX
route-server deployments. In those fabrics, BGP unnumbered is a high-signal
feature: operators run point-to-point fabric links without IPv4 addresses,
establish BGP over IPv6 link-local transport, and carry IPv4 unicast NLRI with
IPv6 next-hops.

This is a standard FRR / Cumulus operating model. FRR exposes interface peers
with `neighbor IFACE interface [v6only] ...`, and Cumulus documents BGP
unnumbered as the model for exchanging IPv4 prefixes without numbered IPv4
peer-facing links. RFC 8950 provides the standards base for IPv4 unicast NLRI
with an IPv6 next-hop. RFC 4007 is the load-bearing scope rule: a link-local
address is not globally unique, so a bare `fe80::1` is not a peer identity on a
router with multiple links.

rustbgpd already has part of the protocol foundation:

- ADR-0037 implements RFC 8950 Extended Next Hop for IPv4 unicast over IPv6
  next-hop.
- ADR-0066 / ADR-0068 provide the unicast Linux FIB and ECMP/weighted
  multipath surfaces that make fabric forwarding useful.
- ADR-0067 explicitly deferred IPv6 link-local BFD because the daemon could not
  yet express a neighbor interface/scope.

The remaining gap is therefore not just "allow `fe80::/10` neighbors". BGP
unnumbered crosses three boundaries:

- transport: active and passive TCP sessions must preserve IPv6 scope/interface;
- BGP semantics: IPv4 NLRI over IPv6 next-hop must be gated by negotiated RFC
  8950 Extended Next Hop;
- FIB: IPv4 routes learned with IPv6 link-local next-hops need the correct
  output interface when installed into Linux.

## Decision

Implement BGP unnumbered first as **static, interface-bound IPv6 link-local
neighbors**. The operator supplies both the remote link-local address and the
local interface. FRR-style interface-only autodiscovery is deferred.

Example v1 configuration:

```toml
[[neighbors]]
address = "fe80::5054:ff:fe00:1"
interface = "eth1"
remote_as = 65101
address_families = ["ipv4_unicast"]
```

### Scoped peer identity

Link-local peers are identified by address plus interface/scope, not by bare
`IpAddr`. The configured interface is required for any IPv6 link-local neighbor.
The daemon may accept the same link-local address on multiple interfaces, but a
duplicate `(address, interface)` is still a duplicate neighbor.

The scoped identity must be preserved through:

- active open, where outbound connect builds a scoped `SocketAddrV6`;
- passive open, where accepted sessions keep enough socket/interface context to
  match the configured peer;
- TCP collision handling and `PeerManager` ownership;
- status, gRPC, CLI, events, and logs.

Human-facing surfaces should render the peer as `fe80::x%ifname` where useful,
but structured APIs should keep address and interface as separate fields so
callers do not need to parse zone strings.

### Next-hop encoding: RFC 8950 gating plus the link-local form

Two distinct, composable mechanisms are in play; do not conflate them.

**RFC 8950 Extended Next Hop (already shipped, ADR-0037)** gates *whether* IPv4
unicast NLRI may carry an IPv6 next-hop, negotiated per the
`(IPv4 unicast -> IPv6 next-hop)` AFI tuple. An unnumbered peer configured for
`ipv4_unicast` must negotiate it; if the peer does not, the `ipv4_unicast`
family **fails closed and surfaces an explicit reason** rather than sending
IPv4-over-IPv6 the peer cannot parse (a fabric misconfiguration is better made
loud than silently degraded).

**The next-hop value itself is link-local** on a true unnumbered link, because no
global IPv6 exists on the fabric interface. RFC 2545 historically defined only a
global next-hop (optionally followed by a link-local), so a *link-local-only*
next-hop was under-specified. The Link-Local Next Hop Capability
(draft-ietf-idr-linklocal-capability, **capability code 77**) standardizes it: a
**16-byte** Next Hop is link-local-only; a **32-byte** Next Hop is
global+link-local; its procedures are defined only when *both* speakers advertise
the capability. FRR and Cumulus have emitted a link-local next-hop as de-facto
behavior for years and are the interop targets here.

**Codec implication.** `crates/wire` already accepts 16- and 32-byte MP_REACH
next-hops, but a 16-byte link-local-only next-hop currently lands in the *primary*
`next_hop` field as an `fe80::` address (the `link_local_next_hop` companion is
populated only for the 32-byte form). The implementation must recognize an
`fe80::/10` next-hop as a **scoped** link-local next-hop and resolve its zone from
the session's bound interface — the wire carries no zone id. Whether to also
advertise capability 77, or whether RFC 8950 plus the existing 32-byte
RFC 2545/8950 handling already interoperates with the target FRR/Cumulus
versions, is a **spike question** (below), not an assumption.

Existing global-IPv6 Extended Next Hop behavior remains unchanged.

### Tranche 3 production behavior

After scoped static peer identity exists, unnumbered IPv4 route exchange follows
these fail-closed rules:

- a scoped IPv6 link-local peer configured for `ipv4_unicast` never imports or
  falls back to IPv4 body NLRI; RFC 8950 `MP_REACH_NLRI` is required;
- inbound IPv4 `MP_REACH_NLRI` with a link-local primary next-hop is accepted
  only when the session is a configured scoped link-local peer and Extended Next
  Hop was negotiated;
- outbound unnumbered IPv4 routes use the FRR-proven 32-byte shape where the
  primary IPv6 next-hop and companion link-local next-hop are both the local
  link-local address;
- accepted link-local primary next-hops carry the configured interface/scope in
  the RIB install-candidate metadata for the later Linux FIB `dev`/OIF slice.

The FIB tranche remains separate: until it lands, forwarding projection still
rejects IPv4 routes whose next-hop family is IPv6.

### FIB install is part of the feature

BGP unnumbered is not complete if the daemon can establish the session and
learn routes but cannot program forwarding. IPv4 routes whose next-hop is IPv6
link-local must carry the egress interface into the FIB projection and install
with an output interface in Linux. If the route lacks the required scope, the
FIB layer must fail closed for that row and surface an explicit unsupported
reason rather than silently installing an unusable route.

Same-family FIB routes and current ECMP behavior must remain unchanged.

### Spike gate before production wiring

Before the production slices land, add a throwaway or protected netns spike that
proves the kernel, socket, and wire primitives:

- **capture the exact MP_REACH next-hop the target FRR/Cumulus version sends for
  IPv4-over-unnumbered** — 16-byte link-local-only vs 32-byte global+link-local —
  and whether it advertises Link-Local Next Hop Capability 77. This is the
  highest-risk unknown: it decides whether RFC 8950 + the existing 32-byte
  handling already interoperates, or whether capability 77 / 16-byte
  link-local-only parsing must be implemented before the production slices;
- scoped TCP connect to `fe80::peer%ifindex`;
- passive accept preserves enough scope/interface information to match the peer
  (prefer the accepted `SocketAddrV6` scope id; if Linux does not expose it
  reliably for wildcard listeners, fall back to per-interface listener binding /
  `SO_BINDTODEVICE` rather than accepting ambiguous link-local inbound sessions);
- IPv6 GTSM / Hop-Limit handling still works for scoped sessions;
- Linux accepts an IPv4 route via IPv6 link-local gateway with `dev`.

If the FIB primitive fails on the supported Linux baseline, this ADR must be
revisited before shipping a control-plane-only feature.

### Spike findings (2026-05-25)

The Tranche 1 proof artifacts pin the Linux primitives and the current FRR
target behavior:

- `crates/evpn-linux/tests/netns_bgp_unnumbered.rs` proves active TCP connect
  to `fe80::peer%ifindex`, passive wildcard accept reporting a non-zero peer
  scope (`scope_id=3` in the two-netns proof), IPv6 TCP Hop-Limit / minimum-hop
  socket options (`IPV6_UNICAST_HOPS=255`, `IPV6_MINHOPCOUNT=254`), and Linux
  IPv4 route install via an IPv6 link-local gateway with `dev`.
- `tests/interop/m53-bgp-unnumbered-spike.clab.yml` proves FRR 10.3.1
  interface peers establish over IPv6 link-local only, with no IPv4 addresses on
  the fabric link, and exchange IPv4 unicast routes whose visible next-hop is
  `fe80::/10`.
- The M53 spike packet capture proves FRR 10.3.1 sends IPv4 MP_REACH over this
  link-local-only session with `nh-length: 32`: the two 16-byte IPv6 next-hop
  segments are both link-local. FRR exposes RFC 8950 Extended Next Hop in
  neighbor state and the packet capture / `vtysh` JSON did **not** expose
  Link-Local Next Hop Capability code 77. For the v1 rustbgpd target this means
  capability 77 is not a prerequisite to interoperate with the pinned FRR
  version; the production slices should support scoped link-local next-hops
  under RFC 8950's extended-next-hop negotiation. Capability 77 remains a
  follow-up unless a newer FRR/Cumulus target advertises or requires it.

### Interop gate

Add an M-series FRR interop smoke after the production slices:

- rustbgpd peers with FRR over IPv6 link-local only;
- no IPv4 addresses exist on the fabric links;
- IPv4 unicast routes are exchanged using RFC 8950 Extended Next Hop;
- rustbgpd status shows address plus interface identity;
- Linux FIB installs the IPv4 route via IPv6 link-local next-hop with the
  correct output interface;
- withdraw/failure collapses forwarding to the surviving path, and recovery
  restores it.

## Consequences

- BGP unnumbered becomes a real fabric feature rather than a control-plane demo:
  peering, route exchange, and forwarding all work together.
- The largest implementation cost is the peer-identity refactor from plain
  `IpAddr` toward a scoped peer key in the paths that need it.
- Existing numbered IPv4/IPv6 peers remain unchanged. Link-local behavior is
  opt-in through the presence of an interface-bound neighbor.
- ADR-0067's IPv6 link-local BFD deferral can be lifted after scoped BGP peers
  exist; BFD can then key sessions by the same scoped peer identity.
- Operator-facing documentation must be clear that v1 supports explicit static
  link-local peers, not interface-neighbor autodiscovery.

## Deferred

- FRR-style `neighbor swp1 interface remote-as external` autodiscovery via
  interface/ND lifecycle.
- IPv6 link-local BFD for unnumbered peers. This follows naturally once scoped
  BGP peer identity exists.
- Link-Local Next Hop Capability (code 77) for the 16-byte link-local-only
  MP_REACH next-hop encoding. Deferred *only* if the spike shows RFC 8950 plus
  the existing 32-byte RFC 2545/8950 handling already interoperates with the
  target FRR/Cumulus versions; if the spike shows those versions advertise
  capability 77 or send the 16-byte link-local-only form, this is promoted into a
  v1 production slice rather than deferred.
- Multihop unnumbered, non-point-to-point links, and policy-driven next-hop
  rewrites that synthesize link-local next-hops without an interface.

## References

- RFC 4007, IPv6 scoped address architecture:
  <https://www.rfc-editor.org/rfc/rfc4007>
- RFC 8950, Extended Next Hop Encoding:
  <https://www.rfc-editor.org/rfc/rfc8950>
- FRR BGP interface peer documentation:
  <https://docs.frrouting.org/en/latest/bgp.html>
- NVIDIA Cumulus Linux BGP documentation:
  <https://docs.nvidia.com/networking-ethernet-software/cumulus-linux-514/Layer-3/Border-Gateway-Protocol-BGP/Optional-BGP-Configuration/>
- Link-Local Next Hop Capability draft (capability code 77; 16-byte
  link-local-only vs 32-byte global+link-local next-hop encoding):
  <https://datatracker.ietf.org/doc/draft-ietf-idr-linklocal-capability/>
- RFC 2545, BGP-4 multiprotocol extensions for IPv6 (next-hop encoding):
  <https://www.rfc-editor.org/rfc/rfc2545>
- ipSpace, "BGP Unnumbered Duct Tape" (operator view of the de-facto behavior):
  <https://blog.ipspace.net/2022/11/bgp-unnumbered-duct-tape/>
- BGP Labs, EBGP sessions over IPv6 LLA interfaces:
  <https://bgplabs.net/basic/d-interface/>
