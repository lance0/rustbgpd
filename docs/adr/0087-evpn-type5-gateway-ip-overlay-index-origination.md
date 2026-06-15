# ADR-0087: Native GW-IP overlay-index Type 5 origination (RFC 9136)

**Status:** Accepted
**Date:** 2026-06-12

## Context

rustbgpd's Type 5 (IP Prefix, RFC 9136) story is asymmetric. The
receive side of the GW-IP overlay index is complete and shipped:
`project_ip_prefix_routes_with_overlay_index`
(`crates/evpn/src/ip_vrf/projection.rs`) recursively resolves a
non-zero Gateway Address through Type 2 MAC/IP routes in the matched
IP-VRF's linked L2VNIs, with explicit fail-closed drop signals
(`UnresolvedOverlayIndexGateway`, `AmbiguousOverlayIndexGateway`,
`OverlayIndexNoLinkedL2Vni`) and a MAC-mobility tie-break. The
controller-injection path (`AddEvpnRoute`,
`crates/api/src/injection_service.rs::parse_type5_gateway`) accepts
non-zero gateways. But native origination —
`crates/evpn/src/ip_vrf/origination.rs` fed by the kernel-route
observation loop in `src/evpn_l3_originator.rs` — is interface-less
only: the gateway is hardcoded to `0.0.0.0`/`::` and every route
carries the Router's MAC extended community per ADR-0058 §2.

The GW-IP overlay index is exactly RFC 9136 §4.1/§4.2's use case for
a tenant route whose next hop is an overlay host — a virtual
appliance, a floating gateway IP, a service-chained router living on
an L2VNI-bridged segment. With the interface-less shape, traffic for
such a prefix lands on *this* VTEP and takes a second hop across the
fabric to the appliance's VTEP. With the GW-IP shape, receivers
recursively resolve the gateway through the appliance's own RT-2 and
send traffic directly to wherever the gateway currently lives — and
when the gateway *moves* (VM migration, floating-IP failover), the
RT-2 alone re-converges every RT-5 that points at it. This slice
closes the origination half-gap so the daemon natively originates
what it already consumes.

### Load-bearing code finding: the observation layer drops the via

`LocalIpRouteObservation` (`crates/evpn/src/ip_vrf/observation.rs`)
carries only `{vrf_id, prefix, source}`. The netlink ingest
(`crates/evpn-linux/src/linux/routes.rs::ingest_route_message`)
never reads `RouteAttribute::Gateway` — a sibling helper exists in
`linux/l3_adoption.rs::extract_gateway` for the ADR-0079 adoption
walk, with a comment explicitly noting the observation path "never
needs the gateway". The gateway therefore cannot come from existing
plumbing; extending the observation record is in scope for this
slice (Decision 1).

### RFC 9136 ground truth (verified against the RFC text)

- §3.1: "The GW IP field MUST be all bytes zero if it is not used
  as an Overlay Index."
- §3.2: ESI and GW IP "MUST NOT both be non-zero at the same time"
  (a route violating this is treat-as-withdraw). GW-IP mode
  therefore requires ESI zero.
- §3.2: "If the GW IP is the Overlay Index (hence, ESI is zero), the
  EVPN Router's MAC Extended Community is ignored if present."
- §3.2: recursive resolution requires the receiver to have installed
  an RT-2 whose IP Address field matches the GW IP — the companion
  RT-2 requirement.
- §3.1: "the label value SHOULD be zero if a recursive resolution
  based on an Overlay Index is used" — a SHOULD we deliberately
  deviate from (Decision 4).

## Decision

### 1. Gateway source: the kernel route's via, gated on containment in a connected subnet of the same IP-VRF

The natural source for the Gateway Address is the kernel route's
`RTA_GATEWAY` (the `via` in `ip route add <prefix> via <gw> vrf …`).
A tenant route via an overlay router/floating IP is precisely the
RFC 9136 GW-IP use case, and the via is operator intent already
expressed in the dataplane — no second config surface needed per
prefix.

The observation layer is extended to carry it:
`LocalIpRouteObservation` gains `via: Option<IpAddr>`, populated from
the first `RouteAttribute::Gateway` (the existing `extract_gateway`
helper moves from the adoption walk into `linux/routes.rs` and is
shared). Multipath routes (`RTA_MULTIPATH`) carry no top-level
gateway attribute and observe as `via: None`; cross-family vias
(`RTA_VIA`, e.g. IPv4-over-IPv6-nexthop) are not representable in the
RT-5 Gateway field (same-family as the prefix by wire construction)
and also observe as `None`.

A via becomes the Gateway Address only when **all** hold:

1. The IP-VRF opted in (`overlay_index_mode = "gateway_ip"`,
   Decision 3).
2. The via's family matches the prefix's family (wire constraint).
3. The via is contained in a **connected subnet of the same IP-VRF**
   — a `RouteSource::Connected` (RTPROT_KERNEL) observation in the
   same reconcile snapshot with prefix length > 0 — and, for IPv4,
   is a usable host address in that subnet. Ordinary IPv4 subnet
   network and directed-broadcast addresses are not eligible
   gateways; `/31` point-to-point endpoints (RFC 3021) and `/32` host
   routes are eligible.

Rationale for (3): a remote PE can only resolve the GW IP through an
RT-2, and an RT-2 for that IP can only exist if the gateway host
lives on a bridged tenant segment. A via outside every connected
subnet of the VRF (e.g. a leaked or underlay-recursive nexthop) is
not a directly attached overlay host, so no RT-2 will ever name it —
advertising it as a GW IP would strand the route at every receiver
(`unresolved_overlay_index_gateway`). Containment in a connected
subnet is the strongest tenant-subnet signal available without
binding the daemon to kernel interface identity. We considered the
tighter check "connected subnet whose output device is a linked
L2VNI's bridge" and rejected it for this slice: SVI arrangements vary
(bridge-self IP vs. separate SVI device), the daemon's observation
record does not carry per-subnet device identity today, and the
failure direction of the looser check is benign — a wrongly-GW-IP'd
route degrades to held-unresolved at receivers with an explicit drop
signal, while the fallback direction (interface-less) always
forwards correctly. The /0 exclusion keeps a (pathological) connected
default route from whitelisting every via; the IPv4 usable-host check
keeps a subnet's network or directed-broadcast address from becoming
an overlay-index gateway that cannot have a companion host RT-2.

Routes that fail any gate — no via (connected/direct routes), wrong
family, off-subnet via, non-usable IPv4 endpoint, or mode off —
originate **interface-less**, exactly as today. Fallback is safe by
construction: an interface-less RT-5 with the Router's MAC extcomm
attracts traffic to this VTEP, whose kernel FIB holds the original
via and completes delivery; only the one-fabric-hop indirection
optimization is lost.

### 2. Companion RT-2: depend on it, do not duplicate it, do not gate on it

RFC 9136 §3.2 requires receivers to resolve the GW IP through an
installed RT-2. When the gateway host is local to this VTEP, the
existing local MAC/IP origination (FDB + neighbor learning,
ADR-0055) already produces that RT-2; when it lives behind another
PE, that PE's RT-2 does. This slice produces **no** new RT-2 — the
design dependency is stated, not re-implemented.

Origination is **not gated** on the RT-2 existing (locally or in the
RIB). We originate the RT-5 immediately and let receivers hold it
unresolved until the RT-2 arrives, for three reasons:

- **Convergence symmetry.** The receive side is level-triggered and
  re-projects on every RIB pass: the RT-5 resolves the instant the
  RT-2 lands, regardless of arrival order. Gating origination would
  re-create the same ordering problem on the send side, with a
  withdraw/re-announce churn cycle every time the RT-2 flaps.
- **Observability.** The unresolved state is not silent — receivers
  (ours and FRR's) surface it (`unresolved_overlay_index_gateway`
  drop counter here), which is strictly better diagnostics than a
  route that never appears.
- **Coupling.** Gating would couple the L3 originator to the L2
  originator's mobility state machine across actor boundaries for no
  forwarding-correctness gain — an unresolved overlay-index route
  installs nothing, so there is no blackhole window either way.

### 3. Config surface: per-IP-VRF `overlay_index_mode`, default `interface_less`

`[[evpn_ip_vrfs]]` gains:

```toml
overlay_index_mode = "interface_less"   # default; or "gateway_ip"
```

- `interface_less` (default): today's behavior, bit-for-bit. Zero
  behavior change unless opted in.
- `gateway_ip`: enables Decision 1's via-to-gateway selection for
  routes observed in this VRF.

Validation at config load rejects `gateway_ip` on an IP-VRF with no
linked L2VNI (no `[[evpn_instances]].ip_vrf` reference): the receive
side requires the L2VNI link to scope the RT-2 recursion
(`OverlayIndexNoLinkedL2Vni` is a hard drop), so a gateway_ip VRF
without one could never produce a resolvable route — fail at load,
not on the wire. The mode rides the existing `[[evpn_ip_vrfs]]`
lifecycle: restart-required under SIGHUP, live-committable through
`ApplyEvpnRuntime` redefine (the mode is part of `IpVrf` equality, so
a mode flip drains and re-originates the VRF's routes through the
existing `drain_changed_ip_vrfs` path).

### 4. Wire shape in GW-IP mode

A GW-IP-mode RT-5 (via passed all gates) carries:

- `gateway` = the via (non-zero, same family as the prefix).
- `esi` = zero (RFC 9136 §3.2: at most one overlay index;
  unchanged from today).
- `ethernet_tag` = zero (unchanged).
- `label` = the IP-VRF's **L3VNI — deliberately not zero**, deviating
  from the §3.1 SHOULD. Two grounds: (a) our own shipped receive side
  enforces `route.l3vni == vrf.id.as_u32()` for *every* RT-5 before
  overlay resolution runs (`L3VniMismatch` drop,
  `crates/evpn/src/ip_vrf/projection.rs`) — a zero label would make
  rustbgpd's own origination unconsumable by rustbgpd, and the
  controller-injection path already injects overlay-index routes with
  the L3VNI; (b) FRR's `advertise ipv4 unicast gateway-ip` RT-5s
  likewise keep the VNI in the label (observed in FRR issue #15844
  packet decodes: `IPv4 Gateway address` + `VNI: 1000` together).
  SHOULD permits this with reason; fabric-wide consistency with our
  receiver and FRR is the reason.
- Extended communities: route targets + BGP Encapsulation (VXLAN)
  as today, **no Router's MAC extcomm**. RFC 9136 §3.2 makes the
  RMAC ignored-if-present when GW IP is the overlay index — the
  inner MAC comes from the resolved RT-2 — and omitting it keeps the
  route's semantics unambiguous (a receiver can't mistake it for an
  interface-less route with a stray gateway). Our own projection
  ignores `router_mac` on the overlay path, so this is
  self-consistent; FRR attaches its VRF RMAC to all RT-5s but must
  ignore it on receipt per the RFC, so interop is unaffected.
- `NEXT_HOP` = `local_vtep_ip` (unchanged) — the gateway field, not
  the next hop, carries the recursion target.

Interface-less routes (fallback or mode off) are byte-identical to
today's output.

### 5. Reconcile semantics: via changes re-originate in place

`EvpnRouteKey::IpPrefix` is `{rd, ethernet_tag, prefix}` — correctly,
per RFC 7432/9136 route identity, the gateway is *not* part of the
key. The originator's reconcile loop previously skipped re-injection
when the desired key matched the originated key, which would swallow
a via change (same prefix, new gateway → same key). The originated
map now tracks the gateway alongside the key; a same-key
gateway-payload change re-injects **in place** (the RIB's
`insert_evpn` replaces on key and re-distributes) without an
intermediate withdraw, so peers see a single UPDATE rather than a
withdraw/announce pulse. Via appearing/disappearing and a via
drifting on/off the connected subnet are the same case: the selected
gateway changes (possibly to zero/fallback), and the level-triggered
pass re-injects. Key changes (VRF redefine) keep the existing
withdraw-then-inject path.

### 6. ESI overlay-index follow-up

The RFC 9136 §4.3 ESI overlay-index origination follow-up is now
implemented as the second explicit `overlay_index_mode`:
`overlay_index_mode = "esi"`. It preserves the default
`"interface_less"` behavior and the shipped `"gateway_ip"` path, but
originates Type 5 routes with:

- `esi` = the configured non-zero `overlay_index_esi`;
- `gateway` = zero, so the route carries exactly one overlay index;
- `label` = the IP-VRF's L3VNI, matching the GW-IP decision above;
- Router MAC extcomm = configured `overlay_index_mac`, naming the
  virtual appliance / transit-switch MAC rather than the PE/NVE
  `router_mac`.

Config validation is deliberately fail-closed: the ESI must name a
configured `[[ethernet_segments]]` entry, the IP-VRF must have at
least one linked L2VNI, multiple linked L2VNIs require
`overlay_index_l2vni`, and the selected L2VNI must be a member of
the selected ESI. The pure origination and daemon-originator tests pin
the wire shape. Receive-side ESI protected recursion and a real-peer
interop proof are still separate standards-tail follow-ups. The
receive-side projection DTO carries Type 5 ESI now, but non-zero-ESI
RT-5s are dropped fail-closed until the EAD protected-recursion
dependency exists. That dependency is deliberately more than "look up
an ESI in the existing alias index": receive-side recursion must carry
L2VNI/MAC-VRF scope on EAD-per-EVI resolver rows, preserve the Type-5
Ethernet Tag in the projection DTO, and decide whether the first
shipping receiver supports all-active L3 multipath/NHG resolution or a
documented single-active-only subset.

### 7. Out of scope / follow-ups

- **Additional protected-recursion interop breadth** — M68 proves FRR
  (with `enable-resolve-overlay-index`) consumes a rustbgpd-originated
  GW-IP RT-5, holds it unresolved until the companion RT-2 appears,
  then imports it through the Gateway Address. Broader protected
  recursion-path smokes can land later without changing this ADR's
  default `"interface_less"` posture.
- **ESI receive-side protected recursion** — originated ESI RT-5s are
  standards-shaped, but rustbgpd's receive-side Type 5 projection still
  imports only interface-less and GW-IP recursion. Non-zero-ESI Type 5s
  are carried far enough to drop with `unsupported_esi_overlay_index`;
  resolve them through scoped EAD-per-EVI state before claiming
  receive-side ESI recursion. The intended sequence is: extend the
  EAD-per-EVI projection input with L2VNI/MAC-VRF identity, carry the
  Type-5 Ethernet Tag into `ProjectedIpPrefixRoute`, then choose either
  all-active L3 multipath/NHG support or a single-active-only v1 before
  adding an M-series real-peer proof.
- **gRPC `IpVrfState` surface** — `ListIpVrfs`/`GetIpVrf` do not yet
  report the mode; add when an operator asks.
- **Tighter subnet attribution** (linked-L2VNI-bridge-scoped
  containment, Decision 1) — revisit if the benign-fallback argument
  stops holding in practice.

## Consequences

- Operators get native GW-IP origination with one config line and
  their existing `ip route … via …` intent; nothing changes for
  existing deployments (default `interface_less`, byte-identical
  wire output).
- The observation record grows by an `Option<IpAddr>`; every
  reconcile pass now also derives a per-VRF connected-subnet set
  (small, already-in-hand data — no extra netlink walks).
- A via change converges as a single in-place UPDATE; receivers
  re-resolve without route identity churn.
- ESI overlay-index origination adds three optional IP-VRF config
  fields (`overlay_index_esi`, `overlay_index_mac`, and
  `overlay_index_l2vni`) that are rejected unless
  `overlay_index_mode = "esi"` and the selected ESI/L2VNI are
  configured consistently.
- The label deviation from §3.1's SHOULD is pinned here; if a future
  peer rejects non-zero labels on overlay-index routes, this ADR is
  the decision to revisit.
