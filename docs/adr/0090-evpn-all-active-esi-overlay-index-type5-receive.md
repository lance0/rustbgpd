# ADR-0090: All-active ESI overlay-index Type 5 receive

**Status:** Accepted
**Date:** 2026-06-17

## Context

ADR-0087 closed the native GW-IP overlay-index origination gap and then added
the bounded ESI overlay-index tail: rustbgpd can originate non-zero-ESI RT-5
routes and can import the receive-side shape when scoped EAD state yields
exactly one single-active remote VTEP. That is intentionally not the all-active
case. The first all-active implementation now accepts valid two-or-more-member
target sets through the L3 writer; malformed, ambiguous, or single-member
all-active shapes still fail closed with bounded drop reasons.

The remaining work is not just a projection switch. RFC 9136 says an RT-5 with
non-zero ESI and zero Gateway Address uses the ESI as an overlay index, and the
receiver can install it only after recursive resolution through RT-1 EAD-per-EVI
state. RFC 7432's all-active rule then makes the remote PE construct a
next-hop set from the PEs advertising matching EAD-per-ES and EAD-per-EVI state.
For RT-5 in rustbgpd's Linux/VXLAN dataplane, that means a route-level ECMP
next-hop set through one L3VXLAN device plus a shared Router-MAC L3VXLAN FDB
resolution object. A duplicate single-destination FDB row is not sufficient:
LAN-70's real-kernel proof showed that duplicate single-dst FDB rows for one
Router MAC collapse to one destination, while a VRF-table multipath route and an
L3VXLAN FDB nexthop-group both work.

The current production model reflects the single-target assumption:

- `RemoteIpPrefixEntry` carries one `next_hop` and one `router_mac`.
- `L3OwnedState` owns one installed next hop per route and one FDB destination
  per `(ifindex, router_mac)`.
- `l3_diff` treats two rows that need the same Router MAC but different remote
  VTEPs as a conflict and drops them rather than programming a misforwarding
  single-dst FDB row.

Those choices are correct for interface-less, GW-IP, and single-active ESI
receive. All-active receive needs an explicit target-set and ownership contract
before product code changes.

## Decision

### 1. Scope the feature as receive-side all-active protected recursion

This ADR covers receive-side import of RFC 9136 ESI overlay-index RT-5 routes
when the resolving Ethernet Segment is operating in all-active redundancy mode.
It does not change GW-IP overlay-index behavior, ESI overlay-index origination,
or the already-shipped single-active receive path.

The accepted route shape is:

- non-zero ESI;
- zero Gateway Address;
- matching RT/L3VNI for the selected IP-VRF;
- Router MAC extended community present and valid;
- recursive scope through one or more L2VNIs linked to the selected IP-VRF;
- EAD-per-EVI rows matching `(ESI, Ethernet Tag)` and matching all-active
  EAD-per-ES redundancy state.

Routes that fail any of these gates remain fail-closed and counted through the
existing remote-prefix drop surface.

### 2. Preserve the single-active path exactly

The current single-active v1 remains the installable single-target path:
exactly one single-active EAD candidate imports as a single VRF route next hop,
one L3 neighbor row, and one single-dst L3VXLAN FDB row.

Mixed or conflicting redundancy signals do not fall back to single-active. The
strict Type-5 import fold introduced for the single-active receive slice stays:
if one view of a candidate says all-active and another says single-active, the
route is treated as ambiguous and remains fail-closed.

### 3. Project all-active receive as a deterministic target set

The all-active projection result must carry a deterministic set of eligible
remote VTEPs. A target is eligible only when the same snapshot contains:

- matching EAD-per-EVI state for the selected linked L2VNI, ESI, and Ethernet
  Tag; and
- all-active EAD-per-ES state for that ESI and remote VTEP.

The route ECMP target set and the FDB-NHG target set are the same set. Sorting
and deduplication are part of projection, not the Linux writer, so status,
tests, and future event surfaces can report the exact intended set before any
kernel operation happens.

All-active with fewer than two surviving targets remains fail-closed in v1.
That keeps the all-active writer limited to shapes that prove actual ECMP/NHG
behavior; a single surviving target should arrive through the already shipped
single-active/scalar paths or wait for a later, explicit degenerate-case
decision. The M72 proof must use at least two remote targets.

### 4. Program the route through route-level ECMP plus FDB-NHG

For an all-active target set with `N >= 2` remote VTEPs, rustbgpd programs:

- one VRF-table route for the RT-5 prefix with `N` `onlink` nexthops through the
  L3VXLAN device;
- one permanent, externally learned L3 neighbor row per remote VTEP, mapping the
  VTEP address to the RT-5 Router MAC on the L3VXLAN device;
- one shared Router-MAC L3VXLAN FDB row using an FDB nexthop-group whose members
  are exactly the target VTEPs.

The single-dst FDB form is reserved for single-target installs. It is not an
all-active primitive, because Linux keeps only one destination for a duplicate
single-dst `(ifindex, router_mac)` row.

### 5. Own NHIDs separately from L2 aliasing unless sharing is proven safe

L2 aliasing already owns FDB nexthop-groups for remote MAC reachability.
All-active RT-5 receive introduces L3VXLAN Router-MAC FDB groups. The L3 path
must either use a separate NHID namespace/tagging scheme or prove that sharing
with the L2 aliasing allocator cannot collide across device class, key shape,
adoption, reap, and restart.

The first implementation should prefer explicit separation. A later
consolidation can merge the allocators only after tests prove cross-class
foreign preservation, adoption, and cleanup.

### 6. Keep conflict handling fail-closed

The implementation must fail closed rather than merge unrelated target sets.
In particular, reject or hold unresolved:

- no linked L2VNI for the selected IP-VRF;
- missing Router MAC;
- non-zero ESI and non-zero Gateway Address on the same RT-5;
- missing EAD-per-EVI or EAD-per-ES state;
- mixed single-active/all-active signals for the same ESI path;
- more than one single-active candidate;
- the same `(l3vxlan_ifindex, router_mac)` needed by different prefixes with
  different all-active target sets;
- any kernel capability gap for route multipath or FDB-NHG;
- any NHID ownership collision or adoption ambiguity.

This preserves the current "wrong forwarding is worse than no import" posture.

### 7. Prove the transition with M72, not by weakening M71

M71 remains the real-peer proof for the shipped single-active v1. Its current
all-active phase is a regression guard for the present fail-closed behavior.

The all-active implementation must add a new proof, M72, with an independent
route source that can originate:

1. an ESI overlay-index RT-5 alone, proving the route is held unresolved;
2. matching all-active EAD-per-ES and EAD-per-EVI from at least two remote
   VTEPs, proving import;
3. the VRF route with every remote VTEP present as an `onlink` nexthop through
   the L3VXLAN device;
4. the Router-MAC L3VXLAN FDB row using `nhid`, not duplicate single-dst FDB
   rows;
5. withdraw or target collapse cleanup, proving route, neighbor, FDB, NHG, and
   NH ownership converge deterministically.

If practical, M72 should include a packet-level forwarding assertion. Route ECMP
and FDB-NHG are separate kernel objects; object presence is necessary but does
not alone prove the two hashing layers forward consistently.

## Consequences

- The all-active ESI receive work gets its own review boundary rather than
  expanding ADR-0087 past its GW-IP/origination title.
- LAN-70 is now explicitly classified as a mechanism receipt, not a product
  feature. It proves Linux can host the route/FDB shape this ADR requires.
- The implementation is intentionally sliced: projection/model substrate first,
  L3 ownership substrate second, then the production L3 writer that owns route
  ECMP plus L3VXLAN FDB-NHG together.
- LAN-76 is the same-host production writer receipt. It proves a real
  `ReconcileActor<LinuxDataplane>` can install and withdraw the route ECMP,
  per-VTEP L3 neighbors, L3-tagged FDB-NHG members, and Router-MAC `nhid` FDB
  row against a Linux kernel.
- M72 is the required cross-vendor or real-peer receipt before the roadmap may
  claim the all-active ESI overlay-index Type 5 receive arc complete.
