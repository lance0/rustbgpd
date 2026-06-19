# ADR-0088: EVPN VLAN-aware bridge and managed netdev boundary

**Status:** Accepted
**Date:** 2026-06-15

## Context

ADR-0054 deliberately made rustbgpd's first Linux EVPN dataplane slice
non-destructive: operators create bridge, VXLAN, and VRF netdevs out of
band, while rustbgpd probes that topology and reconciles owned FDB / L3
FIB state on top. The L2VNI readiness probe still rejects a bridge with
`vlan_filtering=1` because the `[[evpn_instances]]` schema has no VLAN,
Ethernet Tag, or bridge-domain field. Accepting such a bridge today would
force the daemon to guess which VLAN maps to which EVI/VNI.

That fail-closed boundary is increasingly visible because Linux and
FRR-style EVPN deployments commonly use two valid host models:

- one bridge / VXLAN netdev per VNI, where bridge VLAN filtering is not
  part of the EVPN ownership contract; and
- a VLAN-aware bridge model, where VLAN membership and tunnel mapping are
  configured on bridge ports and VXLAN devices.

The Linux bridge documentation makes VLAN filtering a first-class bridge
attribute (`IFLA_BR_VLAN_FILTERING`) and models VLAN state as per-bridge
and per-port data with per-VLAN flags, state, multicast context, tunnel
metadata, and MST instance. The Linux VXLAN documentation models VXLAN
devices as L2 tunnel endpoints whose forwarding state is driven by bridge
FDB operations. FRRouting's EVPN documentation describes how BGP EVPN is
bound to Linux bridge, VXLAN, and VRF objects through zebra. NVIDIA
Cumulus documents both traditional and
VLAN-aware VXLAN deployment shapes, which is the operational signal that
rustbgpd should not treat the current one-bridge-per-VNI shape as the
only Linux topology forever.

At the same time, managed netdev creation is a different problem from
VLAN-aware reconciliation. Creating or deleting bridges, VXLAN devices,
and VRFs introduces host ownership questions: who chose the name, who owns
MTU, underlay device, UDP port, learning mode, VLAN membership, bridge
STP state, VRF table, and crash-restart cleanup? rustbgpd already has
adoption-sweep machinery for owned routes and FDB entries, but it does
not yet have an ownership stamp or adoption contract for netdevs
themselves.

The standards do not remove this ambiguity. RFC 7432 defines EVPN route
identity, including Ethernet Tag ID. RFC 8365 maps EVPN to VXLAN and
uses the VNI as the network virtualization identifier. RFC 8584 and the
single-active/all-active multi-homing work depend on Ethernet Tag scoped
state. Those are control-plane identities; they do not say which Linux
bridge/VLAN/VXLAN object rustbgpd is allowed to create, adopt, or delete
on a host.

The decision needed now is the boundary for the next implementation
slices:

1. what remains unsupported and fail-closed;
2. what read-only kernel substrate can safely land first; and
3. what must be true before rustbgpd programs VLAN-aware bridges or
   creates netdev topology.

Reference material:

- Linux bridge documentation:
  <https://docs.kernel.org/networking/bridge.html>
- Linux VXLAN documentation:
  <https://docs.kernel.org/networking/vxlan.html>
- FRRouting EVPN documentation:
  <https://docs.frrouting.org/en/latest/evpn.html>
- NVIDIA Cumulus VXLAN devices:
  <https://docs.nvidia.com/networking-ethernet-software/cumulus-linux-515/Network-Virtualization/VXLAN-Devices/>
- RFC 7432, RFC 8365, RFC 8584, and RFC 9136.

## Decision

### 1. Keep the production default observe-only

rustbgpd remains observe-only for Linux bridge, VXLAN, and VRF netdev
lifecycle by default. The daemon may reconcile owned FDB entries, FDB
nexthop groups, neighbors, and L3 FIB routes on top of existing devices,
but it must not create or delete bridge, VXLAN, VRF, bond, VLAN, or
lower-link netdevs unless an opt-in ownership mode explicitly says so.
ADR-0091 is the first such mode for Linux bridge and fixed-VNI VXLAN
create/adopt/reap, and also adds VRF/L3VXLAN schema/status substrate;
SVD / collect-metadata VXLAN lifecycle, VRF/L3VXLAN lifecycle, bond, VLAN, and
lower-link creation remain outside the default boundary.

The current L2VNI readiness rule also remains in force: a configured
`[[evpn_instances]].bridge` with `vlan_filtering=1` is `NotReady`, not a
partially supported topology. This is a deliberate safety boundary, not a
missing probe.

### 2. Treat VLAN-aware support and managed netdev creation as separate gates

VLAN-aware bridge support and rustbgpd-managed netdev creation must not
ship as one bundled feature. They have different risk surfaces:

- VLAN-aware bridge support is about interpreting and programming an
  existing kernel topology without collapsing VLAN, Ethernet Tag, and VNI
  identity.
- Managed netdev creation is about host lifecycle ownership, adoption,
  foreign-state preservation, and cleanup.

Either can gain read-only substrate before programming. Neither may make
the other implicit.

### 3. VLAN-aware programming requires an explicit EVPN-to-Linux binding

Before rustbgpd programs a VLAN-aware bridge, the desired model must name
the binding that currently has to be guessed. The design does not have to
choose the final TOML spelling in this ADR, but it must provide enough
identity to answer these questions without inspecting accidental kernel
state:

- Which EVPN instance, Ethernet Tag, and VNI does a Linux VLAN belong to?
- Which bridge and port membership are in rustbgpd's ownership scope?
- Which VXLAN device or VXLAN tunnel mapping carries that VLAN/VNI?
- Which bridge FDB and neighbor rows are local observations versus
  rustbgpd-owned remote programming?
- What happens when a VLAN is present on one bridge port but missing on
  another, or when a port is STP-blocking for that VLAN?

The implementation must preserve route identity. Existing code can use
`(VNI, MAC)` in the one-bridge-per-VNI path because Ethernet Tag is zero
and the bridge maps one EVI. A VLAN-aware path needs a key that includes
the VLAN / Ethernet Tag dimension wherever Linux can hold multiple rows
for the same `(bridge, MAC)` or the control plane can carry multiple tags
for the same ESI/MAC/VNI. A generic "VNI equals VLAN" shortcut is not a
valid architecture boundary.

The first programming-capable design must also decide whether rustbgpd
owns only FDB/neighbor state for configured VLANs or also port VLAN
membership. If it owns port membership, that is configuration state and
must use the same transaction, rollback, and crash-restart discipline as
other runtime mutations.

### 4. Read-only VLAN-aware substrate may land before support

It is safe, and desirable, to land read-only Linux substrate before
enabling VLAN-aware programming. That substrate may:

- parse bridge `vlan_filtering` state more completely;
- dump and model per-port VLAN membership, PVID, untagged/tagged flags,
  per-VLAN STP state, and tunnel metadata where the kernel exposes it;
- record VXLAN device attributes needed to explain a topology;
- expose diagnostics through logs, tests, and existing status surfaces;
  and
- keep the existing `NotReady` decision for VLAN-aware L2VNIs.

The review rule is simple: if a PR makes a VLAN-aware L2VNI become
`Ready` or writes VLAN-scoped bridge/FDB state, it is no longer
read-only substrate and must satisfy the programming gate below.

### 5. Managed netdev creation must be explicit, opt-in, and class-scoped

Future rustbgpd-managed bridge / VXLAN / VRF creation must be opt-in at
the config/API boundary. Missing kernel devices in the default mode stay
`NotReady`; they do not silently trigger creation.

Managed creation must land one netdev class at a time unless an ADR
justifies bundling:

1. bridge creation;
2. VXLAN device creation and bridge attachment;
3. VRF / L3 VXLAN creation;
4. VLAN membership or VLAN-aware bridge tunnel mapping;
5. lower-link or bond ownership.

Each class needs:

- explicit config for all operator-visible attributes rustbgpd will set;
- idempotent create/update/delete behavior;
- a marker or adoption rule that distinguishes rustbgpd-owned devices
  from foreign devices after a crash;
- no deletion of foreign devices;
- documented cleanup semantics for clean shutdown, crash restart, and
  config removal; and
- tests that prove restart adoption/reap and foreign preservation.

### 6. Runtime mutation and gNMI stay fail-closed until the boundary exists

Config transactions, SIGHUP, `ApplyEvpnRuntime`, and gNMI Set must keep
rejecting unsupported VLAN-aware or managed-netdev effects until the
matching gate ships. A candidate must not be accepted merely because its
TOML parses. The decision point is whether the daemon can reconcile the
kernel state with explicit ownership, rollback, and diagnostics.

Any future mutating API that changes bridge/VXLAN/VRF topology must be in
the operator-only authorization tier and must be documented in the gRPC
inventory, operations guide, and VTEP setup guide.

## Consequences

### Positive

- Current production behavior remains non-destructive: rustbgpd will not
  delete or create host networking objects that another system owns.
- Operators get an honest fail-closed result for VLAN-aware bridges
  instead of a best-effort partial dataplane.
- The next low-risk code slice is clear: build read-only topology
  inventory and diagnostics without changing readiness.
- Future VLAN-aware work has a concrete route-identity and kernel
  ownership checklist before code starts.
- Future managed-netdev work can be reviewed one ownership class at a
  time instead of as a broad "make the topology" feature.

### Negative

- Operators using VLAN-aware bridge fabrics must keep using an
  operator-provisioned one-bridge-per-VNI shape with rustbgpd today, or
  run rustbgpd as control-plane-only for those VNIs.
- The daemon will continue to report `NotReady` for otherwise valid
  Linux VLAN-aware EVPN topologies until the explicit binding model and
  programming gate land.
- Managed netdev ergonomics stay deferred, so deployment automation must
  still pre-create bridge, VXLAN, and VRF devices.

### Neutral

- This ADR adds no runtime feature and no wire-protocol behavior.
- `bridge = None` remains valid for RR/control-plane-only L2VNIs.
- Existing EVPN Ethernet Tag support for EAD, aliasing, protected
  recursion substrate, and Type 5 overlay-index routes is unaffected; the
  decision is about Linux host attribution and programming.
- ADR-0054 remains the baseline for today's L2 dataplane. This ADR
  narrows the deferred VLAN-aware and managed-netdev follow-ups rather
  than replacing ADR-0054.

## Rejected Alternatives

### Accept VLAN-aware bridges and assume VLAN equals VNI

Rejected. Some deployments happen to choose matching values, but neither
Linux nor EVPN requires it. Guessing would create silent FDB/neighbor
attribution bugs and could blackhole traffic for tenants whose VLAN, VNI,
and Ethernet Tag do not align.

### Accept VLAN-aware bridges but program only untagged/default VLAN rows

Rejected. This would make the instance appear `Ready` while programming a
subset of the bridge-domain state. Partial support is worse than
`NotReady` because operators would have to discover the missing VLAN scope
from traffic loss.

### Auto-create missing devices from existing `[[evpn_instances]]` fields

Rejected. The current schema lacks enough information to create safe
Linux topology. Device name, underlay binding, MTU, UDP port, learning
mode, bridge VLAN mode, VLAN membership, VRF table, and cleanup ownership
are not all encoded today.

### Add a single "managed = true" switch for all netdevs

Rejected. Bridge, VXLAN, VRF, VLAN membership, and lower-link ownership
have different failure modes. A single switch would make review and
rollback too coarse and would make it hard to preserve foreign state.

## Test Obligations

Read-only substrate PRs must prove they do not change readiness or
programming behavior:

- unit tests for parsing VLAN-aware bridge and per-port VLAN attributes;
- fixture coverage for PVID, tagged/untagged, missing VLAN, and
  STP-blocking states where the kernel exposes them;
- a regression that a VLAN-aware bridge remains `NotReady` unless a later
  programming PR supplies an explicit binding and full kernel attribution
  semantics.

VLAN-aware programming PRs must add:

- local kernel dataplane tests with at least two VLANs sharing a bridge
  and at least one non-matching VLAN/VNI pair;
- FDB/neighbor attribution tests showing rows are scoped to the intended
  VLAN/Ethernet Tag;
- rollback tests for failed programming and failed persistence if exposed
  through transactions;
- an interop smoke against FRR or another Linux EVPN implementation.

Managed-netdev PRs must add:

- create/update/delete tests for the specific netdev class;
- crash-restart adoption/reap tests;
- foreign-device preservation tests; and
- deployment documentation showing how the opt-in mode interacts with
  external host-networking systems.
