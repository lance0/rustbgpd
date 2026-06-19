# ADR-0091: rustbgpd-managed netdev creation

**Status:** Proposed
**Date:** 2026-06-19

> Draft / stub. This ADR frames the problem, the proposed decision shape, and
> the open questions for the next implementation slice. Decisions marked
> *(proposed)* are not final until this moves to Accepted.

## Context

Today rustbgpd is **observe-only** over the Linux netdev topology (ADR-0088):
operators create the bridge, VXLAN, and VRF devices out of band — including
their MTU, underlay device, UDP port, learning mode, and VLAN membership — and
rustbgpd probes that topology and reconciles only the *owned* FDB / L3 FIB /
nexthop state on top. The L2VNI / IP-VRF readiness probes fail closed when the
expected device is missing.

That is a real operator-UX cost. A working EVPN VTEP deployment requires the
operator to hand-craft and keep consistent a non-trivial set of kernel devices
before rustbgpd can do anything, and to tear them down by hand afterward.
ADR-0088 Decision 5 already accepted the direction — *managed netdev creation
must be explicit, opt-in, and class-scoped, with crash-restart adoption/reap
and foreign-state preservation* — and Decision 2 established that managed
creation is a **separate gate** from VLAN-aware support. This ADR proposes the
implementation contract for that gate.

rustbgpd already owns the hard half of the pattern this needs: crash-restart
adoption sweeps (ADR-0079) and a durable ownership stamp for FDB / neighbor
state (ADR-0082, `NDA_PROTOCOL`). The new work is extending that
ownership/adoption/reap discipline to a new object class — **links** — which,
unlike routes/FDB/neighbors, have no per-object protocol/owner field in
rtnetlink. Establishing a durable, collision-safe ownership marker for a
created netdev is the central design problem.

## Decision

### 1. Opt-in, class-scoped, no global switch *(proposed)*

Managed creation is enabled per device class, behind explicit config — never a
single repo-wide `managed = true` (ADR-0088 rejected that). The implementation
lands one class at a time, in dependency order:

1. **bridge** (first slice — smallest blast radius, unblocks the most common
   single-bridge VTEP),
2. **VXLAN**,
3. **VRF / L3VXLAN**.

Each class is independently shippable and demoable.

### 2. Durable, collision-safe ownership marker for links *(open — the load-bearing decision)*

Adoption/reap must distinguish a rustbgpd-created device from an operator's
foreign device across a restart, with no false positives. rtnetlink links have
no `NDA_PROTOCOL` equivalent. Candidate mechanisms to evaluate (pick one,
prove it survives restart + is not spoofable by a coincidental operator name):

- an `IFLA_ALT_IFNAME` alt-name stamp (e.g. `rustbgpd:owned:<instance>`);
- an `IFLA_INFO_DATA` / device-attribute marker where the device type allows;
- a persisted ownership record (sidecar state, keyed by ifindex + creation
  cookie) cross-checked against the live dump;
- a reserved name prefix (weakest — collides with operator naming; likely
  insufficient alone).

The chosen marker must be re-readable from a plain `dump_links` so the existing
adoption-sweep shape (ADR-0079) applies.

### 3. Create / adopt / reap lifecycle mirrors the FDB sweep *(proposed)*

- **Create on config** when the device is absent.
- **Adopt on restart** a device that carries our ownership marker (re-own,
  don't recreate or clobber).
- **Reap on removal** only devices we own; never touch foreign/unstamped
  devices (foreign-state preservation, per ADR-0088).
- Creation respects dependency order (VRF before its L3VXLAN, bridge before
  bridge-VLAN bindings); teardown reverses it.

### 4. Fail closed on ownership ambiguity *(proposed)*

If a device with the target name already exists but is **not** stamped as ours,
do not adopt, modify, or delete it — surface an error and stay observe-only for
that instance. "Wrong device ownership is worse than no device."

### 5. Config schema *(open)*

New surface to express which devices rustbgpd owns and their parameters (name,
MTU, underlay device, VXLAN UDP port / VNI / learning, VRF table id, bridge
`vlan_filtering`, VLAN membership). Open question whether this is a new
`[[managed_netdevs]]` block or per-`[[evpn_instances]]` / `[[evpn_ip_vrfs]]`
`manage_*` fields. Runtime mutation (ADR-0063) and gNMI `Set` stay fail-closed
for managed-netdev fields until this lands (ADR-0088 Decision 6).

## Consequences

- Removes the largest single operator-UX cost in the EVPN/VTEP story.
- Extends a proven ownership/adoption pattern rather than inventing one — but
  to a class (links) that lacks a native owner field, so the ownership marker
  (Decision 2) carries the correctness weight.
- If rustbgpd creates the VLAN topology, it can create **VLAN upper devices**
  (`brvlan.10`) — the MAC+IP attribution path that already works (ADR-0089) —
  which reduces the need for the raw-bridge-ifindex correlation in
  [ADR-0093](0093-evpn-vlan-macip-fdb-correlation.md).

## Dependencies and relationships

- **Builds on:** ADR-0088 (boundary + Decision 5 scope), ADR-0079 (adoption
  sweeps), ADR-0082 (ownership-stamp pattern).
- **Independent of:** ADR-0092 (VLAN-aware bundle) and ADR-0093 (MAC+IP
  correlation) — explicitly decoupled per ADR-0088 Decision 2. It *eases*
  ADR-0093 (see Consequences) but neither blocks the other.

## Rejected Alternatives

- **A single `managed = true` switch for all netdevs** — rejected in ADR-0088;
  too coarse, unclear blast radius.
- **Auto-create from existing `[[evpn_instances]]` fields** — rejected in
  ADR-0088; conflates probe topology with ownership and gives no foreign-vs-ours
  signal.

## Test Obligations

- netns: create → adopt-on-restart (no recreate, marker re-read) → reap; a
  foreign unstamped device of the same name is never created-over or deleted.
- Ambiguity: target name exists unstamped ⇒ fail closed, observe-only.
- Dependency ordering on create and teardown.
- One class per slice; bridge slice ships with its own proof before VXLAN/VRF.
