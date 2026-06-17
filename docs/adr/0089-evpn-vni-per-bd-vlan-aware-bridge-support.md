# ADR-0089: EVPN VNI-per-BD VLAN-aware bridge support

**Status:** Accepted
**Date:** 2026-06-15

## Context

ADR-0088 kept Linux `vlan_filtering=1` bridges fail-closed until
rustbgpd had an explicit EVPN-to-Linux binding. The read-only substrate
now exists: the Linux link inventory can snapshot bridge VLAN membership
and VLAN tunnel mappings, while the L2 readiness probe still reports a
VLAN-aware bridge as `NotReady`.

The next decision is narrower than ADR-0088. We need to decide which
VLAN-aware service model rustbgpd should implement first.

Three concepts are easy to conflate:

1. **Linux VLAN-aware bridge topology.** A bridge with
   `vlan_filtering=1` forwards and learns using VLAN-scoped bridge state.
   Linux can attach one VXLAN device per VNI, or a single
   collect-metadata VXLAN device whose bridge VLAN tunnel mappings select
   VNIs.
2. **EVPN service-interface model.** RFC 7432 defines VLAN-Based,
   VLAN Bundle, and VLAN-Aware Bundle service interfaces. Only the
   VLAN-Aware Bundle service uses Ethernet Tag ID to identify multiple
   bridge tables within one EVI.
3. **VXLAN broadcast-domain demux.** RFC 8365 maps EVPN to VXLAN. For
   the common VNI-per-broadcast-domain model, the VNI identifies the
   broadcast domain and the Ethernet Tag field in MAC/IP Advertisement,
   Ethernet A-D per EVI, and IMET routes is zero. For the RFC 8365
   VLAN-Aware Bundle model, multiple VNIs live in one MAC-VRF / EVI and
   the Ethernet Tag identifies a bridge table.

That means a Linux VLAN-aware bridge does not automatically imply EVPN
VLAN-Aware Bundle semantics. FRRouting makes this distinction explicit:
it implements MAC-VRFs using the RFC 7432 VLAN-Based Service Interface,
while still supporting Linux VLAN-aware bridge topologies. NVIDIA Cumulus
documents the same operational shape by mapping bridge VLANs to VNIs on
Linux bridges and VXLAN devices.

rustbgpd's current EVPN domain model is already VNI-per-broadcast-domain:
`[[evpn_instances]]` declares one VNI/EVI, Type 2 / Type 3 / EAD-per-EVI
origination pins Ethernet Tag ID to zero, and the remote-MAC desired table
is keyed by `(VNI, MAC)`. The missing v1 information is not an EVPN
Ethernet Tag. It is the local Linux bridge VLAN that selects the
broadcast domain on a `vlan_filtering=1` bridge.

Local implementation facts at ADR acceptance:

- `EvpnInstanceConfig` has `vni`, `bridge`, and `local_vtep_ip`, but no
  bridge VLAN binding.
- The readiness probe rejects `bridge.vlan_filtering == true`.
- The FDB writer programs `NDA_LLADDR`, `NDA_DST`, and the ADR-0082
  ownership stamp, but no `NDA_VLAN`.
- The locked `netlink-packet-route 0.30.0` crate already exposes
  `NeighbourAttribute::Vlan(u16)`, so VLAN-scoped FDB writes do not
  require a raw encoder or dependency upgrade.

Reference material:

- RFC 7432 §6.1-§6.3:
  <https://datatracker.ietf.org/doc/html/rfc7432#section-6>
- RFC 8365 §5.1.3:
  <https://datatracker.ietf.org/doc/html/rfc8365#section-5.1.3>
- FRRouting EVPN documentation:
  <https://docs.frrouting.org/en/latest/evpn.html>
- NVIDIA Cumulus VXLAN devices:
  <https://docs.nvidia.com/networking-ethernet-software/cumulus-linux-515/Network-Virtualization/VXLAN-Devices/>
- Linux bridge documentation:
  <https://docs.kernel.org/networking/bridge.html>

## Decision

### 1. Scope v1 to VNI-per-broadcast-domain EVPN over Linux VLAN-aware bridges

The first supported VLAN-aware bridge mode is:

- one rustbgpd EVPN instance per VNI / broadcast domain;
- one Route Distinguisher and Route Target set per VNI;
- one local Linux bridge VLAN selecting that broadcast domain; and
- EVPN Ethernet Tag ID `0` on Type 2 MAC/IP, Type 3 IMET, and
  EAD-per-EVI routes.

This realizes the RFC 7432 VLAN-Based Service Interface — one broadcast
domain per EVI with Ethernet Tag ID `0` (RFC 8365 §5.1.3) — on a Linux
VLAN-aware bridge topology, the same model FRRouting uses. It is Linux
VLAN-aware bridge support for rustbgpd's existing VNI-per-broadcast-domain
EVPN model. It is not RFC VLAN-Aware Bundle service support.

The public docs and code comments should avoid calling this v1 mode
"VLAN-aware bundle". That term is reserved for the RFC 7432 / RFC 8365
model where one EVI contains multiple bridge tables and Ethernet Tag ID
identifies those tables.

### 2. Add an explicit local bridge VLAN binding, not an Ethernet Tag knob

The v1 config model should extend `[[evpn_instances]]` with one local
Linux VLAN selector, tentatively:

```toml
[[evpn_instances]]
vni = 10010
bridge = "br_default"
bridge_vlan = 10
local_vtep_ip = "10.0.0.1"
```

`bridge_vlan` is a local kernel binding. It selects the VLAN on the named
Linux bridge and VXLAN port. It is not an EVPN Ethernet Tag field and it
must not change wire encoding.

Validation and readiness rules:

- `bridge_vlan` is valid only with `bridge`.
- The value is a normal VLAN ID (`1..=4094`).
- `bridge_vlan` absent keeps today's non-VLAN-aware bridge behavior.
- `bridge_vlan` present selects the VLAN-aware path; if the observed
  bridge is not `vlan_filtering=1`, the instance is `NotReady`.
- A `vlan_filtering=1` bridge without `bridge_vlan` remains `NotReady`.
- Config transactions, SIGHUP, `ApplyEvpnRuntime`, and gNMI Set must
  preserve the same fail-closed behavior until every programming slice
  below is implemented.

The config schema should not expose an `ethernet_tag` option for this v1
mode. A future non-zero-Ethernet-Tag service model needs a separate ADR
because it changes route identity, import/export matching, aliasing keys,
and interop expectations.

### 3. Keep EVPN route identity unchanged in v1

The control-plane desired-state key remains `(VNI, MAC)` for remote L2
programming. The Type 2 / Type 3 / EAD-per-EVI Ethernet Tag remains zero,
so widening `RemoteMacTable` to `(VNI, VLAN, MAC)` is not part of v1.

The Linux dataplane still needs VLAN-scoped kernel identity:

- FDB snapshots and owned-state classification must include the observed
  bridge VLAN where the kernel reports one.
- FDB installs for a VLAN-aware L2VNI must include
  `NeighbourAttribute::Vlan(bridge_vlan)`.
- Local-MAC observation must map a learned `(bridge, VLAN, MAC)` back to
  exactly one configured VNI before Type 2 origination.

This is the two-key boundary:

- EVPN key: `(VNI, MAC)` with Ethernet Tag `0`.
- Linux key: `(bridge or VXLAN ifindex, bridge VLAN, MAC)`.

The bridge VLAN resolves the Linux key to the EVPN key. It does not
become part of the EVPN key.

### 4. Start with the traditional multi-VXLAN-device topology

The first programming-capable slice should support the smallest safe
topology change from today's probe:

- one `vlan_filtering=1` bridge;
- one traditional VXLAN device per VNI, attached to that bridge;
- the configured `bridge_vlan` present on that VXLAN port; and
- no rustbgpd-managed bridge, VXLAN, VRF, or port VLAN creation.

In this model, the VXLAN device still identifies the VNI, and
`NDA_VLAN` scopes the bridge FDB row to the local VLAN. This makes the
first implementation a readiness / FDB-attribution change rather than a
collect-metadata VXLAN rewrite.

The probe must remain fail-closed when:

- the bridge VLAN is absent from the bridge or VXLAN port;
- more than one candidate traditional VXLAN port matches the instance;
- the VXLAN port's VNI or local VTEP IP mismatches config;
- the VXLAN port has kernel learning enabled; or
- the kernel reports a state that rustbgpd cannot attribute to exactly
  one `(bridge, bridge_vlan, VNI)` binding.

### 5. Stage SVD / collect-metadata VXLAN as a compatible follow-up

Single VXLAN Device (SVD) / collect-metadata VXLAN with `vnifilter` is an
important operator topology and is the likely long-term Linux EVPN
default. It was intentionally not the first v1 programming slice, but the
schema and route model below are compatible with it.

SVD requires additional topology attribution:

- detecting `external` / collect-metadata VXLAN devices and `vnifilter`;
- validating bridge VLAN tunnel mappings (`bridge vlan ... tunnel_info`
  and `bridge vni ...`) against `bridge_vlan` and `vni`;
- programming and parsing any required `NDA_VNI` / `NDA_SRC_VNI`
  attributes in addition to `NDA_VLAN`; and
- ensuring one SVD can serve multiple rustbgpd EVPN instances without
  cross-VNI FDB ownership leaks.

The `bridge_vlan` schema is deliberately compatible with this follow-up:
SVD changes how the Linux binding is observed and programmed, not the
EVPN wire model.

The LAN-64 follow-up landed this compatible SVD path: rustbgpd detects
collect-metadata VXLAN devices and `vnifilter`, accepts an unambiguous
`(bridge_vlan, tunnel_info id <VNI>)` mapping as a Ready VXLAN target,
programs single-dst and FDB-NHG rows on the shared ifindex with
`NDA_SRC_VNI`, parses explicit-VNI FDB rows on known SVD ifindexes, and
handles sparse tested-kernel echoes by inferring the configured VLAN and
using owned state for convergence when `NDA_DST` is absent. The privileged
`svd_fdb_vni` netns proof covers Ready + add + same-MAC two-VNI isolation +
scoped delete on one SVD device.

### 6. Defer non-zero Ethernet Tag service models

The following remain out of v1:

- RFC 7432 / RFC 8365 VLAN-Aware Bundle service where one EVI contains
  multiple bridge tables and Ethernet Tag ID identifies them;
- shared-VNI service where Ethernet Tag ID, not VNI, demuxes bridge
  domains;
- VLAN Bundle / port-based bundle service with one shared FDB across
  multiple VLANs; and
- any interop mode requiring Type 2, Type 3, Type 5, aliasing, EAD, or
  DF-election state keyed by non-zero Ethernet Tag.

Implementing those models requires a new ADR and a real control-plane
route-identity expansion. The existing wire codec can carry non-zero
Ethernet Tags, but the domain model, policy surfaces, status APIs, and
dataplane projection must intentionally consume them before rustbgpd
advertises or installs such routes.

### 7. Keep managed netdev creation separate

ADR-0088's managed-netdev boundary remains unchanged. This ADR allows
programming owned FDB state on an operator-created VLAN-aware topology.
It does not authorize rustbgpd to create or delete bridges, VXLAN
devices, VRFs, VLAN membership, lower links, or bonds.

Missing or mismatched netdev topology remains `NotReady` unless a future
managed-netdev ADR and opt-in configuration explicitly changes that
class of ownership.

## Consequences

### Positive

- The v1 feature solves the visible operator pain: otherwise-valid
  Linux VLAN-aware bridge topologies can become `Ready` without changing
  rustbgpd's EVPN wire behavior.
- The control-plane blast radius stays small. Type 2 / Type 3 /
  EAD-per-EVI routes keep Ethernet Tag `0`, and `RemoteMacTable` remains
  keyed by `(VNI, MAC)`.
- The staged code slices are concrete: config binding, probe readiness,
  VLAN-scoped FDB writes, local-MAC VLAN attribution, and netns proof.
- SVD / collect-metadata support remains inside the same EVPN service
  model because `bridge_vlan` is a local Linux selector, not an EVPN
  service-interface commitment.

### Negative

- Operators wanting true RFC VLAN-Aware Bundle interop with non-zero
  Ethernet Tags still have no runtime support.
- The daemon must carry a second Linux L2 readiness shape while keeping
  the existing non-VLAN-aware path stable.

### Neutral

- This ADR adds no runtime feature by itself.
- `bridge = None` remains control-plane-only / RR behavior.
- Existing ESI, aliasing, single-active, GW-IP overlay-index, and
  ESI overlay-index logic remain valid because v1 keeps Ethernet Tag
  `0` for the VNI-per-broadcast-domain service.
- ADR-0088 remains the broader host-ownership boundary; this ADR selects
  the first programming-capable VLAN-aware subset.

## Implementation Plan

1. **Schema and documentation.** Add `bridge_vlan` to
   `[[evpn_instances]]`, status output, and docs. Validate range and the
   static config relationships that do not require a kernel probe.
2. **Domain plumbing.** Carry the local bridge VLAN through
   `EvpnInstance`, dataplane intent/report rows, and CLI/API status
   surfaces. Do not add an EVPN Ethernet Tag knob.
3. **Readiness probe.** Allow `vlan_filtering=1` only when
   `bridge_vlan` is configured and the observed traditional VXLAN port
   and VLAN membership resolve to exactly one instance.
4. **FDB programming and adoption.** Add `NDA_VLAN` to single-dst and
   FDB-NHG writes on VLAN-aware instances. Include VLAN in kernel snapshot
   classification and owned-state matching so foreign rows and other VLANs
   are preserved.
5. **Local-MAC observation.** Map learned local MACs back through
   `(bridge, VLAN)` before origination. Drop or report observations that
   cannot be attributed to exactly one instance.
6. **Tests and receipts.** Add pure probe/diff tests, netns FDB tests,
   and one M-series interop smoke against FRR or another Linux EVPN
   implementation.
7. **SVD follow-up.** Add collect-metadata / `vnifilter` support only
   after the traditional topology is green and prove no cross-VNI FDB
   ownership leaks on one shared VXLAN device.

## Rejected Alternatives

### Call the v1 feature "VLAN-aware bundle"

Rejected. Linux `vlan_filtering=1` is not the same thing as the RFC EVPN
VLAN-Aware Bundle service. In this v1 model, each VNI remains its own
broadcast domain / EVI and the Ethernet Tag stays zero.

### Add an `ethernet_tag` config field and set it to the bridge VLAN

Rejected. That would turn a local Linux selector into a wire-protocol
identity and would change Type 2 / Type 3 / EAD-per-EVI interop. Non-zero
Ethernet Tags need a separate service-model ADR.

### Widen `RemoteMacTable` to `(VNI, VLAN, MAC)` for v1

Rejected for v1. The EVPN identity is still `(VNI, MAC)` because VNI
selects the broadcast domain and Ethernet Tag is zero. VLAN belongs in
the Linux attribution layer. Widening the control-plane table would make
the first implementation look like true VLAN-Aware Bundle support while
still advertising VLAN-Based Service routes.

### Support SVD first

Deferred. SVD is operationally important and likely the better long-term
Linux scale target, but it adds collect-metadata / `vnifilter` attribution
and `NDA_VNI` questions on top of the VLAN-scoped FDB work. The
traditional multi-VXLAN-device topology proves the service model and
VLAN attribution first.

### Accept `vlan_filtering=1` and assume VLAN equals VNI

Rejected. Cumulus and operator examples often use offsets or
non-matching VLAN/VNI pairs. Guessing would silently program the wrong
bridge domain in exactly the deployments this feature is meant to serve.

## Test Obligations

The first programming PR must add:

- config tests for `bridge_vlan` range and invalid combinations;
- probe tests showing `vlan_filtering=1` stays `NotReady` without
  `bridge_vlan` and becomes `Ready` only with exact VLAN/VNI attribution;
- FDB message-shape tests proving `NDA_VLAN` is present for VLAN-aware
  instances and absent for today's non-VLAN-aware path;
- diff/adoption tests proving rows on other VLANs are foreign and are not
  deleted or claimed;
- local-MAC observation tests for two VLANs sharing one bridge, including
  the same MAC appearing on two VLANs; and
- a netns or M-series smoke with at least two VLANs on one bridge and at
  least one non-matching VLAN/VNI pair.

SVD follow-up PRs additionally prove collect-metadata VXLAN / `vnifilter`
discovery, bridge VLAN tunnel mapping attribution, and multi-VNI ownership
isolation on one VXLAN device.
