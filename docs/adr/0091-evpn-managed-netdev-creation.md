# ADR-0091: rustbgpd-managed netdev creation

**Status:** Accepted
**Date:** 2026-06-19

## Context

Today rustbgpd is **observe-only** over the Linux netdev topology
(ADR-0088): operators create bridge, VXLAN, VRF, L3VXLAN, VLAN upper,
and bridge-VLAN membership objects out of band. rustbgpd probes that
topology, reports readiness, and reconciles only the owned FDB / L3 FIB /
nexthop state on top.

That boundary is correct by default, but it is a real operator-UX cost.
A useful EVPN VTEP needs several kernel objects with matching attributes
before the daemon can become `Ready`, and the operator must also clean them
up after removing the EVPN configuration. ADR-0088 already accepted the
direction: managed netdev creation must be explicit, opt-in, class-scoped,
crash-restart safe, and foreign-state preserving. This ADR defines the
ownership and lifecycle contract for that feature.

The existing ownership/adoption pattern for dataplane rows is not enough
for links. Routes, FDB entries, and neighbors can be stamped with
protocol-level ownership metadata such as `RTPROT_BGP` or `NDA_PROTOCOL`
(ADR-0079 / ADR-0082). Linux links have no equivalent protocol owner field.
The central decision is therefore how a restarted daemon can distinguish a
rustbgpd-created bridge or VXLAN device from an operator-created device with
the same name.

Primary source anchors:

- `ip-link(8)` exposes alternate interface names through
  `ip link property add|del dev DEVICE altname NAME`
  (<https://man7.org/linux/man-pages/man8/ip-link.8.html>).
- Linux rtnetlink exposes link properties as `IFLA_PROP_LIST`, with
  alternate names as `IFLA_ALT_IFNAME`
  (<https://docs.kernel.org/netlink/specs/rt-link.html>).
- The locked `netlink-packet-route 0.30.0` crate already models this as
  `LinkAttribute::PropList(Vec<Prop>)` and `Prop::AltIfName(String)`.

## Decision

### 1. Managed creation is opt-in and class-scoped

rustbgpd never infers link ownership from ordinary EVPN bindings. Existing
fields such as `[[evpn_instances]].bridge`,
`[[evpn_ip_vrfs]].vrf_device`, and `l3vxlan_device` continue to mean
"bind to this observed object by name," not "create this object."

Managed creation is enabled only through top-level, class-scoped
configuration. The feature lands one object class at a time, in dependency
order:

1. bridge,
2. VXLAN,
3. VRF / L3VXLAN,
4. optional VLAN upper / bridge membership helpers after the base classes.

The first implementation slice is bridge create/adopt/reap. VXLAN and
VRF/L3VXLAN are separate slices with their own proofs.

### 2. `IFLA_ALT_IFNAME` is the durable ownership marker

Every rustbgpd-created managed link carries an alternate interface name
stamp, read back from `IFLA_PROP_LIST` during the normal link dump:

```text
rbgp_owned_<class>_<stable-config-id>_<owner-token>
```

The exact encoding can be adjusted for length and character constraints, but
the logical fields are fixed:

- `class`: managed object class, such as `bridge`, `vxlan`, or `vrf`;
- `stable-config-id`: deterministic identifier derived from the managed
  block's stable identity;
- `owner-token`: operator-configured daemon / installation token.

The owner token is not a secret. It does not defend against privileged local
root or an operator deliberately spoofing the marker. Its job is accidental
collision avoidance: two rustbgpd daemons, two configs, or a renamed object
must not silently adopt each other's links.

Changing the owner token is an ownership migration. The daemon must not use a
new token to adopt links stamped with the old token unless an explicit future
migration flow says so.

### 3. Adopt/reap only on exact identity and attribute match

A managed link is adoptable or reapable only when all of the following match:

- configured link name;
- link kind (`bridge`, `vxlan`, `vrf`, etc.);
- exact rustbgpd altname ownership stamp;
- expected immutable or high-risk attributes for that class.

Class attributes include at least:

- bridge: `vlan_filtering` and other managed bridge options;
- VXLAN: VNI, local address, UDP destination port, learning mode,
  `external` / collect-metadata mode, and VNI-filter mode where relevant;
- VRF: table id;
- L3VXLAN: VNI, local address, UDP port, learning/external flags, and
  relationship to the configured VRF.

If the target name exists without the exact stamp, rustbgpd treats it as
foreign and preserves it. If the stamp exists but the kind or protected
attributes do not match, rustbgpd treats the link as **owned but unsafe**:
it fails closed and requires operator action. The v1 design does not repair
stamped drift in place.

### 4. Crash windows fail closed

Link creation and altname stamping are separate kernel operations in the
common rtnetlink/iproute2 flow. If rustbgpd crashes after creating a link but
before applying the altname stamp, the restarted daemon must treat the
unstamped link as foreign/ambiguous. A sidecar record must not override the
missing live kernel stamp.

Ownership is network-namespace scoped. A managed link moved to another netns
is absent from the original daemon's link dump; the daemon does not chase it
or reap it from another namespace.

### 5. Config shape is top-level managed-netdev blocks

Managed lifecycle belongs in a separate top-level block rather than per-EVPN
instance `manage_*` booleans. EVPN instances and IP-VRFs continue to bind by
device name; managed-netdev blocks declare lifecycle ownership and the
attributes rustbgpd will set.

Indicative shape:

```toml
[managed_netdevs]
owner_token = "site-a-leaf-01"

[[managed_netdevs.bridges]]
name = "br_default"
vlan_filtering = true

[[managed_netdevs.vxlans]]
name = "vxlan10010"
vni = 10010
local = "10.0.0.1"
dstport = 4789
learning = false
bridge = "br_default"

[[managed_netdevs.vrfs]]
name = "vrf-blue"
table = 1001
```

The final schema may split fixed-VNI VXLAN, SVD/collect-metadata VXLAN, and
L3VXLAN into more specific blocks. The ownership model stays the same.

Runtime mutation, SIGHUP reload, gNMI `Set`, and `ApplyEvpnRuntime` must
remain fail-closed for managed-netdev fields until the corresponding class
executor and rollback/adoption proof exists.

## Consequences

### Positive

- Removes a major EVPN VTEP bring-up burden without changing the default
  observe-only safety boundary.
- Reuses the ADR-0079 / ADR-0082 adoption discipline: live kernel state is
  authoritative, and foreign objects are preserved.
- Gives rustbgpd a safe path to create VLAN upper devices (`brvlan.10`),
  which already provide precise MAC+IP VLAN attribution and reduce the need
  for raw bridge FDB correlation (ADR-0093).

### Negative

- Adds a new kernel object class to the reconciliation surface.
- Creates an unavoidable create-before-stamp crash window; the required
  behavior is safe but leaves an operator-visible ambiguous link.
- Does not protect against privileged local spoofing of the altname marker.
  That is outside the threat model for local Linux netdev ownership.

## Dependencies and relationships

- **Builds on:** ADR-0088 (boundary and managed-netdev scope), ADR-0079
  (adoption sweeps), ADR-0082 (ownership-stamp pattern), ADR-0089 (VLAN-aware
  readiness and VLAN upper attribution).
- **Independent of:** ADR-0092 (true VLAN-Aware Bundle service) and ADR-0093
  (raw bridge MAC+IP correlation). Managed creation can ease ADR-0093 by
  creating VLAN uppers, but neither blocks the other.

## Rejected Alternatives

### Use a reserved name prefix as ownership authority

Rejected. Operator naming can collide with any prefix. A prefix can make
objects readable, but it is not an adoption or deletion authority.

### Use a sidecar ownership database as authority

Rejected. Ifindex is namespace-local and reusable; names can be reused; and a
stale sidecar cannot prove that a live unstamped link is safe to delete after
a crash. A sidecar may record diagnostics or pending intent, but the live
kernel altname remains authoritative.

### Overload device-type attributes

Rejected. Bridge, VXLAN, and VRF expose type-specific operational attributes,
not a shared owner field. Overloading real dataplane attributes would confuse
configuration with ownership.

### Use `IFLA_IFALIAS`

Rejected as the primary marker. It is generic and dumpable, but it is a single
operator-facing alias/description field. `IFLA_ALT_IFNAME` is multi-valued
and purpose-built for alternate names, so it does not consume the operator's
alias slot.

### Auto-create from existing `[[evpn_instances]]` fields

Rejected. It conflates topology binding with ownership and gives no safe
foreign-vs-owned signal.

## Implementation Plan

1. Parse managed-link altname stamps in the link inventory.
2. Add `[managed_netdevs] owner_token` and `[[managed_netdevs.bridges]]`.
3. Implement bridge create -> stamp -> adopt -> reap with an acked,
   rollback-aware executor.
4. Add VXLAN class support.
5. Add VRF / L3VXLAN class support.
6. Add optional VLAN upper / bridge membership helpers if operator demand
   remains after bridge/VXLAN/VRF creation.

## Test Obligations

- netns bridge proof: create -> stamp -> dump -> simulated restart adopt ->
  config removal reap.
- Same-name unstamped foreign bridge is never modified or deleted.
- Crash before stamp leaves an unstamped link that is preserved on restart.
- Stamped wrong-kind or wrong-attribute link reports owned-but-unsafe and is
  not repaired in place.
- Same ifname / same stamp in another netns is not visible or adopted by the
  first daemon.
- Dependency ordering is correct on create and teardown.

## References

- `ip-link(8)`: <https://man7.org/linux/man-pages/man8/ip-link.8.html>
- Linux rt-link netlink specification:
  <https://docs.kernel.org/netlink/specs/rt-link.html>
- Linux bridge documentation:
  <https://docs.kernel.org/networking/bridge.html>
- Linux VXLAN documentation:
  <https://docs.kernel.org/networking/vxlan.html>
- Linux VRF documentation:
  <https://docs.kernel.org/networking/vrf.html>
