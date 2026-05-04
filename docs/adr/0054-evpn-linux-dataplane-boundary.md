# ADR-0054: EVPN Linux Dataplane Boundary

**Status:** Accepted
**Date:** 2026-05-04

## Context

ADR-0052 landed the Gate 7a EVPN VTEP foundation: `crates/evpn`
contains the declarative local EVI/VNI model, daemon config accepts
`[[evpn_instances]]`, and `EvpnService.ListEvpnInstances` /
`rustbgpctl evpn instances` expose that resolved table. It deliberately
did **not** touch Linux netlink, bridge FDB state, VXLAN devices, or
Type 2/3 local origination.

Gate 7b is where rustbgpd starts acting like a Linux VTEP. That adds a
new class of state:

- desired local VTEP intent from `crates/evpn`;
- actual kernel bridge/VXLAN/FDB state;
- locally learned MACs that may need EVPN Type 2 origination;
- remote EVPN MACs that may need VXLAN FDB programming;
- failures from netlink operations that are operationally important but
  should not mutate the desired-state model.

The boundary must be explicit before Linux logic lands. If netlink
helpers grow on `EvpnInstance`, the domain crate stops being portable
intent and becomes an OS driver. If RIB or transport code starts owning
FDB apply decisions directly, route-reflector behavior becomes coupled
to a local dataplane. This ADR locks the interface between the existing
domain model and the future Linux dataplane crate.

Relevant source constraints:

- RFC 7432 defines the EVPN route family, including MAC/IP
  Advertisement routes and MAC mobility procedures.
- RFC 8365 maps EVPN overlays onto VXLAN/NVGRE and treats the VXLAN
  VNI as the network virtualization instance identifier.
- The Linux VXLAN documentation models a VXLAN device as a 1:N tunnel
  whose forwarding table is managed through bridge FDB operations.
- The Linux bridge uAPI is netlink-based; bridge aging, VLAN filtering,
  and FDB behavior are kernel-owned actual state.
- Switchdev documentation distinguishes bridge-owned FDB entries from
  device-local `self` entries and recommends programming bridge-owned
  static entries through the bridge/master path when offload is in play.

## Decision

### 1. Add a Linux-only dataplane crate; keep `crates/evpn` pure

Gate 7b introduces a new crate with working name `crates/evpn-linux`.
It is the only crate allowed to speak Linux netlink for EVPN VTEP
dataplane work.

`crates/evpn-linux` consumes domain intent from `crates/evpn`. It does
not define, validate, or mutate that intent. The first consumed input is
the existing `EvpnInstanceTable`. Follow-on domain inputs, such as a
local/remote MAC ownership table, belong in `crates/evpn` as portable
types and are then consumed by `crates/evpn-linux`.

Dependency direction:

```text
crates/wire  <-- transport/rib existing EVPN route flow

crates/evpn  --desired local VTEP intent-->  crates/evpn-linux
     ^                                            |
     |                                            v
 daemon config / future MAC domain        Linux netlink / kernel snapshot
```

`crates/evpn-linux` may depend on `crates/evpn` and Linux netlink
libraries. It must not depend on `crates/rib` or `crates/transport`.
The daemon wires data between actors. Route-reflector deployments with
empty `[[evpn_instances]]` must not instantiate the dataplane actor.

### 2. Dataplane input is a snapshot, not mutable callbacks

The crate accepts immutable desired-state snapshots. The initial shape
is conceptual, not a frozen Rust API:

```rust
pub struct DataplaneIntent {
    pub instances: Arc<EvpnInstanceTable>,
    pub remote_macs: Arc<RemoteMacTable>, // future crates/evpn type
}
```

The current Gate 7b runway only needs `instances`. Remote/local MAC
domain tables land when Type 2 origination and remote FDB programming
start. They should be domain objects such as "MAC X in VNI Y is owned
locally with mobility sequence N" or "remote MAC X in VNI Y resolves to
VTEP Z", not raw `rustbgpd_wire::EvpnRoute` values.

### 3. Kernel observation surface is explicit and narrow

`crates/evpn-linux` observes Linux state through netlink dumps and
subscriptions. It builds an internal `KernelSnapshot` containing only
the fields needed to reconcile the EVPN VTEP contract:

- bridge links by ifindex/name: existence, admin/oper state,
  VLAN-filtering state, and bridge FDB aging time;
- VXLAN links by ifindex/name: VNI, local VTEP IP, destination UDP
  port, learning mode, and master bridge membership;
- bridge/VXLAN FDB entries: MAC, bridge/VXLAN device, VLAN if present,
  remote VTEP destination if present, and ownership flags such as
  `self`, `master`, `extern_learn`, `offload`, `static`, `permanent`,
  and dynamic/learned;
- netlink notifications for link and FDB create/update/delete events.

Everything outside that list is out of scope for the first dataplane
crate. In particular, interface statistics, neighbor tables, route
tables, tc filters, nftables, and VRF/L3VNI state are not part of the
Gate 7b L2VNI dataplane boundary.

### 4. First slice observes/provisions FDB state, not netdev topology

Gate 7b does not create or delete Linux bridge or VXLAN netdevs. It
expects the operator or host-networking layer to create them. For an
`EvpnInstance` with `bridge = "br100"`, the dataplane crate verifies:

1. the bridge exists;
2. exactly one VXLAN port for the instance VNI is attached to that
   bridge;
3. the VXLAN port's local address matches `local_vtep_ip`;
4. the VXLAN port uses a supported destination port and learning mode.

If any check fails, the instance is reported `NotReady`; no synthetic
device is created. This keeps the first Linux integration non-
destructive and avoids inventing schema fields for VXLAN device names,
underlay device selection, MTU, source port ranges, or multicast groups
before the project has real operator signal.

Future ADRs may allow rustbgpd to create netdev topology, but that is a
separate ownership decision.

### 5. Local MACs are observed; remote MACs are programmed

Local MAC ownership comes from kernel learning on non-VXLAN bridge
ports. `crates/evpn-linux` classifies a learned FDB entry as a local MAC
candidate only when all of these are true:

- the entry belongs to a bridge named by an `EvpnInstance`;
- the entry is learned on a bridge port that is not the instance VXLAN
  device;
- the entry is not a bridge `self` / local address entry;
- the entry is not one rustbgpd previously programmed from remote EVPN.

Those local candidates are emitted upward as domain events. The EVPN
domain layer decides whether they become local MAC records and whether
MAC mobility sequence numbers advance. The Linux crate does not run
RFC 7432 mobility policy.

Remote MAC programming flows the opposite direction. Once the control
plane selects a remote EVPN Type 2 as installed for `(VNI, MAC)`, the
daemon provides a remote-MAC intent to `crates/evpn-linux`. The Linux
crate reconciles that intent into VXLAN FDB entries pointing at the
remote VTEP IP. Remote entries are marked as rustbgpd-owned in the
internal snapshot and should use kernel ownership flags such as
`extern_learn` where supported so they are distinguishable from
kernel-learned local entries.

### 6. Reconcile-on-event plus periodic full resync

The dataplane actor is a single owner of netlink state. It reacts to
four inputs:

1. a new desired intent snapshot from the daemon;
2. netlink link/FDB notifications;
3. a periodic full-dump timer;
4. explicit operator retry / resync commands.

Every input schedules the same reconcile function:

```text
desired intent + kernel snapshot -> diff -> idempotent netlink ops
```

The diff loop is level-triggered, not edge-triggered. Missing a single
netlink notification is not fatal because the periodic dump repairs the
snapshot. Re-applying the same desired snapshot is a no-op. Failed ops
stay pending with bounded backoff until the next reconcile input.

Deletes are conservative:

- withdraw remote FDB entries only when rustbgpd owns them;
- never delete kernel-learned local MACs;
- never delete bridge or VXLAN netdevs in Gate 7b;
- when an instance disappears from desired intent, withdraw only
  rustbgpd-owned FDB entries for that instance and mark local learned
  observations stale upward.

### 7. Failures surface as status, not domain mutation

Netlink errors are dataplane status, not edits to `EvpnInstanceTable`.
The Linux crate returns structured reports:

```rust
pub struct DataplaneReport {
    pub generation: u64,
    pub instance_status: Vec<InstanceDataplaneStatus>,
    pub applied: Vec<AppliedOp>,
    pub failed: Vec<FailedOp>,
}
```

The daemon turns these into logs, metrics, and eventually a gRPC status
surface. `crates/evpn` does not learn that its desired bridge "failed";
it remains the source of desired truth. The actual-state failure lives
in the dataplane actor.

## Consequences

### Positive

- `crates/evpn` stays portable and testable. Linux-specific behavior is
  isolated behind one crate.
- Route-reflector behavior remains independent of local VTEP state.
- The diff loop can be unit-tested with fake desired/kernel snapshots
  before any privileged netlink integration test exists.
- Kernel drift is handled by reconciliation, not by assuming every
  netlink notification arrives.
- Non-destructive first behavior is safe for real hosts: rustbgpd will
  observe and program owned FDB entries, but it will not create or
  delete bridges/VXLAN devices.

### Negative

- More glue is required between RIB-selected EVPN routes and portable
  domain MAC intent. The Linux crate intentionally refuses to consume
  raw wire/RIB route types.
- Operators must pre-create bridge/VXLAN topology for Gate 7b. A later
  "rustbgpd owns netdev topology" feature will need schema additions
  and a separate ADR.
- Failure reporting requires a new daemon/API surface; logs and metrics
  are enough for the first slice but not enough long term.

### Neutral

- `bridge = None` remains valid. Such instances are visible via
  `rustbgpctl evpn instances` but are not eligible for Linux
  reconciliation until bound to a bridge.
- L3VNI / IRB / Type 5 origination stay out of this ADR except where
  current fields such as `advertise_svi_mac` need to remain compatible.
- Switchdev offload is treated as a kernel consequence of bridge FDB
  programming, not a separate rustbgpd hardware API.

## Test Obligations

- Keep the Gate 7b runway binary-spawn integration test: start the real
  `rustbgpd` binary with `[[evpn_instances]]`, then query it through a
  real `rustbgpctl evpn instances` subprocess.
- `crates/evpn-linux` must start with diff-loop unit tests over fake
  desired/kernel snapshots: create, no-op, update, delete, foreign-entry
  preservation, and retry-after-failure.
- Privileged netlink tests should live behind an explicit Linux
  namespace/capability gate. They are valuable, but they are not a
  substitute for pure diff tests.

## Cross-References

- ADR-0050 - EVPN Route Reflector (RFC 7432 Phase 1)
- ADR-0052 - EVPN VTEP Foundation - Local EVI/VNI Domain Model
- `docs/evpn-enablement.md` Gate 7b
- RFC 7432 - BGP MPLS-Based Ethernet VPN
- RFC 8365 - Network Virtualization Overlay Solution Using EVPN
- RFC 9135 - Integrated Routing and Bridging in EVPN
- Linux kernel VXLAN documentation:
  <https://www.kernel.org/doc/html/v6.6/networking/vxlan.html>
- Linux kernel bridge documentation:
  <https://kernel.org/doc/html/next/networking/bridge.html>
- Linux switchdev documentation:
  <https://docs.kernel.org/6.2/networking/switchdev.html>
