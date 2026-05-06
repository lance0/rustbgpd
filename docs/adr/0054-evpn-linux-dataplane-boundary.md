# ADR-0054: EVPN Linux Dataplane Boundary

**Status:** Accepted (implementation in PR #34, branch `feat/evpn-linux-dataplane`)
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

### 2. Dataplane input is a coalescing snapshot channel

The crate accepts immutable desired-state snapshots. The initial shape
is conceptual, not a frozen Rust API:

```rust
pub struct DataplaneIntent {
    pub generation: u64,
    pub instances: Arc<EvpnInstanceTable>,
    pub remote_macs: Arc<RemoteMacTable>,
}

pub struct RemoteMacTable {
    // Minimum Gate 7b shape. VLAN-aware expansion is a follow-up.
    pub entries: BTreeMap<(EvpnInstanceId, MacAddress), RemoteMacEntry>,
}

pub struct RemoteMacEntry {
    pub remote_vtep_ip: IpAddr,
    pub mobility_sequence: Option<u32>,
    pub source: RemoteMacSource,
}
```

The daemon sends this through a `watch::Sender<Arc<DataplaneIntent>>`.
That choice is part of the decision:

- intermediate desired snapshots may be dropped;
- the dataplane actor always reconciles the latest visible snapshot;
- no queue grows under Type 2 churn;
- missed snapshots are harmless because the next generation supersedes
  every prior one.

A plain `mpsc` queue is the wrong default for this surface. It would
preserve transient desired states that are intentionally obsolete by
the time the actor sees them.

The `RemoteMacTable` is a **complete snapshot**, not a delta stream. The
dataplane actor computes create/update/delete operations by comparing
the new complete desired table against the kernel snapshot and its
previous applied state. The minimum key is `(VNI, MAC)`;
`RemoteMacEntry` initially needs the remote VTEP IP, optional MAC
mobility sequence, and source class. VLAN-aware keys are deferred until
the EVPN instance schema has an explicit VLAN field.

Remote/local MAC domain tables should be portable domain objects such
as "MAC X in VNI Y is owned locally with mobility sequence N" or
"remote MAC X in VNI Y resolves to VTEP Z", not raw
`rustbgpd_wire::EvpnRoute` values.

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
4. the VXLAN port uses a supported destination port and learning mode;
5. the bridge is not VLAN-aware.

If any check fails, the instance is reported `NotReady`; no synthetic
device is created. This keeps the first Linux integration non-
destructive and avoids inventing schema fields for VXLAN device names,
underlay device selection, MTU, source port ranges, or multicast groups
before the project has real operator signal.

VLAN-aware bridges are rejected for Gate 7b. The current
`EvpnInstance` schema has no VLAN field, so accepting a VLAN-filtering
bridge would force the dataplane crate to guess a VNI-to-VLAN mapping.
That mapping belongs in a follow-on schema/ADR, likely an additive
`vlan = N` field on the instance.

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

Local age-out is also an upward observation. When a previously observed
local MAC disappears from the kernel FDB because of aging or explicit
operator deletion, `crates/evpn-linux` emits "local MAC no longer
observed" to the domain layer. The domain layer decides whether that
causes Type 2 withdrawal, delayed hold-down, or mobility handling; the
Linux crate does not originate or withdraw EVPN routes directly.

Remote MAC programming flows the opposite direction. Once the control
plane selects a remote EVPN Type 2 as installed for `(VNI, MAC)`, the
daemon provides a remote-MAC intent to `crates/evpn-linux`. The Linux
crate reconciles that intent into VXLAN FDB entries pointing at the
remote VTEP IP. Remote entries are marked as rustbgpd-owned via
`NTF_EXT_LEARNED` in the internal snapshot so they are distinguishable
from kernel-learned local entries; `NTF_EXT_LEARNED` is required for
correctness on both observed kernel rows.

The wire shape, verified via `strace` on iproute2's
`bridge fdb add MAC dev vxlanX master dst REMOTE self extern_learn`,
is a **single** `RTM_NEWNEIGH` carrying
`NTF_SELF | NTF_MASTER | NTF_EXT_LEARNED` flags + `NDA_DST` with state
`NUD_NOARP | NUD_PERMANENT`. The kernel programs both forwarding rows
from that one message: the VXLAN-self+dst row on the VXLAN port (which
gives the VXLAN driver the tunnel encap target) and the bridge-master
row on the bridge (which makes the MAC reachable via the VXLAN port
instead of being flooded). Both rows carry `NTF_EXT_LEARNED` after the
kernel propagates the flag, and the diff/dump path requires it on both
to classify the entry as rustbgpd-owned. Switchdev-capable drivers can
offload the bridge-master row through the master path. Device-local
`self`-only programming without bridge participation is reserved for
explicit cases where bridge mediation is not desired; it is not the
default Gate 7b behavior.

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

Startup ordering matters. The actor starts its netlink notification
subscription, then performs an initial full link/FDB dump. Notifications
received before that dump completes are buffered and replayed onto the
initial snapshot before the first reconcile. If ordering metadata is
available from the netlink library, events newer than the dump snapshot
win. If not, replay is conservative: create/update events are applied
over the dump, delete events remove only matching snapshot entries, and
the periodic dump repairs any ambiguity.

Default timer policy:

- full kernel dump every 60 seconds, configurable later if operators
  show hosts with very large FDBs need a different cadence;
- failed netlink ops retry with exponential backoff from 100 ms to a
  5 second cap, with jitter;
- any new desired snapshot or netlink event resets the sleep and
  schedules reconcile immediately.

Implementation note: `RTNLGRP_NEIGH` / `RTNLGRP_LINK` subscription is
deferred past PR #34 — `Dataplane::next_event` returns `pending()` in
the first slice. The level-triggered reconcile design tolerates the
gap because the 60 s periodic dump structurally repairs any drift; the
follow-up that wires subscriptions is purely a latency optimization.

Permanent-failure suppression is **per-op-fingerprint**, not
generation-wide: if the kernel returns a permanent classification
(`PermissionDenied`, `KernelTooOld`, `InvalidArgument`) for a specific
`(VNI, MAC, dst)` op shape, that exact fingerprint is suppressed until
the op shape changes or the fingerprint clears on next intent. A
different op for the same key (e.g., a new dst on mobility) is
re-attempted immediately. Generation-wide suppression would mask real
churn.

The supervisor publishes a new `DataplaneIntent` only when the
projected `RemoteMacTable` differs semantically from the last
publication. The 5 s polling cadence does not bump
`DataplaneIntent::generation` if the projected table is unchanged —
the reconcile actor uses the generation as the trigger to clear its
permanent-failure suppression, so spurious bumps would defeat
suppression and re-flap permanent errors.

Deletes are conservative:

- withdraw remote FDB entries only when rustbgpd owns them;
- never delete kernel-learned local MACs;
- never delete bridge or VXLAN netdevs in Gate 7b;
- when an instance disappears from desired intent, withdraw only
  rustbgpd-owned FDB entries for that instance and mark local learned
  observations stale upward.

### 7. Shutdown leaves host topology intact and removes owned FDB entries

On daemon shutdown, the dataplane actor attempts a bounded graceful
drain: delete rustbgpd-owned remote FDB entries, emit final status, and
exit. The initial timeout target is 5 seconds. If the timeout expires,
the daemon exits and leaves remaining FDB entries for the kernel,
operator tooling, or the next rustbgpd start to reconcile.

The actor never deletes bridges, VXLAN links, kernel-learned local MACs,
or foreign FDB entries on shutdown. Fast restart is handled by the next
startup's initial dump and ownership reconciliation, not by preserving a
special daemon-owned runtime file.

### 8. Failures surface as status, not domain mutation

Netlink errors are dataplane status, not edits to `EvpnInstanceTable`.
The Linux crate returns structured reports:

```rust
pub struct DataplaneReport {
    pub intent_generation: u64,
    pub reconcile_generation: u64,
    pub instance_status: Vec<InstanceDataplaneStatus>,
    pub applied: Vec<AppliedOp>,
    pub failed: Vec<FailedOp>,
}
```

`intent_generation` echoes the `DataplaneIntent::generation` that
produced the report, letting the daemon correlate "I sent desired
snapshot N" with "Linux applied/failed N". `reconcile_generation` is the
dataplane actor's own monotonic reconcile-pass counter for debugging
and metrics.

The daemon turns these reports into logs, metrics, and eventually a
gRPC status surface. `crates/evpn` does not learn that its desired
bridge "failed"; it remains the source of desired truth. The
actual-state failure lives in the dataplane actor.

## Rejected Alternatives

### Edge-triggered netlink event processing

Rejected because netlink notifications can be missed, coalesced, or
arrive around startup dump boundaries. The actor uses events to wake a
level-triggered reconcile loop; the periodic full dump is the source of
repair.

### `mpsc` queue of desired snapshots

Rejected because desired snapshots supersede prior snapshots. A queue
that preserves every intermediate generation can grow under MAC churn
and make the dataplane actor spend time applying obsolete states.

### Raw `rustbgpd_wire::EvpnRoute` in the dataplane API

Rejected because wire types describe NLRI encoding, not local host
intent. The dataplane crate consumes portable domain MAC intent and
kernel snapshots; it should not know how the selected MAC reached the
daemon.

### Dataplane errors mutate `EvpnInstance`

Rejected because desired state and actual state have different
lifetimes. A bridge bind failure is operational status, not a reason to
delete or rewrite the operator's intended EVI.

### `crates/evpn-linux` depends on `crates/rib` or `crates/transport`

Rejected because it would couple route-reflector behavior to local
Linux dataplane concerns. The daemon is the coordinator; the dataplane
crate is a Linux actor.

### rustbgpd creates bridge/VXLAN netdev topology in Gate 7b

Deferred. Creating topology needs schema for device names, underlay
selection, MTU, UDP port, learning mode, VLAN mapping, and cleanup
ownership. Gate 7b observes existing topology and programs owned FDB
entries only.

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
- Switchdev offload is treated as a kernel consequence of bridge/master
  FDB programming, not a separate rustbgpd hardware API.

## Test Obligations

- Keep the Gate 7b runway binary-spawn integration test: start the real
  `rustbgpd` binary with `[[evpn_instances]]`, then query it through a
  real `rustbgpctl evpn instances` subprocess.
- `crates/evpn-linux` must carry diff-loop unit tests over fake
  desired/kernel snapshots: create, no-op, update, delete, foreign-entry
  preservation, and retry-after-failure.
- Privileged netlink tests must live behind an explicit Linux
  namespace/capability gate (`EVPN_LINUX_NETNS=1`). They are valuable,
  but they are not a substitute for pure diff tests.

What landed in PR #34:

- **12 explicit diff cases** in `crates/evpn-linux/src/diff.rs` covering
  create, no-op, update on VTEP change, delete on withdrawal, delete on
  instance NotReady, foreign-static preservation, foreign kernel-learned
  preservation, unbound instance, idempotency, mobility-sequence advance
  triggering update (not recreate), already-gone owned entry, and a
  grounding invariant that emitted keys come from inputs.
- **`InMemoryDataplane`** fake (`crates/evpn-linux/src/in_memory.rs`)
  for actor-level tests without netlink.
- **6 merge-helper tests** in `crates/evpn-linux/src/linux/fdb.rs`
  covering the two-row dump merge (`NTF_SELF`+dst row and `NTF_MASTER`
  row collide on the same `(VNI, MAC)` key) and the combined
  `NUD_NOARP | NUD_PERMANENT` state-bitmask decoder, plus
  per-errno-class permanent-failure classification (EPERM/EACCES →
  `PermissionDenied`, EINVAL → `InvalidArgument`, EOPNOTSUPP →
  `KernelTooOld`, others stay transient).
- **M36 containerlab smoke** (`tests/interop/scripts/test-m36-evpn-vtep-smoke.sh`)
  with rustbgpd as VTEP and FRR as Type 2 originator over iBGP in
  AS 65000. Verifies: bridge + VXLAN topology, foreign-static
  pre-load survives, BGP Established, MAC programmed with the
  bridge-master row + VXLAN-self+dst row both carrying `extern_learn`,
  withdraw cleans up. 8/8 rows pass.
- **Privileged netns dataplane test** (`crates/evpn-linux/tests/netns_dataplane.rs`)
  gated on `EVPN_LINUX_NETNS=1`; runs nightly outside PR-CI.

Total: 1493 workspace tests + 8/8 M36 smoke at the time of PR #34.

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
