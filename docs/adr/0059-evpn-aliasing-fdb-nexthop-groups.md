# ADR-0059: EVPN aliasing dataplane via FDB nexthop groups

**Status:** Accepted; implementation pending (slicing in §6 below)
**Date:** 2026-05-12

## Context

Gate 8 / 8b shipped the EVPN multi-homing control-plane story end
to end: DF election (ADR-0057), Type 4 ES + Type 1 EAD-per-ES /
per-EVI origination, ES-Import RT and ESI Label extcomms, kernel
BUM-suppression on Non-DF peers, mass-withdraw filtering, and
**receive-side aliasing projection** in `crates/evpn/src/aliasing.rs`.
The receive-side projection populates `RemoteMacEntry::alias_vtep_ips`
with the additional VTEP next-hops that have advertised EAD-per-EVI
reachability for the same `(ESI, EthernetTag)` — exactly what RFC
7432 §14 specifies. But the Linux dataplane (`crates/evpn-linux`)
**reads only `remote_vtep_ip` and silently drops the alias list**:
the existing `diff.rs` emits a single-dst `AddRemoteFdb` op, and
`linux/fdb.rs::apply_op` programs one bridge FDB row pointing at the
primary VTEP.

The practical effect is:

- Unicast frames to a multi-homed MAC reach the primary VTEP only.
  The aliases get nothing.
- On primary-VTEP failure, forwarding waits for BGP withdraw +
  reconverge instead of failing over immediately to an already-
  advertised alternate (the whole point of EAD-per-EVI).
- Operators who configure non-zero `[[ethernet_segments]]` for
  multi-homing get the *control plane* of multi-homing but
  unicast traffic still goes single-path, which is worse than the
  single-homed case because the operator believes they're
  multi-homed.

This ADR pins the dataplane mechanism, the portable intent shape
extension required to feed it, and the implementation slicing.

## Decision

### 1. Mechanism: Linux FDB nexthop groups (`NDA_NH_ID` + `NHA_FDB`)

The kernel mechanism for *real* per-flow ECMP across multiple VTEP
destinations for a single bridge-FDB MAC is **FDB nexthop groups**:

1. Create one `RTM_NEWNEXTHOP` per VTEP IP with attributes
   `NHA_ID`, `NHA_FDB` (zero-length flag), `NHA_GATEWAY` (the
   remote VTEP's outer IP). These are **fdb-typed nexthops** — they
   carry no output interface, no encapsulation; they only resolve
   to a remote VTEP IP and are valid only inside an FDB nexthop
   group.
2. Create one `RTM_NEWNEXTHOP` group with `NHA_ID`, `NHA_FDB`, and
   `NHA_GROUP` (an array of `nexthop_grp { id, weight }` entries
   referencing the per-VTEP nexthop IDs).
3. Install the bridge FDB row with `RTM_NEWNEIGH` (AF_BRIDGE,
   ifindex = VXLAN port) carrying `NDA_LLADDR(MAC)` and
   `NDA_NH_ID(group_id)` — **not** `NDA_DST`. The kernel's VXLAN
   driver hashes each skb to one group member, achieving per-flow
   ECMP.

Available since Linux 5.8 (kernel commit
[`38428d68719c`](https://github.com/torvalds/linux/commit/38428d68719c),
May 2020) and iproute2 5.8. Device constraint: the FDB entry's
output device must be a VXLAN netdev. The nexthop group must be
marked `NHA_FDB`; members must each be `NHA_FDB` nexthops with
`NHA_GATEWAY`. Mixing FDB and non-FDB nexthops in one group is
rejected with `EINVAL`. Empty groups are also rejected.

This mechanism is what FRR (`zebra/zebra_evpn_mh.c::zebra_evpn_nhg_update`,
`zebra/rt_netlink.c::netlink_fdb_nhg_update`) implements. Matching
FRR's behaviour means operators get the dataplane they expect.

### 2. Rejected alternative: `bridge fdb append ... dst <ip>`

`bridge fdb append MAC dev vxlanX self dst IP` adds an additional
destination to an existing FDB row. The Linux VXLAN driver treats
the resulting multi-dst entry as **head-end replication / flood
semantics** — every frame matching the MAC is *duplicated* to all
destinations. That's the BUM pattern (used for the all-zeros
multicast / broadcast FDB entry). For unicast traffic to a single
MAC, this is wrong: it bandwidth-multiplies traffic, breaks
per-flow ordering invariants on the remote bridge, and would
silently regress every multi-homed MAC the moment we used it.

We do not consider `bridge fdb append` further.

### 3. Crate stack: raw netlink construction required

`rtnetlink 0.21` and `netlink-packet-route 0.30` (the versions
pinned in `crates/evpn-linux/Cargo.toml`) **expose no nexthop API
at all**:

- `netlink-packet-route 0.30` has no `nexthop` module. The crate's
  `RouteNetlinkMessage` enum has no `NewNextHop` / `DelNextHop`
  variants ([`src/message.rs:333`](https://docs.rs/netlink-packet-route/0.30.0/src/netlink_packet_route/message.rs.html#333)).
- `NDA_NH_ID` is defined but commented out in
  `NeighbourAttribute` ([`src/neighbour/attribute.rs:28`](https://docs.rs/netlink-packet-route/0.30.0/src/netlink_packet_route/neighbour/attribute.rs.html#28)).
- `rtnetlink 0.21` exposes `LinkHandle`, `AddressHandle`,
  `RouteHandle`, `NeighbourHandle`, `RuleHandle`, `QDiscHandle`,
  `TrafficChain/Class/FilterHandle` — no `NextHopHandle`.

We will **construct the netlink messages by hand** through the
`netlink-packet-core` + `netlink-proto` layer that rtnetlink
already pulls in. Concretely a new
`crates/evpn-linux/src/linux/nexthop_raw.rs` module emits
`RTM_NEWNEXTHOP=104` / `RTM_DELNEXTHOP=106` payloads with raw
`NHA_*` attribute packing and routes them through
`rtnetlink::Handle`'s underlying transport. The UAPI constants are
stable (`NHA_ID=1`, `NHA_GROUP=2`, `NHA_FDB=10`, `NDA_NH_ID=13`,
plus the `nexthop_grp { id: u32, weight: u8, resvd1: u8, resvd2: u16 }`
struct), so the hand-rolled layer is a closed scope, not an
ongoing maintenance liability. Upstreaming a `NextHopHandle` to
the `rust-netlink` org is a separate workstream; not blocking.

The same `nexthop_raw` module will also need to encode `NDA_NH_ID`
into the FDB add path — `NeighbourAttribute::Other(DefaultNla)`
with the right type number, since the enum variant is
unimplemented upstream.

### 4. Portable intent shape: add `alias_group_key` to `RemoteMacEntry`

The current `RemoteMacEntry` (`crates/evpn/src/mac.rs:67`) carries:

```rust
pub remote_vtep_ip: IpAddr,
pub mobility_sequence: Option<u32>,
pub alias_vtep_ips: Vec<IpAddr>,
pub source: RemoteMacSource,
```

This is **insufficient identity for refcounting nexthop groups
across MACs**. The kernel memory win — and FRR's design — comes
from keying one nexthop group per `(ESI, EthernetTag)` so every
MAC behind that Ethernet Segment shares one group. With only
`remote_vtep_ip` + `alias_vtep_ips`, the dataplane would have to
reverse-engineer the ESI from the sorted IP set, which:

- Conflates two different `(ESI, EthernetTag)` pairs that happen
  to have identical VTEP membership (e.g., during a migration
  window).
- Forces a re-key whenever a single VTEP joins or leaves the ES,
  even though the ESI / EthernetTag identity is stable.
- Couples the Linux crate to the EVPN domain semantics in a way
  ADR-0054 §1 explicitly rejects.

We extend `RemoteMacEntry` with:

```rust
/// Aliasing group key — present when the originating Type 2
/// carries a non-zero ESI and at least one EAD-per-EVI alias
/// has been observed. Identifies the Ethernet Segment instance
/// (ESI + Ethernet Tag) the MAC sits behind; the dataplane
/// uses it to key one FDB nexthop group per ES so multiple
/// MACs share one kernel resource. `None` for single-homed
/// routes (ESI == ZERO) and for multi-homed routes that
/// haven't yet observed any alias VTEPs.
pub alias_group_key: Option<(EthernetSegmentIdentifier, EthernetTagId)>,
```

Projection (`crates/evpn/src/projection.rs`) already has both
values in scope (lines ~205-227 — `route.esi`, `route.ethernet_tag`)
and only needs to thread them into the constructed entry. The
projection's existing `alias_vtep_ips.is_empty()` check determines
when to populate the key — same gate as `alias_vtep_ips` itself.

### 5. Lifecycle invariants (binding for the implementation)

The kernel ordering and error-handling rules are non-negotiable:

1. **Create order**: per-VTEP fdb-nexthops first, group second,
   FDB row third. Kernel `EINVAL`s on dangling references.
2. **Tear-down order**: FDB row first, group second, members
   third. Kernel `EBUSY`s if a referenced nexthop or group is
   deleted while still in use.
3. **Atomic alias-set change**: re-emit the group with
   `NLM_F_CREATE | NLM_F_REPLACE` on the *same* `nhg_id`. FDB
   rows keep pointing at the group; no forwarding gap.
4. **Empty-group footgun**: kernel rejects 0-member groups. When
   the alias set drains to a single VTEP (or none), the
   dataplane MUST switch the FDB row back to a single-dst
   `NDA_DST` entry and delete the group. The single-MAC,
   single-VTEP case never uses a group.
5. **ID allocation**: use a bitmap allocator keyed by tag-bits
   matching FRR's convention (top bit = "MAC NHG ID space") so
   rustbgpd's IDs never collide with kernel-allocated nexthops
   on the same box. Group ID = hash of `(ESI, EthernetTag)`
   into the reserved range; persistent across a single run, may
   change across daemon restarts (kernel state re-syncs via
   `RTM_GETNEXTHOP` dump on attach).
6. **Refcount across MACs**: maintain `nhg_refs: HashMap<(ESI,
   EthernetTag), HashSet<(VNI, MAC)>>` in owned state. Group
   install on first MAC referencing it; group delete on last
   MAC unreferencing it.
7. **Partial-creation rollback**: if any member-add fails mid-
   sequence (`EEXIST`, transient netlink failure), unwind the
   successfully-installed members and surface the failure so
   the FDB row never gets installed pointing at a half-built
   group.
8. **No multicast notification for hash-bucket rebalances**:
   subscribe to `RTNLGRP_NEXTHOP` so out-of-band `ip nexthop
   del` is observed and reconciled, same level-triggered
   pattern as the rest of the dataplane.

### 6. Implementation slicing

The implementation is **explicitly not** a "wire the data through;
make apply a no-op log" first slice. That would create the false
impression that aliasing-ECMP is partially shipped while
forwarding still goes single-path. Operators reading the gauge or
the docs would draw the wrong conclusion.

The first PR must extend the portable intent shape and pure-logic
projection; subsequent PRs add the kernel primitive and wire it
through. Each slice ships independently green.

#### Slice 1 — portable intent shape + projection (PR-sized: ~half-day)

- Extend `RemoteMacEntry` with `alias_group_key:
  Option<(EthernetSegmentIdentifier, EthernetTagId)>`.
- Update `crates/evpn/src/projection.rs` to populate it from
  `route.esi` / `route.ethernet_tag` whenever
  `alias_vtep_ips.is_empty() == false`.
- Add a pure-function helper `aliasing::group_members(entry: &RemoteMacEntry) -> Vec<IpAddr>`
  returning the sorted, deduplicated `[remote_vtep_ip, ...alias_vtep_ips]`
  set — the canonical group membership the dataplane will key on.
- Unit tests in `projection.rs` covering: ESI == ZERO + no aliases
  → `alias_group_key = None`; ESI != ZERO + aliases → key
  populated; ESI != ZERO + no aliases observed yet → key None
  (we don't pre-create groups for unobserved aliases).
- No dataplane change; existing diff/apply ignores the new field.
- Output: `RemoteMacEntry` is now expressive enough for the
  dataplane to do its job. No operational behaviour change.

#### Slice 2 — raw-netlink `nexthop_raw` module (~day)

- New `crates/evpn-linux/src/linux/nexthop_raw.rs`. Three pure-
  function builders:
  - `build_fdb_nexthop(id: u32, gateway: IpAddr) -> Vec<u8>`
    (RTM_NEWNEXTHOP body with `NHA_ID`, `NHA_FDB` flag,
    `NHA_GATEWAY`).
  - `build_fdb_nexthop_group(id: u32, members: &[(u32, u8)]) -> Vec<u8>`
    (RTM_NEWNEXTHOP body with `NHA_ID`, `NHA_FDB` flag,
    `NHA_GROUP` array of `nexthop_grp` structs).
  - `build_delete_nexthop(id: u32) -> Vec<u8>` (RTM_DELNEXTHOP).
- Plus an `apply_nexthop_op` async helper that wraps the
  rtnetlink `Handle`'s transport, sends the constructed
  `NetlinkMessage`, and awaits an ACK.
- NHID bitmap allocator (`crates/evpn-linux/src/nhid_alloc.rs`):
  tag-bit-tagged range, monotonic within the range, deterministic
  per `(ESI, EthernetTag)` hash (so atomic-replace can target
  the same ID across reconcile passes).
- Pure-function tests asserting the byte-exact wire shape against
  captured `RTM_NEWNEXTHOP` payloads (use `strace -e
  trace=sendmsg` against iproute2 to capture the reference bytes).
- No interaction with the diff or apply layers yet.
- Output: a tested netlink primitive ready to be called.

#### Slice 3 — diff + reconcile actor + owned-state lifecycle (~day)

- Extend `DataplaneOp`:
  - `AddFdbNexthopGroup { nhg_id: u32, members: Vec<(u32, IpAddr)> }`
  - `RemoveFdbNexthopGroup { nhg_id: u32 }`
  - `AddRemoteFdb` / `UpdateRemoteFdb` gain
    `nhid: Option<u32>` — when `Some`, the apply layer emits the
    FDB row with `NDA_NH_ID`; when `None`, the existing
    `NDA_DST` single-dst path.
- Extend `OwnedSet` / `OwnedEntry`:
  - `nhg_refs: HashMap<(ESI, EthernetTag), HashSet<(VNI, MAC)>>`
  - Per-FDB-row `last_applied_nhid: Option<u32>`
- `compute_diff` keys groups by `entry.alias_group_key`. For each
  `(ESI, EthernetTag)` group present in desired:
  - If members differ from `last_applied`: emit
    `AddFdbNexthopGroup` with `NLM_F_REPLACE` (atomic update).
  - Otherwise: no group-level op.
- For each `(VNI, MAC)` in desired:
  - If `alias_group_key == None`: existing single-dst flow.
  - Else: emit `AddRemoteFdb` / `UpdateRemoteFdb` with
    `nhid = Some(allocator.id_for(esi, eth_tag))`.
- Tear-down order enforced via the existing four-phase apply
  ordering (we already have this pattern from slice 6c L3 ownership).
- Unit tests for the diff: alias-set grows, alias-set shrinks
  (including drain-to-one → switch back to single-dst),
  multi-MAC sharing of one group, ESI change on a MAC (group key
  drift), partial-success retry.
- Output: kernel programming end-to-end against the apply path,
  but only validated by mocks. No netns yet.

#### Slice 4 — privileged netns smoke + M40 interop (~half-day)

- New `crates/evpn-linux/tests/netns_aliasing_install.rs` (gated
  on `EVPN_LINUX_NETNS=1`): create a netns with a bridge + VXLAN +
  three CE veths simulating one primary + two aliases, inject a
  synthetic `RemoteMacEntry` with `alias_group_key` populated,
  assert:
  - `ip nexthop show id <nhg>` returns the group with the right
    members.
  - `bridge fdb show dev vxlanX` shows the MAC with the right
    `nhid` (not `dst`).
  - Withdraw cycle removes FDB row, then the group, then the
    members. Foreign nexthop groups (operator-installed
    out-of-band) survive the cycle.
- M40 manual containerlab smoke: three rustbgpd PEs, two of them
  sharing a non-zero ESI for VNI 100, one acting as the consumer.
  Assert the consumer's `bridge fdb show dev vxlan100` carries
  an `nhid`, that `ip nexthop show` shows the group with both
  remote VTEPs as members, and that one of the producer PEs
  going down does NOT cause a forwarding gap on the consumer
  (the alias absorbs the load).
- Docs: `docs/INTEROP.md` M40 row, `docs/evpn-alpha-soak.md`
  aliasing-dataplane bullet flipped to shipped, CHANGELOG entry.
- Output: end-to-end multi-homing forwarding shipped.

## Out of scope for this ADR

- **Weighted ECMP**. Initial impl uses uniform `weight = 1` per
  member. RFC 7432 §14 doesn't mandate weighted distribution;
  future capability if operators ask.
- **Cross-family aliasing** (mixed v4 / v6 VTEP members in one
  group). Same family per group is the simpler model and matches
  FRR. Group key includes the AF implicitly.
- **L3 EVPN aliasing** (Type 5 alongside the primary nexthop).
  Symmetric IRB / slice 6 ships with single-VTEP routes today;
  L3 multi-homing is a separate scope.
- **`RTNLGRP_NEXTHOP` subscription** for out-of-band reconcile.
  The reconcile actor's periodic `RTM_GETNEXTHOP` dump catches
  drift on the existing cadence; sub-second nexthop reconcile is
  a follow-up after slice 4.
- **Upstreaming `NextHopHandle` to `rust-netlink`**. Separate
  workstream. The hand-rolled `nexthop_raw` is scoped to the
  three operations we need; we don't owe upstream a complete
  nexthop API.

## Cross-references

- [ADR-0054](0054-evpn-linux-dataplane-boundary.md) — "Linux
  observes, daemon decides" and the level-triggered reconcile
  model that slice 3 follows.
- [ADR-0057](0057-evpn-gate-8-observable-df-election.md) — the
  control-plane multi-homing context this ADR completes the
  dataplane half of.
- [RFC 7432 §14](https://datatracker.ietf.org/doc/html/rfc7432#section-14)
  — Multi-Homing Aliasing.
- [Linux kernel commit 38428d68719c](https://github.com/torvalds/linux/commit/38428d68719c)
  — nexthop: support for fdb ecmp nexthops (v5.8).
- FRR reference implementation:
  [`zebra/zebra_evpn_mh.c::zebra_evpn_nhg_update`](https://github.com/FRRouting/frr/blob/master/zebra/zebra_evpn_mh.c)
  and [`zebra/rt_netlink.c::netlink_fdb_nhg_update`](https://github.com/FRRouting/frr/blob/master/zebra/rt_netlink.c).
- [`include/uapi/linux/nexthop.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/nexthop.h)
  — UAPI constants (`NHA_ID`, `NHA_GROUP`, `NHA_FDB`, `nexthop_grp`).
- [`netlink-packet-route 0.30.0 src/neighbour/attribute.rs`](https://docs.rs/netlink-packet-route/0.30.0/src/netlink_packet_route/neighbour/attribute.rs.html)
  — confirms `NDA_NH_ID` is unimplemented at the crate level.
