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
`netlink-packet-core` + `netlink-sys` layer. Concretely a new
`crates/evpn-linux/src/linux/nexthop_raw.rs` module emits
`RTM_NEWNEXTHOP` / `RTM_DELNEXTHOP` payloads with raw `NHA_*`
attribute packing.

**Transport: a separate `NETLINK_ROUTE` socket** (opened via
`netlink-sys` directly), **not** the existing
`rtnetlink::Handle`. `Handle::request` is typed as
`NetlinkMessage<RouteNetlinkMessage>`, and `RouteNetlinkMessage`
has no `NewNextHop` / `DelNextHop` / `GetNextHop` variants in
`netlink-packet-route 0.30` — there is no escape hatch on that
path, so an implementer who tries to thread nexthop messages
through the existing `Handle` will burn an afternoon before
hitting that wall. The aliasing-ECMP module opens its own
send/recv socket alongside the existing rtnetlink one and parses
`NetlinkMessage<()>` ACK framing manually; the inner body is the
hand-rolled byte buffer.

**UAPI constants** (pinned by unit tests against
`include/uapi/linux/rtnetlink.h` + `include/uapi/linux/nexthop.h`
+ `include/uapi/linux/neighbour.h` so a kernel-header drift or a
typo gets caught at compile-time):

| Constant            | Value | Source header                            |
|---------------------|-------|------------------------------------------|
| `RTM_NEWNEXTHOP`    | `104` | `uapi/linux/rtnetlink.h`                 |
| `RTM_DELNEXTHOP`    | `105` | `uapi/linux/rtnetlink.h`                 |
| `RTM_GETNEXTHOP`    | `106` | `uapi/linux/rtnetlink.h`                 |
| `NHA_ID`            | `1`   | `uapi/linux/nexthop.h`                   |
| `NHA_GROUP`         | `2`   | `uapi/linux/nexthop.h`                   |
| `NHA_GATEWAY`       | `6`   | `uapi/linux/nexthop.h`                   |
| `NHA_FDB`           | `11`  | `uapi/linux/nexthop.h` (`NHA_MASTER`=10) |
| `NDA_NH_ID`         | `13`  | `uapi/linux/neighbour.h`                 |

Plus the `nexthop_grp { id: u32, weight: u8, resvd1: u8, resvd2: u16 }`
struct from `uapi/linux/nexthop.h`. (Earlier drafts of this ADR
listed `RTM_DELNEXTHOP=106` and `NHA_FDB=10` — both wrong.
`106` is `RTM_GETNEXTHOP`; `10` is `NHA_MASTER`. Picking those
values would have shipped deletes that the kernel parses as
GETs and a flag bit packed at the wrong attribute type. The
constant pin in tests is non-negotiable.)

The hand-rolled layer is a closed scope (three message
builders, one ACK parser, one constants test), not an ongoing
maintenance liability. Upstreaming a `NextHopHandle` to the
`rust-netlink` org is a separate workstream; not blocking.

The same `nexthop_raw` module also encodes `NDA_NH_ID` into the
FDB add path — `NeighbourAttribute::Other(DefaultNla)` with type
`13`, since the enum variant is unimplemented upstream in
`netlink-packet-route 0.30`. That FDB-add path stays on the
existing `rtnetlink::Handle` socket (it's still a `NewNeighbour`
message; only the attribute payload differs).

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

The kernel ordering and error-handling rules are non-negotiable.
Every rule below has a corresponding line reference in FRR's
`zebra/zebra_evpn_mh.c` and `zebra/rt_netlink.c` — we match FRR
unless this ADR explicitly diverges.

1. **Create order**: per-VTEP fdb-nexthops first, group second,
   FDB row third. Kernel `EINVAL`s on dangling references.
2. **Tear-down order**: FDB row first, group second, members
   third. Kernel `EBUSY`s if a referenced nexthop or group is
   deleted while still in use.
3. **Atomic alias-set change**: re-emit the group with
   `NLM_F_CREATE | NLM_F_REPLACE` on the *same* `nhg_id`. FDB
   rows keep pointing at the group; no forwarding gap. (FRR
   reference: `netlink_fdb_nhg_update`, `rt_netlink.c:5207-5263`.)
4. **N → 1 drain keeps the group**, N → 0 tears it down.
   The kernel rejects 0-member groups but a 1-member group is
   legal and stays at MPATH type with `weight=0` (the kernel
   interprets `weight=0` as 1 — see
   `nexthop_grp_weight()` in `uapi/linux/nexthop.h:23-26`). FRR
   keeps a 1-member NHG and leaves dependent FDB rows
   referencing it via `NDA_NH_ID` (no rewrite to `NDA_DST` —
   `zebra_evpn_rem_mac_install` at `zebra_evpn_mac.c:185-239`
   keys on `mac->es && ZEBRA_EVPNES_NHG_ACTIVE`, encodes
   `NDA_NH_ID` not `NDA_DST` for any MAC behind an active ES).
   N → 0 triggers `zebra_evpn_nhg_mac_update` at
   `zebra_evpn_mh.c:1357-1398`: uninstall every dependent
   remote MAC (`zebra_evpn_rem_mac_uninstall(..., force=true)`),
   then `kernel_del_mac_nhg`. **There is no "rewrite the FDB
   row to single-dst `NDA_DST` on drain-to-zero" path**. Match
   this.
5. **VTEP IP change = delete-and-recreate the per-VTEP NH,
   not REPLACE.** FRR keys the per-VTEP nexthop hash by
   `vtep_ip` (`zebra_evpn_l2_nh_find` at
   `zebra_evpn_mh.c:1512`); an ES-VTEP whose IP changes goes
   through `_deref` (frees the old `nh_id` once `ref_cnt == 0`)
   followed by `_ref` (allocates a new `nh_id` for the new IP).
   The parent NHG is then re-emitted via the standard `REPLACE`
   path with the new member set. Don't try to in-place-mutate
   `NHA_GATEWAY` on an existing `nh_id` — the kernel allows it,
   but skipping the realloc would diverge from FRR's invariant
   that `nh_id` is stable for the lifetime of one `vtep_ip`.
6. **ID allocation: deliberately do NOT collide with FRR's
   tag bits.** FRR carves IDs as `(NHG_TYPE << 28) | bitmap_id`
   with `NHG_TYPE_L3 = 0`, `NHG_TYPE_L2_NH = 1`,
   `NHG_TYPE_L2 = 2` (`zebra_nhg.h:179-184`,
   `zebra_evpn_mh.h:255-261`). The per-VTEP L2-NH and the L2-NHG
   share the same bitmap; the type bit is purely for
   debug-discriminability in `ip nexthop show`. **The kernel
   does not enforce per-protocol nexthop-ID ownership** — if
   rustbgpd and FRR were both running on the same box and both
   chose `nh_id = 0x2000_0001`, the second writer's
   `NLM_F_REPLACE` would silently overwrite the first. We
   therefore reserve different tag bits for rustbgpd:
   - per-VTEP L2-NH: `0x3000_0000 | bitmap_id`
   - L2-NHG: `0x4000_0000 | bitmap_id`
   - `bitmap_id` range: `[1, 0x4000]` (matches FRR's
     `EVPN_NH_ID_MAX`; index 0 reserved).
   Allocator is a single `BitVec` of size `0x4001`, shared
   between per-VTEP and NHG IDs; the type bit is OR'd on at
   emit time. Kernel re-sync on attach via `RTM_GETNEXTHOP`
   dump filters by the high nibble so rustbgpd never claims
   ownership of an FRR-tagged ID.
7. **Refcount across MACs**: maintain `nhg_refs: HashMap<(ESI,
   EthernetTag), HashSet<(VNI, MAC)>>` in owned state. Group
   install on first MAC referencing it; group delete on last
   MAC unreferencing it.
8. **Partial-creation rollback**: if any member-add fails mid-
   sequence (transient netlink failure), unwind the
   successfully-installed members and surface the failure so
   the FDB row never gets installed pointing at a half-built
   group. **`EEXIST` on `RTM_NEWNEXTHOP` and `ENOENT` on
   `RTM_DELNEXTHOP` are benign** — FRR uses
   `NLM_F_CREATE | NLM_F_REPLACE` on every emit (so `EEXIST`
   doesn't happen in practice) and ignores the return of
   `netlink_fdb_nh_del` (`zebra_evpn_mh.c:1544-1552`). Mirror
   this: log at INFO, do not unwind. `EINVAL` on a group with
   a dangling member is a real failure (caller violated the
   create order rule); surface it as an error.
9. **CVE-2025-39851 hard-guard**: kernel had a VXLAN NULL-pointer
   deref when refreshing an FDB entry that points to a nexthop
   group **while learning is enabled on the VXLAN device**.
   Fixed by mainline commits `4ff4f3104da6`, `0e8630f24c14`,
   `6ead38147ebb`; backported to stable. **The reconcile actor
   MUST refuse to install an FDB-NHG row unless the target
   VXLAN device has `learning off`.** Slice 6c's IP-VRF
   readiness probe already insists on `nolearning` for the
   L3VXLAN device; the L2VXLAN path needs the same guard. The
   error message cites the CVE so an operator with a misconfigured
   bridge sees what they're walking into.
10. **Explicit failure logging** (improves on FRR). When a
    Type-2 with non-zero ESI cannot be installed because no
    member VTEPs are resolved, FRR currently fails silently —
    `zebra_evpn_rem_mac_install` skips the install but emits
    nothing. Operators chasing "why isn't my multi-homed MAC
    forwarding?" have no log line to grep. rustbgpd must log
    at `warn!` with `(ESI, EthernetTag, MAC, observed_aliases)`
    so the failure mode is visible.
11. **Initial drift recovery via periodic `RTM_GETNEXTHOP` dump**:
    the reconcile actor walks the kernel's nexthop table on every
    periodic pass (level-triggered, same cadence as the existing
    FDB / link / route dumps) and reconciles owned state against
    the result. Filter by the rustbgpd tag-bits (`0x3000_0000` /
    `0x4000_0000`) so the dump-side compare only touches IDs we
    own. Out-of-band `ip nexthop del` is caught on the next dump
    rather than synchronously — sub-second nexthop reconcile via
    `RTNLGRP_NEXTHOP` subscription is a follow-up after slice 4
    (mirrors the same trade-off the original slice 6a route
    observation took: dump first, multicast wake second).

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

- **Vendor source**: start from
  [`rust-netlink/netlink-packet-route` PR #225](https://github.com/rust-netlink/netlink-packet-route/pull/225)
  (MIT-licensed, stalled since Feb on a maintainer ask for
  `nlmon` byte-fixture tests). The PR already contains a
  `nexthop` module with `RouteNetlinkMessage::{New,Del,Get}Nexthop`
  + `NexthopAttribute::{Id, Group, Fdb, Gateway, ...}` +
  `NexthopGroupEntry { id, weight, resvd1, resvd2 }` Emitable
  — exactly the surface area we need. Vendor it into
  `crates/evpn-linux/src/linux/nexthop_raw/` rather than
  forking the upstream crate; we'll satisfy the maintainer's
  fixture-test requirement and then offer it back upstream.
- Three message builders the dataplane calls directly (kept as
  thin Rust wrappers over the vendored types so the call sites
  read as `NexthopMsg::add_fdb_member(id, gateway)` /
  `NexthopMsg::add_fdb_group(id, &members)` /
  `NexthopMsg::del(id)`).
- **Wire-shape mirror of FRR** (verified against
  `netlink_fdb_nhg_update` at `zebra/rt_netlink.c:5207-5263`):
  - Header: `nlmsg_type = RTM_NEWNEXTHOP`,
    `nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE`
    (FRR omits `NLM_F_ACK`; we keep it because we want strict
    ack semantics in tokio).
  - `nhmsg { nh_family = AF_UNSPEC, nh_scope = 0, nh_protocol = 0,
    resvd = 0, nh_flags = 0 }`.
  - Attributes in this order: `NHA_ID(u32)`, `NHA_FDB` (zero-length
    flag), then either `NHA_GATEWAY(IP)` for a per-VTEP member
    or `NHA_GROUP(&[nexthop_grp])` for a group. `NHA_GROUP_TYPE`
    is **not** emitted — kernel defaults to `NEXTHOP_GRP_TYPE_MPATH = 0`.
  - `struct nexthop_grp { id: u32, weight: u8, weight_high: u8,
    resvd2: u16 }` = exactly 8 bytes, no implicit padding. Array
    stride is naturally 4-aligned. `weight = 0` means "weight 1"
    per `nexthop_grp_weight()` in `uapi/linux/nexthop.h:23-26` —
    so uniform-weight ECMP is just `weight: 0` per member.
  - DEL: `nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK`, body =
    `NHA_ID(u32)` only. No `NHA_FDB`, no `NHA_GROUP`.
- **Transport**: `apply_nexthop_op` async helper uses the
  module's own dedicated `NETLINK_ROUTE` socket (opened via
  `netlink-sys::TokioSocket` with the `tokio_socket` feature so
  it integrates cleanly with the existing tokio runtime), sends
  the constructed raw nexthop message, and parses the ACK via
  `NetlinkMessage::<()>::deserialize` — `ErrorMessage::code` is
  `None` for an ACK and `Some(-errno)` for a real error. **Does
  NOT route through the existing `rtnetlink::Handle`** —
  `Handle::request` is typed `NetlinkMessage<RouteNetlinkMessage>`
  and the vendored payload type doesn't fit. The reconcile
  actor holds both sockets (one rtnetlink for the existing
  FDB / link / route plumbing, one raw for nexthop).
- NHID bitmap allocator (`crates/evpn-linux/src/nhid_alloc.rs`):
  single `BitVec` of size `0x4001` shared between per-VTEP L2-NH
  and L2-NHG IDs (mirroring FRR's design). Tag bits OR'd on at
  emit time: per-VTEP = `0x3000_0000 | id`, NHG = `0x4000_0000 | id`
  (deliberately offset from FRR's `0x1000_0000` / `0x2000_0000`
  so concurrent FRR + rustbgpd installs are distinguishable in
  `ip nexthop show` and never collide on `NLM_F_REPLACE`).
- **Byte-fixture test**: capture FRR's actual wire bytes via
  `strace -e trace=sendto -x -s 4096 ip nexthop add id 200 group 12/13 fdb`
  and `... bridge fdb add 00:11:22:33:44:55 dev vxlan0 nhid 200 self`
  on a netns. Drop the captured `\x..` blobs into
  `tests/fixtures/` as byte arrays; the unit test asserts our
  builder produces bytewise-identical output. This is also the
  test the upstream PR #225 maintainer is asking for, so we're
  building it once for both sides.
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
  - `bridge fdb show dev vxlanX | grep nhid` matches the
    iproute2 print format `<mac> dev vxlanX nhid <decimal> self
    extern_learn` (regex anchor:
    `\b<mac>.*\bdev vxlan\S+\b.*\bnhid (\d+)\b.*\bself\b`;
    `extern_learn` and `offload` are conditional on
    `NTF_EXT_LEARNED` / `NTF_OFFLOADED`).
  - Withdraw cycle removes FDB row, then the group, then the
    members. Foreign nexthop groups (operator-installed
    out-of-band) survive the cycle.
- M40 manual containerlab smoke: three rustbgpd PEs, two of them
  sharing a non-zero ESI for VNI 100, one acting as the consumer.
  Assert the consumer's `bridge fdb show dev vxlan100` carries
  an `nhid`, that `ip nexthop show fdb` shows the group with
  both remote VTEPs as members, and that one of the producer
  PEs going down does NOT cause a forwarding gap on the
  consumer (the alias absorbs the load).
- Pin **`runs-on: ubuntu-24.04`** (not `ubuntu-latest`) so the
  privileged netns step doesn't drift if GitHub rolls the
  hosted image. The 24.04 Azure-tuned image ships kernel
  ≥ 6.17, iproute2 6.1 (`bridge fdb add ... nhid` supported),
  `vrf` module built, and `CAP_NET_ADMIN` available inside
  `unshare -rn` — all the prereqs satisfied. iproute2 < 5.10
  prints `nhid` differently (or not at all), so the version
  pin matters for the regex matcher above.
- Docs: `docs/INTEROP.md` M40 row, `docs/evpn-alpha-soak.md`
  aliasing-dataplane bullet flipped to shipped, CHANGELOG entry.
- Output: end-to-end multi-homing forwarding shipped.

### 7. Configuration knobs

- **`apply_aliasing_ecmp = true`** (default, but operator-
  flippable per-instance in `[[evpn_instances]]`) — gates the
  whole feature. Off means the dataplane keeps single-dst FDB
  rows and ignores `alias_group_key`. Useful for incident
  response if the feature regresses in a release.
- **`share_l2_nhg = true`** (default, per-instance). Mirrors
  NVIDIA Cumulus's `evpn.multihoming.shared_l2_groups`. With
  `true`, one NHG per `(ESI, EthernetTag)` is shared across
  every MAC behind that ES (memory win). With `false`, each
  MAC gets its own NHG (faster ES-flap failover because there's
  no thundering-herd FDB churn). Soak isolation knob; default
  matches FRR's behaviour.

### 8. Kernel + distro compatibility

- **Minimum kernel**: 5.8 (FDB-NHG feature merged via commit
  `38428d68719c`, "nexthop: support for fdb ecmp nexthops",
  net-next May 2020 → mainline v5.8). Distro coverage is
  universal across modern distros: Debian 11+ (5.10), Ubuntu
  22.04+ (5.15 / HWE 6.5), RHEL 9+ (5.14). No mainstream distro
  builds ≥ 5.10 without the nexthop subsystem; the only way to
  hit "feature missing" is a custom `tinyconfig` build.
- **Minimum iproute2**: 5.10 for `bridge fdb show ... nhid`
  printing. Older versions print the FDB row but elide the
  `nhid` field, which would break the slice 4 regex matcher.
- **Sysctl `net.ipv4.nexthop_compat_mode = 1`** (default). With
  it set, every nexthop replace emits a per-FIB-entry
  `RTM_NEWROUTE` notification — on a 100k-MAC table this is a
  netlink storm. We do NOT depend on the storm; the soak
  harness should toggle `1 → 0` mid-run and assert the daemon
  keeps converging. Document this in the runbook so an
  operator on a tuned distro (some ship `0` by default) doesn't
  hit surprises.
- **CVE-2025-39851** mitigation (see §5 rule 9): refuse to
  install an FDB-NHG row when the target VXLAN device has
  `learning on`. The kernel had a NULL-pointer-deref when
  refreshing an FDB entry pointing to a nexthop group with
  learning enabled; fix train `4ff4f3104da6`, `0e8630f24c14`,
  `6ead38147ebb` landed in mainline 6.17-rc and is backported
  to stable. Slice 6c IRB already enforces `nolearning` on the
  L3VXLAN; slice 2 must enforce the same for the L2VXLAN path.

## Out of scope for this ADR

- **Weighted ECMP**. Initial impl uses uniform `weight = 0` per
  member, which the kernel reads as weight 1 per
  `nexthop_grp_weight()`. RFC 7432 §14 doesn't mandate weighted
  distribution; future capability if operators ask.
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
- **Resilient nexthop groups** (`NEXTHOP_GRP_TYPE_RES` /
  `NHA_RES_GROUP` / `NHA_RES_BUCKET`). Adds smooth bucket
  rebalancing across member changes — operationally nicer but
  needs kernel 5.12+ and changes the diagnostic surface. Defer
  until the basic MPATH path is stable.
- **Upstreaming `NextHopHandle` to `rust-netlink`**. Separate
  workstream — once the vendored `nexthop_raw` module has its
  byte-fixture tests (which slice 2 writes anyway), offer them
  as the missing piece for PR #225 / #149 upstream. Not
  blocking implementation.

## Cross-references

### Internal

- [ADR-0054](0054-evpn-linux-dataplane-boundary.md) — "Linux
  observes, daemon decides" and the level-triggered reconcile
  model that slice 3 follows.
- [ADR-0057](0057-evpn-gate-8-observable-df-election.md) — the
  control-plane multi-homing context this ADR completes the
  dataplane half of.

### Specifications

- [RFC 7432 §14](https://datatracker.ietf.org/doc/html/rfc7432#section-14)
  — Multi-Homing Aliasing.

### Linux kernel

- [Commit 38428d68719c](https://github.com/torvalds/linux/commit/38428d68719c)
  — nexthop: support for fdb ecmp nexthops (v5.8).
- [`include/uapi/linux/nexthop.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/nexthop.h)
  — UAPI constants (`NHA_ID=1`, `NHA_GROUP=2`, `NHA_FDB=11`,
  `nexthop_grp { id, weight, weight_high, resvd2 }`).
- [`include/uapi/linux/neighbour.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/neighbour.h)
  — `NDA_NH_ID = 13`.
- [CVE-2025-39851](https://www.suse.com/security/cve/CVE-2025-39851.html)
  — VXLAN NPD when refreshing FDB-NHG with learning ON. Slice
  2 hard-guards against this.
- [`net.ipv4.nexthop_compat_mode` sysctl](https://docs.kernel.org/networking/ip-sysctl.html)
  — defaults to 1; flip to 0 to silence the per-FIB-entry
  notification storm on nexthop replace.

### FRR reference implementation (we mirror unless noted)

- [`zebra/zebra_evpn_mh.c::zebra_evpn_nhg_update`](https://github.com/FRRouting/frr/blob/master/zebra/zebra_evpn_mh.c)
  — group build from `es_vtep_list` (sorted by VTEP IP ascending,
  deduplicated by `nh_ip_table` hash, member skip on missing
  per-VTEP NH).
- [`zebra/zebra_evpn_mh.c::zebra_evpn_nhg_mac_update`](https://github.com/FRRouting/frr/blob/master/zebra/zebra_evpn_mh.c)
  — N→0 collapse path (uninstall dependent MACs, then
  `kernel_del_mac_nhg`).
- [`zebra/zebra_evpn_mac.c::zebra_evpn_rem_mac_install`](https://github.com/FRRouting/frr/blob/master/zebra/zebra_evpn_mac.c)
  — `NDA_NH_ID` vs `NDA_DST` choice (keys on
  `mac->es && ZEBRA_EVPNES_NHG_ACTIVE`).
- [`zebra/rt_netlink.c::netlink_fdb_nhg_update`](https://github.com/FRRouting/frr/blob/master/zebra/rt_netlink.c)
  — canonical `RTM_NEWNEXTHOP` wire shape.
- [`zebra/zebra_evpn_mh.h`](https://github.com/FRRouting/frr/blob/master/zebra/zebra_evpn_mh.h)
  — `EVPN_NH_ID_MAX = 16*1024`, type-bit constants. We diverge
  on tag-bit values to avoid collision.

### Rust netlink ecosystem

- [PR rust-netlink/netlink-packet-route#225](https://github.com/rust-netlink/netlink-packet-route/pull/225)
  — vendored as slice 2's starting point. MIT-licensed.
- [PR rust-netlink/rtnetlink#149](https://github.com/rust-netlink/rtnetlink/pull/149)
  — `NexthopMessageBuilder` shape; no FDB builder yet.
- [`al8n/getifs` Rust raw-netlink scaffold](https://github.com/al8n/getifs/blob/main/src/linux/netlink.rs)
  — 24-byte `nlmsghdr + nhmsg` framing reference for the dump
  path.
- [`netlink-sys::TokioSocket`](https://github.com/rust-netlink/netlink-sys/blob/main/src/tokio.rs)
  — `AsyncFd<Socket>` wrapper, integrates with tokio via the
  `tokio_socket` feature.

### Operator references

- [NVIDIA Cumulus EVPN Multihoming](https://docs.nvidia.com/networking-ethernet-software/cumulus-linux-514/Network-Virtualization/Ethernet-Virtual-Private-Network-EVPN/EVPN-Multihoming/)
  — `evpn.multihoming.shared_l2_groups` knob is the precedent
  for our `share_l2_nhg`.
- [SONiC EVPN_VxLAN_Multihoming HLD](https://github.com/sonic-net/SONiC/blob/master/doc/vxlan/EVPN/EVPN_VxLAN_Multihoming.md)
  — confirms SONiC reuses FRR/zebra's identical netlink path;
  the SAI side is out of scope for us.
- [`ip-nexthop(8)` man page](https://man7.org/linux/man-pages/man8/ip-nexthop.8.html)
  — `ip nexthop show fdb`, `ip nexthop bucket show id N`,
  `ip nexthop monitor`.
