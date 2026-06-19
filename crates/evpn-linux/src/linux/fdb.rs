//! Bridge FDB program / withdraw / dump via netlink `RTM_NEWNEIGH` /
//! `RTM_DELNEIGH` / `RTM_GETNEIGH`.
//!
//! ## Wire shape
//!
//! Linux EVPN remote MACs are programmed with the
//! `bridge fdb add MAC dev vxlanX master dst REMOTE_VTEP` shape on
//! the wire — i.e., the netlink message's `ifindex` field is the
//! **VXLAN port** ifindex (not the bridge), and the entry carries
//! `NTF_MASTER` so the bridge owns the entry. We program with
//! `NTF_EXT_LEARNED | NTF_MASTER` and `NUD_NOARP` so kernel-learned
//! entries (which lack `NTF_EXT_LEARNED`) remain visible to the diff
//! loop as foreign and never deleted by mistake.
//!
//! ## VNI resolution on dump
//!
//! Bridge FDB messages carry the VXLAN ifindex in `header.ifindex`.
//! For traditional VXLAN devices, the link-cache's
//! `vxlan_ifindex_to_vni` map turns that back into an `EvpnInstanceId`.
//! Collect-metadata / SVD VXLAN devices can carry many VNIs on one
//! ifindex, so rows on an observed SVD ifindex must include an explicit
//! VNI attribute (`NDA_SRC_VNI` or `NDA_VNI`) before they enter the
//! snapshot. Entries whose ifindex can't be attributed are silently
//! dropped from the snapshot.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;

use futures::stream::TryStreamExt;
use netlink_packet_core::Nla;
use netlink_packet_route::AddressFamily;
use netlink_packet_route::neighbour::{
    NeighbourAddress, NeighbourAttribute, NeighbourFlags, NeighbourMessage, NeighbourState,
};
use netlink_packet_route::route::{RouteProtocol, RouteType};
use rtnetlink::Handle;
use rustbgpd_evpn::{EvpnInstanceId, MacAddress};

use crate::dataplane::DataplaneOp;
use crate::error::DataplaneError;
use crate::snapshot::{KernelFdbEntry, KernelFdbFlags};

use super::links::{LinkCache, matching_svd_vxlan_ports, unique_fdb_vxlan_target_for_vni};

/// `NDA_NH_ID` neighbour attribute (kind = 13). Not exposed as a typed
/// variant by `netlink-packet-route 0.30`; we read it via the
/// `Nla` trait's `kind()` accessor on the `Other(DefaultNla)` escape
/// hatch.
const NDA_NH_ID: u16 = 13;

/// `NUD_NOARP` (no-arp) — neighbor entries in this state do not
/// participate in ARP resolution.
const NUD_NOARP: u16 = 0x40;
/// `NUD_PERMANENT` — entry never auto-ages.
const NUD_PERMANENT: u16 = 0x80;
/// `NUD_NOARP | NUD_PERMANENT` — the entry-state bitmask Linux uses
/// for non-expiring control-plane-owned FDB entries (matching what
/// iproute2's `bridge fdb add ... extern_learn` sends on the wire).
/// Centralized here so both [`apply_op`] and the dump-side decoder
/// use the same constant.
const NUD_NOARP_PERMANENT: u16 = NUD_NOARP | NUD_PERMANENT;

/// Dump every bridge FDB entry in the kernel and key them by
/// `(EvpnInstanceId, Option<VLAN>, MacAddress)`.
///
/// Each FDB entry's `header.ifindex` points at the **VXLAN port** for
/// bridge-family neighbours. We map traditional VXLAN rows via the
/// link cache's `vxlan_ifindex_to_vni` table. Rows on known
/// collect-metadata / SVD ports must carry explicit VNI metadata,
/// because their ifindex no longer identifies a single VNI.
///
/// ## Multi-row merge
///
/// A single rustbgpd-programmed `(VNI, MAC)` produces *two* rows on
/// the kernel side: a `NTF_SELF` row carrying `dst` (the VXLAN-encap
/// entry on vxlanX), and a `NTF_MASTER` row carrying no `dst` (the
/// bridge-FDB entry on br100). Both rows have `header.ifindex ==
/// vxlan_ifindex` and `LinkLayerAddress == MAC`, so they collide on
/// the same map key. If we let the second row overwrite the first
/// blindly, whichever leg the kernel emits last wins — and if it's
/// the master leg, [`KernelFdbEntry::dst`] becomes `None` and the
/// next [`crate::compute_diff`] pass would emit a redundant
/// `UpdateRemoteFdb` (because `desired.dst != None != kernel.dst`)
/// every reconcile. [`merge_fdb_rows`] folds the two rows into one:
/// `dst` is preserved if any contributing row had it, flags OR
/// together, and the state bitmask covers all observed NUD bits.
pub(crate) async fn dump_fdb(
    handle: &Handle,
    cache: &LinkCache,
) -> Result<HashMap<(EvpnInstanceId, Option<u16>, MacAddress), KernelFdbEntry>, DataplaneError> {
    let mut out: HashMap<(EvpnInstanceId, Option<u16>, MacAddress), KernelFdbEntry> =
        HashMap::new();
    let mut req = handle.neighbours().get();
    req.message_mut().header.family = AddressFamily::Bridge;
    let mut stream = req.execute();
    while let Some(msg) = stream
        .try_next()
        .await
        .map_err(|e| DataplaneError::Other(format!("fdb dump: {e}")))?
    {
        let Some((key, entry)) = parse_fdb_entry(&msg, cache) else {
            continue;
        };
        match out.get_mut(&key) {
            None => {
                out.insert(key, entry);
            }
            Some(existing) => merge_fdb_rows(existing, &entry),
        }
    }
    Ok(out)
}

/// Fold `incoming` into `existing` for the same `(VNI, MAC)` key.
///
/// `dst` is preserved if either row has one (the VXLAN-self row
/// carries it, the bridge-master row doesn't); flag bools OR
/// together so an entry that has both `extern_learn` (set by
/// rustbgpd) and `master` (set by the bridge-FDB plumbing) reads
/// correctly downstream. Pure helper kept testable in isolation.
fn merge_fdb_rows(existing: &mut KernelFdbEntry, incoming: &KernelFdbEntry) {
    if existing.dst.is_none() && incoming.dst.is_some() {
        existing.dst = incoming.dst;
    }
    // Preserve NDA_NH_ID across the self/master split. Kernel
    // currently emits the nh_id only on the self row (the VXLAN-encap
    // entry); if a future kernel emits it on either or both, the
    // merge stays correct.
    if existing.nh_id.is_none() && incoming.nh_id.is_some() {
        existing.nh_id = incoming.nh_id;
    }
    // Same shape for the ADR-0082 NDA_PROTOCOL stamp: mainline kernels
    // never emit it for FDB rows, and a future kernel that does may
    // emit it on either leg.
    if existing.protocol.is_none() && incoming.protocol.is_some() {
        existing.protocol = incoming.protocol;
    }
    existing.flags.extern_learn |= incoming.flags.extern_learn;
    existing.flags.permanent |= incoming.flags.permanent;
    existing.flags.noarp |= incoming.flags.noarp;
    existing.flags.master |= incoming.flags.master;
    existing.flags.self_flag |= incoming.flags.self_flag;
}

type FdbSnapshotRow = ((EvpnInstanceId, Option<u16>, MacAddress), KernelFdbEntry);

fn parse_fdb_entry(msg: &NeighbourMessage, cache: &LinkCache) -> Option<FdbSnapshotRow> {
    if msg.header.family != AddressFamily::Bridge {
        return None;
    }
    // Bridge-family FDB header.ifindex points at the VXLAN port, not
    // the bridge. (For non-VXLAN bridge ports it's the slave ifindex,
    // but those aren't EVPN-managed so we drop them via the
    // attribution lookup below.)
    let port_ifindex = msg.header.ifindex;

    let mut mac: Option<MacAddress> = None;
    let mut dst: Option<std::net::IpAddr> = None;
    let mut nh_id: Option<u32> = None;
    let mut protocol: Option<u8> = None;
    let mut vlan: Option<u16> = None;
    let mut explicit_vni: Option<u32> = None;
    for attr in &msg.attributes {
        match attr {
            NeighbourAttribute::LinkLayerAddress(bytes) if bytes.len() == 6 => {
                let mut arr = [0u8; 6];
                arr.copy_from_slice(bytes);
                mac = Some(MacAddress::new(arr));
            }
            NeighbourAttribute::Destination(addr) => match addr {
                NeighbourAddress::Inet(v4) => dst = Some(std::net::IpAddr::V4(*v4)),
                NeighbourAddress::Inet6(v6) => dst = Some(std::net::IpAddr::V6(*v6)),
                _ => {}
            },
            // NDA_NH_ID (kind = 13) — `netlink-packet-route 0.30` doesn't
            // expose a typed variant, so the kernel sends it through the
            // `Other` escape hatch with a 4-byte native-endian payload.
            // `DefaultNla` keeps its fields private; we read via the
            // `Nla` trait's `kind()` + `emit_value()` accessors.
            NeighbourAttribute::Other(default_nla)
                if Nla::kind(default_nla) == NDA_NH_ID && Nla::value_len(default_nla) == 4 =>
            {
                let mut bytes = [0u8; 4];
                Nla::emit_value(default_nla, &mut bytes);
                nh_id = Some(u32::from_ne_bytes(bytes));
            }
            // NDA_PROTOCOL (ADR-0082 ownership stamp). Mainline
            // AF_BRIDGE never returns it today; parsed so the
            // prefer-mode ownership check engages automatically once
            // kernel FDB support lands. Stored as the raw
            // `rtm_protocol` byte — the snapshot types are
            // platform-independent and don't see netlink enums.
            NeighbourAttribute::Protocol(p) => protocol = Some(u8::from(*p)),
            NeighbourAttribute::Vlan(v) => vlan = Some(*v),
            // SVD / collect-metadata VXLAN rows need an explicit
            // VNI because the VXLAN ifindex no longer identifies one
            // VNI. `src_vni` is the bridge FDB spelling for "the VNI
            // this entry belongs to"; accept `vni` too for kernels /
            // iproute2 paths that echo the destination-VNI attribute
            // on dump.
            NeighbourAttribute::SourceVni(v) | NeighbourAttribute::Vni(v) => match explicit_vni {
                Some(existing) if existing != *v => return None,
                Some(_) => {}
                None => explicit_vni = Some(*v),
            },
            _ => {}
        }
    }
    let mac = mac?;
    let from_svd;
    let vni_raw = if let Some(vni) = cache.vxlan_ifindex_to_vni.get(&port_ifindex) {
        if let Some(explicit) = explicit_vni
            && explicit != *vni
        {
            return None;
        }
        from_svd = false;
        *vni
    } else if cache.svd_vxlan_ifindexes.contains(&port_ifindex) {
        from_svd = true;
        explicit_vni?
    } else {
        return None;
    };
    if from_svd && vlan.is_none() {
        vlan = infer_svd_bridge_vlan(cache, port_ifindex, vni_raw);
    }
    let vni = EvpnInstanceId::new(vni_raw).ok()?;

    let mut flags = KernelFdbFlags::default();
    let hf = msg.header.flags;
    if hf.contains(NeighbourFlags::ExtLearned) {
        flags.extern_learn = true;
    }
    if hf.contains(NeighbourFlags::Own) {
        flags.self_flag = true;
    }
    // `NeighbourFlags::Controller` is the netlink-packet-route
    // spelling for `NTF_MASTER` — the bit set by `bridge fdb add
    // ... master`.
    if hf.contains(NeighbourFlags::Controller) {
        flags.master = true;
    }
    decode_state(msg.header.state, &mut flags);

    Some((
        (vni, vlan, mac),
        KernelFdbEntry {
            mac,
            vlan,
            dst,
            nh_id,
            protocol,
            flags,
        },
    ))
}

fn infer_svd_bridge_vlan(cache: &LinkCache, ifindex: u32, vni: u32) -> Option<u16> {
    let mut found = None;
    for ((bridge_name, bridge_vlan), bound_vni) in &cache.local_mac_vlan_bindings {
        if *bound_vni != Some(vni) {
            continue;
        }
        let Some(bridge) = cache.bridges.get(bridge_name) else {
            continue;
        };
        if !matching_svd_vxlan_ports(bridge, *bridge_vlan, vni)
            .iter()
            .any(|svd| svd.ifindex == ifindex)
        {
            continue;
        }
        match found {
            None => found = Some(*bridge_vlan),
            Some(existing) if existing == *bridge_vlan => {}
            Some(_) => return None,
        }
    }
    found
}

/// Decode an `ndm_state` value into the flag fields we care about.
///
/// The crate's [`NeighbourState`] enum has separate `Noarp` and
/// `Permanent` variants, but iproute2 sends the combined bitmask
/// `NUD_NOARP | NUD_PERMANENT` for control-plane-owned entries
/// (which is what we send too — see [`apply_op`]). Newer kernels
/// also emit the same combined state in dump replies. We use the
/// `Other(bits)` escape hatch to capture both bits in one pass so a
/// "permanent `extern_learn`" entry surfaces with both
/// [`KernelFdbFlags::permanent`] and [`KernelFdbFlags::noarp`] set.
fn decode_state(state: NeighbourState, flags: &mut KernelFdbFlags) {
    match state {
        NeighbourState::Permanent => flags.permanent = true,
        NeighbourState::Noarp => flags.noarp = true,
        NeighbourState::Other(bits) => {
            if bits & NUD_PERMANENT != 0 {
                flags.permanent = true;
            }
            if bits & NUD_NOARP != 0 {
                flags.noarp = true;
            }
        }
        _ => {}
    }
}

/// Build the `RTM_NEWNEIGH` message for a single-dst remote-MAC FDB
/// row — the `bridge fdb add MAC dev vxlanX master dst R self
/// extern_learn` wire shape:
///
/// - `NTF_SELF` + `NDA_DST` → VXLAN-self encap row on vxlanX (gives
///   the VXLAN driver the tunnel target),
/// - `NTF_MASTER` → bridge-FDB row on br100 (the MAC is reachable
///   via vxlanX),
/// - `NTF_EXT_LEARNED` → distinguishes our entries from
///   kernel-learned ones at FDB dump time.
///
/// `ndm_state` must carry both `NUD_NOARP` and `NUD_PERMANENT` so the
/// entry is non-expiring. The crate's `NeighbourState` enum doesn't
/// represent the combined bitmask, so we use the `Other` escape hatch
/// with the shared `NUD_NOARP_PERMANENT` constant.
///
/// The message also carries the ADR-0082 `NDA_PROTOCOL = RTPROT_BGP`
/// ownership stamp. Mainline `AF_BRIDGE` silently drops the attribute
/// (`rtnl_fdb_add` parses with a NULL policy — it never errors and
/// never round-trips in dumps), so this is a forward-compatible no-op
/// on current kernels, exactly FRR's posture: when bridge/vxlan
/// support merges, already-deployed daemons start writing effective
/// stamps with no upgrade.
fn build_remote_fdb_message(
    vxlan_ifindex: u32,
    mac: MacAddress,
    dst: IpAddr,
    vlan: Option<u16>,
    source_vni: Option<EvpnInstanceId>,
) -> NeighbourMessage {
    let mut msg = NeighbourMessage::default();
    msg.header.family = AddressFamily::Bridge;
    msg.header.ifindex = vxlan_ifindex;
    msg.header.state = NeighbourState::Other(NUD_NOARP_PERMANENT);
    msg.header.flags =
        NeighbourFlags::Own | NeighbourFlags::Controller | NeighbourFlags::ExtLearned;
    msg.header.kind = RouteType::Unspec;
    msg.attributes
        .push(NeighbourAttribute::LinkLayerAddress(mac.octets().to_vec()));
    msg.attributes
        .push(NeighbourAttribute::Destination(match dst {
            IpAddr::V4(v4) => NeighbourAddress::Inet(v4),
            IpAddr::V6(v6) => NeighbourAddress::Inet6(v6),
        }));
    if let Some(vlan) = vlan {
        msg.attributes.push(NeighbourAttribute::Vlan(vlan));
    }
    if let Some(vni) = source_vni {
        msg.attributes
            .push(NeighbourAttribute::SourceVni(vni.as_u32()));
    }
    msg.attributes
        .push(NeighbourAttribute::Protocol(RouteProtocol::Bgp));
    msg
}

/// Apply one [`DataplaneOp`] against the kernel.
///
/// Mirrors the iproute2 `bridge fdb add MAC dev vxlanX master dst
/// REMOTE self extern_learn` shape, verified via `strace` on
/// iproute2 itself. iproute2 sends a single `RTM_NEWNEIGH`
/// carrying `NTF_SELF | NTF_MASTER | NTF_EXT_LEARNED` flags +
/// `NDA_DST` + `ndm_state = NUD_NOARP | NUD_PERMANENT`; the kernel
/// programs both rows from that one message:
///
/// 1. The **VXLAN-self+dst row** on the VXLAN port — tells the
///    VXLAN driver "for this MAC, tunnel to REMOTE". Without this
///    row the data plane can't encap; the bridge would forward the
///    frame to vxlanX but vxlanX wouldn't know where to send it.
/// 2. The **bridge-master row** on br100 — tells the bridge "this
///    MAC is reachable via vxlanX". Without this row the bridge
///    forwards by flood instead of direct unicast through the
///    tunnel.
///
/// `NTF_EXT_LEARNED` distinguishes rustbgpd-programmed entries
/// from kernel-learned and operator-static ones at dump time;
/// `NUD_NOARP | NUD_PERMANENT` keeps the entry from auto-aging.
/// `.replace()` makes Add/Update idempotent.
///
/// `Remove` symmetrically sends one `RTM_DELNEIGH` with
/// `NTF_SELF | NTF_MASTER`; the kernel cleans up both rows.
pub(crate) async fn apply_op(
    handle: &Handle,
    cache: &LinkCache,
    op: &DataplaneOp,
) -> Result<(), DataplaneError> {
    let (vni, mac) = match op {
        DataplaneOp::AddRemoteFdb { vni, mac, .. }
        | DataplaneOp::UpdateRemoteFdb { vni, mac, .. }
        | DataplaneOp::RemoveRemoteFdb { vni, mac, .. } => (*vni, *mac),
        DataplaneOp::SetBumPortFlags { .. }
        | DataplaneOp::SetAcPortState { .. }
        | DataplaneOp::AddRemoteIpRoute { .. }
        | DataplaneOp::RemoveRemoteIpRoute { .. }
        | DataplaneOp::AddRemoteIpRouteEcmp { .. }
        | DataplaneOp::RemoveRemoteIpRouteEcmp { .. }
        | DataplaneOp::AddL3Neighbor { .. }
        | DataplaneOp::RemoveL3Neighbor { .. }
        | DataplaneOp::AddL3VxlanFdb { .. }
        | DataplaneOp::RemoveL3VxlanFdb { .. }
        | DataplaneOp::InstallFdbNhg { .. }
        | DataplaneOp::UpdateFdbNhgMembers { .. }
        | DataplaneOp::RemoveFdbNhg { .. }
        | DataplaneOp::InstallL3FdbNhg { .. }
        | DataplaneOp::RemoveL3FdbNhg { .. }
        | DataplaneOp::CreateManagedBridge { .. }
        | DataplaneOp::RemoveManagedBridge { .. } => {
            // BUM port-flag ops are routed through `linux::bum_filter`,
            // AC-gate ops through `linux::ac_gate`, L3 ops through
            // `linux::l3`, managed-netdev ops through
            // `linux::managed_netdev`, and ADR-0059 FDB-NHG ops through
            // the reconcile actor's coordinator (which calls `NexthopOps`
            // and `linux::fdb_nhg` directly). They never reach this
            // single-dst FDB helper.
            unreachable!("non-single-dst-FDB op routed to FDB apply helper")
        }
    };

    let target = unique_fdb_vxlan_target_for_vni(cache, vni)?;

    match op {
        DataplaneOp::AddRemoteFdb { dst, vlan, .. }
        | DataplaneOp::UpdateRemoteFdb { dst, vlan, .. } => {
            // Single message matching what iproute2 sends for
            // `bridge fdb add MAC dev vxlanX master dst R self
            // extern_learn` (verified via strace on FRR's exact wire
            // shape) — see [`build_remote_fdb_message`] for the
            // field-by-field rationale. The kernel programs both the
            // VXLAN-self encap row and the bridge-master row from
            // this one RTM_NEWNEIGH. The builder request is just the
            // transport; the message shape lives in the pure
            // function so it unit-tests without a netlink socket.
            let mut req = handle
                .neighbours()
                .add_bridge(target.ifindex, &mac.octets())
                .replace();
            *req.message_mut() =
                build_remote_fdb_message(target.ifindex, mac, *dst, *vlan, target.source_vni);
            req.execute().await.map_err(|e| classify_apply_error(&e))?;
            Ok(())
        }
        DataplaneOp::RemoveRemoteFdb { vlan, .. } => {
            // Delete the same row we programmed: single NTF_SELF |
            // NTF_MASTER message on the VXLAN port. Kernel cleans
            // up both the bridge-FDB row and the VXLAN-encap row.
            let mut msg = NeighbourMessage::default();
            msg.header.family = AddressFamily::Bridge;
            msg.header.ifindex = target.ifindex;
            msg.header.kind = RouteType::Unspec;
            msg.header.flags = NeighbourFlags::Own | NeighbourFlags::Controller;
            msg.attributes
                .push(NeighbourAttribute::LinkLayerAddress(mac.octets().to_vec()));
            if let Some(vlan) = vlan {
                msg.attributes.push(NeighbourAttribute::Vlan(*vlan));
            }
            if let Some(vni) = target.source_vni {
                msg.attributes
                    .push(NeighbourAttribute::SourceVni(vni.as_u32()));
            }
            match handle.neighbours().del(msg).execute().await {
                Ok(()) => Ok(()),
                Err(e) => classify_remove_apply_error(&e),
            }?;
            Ok(())
        }
        DataplaneOp::SetBumPortFlags { .. }
        | DataplaneOp::SetAcPortState { .. }
        | DataplaneOp::AddRemoteIpRoute { .. }
        | DataplaneOp::RemoveRemoteIpRoute { .. }
        | DataplaneOp::AddRemoteIpRouteEcmp { .. }
        | DataplaneOp::RemoveRemoteIpRouteEcmp { .. }
        | DataplaneOp::AddL3Neighbor { .. }
        | DataplaneOp::RemoveL3Neighbor { .. }
        | DataplaneOp::AddL3VxlanFdb { .. }
        | DataplaneOp::RemoveL3VxlanFdb { .. }
        | DataplaneOp::InstallFdbNhg { .. }
        | DataplaneOp::UpdateFdbNhgMembers { .. }
        | DataplaneOp::RemoveFdbNhg { .. }
        | DataplaneOp::InstallL3FdbNhg { .. }
        | DataplaneOp::RemoveL3FdbNhg { .. }
        | DataplaneOp::CreateManagedBridge { .. }
        | DataplaneOp::RemoveManagedBridge { .. } => {
            // Unreachable: the early-return at the top of `apply_op`
            // already handled non-single-dst-FDB ops. Arms exist so
            // the compiler can prove exhaustiveness.
            unreachable!("non-single-dst-FDB op handled at function entry")
        }
    }
}

#[cfg(test)]
fn vxlan_ifindex_for_vni(cache: &LinkCache, vni: EvpnInstanceId) -> Result<u32, DataplaneError> {
    unique_fdb_vxlan_target_for_vni(cache, vni).map(|target| target.ifindex)
}

/// Classify a netlink error into the right [`DataplaneError`] variant.
///
/// Reads the `ErrorMessage::raw_code()` (an errno-style negative
/// integer) and delegates to [`errno_to_dataplane_error`] for the
/// per-errno mapping.
pub(super) fn classify_apply_error(err: &rtnetlink::Error) -> DataplaneError {
    if let rtnetlink::Error::NetlinkError(msg) = err {
        // raw_code() is the errno-style integer the kernel sent
        // back, negative-encoded per netlink convention. Take the
        // absolute value to get the standard errno.
        let errno = i32::try_from(msg.raw_code().unsigned_abs()).unwrap_or(0);
        let detail = msg.to_io().to_string();
        return errno_to_dataplane_error(errno, &detail);
    }
    if matches!(err, rtnetlink::Error::RequestFailed) {
        return DataplaneError::Io(io::Error::other("rtnetlink request failed"));
    }
    DataplaneError::Other(format!("rtnetlink: {err:?}"))
}

/// `true` when the netlink error is the kernel's `EINVAL` reply.
/// Used by the L3 neighbor install path's ADR-0082 retry-once shape
/// (a strict-validation kernel without the `NDA_PROTOCOL` neighbor
/// attribute rejects the stamped message with `EINVAL`).
pub(super) fn is_einval(err: &rtnetlink::Error) -> bool {
    if let rtnetlink::Error::NetlinkError(msg) = err {
        i32::try_from(msg.raw_code().unsigned_abs()).unwrap_or(0) == libc::EINVAL
    } else {
        false
    }
}

/// Variant of [`classify_apply_error`] for **remove** ops:
/// `ENOENT` is idempotent success.
///
/// Remove ops have a post-condition of "the kernel row is absent
/// when this returns Ok". If the row was already absent — manual
/// `ip route del`, prior partial drain, kernel cleanup, foreign
/// removal — the desired state already holds, so surfacing ENOENT
/// as an error would wedge `L3OwnedState` convergence: the actor
/// would never call `record_l3_success`, the owned row would stay
/// indefinitely, and every reconcile pass would re-emit the same
/// failing remove. Mapping ENOENT to Ok(()) lets owned state
/// advance and matches the "idempotent delete" semantic operators
/// expect.
///
/// All other errno values route through `classify_apply_error`
/// unchanged.
pub(super) fn classify_remove_apply_error(err: &rtnetlink::Error) -> Result<(), DataplaneError> {
    if let rtnetlink::Error::NetlinkError(msg) = err {
        let errno = i32::try_from(msg.raw_code().unsigned_abs()).unwrap_or(0);
        let detail = msg.to_io().to_string();
        return errno_to_remove_apply_result(errno, &detail);
    }
    Err(classify_apply_error(err))
}

fn errno_to_remove_apply_result(errno: i32, detail: &str) -> Result<(), DataplaneError> {
    if errno == libc::ENOENT {
        return Ok(());
    }
    Err(errno_to_dataplane_error(errno, detail))
}

/// Pure-function map from a positive errno to a [`DataplaneError`].
///
/// Split out from [`classify_apply_error`] so unit tests can exercise
/// the per-errno mapping without forging an `ErrorMessage`
/// (`#[non_exhaustive]`, no public constructor).
///
/// - `EPERM` / `EACCES` → [`DataplaneError::PermissionDenied`]
///   (Permanent — retrying without privilege change can't help).
/// - `EOPNOTSUPP` → [`DataplaneError::KernelTooOld`] (Permanent —
///   kernel doesn't support the flag/feature).
/// - `EINVAL` → [`DataplaneError::InvalidArgument`] (Permanent — our
///   message shape is wrong; retrying same shape just retries the
///   error).
/// - Anything else → [`DataplaneError::Other`] (Transient — backoff
///   schedule retries).
fn errno_to_dataplane_error(errno: i32, detail: &str) -> DataplaneError {
    match errno {
        libc::EPERM | libc::EACCES => DataplaneError::PermissionDenied(detail.to_owned()),
        libc::EOPNOTSUPP => DataplaneError::KernelTooOld {
            feature: "NTF_EXT_LEARNED (Linux ≥4.18)".to_string(),
        },
        libc::EINVAL => DataplaneError::InvalidArgument(detail.to_owned()),
        _ => DataplaneError::Other(format!("netlink errno {errno}: {detail}")),
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::FailureClass;
    use crate::linux::links::BridgeLink;
    use crate::snapshot::{
        KernelBridgePortVlanInfo, KernelBridgeVlanFlags, KernelBridgeVlanInfo,
        KernelBridgeVlanTunnelInfo, KernelSvdVxlanInfo, KernelVxlanInfo,
    };

    fn ipa(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn vlan_row(vid: u16) -> KernelBridgeVlanInfo {
        KernelBridgeVlanInfo {
            vid,
            flags: KernelBridgeVlanFlags::default(),
        }
    }

    fn svd_cache_with_binding(raw_vni: u32, bridge_vlan: u16) -> LinkCache {
        let mut cache = LinkCache::default();
        cache.svd_vxlan_ifindexes.insert(11);
        cache
            .local_mac_vlan_bindings
            .insert(("br100".to_string(), bridge_vlan), Some(raw_vni));
        cache.bridges.insert(
            "br100".to_string(),
            BridgeLink {
                ifindex: 10,
                vlan_filtering: true,
                svd_vxlan_ports: vec![KernelSvdVxlanInfo {
                    ifindex: 11,
                    vnifilter: true,
                    local_ip: None,
                    learning_disabled: Some(true),
                }],
                vxlan_attach_count: 1,
                vlans: vec![vlan_row(bridge_vlan)],
                port_vlan_inventory: vec![KernelBridgePortVlanInfo {
                    ifindex: 11,
                    name: Some("vxlan-svd".to_string()),
                    is_vxlan: true,
                    vlans: vec![vlan_row(bridge_vlan)],
                    vlan_tunnels: vec![KernelBridgeVlanTunnelInfo {
                        tunnel_id: Some(raw_vni),
                        vid: Some(bridge_vlan),
                        flags: KernelBridgeVlanFlags::default(),
                    }],
                }],
                ..BridgeLink::default()
            },
        );
        cache
    }

    /// Bit-flag bundle used by the merge tests. Centralizes the
    /// "permanent + noarp share the NUD bitmask" relationship so
    /// each test reads as one assertion rather than four bool
    /// fields.
    #[allow(clippy::struct_excessive_bools)]
    #[derive(Debug, Clone, Copy, Default)]
    struct FlagSet {
        extern_learn: bool,
        master: bool,
        self_flag: bool,
        permanent: bool,
    }

    fn flags(set: FlagSet) -> KernelFdbFlags {
        KernelFdbFlags {
            extern_learn: set.extern_learn,
            master: set.master,
            self_flag: set.self_flag,
            permanent: set.permanent,
            noarp: set.permanent, // shared NUD_NOARP|NUD_PERMANENT case
        }
    }

    fn fdb_row(dst: Option<&str>, f: KernelFdbFlags) -> KernelFdbEntry {
        KernelFdbEntry {
            mac: rustbgpd_evpn::MacAddress::new([1, 2, 3, 4, 5, 6]),
            vlan: None,
            dst: dst.map(ipa),
            nh_id: None,
            protocol: None,
            flags: f,
        }
    }

    // ── merge_fdb_rows: kernel emits both rows for one (VNI, MAC) ──

    #[test]
    fn merge_self_then_master_keeps_dst_and_ors_flags() {
        // First seen: NTF_SELF + dst (VXLAN-encap row).
        let mut acc = fdb_row(
            Some("10.0.0.2"),
            flags(FlagSet {
                extern_learn: true,
                self_flag: true,
                permanent: true,
                ..FlagSet::default()
            }),
        );
        // Then seen: NTF_MASTER, no dst (bridge-FDB row).
        let master_row = fdb_row(
            None,
            flags(FlagSet {
                extern_learn: true,
                master: true,
                permanent: true,
                ..FlagSet::default()
            }),
        );
        merge_fdb_rows(&mut acc, &master_row);

        assert_eq!(
            acc.dst,
            Some(ipa("10.0.0.2")),
            "dst from self row preserved"
        );
        assert!(acc.flags.master, "master OR'd in");
        assert!(acc.flags.self_flag, "self_flag preserved");
        assert!(acc.flags.extern_learn);
        assert!(acc.flags.permanent);
        assert!(acc.flags.noarp);
    }

    #[test]
    fn merge_master_then_self_still_recovers_dst() {
        // Reverse arrival order — the bug we're fixing. Without the
        // merge helper, the master-row insert overwrites the
        // self+dst row and `dst` collapses to None, which would make
        // compute_diff emit redundant UpdateRemoteFdb every reconcile.
        let mut acc = fdb_row(
            None,
            flags(FlagSet {
                extern_learn: true,
                master: true,
                permanent: true,
                ..FlagSet::default()
            }),
        );
        let self_row = fdb_row(
            Some("10.0.0.2"),
            flags(FlagSet {
                extern_learn: true,
                self_flag: true,
                permanent: true,
                ..FlagSet::default()
            }),
        );
        merge_fdb_rows(&mut acc, &self_row);

        assert_eq!(
            acc.dst,
            Some(ipa("10.0.0.2")),
            "dst recovered from later self row"
        );
        assert!(acc.flags.master);
        assert!(acc.flags.self_flag);
    }

    #[test]
    fn merge_preserves_nh_id_across_self_master_split() {
        // Kernel emits the FDB-NHG row only on the self leg with
        // NDA_NH_ID; the master leg has neither dst nor nh_id. The
        // merge must surface nh_id on the combined entry.
        let one = FlagSet {
            extern_learn: true,
            self_flag: true,
            permanent: true,
            ..FlagSet::default()
        };
        let two = FlagSet {
            master: true,
            ..FlagSet::default()
        };
        let mut acc = KernelFdbEntry {
            mac: rustbgpd_evpn::MacAddress::new([1, 2, 3, 4, 5, 6]),
            vlan: None,
            dst: None,
            nh_id: None,
            protocol: None,
            flags: flags(two),
        };
        let nhg_row = KernelFdbEntry {
            mac: rustbgpd_evpn::MacAddress::new([1, 2, 3, 4, 5, 6]),
            vlan: None,
            dst: None,
            nh_id: Some(0x4000_0001),
            protocol: None,
            flags: flags(one),
        };
        merge_fdb_rows(&mut acc, &nhg_row);
        assert_eq!(acc.nh_id, Some(0x4000_0001));
        assert!(acc.flags.extern_learn);
        assert!(acc.flags.master);
    }

    #[test]
    fn merge_does_not_overwrite_dst_when_already_present() {
        // Two self+dst rows with different dst (shouldn't happen in
        // practice, but we don't want a silent dst flip): the merge
        // keeps the first one. compute_diff handles real changes via
        // UpdateRemoteFdb on the *next* reconcile, after our owned
        // set updates.
        let one = FlagSet {
            extern_learn: true,
            self_flag: true,
            permanent: true,
            ..FlagSet::default()
        };
        let mut acc = fdb_row(Some("10.0.0.2"), flags(one));
        let other = fdb_row(Some("10.0.0.3"), flags(one));
        merge_fdb_rows(&mut acc, &other);
        assert_eq!(acc.dst, Some(ipa("10.0.0.2")));
    }

    #[test]
    fn merge_preserves_protocol_across_self_master_split() {
        // A future FDB-storing kernel may echo NDA_PROTOCOL on either
        // leg; the merge must surface it on the combined entry just
        // like dst / nh_id.
        let one = FlagSet {
            extern_learn: true,
            self_flag: true,
            permanent: true,
            ..FlagSet::default()
        };
        let mut acc = fdb_row(None, flags(one));
        let mut stamped = fdb_row(
            Some("10.0.0.2"),
            flags(FlagSet {
                extern_learn: true,
                master: true,
                permanent: true,
                ..FlagSet::default()
            }),
        );
        stamped.protocol = Some(186);
        merge_fdb_rows(&mut acc, &stamped);
        assert_eq!(acc.protocol, Some(186));
    }

    // ── decode_state: combined NUD bitmask ──

    #[test]
    fn decode_state_handles_combined_noarp_permanent_bitmask() {
        let mut f = KernelFdbFlags::default();
        decode_state(NeighbourState::Other(NUD_NOARP_PERMANENT), &mut f);
        assert!(f.permanent, "NUD_PERMANENT bit decoded");
        assert!(f.noarp, "NUD_NOARP bit decoded");
    }

    #[test]
    fn decode_state_individual_variants_still_work() {
        let mut f = KernelFdbFlags::default();
        decode_state(NeighbourState::Permanent, &mut f);
        assert!(f.permanent && !f.noarp);

        let mut f = KernelFdbFlags::default();
        decode_state(NeighbourState::Noarp, &mut f);
        assert!(f.noarp && !f.permanent);
    }

    #[test]
    fn decode_state_other_with_irrelevant_bits_is_noop() {
        let mut f = KernelFdbFlags::default();
        decode_state(NeighbourState::Other(0x01), &mut f); // NUD_INCOMPLETE
        assert!(!f.permanent);
        assert!(!f.noarp);
    }

    // ── encode/parse: ADR-0082 ownership stamp ──

    #[test]
    fn build_remote_fdb_message_shape_includes_ownership_stamp() {
        let mac = rustbgpd_evpn::MacAddress::new([1, 2, 3, 4, 5, 6]);
        let msg = build_remote_fdb_message(11, mac, ipa("10.0.0.2"), None, None);
        assert_eq!(msg.header.family, AddressFamily::Bridge);
        assert_eq!(msg.header.ifindex, 11);
        assert_eq!(msg.header.state, NeighbourState::Other(NUD_NOARP_PERMANENT));
        assert_eq!(
            msg.header.flags,
            NeighbourFlags::Own | NeighbourFlags::Controller | NeighbourFlags::ExtLearned
        );
        assert!(
            msg.attributes
                .contains(&NeighbourAttribute::LinkLayerAddress(mac.octets().to_vec()))
        );
        assert!(
            msg.attributes
                .contains(&NeighbourAttribute::Destination(NeighbourAddress::Inet(
                    "10.0.0.2".parse().unwrap()
                )))
        );
        // ADR-0082: stamped unconditionally; mainline AF_BRIDGE drops
        // it silently, so the encode side must always carry it for
        // the stamp to become effective when kernel support lands.
        assert!(
            msg.attributes
                .contains(&NeighbourAttribute::Protocol(RouteProtocol::Bgp))
        );
        assert!(
            !msg.attributes
                .iter()
                .any(|attr| matches!(attr, NeighbourAttribute::Vlan(_)))
        );
    }

    #[test]
    fn build_remote_fdb_message_carries_vlan_when_scoped() {
        let mac = rustbgpd_evpn::MacAddress::new([1, 2, 3, 4, 5, 6]);
        let msg = build_remote_fdb_message(11, mac, ipa("10.0.0.2"), Some(10), None);
        assert!(msg.attributes.contains(&NeighbourAttribute::Vlan(10)));
    }

    #[test]
    fn build_remote_fdb_message_carries_source_vni_for_svd_shape() {
        let mac = rustbgpd_evpn::MacAddress::new([1, 2, 3, 4, 5, 6]);
        let vni = EvpnInstanceId::new(100).unwrap();
        let msg = build_remote_fdb_message(11, mac, ipa("10.0.0.2"), Some(10), Some(vni));
        assert!(msg.attributes.contains(&NeighbourAttribute::Vlan(10)));
        assert!(
            msg.attributes
                .contains(&NeighbourAttribute::SourceVni(vni.as_u32()))
        );
    }

    #[test]
    fn vxlan_ifindex_lookup_supports_multi_vxlan_vlan_aware_bridge() {
        let mut cache = LinkCache::default();
        cache.vxlan_ifindex_to_vni.insert(11, 100);
        cache.vxlan_ifindex_to_vni.insert(22, 200);
        cache.bridges.insert(
            "br-tenant".to_string(),
            BridgeLink {
                ifindex: 7,
                vlan_filtering: true,
                vxlan: None,
                vxlan_ports: vec![
                    KernelVxlanInfo {
                        ifindex: 11,
                        vni: 100,
                        local_ip: ipa("10.0.0.1"),
                        learning_disabled: Some(true),
                    },
                    KernelVxlanInfo {
                        ifindex: 22,
                        vni: 200,
                        local_ip: ipa("10.0.0.1"),
                        learning_disabled: Some(true),
                    },
                ],
                vxlan_attach_count: 2,
                ..BridgeLink::default()
            },
        );

        assert_eq!(
            vxlan_ifindex_for_vni(&cache, EvpnInstanceId::new(100).unwrap()).unwrap(),
            11
        );
        assert_eq!(
            vxlan_ifindex_for_vni(&cache, EvpnInstanceId::new(200).unwrap()).unwrap(),
            22
        );
    }

    #[test]
    fn vxlan_ifindex_lookup_rejects_duplicate_vni_topology() {
        let mut cache = LinkCache::default();
        cache.bridges.insert(
            "br-tenant".to_string(),
            BridgeLink {
                ifindex: 7,
                vlan_filtering: true,
                vxlan: None,
                vxlan_ports: vec![
                    KernelVxlanInfo {
                        ifindex: 11,
                        vni: 100,
                        local_ip: ipa("10.0.0.1"),
                        learning_disabled: Some(true),
                    },
                    KernelVxlanInfo {
                        ifindex: 22,
                        vni: 100,
                        local_ip: ipa("10.0.0.1"),
                        learning_disabled: Some(true),
                    },
                ],
                vxlan_attach_count: 2,
                ..BridgeLink::default()
            },
        );

        let err = vxlan_ifindex_for_vni(&cache, EvpnInstanceId::new(100).unwrap()).unwrap_err();
        assert!(
            matches!(err, DataplaneError::InvalidArgument(_)),
            "duplicate-VNI topology must fail closed instead of picking an arbitrary ifindex: {err:?}"
        );
    }

    #[test]
    fn parse_fdb_entry_extracts_protocol_when_kernel_echoes_it() {
        let mut cache = LinkCache::default();
        cache.vxlan_ifindex_to_vni.insert(11, 100);
        // Round-trip our own encode shape through the parser, as a
        // future FDB-storing kernel would echo it back.
        let mac = rustbgpd_evpn::MacAddress::new([1, 2, 3, 4, 5, 6]);
        let msg = build_remote_fdb_message(11, mac, ipa("10.0.0.2"), None, None);
        let (_, entry) = parse_fdb_entry(&msg, &cache).unwrap();
        assert_eq!(entry.protocol, Some(186));
        assert!(entry.is_extern_learned());

        // Current kernels return no protocol attribute at all.
        let mut unstamped = build_remote_fdb_message(11, mac, ipa("10.0.0.2"), None, None);
        unstamped
            .attributes
            .retain(|a| !matches!(a, NeighbourAttribute::Protocol(_)));
        let (_, entry) = parse_fdb_entry(&unstamped, &cache).unwrap();
        assert_eq!(entry.protocol, None);
        assert!(entry.is_extern_learned());
    }

    #[test]
    fn parse_fdb_entry_uses_source_vni_for_svd_ifindex() {
        let mut cache = LinkCache::default();
        cache.svd_vxlan_ifindexes.insert(11);
        let mac = rustbgpd_evpn::MacAddress::new([1, 2, 3, 4, 5, 6]);
        let msg = build_remote_fdb_message(
            11,
            mac,
            ipa("10.0.0.2"),
            Some(10),
            Some(EvpnInstanceId::new(200).unwrap()),
        );
        let (key, entry) = parse_fdb_entry(&msg, &cache).unwrap();

        assert_eq!(key.0, EvpnInstanceId::new(200).unwrap());
        assert_eq!(key.1, Some(10));
        assert_eq!(entry.vlan, Some(10));
    }

    #[test]
    fn parse_fdb_entry_drops_conflicting_explicit_vni_attrs() {
        let mut cache = LinkCache::default();
        cache.svd_vxlan_ifindexes.insert(11);
        let mac = rustbgpd_evpn::MacAddress::new([1, 2, 3, 4, 5, 6]);
        let mut msg = build_remote_fdb_message(
            11,
            mac,
            ipa("10.0.0.2"),
            Some(10),
            Some(EvpnInstanceId::new(200).unwrap()),
        );
        msg.attributes.push(NeighbourAttribute::Vni(201));

        assert!(
            parse_fdb_entry(&msg, &cache).is_none(),
            "conflicting NDA_SRC_VNI/NDA_VNI values must fail closed"
        );
    }

    #[test]
    fn parse_fdb_entry_infers_configured_vlan_for_svd_row_when_kernel_omits_vlan() {
        let cache = svd_cache_with_binding(200, 10);
        let mac = rustbgpd_evpn::MacAddress::new([1, 2, 3, 4, 5, 6]);
        let msg = build_remote_fdb_message(
            11,
            mac,
            ipa("10.0.0.2"),
            None,
            Some(EvpnInstanceId::new(200).unwrap()),
        );

        let (key, entry) = parse_fdb_entry(&msg, &cache).unwrap();
        assert_eq!(key.0, EvpnInstanceId::new(200).unwrap());
        assert_eq!(key.1, Some(10));
        assert_eq!(entry.vlan, Some(10));
    }

    #[test]
    fn parse_fdb_entry_drops_svd_row_without_explicit_vni() {
        let mut cache = LinkCache::default();
        cache.svd_vxlan_ifindexes.insert(11);
        let mac = rustbgpd_evpn::MacAddress::new([1, 2, 3, 4, 5, 6]);
        let msg = build_remote_fdb_message(11, mac, ipa("10.0.0.2"), Some(10), None);

        assert!(
            parse_fdb_entry(&msg, &cache).is_none(),
            "SVD ifindexes must not be attributed without explicit VNI metadata"
        );
    }

    // ── errno classification ──

    #[test]
    fn errno_eperm_is_permission_denied_permanent() {
        let dp_err = errno_to_dataplane_error(libc::EPERM, "Operation not permitted (os error 1)");
        assert!(
            matches!(dp_err, DataplaneError::PermissionDenied(_)),
            "got {dp_err:?}"
        );
        assert_eq!(dp_err.class(), FailureClass::Permanent);
    }

    #[test]
    fn errno_eacces_is_permission_denied_permanent() {
        let dp_err = errno_to_dataplane_error(libc::EACCES, "Permission denied");
        assert!(matches!(dp_err, DataplaneError::PermissionDenied(_)));
        assert_eq!(dp_err.class(), FailureClass::Permanent);
    }

    #[test]
    fn errno_einval_is_invalid_argument_permanent() {
        let dp_err = errno_to_dataplane_error(libc::EINVAL, "Invalid argument");
        assert!(matches!(dp_err, DataplaneError::InvalidArgument(_)));
        assert_eq!(dp_err.class(), FailureClass::Permanent);
    }

    #[test]
    fn remove_errno_enoent_is_idempotent_success() {
        assert!(errno_to_remove_apply_result(libc::ENOENT, "No such file or directory").is_ok());
    }

    #[test]
    fn remove_errno_einval_stays_invalid_argument() {
        let dp_err = errno_to_remove_apply_result(libc::EINVAL, "Invalid argument").unwrap_err();
        assert!(matches!(dp_err, DataplaneError::InvalidArgument(_)));
        assert_eq!(dp_err.class(), FailureClass::Permanent);
    }

    #[test]
    fn errno_eopnotsupp_is_kernel_too_old_permanent() {
        let dp_err = errno_to_dataplane_error(libc::EOPNOTSUPP, "Operation not supported");
        assert!(matches!(dp_err, DataplaneError::KernelTooOld { .. }));
        if let DataplaneError::KernelTooOld { ref feature } = dp_err {
            assert!(
                feature.contains("NTF_EXT_LEARNED"),
                "FDB-side EOPNOTSUPP must surface the NTF_EXT_LEARNED feature label, got {feature}"
            );
        }
        assert_eq!(dp_err.class(), FailureClass::Permanent);
    }

    #[test]
    fn errno_unknown_stays_transient() {
        let dp_err = errno_to_dataplane_error(libc::ENOSPC, "No space left on device");
        assert!(matches!(dp_err, DataplaneError::Other(_)));
        assert_eq!(dp_err.class(), FailureClass::Transient);
    }
}
