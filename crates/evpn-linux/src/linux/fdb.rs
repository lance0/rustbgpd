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
//! The link-cache's `vxlan_ifindex_to_vni` map turns that back into
//! an `EvpnInstanceId`; entries whose ifindex isn't indexed (a
//! non-EVPN VXLAN, or a stale entry on a since-removed port) are
//! silently dropped from the snapshot.

use std::collections::HashMap;
use std::io;

use futures::stream::TryStreamExt;
use netlink_packet_route::AddressFamily;
use netlink_packet_route::neighbour::{
    NeighbourAddress, NeighbourAttribute, NeighbourFlag, NeighbourMessage, NeighbourState,
};
use netlink_packet_route::route::RouteType;
use rtnetlink::Handle;
use rustbgpd_evpn::{EvpnInstanceId, MacAddress};

use crate::dataplane::DataplaneOp;
use crate::error::DataplaneError;
use crate::snapshot::{KernelFdbEntry, KernelFdbFlags};

use super::links::LinkCache;

/// Dump every bridge FDB entry in the kernel and key them by
/// `(EvpnInstanceId, MacAddress)`.
///
/// Each FDB entry's `header.ifindex` points at the **VXLAN port** for
/// bridge-family neighbours. We map that ifindex back to a VNI via
/// the link cache's `vxlan_ifindex_to_vni` table; entries on VXLAN
/// ports outside the EVPN inventory drop out silently.
pub(crate) async fn dump_fdb(
    handle: &Handle,
    cache: &LinkCache,
) -> Result<HashMap<(EvpnInstanceId, MacAddress), KernelFdbEntry>, DataplaneError> {
    let mut out = HashMap::new();
    let mut req = handle.neighbours().get();
    req.message_mut().header.family = AddressFamily::Bridge;
    let mut stream = req.execute();
    while let Some(msg) = stream
        .try_next()
        .await
        .map_err(|e| DataplaneError::Other(format!("fdb dump: {e}")))?
    {
        let Some(entry) = parse_fdb_entry(&msg, cache) else {
            continue;
        };
        out.insert(entry.0, entry.1);
    }
    Ok(out)
}

fn parse_fdb_entry(
    msg: &NeighbourMessage,
    cache: &LinkCache,
) -> Option<((EvpnInstanceId, MacAddress), KernelFdbEntry)> {
    if msg.header.family != AddressFamily::Bridge {
        return None;
    }
    // Bridge-family FDB header.ifindex points at the VXLAN port, not
    // the bridge. (For non-VXLAN bridge ports it's the slave ifindex,
    // but those aren't EVPN-managed so we drop them via the lookup
    // miss on `vxlan_ifindex_to_vni` below.)
    let port_ifindex = msg.header.ifindex;
    let vni_raw = *cache.vxlan_ifindex_to_vni.get(&port_ifindex)?;
    let vni = EvpnInstanceId::new(vni_raw).ok()?;

    let mut mac: Option<MacAddress> = None;
    let mut dst: Option<std::net::IpAddr> = None;
    for attr in &msg.attributes {
        match attr {
            NeighbourAttribute::LinkLocalAddress(bytes) if bytes.len() == 6 => {
                let mut arr = [0u8; 6];
                arr.copy_from_slice(bytes);
                mac = Some(MacAddress::new(arr));
            }
            NeighbourAttribute::Destination(addr) => match addr {
                NeighbourAddress::Inet(v4) => dst = Some(std::net::IpAddr::V4(*v4)),
                NeighbourAddress::Inet6(v6) => dst = Some(std::net::IpAddr::V6(*v6)),
                _ => {}
            },
            _ => {}
        }
    }
    let mac = mac?;

    let mut flags = KernelFdbFlags::default();
    for f in &msg.header.flags {
        match f {
            NeighbourFlag::ExtLearned => flags.extern_learn = true,
            NeighbourFlag::Own => flags.self_flag = true,
            // `NeighbourFlag::Controller` is the netlink-packet-route
            // 0.19 spelling for `NTF_MASTER` — the bit set by
            // `bridge fdb add ... master`.
            NeighbourFlag::Controller => flags.master = true,
            _ => {}
        }
    }
    match msg.header.state {
        NeighbourState::Permanent => flags.permanent = true,
        NeighbourState::Noarp => flags.noarp = true,
        _ => {}
    }

    Some(((vni, mac), KernelFdbEntry { mac, dst, flags }))
}

/// Apply one [`DataplaneOp`] against the kernel.
///
/// Add / Update use `RTM_NEWNEIGH` with `NLM_F_REPLACE` so the call
/// is idempotent; Delete uses `RTM_DELNEIGH`. Both target the
/// instance VNI's VXLAN port ifindex (resolved through the link
/// cache) with `NTF_MASTER | NTF_EXT_LEARNED` and `NUD_NOARP`.
pub(crate) async fn apply_op(
    handle: &Handle,
    cache: &LinkCache,
    op: &DataplaneOp,
) -> Result<(), DataplaneError> {
    let (vni, mac) = match op {
        DataplaneOp::AddRemoteFdb { vni, mac, .. }
        | DataplaneOp::UpdateRemoteFdb { vni, mac, .. }
        | DataplaneOp::RemoveRemoteFdb { vni, mac } => (*vni, *mac),
    };

    let vxlan_ifindex =
        vxlan_ifindex_for_vni(cache, vni).ok_or_else(|| DataplaneError::LinkNotFound {
            name: format!("VXLAN port for VNI {vni}"),
        })?;

    match op {
        DataplaneOp::AddRemoteFdb { dst, .. } | DataplaneOp::UpdateRemoteFdb { dst, .. } => {
            handle
                .neighbours()
                .add_bridge(vxlan_ifindex, &mac.octets())
                .destination(*dst)
                .state(NeighbourState::Noarp)
                // NTF_MASTER + NTF_EXT_LEARNED. Master makes the
                // bridge own the entry (so switchdev offload
                // applies); ExtLearned distinguishes our entries
                // from kernel-learned ones at FDB dump time.
                .flags(vec![NeighbourFlag::Controller, NeighbourFlag::ExtLearned])
                .replace()
                .execute()
                .await
                .map_err(|e| classify_apply_error(&e))?;
            Ok(())
        }
        DataplaneOp::RemoveRemoteFdb { .. } => {
            // Build a NeighbourMessage targeting the bridge entry on
            // the VXLAN port.
            let mut msg = NeighbourMessage::default();
            msg.header.family = AddressFamily::Bridge;
            msg.header.ifindex = vxlan_ifindex;
            msg.header.kind = RouteType::Unspec;
            msg.header.flags = vec![NeighbourFlag::Controller];
            msg.attributes
                .push(NeighbourAttribute::LinkLocalAddress(mac.octets().to_vec()));
            handle
                .neighbours()
                .del(msg)
                .execute()
                .await
                .map_err(|e| classify_apply_error(&e))?;
            Ok(())
        }
    }
}

fn vxlan_ifindex_for_vni(cache: &LinkCache, vni: EvpnInstanceId) -> Option<u32> {
    let raw = vni.as_u32();
    cache
        .bridges
        .values()
        .filter(|b| b.vxlan_attach_count == 1)
        .find_map(|b| b.vxlan.as_ref().filter(|v| v.vni == raw).map(|v| v.ifindex))
}

/// Classify a netlink error into the right [`DataplaneError`] variant.
///
/// EPERM / EACCES are mapped to [`DataplaneError::KernelTooOld`]
/// rather than [`DataplaneError::Io`] so the actor's
/// [`crate::FailureClass::Permanent`] classifier kicks in and the
/// reconciler stops retrying. EINVAL maps to
/// [`DataplaneError::InvalidArgument`] — the kernel rejected our
/// flags / message shape, also permanent. Everything else stays
/// transient and gets exponential backoff.
fn classify_apply_error(err: &rtnetlink::Error) -> DataplaneError {
    let rendered = format!("{err:?}");
    match err {
        rtnetlink::Error::NetlinkError(_) => {
            if rendered.contains("EPERM")
                || rendered.contains("EACCES")
                || rendered.contains("Permission denied")
            {
                // Permission errors are *permanent* from the actor's
                // point of view — retrying a missing capability
                // doesn't fix it. The FailureClass::Permanent path
                // moves the key into the suppression set so we stop
                // hammering netlink.
                DataplaneError::KernelTooOld
            } else if rendered.contains("EINVAL") || rendered.contains("Invalid argument") {
                DataplaneError::InvalidArgument(rendered)
            } else if rendered.contains("EOPNOTSUPP")
                || rendered.contains("Operation not supported")
            {
                DataplaneError::KernelTooOld
            } else {
                DataplaneError::Other(format!("netlink: {rendered}"))
            }
        }
        rtnetlink::Error::RequestFailed => {
            DataplaneError::Io(io::Error::other("rtnetlink request failed"))
        }
        _ => DataplaneError::Other(format!("rtnetlink: {rendered}")),
    }
}
