//! Bridge FDB program / withdraw / dump via netlink `RTM_NEWNEIGH` /
//! `RTM_DELNEIGH` / `RTM_GETNEIGH`.
//!
//! Programs entries through the bridge/master path with
//! `NTF_EXT_LEARNED` so kernel-learned entries (which lack the flag)
//! are visible to the diff loop as foreign and never deleted by
//! mistake. Static-permanent state (`NUD_NOARP | NUD_PERMANENT`)
//! prevents the kernel from auto-aging entries we own.

use std::collections::HashMap;

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
/// VNI assignment goes through the link cache: each FDB entry's
/// `master` ifindex points at the bridge that owns it; we look up
/// that bridge in the cache, find its attached VXLAN port, and pull
/// the VNI off the VXLAN attributes. Entries whose bridge isn't
/// indexed (e.g., a non-EVPN bridge on the same host) are silently
/// dropped.
pub(crate) async fn dump_fdb(
    handle: &Handle,
    cache: &LinkCache,
) -> Result<HashMap<(EvpnInstanceId, MacAddress), KernelFdbEntry>, DataplaneError> {
    let mut out = HashMap::new();
    // Bridge address-family dump returns FDB entries.
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
    let bridge_idx = msg.header.ifindex;
    let bridge_name = cache.bridge_ifindex_to_name.get(&bridge_idx)?;
    let bridge = cache.bridges.get(bridge_name)?;
    let vni_raw = bridge.vxlan.as_ref()?.vni;
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
            _ => {}
        }
    }
    // Bridge FDB entries don't explicitly carry NTF_MASTER on the
    // wire — the absence of NTF_SELF implies master. We mark
    // NTF_MASTER so the diff loop can distinguish the two paths if
    // future code wants to.
    if !flags.self_flag {
        flags.master = true;
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
/// is idempotent; Delete uses `RTM_DELNEIGH`. Both are scoped to the
/// bridge ifindex looked up from the link cache by the instance VNI
/// (resolved via the bridge's attached VXLAN port).
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

    let bridge_ifindex =
        bridge_ifindex_for_vni(cache, vni).ok_or_else(|| DataplaneError::LinkNotFound {
            name: format!("bridge for VNI {vni}"),
        })?;

    match op {
        DataplaneOp::AddRemoteFdb { dst, .. } | DataplaneOp::UpdateRemoteFdb { dst, .. } => {
            handle
                .neighbours()
                .add_bridge(bridge_ifindex, &mac.octets())
                .destination(*dst)
                .state(NeighbourState::Noarp)
                .flags(vec![NeighbourFlag::ExtLearned])
                .replace()
                .execute()
                .await
                .map_err(|e| classify_apply_error(e, vni))?;
            Ok(())
        }
        DataplaneOp::RemoveRemoteFdb { .. } => {
            // Build a NeighbourMessage targeting the bridge entry.
            let mut msg = NeighbourMessage::default();
            msg.header.family = AddressFamily::Bridge;
            msg.header.ifindex = bridge_ifindex;
            msg.header.kind = RouteType::Unspec;
            msg.attributes
                .push(NeighbourAttribute::LinkLocalAddress(mac.octets().to_vec()));
            handle
                .neighbours()
                .del(msg)
                .execute()
                .await
                .map_err(|e| classify_apply_error(e, vni))?;
            Ok(())
        }
    }
}

fn bridge_ifindex_for_vni(cache: &LinkCache, vni: EvpnInstanceId) -> Option<u32> {
    let raw = vni.as_u32();
    cache
        .bridges
        .values()
        .find(|b| b.vxlan.as_ref().is_some_and(|v| v.vni == raw))
        .map(|b| b.ifindex)
}

fn classify_apply_error(err: rtnetlink::Error, _vni: EvpnInstanceId) -> DataplaneError {
    use std::io;
    match err {
        rtnetlink::Error::NetlinkError(nlerr) => {
            // ErrorMessage::raw_code() may be negative in netlink
            // semantics (errno-style); stringify is enough for the
            // operator.
            DataplaneError::Other(format!("netlink: {nlerr:?}"))
        }
        rtnetlink::Error::RequestFailed => {
            DataplaneError::Io(io::Error::other("rtnetlink request failed"))
        }
        other => DataplaneError::Other(format!("rtnetlink: {other:?}")),
    }
}
