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
/// Mirrors the iproute2 `bridge fdb add MAC dev vxlanX master dst
/// REMOTE` shape, which is what FRR uses for EVPN-programmed remote
/// MACs. iproute2 expands that command into TWO `RTM_NEWNEIGH`
/// messages, and so do we — for each Add/Update we send:
///
/// 1. **`NTF_SELF` + `dst`** on the VXLAN port — the VXLAN-encap
///    entry that tells the VXLAN driver "for this MAC, tunnel to
///    REMOTE". Without this row the data plane can't encap; the
///    bridge would forward the frame to vxlanX but vxlanX wouldn't
///    know where to send it.
/// 2. **`NTF_MASTER`** on the VXLAN port (no dst) — the bridge-FDB
///    entry that tells br100 "this MAC is reachable via vxlanX".
///    Without this row the bridge forwards by flood instead of
///    direct unicast through the tunnel.
///
/// Both rows carry `NTF_EXT_LEARNED` so the dump path can
/// distinguish rustbgpd-programmed entries from kernel-learned and
/// operator-static ones; `NUD_NOARP` keeps the entry from auto-aging.
/// `.replace()` makes Add/Update idempotent.
///
/// `Remove` symmetrically sends two `RTM_DELNEIGH` messages so we
/// clean up both sides of the entry.
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
            // Single message matching what iproute2 sends for
            // `bridge fdb add MAC dev vxlanX master dst R self
            // extern_learn` (verified via strace on FRR's exact wire
            // shape). The kernel programs both rows from one
            // RTM_NEWNEIGH:
            //
            // - NTF_SELF + NDA_DST → VXLAN-self encap row on
            //   vxlanX (gives the VXLAN driver the tunnel target),
            // - NTF_MASTER → bridge-FDB row on br100 (the MAC is
            //   reachable via vxlanX),
            // - NTF_EXT_LEARNED → distinguishes our entries from
            //   kernel-learned ones at FDB dump time.
            //
            // ndm_state must carry both NUD_NOARP (0x40) and
            // NUD_PERMANENT (0x80) so the entry is non-expiring. The
            // crate's NeighbourState enum doesn't represent the
            // combined bitmask, so we use the `Other` escape hatch.
            const NUD_NOARP_PERMANENT: u16 = 0x40 | 0x80;
            handle
                .neighbours()
                .add_bridge(vxlan_ifindex, &mac.octets())
                .destination(*dst)
                .state(NeighbourState::Other(NUD_NOARP_PERMANENT))
                .flags(vec![
                    NeighbourFlag::Own,
                    NeighbourFlag::Controller,
                    NeighbourFlag::ExtLearned,
                ])
                .replace()
                .execute()
                .await
                .map_err(|e| classify_apply_error(&e))?;
            Ok(())
        }
        DataplaneOp::RemoveRemoteFdb { .. } => {
            // Delete the same row we programmed: single NTF_SELF |
            // NTF_MASTER message on the VXLAN port. Kernel cleans
            // up both the bridge-FDB row and the VXLAN-encap row.
            let mut msg = NeighbourMessage::default();
            msg.header.family = AddressFamily::Bridge;
            msg.header.ifindex = vxlan_ifindex;
            msg.header.kind = RouteType::Unspec;
            msg.header.flags = vec![NeighbourFlag::Own, NeighbourFlag::Controller];
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
/// Reads the `ErrorMessage::raw_code()` (an errno-style negative
/// integer) and delegates to [`errno_to_dataplane_error`] for the
/// per-errno mapping.
fn classify_apply_error(err: &rtnetlink::Error) -> DataplaneError {
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
        libc::EOPNOTSUPP => DataplaneError::KernelTooOld,
        libc::EINVAL => DataplaneError::InvalidArgument(detail.to_owned()),
        _ => DataplaneError::Other(format!("netlink errno {errno}: {detail}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FailureClass;

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
    fn errno_eopnotsupp_is_kernel_too_old_permanent() {
        let dp_err = errno_to_dataplane_error(libc::EOPNOTSUPP, "Operation not supported");
        assert!(matches!(dp_err, DataplaneError::KernelTooOld));
        assert_eq!(dp_err.class(), FailureClass::Permanent);
    }

    #[test]
    fn errno_unknown_stays_transient() {
        let dp_err = errno_to_dataplane_error(libc::ENOSPC, "No space left on device");
        assert!(matches!(dp_err, DataplaneError::Other(_)));
        assert_eq!(dp_err.class(), FailureClass::Transient);
    }
}
