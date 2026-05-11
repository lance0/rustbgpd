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
    NeighbourAddress, NeighbourAttribute, NeighbourFlags, NeighbourMessage, NeighbourState,
};
use netlink_packet_route::route::RouteType;
use rtnetlink::Handle;
use rustbgpd_evpn::{EvpnInstanceId, MacAddress};

use crate::dataplane::DataplaneOp;
use crate::error::DataplaneError;
use crate::snapshot::{KernelFdbEntry, KernelFdbFlags};

use super::links::LinkCache;

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
/// `(EvpnInstanceId, MacAddress)`.
///
/// Each FDB entry's `header.ifindex` points at the **VXLAN port** for
/// bridge-family neighbours. We map that ifindex back to a VNI via
/// the link cache's `vxlan_ifindex_to_vni` table; entries on VXLAN
/// ports outside the EVPN inventory drop out silently.
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
) -> Result<HashMap<(EvpnInstanceId, MacAddress), KernelFdbEntry>, DataplaneError> {
    let mut out: HashMap<(EvpnInstanceId, MacAddress), KernelFdbEntry> = HashMap::new();
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
    existing.flags.extern_learn |= incoming.flags.extern_learn;
    existing.flags.permanent |= incoming.flags.permanent;
    existing.flags.noarp |= incoming.flags.noarp;
    existing.flags.master |= incoming.flags.master;
    existing.flags.self_flag |= incoming.flags.self_flag;
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
            _ => {}
        }
    }
    let mac = mac?;

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

    Some(((vni, mac), KernelFdbEntry { mac, dst, flags }))
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
        | DataplaneOp::RemoveRemoteFdb { vni, mac } => (*vni, *mac),
        DataplaneOp::SetBumPortFlags { .. }
        | DataplaneOp::AddRemoteIpRoute { .. }
        | DataplaneOp::RemoveRemoteIpRoute { .. }
        | DataplaneOp::AddL3Neighbor { .. }
        | DataplaneOp::RemoveL3Neighbor { .. }
        | DataplaneOp::AddL3VxlanFdb { .. }
        | DataplaneOp::RemoveL3VxlanFdb { .. } => {
            // BUM port-flag ops are routed through `linux::bum_filter`
            // and L3 ops through `linux::l3` by `LinuxDataplane::apply`;
            // they never reach this L2 FDB helper. Arms exist so the
            // compiler can prove exhaustiveness.
            unreachable!("non-L2-FDB op routed to FDB apply helper")
        }
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
            // ndm_state must carry both NUD_NOARP and NUD_PERMANENT
            // so the entry is non-expiring. The crate's
            // NeighbourState enum doesn't represent the combined
            // bitmask, so we use the `Other` escape hatch with the
            // shared NUD_NOARP_PERMANENT constant.
            handle
                .neighbours()
                .add_bridge(vxlan_ifindex, &mac.octets())
                .destination(*dst)
                .state(NeighbourState::Other(NUD_NOARP_PERMANENT))
                .flags(
                    NeighbourFlags::Own | NeighbourFlags::Controller | NeighbourFlags::ExtLearned,
                )
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
            msg.header.flags = NeighbourFlags::Own | NeighbourFlags::Controller;
            msg.attributes
                .push(NeighbourAttribute::LinkLayerAddress(mac.octets().to_vec()));
            handle
                .neighbours()
                .del(msg)
                .execute()
                .await
                .map_err(|e| classify_apply_error(&e))?;
            Ok(())
        }
        DataplaneOp::SetBumPortFlags { .. }
        | DataplaneOp::AddRemoteIpRoute { .. }
        | DataplaneOp::RemoveRemoteIpRoute { .. }
        | DataplaneOp::AddL3Neighbor { .. }
        | DataplaneOp::RemoveL3Neighbor { .. }
        | DataplaneOp::AddL3VxlanFdb { .. }
        | DataplaneOp::RemoveL3VxlanFdb { .. } => {
            // Unreachable: the early-return at the top of `apply_op`
            // already handled non-L2-FDB ops. Arms exist so the
            // compiler can prove exhaustiveness.
            unreachable!("non-L2-FDB op handled at function entry")
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

    fn ipa(s: &str) -> IpAddr {
        s.parse().unwrap()
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
            dst: dst.map(ipa),
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
