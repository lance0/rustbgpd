//! Bridge FDB row install/remove with `NDA_NH_ID` (ADR-0059 slice 3).
//!
//! Sibling to [`super::fdb`]; the difference is the attribute that
//! makes the FDB row point at an FDB nexthop group instead of a
//! single VTEP destination. Kernel `vxlan_fdb_parse` rejects
//! `NDA_DST` + `NDA_NH_ID` combined with `-EINVAL`, so these rows
//! are strictly nhid-only.
//!
//! ## Wire shape
//!
//! - `family = AF_BRIDGE`
//! - `ifindex = L2VXLAN port` (via the link cache's
//!   `vxlan_ifindex_for_vni` lookup, mirroring the single-dst path).
//! - `state = NUD_NOARP | NUD_PERMANENT` (the combined bitmask
//!   `rustbgpd` and iproute2 both use for `extern_learn` FDB rows).
//! - `flags = NTF_SELF | NTF_MASTER | NTF_EXT_LEARNED` (matches
//!   FRR's `netlink_macfdb_update_ctx` flag set for remote MACs).
//! - `nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE`
//!   (idempotent; FRR uses CREATE|REPLACE|APPEND but APPEND on a
//!   bridge FDB row is a no-op since there's only ever one row per
//!   `(VNI, MAC)`).
//! - Attributes: `LinkLayerAddress(mac)` + `Other(DefaultNla { kind:
//!   NDA_NH_ID = 13, data: nh_id.to_ne_bytes() })`. No `NDA_DST`.
//!
//! ## CVE-2025-39851 guard
//!
//! Kernel had a VXLAN NULL-pointer deref when refreshing an FDB
//! entry that points at a nexthop object **while learning is enabled
//! on the VXLAN device**. The probe layer (`linux::probe`) is the
//! upstream guard — instances with `learning_disabled == Some(true)`
//! pass readiness; everything else fails `NotReady` before any diff
//! ops are emitted. As belt-and-suspenders, [`apply_install_fdb_nhg_row`]
//! re-reads the link cache and refuses to install if the VXLAN port
//! does not have learning disabled. The refusal surfaces as
//! `DataplaneError::InvalidArgument` so the retry schedule suppresses it
//! until intent changes (probe goes Ready again).
//!
//! Mainline fix: commit `6ead38147ebb` ("vxlan: Fix NPD when
//! refreshing an FDB entry with a nexthop object"), backported to
//! stable trees.
//!
//! ## Slice 3b status
//!
//! Slice 3b wired these functions into `LinuxDataplane`'s
//! `NexthopOps` impl: the reconcile-actor coordinator drives them
//! during apply for `InstallFdbNhg` / `RemoveFdbNhg` ops. The CVE
//! guard runs inline on every install (belt-and-suspenders behind
//! the readiness probe).

use netlink_packet_core::DefaultNla;
use netlink_packet_route::AddressFamily;
use netlink_packet_route::neighbour::{
    NeighbourAttribute, NeighbourFlags, NeighbourMessage, NeighbourState,
};
use netlink_packet_route::route::RouteType;
use rtnetlink::Handle;
use rustbgpd_evpn::{EvpnInstanceId, MacAddress};

use crate::error::DataplaneError;

use super::links::LinkCache;

/// `NDA_NH_ID` (kind = 13). Not exposed as a typed variant by
/// `netlink-packet-route 0.30`; emit via the `Other(DefaultNla)`
/// escape hatch.
const NDA_NH_ID: u16 = 13;

/// `NUD_NOARP` + `NUD_PERMANENT` combined bitmask — what iproute2
/// emits for `extern_learn` FDB rows.
const NUD_NOARP_PERMANENT: u16 = 0x40 | 0x80;

/// Install an FDB row for `(vni, mac)` pointing at nexthop group
/// `nh_id`. Runs the CVE-2025-39851 belt-and-suspenders guard before
/// any netlink call.
///
/// # Errors
///
/// - [`DataplaneError::InvalidArgument`] if the L2VXLAN port for `vni` has
///   learning enabled (CVE guard) or if the cache has no entry for
///   the VNI.
/// - [`DataplaneError::LinkNotFound`] / `Other` per the kernel-side
///   classification on netlink failure.
pub(crate) async fn apply_install_fdb_nhg_row(
    handle: &Handle,
    cache: &LinkCache,
    vni: EvpnInstanceId,
    mac: MacAddress,
    nh_id: u32,
) -> Result<(), DataplaneError> {
    let vxlan_ifindex = check_cve_guard_and_get_ifindex(cache, vni)?;

    // Use `add_bridge` (which builds an AF_BRIDGE NeighbourMessage
    // with the right family + ifindex + mac) and then mutate it to
    // (a) override the auto-set flags/state for the extern_learn
    // case and (b) attach the NDA_NH_ID attribute. The builder
    // doesn't expose `NDA_NH_ID` as a typed setter — we go through
    // `Other(DefaultNla)` like the existing parse path.
    let mut req = handle.neighbours().add_bridge(vxlan_ifindex, &mac.octets());

    {
        let msg = req.message_mut();
        msg.header.kind = RouteType::Unspec;
        msg.attributes
            .push(NeighbourAttribute::Other(DefaultNla::new(
                NDA_NH_ID,
                nh_id.to_ne_bytes().to_vec(),
            )));
    }

    req.state(NeighbourState::Other(NUD_NOARP_PERMANENT))
        .flags(NeighbourFlags::Own | NeighbourFlags::Controller | NeighbourFlags::ExtLearned)
        .replace()
        .execute()
        .await
        .map_err(|e| super::fdb::classify_apply_error(&e))?;

    Ok(())
}

/// Remove an FDB row for `(vni, mac)`. The kernel cleans up by
/// `LinkLayerAddress` match — no need to echo the `NDA_NH_ID` on the
/// delete.
///
/// # Errors
///
/// - [`DataplaneError::LinkNotFound`] if the cache has no VXLAN port
///   for `vni`.
/// - Kernel-classified errors per [`super::fdb::classify_apply_error`].
pub(crate) async fn apply_remove_fdb_nhg_row(
    handle: &Handle,
    cache: &LinkCache,
    vni: EvpnInstanceId,
    mac: MacAddress,
) -> Result<(), DataplaneError> {
    let vxlan_ifindex =
        vxlan_ifindex_for_vni(cache, vni).ok_or_else(|| DataplaneError::LinkNotFound {
            name: format!("VXLAN port for VNI {vni}"),
        })?;

    let mut msg = NeighbourMessage::default();
    msg.header.family = AddressFamily::Bridge;
    msg.header.ifindex = vxlan_ifindex;
    msg.header.kind = RouteType::Unspec;
    msg.header.flags = NeighbourFlags::Own | NeighbourFlags::Controller;
    msg.attributes
        .push(NeighbourAttribute::LinkLayerAddress(mac.octets().to_vec()));

    match handle.neighbours().del(msg).execute().await {
        Ok(()) => Ok(()),
        Err(e) => super::fdb::classify_remove_apply_error(&e),
    }
}

/// CVE-2025-39851 guard: refuse to install an FDB-NHG row unless the
/// L2VXLAN port for `vni` has `learning_disabled == Some(true)`. The
/// upstream readiness probe is the primary check; this function is
/// belt-and-suspenders for the case where link state changes between
/// the probe pass and the apply pass.
fn check_cve_guard_and_get_ifindex(
    cache: &LinkCache,
    vni: EvpnInstanceId,
) -> Result<u32, DataplaneError> {
    // Find the L2VXLAN bridge entry by VNI; pull learning state.
    let vni_raw = vni.as_u32();
    let bridge = cache
        .bridges
        .values()
        .find(|b| b.vxlan.as_ref().is_some_and(|v| v.vni == vni_raw))
        .ok_or_else(|| DataplaneError::LinkNotFound {
            name: format!("bridge for VNI {vni}"),
        })?;

    let vxlan = bridge
        .vxlan
        .as_ref()
        .expect("bridge match guaranteed Some vxlan");

    match vxlan.learning_disabled {
        Some(true) => Ok(vxlan.ifindex),
        Some(false) => Err(DataplaneError::InvalidArgument(format!(
            "CVE-2025-39851 guard: FDB-NHG install refused on VNI {vni} \
             because L2VXLAN port has learning enabled. Set `nolearning` \
             on the VXLAN port before re-enabling FDB-NHG forwarding."
        ))),
        None => Err(DataplaneError::InvalidArgument(format!(
            "CVE-2025-39851 guard: FDB-NHG install refused on VNI {vni} \
             because the kernel did not report `IFLA_VXLAN_LEARNING`; \
             cannot verify `nolearning`"
        ))),
    }
}

/// Helper: VXLAN ifindex for a given VNI. Mirrors the same logic
/// `linux::fdb` uses for the single-dst path.
fn vxlan_ifindex_for_vni(cache: &LinkCache, vni: EvpnInstanceId) -> Option<u32> {
    let vni_raw = vni.as_u32();
    cache.bridges.values().find_map(|b| {
        b.vxlan
            .as_ref()
            .filter(|v| v.vni == vni_raw)
            .map(|v| v.ifindex)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::links::BridgeLink;
    use crate::snapshot::KernelVxlanInfo;

    fn make_cache(vni: u32, learning_disabled: Option<bool>) -> LinkCache {
        let mut cache = LinkCache::default();
        let bridge = BridgeLink {
            ifindex: 10,
            mac: None,
            vlan_filtering: false,
            vxlan: Some(KernelVxlanInfo {
                ifindex: 11,
                vni,
                local_ip: "10.0.0.1".parse().unwrap(),
                learning_disabled,
            }),
            ce_port_ifindexes: vec![],
            vxlan_attach_count: 1,
        };
        cache.bridges.insert("br100".into(), bridge);
        cache.vxlan_ifindex_to_vni.insert(11, vni);
        cache
    }

    #[test]
    fn cve_guard_passes_when_learning_disabled_true() {
        let cache = make_cache(100, Some(true));
        let vni = EvpnInstanceId::new(100).unwrap();
        let ifindex = check_cve_guard_and_get_ifindex(&cache, vni).unwrap();
        assert_eq!(ifindex, 11);
    }

    #[test]
    fn cve_guard_blocks_when_learning_enabled() {
        let cache = make_cache(100, Some(false));
        let vni = EvpnInstanceId::new(100).unwrap();
        let err = check_cve_guard_and_get_ifindex(&cache, vni).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("CVE-2025-39851"),
            "expected CVE error message, got: {msg}"
        );
    }

    #[test]
    fn cve_guard_blocks_when_learning_state_unknown() {
        let cache = make_cache(100, None);
        let vni = EvpnInstanceId::new(100).unwrap();
        let err = check_cve_guard_and_get_ifindex(&cache, vni).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("CVE-2025-39851"),
            "unknown learning state must still block; got: {msg}"
        );
    }

    #[test]
    fn cve_guard_errors_when_no_bridge_for_vni() {
        let cache = make_cache(100, Some(true));
        let vni = EvpnInstanceId::new(999).unwrap();
        let err = check_cve_guard_and_get_ifindex(&cache, vni).unwrap_err();
        assert!(matches!(err, DataplaneError::LinkNotFound { .. }));
    }
}
