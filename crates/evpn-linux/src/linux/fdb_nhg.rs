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
use netlink_packet_route::route::{RouteProtocol, RouteType};
use rtnetlink::Handle;
use rustbgpd_evpn::{EvpnInstanceId, MacAddress};

use crate::error::DataplaneError;

use super::links::{FdbVxlanTarget, LinkCache, unique_fdb_vxlan_target_for_vni};

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
    vlan: Option<u16>,
    nh_id: u32,
) -> Result<(), DataplaneError> {
    let target = check_cve_guard_and_get_target(cache, vni)?;

    // `add_bridge` only supplies the transport; the full message
    // shape comes from the pure builder so it unit-tests without a
    // netlink socket.
    let mut req = handle
        .neighbours()
        .add_bridge(target.ifindex, &mac.octets())
        .replace();
    *req.message_mut() = build_fdb_nhg_message(target.ifindex, mac, vlan, nh_id, target.source_vni);
    req.execute()
        .await
        .map_err(|e| super::fdb::classify_apply_error(&e))?;

    Ok(())
}

/// Build the `RTM_NEWNEIGH` message for an FDB-NHG row: the
/// module-level wire shape (`AF_BRIDGE`, combined `NUD_NOARP |
/// NUD_PERMANENT` state, `NTF_SELF | NTF_MASTER | NTF_EXT_LEARNED`
/// flags, `LinkLayerAddress` + `NDA_NH_ID`, no `NDA_DST`). The
/// builder doesn't expose `NDA_NH_ID` as a typed setter — we go
/// through `Other(DefaultNla)` like the existing parse path.
///
/// Also carries the ADR-0082 `NDA_PROTOCOL = RTPROT_BGP` ownership
/// stamp. Mainline `AF_BRIDGE` parses FDB adds with a NULL attribute
/// policy and silently drops the stamp — a forward-compatible no-op
/// that becomes effective once kernel FDB support lands.
fn build_fdb_nhg_message(
    vxlan_ifindex: u32,
    mac: MacAddress,
    vlan: Option<u16>,
    nh_id: u32,
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
        .push(NeighbourAttribute::Other(DefaultNla::new(
            NDA_NH_ID,
            nh_id.to_ne_bytes().to_vec(),
        )));
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
    vlan: Option<u16>,
) -> Result<(), DataplaneError> {
    let target = unique_fdb_vxlan_target_for_vni(cache, vni)?;

    let mut msg = NeighbourMessage::default();
    msg.header.family = AddressFamily::Bridge;
    msg.header.ifindex = target.ifindex;
    msg.header.kind = RouteType::Unspec;
    msg.header.flags = NeighbourFlags::Own | NeighbourFlags::Controller;
    msg.attributes
        .push(NeighbourAttribute::LinkLayerAddress(mac.octets().to_vec()));
    if let Some(vlan) = vlan {
        msg.attributes.push(NeighbourAttribute::Vlan(vlan));
    }
    if let Some(vni) = target.source_vni {
        msg.attributes
            .push(NeighbourAttribute::SourceVni(vni.as_u32()));
    }

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
fn check_cve_guard_and_get_target(
    cache: &LinkCache,
    vni: EvpnInstanceId,
) -> Result<FdbVxlanTarget, DataplaneError> {
    let target = unique_fdb_vxlan_target_for_vni(cache, vni)?;

    match target.learning_disabled {
        Some(true) => Ok(target),
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
#[cfg(test)]
fn vxlan_ifindex_for_vni(cache: &LinkCache, vni: EvpnInstanceId) -> Result<u32, DataplaneError> {
    unique_fdb_vxlan_target_for_vni(cache, vni).map(|target| target.ifindex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::links::BridgeLink;
    use crate::snapshot::{
        KernelBridgePortVlanInfo, KernelBridgeVlanFlags, KernelBridgeVlanInfo,
        KernelBridgeVlanTunnelInfo, KernelSvdVxlanInfo, KernelVxlanInfo,
    };

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
            ..BridgeLink::default()
        };
        cache.bridges.insert("br100".into(), bridge);
        cache.vxlan_ifindex_to_vni.insert(11, vni);
        cache
    }

    fn vlan_row(vid: u16) -> KernelBridgeVlanInfo {
        KernelBridgeVlanInfo {
            vid,
            flags: KernelBridgeVlanFlags::default(),
        }
    }

    fn make_svd_cache(raw_vni: u32, vlan: u16) -> LinkCache {
        let mut cache = LinkCache::default();
        cache.svd_vxlan_ifindexes.insert(44);
        cache
            .local_mac_vlan_bindings
            .insert(("br-svd".to_string(), vlan), Some(raw_vni));
        cache.bridges.insert(
            "br-svd".into(),
            BridgeLink {
                ifindex: 10,
                vlan_filtering: true,
                svd_vxlan_ports: vec![KernelSvdVxlanInfo {
                    ifindex: 44,
                    vnifilter: true,
                    local_ip: None,
                    learning_disabled: Some(true),
                }],
                vxlan_attach_count: 1,
                vlans: vec![vlan_row(vlan)],
                port_vlan_inventory: vec![KernelBridgePortVlanInfo {
                    ifindex: 44,
                    name: Some("vxlan-svd".to_string()),
                    is_vxlan: true,
                    vlans: vec![vlan_row(vlan)],
                    vlan_tunnels: vec![KernelBridgeVlanTunnelInfo {
                        tunnel_id: Some(raw_vni),
                        vid: Some(vlan),
                        flags: KernelBridgeVlanFlags::default(),
                    }],
                }],
                ..BridgeLink::default()
            },
        );
        cache
    }

    #[test]
    fn cve_guard_passes_when_learning_disabled_true() {
        let cache = make_cache(100, Some(true));
        let vni = EvpnInstanceId::new(100).unwrap();
        let target = check_cve_guard_and_get_target(&cache, vni).unwrap();
        assert_eq!(target.ifindex, 11);
        assert_eq!(target.source_vni, None);
    }

    #[test]
    fn cve_guard_selects_matching_member_on_multi_vxlan_bridge() {
        let mut cache = LinkCache::default();
        cache.bridges.insert(
            "br-tenant".into(),
            BridgeLink {
                ifindex: 10,
                vlan_filtering: true,
                vxlan: None,
                vxlan_ports: vec![
                    KernelVxlanInfo {
                        ifindex: 11,
                        vni: 100,
                        local_ip: "10.0.0.1".parse().unwrap(),
                        learning_disabled: Some(true),
                    },
                    KernelVxlanInfo {
                        ifindex: 22,
                        vni: 200,
                        local_ip: "10.0.0.1".parse().unwrap(),
                        learning_disabled: Some(true),
                    },
                ],
                vxlan_attach_count: 2,
                ..BridgeLink::default()
            },
        );

        let target =
            check_cve_guard_and_get_target(&cache, EvpnInstanceId::new(200).unwrap()).unwrap();
        assert_eq!(target.ifindex, 22);
        assert_eq!(
            vxlan_ifindex_for_vni(&cache, EvpnInstanceId::new(100).unwrap()).unwrap(),
            11
        );
    }

    #[test]
    fn cve_guard_passes_for_svd_target_and_preserves_source_vni() {
        let cache = make_svd_cache(100, 10);
        let vni = EvpnInstanceId::new(100).unwrap();
        let target = check_cve_guard_and_get_target(&cache, vni).unwrap();
        assert_eq!(target.ifindex, 44);
        assert_eq!(target.source_vni, Some(vni));

        let mac = MacAddress::new([1, 2, 3, 4, 5, 6]);
        let msg = build_fdb_nhg_message(
            target.ifindex,
            mac,
            Some(10),
            0x4000_0001,
            target.source_vni,
        );
        assert!(
            msg.attributes
                .contains(&NeighbourAttribute::SourceVni(vni.as_u32()))
        );
    }

    #[test]
    fn cve_guard_rejects_duplicate_vni_topology() {
        let mut cache = LinkCache::default();
        cache.bridges.insert(
            "br-tenant".into(),
            BridgeLink {
                ifindex: 10,
                vlan_filtering: true,
                vxlan: None,
                vxlan_ports: vec![
                    KernelVxlanInfo {
                        ifindex: 11,
                        vni: 100,
                        local_ip: "10.0.0.1".parse().unwrap(),
                        learning_disabled: Some(true),
                    },
                    KernelVxlanInfo {
                        ifindex: 22,
                        vni: 100,
                        local_ip: "10.0.0.1".parse().unwrap(),
                        learning_disabled: Some(true),
                    },
                ],
                vxlan_attach_count: 2,
                ..BridgeLink::default()
            },
        );

        let err =
            check_cve_guard_and_get_target(&cache, EvpnInstanceId::new(100).unwrap()).unwrap_err();
        assert!(
            matches!(err, DataplaneError::InvalidArgument(_)),
            "duplicate-VNI topology must fail closed instead of picking an arbitrary ifindex: {err:?}"
        );
    }

    #[test]
    fn cve_guard_blocks_when_learning_enabled() {
        let cache = make_cache(100, Some(false));
        let vni = EvpnInstanceId::new(100).unwrap();
        let err = check_cve_guard_and_get_target(&cache, vni).unwrap_err();
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
        let err = check_cve_guard_and_get_target(&cache, vni).unwrap_err();
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
        let err = check_cve_guard_and_get_target(&cache, vni).unwrap_err();
        assert!(matches!(err, DataplaneError::LinkNotFound { .. }));
    }

    #[test]
    fn build_fdb_nhg_message_carries_nh_id_and_ownership_stamp() {
        let mac = MacAddress::new([1, 2, 3, 4, 5, 6]);
        let msg = build_fdb_nhg_message(11, mac, None, 0x4000_0001, None);
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
        // NDA_NH_ID rides the Other(DefaultNla) escape hatch; no
        // NDA_DST may accompany it (kernel vxlan_fdb_parse rejects
        // the combination).
        assert!(
            msg.attributes
                .contains(&NeighbourAttribute::Other(DefaultNla::new(
                    NDA_NH_ID,
                    0x4000_0001u32.to_ne_bytes().to_vec()
                )))
        );
        assert!(
            !msg.attributes
                .iter()
                .any(|a| matches!(a, NeighbourAttribute::Destination(_)))
        );
        // ADR-0082 ownership stamp — silently dropped by mainline
        // AF_BRIDGE, emitted anyway as the forward-compatible posture.
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
    fn build_fdb_nhg_message_carries_vlan_when_scoped() {
        let mac = MacAddress::new([1, 2, 3, 4, 5, 6]);
        let msg = build_fdb_nhg_message(11, mac, Some(10), 0x4000_0001, None);
        assert!(msg.attributes.contains(&NeighbourAttribute::Vlan(10)));
    }

    #[test]
    fn build_fdb_nhg_message_carries_source_vni_for_svd_shape() {
        let mac = MacAddress::new([1, 2, 3, 4, 5, 6]);
        let vni = EvpnInstanceId::new(100).unwrap();
        let msg = build_fdb_nhg_message(11, mac, Some(10), 0x4000_0001, Some(vni));
        assert!(msg.attributes.contains(&NeighbourAttribute::Vlan(10)));
        assert!(
            msg.attributes
                .contains(&NeighbourAttribute::SourceVni(vni.as_u32()))
        );
    }
}
