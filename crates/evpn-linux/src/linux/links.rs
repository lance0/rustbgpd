//! Bridge + VXLAN link inventory via `rtnetlink::LinkHandle::get`.
//!
//! Walks every netlink-reported link, filters to bridges and VXLAN
//! ports, and indexes them so the per-instance probe can resolve a
//! bridge name to ifindex / VLAN-aware state / attached VXLAN
//! attributes (VNI, local IP, learning mode) without re-querying.
//!
//! ADR-0054 §3 narrows what this module surfaces: bridge VLAN
//! filtering state, VXLAN VNI / local IP / learning, and the link
//! membership relationships. Statistics, MTU, neighbor tables, etc.
//! are out of scope.

use std::collections::HashMap;
use std::net::IpAddr;

use futures::stream::TryStreamExt;
use netlink_packet_route::link::{
    InfoBridge, InfoData, InfoKind, InfoVxlan, LinkAttribute, LinkInfo, LinkMessage,
};
use rtnetlink::Handle;

use rustbgpd_evpn::MacAddress;

use crate::error::DataplaneError;
use crate::snapshot::KernelVxlanInfo;

/// One bridge link the inventory cared about.
#[derive(Debug, Clone, Default)]
pub(crate) struct BridgeLink {
    /// Kernel ifindex of the bridge. Reserved for future probe
    /// extensions (e.g., reading bridge aging time) — current
    /// reconcile path targets the VXLAN port, not the bridge.
    #[allow(dead_code)]
    pub ifindex: u32,
    /// Bridge link-layer (MAC) address, when the kernel reports one.
    /// Captured for SVI-MAC origination (RFC 9135 §6.1) — the daemon
    /// surfaces this on `InstanceDataplaneStatus.bridge_mac` so the
    /// SVI task can originate Type 2 routes for the bridge's own
    /// address without reaching back into this internal cache.
    pub mac: Option<MacAddress>,
    /// `true` when the bridge has `vlan_filtering=1`. ADR-0054 §4
    /// rejects VLAN-aware bridges in Gate 7b — `probe` reports such
    /// instances `NotReady` rather than guessing a VNI-to-VLAN map.
    pub vlan_filtering: bool,
    /// VXLAN port attached to this bridge whose VNI matches the
    /// instance, if exactly one exists. `None` indicates either no
    /// VXLAN port or multiple competing ports — `probe` reports the
    /// instance `NotReady` in that case. The presence of multiple
    /// ports is detected by [`vxlan_attach_count`], not by
    /// [`Option<KernelVxlanInfo>`] alone.
    pub vxlan: Option<KernelVxlanInfo>,
    /// Number of VXLAN ports attached to this bridge. `1` is the
    /// only legal value for an EVPN-managed bridge; `0` means
    /// missing topology, `>=2` means ambiguous and reports
    /// `NotReady`.
    pub vxlan_attach_count: u32,
}

/// Per-VXLAN port slice, before being attached to a bridge.
#[derive(Debug, Clone)]
struct VxlanPort {
    /// Bridge-master ifindex this VXLAN port slaves to (`IFLA_MASTER`
    /// in netlink terms; we read it from the Controller attribute on
    /// the link message). `None` means the VXLAN device is unparented
    /// and unusable for EVPN.
    master: Option<u32>,
    info: KernelVxlanInfo,
}

/// Result of one link inventory pass. Built fresh on every dump and
/// stored on the [`crate::LinuxDataplane`] so probe + diff see
/// consistent state.
#[derive(Debug, Clone, Default)]
pub(crate) struct LinkCache {
    /// Bridges by name. Empty if no bridges exist on the host.
    pub bridges: HashMap<String, BridgeLink>,
    /// VXLAN ifindex -> EVPN VNI back-reference. Populated alongside
    /// the bridge inventory so the FDB dump can derive the VNI of an
    /// FDB entry from `msg.header.ifindex` (which is the *VXLAN*
    /// ifindex for bridge FDB entries, not the bridge itself).
    pub vxlan_ifindex_to_vni: HashMap<u32, u32>,
    /// **Non-VXLAN** bridge port ifindex -> VNI of the bridge it is
    /// enslaved to. Populated by walking every link's Controller
    /// attribute against the known bridge inventory. Used by the
    /// `RTNLGRP_NEIGH` subscriber to classify a local-MAC observation
    /// (bridge fdb on a real port) into the right `EvpnInstanceId`.
    /// VXLAN ports are intentionally excluded — those carry remote
    /// MACs reached via VXLAN, not local kernel learns.
    pub bridge_port_to_vni: HashMap<u32, u32>,
}

/// Walk every netlink-reported link and build the inventory cache.
///
/// Two-pass: pass 1 captures bridges with their VLAN-filtering state;
/// pass 2 captures VXLAN ports and stitches them onto their master
/// bridge. Two passes are necessary because the link list is
/// kernel-ordered and a VXLAN port can appear before its master
/// bridge.
pub(crate) async fn dump_links(handle: &Handle) -> Result<LinkCache, DataplaneError> {
    let mut bridges: HashMap<String, BridgeLink> = HashMap::new();
    let mut bridge_ifindex_to_name: HashMap<u32, String> = HashMap::new();
    let mut vxlans: Vec<VxlanPort> = Vec::new();
    // (port_ifindex, master_ifindex, is_vxlan) — every link that has
    // a Controller attribute. Post-processed below to seed
    // `bridge_port_to_vni` for non-VXLAN ports of known bridges.
    let mut all_enslaved: Vec<(u32, u32, bool)> = Vec::new();

    let mut stream = handle.link().get().execute();
    while let Some(msg) = stream
        .try_next()
        .await
        .map_err(|e| DataplaneError::Other(format!("link dump: {e}")))?
    {
        let (kind, name) = link_kind_and_name(&msg);
        let ifindex = msg.header.index;
        let master = extract_controller(&msg);
        if let Some(master_idx) = master {
            let is_vxlan = matches!(kind, Some(InfoKind::Vxlan));
            all_enslaved.push((ifindex, master_idx, is_vxlan));
        }
        match kind {
            Some(InfoKind::Bridge) => {
                if let Some(name) = name {
                    let vlan_filtering = bridge_vlan_filtering(&msg);
                    let mac = extract_link_mac(&msg);
                    bridges.insert(
                        name.clone(),
                        BridgeLink {
                            ifindex,
                            mac,
                            vlan_filtering,
                            vxlan: None,
                            vxlan_attach_count: 0,
                        },
                    );
                    bridge_ifindex_to_name.insert(ifindex, name);
                }
            }
            Some(InfoKind::Vxlan) => {
                if let Some(port) = parse_vxlan_port(&msg) {
                    vxlans.push(port);
                }
            }
            _ => {}
        }
    }

    let mut vxlan_ifindex_to_vni: HashMap<u32, u32> = HashMap::new();
    for vxlan in vxlans {
        let Some(master_idx) = vxlan.master else {
            continue;
        };
        let Some(bridge_name) = bridge_ifindex_to_name.get(&master_idx) else {
            continue;
        };
        if let Some(bridge) = bridges.get_mut(bridge_name) {
            bridge.vxlan_attach_count = bridge.vxlan_attach_count.saturating_add(1);
            // Only record the VXLAN port at attach-count 1; subsequent
            // attaches just bump the counter so probe can detect the
            // ambiguity. We never re-set the slot to `Some` once it's
            // been cleared, regardless of count parity.
            if bridge.vxlan_attach_count == 1 {
                vxlan_ifindex_to_vni.insert(vxlan.info.ifindex, vxlan.info.vni);
                bridge.vxlan = Some(vxlan.info);
            } else {
                // ADR-0054 §4 requires "exactly one VXLAN port for
                // the instance VNI". Clear the slot so probe sees
                // None and reports NotReady.
                if let Some(prev) = bridge.vxlan.take() {
                    vxlan_ifindex_to_vni.remove(&prev.ifindex);
                }
            }
        }
    }

    // Build bridge_port_to_vni from the enslaved-ports list. Only
    // include non-VXLAN slaves whose master bridge has a resolved VNI
    // (i.e., exactly one VXLAN port was attached). Bridges without a
    // VNI are EVPN-managed-but-unready and we should not mis-classify
    // their MAC observations.
    let mut bridge_port_to_vni: HashMap<u32, u32> = HashMap::new();
    for (port_ifindex, master_ifindex, is_vxlan) in all_enslaved {
        if is_vxlan {
            continue;
        }
        let Some(bridge_name) = bridge_ifindex_to_name.get(&master_ifindex) else {
            continue;
        };
        let Some(bridge) = bridges.get(bridge_name) else {
            continue;
        };
        let Some(vxlan) = &bridge.vxlan else {
            continue;
        };
        bridge_port_to_vni.insert(port_ifindex, vxlan.vni);
    }

    Ok(LinkCache {
        bridges,
        vxlan_ifindex_to_vni,
        bridge_port_to_vni,
    })
}

/// Extract the Controller (master) ifindex attribute, if present.
fn extract_controller(msg: &LinkMessage) -> Option<u32> {
    for attr in &msg.attributes {
        if let LinkAttribute::Controller(idx) = attr {
            return Some(*idx);
        }
    }
    None
}

/// Extract the link-layer (MAC) address attribute, if the kernel
/// reports one and it is exactly six octets. Other lengths (Infiniband
/// LL is 20 bytes, IP-over-IP tunnels report empty) are silently
/// dropped — the bridge will simply have no `bridge_mac` on its
/// status row.
fn extract_link_mac(msg: &LinkMessage) -> Option<MacAddress> {
    for attr in &msg.attributes {
        if let LinkAttribute::Address(bytes) = attr
            && let Ok(arr) = <[u8; 6]>::try_from(bytes.as_slice())
        {
            return Some(MacAddress::new(arr));
        }
    }
    None
}

fn link_kind_and_name(msg: &LinkMessage) -> (Option<InfoKind>, Option<String>) {
    let mut name = None;
    let mut kind = None;
    for attr in &msg.attributes {
        match attr {
            LinkAttribute::IfName(n) => name = Some(n.clone()),
            LinkAttribute::LinkInfo(infos) => {
                for info in infos {
                    if let LinkInfo::Kind(k) = info {
                        kind = Some(k.clone());
                    }
                }
            }
            _ => {}
        }
    }
    (kind, name)
}

fn bridge_vlan_filtering(msg: &LinkMessage) -> bool {
    for attr in &msg.attributes {
        if let LinkAttribute::LinkInfo(infos) = attr {
            for info in infos {
                if let LinkInfo::Data(InfoData::Bridge(brs)) = info {
                    for br in brs {
                        if let InfoBridge::VlanFiltering(v) = br {
                            return *v != 0;
                        }
                    }
                }
            }
        }
    }
    false
}

fn parse_vxlan_port(msg: &LinkMessage) -> Option<VxlanPort> {
    let ifindex = msg.header.index;
    let mut master = None;
    let mut vni: Option<u32> = None;
    let mut local: Option<IpAddr> = None;
    // None until we observe IFLA_VXLAN_LEARNING. Probe fails closed
    // on `None` so a kernel that omits the attribute doesn't quietly
    // pass the readiness check.
    let mut learning_disabled: Option<bool> = None;

    for attr in &msg.attributes {
        match attr {
            LinkAttribute::Controller(idx) => master = Some(*idx),
            LinkAttribute::LinkInfo(infos) => {
                for info in infos {
                    if let LinkInfo::Data(InfoData::Vxlan(items)) = info {
                        for item in items {
                            match item {
                                InfoVxlan::Id(v) => vni = Some(*v),
                                InfoVxlan::Local(bytes) if bytes.len() == 4 => {
                                    local = Some(IpAddr::from([
                                        bytes[0], bytes[1], bytes[2], bytes[3],
                                    ]));
                                }
                                InfoVxlan::Local6(bytes) if bytes.len() == 16 => {
                                    let mut arr = [0u8; 16];
                                    arr.copy_from_slice(bytes);
                                    local = Some(IpAddr::from(arr));
                                }
                                InfoVxlan::Learning(b) => learning_disabled = Some(!*b),
                                _ => {}
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let vni = vni?;
    let local = local?;
    Some(VxlanPort {
        master,
        info: KernelVxlanInfo {
            ifindex,
            vni,
            local_ip: local,
            learning_disabled,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_route::link::LinkMessage;

    fn synthesize_link_msg(addr: Vec<u8>) -> LinkMessage {
        let mut msg = LinkMessage::default();
        msg.attributes.push(LinkAttribute::Address(addr));
        msg
    }

    #[test]
    fn extract_link_mac_captures_six_octet_address() {
        let bytes = vec![0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let msg = synthesize_link_msg(bytes.clone());
        let mac = extract_link_mac(&msg).expect("six-octet address must yield Some");
        assert_eq!(mac.octets(), [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    }

    #[test]
    fn extract_link_mac_drops_non_six_octet_addresses() {
        // Infiniband-shaped 20-byte LL address — silently ignored
        // rather than half-decoded.
        let msg = synthesize_link_msg(vec![0u8; 20]);
        assert!(extract_link_mac(&msg).is_none());
        // Empty address (some IP-over-IP tunnels) — also dropped.
        let msg = synthesize_link_msg(vec![]);
        assert!(extract_link_mac(&msg).is_none());
    }

    #[test]
    fn extract_link_mac_returns_none_when_no_address_attribute() {
        let msg = LinkMessage::default();
        assert!(extract_link_mac(&msg).is_none());
    }
}
