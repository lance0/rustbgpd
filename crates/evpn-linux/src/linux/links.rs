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
use netlink_packet_route::AddressFamily;
use netlink_packet_route::link::{
    AfSpecBridge, BridgeVlanInfo, BridgeVlanInfoFlags, BridgeVlanTunnelInfo, InfoBridge,
    InfoBridgePort, InfoData, InfoKind, InfoPortData, InfoVxlan, LinkAttribute, LinkExtentMask,
    LinkInfo, LinkMessage,
};
use rtnetlink::Handle;

use rustbgpd_evpn::MacAddress;

use crate::error::DataplaneError;
use crate::snapshot::{
    KernelBridgePortVlanInfo, KernelBridgeVlanFlags, KernelBridgeVlanInfo,
    KernelBridgeVlanTunnelInfo, KernelVxlanInfo,
};

/// One bridge link the inventory cared about.
#[derive(Debug, Clone, Default)]
pub(crate) struct BridgeLink {
    /// Kernel ifindex of the bridge. Used by the `RTNLGRP_LINK`
    /// reconcile-wake classifier (`notify::classify_link_event`) to
    /// recognize changes on — or enslavements to — a managed bridge.
    pub ifindex: u32,
    /// Bridge link-layer (MAC) address, when the kernel reports one.
    /// Captured for SVI-MAC origination (RFC 9135 §6.1) — the daemon
    /// surfaces this on `InstanceDataplaneStatus.bridge_mac` so the
    /// SVI task can originate Type 2 routes for the bridge's own
    /// address without reaching back into this internal cache.
    pub mac: Option<MacAddress>,
    /// `true` when the bridge has `vlan_filtering=1`. Legacy instances
    /// still reject this shape; ADR-0089 instances with `bridge_vlan`
    /// validate the bridge/VXLAN VLAN inventory before reporting Ready.
    pub vlan_filtering: bool,
    /// VXLAN port attached to this bridge whose VNI matches the
    /// instance, if exactly one exists. `None` indicates either no
    /// VXLAN port or multiple competing ports — `probe` reports the
    /// instance `NotReady` in that case. The presence of multiple
    /// ports is detected by [`vxlan_attach_count`], not by
    /// [`Option<KernelVxlanInfo>`] alone.
    pub vxlan: Option<KernelVxlanInfo>,
    /// Every VXLAN member attached to this bridge. Legacy
    /// VLAN-unaware readiness still uses [`Self::vxlan`] plus
    /// [`Self::vxlan_attach_count`] to require exactly one VXLAN
    /// port; ADR-0089 VLAN-aware readiness selects the member whose
    /// VNI matches the instance and then verifies VLAN membership on
    /// that specific port.
    pub vxlan_ports: Vec<KernelVxlanInfo>,
    /// Number of VXLAN ports attached to this bridge. Legacy
    /// VLAN-unaware readiness still requires exactly one; ADR-0089
    /// VLAN-aware readiness allows multiple VXLAN ports on a bridge
    /// when each configured VNI has exactly one matching VLAN member.
    pub vxlan_attach_count: u32,
    /// Non-VXLAN bridge-member ifindexes. These are CE-facing
    /// candidates for Gate 8b BUM enforcement.
    pub ce_port_ifindexes: Vec<u32>,
    /// VLAN membership observed on the bridge device itself.
    pub vlans: Vec<KernelBridgeVlanInfo>,
    /// VLAN tunnel mappings observed on the bridge device itself.
    pub vlan_tunnels: Vec<KernelBridgeVlanTunnelInfo>,
    /// VLAN membership/tunnel inventory for each bridge member that has at
    /// least one VLAN or tunnel row (members with neither are omitted),
    /// including VXLAN members. Read-only ADR-0088 substrate.
    pub port_vlan_inventory: Vec<KernelBridgePortVlanInfo>,
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
    /// Non-VXLAN ports of **any** known bridge, by link name, with
    /// the observed `IFLA_BRPORT_STATE` from the port's
    /// `IFLA_INFO_PORT_DATA` slave info. Unlike `bridge_port_to_vni`
    /// this map does NOT require the bridge to have a resolved VNI —
    /// the AC-gate resolver must find a bound AC even while the
    /// bridge topology is otherwise `NotReady` (e.g. mid-bring-up),
    /// so a non-DF port is never silently left forwarding.
    pub bridge_ports_by_name: HashMap<String, crate::snapshot::KernelBridgePortInfo>,
}

type BridgeVlanInventory =
    HashMap<u32, (Vec<KernelBridgeVlanInfo>, Vec<KernelBridgeVlanTunnelInfo>)>;

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
    let mut vxlan_ports: Vec<VxlanPort> = Vec::new();
    // The AF_BRIDGE filtered dump carries bridge VLAN/tunnel extension
    // rows, but on real kernels it is not a substitute for the normal
    // RTM_GETLINK walk: VXLAN InfoData/learning attributes can be absent
    // there. Keep this diagnostic substrate optional so a kernel that
    // refuses the extension mask does not break existing readiness.
    let vlan_inventory = match dump_bridge_vlan_inventory(handle).await {
        Ok(inventory) => inventory,
        Err(e) => {
            // Best-effort: a kernel that refuses the extension mask (or any
            // dump error) leaves us with no VLAN-aware substrate this pass,
            // which is the fail-closed default. Log so an unexpected refusal
            // is still diagnosable rather than silently invisible.
            tracing::debug!(error = %e, "bridge VLAN inventory dump unavailable; continuing without VLAN-aware substrate");
            BridgeVlanInventory::default()
        }
    };
    // Every link that has a Controller attribute. Post-processed by
    // `index_bridge_ports` to seed `bridge_port_to_vni` and
    // `bridge_ports_by_name` for non-VXLAN ports of known bridges.
    let mut all_enslaved: Vec<EnslavedLink> = Vec::new();

    let mut stream = handle.link().get().execute();
    while let Some(msg) = stream
        .try_next()
        .await
        .map_err(|e| DataplaneError::Other(format!("link dump: {e}")))?
    {
        let (kind, name) = link_kind_and_name(&msg);
        let (bridge_vlans, vlan_tunnels) = vlan_inventory
            .get(&msg.header.index)
            .cloned()
            .unwrap_or_else(|| extract_bridge_vlan_inventory(&msg));
        let ifindex = msg.header.index;
        let master = extract_controller(&msg);
        if let Some(master_idx) = master {
            all_enslaved.push(EnslavedLink {
                ifindex,
                master: master_idx,
                is_vxlan: matches!(kind, Some(InfoKind::Vxlan)),
                name: name.clone(),
                brport_state: extract_bridge_port_state(&msg),
                vlans: bridge_vlans.clone(),
                vlan_tunnels: vlan_tunnels.clone(),
            });
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
                            vxlan_ports: Vec::new(),
                            vxlan_attach_count: 0,
                            ce_port_ifindexes: Vec::new(),
                            vlans: bridge_vlans,
                            vlan_tunnels,
                            port_vlan_inventory: Vec::new(),
                        },
                    );
                    bridge_ifindex_to_name.insert(ifindex, name);
                }
            }
            Some(InfoKind::Vxlan) => {
                if let Some(port) = parse_vxlan_port(&msg) {
                    vxlan_ports.push(port);
                }
            }
            _ => {}
        }
    }

    let mut vxlan_ifindex_to_vni: HashMap<u32, u32> = HashMap::new();
    for vxlan in vxlan_ports {
        let Some(master_idx) = vxlan.master else {
            continue;
        };
        let Some(bridge_name) = bridge_ifindex_to_name.get(&master_idx) else {
            continue;
        };
        if let Some(bridge) = bridges.get_mut(bridge_name) {
            bridge.vxlan_attach_count = bridge.vxlan_attach_count.saturating_add(1);
            vxlan_ifindex_to_vni.insert(vxlan.info.ifindex, vxlan.info.vni);
            bridge.vxlan_ports.push(vxlan.info.clone());
            // Keep the legacy single-port slot only while the bridge has
            // one VXLAN member. VLAN-aware probing uses `vxlan_ports` to
            // select the member matching the configured VNI.
            if bridge.vxlan_attach_count == 1 {
                bridge.vxlan = Some(vxlan.info);
            } else {
                // Clear the legacy slot so non-VLAN-aware probing reports
                // NotReady instead of guessing.
                bridge.vxlan = None;
            }
        }
    }

    let (bridge_port_to_vni, bridge_ports_by_name) =
        index_bridge_ports(all_enslaved, &bridge_ifindex_to_name, &mut bridges);

    Ok(LinkCache {
        bridges,
        vxlan_ifindex_to_vni,
        bridge_port_to_vni,
        bridge_ports_by_name,
    })
}

async fn dump_bridge_vlan_inventory(
    handle: &Handle,
) -> Result<BridgeVlanInventory, DataplaneError> {
    let mut inventory = HashMap::new();
    let mut stream = handle
        .link()
        .get()
        .set_filter_mask(
            AddressFamily::Bridge,
            vec![LinkExtentMask::BrvlanCompressed],
        )
        .execute();
    while let Some(msg) = stream
        .try_next()
        .await
        .map_err(|e| DataplaneError::Other(format!("bridge VLAN link dump: {e}")))?
    {
        let rows = extract_bridge_vlan_inventory(&msg);
        if !rows.0.is_empty() || !rows.1.is_empty() {
            inventory.insert(msg.header.index, rows);
        }
    }
    Ok(inventory)
}

/// One enslaved link from the dump's first pass — the raw material
/// for [`index_bridge_ports`].
struct EnslavedLink {
    ifindex: u32,
    master: u32,
    is_vxlan: bool,
    name: Option<String>,
    brport_state: Option<u8>,
    vlans: Vec<KernelBridgeVlanInfo>,
    vlan_tunnels: Vec<KernelBridgeVlanTunnelInfo>,
}

/// Build `bridge_port_to_vni` + `bridge_ports_by_name` from the
/// enslaved-links list, and fill each bridge's `ce_port_ifindexes`.
///
/// `bridge_port_to_vni` only includes non-VXLAN slaves whose master
/// bridge has a resolved VNI (exactly one VXLAN port attached) —
/// bridges without a VNI are EVPN-managed-but-unready and we should
/// not mis-classify their MAC observations. `bridge_ports_by_name`
/// is broader: any named non-VXLAN port of a known bridge is an
/// AC-gate candidate, VNI-resolved or not (see the field docs).
fn index_bridge_ports(
    all_enslaved: Vec<EnslavedLink>,
    bridge_ifindex_to_name: &HashMap<u32, String>,
    bridges: &mut HashMap<String, BridgeLink>,
) -> (
    HashMap<u32, u32>,
    HashMap<String, crate::snapshot::KernelBridgePortInfo>,
) {
    let mut bridge_port_to_vni: HashMap<u32, u32> = HashMap::new();
    let mut bridge_ports_by_name: HashMap<String, crate::snapshot::KernelBridgePortInfo> =
        HashMap::new();
    for port in all_enslaved {
        let Some(bridge_name) = bridge_ifindex_to_name.get(&port.master) else {
            continue;
        };
        if (!port.vlans.is_empty() || !port.vlan_tunnels.is_empty())
            && let Some(bridge) = bridges.get_mut(bridge_name)
        {
            bridge.port_vlan_inventory.push(KernelBridgePortVlanInfo {
                ifindex: port.ifindex,
                name: port.name.clone(),
                is_vxlan: port.is_vxlan,
                vlans: port.vlans.clone(),
                vlan_tunnels: port.vlan_tunnels.clone(),
            });
        }
        if port.is_vxlan {
            continue;
        }
        if let Some(name) = port.name {
            bridge_ports_by_name.insert(
                name,
                crate::snapshot::KernelBridgePortInfo {
                    ifindex: port.ifindex,
                    state: port.brport_state,
                },
            );
        }
        let Some(bridge) = bridges.get(bridge_name) else {
            continue;
        };
        let Some(vxlan) = &bridge.vxlan else {
            continue;
        };
        bridge_port_to_vni.insert(port.ifindex, vxlan.vni);
        if let Some(bridge) = bridges.get_mut(bridge_name) {
            bridge.ce_port_ifindexes.push(port.ifindex);
        }
    }
    for bridge in bridges.values_mut() {
        bridge.ce_port_ifindexes.sort_unstable();
        bridge.ce_port_ifindexes.dedup();
        bridge
            .port_vlan_inventory
            .sort_by(|a, b| (a.ifindex, &a.name).cmp(&(b.ifindex, &b.name)));
    }
    (bridge_port_to_vni, bridge_ports_by_name)
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

/// Extract the observed `IFLA_BRPORT_STATE` from the link's
/// `IFLA_INFO_PORT_DATA` slave info, if the kernel reported bridge
/// port data. Kept as the raw `BR_STATE_*` scalar — the snapshot
/// types are platform-independent and the parser keeps scalars, not
/// crate enums.
fn extract_bridge_port_state(msg: &LinkMessage) -> Option<u8> {
    for attr in &msg.attributes {
        if let LinkAttribute::LinkInfo(infos) = attr {
            for info in infos {
                if let LinkInfo::PortData(InfoPortData::BridgePort(ports)) = info {
                    for port in ports {
                        if let InfoBridgePort::State(state) = port {
                            return Some(u8::from(*state));
                        }
                    }
                }
            }
        }
    }
    None
}

fn extract_bridge_vlan_inventory(
    msg: &LinkMessage,
) -> (Vec<KernelBridgeVlanInfo>, Vec<KernelBridgeVlanTunnelInfo>) {
    let mut vlans = Vec::new();
    let mut vlan_tunnels = Vec::new();
    for attr in &msg.attributes {
        if let LinkAttribute::AfSpecBridge(items) = attr {
            for item in items {
                match item {
                    AfSpecBridge::VlanInfo(info) => {
                        vlans.push(kernel_bridge_vlan_info(*info));
                    }
                    AfSpecBridge::VlanTunnelInfo(items) => {
                        vlan_tunnels.push(kernel_bridge_vlan_tunnel_info(items));
                    }
                    _ => {}
                }
            }
        }
    }
    // Sort keys must be total — these vectors participate in snapshot `Eq`
    // comparisons, so any field that distinguishes two rows (every flag bit,
    // not just the range/pvid/untagged subset) has to be in the key, or the
    // ordering stays dependent on netlink arrival order and churns the snapshot.
    vlans.sort_by_key(|v| (v.vid, v.flags));
    vlan_tunnels.sort_by_key(|v| (v.vid, v.tunnel_id, v.flags));
    (vlans, vlan_tunnels)
}

fn kernel_bridge_vlan_info(info: BridgeVlanInfo) -> KernelBridgeVlanInfo {
    KernelBridgeVlanInfo {
        vid: info.vid,
        flags: kernel_bridge_vlan_flags(info.flags),
    }
}

fn kernel_bridge_vlan_tunnel_info(items: &[BridgeVlanTunnelInfo]) -> KernelBridgeVlanTunnelInfo {
    let mut tunnel_id = None;
    let mut vid = None;
    let mut flags = KernelBridgeVlanFlags::default();
    for item in items {
        match item {
            BridgeVlanTunnelInfo::Id(id) => tunnel_id = Some(*id),
            BridgeVlanTunnelInfo::Vid(v) => vid = Some(*v),
            BridgeVlanTunnelInfo::Flags(f) => flags = kernel_bridge_vlan_flags(*f),
            _ => {}
        }
    }
    KernelBridgeVlanTunnelInfo {
        tunnel_id,
        vid,
        flags,
    }
}

fn kernel_bridge_vlan_flags(flags: BridgeVlanInfoFlags) -> KernelBridgeVlanFlags {
    KernelBridgeVlanFlags {
        controller: flags.contains(BridgeVlanInfoFlags::Controller),
        pvid: flags.contains(BridgeVlanInfoFlags::Pvid),
        untagged: flags.contains(BridgeVlanInfoFlags::Untagged),
        range_begin: flags.contains(BridgeVlanInfoFlags::RangeBegin),
        range_end: flags.contains(BridgeVlanInfoFlags::RangeEnd),
        bridge_entry: flags.contains(BridgeVlanInfoFlags::Brentry),
        only_options: flags.contains(BridgeVlanInfoFlags::OnlyOpts),
    }
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
                            return *v;
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
                                InfoVxlan::Local(addr) => {
                                    local = Some(IpAddr::V4(*addr));
                                }
                                InfoVxlan::Local6(addr) => {
                                    local = Some(IpAddr::V6(*addr));
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
    use std::collections::HashMap;

    use super::*;
    use crate::snapshot::KernelVxlanInfo;
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

    #[test]
    fn extract_bridge_port_state_reads_port_data_scalar() {
        use netlink_packet_route::link::{BridgePortState, InfoPortKind};

        let mut msg = LinkMessage::default();
        msg.attributes.push(LinkAttribute::LinkInfo(vec![
            LinkInfo::PortKind(InfoPortKind::Bridge),
            LinkInfo::PortData(InfoPortData::BridgePort(vec![InfoBridgePort::State(
                BridgePortState::Disabled,
            )])),
        ]));
        assert_eq!(extract_bridge_port_state(&msg), Some(0));

        let mut msg = LinkMessage::default();
        msg.attributes.push(LinkAttribute::LinkInfo(vec![
            LinkInfo::PortKind(InfoPortKind::Bridge),
            LinkInfo::PortData(InfoPortData::BridgePort(vec![InfoBridgePort::State(
                BridgePortState::Forwarding,
            )])),
        ]));
        assert_eq!(extract_bridge_port_state(&msg), Some(3));
    }

    #[test]
    fn extract_bridge_port_state_none_without_port_data() {
        let msg = LinkMessage::default();
        assert!(extract_bridge_port_state(&msg).is_none());
    }

    #[test]
    fn extract_bridge_vlan_inventory_reads_vlan_and_tunnel_rows() {
        let mut msg = LinkMessage::default();
        msg.attributes.push(LinkAttribute::AfSpecBridge(vec![
            AfSpecBridge::VlanInfo(BridgeVlanInfo {
                flags: BridgeVlanInfoFlags::Pvid | BridgeVlanInfoFlags::Untagged,
                vid: 100,
            }),
            AfSpecBridge::VlanTunnelInfo(vec![
                BridgeVlanTunnelInfo::Id(5000),
                BridgeVlanTunnelInfo::Vid(100),
                BridgeVlanTunnelInfo::Flags(BridgeVlanInfoFlags::Untagged),
            ]),
        ]));

        let (vlans, tunnels) = extract_bridge_vlan_inventory(&msg);

        assert_eq!(vlans.len(), 1);
        assert_eq!(vlans[0].vid, 100);
        assert!(vlans[0].flags.pvid);
        assert!(vlans[0].flags.untagged);
        assert_eq!(tunnels.len(), 1);
        assert_eq!(tunnels[0].tunnel_id, Some(5000));
        assert_eq!(tunnels[0].vid, Some(100));
        assert!(tunnels[0].flags.untagged);
    }

    #[test]
    fn index_bridge_ports_keeps_vlan_inventory_read_only() {
        let mut bridges = HashMap::new();
        bridges.insert(
            "br100".to_string(),
            BridgeLink {
                ifindex: 10,
                vxlan_attach_count: 1,
                vxlan: Some(KernelVxlanInfo {
                    ifindex: 20,
                    vni: 100,
                    local_ip: "10.0.0.1".parse().unwrap(),
                    learning_disabled: Some(true),
                }),
                ..BridgeLink::default()
            },
        );
        let mut bridge_ifindex_to_name = HashMap::new();
        bridge_ifindex_to_name.insert(10, "br100".to_string());

        let (bridge_port_to_vni, bridge_ports_by_name) = index_bridge_ports(
            vec![
                EnslavedLink {
                    ifindex: 20,
                    master: 10,
                    is_vxlan: true,
                    name: Some("vxlan100".to_string()),
                    brport_state: None,
                    vlans: vec![KernelBridgeVlanInfo {
                        vid: 100,
                        flags: KernelBridgeVlanFlags {
                            untagged: true,
                            ..KernelBridgeVlanFlags::default()
                        },
                    }],
                    vlan_tunnels: vec![KernelBridgeVlanTunnelInfo {
                        tunnel_id: Some(5000),
                        vid: Some(100),
                        flags: KernelBridgeVlanFlags::default(),
                    }],
                },
                EnslavedLink {
                    ifindex: 30,
                    master: 10,
                    is_vxlan: false,
                    name: Some("swp1".to_string()),
                    brport_state: Some(3),
                    vlans: vec![KernelBridgeVlanInfo {
                        vid: 100,
                        flags: KernelBridgeVlanFlags {
                            pvid: true,
                            untagged: true,
                            ..KernelBridgeVlanFlags::default()
                        },
                    }],
                    vlan_tunnels: Vec::new(),
                },
            ],
            &bridge_ifindex_to_name,
            &mut bridges,
        );

        assert_eq!(bridge_port_to_vni.get(&30), Some(&100));
        assert!(!bridge_port_to_vni.contains_key(&20));
        assert!(bridge_ports_by_name.contains_key("swp1"));
        assert!(!bridge_ports_by_name.contains_key("vxlan100"));
        let inventory = &bridges["br100"].port_vlan_inventory;
        assert_eq!(inventory.len(), 2);
        assert!(
            inventory
                .iter()
                .any(|row| row.is_vxlan && row.ifindex == 20)
        );
        assert!(
            inventory
                .iter()
                .any(|row| !row.is_vxlan && row.ifindex == 30)
        );
    }
}
