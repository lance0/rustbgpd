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

use crate::error::DataplaneError;
use crate::snapshot::KernelVxlanInfo;

/// One bridge link the inventory cared about.
#[derive(Debug, Clone, Default)]
pub(crate) struct BridgeLink {
    /// Kernel ifindex of the bridge.
    pub ifindex: u32,
    /// `true` when the bridge has `vlan_filtering=1`. ADR-0054 §4
    /// rejects VLAN-aware bridges in Gate 7b — `probe` reports such
    /// instances `NotReady` rather than guessing a VNI-to-VLAN map.
    pub vlan_filtering: bool,
    /// VXLAN port attached to this bridge whose VNI matches the
    /// instance, if exactly one exists. `None` indicates either no
    /// VXLAN port or multiple competing ports — `probe` reports the
    /// instance `NotReady` in that case.
    pub vxlan: Option<KernelVxlanInfo>,
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
    /// Bridge ifindex -> bridge name back-reference. Used by `dump_fdb`
    /// to turn an FDB entry's `master` ifindex into the EVPN VNI by
    /// looking up the bridge's attached VXLAN port.
    pub bridge_ifindex_to_name: HashMap<u32, String>,
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

    let mut stream = handle.link().get().execute();
    while let Some(msg) = stream
        .try_next()
        .await
        .map_err(|e| DataplaneError::Other(format!("link dump: {e}")))?
    {
        let (kind, name) = link_kind_and_name(&msg);
        let ifindex = msg.header.index;
        match kind {
            Some(InfoKind::Bridge) => {
                if let Some(name) = name {
                    let vlan_filtering = bridge_vlan_filtering(&msg);
                    bridges.insert(
                        name.clone(),
                        BridgeLink {
                            ifindex,
                            vlan_filtering,
                            vxlan: None,
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

    for vxlan in vxlans {
        let Some(master_idx) = vxlan.master else {
            continue;
        };
        let Some(bridge_name) = bridge_ifindex_to_name.get(&master_idx) else {
            continue;
        };
        if let Some(bridge) = bridges.get_mut(bridge_name) {
            // If a bridge already has one VXLAN port and we see
            // another, surface the ambiguity by clearing the slot —
            // probe will read None and report NotReady. ADR-0054 §4
            // explicitly requires "exactly one VXLAN port for the
            // instance VNI".
            if bridge.vxlan.is_some() {
                bridge.vxlan = None;
            } else {
                bridge.vxlan = Some(vxlan.info);
            }
        }
    }

    Ok(LinkCache {
        bridges,
        bridge_ifindex_to_name,
    })
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
    let mut learning_disabled = true;

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
                                InfoVxlan::Learning(b) => learning_disabled = !*b,
                                _ => {}
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let _ = ifindex;
    let vni = vni?;
    let local = local?;
    Some(VxlanPort {
        master,
        info: KernelVxlanInfo {
            vni,
            local_ip: local,
            learning_disabled,
        },
    })
}
