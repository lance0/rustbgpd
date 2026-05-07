//! `RTNLGRP_NEIGH` subscriber — Linux kernel local-MAC observation feed.
//!
//! Phase D-real of Gate 7b+1. Subscribes to multicast group
//! `RTNLGRP_NEIGH` (group id 4 — `linux/rtnetlink.h`) on the daemon's
//! existing rtnetlink connection. Unsolicited `RTM_NEWNEIGH` /
//! `RTM_DELNEIGH` messages with `family = AF_BRIDGE` are classified
//! into [`rustbgpd_evpn::LocalMacObservation`] events that flow up
//! the dedicated channel surfaced by
//! [`crate::Dataplane::take_local_mac_rx`].
//!
//! # Classification rules (matches existing fdb.rs invariants)
//!
//! For each `NEWNEIGH` `AF_BRIDGE` message:
//!
//! 1. **Drop if `NTF_EXT_LEARNED` is set** — those entries are routes
//!    we ourselves programmed via [`crate::linux::fdb::apply_op`]; the
//!    kernel echoes them back through the multicast group as a side
//!    effect of the write. Reflecting them upward as "local" learns
//!    would short-circuit the bridge into thinking its own remotes
//!    are local.
//! 2. **Drop if `header.ifindex` is a VXLAN port** — those are
//!    bridge-fdb echoes for remote MACs (the `header.ifindex == VXLAN`
//!    convention from RFC 8365 / `bridge fdb` design), not local
//!    observations. The link cache's `vxlan_ifindex_to_vni` map gives
//!    us the lookup.
//! 3. **Resolve `header.ifindex` → VNI** via
//!    `LinkCache::bridge_port_to_vni`. A miss means the port is not
//!    enslaved to any EVPN-managed bridge and the observation is
//!    dropped silently.
//! 4. **Extract MAC** from the `LinkLocalAddress` attribute.
//! 5. **Emit `LocalMacObservation::Learned { vni, mac, ifindex }`**.
//!
//! `DELNEIGH` is symmetric: drop on `NTF_EXT_LEARNED`, resolve VNI,
//! extract MAC, emit `Aged`.
//!
//! # Why classification is a pure function
//!
//! The actor task drains the rtnetlink message stream and calls
//! [`classify_neigh`] on every `NeighbourMessage`. Pure-function
//! shape lets unit tests construct synthetic `NeighbourMessage` /
//! `LinkCache` values and assert the upward emission without needing
//! `tokio::spawn`, a netlink socket, or `CAP_NET_ADMIN`.
//!
//! # Privileged netns test
//!
//! Real-kernel verification lives in `tests/netns_dataplane.rs` under
//! `EVPN_LINUX_NETNS=1` (Gate 7b's existing privileged test file).

use netlink_packet_route::{
    AddressFamily,
    neighbour::{NeighbourAttribute, NeighbourFlag, NeighbourMessage},
};
use rustbgpd_evpn::{EvpnInstanceId, LocalMacObservation, MacAddress};

use super::links::LinkCache;

/// Multicast group ID for neighbour-table changes (`RTNLGRP_NEIGH` from
/// `<linux/rtnetlink.h>`).
pub(crate) const RTNLGRP_NEIGH: u32 = 4;

/// Kind of `RTM_*NEIGH` message we received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NeighEventKind {
    /// `RTM_NEWNEIGH` — a kernel learn (or re-learn) for a MAC.
    New,
    /// `RTM_DELNEIGH` — a kernel age/delete.
    Del,
}

/// Classify one `NeighbourMessage` into an upward observation. Returns
/// `None` for messages we don't act on (foreign families, our own
/// programmed entries, ports outside the EVPN topology, etc.).
pub(crate) fn classify_neigh(
    kind: NeighEventKind,
    msg: &NeighbourMessage,
    cache: &LinkCache,
) -> Option<LocalMacObservation> {
    // Step 1: AF_BRIDGE only.
    if msg.header.family != AddressFamily::Bridge {
        return None;
    }

    // Step 2: drop our own programming.
    if msg.header.flags.contains(&NeighbourFlag::ExtLearned) {
        return None;
    }

    // Step 3: drop VXLAN-port echoes (those are remote MACs, not
    // local observations).
    let ifindex = msg.header.ifindex;
    if cache.vxlan_ifindex_to_vni.contains_key(&ifindex) {
        return None;
    }

    // Step 4: resolve ifindex → VNI via the bridge-port map. Misses
    // indicate the port isn't enslaved to an EVPN-managed bridge.
    let vni_raw = *cache.bridge_port_to_vni.get(&ifindex)?;
    let vni = EvpnInstanceId::new(vni_raw).ok()?;

    // Step 5: extract MAC.
    let mac = extract_mac(msg)?;

    Some(match kind {
        NeighEventKind::New => LocalMacObservation::Learned { vni, mac, ifindex },
        NeighEventKind::Del => LocalMacObservation::Aged { vni, mac },
    })
}

fn extract_mac(msg: &NeighbourMessage) -> Option<MacAddress> {
    for attr in &msg.attributes {
        if let NeighbourAttribute::LinkLocalAddress(bytes) = attr
            && bytes.len() == 6
        {
            return Some(MacAddress::new([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
            ]));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use netlink_packet_route::{
        AddressFamily,
        neighbour::{
            NeighbourAttribute, NeighbourFlag, NeighbourHeader, NeighbourMessage, NeighbourState,
        },
    };

    use super::super::links::{BridgeLink, LinkCache};
    use super::*;
    use crate::snapshot::KernelVxlanInfo;

    fn cache_for(vni: u32, vxlan_ifindex: u32, port_ifindex: u32) -> LinkCache {
        let mut bridges = HashMap::new();
        bridges.insert(
            "br100".to_string(),
            BridgeLink {
                ifindex: 99,
                vlan_filtering: false,
                vxlan: Some(KernelVxlanInfo {
                    ifindex: vxlan_ifindex,
                    vni,
                    local_ip: "10.0.0.1".parse().unwrap(),
                    learning_disabled: Some(true),
                }),
                vxlan_attach_count: 1,
            },
        );
        let mut vxlan_ifindex_to_vni = HashMap::new();
        vxlan_ifindex_to_vni.insert(vxlan_ifindex, vni);
        let mut bridge_port_to_vni = HashMap::new();
        bridge_port_to_vni.insert(port_ifindex, vni);
        LinkCache {
            bridges,
            vxlan_ifindex_to_vni,
            bridge_port_to_vni,
        }
    }

    fn neigh_msg(
        family: AddressFamily,
        ifindex: u32,
        flags: Vec<NeighbourFlag>,
        mac_attr: Option<Vec<u8>>,
    ) -> NeighbourMessage {
        let mut msg = NeighbourMessage::default();
        msg.header = NeighbourHeader {
            family,
            ifindex,
            state: NeighbourState::Permanent,
            flags,
            kind: netlink_packet_route::route::RouteType::Unspec,
        };
        if let Some(bytes) = mac_attr {
            msg.attributes
                .push(NeighbourAttribute::LinkLocalAddress(bytes));
        }
        msg
    }

    #[test]
    fn classify_new_emits_learned_for_local_bridge_port() {
        let cache = cache_for(100, /* vxlan */ 11, /* eth0 */ 22);
        let msg = neigh_msg(
            AddressFamily::Bridge,
            22,
            vec![NeighbourFlag::Controller],
            Some(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        );
        let obs = classify_neigh(NeighEventKind::New, &msg, &cache).expect("emit");
        match obs {
            LocalMacObservation::Learned { vni, mac, ifindex } => {
                assert_eq!(vni.as_u32(), 100);
                assert_eq!(mac.octets(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
                assert_eq!(ifindex, 22);
            }
            LocalMacObservation::Aged { .. } => panic!("expected Learned, got Aged"),
        }
    }

    #[test]
    fn classify_del_emits_aged() {
        let cache = cache_for(100, 11, 22);
        let msg = neigh_msg(
            AddressFamily::Bridge,
            22,
            vec![NeighbourFlag::Controller],
            Some(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        );
        let obs = classify_neigh(NeighEventKind::Del, &msg, &cache).expect("emit");
        assert!(matches!(obs, LocalMacObservation::Aged { .. }));
    }

    #[test]
    fn classify_drops_ext_learned_echo() {
        let cache = cache_for(100, 11, 22);
        let msg = neigh_msg(
            AddressFamily::Bridge,
            22,
            vec![NeighbourFlag::Controller, NeighbourFlag::ExtLearned],
            Some(vec![0xaa; 6]),
        );
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_drops_vxlan_port_ifindex() {
        // Same ifindex as the cached VXLAN port — message is a remote
        // MAC echo, not a local learn.
        let cache = cache_for(100, /* vxlan */ 11, 22);
        let msg = neigh_msg(AddressFamily::Bridge, 11, vec![], Some(vec![0xaa; 6]));
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_drops_ifindex_outside_known_bridges() {
        let cache = cache_for(100, 11, 22);
        // ifindex 99 isn't in either map.
        let msg = neigh_msg(AddressFamily::Bridge, 99, vec![], Some(vec![0xaa; 6]));
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_drops_non_bridge_family() {
        let cache = cache_for(100, 11, 22);
        let msg = neigh_msg(AddressFamily::Inet, 22, vec![], Some(vec![0xaa; 6]));
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_drops_message_without_mac_attribute() {
        let cache = cache_for(100, 11, 22);
        let msg = neigh_msg(AddressFamily::Bridge, 22, vec![], None);
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_drops_mac_attribute_with_wrong_length() {
        let cache = cache_for(100, 11, 22);
        let msg = neigh_msg(
            AddressFamily::Bridge,
            22,
            vec![],
            Some(vec![0xaa; 4]), // not 6 bytes
        );
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }
}
