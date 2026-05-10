//! `RTNLGRP_NEIGH` subscriber — Linux kernel local-MAC + IP/MAC
//! observation feed.
//!
//! Subscribes to multicast group `RTNLGRP_NEIGH` — enum group id `3`
//! from `<linux/rtnetlink.h>`, **not** the legacy bitmask
//! `RTMGRP_NEIGH = 4` — on the daemon's existing rtnetlink
//! connection. The single subscription receives unsolicited
//! `RTM_NEWNEIGH` / `RTM_DELNEIGH` for every address family; the
//! classifier here splits them into two distinct origination paths:
//!
//! - **`AF_BRIDGE`** messages are bridge-FDB events on a local
//!   non-VXLAN port. They produce `LocalMacObservation::Learned` /
//!   `Aged`, the input to MAC-only Type 2 origination (Gate 7b+1).
//! - **`AF_INET` / `AF_INET6`** messages on a bridge ifindex are
//!   `(IP, MAC)` bindings populated by ARP/ND snooping when the
//!   bridge has `neigh_suppress on`. They produce
//!   `LocalMacObservation::IpAdded` / `IpRemoved`, the input to
//!   MAC+IP Type 2 origination (Gate 7b+2).
//!
//! # Classification rules
//!
//! `AF_BRIDGE` (matches existing `fdb.rs` invariants):
//!
//! 1. Drop if `NTF_EXT_LEARNED` — kernel echo of our own programmed
//!    remote-MAC entries (`crate::linux::fdb::apply_op`). Reflecting
//!    these upward would short-circuit the bridge into thinking its
//!    own remotes are local.
//! 2. Drop if `header.ifindex` is a VXLAN port — those are
//!    bridge-FDB echoes for remote MACs (`header.ifindex == VXLAN`
//!    per RFC 8365 / `bridge fdb` design), not local observations.
//! 3. Resolve `header.ifindex` → VNI via
//!    `LinkCache::bridge_port_to_vni`. A miss means the port isn't
//!    enslaved to any EVPN-managed bridge.
//! 4. Extract MAC from the `LinkLayerAddress` attribute
//!    (`NDA_LLADDR`).
//! 5. Emit `Learned { vni, mac, ifindex }` (or `Aged` on
//!    `RTM_DELNEIGH`).
//!
//! `AF_INET` / `AF_INET6`:
//!
//! 1. Drop if `NTF_EXT_LEARNED` — kernel echo of routes we ourselves
//!    will program in a future slice (today there's no programmer for
//!    these, but the guard keeps the contract consistent with the
//!    `AF_BRIDGE` path).
//! 2. Drop if `header.state` doesn't include a "valid" NUD bit
//!    (`NUD_REACHABLE` / `NUD_STALE` / `NUD_PERMANENT` / `NUD_NOARP`).
//!    Kernel emits transient probe states (`NUD_INCOMPLETE`,
//!    `NUD_FAILED`) that don't represent a usable binding — those
//!    would just produce origination thrash if we acted on them.
//! 3. Resolve `header.ifindex` → VNI via `LinkCache::bridges` —
//!    `AF_INET` / `AF_INET6` neighbours sit on the **bridge** itself,
//!    not on a bridge port, so the `bridge_port_to_vni` map doesn't
//!    apply.
//! 4. Extract MAC (`NDA_LLADDR`) and IP (`NDA_DST`).
//! 5. Emit `IpAdded { vni, mac, ip }` (or `IpRemoved` on
//!    `RTM_DELNEIGH`).
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

use std::net::IpAddr;

use netlink_packet_route::{
    AddressFamily,
    neighbour::{
        NeighbourAddress, NeighbourAttribute, NeighbourFlags, NeighbourMessage, NeighbourState,
    },
};
use rustbgpd_evpn::{EvpnInstanceId, LocalMacObservation, MacAddress};
use tracing::debug;

use super::links::LinkCache;

/// `NUD_*` bits used by the bitmask side of [`is_ip_neighbour_valid`].
/// The reachable / stale / noarp / permanent bits surface as typed
/// [`NeighbourState`] variants, so we only need the raw masks for the
/// [`NeighbourState::Other`] fallthrough where the kernel returns a
/// combined bitmask (e.g., `NUD_NOARP | NUD_PERMANENT` for our own
/// programmed entries).
const NUD_INCOMPLETE: u16 = 0x01;
const NUD_REACHABLE: u16 = 0x02;
const NUD_STALE: u16 = 0x04;
const NUD_DELAY: u16 = 0x08;
const NUD_PROBE: u16 = 0x10;
const NUD_FAILED: u16 = 0x20;
const NUD_NOARP: u16 = 0x40;
const NUD_PERMANENT: u16 = 0x80;
/// Bits that represent a confirmed `(IP, MAC)` binding.
const NUD_VALID_MASK: u16 = NUD_REACHABLE | NUD_STALE | NUD_NOARP | NUD_PERMANENT;
/// Bits that disqualify a binding regardless of what else is set.
/// `INCOMPLETE` (still probing), `DELAY` / `PROBE` (mid-revalidation,
/// no fresh confirmation), and `FAILED` (kernel gave up) are all
/// transient or negative states. Acting on them — even when combined
/// with a "valid" bit like `STALE` — would mean acting on the
/// kernel's *previous* belief while it's actively re-probing, which
/// produces origination thrash.
const NUD_INVALID_MASK: u16 = NUD_INCOMPLETE | NUD_DELAY | NUD_PROBE | NUD_FAILED;

/// Multicast group ID for neighbour-table changes — enum value
/// `RTNLGRP_NEIGH` from `<linux/rtnetlink.h>` (third entry in
/// `enum rtnetlink_groups`, hence value `3`).
///
/// **Critical:** this is the **enum group id**, not the legacy bitmask
/// `RTMGRP_NEIGH = 4` (`1 << RTNLGRP_NEIGH - 1`). `Socket::add_membership`
/// takes the enum value directly via `NETLINK_ADD_MEMBERSHIP` — passing
/// `4` here subscribes to `RTNLGRP_TC` (the next enum entry) and silently
/// loses every neighbour notification. v0.14.x originally shipped the
/// wrong value; the M37 origination smoke caught it. Cross-checked
/// against rtnetlink 0.14's `examples/ip_monitor.rs`.
pub(crate) const RTNLGRP_NEIGH: u32 = 3;

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
    // Drop our own programming. Same guard for both families.
    if msg.header.flags.contains(NeighbourFlags::ExtLearned) {
        return None;
    }

    match msg.header.family {
        AddressFamily::Bridge => classify_bridge_fdb(kind, msg, cache),
        AddressFamily::Inet | AddressFamily::Inet6 => classify_ip_neighbour(kind, msg, cache),
        _ => None,
    }
}

/// `AF_BRIDGE` classifier — kernel learns / ages a MAC on a bridge
/// port. See module-level docs for the full pipeline.
fn classify_bridge_fdb(
    kind: NeighEventKind,
    msg: &NeighbourMessage,
    cache: &LinkCache,
) -> Option<LocalMacObservation> {
    // Drop VXLAN-port echoes (those are remote MACs, not local
    // observations).
    let ifindex = msg.header.ifindex;
    if cache.vxlan_ifindex_to_vni.contains_key(&ifindex) {
        return None;
    }

    // Resolve ifindex → VNI via the bridge-port map. Misses indicate
    // either the port isn't enslaved to an EVPN-managed bridge (drop
    // is correct) or the cache hasn't been primed yet (race window
    // between connect and the first dump_links — the event is lost
    // until the supervisor's next periodic dump). Logged at debug to
    // make the latter diagnosable in field issues without spamming
    // the happy path.
    let Some(&vni_raw) = cache.bridge_port_to_vni.get(&ifindex) else {
        debug!(
            ifindex,
            "RTNLGRP_NEIGH AF_BRIDGE classifier: ifindex not in bridge_port_to_vni; \
             event dropped"
        );
        return None;
    };
    let vni = EvpnInstanceId::new(vni_raw).ok()?;
    let mac = extract_mac(msg)?;

    Some(match kind {
        NeighEventKind::New => LocalMacObservation::Learned { vni, mac, ifindex },
        NeighEventKind::Del => LocalMacObservation::Aged { vni, mac },
    })
}

/// `AF_INET` / `AF_INET6` classifier — kernel learns an `(IP, MAC)`
/// binding via ARP / ND on the bridge itself, surfaced for MAC+IP
/// Type 2 origination (Gate 7b+2).
fn classify_ip_neighbour(
    kind: NeighEventKind,
    msg: &NeighbourMessage,
    cache: &LinkCache,
) -> Option<LocalMacObservation> {
    // Resolve ifindex → VNI by matching the bridge ifindex against
    // the inventory. AF_INET / AF_INET6 neighbours sit on the bridge
    // itself (the kernel's ARP/ND-suppression table is per-bridge);
    // bridge_port_to_vni is the wrong map for this family.
    let ifindex = msg.header.ifindex;
    let Some(vni_raw) = cache.bridges.values().find_map(|b| {
        if b.ifindex == ifindex {
            b.vxlan.as_ref().map(|v| v.vni)
        } else {
            None
        }
    }) else {
        debug!(
            ifindex,
            "RTNLGRP_NEIGH AF_INET[6] classifier: ifindex not a known EVPN bridge; \
             event dropped"
        );
        return None;
    };
    let vni = EvpnInstanceId::new(vni_raw).ok()?;

    // For RTM_NEWNEIGH, require a usable NUD state — a probe in
    // NUD_INCOMPLETE / NUD_FAILED isn't a binding worth originating.
    // RTM_DELNEIGH skips the check: a deletion is meaningful even if
    // the entry was in a transient state.
    if matches!(kind, NeighEventKind::New) && !is_ip_neighbour_valid(msg.header.state) {
        return None;
    }

    let mac = extract_mac(msg)?;
    let ip = extract_ip(msg)?;

    // Drop addresses that aren't valid EVPN MAC+IP advertisement
    // candidates (multicast, unspecified, link-local, loopback, etc.).
    // Filter both add and remove edges — if the domain shouldn't see
    // it as a candidate, the domain shouldn't see either edge.
    if !is_advertisable_ip(ip) {
        return None;
    }

    Some(match kind {
        NeighEventKind::New => LocalMacObservation::IpAdded { vni, mac, ip },
        NeighEventKind::Del => LocalMacObservation::IpRemoved { vni, mac, ip },
    })
}

/// Whether `ip` is eligible to ride on an EVPN MAC+IP Type 2
/// advertisement.
///
/// An EVPN MAC+IP route describes a host's `(IP, MAC)` binding; the
/// IP half must be a unicast host address that remote VTEPs can
/// usefully reach via VXLAN encap. Several kernel-side neighbour
/// rows are not that:
///
/// - **Unspecified** (`0.0.0.0`, `::`) — placeholder, no host.
/// - **Multicast** (`224.0.0.0/4`, `ff00::/8`) — group destinations,
///   not host bindings.
/// - **Broadcast** (`255.255.255.255`) — defunct on a bridge but
///   dropped defensively.
/// - **IPv4 link-local** (`169.254.0.0/16`) — APIPA self-assigned;
///   meaningless across VTEPs.
/// - **IPv6 link-local** (`fe80::/10`) — kernel ND populates these
///   from neighbour discovery; they don't survive VXLAN encap to a
///   remote VTEP and would mislead an L3 consumer.
/// - **Loopback** (`127.0.0.0/8`, `::1`) — local-only; defensive.
fn is_advertisable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_unspecified()
                && !v4.is_multicast()
                && !v4.is_broadcast()
                && !v4.is_link_local()
                && !v4.is_loopback()
        }
        IpAddr::V6(v6) => {
            !v6.is_unspecified()
                && !v6.is_multicast()
                && !v6.is_loopback()
                && !is_ipv6_link_local(v6)
        }
    }
}

/// `fe80::/10` per RFC 4291 §2.5.6. `Ipv6Addr::is_unicast_link_local`
/// is unstable, so check the high-10-bits prefix manually.
fn is_ipv6_link_local(addr: std::net::Ipv6Addr) -> bool {
    addr.segments()[0] & 0xffc0 == 0xfe80
}

fn is_ip_neighbour_valid(state: NeighbourState) -> bool {
    match state {
        NeighbourState::Reachable
        | NeighbourState::Stale
        | NeighbourState::Noarp
        | NeighbourState::Permanent => true,
        NeighbourState::Other(bits) => {
            // Require at least one valid bit AND no invalid bits.
            // Combined states like `NUD_STALE | NUD_PROBE` (kernel
            // re-probing a stale entry) intentionally fail this check
            // — acting on the stale half while the kernel is mid-
            // revalidation produces origination thrash.
            (bits & NUD_VALID_MASK) != 0 && (bits & NUD_INVALID_MASK) == 0
        }
        _ => false,
    }
}

fn extract_mac(msg: &NeighbourMessage) -> Option<MacAddress> {
    for attr in &msg.attributes {
        if let NeighbourAttribute::LinkLayerAddress(bytes) = attr
            && bytes.len() == 6
        {
            return Some(MacAddress::new([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
            ]));
        }
    }
    None
}

fn extract_ip(msg: &NeighbourMessage) -> Option<IpAddr> {
    for attr in &msg.attributes {
        if let NeighbourAttribute::Destination(addr) = attr {
            return match addr {
                NeighbourAddress::Inet(v4) => Some(IpAddr::V4(*v4)),
                NeighbourAddress::Inet6(v6) => Some(IpAddr::V6(*v6)),
                _ => None,
            };
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
            NeighbourAttribute, NeighbourFlags, NeighbourHeader, NeighbourMessage, NeighbourState,
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
                mac: None,
                vlan_filtering: false,
                vxlan: Some(KernelVxlanInfo {
                    ifindex: vxlan_ifindex,
                    vni,
                    local_ip: "10.0.0.1".parse().unwrap(),
                    learning_disabled: Some(true),
                }),
                vxlan_attach_count: 1,
                ce_port_ifindexes: vec![port_ifindex],
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
        flags: NeighbourFlags,
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
                .push(NeighbourAttribute::LinkLayerAddress(bytes));
        }
        msg
    }

    #[test]
    fn classify_new_emits_learned_for_local_bridge_port() {
        let cache = cache_for(100, /* vxlan */ 11, /* eth0 */ 22);
        let msg = neigh_msg(
            AddressFamily::Bridge,
            22,
            NeighbourFlags::Controller,
            Some(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        );
        let obs = classify_neigh(NeighEventKind::New, &msg, &cache).expect("emit");
        match obs {
            LocalMacObservation::Learned { vni, mac, ifindex } => {
                assert_eq!(vni.as_u32(), 100);
                assert_eq!(mac.octets(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
                assert_eq!(ifindex, 22);
            }
            other => panic!("expected Learned, got {other:?}"),
        }
    }

    #[test]
    fn classify_del_emits_aged() {
        let cache = cache_for(100, 11, 22);
        let msg = neigh_msg(
            AddressFamily::Bridge,
            22,
            NeighbourFlags::Controller,
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
            NeighbourFlags::Controller | NeighbourFlags::ExtLearned,
            Some(vec![0xaa; 6]),
        );
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_drops_vxlan_port_ifindex() {
        // Same ifindex as the cached VXLAN port — message is a remote
        // MAC echo, not a local learn.
        let cache = cache_for(100, /* vxlan */ 11, 22);
        let msg = neigh_msg(
            AddressFamily::Bridge,
            11,
            NeighbourFlags::empty(),
            Some(vec![0xaa; 6]),
        );
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_drops_ifindex_outside_known_bridges() {
        let cache = cache_for(100, 11, 22);
        // ifindex 99 isn't in either map.
        let msg = neigh_msg(
            AddressFamily::Bridge,
            99,
            NeighbourFlags::empty(),
            Some(vec![0xaa; 6]),
        );
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_drops_unhandled_family() {
        // Anything that isn't Bridge / Inet / Inet6 must drop. AF_PACKET
        // (raw socket family) is a representative non-handled case the
        // kernel does not normally use for RTM_NEWNEIGH but a buggy
        // kernel-side change shouldn't cause us to mis-classify.
        let cache = cache_for(100, 11, 22);
        let msg = neigh_msg(
            AddressFamily::Packet,
            22,
            NeighbourFlags::empty(),
            Some(vec![0xaa; 6]),
        );
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_drops_bridge_message_without_mac_attribute() {
        let cache = cache_for(100, 11, 22);
        let msg = neigh_msg(AddressFamily::Bridge, 22, NeighbourFlags::empty(), None);
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_drops_bridge_mac_attribute_with_wrong_length() {
        let cache = cache_for(100, 11, 22);
        let msg = neigh_msg(
            AddressFamily::Bridge,
            22,
            NeighbourFlags::empty(),
            Some(vec![0xaa; 4]), // not 6 bytes
        );
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    // --- Gate 7b+2: AF_INET / AF_INET6 IP-neighbour classifier ---

    /// Build a synthetic `AF_INET` / `AF_INET6` `RTM_NEWNEIGH` for
    /// ARP/ND snooping tests. `bridge_ifindex` must match the bridge
    /// stored in the cache (not a bridge port — `AF_INET` /
    /// `AF_INET6` neighbours sit on the bridge itself).
    fn ip_neigh_msg(
        family: AddressFamily,
        bridge_ifindex: u32,
        state: NeighbourState,
        flags: NeighbourFlags,
        mac: Option<[u8; 6]>,
        ip: Option<IpAddr>,
    ) -> NeighbourMessage {
        let mut msg = NeighbourMessage::default();
        msg.header = NeighbourHeader {
            family,
            ifindex: bridge_ifindex,
            state,
            flags,
            kind: netlink_packet_route::route::RouteType::Unspec,
        };
        if let Some(bytes) = mac {
            msg.attributes
                .push(NeighbourAttribute::LinkLayerAddress(bytes.to_vec()));
        }
        if let Some(addr) = ip {
            let na = match addr {
                IpAddr::V4(v4) => NeighbourAddress::Inet(v4),
                IpAddr::V6(v6) => NeighbourAddress::Inet6(v6),
            };
            msg.attributes.push(NeighbourAttribute::Destination(na));
        }
        msg
    }

    #[test]
    fn classify_inet_emits_ip_added_for_known_bridge() {
        // cache_for builds br100 with bridge ifindex 99.
        let cache = cache_for(100, /* vxlan */ 11, /* port */ 22);
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet,
            99,
            NeighbourState::Reachable,
            NeighbourFlags::empty(),
            Some([0x02, 0x00, 0x00, 0x00, 0x00, 0xAA]),
            Some(v4),
        );
        let obs = classify_neigh(NeighEventKind::New, &msg, &cache).expect("emit");
        match obs {
            LocalMacObservation::IpAdded { vni, mac, ip } => {
                assert_eq!(vni.as_u32(), 100);
                assert_eq!(mac.octets(), [0x02, 0x00, 0x00, 0x00, 0x00, 0xAA]);
                assert_eq!(ip, v4);
            }
            other => panic!("expected IpAdded, got {other:?}"),
        }
    }

    #[test]
    fn classify_inet6_emits_ip_added() {
        let cache = cache_for(100, 11, 22);
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet6,
            99,
            NeighbourState::Stale,
            NeighbourFlags::empty(),
            Some([0xAA; 6]),
            Some(v6),
        );
        let obs = classify_neigh(NeighEventKind::New, &msg, &cache).expect("emit");
        assert!(matches!(obs, LocalMacObservation::IpAdded { ip, .. } if ip == v6));
    }

    #[test]
    fn classify_inet_del_emits_ip_removed_regardless_of_state() {
        // A deletion is meaningful even if the entry was in a
        // transient state — RTM_DELNEIGH skips the validity check.
        let cache = cache_for(100, 11, 22);
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet,
            99,
            NeighbourState::Other(NUD_FAILED),
            NeighbourFlags::empty(),
            Some([0xAA; 6]),
            Some(v4),
        );
        let obs = classify_neigh(NeighEventKind::Del, &msg, &cache).expect("emit");
        assert!(matches!(obs, LocalMacObservation::IpRemoved { .. }));
    }

    #[test]
    fn classify_inet_drops_incomplete_state() {
        // NUD_INCOMPLETE = 0x01, not in NUD_VALID_MASK.
        let cache = cache_for(100, 11, 22);
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet,
            99,
            NeighbourState::Other(0x01),
            NeighbourFlags::empty(),
            Some([0xAA; 6]),
            Some(v4),
        );
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_inet_accepts_noarp_permanent_combined_state() {
        // EVPN-suppression entries land with NUD_NOARP | NUD_PERMANENT
        // (the same combined bitmask we use for our own AF_BRIDGE
        // programming). Comes through as NeighbourState::Other(0xC0).
        let cache = cache_for(100, 11, 22);
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet,
            99,
            NeighbourState::Other(NUD_NOARP | NUD_PERMANENT),
            NeighbourFlags::empty(),
            Some([0xAA; 6]),
            Some(v4),
        );
        assert!(matches!(
            classify_neigh(NeighEventKind::New, &msg, &cache),
            Some(LocalMacObservation::IpAdded { .. })
        ));
    }

    /// Regression: `NUD_STALE | NUD_PROBE` represents the kernel
    /// actively re-probing a stale entry — the binding is not
    /// freshly confirmed, just the kernel's previous belief. Acting
    /// on it would produce origination thrash. Earlier validity
    /// check accepted this combination because at least one valid
    /// bit was set; the explicit invalid mask rejects it.
    #[test]
    fn classify_inet_drops_stale_with_probe_bit() {
        let cache = cache_for(100, 11, 22);
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet,
            99,
            NeighbourState::Other(NUD_STALE | NUD_PROBE),
            NeighbourFlags::empty(),
            Some([0xAA; 6]),
            Some(v4),
        );
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    /// Regression: same shape — `NUD_REACHABLE | NUD_DELAY` means
    /// the kernel has scheduled revalidation against a previously-
    /// reachable entry. Drop until the next steady state.
    #[test]
    fn classify_inet_drops_reachable_with_delay_bit() {
        let cache = cache_for(100, 11, 22);
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet,
            99,
            NeighbourState::Other(NUD_REACHABLE | NUD_DELAY),
            NeighbourFlags::empty(),
            Some([0xAA; 6]),
            Some(v4),
        );
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_inet_drops_ext_learned_echo() {
        // NTF_EXT_LEARNED guard applies to all families — kernel echo
        // of routes we ourselves programmed must not surface upward.
        let cache = cache_for(100, 11, 22);
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet,
            99,
            NeighbourState::Reachable,
            NeighbourFlags::ExtLearned,
            Some([0xAA; 6]),
            Some(v4),
        );
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_inet_drops_unknown_bridge_ifindex() {
        // ifindex 555 is neither a known bridge nor port.
        let cache = cache_for(100, 11, 22);
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet,
            555,
            NeighbourState::Reachable,
            NeighbourFlags::empty(),
            Some([0xAA; 6]),
            Some(v4),
        );
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_inet_drops_message_without_destination() {
        let cache = cache_for(100, 11, 22);
        let msg = ip_neigh_msg(
            AddressFamily::Inet,
            99,
            NeighbourState::Reachable,
            NeighbourFlags::empty(),
            Some([0xAA; 6]),
            None,
        );
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    #[test]
    fn classify_inet_drops_message_without_mac() {
        let cache = cache_for(100, 11, 22);
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet,
            99,
            NeighbourState::Reachable,
            NeighbourFlags::empty(),
            None,
            Some(v4),
        );
        assert!(classify_neigh(NeighEventKind::New, &msg, &cache).is_none());
    }

    // --- IP advertisability filter ---
    //
    // Per ADR-0054 §1, the classifier is the boundary that decides
    // what shape of (IP, MAC) binding becomes an EVPN candidate.
    // These tests pin which IPs the filter accepts and rejects.

    /// Helper — runs an `AF_INET` / `AF_INET6` classifier message
    /// with the given IP and asserts whether the classifier emits or
    /// drops.
    fn assert_classify_inet(ip_str: &str, expect_emitted: bool) {
        let cache = cache_for(100, 11, 22);
        let ip: IpAddr = ip_str.parse().unwrap();
        let family = match ip {
            IpAddr::V4(_) => AddressFamily::Inet,
            IpAddr::V6(_) => AddressFamily::Inet6,
        };
        let msg = ip_neigh_msg(
            family,
            99,
            NeighbourState::Reachable,
            NeighbourFlags::empty(),
            Some([0xAA; 6]),
            Some(ip),
        );
        let got = classify_neigh(NeighEventKind::New, &msg, &cache);
        if expect_emitted {
            assert!(
                matches!(got, Some(LocalMacObservation::IpAdded { .. })),
                "expected IpAdded for {ip_str}, got {got:?}"
            );
        } else {
            assert!(got.is_none(), "expected drop for {ip_str}, got {got:?}");
        }
    }

    #[test]
    fn classify_accepts_ipv4_global_unicast() {
        assert_classify_inet("192.0.2.10", true);
    }

    #[test]
    fn classify_drops_ipv4_unspecified() {
        assert_classify_inet("0.0.0.0", false);
    }

    #[test]
    fn classify_drops_ipv4_multicast() {
        assert_classify_inet("224.0.0.1", false);
    }

    #[test]
    fn classify_drops_ipv4_broadcast() {
        assert_classify_inet("255.255.255.255", false);
    }

    #[test]
    fn classify_drops_ipv4_link_local_apipa() {
        assert_classify_inet("169.254.1.1", false);
    }

    #[test]
    fn classify_drops_ipv4_loopback() {
        assert_classify_inet("127.0.0.1", false);
    }

    #[test]
    fn classify_accepts_ipv6_global_unicast() {
        assert_classify_inet("2001:db8::1", true);
    }

    #[test]
    fn classify_drops_ipv6_unspecified() {
        assert_classify_inet("::", false);
    }

    #[test]
    fn classify_drops_ipv6_loopback() {
        assert_classify_inet("::1", false);
    }

    #[test]
    fn classify_drops_ipv6_multicast() {
        assert_classify_inet("ff02::1", false);
    }

    #[test]
    fn classify_drops_ipv6_link_local() {
        assert_classify_inet("fe80::1", false);
    }

    /// Filter applies on the delete edge too — if the domain
    /// shouldn't see an `IpAdded` for a non-advertisable IP, it
    /// shouldn't see an `IpRemoved` either. Otherwise a domain
    /// layer that filtered `IpAdded` would still get spurious
    /// `IpRemoved` events for IPs it never registered.
    #[test]
    fn classify_drops_non_advertisable_ip_on_delete() {
        let cache = cache_for(100, 11, 22);
        let bad: IpAddr = "fe80::1".parse().unwrap();
        let msg = ip_neigh_msg(
            AddressFamily::Inet6,
            99,
            NeighbourState::Reachable,
            NeighbourFlags::empty(),
            Some([0xAA; 6]),
            Some(bad),
        );
        assert!(classify_neigh(NeighEventKind::Del, &msg, &cache).is_none());
    }

    /// Pins `RTNLGRP_NEIGH` to its `<linux/rtnetlink.h>` enum value `3`,
    /// not the legacy `RTMGRP_NEIGH` bitmask `4`. v0.14.x shipped `4`
    /// here, which subscribed to `RTNLGRP_TC` instead and silently lost
    /// every neighbour notification (caught by the M37 origination
    /// smoke). The constant pin guards against the same regression.
    #[test]
    fn rtnlgrp_neigh_constant_matches_kernel_enum_value() {
        assert_eq!(RTNLGRP_NEIGH, 3);
    }
}
