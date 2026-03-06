//! Pure encoding functions for MRT `TABLE_DUMP_V2` records (RFC 6396).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

use rustbgpd_rib::route::Route;
use rustbgpd_rib::update::MrtPeerEntry;
use rustbgpd_wire::attribute::encode_path_attributes;
use rustbgpd_wire::{PathAttribute, Prefix};
use thiserror::Error;

/// MRT message type for `TABLE_DUMP_V2`.
const TABLE_DUMP_V2: u16 = 13;

/// `TABLE_DUMP_V2` subtypes.
const PEER_INDEX_TABLE: u16 = 1;
const RIB_IPV4_UNICAST: u16 = 2;
const RIB_IPV6_UNICAST: u16 = 4;
const RIB_IPV4_UNICAST_ADDPATH: u16 = 8;
const RIB_IPV6_UNICAST_ADDPATH: u16 = 9;

/// An individual RIB entry within a RIB_* record.
pub struct RibEntry {
    /// Index into the `PEER_INDEX_TABLE`.
    pub peer_index: u16,
    /// Unix timestamp when this route was originated.
    pub originated_time: u32,
    /// Add-Path path identifier (RFC 8050). 0 = no Add-Path.
    pub path_id: u32,
    /// BGP path attributes for this RIB entry.
    pub attributes: Vec<PathAttribute>,
}

/// MRT encoding errors.
#[derive(Debug, Error)]
pub enum EncodeError {
    /// A field value exceeds the maximum representable MRT wire size.
    #[error("{field} too large for MRT encoding: {value}")]
    FieldTooLarge {
        /// Name of the field that overflowed.
        field: &'static str,
        /// The actual value that was too large.
        value: usize,
    },
}

/// Encode the 12-byte MRT common header.
fn encode_mrt_header(buf: &mut Vec<u8>, timestamp: u32, mrt_type: u16, subtype: u16, length: u32) {
    buf.extend_from_slice(&timestamp.to_be_bytes());
    buf.extend_from_slice(&mrt_type.to_be_bytes());
    buf.extend_from_slice(&subtype.to_be_bytes());
    buf.extend_from_slice(&length.to_be_bytes());
}

/// Encode a complete MRT record: header + payload.
fn encode_mrt_record(
    buf: &mut Vec<u8>,
    timestamp: u32,
    subtype: u16,
    payload: &[u8],
) -> Result<(), EncodeError> {
    let length = u32::try_from(payload.len()).map_err(|_| EncodeError::FieldTooLarge {
        field: "MRT payload length",
        value: payload.len(),
    })?;
    encode_mrt_header(buf, timestamp, TABLE_DUMP_V2, subtype, length);
    buf.extend_from_slice(payload);
    Ok(())
}

/// Encode the `PEER_INDEX_TABLE` record (subtype 1).
///
/// Always uses AS4 (type bit 1 set) and includes IPv6 peers (type bit 0).
///
/// # Errors
///
/// Returns [`EncodeError::FieldTooLarge`] if the view name or peer count
/// exceeds the representable MRT field width.
pub fn encode_peer_index_table(
    buf: &mut Vec<u8>,
    timestamp: u32,
    collector_bgp_id: Ipv4Addr,
    view_name: &str,
    peers: &[MrtPeerEntry],
) -> Result<(), EncodeError> {
    let mut payload = Vec::new();

    // Collector BGP ID
    payload.extend_from_slice(&collector_bgp_id.octets());

    // View name
    let name_bytes = view_name.as_bytes();
    let view_name_len =
        u16::try_from(name_bytes.len()).map_err(|_| EncodeError::FieldTooLarge {
            field: "PEER_INDEX_TABLE.view_name length",
            value: name_bytes.len(),
        })?;
    payload.extend_from_slice(&view_name_len.to_be_bytes());
    payload.extend_from_slice(name_bytes);

    // Peer count
    let peer_count = u16::try_from(peers.len()).map_err(|_| EncodeError::FieldTooLarge {
        field: "PEER_INDEX_TABLE.peer_count",
        value: peers.len(),
    })?;
    payload.extend_from_slice(&peer_count.to_be_bytes());

    for peer in peers {
        // Peer type: bit 0 = IPv6, bit 1 = AS4 (always set)
        let peer_type: u8 = match peer.peer_addr {
            IpAddr::V6(_) => 0b11, // IPv6 + AS4
            IpAddr::V4(_) => 0b10, // AS4 only
        };
        payload.push(peer_type);

        // Peer BGP ID
        payload.extend_from_slice(&peer.peer_bgp_id.octets());

        // Peer IP address
        match peer.peer_addr {
            IpAddr::V4(v4) => payload.extend_from_slice(&v4.octets()),
            IpAddr::V6(v6) => payload.extend_from_slice(&v6.octets()),
        }

        // Peer AS (always 4 bytes)
        payload.extend_from_slice(&peer.peer_asn.to_be_bytes());
    }

    encode_mrt_record(buf, timestamp, PEER_INDEX_TABLE, &payload)
}

/// Synthesize path attributes for MRT encoding from a `Route`.
///
/// The route's `attributes` vec doesn't contain next-hop or `MP_REACH`
/// (stripped per MP-BGP architecture). We reconstruct the appropriate
/// attribute based on the route's prefix family:
/// - IPv4: `PathAttribute::NextHop(ipv4)` (type 3)
/// - IPv6: `PathAttribute::MpReachNlri` with IPv6 next-hop, empty NLRI
#[must_use]
pub fn synthesize_attributes(route: &Route) -> Vec<PathAttribute> {
    let mut attrs = route.attributes.clone();

    match route.prefix {
        Prefix::V4(_) => {
            match route.next_hop {
                IpAddr::V4(nh) => {
                    // Synthesize NEXT_HOP for IPv4.
                    // Insert after ORIGIN and AS_PATH if they exist (canonical order).
                    let insert_pos = attrs
                        .iter()
                        .position(|a| {
                            !matches!(a, PathAttribute::Origin(_) | PathAttribute::AsPath(_))
                        })
                        .unwrap_or(attrs.len());
                    attrs.insert(insert_pos, PathAttribute::NextHop(nh));
                }
                IpAddr::V6(_) => {
                    // RFC 8950: IPv4 NLRI can carry IPv6 next-hop via MP_REACH_NLRI.
                    use rustbgpd_wire::{Afi, MpReachNlri, Safi};
                    attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
                        afi: Afi::Ipv4,
                        safi: Safi::Unicast,
                        next_hop: route.next_hop,
                        announced: vec![],
                        flowspec_announced: vec![],
                    }));
                }
            }
        }
        Prefix::V6(_) => {
            // Synthesize MP_REACH_NLRI for IPv6 with `next_hop` only (no NLRI —
            // the prefix is in the RIB entry header per `TABLE_DUMP_V2` spec).
            use rustbgpd_wire::{Afi, MpReachNlri, Safi};
            let mp_reach = PathAttribute::MpReachNlri(MpReachNlri {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                next_hop: route.next_hop,
                announced: vec![],
                flowspec_announced: vec![],
            });
            attrs.push(mp_reach);
        }
    }

    attrs
}

/// Encode a single RIB entry (shared by all RIB_* subtypes).
fn encode_rib_entry(
    buf: &mut Vec<u8>,
    entry: &RibEntry,
    add_path: bool,
) -> Result<(), EncodeError> {
    if add_path {
        buf.extend_from_slice(&entry.path_id.to_be_bytes());
    }

    buf.extend_from_slice(&entry.peer_index.to_be_bytes());
    buf.extend_from_slice(&entry.originated_time.to_be_bytes());

    // Encode attributes to a temp buffer to get length
    let mut attr_buf = Vec::new();
    encode_path_attributes(&entry.attributes, &mut attr_buf, true, false);
    let attr_len = u16::try_from(attr_buf.len()).map_err(|_| EncodeError::FieldTooLarge {
        field: "RIB entry attribute length",
        value: attr_buf.len(),
    })?;
    buf.extend_from_slice(&attr_len.to_be_bytes());
    buf.extend_from_slice(&attr_buf);
    Ok(())
}

/// Encode a prefix into MRT format: length byte then ceil(len/8) prefix bytes.
fn encode_prefix_bytes(buf: &mut Vec<u8>, prefix: &Prefix) {
    match prefix {
        Prefix::V4(v4) => {
            buf.push(v4.len);
            let byte_len = usize::from(v4.len).div_ceil(8);
            buf.extend_from_slice(&v4.addr.octets()[..byte_len]);
        }
        Prefix::V6(v6) => {
            buf.push(v6.len);
            let byte_len = usize::from(v6.len).div_ceil(8);
            buf.extend_from_slice(&v6.addr.octets()[..byte_len]);
        }
    }
}

/// Encode a `RIB_IPV4_UNICAST` or `RIB_IPV6_UNICAST` record.
///
/// If any entry has `path_id != 0`, the ADDPATH subtype is used instead.
///
/// # Errors
///
/// Returns [`EncodeError::FieldTooLarge`] if the number of entries or encoded
/// attribute payload for an entry exceeds MRT field limits.
pub fn encode_rib_entries(
    buf: &mut Vec<u8>,
    timestamp: u32,
    seq_num: u32,
    prefix: &Prefix,
    entries: &[RibEntry],
) -> Result<(), EncodeError> {
    let has_addpath = entries.iter().any(|e| e.path_id != 0);

    let subtype = match (prefix, has_addpath) {
        (Prefix::V4(_), false) => RIB_IPV4_UNICAST,
        (Prefix::V4(_), true) => RIB_IPV4_UNICAST_ADDPATH,
        (Prefix::V6(_), false) => RIB_IPV6_UNICAST,
        (Prefix::V6(_), true) => RIB_IPV6_UNICAST_ADDPATH,
    };

    let mut payload = Vec::new();
    payload.extend_from_slice(&seq_num.to_be_bytes());

    encode_prefix_bytes(&mut payload, prefix);

    let entry_count = u16::try_from(entries.len()).map_err(|_| EncodeError::FieldTooLarge {
        field: "RIB entry count",
        value: entries.len(),
    })?;
    payload.extend_from_slice(&entry_count.to_be_bytes());

    for entry in entries {
        encode_rib_entry(&mut payload, entry, has_addpath)?;
    }

    encode_mrt_record(buf, timestamp, subtype, &payload)
}

/// Encode a full MRT `TABLE_DUMP_V2` dump from a snapshot.
///
/// Returns the complete binary output suitable for writing to a file.
///
/// # Errors
///
/// Returns [`EncodeError::FieldTooLarge`] if any encoded MRT field exceeds its
/// wire-size bounds (for example peer index, record payload, or attribute
/// lengths).
pub fn encode_snapshot(
    collector_bgp_id: Ipv4Addr,
    peers: &[MrtPeerEntry],
    routes: &[Route],
    timestamp: u32,
) -> Result<Vec<u8>, EncodeError> {
    let mut buf = Vec::new();

    // 1. Build effective peer list from explicit peers + any route-origin peers.
    let mut effective_peers: Vec<MrtPeerEntry> = peers.to_vec();
    let mut seen_peers: HashSet<IpAddr> = effective_peers.iter().map(|p| p.peer_addr).collect();
    for route in routes {
        if seen_peers.insert(route.peer) {
            effective_peers.push(MrtPeerEntry {
                peer_addr: route.peer,
                peer_bgp_id: Ipv4Addr::UNSPECIFIED,
                peer_asn: 0,
            });
        }
    }
    effective_peers.sort_by(|a, b| {
        let a_key = match a.peer_addr {
            IpAddr::V4(v4) => (0u8, v4.octets().to_vec()),
            IpAddr::V6(v6) => (1u8, v6.octets().to_vec()),
        };
        let b_key = match b.peer_addr {
            IpAddr::V4(v4) => (0u8, v4.octets().to_vec()),
            IpAddr::V6(v6) => (1u8, v6.octets().to_vec()),
        };
        a_key
            .cmp(&b_key)
            .then(a.peer_asn.cmp(&b.peer_asn))
            .then(a.peer_bgp_id.octets().cmp(&b.peer_bgp_id.octets()))
    });

    // 2. `PEER_INDEX_TABLE`
    encode_peer_index_table(&mut buf, timestamp, collector_bgp_id, "", &effective_peers)?;

    // 3. Build peer index lookup
    let peer_index: HashMap<IpAddr, u16> = effective_peers
        .iter()
        .enumerate()
        .map(|(i, p)| {
            u16::try_from(i)
                .map(|idx| (p.peer_addr, idx))
                .map_err(|_| EncodeError::FieldTooLarge {
                    field: "peer index",
                    value: i,
                })
        })
        .collect::<Result<_, _>>()?;

    // 4. Group routes by prefix
    let mut by_prefix: HashMap<Prefix, Vec<&Route>> = HashMap::new();
    for route in routes {
        by_prefix.entry(route.prefix).or_default().push(route);
    }

    // 5. Encode each prefix group
    let mut seq_num: u32 = 0;
    // Sort prefixes for deterministic output
    let mut prefixes: Vec<Prefix> = by_prefix.keys().copied().collect();
    prefixes.sort_by(|a, b| {
        let a_bytes = match a {
            Prefix::V4(v4) => (0u8, v4.addr.octets().to_vec(), v4.len),
            Prefix::V6(v6) => (1u8, v6.addr.octets().to_vec(), v6.len),
        };
        let b_bytes = match b {
            Prefix::V4(v4) => (0u8, v4.addr.octets().to_vec(), v4.len),
            Prefix::V6(v6) => (1u8, v6.addr.octets().to_vec(), v6.len),
        };
        a_bytes.cmp(&b_bytes)
    });
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    for prefix in &prefixes {
        let mut prefix_routes = by_prefix[prefix].clone();
        prefix_routes.sort_by(|a, b| {
            let a_idx = peer_index.get(&a.peer).copied().unwrap_or(u16::MAX);
            let b_idx = peer_index.get(&b.peer).copied().unwrap_or(u16::MAX);
            a_idx
                .cmp(&b_idx)
                .then(a.path_id.cmp(&b.path_id))
                .then(prefix_family_sort_key(a.prefix).cmp(&prefix_family_sort_key(b.prefix)))
        });
        let mut entries: Vec<RibEntry> = Vec::with_capacity(prefix_routes.len());
        for route in prefix_routes {
            let Some(&idx) = peer_index.get(&route.peer) else {
                continue;
            };
            let age = route.received_at.elapsed().as_secs();
            let originated_u64 = now_secs.saturating_sub(age);
            let originated = u32::try_from(originated_u64).unwrap_or(u32::MAX);
            entries.push(RibEntry {
                peer_index: idx,
                originated_time: originated,
                path_id: route.path_id,
                attributes: synthesize_attributes(route),
            });
        }

        if !entries.is_empty() {
            encode_rib_entries(&mut buf, timestamp, seq_num, prefix, &entries)?;
            seq_num = seq_num.wrapping_add(1);
        }
    }

    Ok(buf)
}

fn prefix_family_sort_key(prefix: Prefix) -> (u8, Vec<u8>, u8) {
    match prefix {
        Prefix::V4(v4) => (0u8, v4.addr.octets().to_vec(), v4.len),
        Prefix::V6(v6) => (1u8, v6.addr.octets().to_vec(), v6.len),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::Instant;

    use rustbgpd_rib::route::{Route, RouteOrigin};
    use rustbgpd_wire::{
        AsPath, Ipv4Prefix, Ipv6Prefix, Origin, PathAttribute, Prefix, RpkiValidation,
    };

    use super::*;

    fn make_peer(addr: IpAddr, asn: u32) -> MrtPeerEntry {
        let bgp_id = match addr {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => Ipv4Addr::new(10, 0, 0, 1),
        };
        MrtPeerEntry {
            peer_addr: addr,
            peer_bgp_id: bgp_id,
            peer_asn: asn,
        }
    }

    fn make_route(prefix: Prefix, peer: IpAddr, next_hop: IpAddr) -> Route {
        Route {
            prefix,
            next_hop,
            peer,
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![rustbgpd_wire::AsPathSegment::AsSequence(vec![65001])],
                }),
                PathAttribute::LocalPref(100),
            ],
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: RpkiValidation::NotFound,
        }
    }

    #[test]
    fn mrt_header_encoding() {
        let mut buf = Vec::new();
        encode_mrt_header(&mut buf, 1_700_000_000, TABLE_DUMP_V2, PEER_INDEX_TABLE, 42);
        assert_eq!(buf.len(), 12);
        // timestamp
        assert_eq!(
            u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            1_700_000_000
        );
        // type = 13
        assert_eq!(u16::from_be_bytes([buf[4], buf[5]]), 13);
        // subtype = 1
        assert_eq!(u16::from_be_bytes([buf[6], buf[7]]), 1);
        // length = 42
        assert_eq!(u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]), 42);
    }

    #[test]
    fn peer_index_table_encoding() {
        let peers = vec![
            make_peer(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 65001),
            make_peer(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                65002,
            ),
        ];

        let mut buf = Vec::new();
        encode_peer_index_table(
            &mut buf,
            1_700_000_000,
            Ipv4Addr::new(1, 2, 3, 4),
            "",
            &peers,
        )
        .unwrap();

        // Should have 12-byte header + payload
        assert!(buf.len() > 12);
        // MRT type = 13, subtype = 1
        assert_eq!(u16::from_be_bytes([buf[4], buf[5]]), 13);
        assert_eq!(u16::from_be_bytes([buf[6], buf[7]]), 1);

        // Collector BGP ID at offset 12
        assert_eq!(&buf[12..16], &[1, 2, 3, 4]);

        // View name length = 0
        assert_eq!(u16::from_be_bytes([buf[16], buf[17]]), 0);

        // Peer count = 2
        assert_eq!(u16::from_be_bytes([buf[18], buf[19]]), 2);

        // First peer: type = 0b10 (AS4, IPv4)
        assert_eq!(buf[20], 0b10);

        // Second peer: type = 0b11 (AS4, IPv6)
        // After first peer: 1 (type) + 4 (bgp_id) + 4 (ipv4) + 4 (asn) = 13
        let second_peer_offset = 20 + 13;
        assert_eq!(buf[second_peer_offset], 0b11);
    }

    #[test]
    fn rib_ipv4_unicast_encoding() {
        let entry = RibEntry {
            peer_index: 0,
            originated_time: 1_700_000_000,
            path_id: 0,
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
            ],
        };

        let prefix = Prefix::V4(Ipv4Prefix {
            addr: Ipv4Addr::new(192, 168, 1, 0),
            len: 24,
        });

        let mut buf = Vec::new();
        encode_rib_entries(&mut buf, 1_700_000_000, 0, &prefix, &[entry]).unwrap();

        assert!(buf.len() > 12);
        // subtype = 2 (RIB_IPV4_UNICAST)
        assert_eq!(u16::from_be_bytes([buf[6], buf[7]]), 2);

        // seq_num at offset 12 = 0
        assert_eq!(u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]), 0);

        // prefix_len at offset 16 = 24
        assert_eq!(buf[16], 24);

        // prefix bytes: 3 bytes for /24
        assert_eq!(&buf[17..20], &[192, 168, 1]);

        // entry_count at offset 20 = 1
        assert_eq!(u16::from_be_bytes([buf[20], buf[21]]), 1);
    }

    #[test]
    fn rib_ipv6_unicast_encoding() {
        let entry = RibEntry {
            peer_index: 1,
            originated_time: 1_700_000_000,
            path_id: 0,
            attributes: vec![PathAttribute::Origin(Origin::Igp)],
        };

        let prefix = Prefix::V6(Ipv6Prefix {
            addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            len: 32,
        });

        let mut buf = Vec::new();
        encode_rib_entries(&mut buf, 1_700_000_000, 1, &prefix, &[entry]).unwrap();

        // subtype = 4 (RIB_IPV6_UNICAST)
        assert_eq!(u16::from_be_bytes([buf[6], buf[7]]), 4);

        // prefix_len = 32
        assert_eq!(buf[16], 32);

        // 4 bytes for /32 prefix
        assert_eq!(&buf[17..21], &[0x20, 0x01, 0x0d, 0xb8]);
    }

    #[test]
    fn addpath_subtype_used_when_path_id_nonzero() {
        let entry = RibEntry {
            peer_index: 0,
            originated_time: 1_700_000_000,
            path_id: 42,
            attributes: vec![PathAttribute::Origin(Origin::Igp)],
        };

        let prefix = Prefix::V4(Ipv4Prefix {
            addr: Ipv4Addr::new(10, 0, 0, 0),
            len: 8,
        });

        let mut buf = Vec::new();
        encode_rib_entries(&mut buf, 1_700_000_000, 0, &prefix, &[entry]).unwrap();

        // subtype = 8 (RIB_IPV4_UNICAST_ADDPATH)
        assert_eq!(u16::from_be_bytes([buf[6], buf[7]]), 8);
    }

    #[test]
    fn synthesize_ipv4_next_hop() {
        let route = make_route(
            Prefix::V4(Ipv4Prefix {
                addr: Ipv4Addr::new(10, 0, 0, 0),
                len: 8,
            }),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        );

        let attrs = synthesize_attributes(&route);
        let has_nh = attrs.iter().any(|a| matches!(a, PathAttribute::NextHop(_)));
        assert!(has_nh, "IPv4 route should have synthesized NextHop");
    }

    #[test]
    fn synthesize_ipv6_mp_reach() {
        let route = make_route(
            Prefix::V6(Ipv6Prefix {
                addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                len: 32,
            }),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        );

        let attrs = synthesize_attributes(&route);
        let has_mp = attrs
            .iter()
            .any(|a| matches!(a, PathAttribute::MpReachNlri(_)));
        assert!(has_mp, "IPv6 route should have synthesized MpReachNlri");
    }

    #[test]
    fn synthesize_ipv4_mp_reach_for_ipv6_next_hop() {
        let route = make_route(
            Prefix::V4(Ipv4Prefix {
                addr: Ipv4Addr::new(203, 0, 113, 0),
                len: 24,
            }),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        );

        let attrs = synthesize_attributes(&route);
        assert!(
            attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::MpReachNlri(_))),
            "RFC 8950 IPv4 route with IPv6 NH should synthesize MpReachNlri"
        );
        assert!(
            !attrs.iter().any(|a| matches!(a, PathAttribute::NextHop(_))),
            "RFC 8950 IPv4 route with IPv6 NH must not synthesize IPv4 NextHop"
        );
    }

    #[test]
    fn full_snapshot_encoding() {
        let peer = make_peer(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 65001);
        let route = make_route(
            Prefix::V4(Ipv4Prefix {
                addr: Ipv4Addr::new(192, 168, 0, 0),
                len: 16,
            }),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        );

        let data =
            encode_snapshot(Ipv4Addr::new(1, 2, 3, 4), &[peer], &[route], 1_700_000_000).unwrap();

        // Should have at least two MRT records (peer index + one RIB entry)
        assert!(data.len() > 24);

        // First record: `PEER_INDEX_TABLE`
        assert_eq!(u16::from_be_bytes([data[4], data[5]]), 13);
        assert_eq!(u16::from_be_bytes([data[6], data[7]]), 1);

        // Find second record
        let first_len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let second_offset = 12 + first_len;
        // Second record: RIB_IPV4_UNICAST
        assert_eq!(
            u16::from_be_bytes([data[second_offset + 4], data[second_offset + 5]]),
            13
        );
        assert_eq!(
            u16::from_be_bytes([data[second_offset + 6], data[second_offset + 7]]),
            2
        );
    }

    #[test]
    fn empty_snapshot_encoding() {
        let data = encode_snapshot(Ipv4Addr::new(1, 2, 3, 4), &[], &[], 1_700_000_000).unwrap();
        // Should have exactly one MRT record (peer index table with 0 peers)
        assert!(data.len() > 12);
        assert_eq!(u16::from_be_bytes([data[6], data[7]]), 1);
    }

    #[test]
    fn snapshot_includes_routes_for_missing_peer_metadata() {
        let route = make_route(
            Prefix::V4(Ipv4Prefix {
                addr: Ipv4Addr::new(198, 51, 100, 0),
                len: 24,
            }),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
        );

        let data =
            encode_snapshot(Ipv4Addr::new(1, 2, 3, 4), &[], &[route], 1_700_000_000).unwrap();
        // Must include a peer index table plus at least one RIB record.
        let first_len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let second_offset = 12 + first_len;
        assert!(data.len() > second_offset + 12);
        assert_eq!(
            u16::from_be_bytes([data[second_offset + 6], data[second_offset + 7]]),
            RIB_IPV4_UNICAST
        );
    }
}
