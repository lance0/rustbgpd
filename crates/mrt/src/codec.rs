//! Pure encoding functions for MRT `TABLE_DUMP_V2` records (RFC 6396).
use rustbgpd_rib::route::{EvpnRibRoute, Route};
use rustbgpd_rib::update::MrtPeerEntry;
use rustbgpd_wire::attribute::encode_path_attributes;
use rustbgpd_wire::error::EncodeError as WireEncodeError;
use rustbgpd_wire::{Afi, MpReachNlri, PathAttribute, Prefix, Safi, encode_evpn_nlri};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use thiserror::Error;
/// MRT message type for `TABLE_DUMP_V2`.
pub(crate) const TABLE_DUMP_V2: u16 = 13;
/// `TABLE_DUMP_V2` subtypes.
pub(crate) const PEER_INDEX_TABLE: u16 = 1;
pub(crate) const RIB_IPV4_UNICAST: u16 = 2;
pub(crate) const RIB_IPV6_UNICAST: u16 = 4;
/// RFC 6396 §4.3.5 — generic RIB record carrying any AFI/SAFI.
/// Used here for L2VPN/EVPN (AFI 25 / SAFI 70).
pub(crate) const RIB_GENERIC: u16 = 6;
pub(crate) const RIB_IPV4_UNICAST_ADDPATH: u16 = 8;
pub(crate) const RIB_IPV6_UNICAST_ADDPATH: u16 = 9;
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

/// One peer/family for which the warm snapshot must use RFC 8050 framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MrtAddPathReceiveProfile {
    /// Peer transport address.
    pub peer: IpAddr,
    /// Address family.
    pub afi: Afi,
    /// Subsequent address family.
    pub safi: Safi,
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
    /// A BGP path attribute could not be encoded.
    #[error("path attribute encode failed: {0}")]
    AttributeEncode(#[from] WireEncodeError),
    /// Add-Path profile contained duplicates or an unsupported family.
    #[error("invalid MRT Add-Path receive profile for {peer} ({afi:?}/{safi:?}): {reason}")]
    InvalidAddPathProfile {
        /// Peer in the invalid profile.
        peer: IpAddr,
        /// Address family in the invalid profile.
        afi: Afi,
        /// Subsequent address family in the invalid profile.
        safi: Safi,
        /// Why the profile cannot be encoded.
        reason: &'static str,
    },
    /// A non-Add-Path profile carried a nonzero path identifier.
    #[error("route from {peer} has path_id {path_id} but its MRT profile is not Add-Path")]
    AddPathProfileMismatch {
        /// Advertising peer.
        peer: IpAddr,
        /// Unexpected nonzero path identifier.
        path_id: u32,
    },
    /// A route depends on identity that V1 cannot recover exactly.
    #[error("route from {peer} cannot be used in a V1 warm snapshot: {reason}")]
    UnsupportedWarmRouteProfile {
        /// Advertising peer.
        peer: IpAddr,
        /// Why the route cannot be restored exactly.
        reason: &'static str,
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
    let mut attrs = (*route.attributes).clone();
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
                        link_local_next_hop: route.link_local_next_hop,
                        announced: vec![],
                        flowspec_announced: vec![],
                        evpn_announced: vec![],
                        bgpls_announced: vec![],
                        labeled_announced: vec![],
                        vpn_announced: vec![],
                        rtc_announced: vec![],
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
                link_local_next_hop: route.link_local_next_hop,
                announced: vec![],
                flowspec_announced: vec![],
                evpn_announced: vec![],
                bgpls_announced: vec![],
                labeled_announced: vec![],
                vpn_announced: vec![],
                rtc_announced: vec![],
            });
            attrs.push(mp_reach);
        }
    }
    attrs
}
/// Synthesize path attributes for an EVPN RIB entry.
///
/// `EvpnRibRoute.attributes` was stripped of `MP_REACH_NLRI` at decode
/// (per MP-BGP architecture). For the MRT encoding we add a fresh
/// `MP_REACH_NLRI` carrying the next-hop only — the EVPN NLRI itself
/// rides in the `RIB_GENERIC` record header per RFC 6396 §4.3.5, not
/// in the attribute. The attribute's NLRI/AFI/SAFI fields are dropped
/// when the entry is serialized by the internal MRT RIB-attribute
/// encoder, which rewrites `MP_REACH_NLRI` to the RFC 6396 §4.3.4
/// reduced form (NH-Len + NH bytes only).
#[must_use]
pub fn synthesize_evpn_attributes(route: &EvpnRibRoute) -> Vec<PathAttribute> {
    let mut attrs = (*route.attributes).clone();
    attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
        afi: Afi::L2Vpn,
        safi: Safi::Evpn,
        next_hop: route.next_hop,
        link_local_next_hop: route.link_local_next_hop,
        announced: vec![],
        flowspec_announced: vec![],
        evpn_announced: vec![],
        bgpls_announced: vec![],
        labeled_announced: vec![],
        vpn_announced: vec![],
        rtc_announced: vec![],
    }));
    attrs
}
/// Encode a single EVPN route as a `RIB_GENERIC` (subtype 6) record.
///
/// Layout per RFC 6396 §4.3.5:
/// ```text
///   Sequence Number (4)
///   AFI (2)              = 25 (L2VPN)
///   SAFI (1)             = 70 (EVPN)
///   NLRI (variable)      = encoded EVPN route TLV (route_type + length + body)
///   Entry Count (2)      = 1 (EVPN does not use Add-Path in this codebase)
///   RIB Entries          = single entry [peer_index, originated_time,
///                          attribute_length, attributes]
/// ```
///
/// # Errors
///
/// Returns [`EncodeError::FieldTooLarge`] if the encoded attribute payload
/// for the entry exceeds the 16-bit `attribute_length` field.
fn encode_evpn_rib_generic(
    buf: &mut Vec<u8>,
    timestamp: u32,
    seq_num: u32,
    route: &EvpnRibRoute,
    peer_index: u16,
    originated_time: u32,
) -> Result<(), EncodeError> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&seq_num.to_be_bytes());
    payload.extend_from_slice(&(Afi::L2Vpn as u16).to_be_bytes());
    payload.push(Safi::Evpn as u8);
    encode_evpn_nlri(std::slice::from_ref(&route.route), &mut payload);
    payload.extend_from_slice(&1u16.to_be_bytes());
    let entry = RibEntry {
        peer_index,
        originated_time,
        path_id: 0,
        attributes: synthesize_evpn_attributes(route),
    };
    encode_rib_entry(&mut payload, &entry, false)?;
    encode_mrt_record(buf, timestamp, RIB_GENERIC, &payload)
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
    let mut attr_buf = Vec::new();
    encode_mrt_rib_attributes(&entry.attributes, &mut attr_buf)?;
    let attr_len = u16::try_from(attr_buf.len()).map_err(|_| EncodeError::FieldTooLarge {
        field: "RIB entry attribute length",
        value: attr_buf.len(),
    })?;
    buf.extend_from_slice(&attr_len.to_be_bytes());
    buf.extend_from_slice(&attr_buf);
    Ok(())
}
/// Encode path attributes for an MRT RIB entry per RFC 6396 §4.3.4.
///
/// `MP_REACH_NLRI` is rewritten to the MRT-reduced form: only NH-Len
/// and the next-hop bytes appear in the attribute value. The AFI,
/// SAFI, Reserved, and NLRI fields are omitted because the RIB entry
/// header already carries that information. All other attributes
/// encode identically to a regular BGP UPDATE.
fn encode_mrt_rib_attributes(
    attrs: &[PathAttribute],
    buf: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let others: Vec<PathAttribute> = attrs
        .iter()
        .filter(|a| !matches!(a, PathAttribute::MpReachNlri(_)))
        .cloned()
        .collect();
    encode_path_attributes(&others, buf, true, false)?;
    for attr in attrs {
        if let PathAttribute::MpReachNlri(mp) = attr {
            encode_mrt_mp_reach(mp.next_hop, mp.link_local_next_hop, buf);
        }
    }
    Ok(())
}
/// Append a single `MP_REACH_NLRI` attribute in MRT-reduced form.
///
/// Wire layout per RFC 6396 §4.3.4 — TLV header followed by the
/// reduced value (NH-Len + NH bytes only). The attribute uses the
/// optional flag (0x80) and type code 14, matching the standard
/// `MP_REACH_NLRI` framing.
///
/// When `link_local` is `Some`, the value is 33 bytes: NH-Len=32 +
/// 16-byte global + 16-byte link-local, per RFC 4760 §3 / RFC 2545.
fn encode_mrt_mp_reach(
    next_hop: IpAddr,
    link_local: Option<std::net::Ipv6Addr>,
    buf: &mut Vec<u8>,
) {
    let mut value: Vec<u8> = Vec::with_capacity(33);
    match (next_hop, link_local) {
        (IpAddr::V4(addr), _) => {
            value.push(4);
            value.extend_from_slice(&addr.octets());
        }
        (IpAddr::V6(addr), Some(ll)) => {
            value.push(32);
            value.extend_from_slice(&addr.octets());
            value.extend_from_slice(&ll.octets());
        }
        (IpAddr::V6(addr), None) => {
            value.push(16);
            value.extend_from_slice(&addr.octets());
        }
    }
    buf.push(0x80);
    buf.push(14);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "value length is at most 33 bytes"
    )]
    buf.push(value.len() as u8);
    buf.extend_from_slice(&value);
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
    encode_rib_entries_profile(buf, timestamp, seq_num, prefix, entries, has_addpath)
}

fn encode_rib_entries_profile(
    buf: &mut Vec<u8>,
    timestamp: u32,
    seq_num: u32,
    prefix: &Prefix,
    entries: &[RibEntry],
    has_addpath: bool,
) -> Result<(), EncodeError> {
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
    evpn_routes: &[EvpnRibRoute],
    timestamp: u32,
) -> Result<Vec<u8>, EncodeError> {
    encode_snapshot_with_view(collector_bgp_id, "", peers, routes, evpn_routes, timestamp)
}

/// Encode a full MRT snapshot with an explicit `PEER_INDEX_TABLE` view name.
///
/// Warm checkpoints use the view name as a caller-issued generation and bind
/// it into the warm-bundle identity. Periodic dumps should continue to use
/// [`encode_snapshot`], whose view name remains empty for compatibility.
///
/// # Errors
///
/// Returns [`EncodeError::FieldTooLarge`] if the view name or another encoded
/// MRT field exceeds its wire-size bound.
pub fn encode_snapshot_with_view(
    collector_bgp_id: Ipv4Addr,
    view_name: &str,
    peers: &[MrtPeerEntry],
    routes: &[Route],
    evpn_routes: &[EvpnRibRoute],
    timestamp: u32,
) -> Result<Vec<u8>, EncodeError> {
    encode_snapshot_inner(
        collector_bgp_id,
        view_name,
        peers,
        routes,
        evpn_routes,
        timestamp,
        None,
    )
}

/// Encode a warm snapshot with an exact per-peer Add-Path receive profile.
///
/// Entries for one prefix are split into separate Add-Path and legacy RIB
/// records when peers negotiated different profiles. This preserves a zero
/// path identifier as an Add-Path entry and gives the warm loader an exact
/// record-subtype identity to validate.
///
/// # Errors
///
/// Returns [`EncodeError::InvalidAddPathProfile`] for duplicate or non-unicast
/// profiles, [`EncodeError::AddPathProfileMismatch`] when a route with a
/// nonzero path ID is assigned to a legacy profile, and
/// [`EncodeError::UnsupportedWarmRouteProfile`] when next-hop scope cannot be
/// recovered exactly.
pub fn encode_warm_snapshot(
    collector_bgp_id: Ipv4Addr,
    view_name: &str,
    peers: &[MrtPeerEntry],
    routes: &[Route],
    evpn_routes: &[EvpnRibRoute],
    timestamp: u32,
    add_path_receive: &[MrtAddPathReceiveProfile],
) -> Result<Vec<u8>, EncodeError> {
    if let Some(route) = routes.iter().find(|route| {
        route.next_hop_scope.is_some()
            || route.link_local_next_hop.is_some()
            || is_ipv6_link_local(route.next_hop)
    }) {
        return Err(EncodeError::UnsupportedWarmRouteProfile {
            peer: route.peer,
            reason: "scoped or link-local next-hop identity",
        });
    }
    if let Some(route) = evpn_routes
        .iter()
        .find(|route| route.link_local_next_hop.is_some() || is_ipv6_link_local(route.next_hop))
    {
        return Err(EncodeError::UnsupportedWarmRouteProfile {
            peer: route.peer,
            reason: "link-local next-hop identity",
        });
    }
    let mut unique = HashSet::with_capacity(add_path_receive.len());
    for profile in add_path_receive {
        if !unique.insert(*profile) {
            return Err(EncodeError::InvalidAddPathProfile {
                peer: profile.peer,
                afi: profile.afi,
                safi: profile.safi,
                reason: "duplicate profile",
            });
        }
    }
    if let Some(profile) = add_path_receive.iter().find(|profile| {
        !matches!(
            (profile.afi, profile.safi),
            (Afi::Ipv4 | Afi::Ipv6, Safi::Unicast)
        )
    }) {
        return Err(EncodeError::InvalidAddPathProfile {
            peer: profile.peer,
            afi: profile.afi,
            safi: profile.safi,
            reason: "only IPv4/IPv6 unicast Add-Path is supported by TABLE_DUMP_V2",
        });
    }
    encode_snapshot_inner(
        collector_bgp_id,
        view_name,
        peers,
        routes,
        evpn_routes,
        timestamp,
        Some(&unique),
    )
}

fn is_ipv6_link_local(address: IpAddr) -> bool {
    matches!(address, IpAddr::V6(address) if address.segments()[0] & 0xffc0 == 0xfe80)
}

#[expect(
    clippy::too_many_lines,
    reason = "Single-pass encoder over peer index, unicast prefix groups, and EVPN RIB_GENERIC records — splitting hides the linear flow"
)]
fn encode_snapshot_inner(
    collector_bgp_id: Ipv4Addr,
    view_name: &str,
    peers: &[MrtPeerEntry],
    routes: &[Route],
    evpn_routes: &[EvpnRibRoute],
    timestamp: u32,
    add_path_receive: Option<&HashSet<MrtAddPathReceiveProfile>>,
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
    for route in evpn_routes {
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
    encode_peer_index_table(
        &mut buf,
        timestamp,
        collector_bgp_id,
        view_name,
        &effective_peers,
    )?;
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
        let mut legacy_entries: Vec<RibEntry> = Vec::with_capacity(prefix_routes.len());
        let mut add_path_entries: Vec<RibEntry> = Vec::new();
        for route in prefix_routes {
            let Some(&idx) = peer_index.get(&route.peer) else {
                continue;
            };
            let age = route.received_at.elapsed().as_secs();
            let originated_u64 = now_secs.saturating_sub(age);
            let originated = u32::try_from(originated_u64).unwrap_or(u32::MAX);
            let entry = RibEntry {
                peer_index: idx,
                originated_time: originated,
                path_id: route.path_id,
                attributes: synthesize_attributes(route),
            };
            let uses_add_path = add_path_receive.is_some_and(|profiles| {
                let afi = match prefix {
                    Prefix::V4(_) => Afi::Ipv4,
                    Prefix::V6(_) => Afi::Ipv6,
                };
                profiles.contains(&MrtAddPathReceiveProfile {
                    peer: route.peer,
                    afi,
                    safi: Safi::Unicast,
                })
            });
            if add_path_receive.is_some() && !uses_add_path && route.path_id != 0 {
                return Err(EncodeError::AddPathProfileMismatch {
                    peer: route.peer,
                    path_id: route.path_id,
                });
            }
            if uses_add_path {
                add_path_entries.push(entry);
            } else {
                legacy_entries.push(entry);
            }
        }
        if !legacy_entries.is_empty() {
            if add_path_receive.is_some() {
                encode_rib_entries_profile(
                    &mut buf,
                    timestamp,
                    seq_num,
                    prefix,
                    &legacy_entries,
                    false,
                )?;
            } else {
                encode_rib_entries(&mut buf, timestamp, seq_num, prefix, &legacy_entries)?;
            }
            seq_num = seq_num.wrapping_add(1);
        }
        if !add_path_entries.is_empty() {
            encode_rib_entries_profile(
                &mut buf,
                timestamp,
                seq_num,
                prefix,
                &add_path_entries,
                true,
            )?;
            seq_num = seq_num.wrapping_add(1);
        }
    }
    // 6. Encode EVPN routes as RIB_GENERIC records (RFC 6396 §4.3.5).
    // EVPN does not use Add-Path in this codebase, and EVPN keys are
    // already per-route (RD + ESI + ETag + MAC + IP), so each route maps
    // to a single-entry RIB_GENERIC record. Sort for deterministic output
    // by (peer_index, route).
    // Sort by (peer_index, encoded EVPN NLRI bytes). EvpnRouteKey doesn't
    // derive Ord, but the encoded NLRI is a canonical byte representation
    // and gives a deterministic ordering.
    let mut sorted_evpn: Vec<(&EvpnRibRoute, Vec<u8>)> = evpn_routes
        .iter()
        .map(|route| {
            let mut nlri_bytes = Vec::new();
            encode_evpn_nlri(std::slice::from_ref(&route.route), &mut nlri_bytes);
            (route, nlri_bytes)
        })
        .collect();
    sorted_evpn.sort_by(|(a, a_bytes), (b, b_bytes)| {
        let a_idx = peer_index.get(&a.peer).copied().unwrap_or(u16::MAX);
        let b_idx = peer_index.get(&b.peer).copied().unwrap_or(u16::MAX);
        a_idx.cmp(&b_idx).then_with(|| a_bytes.cmp(b_bytes))
    });
    let sorted_evpn: Vec<&EvpnRibRoute> = sorted_evpn.into_iter().map(|(r, _)| r).collect();
    for route in sorted_evpn {
        let Some(&idx) = peer_index.get(&route.peer) else {
            continue;
        };
        let age = route.received_at.elapsed().as_secs();
        let originated_u64 = now_secs.saturating_sub(age);
        let originated = u32::try_from(originated_u64).unwrap_or(u32::MAX);
        encode_evpn_rib_generic(&mut buf, timestamp, seq_num, route, idx, originated)?;
        seq_num = seq_num.wrapping_add(1);
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
    use super::*;
    use rustbgpd_rib::route::{Route, RouteOrigin};
    use rustbgpd_wire::{
        AsPath, Ipv4Prefix, Ipv6Prefix, Origin, PathAttribute, Prefix, RpkiValidation,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::time::Instant;
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
            link_local_next_hop: None,
            next_hop_scope: None,
            peer,
            attributes: Arc::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![rustbgpd_wire::AsPathSegment::AsSequence(vec![65001])],
                }),
                PathAttribute::LocalPref(100),
            ]),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
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
    fn warm_snapshot_splits_mixed_profiles_and_preserves_zero_addpath_id() {
        let prefix = Prefix::V4(Ipv4Prefix {
            addr: Ipv4Addr::new(198, 51, 100, 0),
            len: 24,
        });
        let add_peer_addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let plain_peer_addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let peers = vec![
            make_peer(add_peer_addr, 64_501),
            make_peer(plain_peer_addr, 64_502),
        ];
        let routes = vec![
            make_route(prefix, add_peer_addr, add_peer_addr),
            make_route(prefix, plain_peer_addr, plain_peer_addr),
        ];
        let snapshot = encode_warm_snapshot(
            Ipv4Addr::new(10, 0, 0, 1),
            "generation-1",
            &peers,
            &routes,
            &[],
            1_700_000_000,
            &[MrtAddPathReceiveProfile {
                peer: add_peer_addr,
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            }],
        )
        .unwrap();
        let reader = crate::reader::SnapshotReader::new(&snapshot).unwrap();
        assert_eq!(reader.view_name(), "generation-1");
        let entries: Vec<_> = reader.map(Result::unwrap).collect();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|entry| {
            entry.peer.peer_addr == add_peer_addr && entry.add_path && entry.path_id == 0
        }));
        assert!(
            entries
                .iter()
                .any(|entry| entry.peer.peer_addr == plain_peer_addr && !entry.add_path)
        );
    }

    #[test]
    fn warm_snapshot_rejects_link_local_next_hop_before_encoding() {
        let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let prefix = Prefix::V6(Ipv6Prefix {
            addr: "2001:db8::".parse().unwrap(),
            len: 64,
        });
        let route = make_route(prefix, peer, "fe80::1".parse().unwrap());
        assert!(matches!(
            encode_warm_snapshot(
                Ipv4Addr::new(10, 0, 0, 1),
                "generation-1",
                &[make_peer(peer, 64_501)],
                &[route],
                &[],
                1_700_000_000,
                &[],
            ),
            Err(EncodeError::UnsupportedWarmRouteProfile { .. })
        ));
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
        let data = encode_snapshot(
            Ipv4Addr::new(1, 2, 3, 4),
            &[peer],
            &[route],
            &[],
            1_700_000_000,
        )
        .unwrap();
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
        let data =
            encode_snapshot(Ipv4Addr::new(1, 2, 3, 4), &[], &[], &[], 1_700_000_000).unwrap();
        // Should have exactly one MRT record (peer index table with 0 peers)
        assert!(data.len() > 12);
        assert_eq!(u16::from_be_bytes([data[6], data[7]]), 1);
    }
    fn make_evpn_macip(peer: IpAddr, next_hop: IpAddr) -> EvpnRibRoute {
        use rustbgpd_wire::{
            EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, EvpnRoute, MacAddress, MplsLabel,
            RouteDistinguisher,
        };
        let rd = RouteDistinguisher([0x00, 0x00, 0xFD, 0xE8, 0x00, 0x00, 0x00, 0x64]);
        let mac = MacAddress([0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01]);
        let ip = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
        let route = EvpnRoute::MacIp(EvpnMacIp {
            rd,
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(0),
            mac,
            ip,
            label1: MplsLabel::new(100),
            label2: None,
        });
        EvpnRibRoute {
            route,
            next_hop,
            link_local_next_hop: None,
            peer,
            attributes: Arc::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![rustbgpd_wire::AsPathSegment::AsSequence(vec![65001])],
                }),
                PathAttribute::LocalPref(100),
            ]),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            is_stale: false,
            is_llgr_stale: false,
        }
    }
    fn make_evpn_ipprefix(peer: IpAddr, next_hop: IpAddr) -> EvpnRibRoute {
        use rustbgpd_wire::{
            EthernetSegmentIdentifier, EthernetTagId, EvpnIpPrefixRoute, EvpnIpPrefixValue,
            EvpnRoute, MplsLabel, RouteDistinguisher,
        };
        let rd = RouteDistinguisher([0x00, 0x00, 0xFD, 0xE8, 0x00, 0x00, 0x00, 0x64]);
        let prefix = EvpnIpPrefixValue::V4(Ipv4Prefix {
            addr: Ipv4Addr::new(192, 0, 2, 0),
            len: 24,
        });
        let route = EvpnRoute::IpPrefix(EvpnIpPrefixRoute {
            rd,
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(0),
            prefix,
            gateway: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            label: MplsLabel::new(200),
        });
        EvpnRibRoute {
            route,
            next_hop,
            link_local_next_hop: None,
            peer,
            attributes: Arc::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![rustbgpd_wire::AsPathSegment::AsSequence(vec![65001])],
                }),
                PathAttribute::LocalPref(100),
            ]),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            is_stale: false,
            is_llgr_stale: false,
        }
    }
    /// Locate an `RIB_GENERIC` (subtype 6) record in `data` after the
    /// `PEER_INDEX_TABLE`. Returns the offset of its MRT header.
    fn find_rib_generic(data: &[u8]) -> Option<usize> {
        let mut offset = 0;
        while offset + 12 <= data.len() {
            let mrt_type = u16::from_be_bytes([data[offset + 4], data[offset + 5]]);
            let subtype = u16::from_be_bytes([data[offset + 6], data[offset + 7]]);
            let length = u32::from_be_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
            ]) as usize;
            if mrt_type == TABLE_DUMP_V2 && subtype == RIB_GENERIC {
                return Some(offset);
            }
            offset += 12 + length;
        }
        None
    }
    /// EVPN Type 2 (MAC/IP Advertisement) → MRT `RIB_GENERIC`. Asserts the
    /// record carries AFI 25 / SAFI 70 and the encoded EVPN NLRI bytes
    /// match `encode_evpn_nlri` for the same route.
    #[test]
    fn evpn_type2_rib_generic_encoding() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let peer = make_peer(peer_addr, 65002);
        let route = make_evpn_macip(peer_addr, peer_addr);
        let data = encode_snapshot(
            Ipv4Addr::new(1, 2, 3, 4),
            &[peer],
            &[],
            std::slice::from_ref(&route),
            1_700_000_000,
        )
        .unwrap();
        let rib_offset =
            find_rib_generic(&data).expect("RIB_GENERIC record must be present for EVPN route");
        // Payload starts after 12-byte MRT header.
        let payload = &data[rib_offset + 12..];
        // Sequence Number (4 bytes), then AFI (2), SAFI (1).
        let afi = u16::from_be_bytes([payload[4], payload[5]]);
        let safi = payload[6];
        assert_eq!(afi, 25, "RIB_GENERIC AFI must be 25 (L2VPN) for EVPN");
        assert_eq!(safi, 70, "RIB_GENERIC SAFI must be 70 (EVPN)");
        // NLRI bytes follow. Compare against an independent encode of the
        // same EvpnRoute — proves the record header carries the canonical
        // EVPN NLRI TLV (route_type + length + body).
        let mut expected_nlri = Vec::new();
        encode_evpn_nlri(std::slice::from_ref(&route.route), &mut expected_nlri);
        let nlri_start = 7; // after seq(4) + afi(2) + safi(1)
        let nlri_end = nlri_start + expected_nlri.len();
        assert_eq!(
            &payload[nlri_start..nlri_end],
            expected_nlri.as_slice(),
            "encoded NLRI bytes must match encode_evpn_nlri output"
        );
        // Entry Count (2 bytes) immediately after NLRI = 1.
        let entry_count = u16::from_be_bytes([payload[nlri_end], payload[nlri_end + 1]]);
        assert_eq!(
            entry_count, 1,
            "EVPN does not use Add-Path; entry count must be 1"
        );
    }
    /// EVPN Type 5 (IP Prefix) → MRT `RIB_GENERIC`. Same shape as the Type 2
    /// test but exercises the longer IP-Prefix NLRI encoding.
    #[test]
    fn evpn_type5_rib_generic_encoding() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let peer = make_peer(peer_addr, 65002);
        let route = make_evpn_ipprefix(peer_addr, peer_addr);
        let data = encode_snapshot(
            Ipv4Addr::new(1, 2, 3, 4),
            &[peer],
            &[],
            std::slice::from_ref(&route),
            1_700_000_000,
        )
        .unwrap();
        let rib_offset =
            find_rib_generic(&data).expect("RIB_GENERIC record must be present for EVPN Type 5");
        let payload = &data[rib_offset + 12..];
        assert_eq!(u16::from_be_bytes([payload[4], payload[5]]), 25);
        assert_eq!(payload[6], 70);
        let mut expected_nlri = Vec::new();
        encode_evpn_nlri(std::slice::from_ref(&route.route), &mut expected_nlri);
        assert_eq!(
            &payload[7..7 + expected_nlri.len()],
            expected_nlri.as_slice()
        );
    }
    /// Walk a serialized BGP attribute block and return the value bytes
    /// of the first attribute matching `type_code`. Used by the
    /// MRT-reduced-form regression tests below.
    fn find_attribute_value(attrs: &[u8], type_code: u8) -> Option<&[u8]> {
        let mut offset = 0;
        while offset + 2 <= attrs.len() {
            let flags = attrs[offset];
            let tc = attrs[offset + 1];
            let extended = (flags & 0x10) != 0;
            let (len, header_len) = if extended {
                if offset + 4 > attrs.len() {
                    return None;
                }
                (
                    u16::from_be_bytes([attrs[offset + 2], attrs[offset + 3]]) as usize,
                    4,
                )
            } else {
                if offset + 3 > attrs.len() {
                    return None;
                }
                (attrs[offset + 2] as usize, 3)
            };
            let value_start = offset + header_len;
            let value_end = value_start + len;
            if value_end > attrs.len() {
                return None;
            }
            if tc == type_code {
                return Some(&attrs[value_start..value_end]);
            }
            offset = value_end;
        }
        None
    }
    /// Locate the encoded `MP_REACH_NLRI` (type 14) value bytes inside
    /// the single RIB entry of an EVPN `RIB_GENERIC` record.
    fn evpn_rib_generic_mp_reach_value(data: &[u8]) -> Vec<u8> {
        let rib_offset = find_rib_generic(data).expect("RIB_GENERIC must be present");
        let payload = &data[rib_offset + 12..];
        // Walk: seq(4) + afi(2) + safi(1) + nlri(var) + entry_count(2) + entry.
        let nlri_start = 7;
        // EVPN NLRI = route_type(1) + length(1) + body(length) — peek the
        // length byte to skip past it without re-decoding the whole thing.
        let nlri_body_len = payload[nlri_start + 1] as usize;
        let nlri_end = nlri_start + 2 + nlri_body_len;
        let entry_start = nlri_end + 2; // skip entry_count
        // Entry header: peer_index(2) + originated_time(4) + attr_len(2).
        let attr_len_offset = entry_start + 6;
        let attr_len =
            u16::from_be_bytes([payload[attr_len_offset], payload[attr_len_offset + 1]]) as usize;
        let attrs_start = attr_len_offset + 2;
        let attrs = &payload[attrs_start..attrs_start + attr_len];
        find_attribute_value(attrs, 14)
            .expect("MP_REACH_NLRI must be present in EVPN RIB entry")
            .to_vec()
    }
    /// RFC 6396 §4.3.4: `MP_REACH_NLRI` inside an MRT RIB entry must
    /// carry only NH-Len + NH bytes. AFI/SAFI/Reserved/NLRI must be
    /// omitted because the RIB entry header already encodes them.
    /// Regression for the EVPN export path.
    #[test]
    fn evpn_rib_entry_mp_reach_is_mrt_reduced_form() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let next_hop = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99));
        let peer = make_peer(peer_addr, 65002);
        let route = make_evpn_macip(peer_addr, next_hop);
        let data = encode_snapshot(
            Ipv4Addr::new(1, 2, 3, 4),
            &[peer],
            &[],
            std::slice::from_ref(&route),
            1_700_000_000,
        )
        .unwrap();
        let mp_value = evpn_rib_generic_mp_reach_value(&data);
        // Reduced form: 1-byte NH-Len + NH octets, nothing else.
        assert_eq!(
            mp_value.len(),
            5,
            "EVPN MP_REACH must be 5 bytes (NH-Len=4 + 4-byte IPv4 NH); got {} bytes",
            mp_value.len()
        );
        assert_eq!(mp_value[0], 4, "NH-Len byte must equal 4 for IPv4 NH");
        assert_eq!(
            &mp_value[1..5],
            &[10, 0, 0, 99],
            "NH bytes must equal the route's next-hop"
        );
    }
    /// Same regression for IPv6 unicast — `MP_REACH` in MRT RIB entries
    /// must be reduced form, not the BGP UPDATE form. Pre-existing
    /// codepath but never byte-level asserted before.
    #[test]
    fn ipv6_unicast_rib_entry_mp_reach_is_mrt_reduced_form() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer = make_peer(peer_addr, 65001);
        let nh = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let route = make_route(
            Prefix::V6(Ipv6Prefix {
                addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                len: 32,
            }),
            peer_addr,
            IpAddr::V6(nh),
        );
        let data = encode_snapshot(
            Ipv4Addr::new(1, 2, 3, 4),
            &[peer],
            &[route],
            &[],
            1_700_000_000,
        )
        .unwrap();
        // Walk past PEER_INDEX_TABLE to the RIB_IPV6_UNICAST record.
        let first_len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let rib_offset = 12 + first_len;
        let payload = &data[rib_offset + 12..];
        // Payload: seq(4) + prefix_len(1) + prefix_bytes(ceil(32/8)=4) +
        // entry_count(2) + entry.
        let entry_start = 4 + 1 + 4 + 2;
        let attr_len_offset = entry_start + 6;
        let attr_len =
            u16::from_be_bytes([payload[attr_len_offset], payload[attr_len_offset + 1]]) as usize;
        let attrs = &payload[attr_len_offset + 2..attr_len_offset + 2 + attr_len];
        let mp_value = find_attribute_value(attrs, 14).expect("MP_REACH must be present");
        assert_eq!(
            mp_value.len(),
            17,
            "IPv6 MP_REACH must be 17 bytes (NH-Len=16 + 16-byte IPv6 NH); got {}",
            mp_value.len()
        );
        assert_eq!(mp_value[0], 16, "NH-Len must equal 16 for IPv6 NH");
        assert_eq!(
            &mp_value[1..17],
            &nh.octets(),
            "NH bytes must equal the route's IPv6 next-hop"
        );
    }
    /// RFC 4760 §3 / RFC 2545: IPv6 next-hop can carry global +
    /// link-local (32 bytes total). When `Route.link_local_next_hop`
    /// is `Some`, the MRT-reduced `MP_REACH_NLRI` value must be 33
    /// bytes — NH-Len=32, then the 16-byte global, then the 16-byte
    /// link-local. Regression for the pre-existing gap where this
    /// data was discarded.
    #[test]
    fn ipv6_unicast_32byte_next_hop_emits_33_byte_attribute_value() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer = make_peer(peer_addr, 65001);
        let global = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let mut route = make_route(
            Prefix::V6(Ipv6Prefix {
                addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                len: 32,
            }),
            peer_addr,
            IpAddr::V6(global),
        );
        route.link_local_next_hop = Some(link_local);
        let data = encode_snapshot(
            Ipv4Addr::new(1, 2, 3, 4),
            &[peer],
            &[route],
            &[],
            1_700_000_000,
        )
        .unwrap();
        let first_len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let rib_offset = 12 + first_len;
        let payload = &data[rib_offset + 12..];
        let entry_start = 4 + 1 + 4 + 2;
        let attr_len_offset = entry_start + 6;
        let attr_len =
            u16::from_be_bytes([payload[attr_len_offset], payload[attr_len_offset + 1]]) as usize;
        let attrs = &payload[attr_len_offset + 2..attr_len_offset + 2 + attr_len];
        let mp_value = find_attribute_value(attrs, 14).expect("MP_REACH must be present");
        assert_eq!(
            mp_value.len(),
            33,
            "32-byte NH must produce a 33-byte MP_REACH value (NH-Len=32 + 16 + 16); got {}",
            mp_value.len()
        );
        assert_eq!(mp_value[0], 32, "NH-Len must equal 32 for global+LL form");
        assert_eq!(
            &mp_value[1..17],
            &global.octets(),
            "global NH bytes mismatch"
        );
        assert_eq!(
            &mp_value[17..33],
            &link_local.octets(),
            "link-local NH bytes mismatch"
        );
    }
    /// RFC 8950: IPv4 NLRI carried in an `MP_REACH_NLRI` with an IPv6
    /// next-hop. The MRT encoding still uses the reduced form — the
    /// `RIB_IPV4_UNICAST` record header carries the prefix, the
    /// attribute carries only NH-Len + NH.
    #[test]
    fn rfc8950_ipv4_with_ipv6_nh_mp_reach_is_mrt_reduced_form() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer = make_peer(peer_addr, 65001);
        let nh = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 99);
        let route = make_route(
            Prefix::V4(Ipv4Prefix {
                addr: Ipv4Addr::new(203, 0, 113, 0),
                len: 24,
            }),
            peer_addr,
            IpAddr::V6(nh),
        );
        let data = encode_snapshot(
            Ipv4Addr::new(1, 2, 3, 4),
            &[peer],
            &[route],
            &[],
            1_700_000_000,
        )
        .unwrap();
        let first_len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let rib_offset = 12 + first_len;
        let payload = &data[rib_offset + 12..];
        // RIB_IPV4_UNICAST payload: seq(4) + prefix_len(1) +
        // prefix_bytes(ceil(24/8)=3) + entry_count(2) + entry.
        let entry_start = 4 + 1 + 3 + 2;
        let attr_len_offset = entry_start + 6;
        let attr_len =
            u16::from_be_bytes([payload[attr_len_offset], payload[attr_len_offset + 1]]) as usize;
        let attrs = &payload[attr_len_offset + 2..attr_len_offset + 2 + attr_len];
        let mp_value = find_attribute_value(attrs, 14).expect("MP_REACH must be present");
        assert_eq!(
            mp_value.len(),
            17,
            "RFC 8950 MP_REACH must be 17 bytes (NH-Len=16 + 16-byte IPv6 NH); got {}",
            mp_value.len()
        );
        assert_eq!(mp_value[0], 16);
        assert_eq!(&mp_value[1..17], &nh.octets());
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
            encode_snapshot(Ipv4Addr::new(1, 2, 3, 4), &[], &[route], &[], 1_700_000_000).unwrap();
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
