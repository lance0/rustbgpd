//! RFC 7432 EVPN NLRI codec and types.
//!
//! EVPN NLRI is a typed TLV format carried under AFI=25 / SAFI=70. Each NLRI
//! entry has a 1-byte route type, 1-byte length, and a type-specific payload.
//! Five route types are defined:
//!
//! - Type 1: Ethernet Auto-Discovery (EAD) — per-ES (ethernet_tag=MAX_ET) or per-EVI
//! - Type 2: MAC/IP Advertisement
//! - Type 3: Inclusive Multicast Ethernet Tag (IMET)
//! - Type 4: Ethernet Segment (ES)
//! - Type 5: IP Prefix Route (RFC 9136)
//!
//! This module is the structural codec — no semantic interpretation of RDs,
//! ESIs, MACs, or labels. Upstream layers (RIB, best-path) apply meaning.
//!
//! The module intentionally splits route payload from route identity:
//! [`EvpnRoute`] carries the full wire payload (needed for encoding and
//! reflection), while [`EvpnRouteKey`] carries only the RFC 7432 identifying
//! fields per route type (used as a HashMap key in the RIB).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::DecodeError;
use crate::nlri::{Ipv4Prefix, Ipv6Prefix};

// ---------------------------------------------------------------------------
// Core primitive types
// ---------------------------------------------------------------------------

/// Ethernet Tag ID — 32-bit namespace identifier within an EVI (RFC 7432 §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EthernetTagId(pub u32);

impl EthernetTagId {
    /// `MAX_ET` (RFC 7432 §7.1) — Ethernet Tag 0xFFFFFFFF marks EAD-per-ES routes.
    pub const MAX_ET: Self = Self(0xFFFF_FFFF);

    /// Returns `true` if this tag equals `MAX_ET` (EAD per-ES discriminator).
    #[must_use]
    pub fn is_max_et(&self) -> bool {
        self.0 == Self::MAX_ET.0
    }
}

impl fmt::Display for EthernetTagId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_max_et() {
            write!(f, "MAX_ET")
        } else {
            write!(f, "{}", self.0)
        }
    }
}

/// 48-bit Ethernet MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// Construct from a raw 6-byte array.
    #[must_use]
    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// The underlying 6 bytes.
    #[must_use]
    pub const fn octets(&self) -> [u8; 6] {
        self.0
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let o = &self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            o[0], o[1], o[2], o[3], o[4], o[5]
        )
    }
}

/// 10-byte Ethernet Segment Identifier (RFC 7432 §5).
///
/// ESI type is encoded in the first byte; the remaining 9 bytes carry the
/// type-specific value. The codec stores ESIs opaquely — consumers that
/// need to interpret the ESI type (single-active, LACP-derived, etc.) must
/// do so on the raw bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EthernetSegmentIdentifier(pub [u8; 10]);

impl EthernetSegmentIdentifier {
    /// ESI Type 0 (all zero) — used when a CE is single-homed.
    pub const ZERO: Self = Self([0u8; 10]);

    /// Construct from a raw 10-byte array.
    #[must_use]
    pub const fn new(bytes: [u8; 10]) -> Self {
        Self(bytes)
    }

    /// The underlying 10 bytes.
    #[must_use]
    pub const fn octets(&self) -> [u8; 10] {
        self.0
    }

    /// ESI Type (first byte per RFC 7432 §5).
    #[must_use]
    pub const fn esi_type(&self) -> u8 {
        self.0[0]
    }

    /// Returns `true` if all 10 bytes are zero (ESI Type 0, single-homed).
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl fmt::Display for EthernetSegmentIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, byte) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, ":")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Route Distinguisher (RFC 4364 §4.2) — 8-byte administratively-assigned
/// identifier that makes VPN routes unique across EVIs.
///
/// RFC 4364 defines three encodings, distinguished by the first 2 bytes
/// (Type field). The codec preserves the raw 8 bytes and exposes typed
/// decode helpers; it never rejects unknown RD types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RouteDistinguisher(pub [u8; 8]);

impl RouteDistinguisher {
    /// All-zero RD, used where a valid RD is required but none is meaningful.
    pub const ZERO: Self = Self([0u8; 8]);

    /// Construct from a raw 8-byte array.
    #[must_use]
    pub const fn new(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    /// The underlying 8 bytes.
    #[must_use]
    pub const fn octets(&self) -> [u8; 8] {
        self.0
    }

    /// RD type (first 2 bytes, big-endian).
    #[must_use]
    pub fn rd_type(&self) -> u16 {
        u16::from_be_bytes([self.0[0], self.0[1]])
    }
}

impl fmt::Display for RouteDistinguisher {
    /// Format per RFC 4364 §4.2:
    /// - Type 0: `<admin-asn-16>:<assigned-32>`
    /// - Type 1: `<admin-ipv4>:<assigned-16>`
    /// - Type 2: `<admin-asn-32>:<assigned-16>`
    /// - Other: hex-encoded fallback.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        match self.rd_type() {
            0 => {
                let asn = u16::from_be_bytes([b[2], b[3]]);
                let assigned = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
                write!(f, "{asn}:{assigned}")
            }
            1 => {
                let ip = Ipv4Addr::new(b[2], b[3], b[4], b[5]);
                let assigned = u16::from_be_bytes([b[6], b[7]]);
                write!(f, "{ip}:{assigned}")
            }
            2 => {
                let asn = u32::from_be_bytes([b[2], b[3], b[4], b[5]]);
                let assigned = u16::from_be_bytes([b[6], b[7]]);
                write!(f, "{asn}:{assigned}")
            }
            _ => {
                write!(f, "0x")?;
                for byte in b {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    }
}

/// A 3-byte MPLS label field (RFC 3032) as carried in EVPN NLRI.
///
/// For VXLAN-encapsulated EVPN (RFC 8365), the 24-bit label field carries
/// a 24-bit VNI. The codec does not distinguish — consumers interpret the
/// value based on the Encapsulation extended community.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MplsLabel(pub u32);

impl MplsLabel {
    /// Construct from a raw 24-bit value (upper 8 bits ignored).
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value & 0x00FF_FFFF)
    }

    /// Raw 24-bit value.
    #[must_use]
    pub const fn value(&self) -> u32 {
        self.0
    }

    /// Interpret this field as a VXLAN VNI (RFC 8365 §5).
    ///
    /// The label field on the wire is `(label << 4) | (TC << 1) | S` when
    /// used for MPLS, but for VXLAN the full 24 bits are the VNI. Both
    /// uses call this accessor; it's up to the caller to know the encap.
    #[must_use]
    pub const fn as_vni(&self) -> u32 {
        self.0
    }

    /// Extract the 20-bit MPLS label field (upper 20 bits of the 24-bit word).
    #[must_use]
    pub const fn as_mpls_label(&self) -> u32 {
        self.0 >> 4
    }
}

/// An IP prefix encoded inside an EVPN Type 5 NLRI — IPv4 or IPv6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EvpnIpPrefixValue {
    /// IPv4 prefix.
    V4(Ipv4Prefix),
    /// IPv6 prefix.
    V6(Ipv6Prefix),
}

impl fmt::Display for EvpnIpPrefixValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(p) => write!(f, "{}/{}", p.addr, p.len),
            Self::V6(p) => write!(f, "{}/{}", p.addr, p.len),
        }
    }
}

// ---------------------------------------------------------------------------
// Per-route-type payload structs
// ---------------------------------------------------------------------------

/// Type 1: Ethernet Auto-Discovery per-ES route (RFC 7432 §7.1).
///
/// Ethernet Tag field MUST be `MAX_ET`; discriminated from per-EVI by value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EvpnEadPerEs {
    /// Route Distinguisher.
    pub rd: RouteDistinguisher,
    /// Ethernet Segment Identifier (must be non-zero).
    pub esi: EthernetSegmentIdentifier,
    /// Ethernet Tag (must be `MAX_ET` for per-ES).
    pub ethernet_tag: EthernetTagId,
    /// MPLS label — typically the ESI label for per-ES.
    pub label: MplsLabel,
}

/// Type 1: Ethernet Auto-Discovery per-EVI route (RFC 7432 §7.1).
///
/// Same wire shape as per-ES but Ethernet Tag is a real EVI/bridge-domain
/// identifier rather than `MAX_ET`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EvpnEadPerEvi {
    /// Route Distinguisher.
    pub rd: RouteDistinguisher,
    /// Ethernet Segment Identifier (must be non-zero).
    pub esi: EthernetSegmentIdentifier,
    /// Ethernet Tag identifying the EVI / bridge domain.
    pub ethernet_tag: EthernetTagId,
    /// MPLS label / VNI for this EVI on this ES.
    pub label: MplsLabel,
}

/// Type 2: MAC/IP Advertisement route (RFC 7432 §7.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EvpnMacIp {
    /// Route Distinguisher.
    pub rd: RouteDistinguisher,
    /// Ethernet Segment Identifier (may be ZERO for single-homed CE).
    pub esi: EthernetSegmentIdentifier,
    /// Ethernet Tag identifying the EVI / bridge domain.
    pub ethernet_tag: EthernetTagId,
    /// MAC address being advertised.
    pub mac: MacAddress,
    /// Host IP address, if any. Wire length is 0, 4, or 16 bytes.
    pub ip: Option<IpAddr>,
    /// Primary MPLS label / VNI (present on all Type 2 routes).
    pub label1: MplsLabel,
    /// Secondary label for symmetric IRB (RFC 9135), if present.
    pub label2: Option<MplsLabel>,
}

/// Type 3: Inclusive Multicast Ethernet Tag route (RFC 7432 §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EvpnImet {
    /// Route Distinguisher.
    pub rd: RouteDistinguisher,
    /// Ethernet Tag identifying the EVI / bridge domain.
    pub ethernet_tag: EthernetTagId,
    /// Originator Router IP. Wire length is 4 or 16 bytes.
    pub originator_ip: IpAddr,
}

/// Type 4: Ethernet Segment route (RFC 7432 §7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EvpnEs {
    /// Route Distinguisher.
    pub rd: RouteDistinguisher,
    /// Ethernet Segment Identifier (must be non-zero).
    pub esi: EthernetSegmentIdentifier,
    /// Originator Router IP. Wire length is 4 or 16 bytes.
    pub originator_ip: IpAddr,
}

/// Type 5: IP Prefix route (RFC 9136).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EvpnIpPrefixRoute {
    /// Route Distinguisher.
    pub rd: RouteDistinguisher,
    /// Ethernet Segment Identifier (may be ZERO).
    pub esi: EthernetSegmentIdentifier,
    /// Ethernet Tag (often 0 for Type 5).
    pub ethernet_tag: EthernetTagId,
    /// IP prefix being advertised (IPv4 or IPv6).
    pub prefix: EvpnIpPrefixValue,
    /// Gateway IP address. Same family as `prefix`. May be 0.0.0.0 / ::.
    pub gateway: IpAddr,
    /// MPLS label / L3 VNI.
    pub label: MplsLabel,
}

// ---------------------------------------------------------------------------
// EvpnRoute + EvpnRouteKey top-level enums
// ---------------------------------------------------------------------------

/// A single EVPN NLRI entry (RFC 7432 §7), one of five route types.
///
/// This carries the full wire payload — needed for round-trip encoding and
/// for reflection through a route reflector. For a minimal hashable
/// identifier suitable as a RIB key, see [`EvpnRouteKey`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EvpnRoute {
    /// Type 1 — EAD per-ES.
    EadPerEs(EvpnEadPerEs),
    /// Type 1 — EAD per-EVI.
    EadPerEvi(EvpnEadPerEvi),
    /// Type 2 — MAC/IP Advertisement.
    MacIp(EvpnMacIp),
    /// Type 3 — Inclusive Multicast Ethernet Tag.
    Imet(EvpnImet),
    /// Type 4 — Ethernet Segment.
    Es(EvpnEs),
    /// Type 5 — IP Prefix (RFC 9136).
    IpPrefix(EvpnIpPrefixRoute),
}

impl EvpnRoute {
    /// Wire route-type byte (1..=5).
    #[must_use]
    pub const fn route_type(&self) -> u8 {
        match self {
            Self::EadPerEs(_) | Self::EadPerEvi(_) => 1,
            Self::MacIp(_) => 2,
            Self::Imet(_) => 3,
            Self::Es(_) => 4,
            Self::IpPrefix(_) => 5,
        }
    }

    /// Identifying subset of the route, suitable as a RIB key.
    #[must_use]
    pub fn key(&self) -> EvpnRouteKey {
        match self {
            Self::EadPerEs(r) => EvpnRouteKey::EadPerEs {
                rd: r.rd,
                esi: r.esi,
                ethernet_tag: r.ethernet_tag,
            },
            Self::EadPerEvi(r) => EvpnRouteKey::EadPerEvi {
                rd: r.rd,
                esi: r.esi,
                ethernet_tag: r.ethernet_tag,
            },
            Self::MacIp(r) => EvpnRouteKey::MacIp {
                rd: r.rd,
                ethernet_tag: r.ethernet_tag,
                mac: r.mac,
                ip: r.ip,
            },
            Self::Imet(r) => EvpnRouteKey::Imet {
                rd: r.rd,
                ethernet_tag: r.ethernet_tag,
                originator_ip: r.originator_ip,
            },
            Self::Es(r) => EvpnRouteKey::Es {
                rd: r.rd,
                esi: r.esi,
                originator_ip: r.originator_ip,
            },
            Self::IpPrefix(r) => EvpnRouteKey::IpPrefix {
                rd: r.rd,
                ethernet_tag: r.ethernet_tag,
                prefix: r.prefix,
            },
        }
    }
}

/// Identifying subset of an EVPN route — the fields that make two routes
/// distinct per RFC 7432. Suitable as a `HashMap` key in the RIB.
///
/// EAD per-ES and EAD per-EVI share a wire format but get distinct variants
/// here so the RIB never accidentally collapses them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvpnRouteKey {
    /// Type 1 per-ES key.
    EadPerEs {
        /// Route Distinguisher.
        rd: RouteDistinguisher,
        /// Ethernet Segment Identifier.
        esi: EthernetSegmentIdentifier,
        /// Ethernet Tag (`MAX_ET` for per-ES).
        ethernet_tag: EthernetTagId,
    },
    /// Type 1 per-EVI key.
    EadPerEvi {
        /// Route Distinguisher.
        rd: RouteDistinguisher,
        /// Ethernet Segment Identifier.
        esi: EthernetSegmentIdentifier,
        /// Ethernet Tag identifying the EVI.
        ethernet_tag: EthernetTagId,
    },
    /// Type 2 key — RD, tag, MAC, optional IP.
    MacIp {
        /// Route Distinguisher.
        rd: RouteDistinguisher,
        /// Ethernet Tag identifying the EVI.
        ethernet_tag: EthernetTagId,
        /// MAC address.
        mac: MacAddress,
        /// Optional host IP (0, 32, or 128 bits on the wire).
        ip: Option<IpAddr>,
    },
    /// Type 3 key.
    Imet {
        /// Route Distinguisher.
        rd: RouteDistinguisher,
        /// Ethernet Tag identifying the EVI.
        ethernet_tag: EthernetTagId,
        /// Originator Router IP.
        originator_ip: IpAddr,
    },
    /// Type 4 key.
    Es {
        /// Route Distinguisher.
        rd: RouteDistinguisher,
        /// Ethernet Segment Identifier.
        esi: EthernetSegmentIdentifier,
        /// Originator Router IP.
        originator_ip: IpAddr,
    },
    /// Type 5 key.
    IpPrefix {
        /// Route Distinguisher.
        rd: RouteDistinguisher,
        /// Ethernet Tag.
        ethernet_tag: EthernetTagId,
        /// IP prefix.
        prefix: EvpnIpPrefixValue,
    },
}

impl EvpnRouteKey {
    /// Wire route-type byte (1..=5).
    #[must_use]
    pub const fn route_type(&self) -> u8 {
        match self {
            Self::EadPerEs { .. } | Self::EadPerEvi { .. } => 1,
            Self::MacIp { .. } => 2,
            Self::Imet { .. } => 3,
            Self::Es { .. } => 4,
            Self::IpPrefix { .. } => 5,
        }
    }
}

// ---------------------------------------------------------------------------
// Decode helpers
// ---------------------------------------------------------------------------

fn decode_rd(buf: &[u8]) -> Result<RouteDistinguisher, DecodeError> {
    if buf.len() < 8 {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: "EVPN NLRI truncated: expected 8-byte Route Distinguisher".to_string(),
        });
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[..8]);
    Ok(RouteDistinguisher(bytes))
}

fn decode_esi(buf: &[u8]) -> Result<EthernetSegmentIdentifier, DecodeError> {
    if buf.len() < 10 {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: "EVPN NLRI truncated: expected 10-byte ESI".to_string(),
        });
    }
    let mut bytes = [0u8; 10];
    bytes.copy_from_slice(&buf[..10]);
    Ok(EthernetSegmentIdentifier(bytes))
}

fn decode_ethernet_tag(buf: &[u8]) -> Result<EthernetTagId, DecodeError> {
    if buf.len() < 4 {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: "EVPN NLRI truncated: expected 4-byte Ethernet Tag".to_string(),
        });
    }
    Ok(EthernetTagId(u32::from_be_bytes([
        buf[0], buf[1], buf[2], buf[3],
    ])))
}

fn decode_mpls_label(buf: &[u8]) -> Result<MplsLabel, DecodeError> {
    if buf.len() < 3 {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: "EVPN NLRI truncated: expected 3-byte MPLS label".to_string(),
        });
    }
    // 24-bit value stored in 3 bytes, big-endian.
    let value = (u32::from(buf[0]) << 16) | (u32::from(buf[1]) << 8) | u32::from(buf[2]);
    Ok(MplsLabel(value))
}

fn decode_ip_addr(buf: &[u8], len: usize, field: &str) -> Result<IpAddr, DecodeError> {
    match len {
        4 => {
            if buf.len() < 4 {
                return Err(DecodeError::MalformedField {
                    message_type: "UPDATE",
                    detail: format!("EVPN NLRI truncated: expected 4 bytes for {field}"),
                });
            }
            Ok(IpAddr::V4(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3])))
        }
        16 => {
            if buf.len() < 16 {
                return Err(DecodeError::MalformedField {
                    message_type: "UPDATE",
                    detail: format!("EVPN NLRI truncated: expected 16 bytes for {field}"),
                });
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[..16]);
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        other => Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: format!("EVPN NLRI {field} length {other} (expected 4 or 16)"),
        }),
    }
}

// ---------------------------------------------------------------------------
// Per-route-type decode
// ---------------------------------------------------------------------------

fn decode_type1(payload: &[u8]) -> Result<EvpnRoute, DecodeError> {
    // RD (8) | ESI (10) | Ethernet Tag (4) | MPLS Label (3) = 25 bytes
    if payload.len() != 25 {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: format!("EVPN Type 1 payload length {} (expected 25)", payload.len()),
        });
    }
    let rd = decode_rd(&payload[0..8])?;
    let esi = decode_esi(&payload[8..18])?;
    let ethernet_tag = decode_ethernet_tag(&payload[18..22])?;
    let label = decode_mpls_label(&payload[22..25])?;
    if ethernet_tag.is_max_et() {
        Ok(EvpnRoute::EadPerEs(EvpnEadPerEs {
            rd,
            esi,
            ethernet_tag,
            label,
        }))
    } else {
        Ok(EvpnRoute::EadPerEvi(EvpnEadPerEvi {
            rd,
            esi,
            ethernet_tag,
            label,
        }))
    }
}

fn decode_type2(payload: &[u8]) -> Result<EvpnRoute, DecodeError> {
    // RD (8) | ESI (10) | Ethernet Tag (4) | MAC Addr Len (1) | MAC (6) |
    //   IP Addr Len (1, bits) | IP (0/4/16) | Label1 (3) | [Label2 (3)]
    if payload.len() < 25 {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: format!(
                "EVPN Type 2 payload too short: {} bytes (need at least 25)",
                payload.len()
            ),
        });
    }
    let rd = decode_rd(&payload[0..8])?;
    let esi = decode_esi(&payload[8..18])?;
    let ethernet_tag = decode_ethernet_tag(&payload[18..22])?;
    let mac_addr_len = payload[22];
    if mac_addr_len != 48 {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: format!("EVPN Type 2 MAC Addr Length {mac_addr_len} (expected 48)"),
        });
    }
    if payload.len() < 23 + 6 + 1 {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: "EVPN Type 2 truncated before IP Addr Length byte".into(),
        });
    }
    let mac = MacAddress([
        payload[23],
        payload[24],
        payload[25],
        payload[26],
        payload[27],
        payload[28],
    ]);
    let ip_addr_len_bits = payload[29];
    let ip_bytes_expected = match ip_addr_len_bits {
        0 => 0,
        32 => 4,
        128 => 16,
        other => {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: format!("EVPN Type 2 IP Addr Length {other} bits (expected 0, 32, 128)"),
            });
        }
    };
    let ip_start = 30;
    if payload.len() < ip_start + ip_bytes_expected + 3 {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: format!(
                "EVPN Type 2 truncated: need {} bytes for IP + Label1, have {}",
                ip_bytes_expected + 3,
                payload.len() - ip_start
            ),
        });
    }
    let ip = if ip_bytes_expected == 0 {
        None
    } else {
        Some(decode_ip_addr(
            &payload[ip_start..ip_start + ip_bytes_expected],
            ip_bytes_expected,
            "Type 2 IP",
        )?)
    };
    let label1_start = ip_start + ip_bytes_expected;
    let label1 = decode_mpls_label(&payload[label1_start..label1_start + 3])?;
    let label2_start = label1_start + 3;
    let label2 = match payload.len() - label2_start {
        0 => None,
        3 => Some(decode_mpls_label(&payload[label2_start..label2_start + 3])?),
        other => {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: format!(
                    "EVPN Type 2 trailing bytes {other} (expected 0 or 3 for optional Label2)"
                ),
            });
        }
    };
    Ok(EvpnRoute::MacIp(EvpnMacIp {
        rd,
        esi,
        ethernet_tag,
        mac,
        ip,
        label1,
        label2,
    }))
}

fn decode_type3(payload: &[u8]) -> Result<EvpnRoute, DecodeError> {
    // RD (8) | Ethernet Tag (4) | IP Addr Len (1, bits) | Originator IP (variable)
    if payload.len() < 13 {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: format!(
                "EVPN Type 3 payload too short: {} bytes (need at least 13)",
                payload.len()
            ),
        });
    }
    let rd = decode_rd(&payload[0..8])?;
    let ethernet_tag = decode_ethernet_tag(&payload[8..12])?;
    let ip_len_bits = payload[12];
    let ip_bytes = match ip_len_bits {
        32 => 4,
        128 => 16,
        other => {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: format!("EVPN Type 3 IP Addr Length {other} bits (expected 32 or 128)"),
            });
        }
    };
    if payload.len() != 13 + ip_bytes {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: format!(
                "EVPN Type 3 payload length {} (expected {})",
                payload.len(),
                13 + ip_bytes
            ),
        });
    }
    let originator_ip = decode_ip_addr(&payload[13..], ip_bytes, "Type 3 originator IP")?;
    Ok(EvpnRoute::Imet(EvpnImet {
        rd,
        ethernet_tag,
        originator_ip,
    }))
}

fn decode_type4(payload: &[u8]) -> Result<EvpnRoute, DecodeError> {
    // RD (8) | ESI (10) | IP Addr Len (1, bits) | Originator IP (variable)
    if payload.len() < 19 {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: format!(
                "EVPN Type 4 payload too short: {} bytes (need at least 19)",
                payload.len()
            ),
        });
    }
    let rd = decode_rd(&payload[0..8])?;
    let esi = decode_esi(&payload[8..18])?;
    let ip_len_bits = payload[18];
    let ip_bytes = match ip_len_bits {
        32 => 4,
        128 => 16,
        other => {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: format!("EVPN Type 4 IP Addr Length {other} bits (expected 32 or 128)"),
            });
        }
    };
    if payload.len() != 19 + ip_bytes {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: format!(
                "EVPN Type 4 payload length {} (expected {})",
                payload.len(),
                19 + ip_bytes
            ),
        });
    }
    let originator_ip = decode_ip_addr(&payload[19..], ip_bytes, "Type 4 originator IP")?;
    Ok(EvpnRoute::Es(EvpnEs {
        rd,
        esi,
        originator_ip,
    }))
}

fn decode_type5(payload: &[u8]) -> Result<EvpnRoute, DecodeError> {
    // RFC 9136:
    //   RD (8) | ESI (10) | Ethernet Tag (4) | IP Prefix Length (1) |
    //   IP Prefix (4 or 16) | GW IP (4 or 16, same family) | MPLS Label (3)
    // IPv4 total = 8+10+4+1+4+4+3 = 34
    // IPv6 total = 8+10+4+1+16+16+3 = 58
    //
    // Family discrimination is by NLRI total length only — RFC 9136 does
    // not carry an explicit AFI inside the Type 5 body. Receivers must
    // therefore reject any other length as malformed. Non-canonical IP
    // prefix bytes (host bits set beyond `prefix_len`) are silently
    // canonicalized by `Ipv4Prefix::new` / `Ipv6Prefix::new`.
    let total = payload.len();
    if total != 34 && total != 58 {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: format!("EVPN Type 5 payload length {total} (expected 34 or 58)"),
        });
    }
    let rd = decode_rd(&payload[0..8])?;
    let esi = decode_esi(&payload[8..18])?;
    let ethernet_tag = decode_ethernet_tag(&payload[18..22])?;
    let prefix_len = payload[22];
    let is_v6 = total == 58;
    let prefix = if is_v6 {
        if prefix_len > 128 {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: format!("EVPN Type 5 IPv6 prefix length {prefix_len} > 128"),
            });
        }
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&payload[23..39]);
        EvpnIpPrefixValue::V6(Ipv6Prefix::new(Ipv6Addr::from(octets), prefix_len))
    } else {
        if prefix_len > 32 {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: format!("EVPN Type 5 IPv4 prefix length {prefix_len} > 32"),
            });
        }
        let addr = Ipv4Addr::new(payload[23], payload[24], payload[25], payload[26]);
        EvpnIpPrefixValue::V4(Ipv4Prefix::new(addr, prefix_len))
    };
    let (gateway, label_start) = if is_v6 {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&payload[39..55]);
        (IpAddr::V6(Ipv6Addr::from(octets)), 55)
    } else {
        (
            IpAddr::V4(Ipv4Addr::new(
                payload[27],
                payload[28],
                payload[29],
                payload[30],
            )),
            31,
        )
    };
    let label = decode_mpls_label(&payload[label_start..label_start + 3])?;
    Ok(EvpnRoute::IpPrefix(EvpnIpPrefixRoute {
        rd,
        esi,
        ethernet_tag,
        prefix,
        gateway,
        label,
    }))
}

// ---------------------------------------------------------------------------
// Public NLRI encode / decode
// ---------------------------------------------------------------------------

/// Decode one or more EVPN NLRI entries from a contiguous buffer.
///
/// Each entry is framed as `route_type (1) | length (1) | payload`.
///
/// Unknown route types (anything outside 1..=5) are skipped per
/// RFC 7432 §11.2 ("Receivers MUST ignore Route Types they do not
/// understand"), so a future EVPN extension does not tear down the
/// session. Truncation and per-type malformed payloads still error.
///
/// # Errors
///
/// Returns [`DecodeError`] if a length byte runs past the end of `buf`,
/// or a recognized route type's payload is malformed.
pub fn decode_evpn_nlri(mut buf: &[u8]) -> Result<Vec<EvpnRoute>, DecodeError> {
    let mut routes = Vec::new();
    while !buf.is_empty() {
        if buf.len() < 2 {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: "EVPN NLRI truncated: need route-type + length bytes".into(),
            });
        }
        let route_type = buf[0];
        let length = usize::from(buf[1]);
        if buf.len() < 2 + length {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: format!(
                    "EVPN NLRI truncated: route type {route_type} claims length {length}, \
                     but only {} bytes remain",
                    buf.len() - 2
                ),
            });
        }
        let payload = &buf[2..2 + length];
        match route_type {
            1 => routes.push(decode_type1(payload)?),
            2 => routes.push(decode_type2(payload)?),
            3 => routes.push(decode_type3(payload)?),
            4 => routes.push(decode_type4(payload)?),
            5 => routes.push(decode_type5(payload)?),
            // RFC 7432 §11.2: silently skip unknown types so the session
            // survives a peer advertising a future EVPN extension.
            _ => {}
        }
        buf = &buf[2 + length..];
    }
    Ok(routes)
}

// ---------------------------------------------------------------------------
// Per-route-type encode
// ---------------------------------------------------------------------------

fn encode_mpls_label(label: MplsLabel, out: &mut Vec<u8>) {
    let v = label.0 & 0x00FF_FFFF;
    #[expect(clippy::cast_possible_truncation)]
    {
        out.push((v >> 16) as u8);
        out.push((v >> 8) as u8);
        out.push(v as u8);
    }
}

fn encode_ip_addr(ip: IpAddr, out: &mut Vec<u8>) {
    match ip {
        IpAddr::V4(v4) => out.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => out.extend_from_slice(&v6.octets()),
    }
}

fn encode_type1_body(
    rd: RouteDistinguisher,
    esi: EthernetSegmentIdentifier,
    ethernet_tag: EthernetTagId,
    label: MplsLabel,
    out: &mut Vec<u8>,
) {
    out.extend_from_slice(&rd.0);
    out.extend_from_slice(&esi.0);
    out.extend_from_slice(&ethernet_tag.0.to_be_bytes());
    encode_mpls_label(label, out);
}

fn encode_type2_body(r: &EvpnMacIp, out: &mut Vec<u8>) {
    out.extend_from_slice(&r.rd.0);
    out.extend_from_slice(&r.esi.0);
    out.extend_from_slice(&r.ethernet_tag.0.to_be_bytes());
    out.push(48); // MAC Addr Length in bits
    out.extend_from_slice(&r.mac.0);
    match r.ip {
        None => out.push(0),
        Some(IpAddr::V4(v4)) => {
            out.push(32);
            out.extend_from_slice(&v4.octets());
        }
        Some(IpAddr::V6(v6)) => {
            out.push(128);
            out.extend_from_slice(&v6.octets());
        }
    }
    encode_mpls_label(r.label1, out);
    if let Some(label2) = r.label2 {
        encode_mpls_label(label2, out);
    }
}

fn encode_type3_body(r: &EvpnImet, out: &mut Vec<u8>) {
    out.extend_from_slice(&r.rd.0);
    out.extend_from_slice(&r.ethernet_tag.0.to_be_bytes());
    match r.originator_ip {
        IpAddr::V4(_) => out.push(32),
        IpAddr::V6(_) => out.push(128),
    }
    encode_ip_addr(r.originator_ip, out);
}

fn encode_type4_body(r: &EvpnEs, out: &mut Vec<u8>) {
    out.extend_from_slice(&r.rd.0);
    out.extend_from_slice(&r.esi.0);
    match r.originator_ip {
        IpAddr::V4(_) => out.push(32),
        IpAddr::V6(_) => out.push(128),
    }
    encode_ip_addr(r.originator_ip, out);
}

fn encode_type5_body(r: &EvpnIpPrefixRoute, out: &mut Vec<u8>) {
    // RFC 9136 §3 requires the GW IP to be the same family as the IP
    // prefix. A debug assertion catches programmer bugs immediately;
    // release builds fall back to UNSPECIFIED in the prefix family
    // rather than silently truncating/scrambling the wrong-family
    // address bytes.
    debug_assert!(
        matches!(
            (&r.prefix, &r.gateway),
            (EvpnIpPrefixValue::V4(_), IpAddr::V4(_)) | (EvpnIpPrefixValue::V6(_), IpAddr::V6(_))
        ),
        "EVPN Type 5: gateway family must match prefix family"
    );
    out.extend_from_slice(&r.rd.0);
    out.extend_from_slice(&r.esi.0);
    out.extend_from_slice(&r.ethernet_tag.0.to_be_bytes());
    match r.prefix {
        EvpnIpPrefixValue::V4(p) => {
            out.push(p.len);
            out.extend_from_slice(&p.addr.octets());
            if let IpAddr::V4(gw) = r.gateway {
                out.extend_from_slice(&gw.octets());
            } else {
                out.extend_from_slice(&Ipv4Addr::UNSPECIFIED.octets());
            }
        }
        EvpnIpPrefixValue::V6(p) => {
            out.push(p.len);
            out.extend_from_slice(&p.addr.octets());
            if let IpAddr::V6(gw) = r.gateway {
                out.extend_from_slice(&gw.octets());
            } else {
                out.extend_from_slice(&Ipv6Addr::UNSPECIFIED.octets());
            }
        }
    }
    encode_mpls_label(r.label, out);
}

/// Encode a list of EVPN NLRI entries to wire bytes.
pub fn encode_evpn_nlri(routes: &[EvpnRoute], buf: &mut Vec<u8>) {
    for route in routes {
        let route_type = route.route_type();
        let len_placeholder = buf.len();
        buf.push(route_type);
        buf.push(0); // length placeholder, backfilled below
        let body_start = buf.len();
        match route {
            EvpnRoute::EadPerEs(r) => {
                // RFC 7432 §7.1: EAD-per-ES carries MAX_ET in the Ethernet
                // Tag field; the decoder uses that to discriminate from
                // EAD-per-EVI. Force MAX_ET on the wire regardless of the
                // struct field so a buggy upstream cannot silently flip
                // the route's identity.
                debug_assert!(
                    r.ethernet_tag.is_max_et(),
                    "EVPN EAD-per-ES must carry MAX_ET ethernet tag"
                );
                encode_type1_body(r.rd, r.esi, EthernetTagId::MAX_ET, r.label, buf);
            }
            EvpnRoute::EadPerEvi(r) => {
                debug_assert!(
                    !r.ethernet_tag.is_max_et(),
                    "EVPN EAD-per-EVI must not carry MAX_ET ethernet tag"
                );
                encode_type1_body(r.rd, r.esi, r.ethernet_tag, r.label, buf);
            }
            EvpnRoute::MacIp(r) => encode_type2_body(r, buf),
            EvpnRoute::Imet(r) => encode_type3_body(r, buf),
            EvpnRoute::Es(r) => encode_type4_body(r, buf),
            EvpnRoute::IpPrefix(r) => encode_type5_body(r, buf),
        }
        let body_len = buf.len() - body_start;
        debug_assert!(
            u8::try_from(body_len).is_ok(),
            "EVPN NLRI body exceeds 255 bytes"
        );
        #[expect(clippy::cast_possible_truncation)]
        {
            buf[len_placeholder + 1] = body_len as u8;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_rd() -> RouteDistinguisher {
        // Type 0: 2-byte ASN 65000 + 4-byte assigned 100
        RouteDistinguisher([0x00, 0x00, 0xFD, 0xE8, 0x00, 0x00, 0x00, 0x64])
    }

    fn sample_esi() -> EthernetSegmentIdentifier {
        EthernetSegmentIdentifier([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A])
    }

    fn roundtrip(routes: &[EvpnRoute]) {
        let mut buf = Vec::new();
        encode_evpn_nlri(routes, &mut buf);
        let decoded = decode_evpn_nlri(&buf).expect("decode should succeed");
        assert_eq!(routes, decoded.as_slice(), "round-trip mismatch");
    }

    #[test]
    fn rd_display_type0() {
        assert_eq!(sample_rd().to_string(), "65000:100");
    }

    #[test]
    fn rd_display_type1() {
        let rd = RouteDistinguisher([0x00, 0x01, 10, 0, 0, 1, 0x00, 0x42]);
        assert_eq!(rd.to_string(), "10.0.0.1:66");
    }

    #[test]
    fn ethernet_tag_max_et() {
        assert!(EthernetTagId::MAX_ET.is_max_et());
        assert_eq!(EthernetTagId::MAX_ET.to_string(), "MAX_ET");
        assert!(!EthernetTagId(100).is_max_et());
    }

    #[test]
    fn mac_display() {
        let mac = MacAddress([0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc]);
        assert_eq!(mac.to_string(), "00:11:22:aa:bb:cc");
    }

    #[test]
    fn mpls_label_vxlan_vni() {
        let label = MplsLabel::new(10_000);
        assert_eq!(label.as_vni(), 10_000);
    }

    #[test]
    fn roundtrip_type1_per_es() {
        roundtrip(&[EvpnRoute::EadPerEs(EvpnEadPerEs {
            rd: sample_rd(),
            esi: sample_esi(),
            ethernet_tag: EthernetTagId::MAX_ET,
            label: MplsLabel::new(500),
        })]);
    }

    #[test]
    fn roundtrip_type1_per_evi() {
        roundtrip(&[EvpnRoute::EadPerEvi(EvpnEadPerEvi {
            rd: sample_rd(),
            esi: sample_esi(),
            ethernet_tag: EthernetTagId(200),
            label: MplsLabel::new(10_001),
        })]);
    }

    #[test]
    fn roundtrip_type2_mac_only() {
        roundtrip(&[EvpnRoute::MacIp(EvpnMacIp {
            rd: sample_rd(),
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(100),
            mac: MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            ip: None,
            label1: MplsLabel::new(10_000),
            label2: None,
        })]);
    }

    #[test]
    fn roundtrip_type2_mac_ipv4_two_labels() {
        roundtrip(&[EvpnRoute::MacIp(EvpnMacIp {
            rd: sample_rd(),
            esi: sample_esi(),
            ethernet_tag: EthernetTagId(100),
            mac: MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            ip: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            label1: MplsLabel::new(10_000),
            label2: Some(MplsLabel::new(20_000)),
        })]);
    }

    #[test]
    fn roundtrip_type2_mac_ipv6() {
        roundtrip(&[EvpnRoute::MacIp(EvpnMacIp {
            rd: sample_rd(),
            esi: sample_esi(),
            ethernet_tag: EthernetTagId(100),
            mac: MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            ip: Some(IpAddr::V6("2001:db8::10".parse().unwrap())),
            label1: MplsLabel::new(10_000),
            label2: None,
        })]);
    }

    #[test]
    fn roundtrip_type3_ipv4() {
        roundtrip(&[EvpnRoute::Imet(EvpnImet {
            rd: sample_rd(),
            ethernet_tag: EthernetTagId(100),
            originator_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        })]);
    }

    #[test]
    fn roundtrip_type3_ipv6() {
        roundtrip(&[EvpnRoute::Imet(EvpnImet {
            rd: sample_rd(),
            ethernet_tag: EthernetTagId(100),
            originator_ip: IpAddr::V6("2001:db8::1".parse().unwrap()),
        })]);
    }

    #[test]
    fn roundtrip_type4_ipv4() {
        roundtrip(&[EvpnRoute::Es(EvpnEs {
            rd: sample_rd(),
            esi: sample_esi(),
            originator_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        })]);
    }

    #[test]
    fn roundtrip_type5_ipv4() {
        roundtrip(&[EvpnRoute::IpPrefix(EvpnIpPrefixRoute {
            rd: sample_rd(),
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(0),
            prefix: EvpnIpPrefixValue::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 100, 0, 0), 24)),
            gateway: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            label: MplsLabel::new(20_001),
        })]);
    }

    #[test]
    fn roundtrip_type5_ipv6() {
        roundtrip(&[EvpnRoute::IpPrefix(EvpnIpPrefixRoute {
            rd: sample_rd(),
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(0),
            prefix: EvpnIpPrefixValue::V6(Ipv6Prefix::new("2001:db8:100::".parse().unwrap(), 48)),
            gateway: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            label: MplsLabel::new(20_001),
        })]);
    }

    #[test]
    fn roundtrip_all_types_one_nlri() {
        roundtrip(&[
            EvpnRoute::EadPerEs(EvpnEadPerEs {
                rd: sample_rd(),
                esi: sample_esi(),
                ethernet_tag: EthernetTagId::MAX_ET,
                label: MplsLabel::new(500),
            }),
            EvpnRoute::Imet(EvpnImet {
                rd: sample_rd(),
                ethernet_tag: EthernetTagId(100),
                originator_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            }),
            EvpnRoute::MacIp(EvpnMacIp {
                rd: sample_rd(),
                esi: EthernetSegmentIdentifier::ZERO,
                ethernet_tag: EthernetTagId(100),
                mac: MacAddress([0xaa; 6]),
                ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
                label1: MplsLabel::new(10_000),
                label2: None,
            }),
            EvpnRoute::Es(EvpnEs {
                rd: sample_rd(),
                esi: sample_esi(),
                originator_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            }),
            EvpnRoute::IpPrefix(EvpnIpPrefixRoute {
                rd: sample_rd(),
                esi: EthernetSegmentIdentifier::ZERO,
                ethernet_tag: EthernetTagId(0),
                prefix: EvpnIpPrefixValue::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 168, 0, 0), 24)),
                gateway: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                label: MplsLabel::new(20_001),
            }),
        ]);
    }

    #[test]
    fn decode_truncated_nlri_fails() {
        // Route type 2 with declared length 25 but only 20 bytes
        let bytes = [
            2u8, 25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(decode_evpn_nlri(&bytes).is_err());
    }

    /// RFC 7432 §11.2: receivers MUST silently ignore unknown route
    /// types so a session survives a peer advertising a future EVPN
    /// extension. The decoder skips the unknown TLV and continues
    /// parsing — known route types after the unknown one still decode.
    #[test]
    fn decode_skips_unknown_route_type() {
        // Build: known Type 3 IMET | unknown Type 99 (length 4) | another known Type 3.
        let imet = EvpnRoute::Imet(EvpnImet {
            rd: sample_rd(),
            ethernet_tag: EthernetTagId(100),
            originator_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        });
        let imet2 = EvpnRoute::Imet(EvpnImet {
            rd: sample_rd(),
            ethernet_tag: EthernetTagId(200),
            originator_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        });
        let mut buf = Vec::new();
        encode_evpn_nlri(std::slice::from_ref(&imet), &mut buf);
        // Append an unknown route type (99) with a 4-byte payload.
        buf.extend_from_slice(&[99u8, 4, 0xAA, 0xBB, 0xCC, 0xDD]);
        encode_evpn_nlri(std::slice::from_ref(&imet2), &mut buf);

        let decoded = decode_evpn_nlri(&buf).unwrap();
        assert_eq!(decoded.len(), 2, "unknown type should be skipped");
        assert!(matches!(decoded[0], EvpnRoute::Imet(_)));
        assert!(matches!(decoded[1], EvpnRoute::Imet(_)));
    }

    /// Truncation still fails — the length byte must point inside the buffer.
    #[test]
    fn decode_unknown_route_type_truncated_still_fails() {
        // Type 99 claims length 10 but only 2 bytes follow.
        let bytes = [99u8, 10, 0, 0];
        assert!(decode_evpn_nlri(&bytes).is_err());
    }

    #[test]
    fn empty_buffer_decodes_to_empty() {
        assert_eq!(decode_evpn_nlri(&[]).unwrap(), Vec::<EvpnRoute>::new());
    }

    #[test]
    fn route_key_discriminates_ead_per_es_vs_per_evi() {
        let per_es = EvpnRoute::EadPerEs(EvpnEadPerEs {
            rd: sample_rd(),
            esi: sample_esi(),
            ethernet_tag: EthernetTagId::MAX_ET,
            label: MplsLabel::new(500),
        });
        let per_evi = EvpnRoute::EadPerEvi(EvpnEadPerEvi {
            rd: sample_rd(),
            esi: sample_esi(),
            ethernet_tag: EthernetTagId(200),
            label: MplsLabel::new(500),
        });
        assert_ne!(per_es.key(), per_evi.key());
    }

    /// Regression: an EAD-per-ES route round-trips encode → decode back
    /// to `EadPerEs`, never silently becoming `EadPerEvi`. The encoder
    /// pins the ethernet tag to `MAX_ET` (the per-ES discriminator
    /// per RFC 7432 §7.1) regardless of what the struct field holds.
    #[test]
    fn ead_per_es_encode_round_trips_to_per_es() {
        let r = EvpnRoute::EadPerEs(EvpnEadPerEs {
            rd: sample_rd(),
            esi: sample_esi(),
            ethernet_tag: EthernetTagId::MAX_ET,
            label: MplsLabel::new(7),
        });
        let mut buf = Vec::new();
        encode_evpn_nlri(std::slice::from_ref(&r), &mut buf);
        let decoded = decode_evpn_nlri(&buf).unwrap();
        assert_eq!(decoded.len(), 1);
        assert!(matches!(decoded[0], EvpnRoute::EadPerEs(_)));
    }

    /// Regression: gateway-family mismatch on Type 5 trips the
    /// `debug_assert!` so encoder bugs surface in tests/CI rather than
    /// silently corrupting the wire payload. Cargo runs unit tests with
    /// debug assertions on, so this test is `#[should_panic]`.
    #[test]
    #[should_panic(expected = "gateway family must match prefix family")]
    fn type5_encode_panics_on_family_mismatch_in_debug() {
        let r = EvpnRoute::IpPrefix(EvpnIpPrefixRoute {
            rd: sample_rd(),
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(0),
            prefix: EvpnIpPrefixValue::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8)),
            gateway: IpAddr::V6(Ipv6Addr::LOCALHOST),
            label: MplsLabel::new(100),
        });
        let mut buf = Vec::new();
        encode_evpn_nlri(&[r], &mut buf);
    }
}
