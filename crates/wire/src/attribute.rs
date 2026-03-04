use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use crate::capability::{Afi, Safi};
use crate::constants::{as_path_segment, attr_flags, attr_type};
use crate::error::DecodeError;
use crate::nlri::{NlriEntry, Prefix};
use crate::notification::update_subcode;

/// Origin attribute values per RFC 4271 §5.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Origin {
    Igp = 0,
    Egp = 1,
    Incomplete = 2,
}

impl Origin {
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Igp),
            1 => Some(Self::Egp),
            2 => Some(Self::Incomplete),
            _ => None,
        }
    }
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Igp => write!(f, "IGP"),
            Self::Egp => write!(f, "EGP"),
            Self::Incomplete => write!(f, "INCOMPLETE"),
        }
    }
}

/// `AS_PATH` segment types per RFC 4271 §4.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsPathSegment {
    /// `AS_SET` — unordered set of ASNs.
    AsSet(Vec<u32>),
    /// `AS_SEQUENCE` — ordered sequence of ASNs.
    AsSequence(Vec<u32>),
}

/// `AS_PATH` attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsPath {
    pub segments: Vec<AsPathSegment>,
}

impl AsPath {
    /// Count the total number of ASNs in the path for best-path comparison.
    /// `AS_SET` counts as 1 regardless of size (RFC 4271 §9.1.2.2).
    #[must_use]
    pub fn len(&self) -> usize {
        self.segments
            .iter()
            .map(|seg| match seg {
                AsPathSegment::AsSequence(asns) => asns.len(),
                AsPathSegment::AsSet(_) => 1,
            })
            .sum()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Returns true if `asn` appears in any segment (`AS_SEQUENCE` or `AS_SET`).
    /// Used for loop detection per RFC 4271 §9.1.2.
    #[must_use]
    pub fn contains_asn(&self, asn: u32) -> bool {
        self.segments.iter().any(|seg| match seg {
            AsPathSegment::AsSequence(asns) | AsPathSegment::AsSet(asns) => asns.contains(&asn),
        })
    }

    /// Extract the origin ASN from the `AS_PATH`.
    ///
    /// The origin AS is the last ASN in the rightmost `AS_SEQUENCE` segment.
    /// Returns `None` if the path has no `AS_SEQUENCE` segments or all
    /// `AS_SEQUENCE` segments are empty.
    #[must_use]
    pub fn origin_asn(&self) -> Option<u32> {
        self.segments.iter().rev().find_map(|seg| match seg {
            AsPathSegment::AsSequence(asns) => asns.last().copied(),
            AsPathSegment::AsSet(_) => None,
        })
    }

    /// Convert to a string representation for regex matching.
    ///
    /// `AS_SEQUENCE` segments produce space-separated ASNs.
    /// `AS_SET` segments produce `{ASN1 ASN2}` (curly braces, space-separated).
    /// Multiple segments are space-separated.
    ///
    /// Examples: `"65001 65002"`, `"65001 {65003 65004}"`, `""` (empty path).
    #[must_use]
    pub fn to_aspath_string(&self) -> String {
        let mut parts = Vec::new();
        for seg in &self.segments {
            match seg {
                AsPathSegment::AsSequence(asns) => {
                    for asn in asns {
                        parts.push(asn.to_string());
                    }
                }
                AsPathSegment::AsSet(asns) => {
                    let inner: Vec<String> = asns.iter().map(ToString::to_string).collect();
                    parts.push(format!("{{{}}}", inner.join(" ")));
                }
            }
        }
        parts.join(" ")
    }
}

/// RFC 4760 `MP_REACH_NLRI` attribute (type code 14).
///
/// Uses [`NlriEntry`] to carry Add-Path path IDs alongside each prefix.
/// For non-Add-Path peers, `path_id` is always 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpReachNlri {
    pub afi: Afi,
    pub safi: Safi,
    /// Next-hop address for the announced prefixes.
    ///
    /// For IPv6, this stores only the global address. When a 32-byte
    /// next-hop is received (global + link-local per RFC 4760 §3), the
    /// decoder extracts the first 16 bytes (global) and discards the
    /// link-local portion. `IpAddr` can only hold a single address, and
    /// link-local next-hops are not needed for routing decisions.
    ///
    /// For `FlowSpec` (SAFI 133), next-hop length is 0 and this field is
    /// unused (defaults to `0.0.0.0`).
    pub next_hop: IpAddr,
    pub announced: Vec<NlriEntry>,
    /// `FlowSpec` NLRI rules (RFC 8955). Populated only when `safi == FlowSpec`.
    pub flowspec_announced: Vec<crate::flowspec::FlowSpecRule>,
}

/// RFC 4760 `MP_UNREACH_NLRI` attribute (type 15).
///
/// Uses [`NlriEntry`] to carry Add-Path path IDs alongside each prefix.
/// For non-Add-Path peers, `path_id` is always 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpUnreachNlri {
    pub afi: Afi,
    pub safi: Safi,
    pub withdrawn: Vec<NlriEntry>,
    /// `FlowSpec` NLRI rules withdrawn (RFC 8955). Populated only when `safi == FlowSpec`.
    pub flowspec_withdrawn: Vec<crate::flowspec::FlowSpecRule>,
}

/// RFC 4360 Extended Community — 8-byte value stored as `u64`.
///
/// Wire layout: type (1) + sub-type (1) + value (6).
/// Bit 6 of the type byte: 0 = transitive, 1 = non-transitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExtendedCommunity(u64);

impl ExtendedCommunity {
    /// Create from a raw 8-byte value.
    #[must_use]
    pub fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Return the raw 8-byte value.
    #[must_use]
    pub fn as_u64(self) -> u64 {
        self.0
    }

    /// High byte — IANA-assigned type.
    #[must_use]
    pub fn type_byte(self) -> u8 {
        (self.0 >> 56) as u8
    }

    /// Second byte — sub-type within the type.
    #[must_use]
    pub fn subtype(self) -> u8 {
        self.0.to_be_bytes()[1]
    }

    /// Transitive if bit 6 of the type byte is 0.
    #[must_use]
    pub fn is_transitive(self) -> bool {
        self.type_byte() & 0x40 == 0
    }

    /// Bytes 2-7 of the community value.
    #[must_use]
    pub fn value_bytes(self) -> [u8; 6] {
        let b = self.0.to_be_bytes();
        [b[2], b[3], b[4], b[5], b[6], b[7]]
    }

    /// Decode as Route Target (sub-type 0x02).
    ///
    /// Returns `(global_admin, local_admin)` as raw u32 values. The
    /// interpretation of `global_admin` depends on the type byte:
    /// - Type 0x00 (2-octet AS specific): global = ASN (fits u16), local = u32
    /// - Type 0x01 (IPv4 address specific): global = IPv4 addr as u32, local = u16
    /// - Type 0x02 (4-octet AS specific): global = ASN (u32), local = u16
    ///
    /// Callers that need to distinguish these encodings (e.g. for display as
    /// `RT:192.0.2.1:100` vs `RT:65001:100`) must also check [`type_byte()`](Self::type_byte).
    #[must_use]
    pub fn route_target(self) -> Option<(u32, u32)> {
        if self.subtype() != 0x02 {
            return None;
        }
        self.decode_two_part()
    }

    /// Decode as Route Origin (sub-type 0x03).
    ///
    /// Same layout as [`route_target()`](Self::route_target) — returns raw
    /// `(global_admin, local_admin)` with the same type-byte-dependent
    /// interpretation. Check [`type_byte()`](Self::type_byte) to distinguish
    /// 2-octet AS, IPv4-address, and 4-octet AS encodings.
    #[must_use]
    pub fn route_origin(self) -> Option<(u32, u32)> {
        if self.subtype() != 0x03 {
            return None;
        }
        self.decode_two_part()
    }

    /// Decode the 6-byte value field as `(global_admin, local_admin)`.
    ///
    /// Handles all three RFC 4360 two-part layouts (2-octet AS, IPv4, 4-octet
    /// AS). Returns raw u32 values — the caller decides how to interpret
    /// `global_admin` (ASN vs IPv4 address) based on `type_byte()`.
    fn decode_two_part(self) -> Option<(u32, u32)> {
        let v = self.value_bytes();
        let t = self.type_byte() & 0x3F; // mask off high two bits
        match t {
            // 2-octet AS specific: AS(2) + value(4)
            0x00 => {
                let global = u32::from(u16::from_be_bytes([v[0], v[1]]));
                let local = u32::from_be_bytes([v[2], v[3], v[4], v[5]]);
                Some((global, local))
            }
            // IPv4 Address specific (0x01) or 4-octet AS specific (0x02): 4 + 2
            0x01 | 0x02 => {
                let global = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
                let local = u32::from(u16::from_be_bytes([v[4], v[5]]));
                Some((global, local))
            }
            _ => None,
        }
    }
}

impl fmt::Display for ExtendedCommunity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let is_ipv4 = self.type_byte() & 0x3F == 0x01;
        if let Some((g, l)) = self.route_target() {
            if is_ipv4 {
                write!(f, "RT:{}:{l}", Ipv4Addr::from(g))
            } else {
                write!(f, "RT:{g}:{l}")
            }
        } else if let Some((g, l)) = self.route_origin() {
            if is_ipv4 {
                write!(f, "RO:{}:{l}", Ipv4Addr::from(g))
            } else {
                write!(f, "RO:{g}:{l}")
            }
        } else {
            write!(f, "0x{:016x}", self.0)
        }
    }
}

/// RFC 8092 Large Community — 12-byte value: `(global_admin, local_data1, local_data2)`.
///
/// Each field is a 32-bit unsigned integer. Display format: `"65001:100:200"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LargeCommunity {
    pub global_admin: u32,
    pub local_data1: u32,
    pub local_data2: u32,
}

impl LargeCommunity {
    #[must_use]
    pub fn new(global_admin: u32, local_data1: u32, local_data2: u32) -> Self {
        Self {
            global_admin,
            local_data1,
            local_data2,
        }
    }
}

impl fmt::Display for LargeCommunity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.global_admin, self.local_data1, self.local_data2
        )
    }
}

/// A known path attribute or raw preserved bytes.
///
/// Known attributes are decoded into typed variants. Unknown attributes
/// are preserved as `RawAttribute` for pass-through with the Partial bit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathAttribute {
    Origin(Origin),
    AsPath(AsPath),
    NextHop(Ipv4Addr),
    LocalPref(u32),
    Med(u32),
    /// RFC 1997 COMMUNITIES — each u32 is high16=ASN, low16=value.
    Communities(Vec<u32>),
    /// RFC 4360 EXTENDED COMMUNITIES.
    ExtendedCommunities(Vec<ExtendedCommunity>),
    /// RFC 8092 LARGE COMMUNITIES.
    LargeCommunities(Vec<LargeCommunity>),
    /// RFC 4456 `ORIGINATOR_ID` — original router-id of the route.
    OriginatorId(Ipv4Addr),
    /// RFC 4456 `CLUSTER_LIST` — list of cluster-ids traversed.
    ClusterList(Vec<Ipv4Addr>),
    /// RFC 4760 `MP_REACH_NLRI`.
    MpReachNlri(MpReachNlri),
    /// RFC 4760 `MP_UNREACH_NLRI`.
    MpUnreachNlri(MpUnreachNlri),
    /// Unknown or unrecognized attribute, preserved for re-advertisement.
    Unknown(RawAttribute),
}

impl PathAttribute {
    /// Return the type code of this attribute.
    #[must_use]
    pub fn type_code(&self) -> u8 {
        match self {
            Self::Origin(_) => attr_type::ORIGIN,
            Self::AsPath(_) => attr_type::AS_PATH,
            Self::NextHop(_) => attr_type::NEXT_HOP,
            Self::LocalPref(_) => attr_type::LOCAL_PREF,
            Self::Med(_) => attr_type::MULTI_EXIT_DISC,
            Self::Communities(_) => attr_type::COMMUNITIES,
            Self::OriginatorId(_) => attr_type::ORIGINATOR_ID,
            Self::ClusterList(_) => attr_type::CLUSTER_LIST,
            Self::ExtendedCommunities(_) => attr_type::EXTENDED_COMMUNITIES,
            Self::LargeCommunities(_) => attr_type::LARGE_COMMUNITIES,
            Self::MpReachNlri(_) => attr_type::MP_REACH_NLRI,
            Self::MpUnreachNlri(_) => attr_type::MP_UNREACH_NLRI,
            Self::Unknown(raw) => raw.type_code,
        }
    }

    /// Return the wire flags for this attribute.
    #[must_use]
    pub fn flags(&self) -> u8 {
        match self {
            Self::Origin(_) | Self::AsPath(_) | Self::NextHop(_) | Self::LocalPref(_) => {
                attr_flags::TRANSITIVE
            }
            Self::Med(_)
            | Self::OriginatorId(_)
            | Self::ClusterList(_)
            | Self::MpReachNlri(_)
            | Self::MpUnreachNlri(_) => attr_flags::OPTIONAL,
            Self::Communities(_) | Self::ExtendedCommunities(_) | Self::LargeCommunities(_) => {
                attr_flags::OPTIONAL | attr_flags::TRANSITIVE
            }
            Self::Unknown(raw) => raw.flags,
        }
    }
}

/// Raw attribute preserved for pass-through (RFC 4271 §5).
///
/// On re-advertisement, the Partial bit (0x20) is OR'd into `flags`.
/// All other flags and bytes are preserved unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAttribute {
    pub flags: u8,
    pub type_code: u8,
    pub data: Bytes,
}

/// Decode path attributes from wire bytes (RFC 4271 §4.3).
///
/// Each attribute is: flags(1) + type(1) + length(1 or 2) + value.
/// The Extended Length flag determines 1-byte vs 2-byte length.
///
/// `four_octet_as` controls whether AS numbers in `AS_PATH` are 2 or 4 bytes.
///
/// # Errors
///
/// Returns `DecodeError` on truncated data or malformed attribute values.
pub fn decode_path_attributes(
    mut buf: &[u8],
    four_octet_as: bool,
    add_path_families: &[(Afi, Safi)],
) -> Result<Vec<PathAttribute>, DecodeError> {
    let mut attrs = Vec::new();

    while !buf.is_empty() {
        // Need at least flags(1) + type(1) = 2
        if buf.len() < 2 {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: "truncated attribute header".to_string(),
            });
        }

        let flags = buf[0];
        let type_code = buf[1];
        buf = &buf[2..];

        let extended = (flags & attr_flags::EXTENDED_LENGTH) != 0;
        let value_len = if extended {
            if buf.len() < 2 {
                return Err(DecodeError::MalformedField {
                    message_type: "UPDATE",
                    detail: "truncated extended-length attribute".to_string(),
                });
            }
            let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            buf = &buf[2..];
            len
        } else {
            if buf.is_empty() {
                return Err(DecodeError::MalformedField {
                    message_type: "UPDATE",
                    detail: "truncated attribute length".to_string(),
                });
            }
            let len = buf[0] as usize;
            buf = &buf[1..];
            len
        };

        if buf.len() < value_len {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: format!(
                    "attribute type {type_code} value truncated: need {value_len}, have {}",
                    buf.len()
                ),
            });
        }

        let value = &buf[..value_len];
        buf = &buf[value_len..];

        let attr =
            decode_attribute_value(flags, type_code, value, four_octet_as, add_path_families)?;
        attrs.push(attr);
    }

    Ok(attrs)
}

/// Decode a single attribute value given its flags, type code, and raw bytes.
#[expect(clippy::too_many_lines)]
fn decode_attribute_value(
    flags: u8,
    type_code: u8,
    value: &[u8],
    four_octet_as: bool,
    add_path_families: &[(Afi, Safi)],
) -> Result<PathAttribute, DecodeError> {
    // Validate Optional + Transitive flags for known attribute types (RFC 4271 §6.3).
    let flags_mask = attr_flags::OPTIONAL | attr_flags::TRANSITIVE;
    if let Some(expected) = expected_flags(type_code)
        && (flags & flags_mask) != expected
    {
        return Err(DecodeError::UpdateAttributeError {
            subcode: update_subcode::ATTRIBUTE_FLAGS_ERROR,
            data: attr_error_data(flags, type_code, value),
            detail: format!(
                "type {} flags {:#04x} (expected {:#04x})",
                type_code,
                flags & flags_mask,
                expected
            ),
        });
    }

    match type_code {
        attr_type::ORIGIN => {
            if value.len() != 1 {
                return Err(DecodeError::UpdateAttributeError {
                    subcode: update_subcode::ATTRIBUTE_LENGTH_ERROR,
                    data: attr_error_data(flags, type_code, value),
                    detail: format!("ORIGIN length {} (expected 1)", value.len()),
                });
            }
            match Origin::from_u8(value[0]) {
                Some(origin) => Ok(PathAttribute::Origin(origin)),
                None => Err(DecodeError::UpdateAttributeError {
                    subcode: update_subcode::INVALID_ORIGIN,
                    data: attr_error_data(flags, type_code, value),
                    detail: format!("invalid ORIGIN value {}", value[0]),
                }),
            }
        }

        attr_type::AS_PATH => {
            let segments = decode_as_path(value, four_octet_as).map_err(|e| {
                DecodeError::UpdateAttributeError {
                    subcode: update_subcode::MALFORMED_AS_PATH,
                    data: attr_error_data(flags, type_code, value),
                    detail: e.to_string(),
                }
            })?;
            Ok(PathAttribute::AsPath(AsPath { segments }))
        }

        attr_type::NEXT_HOP => {
            if value.len() != 4 {
                return Err(DecodeError::UpdateAttributeError {
                    subcode: update_subcode::ATTRIBUTE_LENGTH_ERROR,
                    data: attr_error_data(flags, type_code, value),
                    detail: format!("NEXT_HOP length {} (expected 4)", value.len()),
                });
            }
            let addr = Ipv4Addr::new(value[0], value[1], value[2], value[3]);
            Ok(PathAttribute::NextHop(addr))
        }

        attr_type::MULTI_EXIT_DISC => {
            if value.len() != 4 {
                return Err(DecodeError::UpdateAttributeError {
                    subcode: update_subcode::ATTRIBUTE_LENGTH_ERROR,
                    data: attr_error_data(flags, type_code, value),
                    detail: format!("MED length {} (expected 4)", value.len()),
                });
            }
            let med = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
            Ok(PathAttribute::Med(med))
        }

        attr_type::LOCAL_PREF => {
            if value.len() != 4 {
                return Err(DecodeError::UpdateAttributeError {
                    subcode: update_subcode::ATTRIBUTE_LENGTH_ERROR,
                    data: attr_error_data(flags, type_code, value),
                    detail: format!("LOCAL_PREF length {} (expected 4)", value.len()),
                });
            }
            let lp = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
            Ok(PathAttribute::LocalPref(lp))
        }

        attr_type::COMMUNITIES => {
            if !value.len().is_multiple_of(4) {
                return Err(DecodeError::UpdateAttributeError {
                    subcode: update_subcode::ATTRIBUTE_LENGTH_ERROR,
                    data: attr_error_data(flags, type_code, value),
                    detail: format!("COMMUNITIES length {} not a multiple of 4", value.len()),
                });
            }
            let communities = value
                .chunks_exact(4)
                .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                .collect();
            Ok(PathAttribute::Communities(communities))
        }

        attr_type::EXTENDED_COMMUNITIES => {
            if !value.len().is_multiple_of(8) {
                return Err(DecodeError::UpdateAttributeError {
                    subcode: update_subcode::ATTRIBUTE_LENGTH_ERROR,
                    data: attr_error_data(flags, type_code, value),
                    detail: format!(
                        "EXTENDED_COMMUNITIES length {} not a multiple of 8",
                        value.len()
                    ),
                });
            }
            let communities = value
                .chunks_exact(8)
                .map(|c| {
                    ExtendedCommunity::new(u64::from_be_bytes([
                        c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7],
                    ]))
                })
                .collect();
            Ok(PathAttribute::ExtendedCommunities(communities))
        }

        attr_type::ORIGINATOR_ID => {
            if value.len() != 4 {
                return Err(DecodeError::UpdateAttributeError {
                    subcode: update_subcode::ATTRIBUTE_LENGTH_ERROR,
                    data: attr_error_data(flags, type_code, value),
                    detail: format!("ORIGINATOR_ID length {} (expected 4)", value.len()),
                });
            }
            let addr = Ipv4Addr::new(value[0], value[1], value[2], value[3]);
            Ok(PathAttribute::OriginatorId(addr))
        }

        attr_type::CLUSTER_LIST => {
            if !value.len().is_multiple_of(4) {
                return Err(DecodeError::UpdateAttributeError {
                    subcode: update_subcode::ATTRIBUTE_LENGTH_ERROR,
                    data: attr_error_data(flags, type_code, value),
                    detail: format!("CLUSTER_LIST length {} not a multiple of 4", value.len()),
                });
            }
            let ids = value
                .chunks_exact(4)
                .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                .collect();
            Ok(PathAttribute::ClusterList(ids))
        }

        attr_type::LARGE_COMMUNITIES => {
            if value.is_empty() || !value.len().is_multiple_of(12) {
                return Err(DecodeError::UpdateAttributeError {
                    subcode: update_subcode::ATTRIBUTE_LENGTH_ERROR,
                    data: attr_error_data(flags, type_code, value),
                    detail: format!(
                        "LARGE_COMMUNITIES length {} invalid (must be non-zero multiple of 12)",
                        value.len()
                    ),
                });
            }
            let communities = value
                .chunks_exact(12)
                .map(|c| {
                    LargeCommunity::new(
                        u32::from_be_bytes([c[0], c[1], c[2], c[3]]),
                        u32::from_be_bytes([c[4], c[5], c[6], c[7]]),
                        u32::from_be_bytes([c[8], c[9], c[10], c[11]]),
                    )
                })
                .collect();
            Ok(PathAttribute::LargeCommunities(communities))
        }

        attr_type::MP_REACH_NLRI => decode_mp_reach_nlri(value, add_path_families),
        attr_type::MP_UNREACH_NLRI => decode_mp_unreach_nlri(value, add_path_families),

        // ATOMIC_AGGREGATE, AGGREGATOR, and any unknown type → RawAttribute
        _ => Ok(PathAttribute::Unknown(RawAttribute {
            flags,
            type_code,
            data: Bytes::copy_from_slice(value),
        })),
    }
}

/// Decode `MP_REACH_NLRI` (type 14) attribute value.
///
/// Wire layout (RFC 4760 §3):
///   AFI (2) | SAFI (1) | NH-Len (1) | Next Hop (variable) | Reserved (1) | NLRI (variable)
#[expect(clippy::too_many_lines)]
fn decode_mp_reach_nlri(
    value: &[u8],
    add_path_families: &[(Afi, Safi)],
) -> Result<PathAttribute, DecodeError> {
    if value.len() < 5 {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: format!("MP_REACH_NLRI too short: {} bytes", value.len()),
        });
    }

    let afi_raw = u16::from_be_bytes([value[0], value[1]]);
    let safi_raw = value[2];
    let nh_len = value[3] as usize;

    let afi = Afi::from_u16(afi_raw).ok_or_else(|| DecodeError::MalformedField {
        message_type: "UPDATE",
        detail: format!("MP_REACH_NLRI unsupported AFI {afi_raw}"),
    })?;
    let safi = Safi::from_u8(safi_raw).ok_or_else(|| DecodeError::MalformedField {
        message_type: "UPDATE",
        detail: format!("MP_REACH_NLRI unsupported SAFI {safi_raw}"),
    })?;

    // 4 bytes for AFI+SAFI+NH-Len, then nh_len bytes, then 1 reserved byte
    if value.len() < 4 + nh_len + 1 {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: format!(
                "MP_REACH_NLRI truncated: NH-Len={nh_len}, have {} bytes total",
                value.len()
            ),
        });
    }

    let nh_bytes = &value[4..4 + nh_len];
    // FlowSpec (SAFI 133): NH length is 0 — no next-hop for filter rules
    let next_hop = if safi == Safi::FlowSpec {
        if nh_len != 0 {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: format!("MP_REACH_NLRI FlowSpec next-hop length {nh_len} (expected 0)"),
            });
        }
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        match afi {
            Afi::Ipv4 => {
                if nh_len != 4 {
                    return Err(DecodeError::MalformedField {
                        message_type: "UPDATE",
                        detail: format!("MP_REACH_NLRI IPv4 next-hop length {nh_len} (expected 4)"),
                    });
                }
                IpAddr::V4(Ipv4Addr::new(
                    nh_bytes[0],
                    nh_bytes[1],
                    nh_bytes[2],
                    nh_bytes[3],
                ))
            }
            Afi::Ipv6 => {
                if nh_len != 16 && nh_len != 32 {
                    return Err(DecodeError::MalformedField {
                        message_type: "UPDATE",
                        detail: format!(
                            "MP_REACH_NLRI IPv6 next-hop length {nh_len} (expected 16 or 32)"
                        ),
                    });
                }
                // Take first 16 bytes (global address); ignore link-local if 32
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&nh_bytes[..16]);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        }
    };

    // Skip reserved byte
    let nlri_start = 4 + nh_len + 1;
    let nlri_bytes = &value[nlri_start..];

    // FlowSpec (SAFI 133): NLRI is FlowSpec rules, not prefixes
    if safi == Safi::FlowSpec {
        let flowspec_rules = crate::flowspec::decode_flowspec_nlri(nlri_bytes, afi)?;
        return Ok(PathAttribute::MpReachNlri(MpReachNlri {
            afi,
            safi,
            next_hop,
            announced: vec![],
            flowspec_announced: flowspec_rules,
        }));
    }

    let add_path = add_path_families.contains(&(afi, safi));
    let announced = match (afi, add_path) {
        (Afi::Ipv4, false) => crate::nlri::decode_nlri(nlri_bytes)?
            .into_iter()
            .map(|p| NlriEntry {
                path_id: 0,
                prefix: Prefix::V4(p),
            })
            .collect(),
        (Afi::Ipv4, true) => crate::nlri::decode_nlri_addpath(nlri_bytes)?
            .into_iter()
            .map(|e| NlriEntry {
                path_id: e.path_id,
                prefix: Prefix::V4(e.prefix),
            })
            .collect(),
        (Afi::Ipv6, false) => crate::nlri::decode_ipv6_nlri(nlri_bytes)?
            .into_iter()
            .map(|p| NlriEntry {
                path_id: 0,
                prefix: Prefix::V6(p),
            })
            .collect(),
        (Afi::Ipv6, true) => crate::nlri::decode_ipv6_nlri_addpath(nlri_bytes)?,
    };

    Ok(PathAttribute::MpReachNlri(MpReachNlri {
        afi,
        safi,
        next_hop,
        announced,
        flowspec_announced: vec![],
    }))
}

/// Decode `MP_UNREACH_NLRI` (type 15) attribute value.
///
/// Wire layout (RFC 4760 §4):
///   AFI (2) | SAFI (1) | Withdrawn Routes (variable)
fn decode_mp_unreach_nlri(
    value: &[u8],
    add_path_families: &[(Afi, Safi)],
) -> Result<PathAttribute, DecodeError> {
    if value.len() < 3 {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: format!("MP_UNREACH_NLRI too short: {} bytes", value.len()),
        });
    }

    let afi_raw = u16::from_be_bytes([value[0], value[1]]);
    let safi_raw = value[2];

    let afi = Afi::from_u16(afi_raw).ok_or_else(|| DecodeError::MalformedField {
        message_type: "UPDATE",
        detail: format!("MP_UNREACH_NLRI unsupported AFI {afi_raw}"),
    })?;
    let safi = Safi::from_u8(safi_raw).ok_or_else(|| DecodeError::MalformedField {
        message_type: "UPDATE",
        detail: format!("MP_UNREACH_NLRI unsupported SAFI {safi_raw}"),
    })?;

    let withdrawn_bytes = &value[3..];

    // FlowSpec (SAFI 133): withdrawn is FlowSpec rules
    if safi == Safi::FlowSpec {
        let flowspec_rules = crate::flowspec::decode_flowspec_nlri(withdrawn_bytes, afi)?;
        return Ok(PathAttribute::MpUnreachNlri(MpUnreachNlri {
            afi,
            safi,
            withdrawn: vec![],
            flowspec_withdrawn: flowspec_rules,
        }));
    }

    let add_path = add_path_families.contains(&(afi, safi));
    let withdrawn = match (afi, add_path) {
        (Afi::Ipv4, false) => crate::nlri::decode_nlri(withdrawn_bytes)?
            .into_iter()
            .map(|p| NlriEntry {
                path_id: 0,
                prefix: Prefix::V4(p),
            })
            .collect(),
        (Afi::Ipv4, true) => crate::nlri::decode_nlri_addpath(withdrawn_bytes)?
            .into_iter()
            .map(|e| NlriEntry {
                path_id: e.path_id,
                prefix: Prefix::V4(e.prefix),
            })
            .collect(),
        (Afi::Ipv6, false) => crate::nlri::decode_ipv6_nlri(withdrawn_bytes)?
            .into_iter()
            .map(|p| NlriEntry {
                path_id: 0,
                prefix: Prefix::V6(p),
            })
            .collect(),
        (Afi::Ipv6, true) => crate::nlri::decode_ipv6_nlri_addpath(withdrawn_bytes)?,
    };

    Ok(PathAttribute::MpUnreachNlri(MpUnreachNlri {
        afi,
        safi,
        withdrawn,
        flowspec_withdrawn: vec![],
    }))
}

/// Decode `AS_PATH` segments from the attribute value bytes.
fn decode_as_path(mut buf: &[u8], four_octet_as: bool) -> Result<Vec<AsPathSegment>, DecodeError> {
    let as_size: usize = if four_octet_as { 4 } else { 2 };
    let mut segments = Vec::new();

    while !buf.is_empty() {
        if buf.len() < 2 {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: "truncated AS_PATH segment header".to_string(),
            });
        }

        let seg_type = buf[0];
        let seg_count = buf[1] as usize;
        buf = &buf[2..];

        let needed = seg_count * as_size;
        if buf.len() < needed {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: format!(
                    "AS_PATH segment truncated: need {needed} bytes for {seg_count} ASNs, have {}",
                    buf.len()
                ),
            });
        }

        let mut asns = Vec::with_capacity(seg_count);
        for _ in 0..seg_count {
            let asn = if four_octet_as {
                let v = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                buf = &buf[4..];
                v
            } else {
                let v = u32::from(u16::from_be_bytes([buf[0], buf[1]]));
                buf = &buf[2..];
                v
            };
            asns.push(asn);
        }

        match seg_type {
            as_path_segment::AS_SET => segments.push(AsPathSegment::AsSet(asns)),
            as_path_segment::AS_SEQUENCE => segments.push(AsPathSegment::AsSequence(asns)),
            _ => {
                return Err(DecodeError::MalformedField {
                    message_type: "UPDATE",
                    detail: format!("unknown AS_PATH segment type {seg_type}"),
                });
            }
        }
    }

    Ok(segments)
}

/// Build the attribute-triplet (flags + type + length + value) used as
/// NOTIFICATION data in UPDATE error subcodes per RFC 4271 §6.3.
pub(crate) fn attr_error_data(flags: u8, type_code: u8, value: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(3 + value.len());
    if value.len() > 255 {
        buf.push(flags | attr_flags::EXTENDED_LENGTH);
        buf.push(type_code);
        #[expect(clippy::cast_possible_truncation)]
        let len = value.len() as u16;
        buf.extend_from_slice(&len.to_be_bytes());
    } else {
        buf.push(flags);
        buf.push(type_code);
        #[expect(clippy::cast_possible_truncation)]
        buf.push(value.len() as u8);
    }
    buf.extend_from_slice(value);
    buf
}

/// Return the expected Optional + Transitive flags for known attribute types.
/// Returns `None` for unrecognized types (no validation performed).
fn expected_flags(type_code: u8) -> Option<u8> {
    match type_code {
        // Well-known mandatory/discretionary: Optional=0, Transitive=1
        attr_type::ORIGIN
        | attr_type::AS_PATH
        | attr_type::NEXT_HOP
        | attr_type::LOCAL_PREF
        | attr_type::ATOMIC_AGGREGATE => Some(attr_flags::TRANSITIVE),
        // Optional non-transitive (RFC 4760 §3/§4: MP_REACH/UNREACH are non-transitive;
        // RFC 4456: ORIGINATOR_ID and CLUSTER_LIST are optional non-transitive)
        attr_type::MULTI_EXIT_DISC
        | attr_type::ORIGINATOR_ID
        | attr_type::CLUSTER_LIST
        | attr_type::MP_REACH_NLRI
        | attr_type::MP_UNREACH_NLRI => Some(attr_flags::OPTIONAL),
        // Optional transitive
        attr_type::AGGREGATOR
        | attr_type::COMMUNITIES
        | attr_type::EXTENDED_COMMUNITIES
        | attr_type::LARGE_COMMUNITIES => Some(attr_flags::OPTIONAL | attr_flags::TRANSITIVE),
        _ => None,
    }
}

/// Encode path attributes to wire bytes.
///
/// `four_octet_as` controls whether AS numbers in `AS_PATH` are 2 or 4 bytes.
/// Encode a list of path attributes into wire format.
///
/// When `add_path_mp` is true, `MP_REACH_NLRI` and `MP_UNREACH_NLRI` NLRI
/// entries include 4-byte path IDs per RFC 7911.
pub fn encode_path_attributes(
    attrs: &[PathAttribute],
    buf: &mut Vec<u8>,
    four_octet_as: bool,
    add_path_mp: bool,
) {
    for attr in attrs {
        let mut value = Vec::new();
        let flags;
        let type_code;

        match attr {
            PathAttribute::Origin(origin) => {
                flags = attr_flags::TRANSITIVE;
                type_code = attr_type::ORIGIN;
                value.push(*origin as u8);
            }
            PathAttribute::AsPath(as_path) => {
                flags = attr_flags::TRANSITIVE;
                type_code = attr_type::AS_PATH;
                encode_as_path(as_path, &mut value, four_octet_as);
            }
            PathAttribute::NextHop(addr) => {
                flags = attr_flags::TRANSITIVE;
                type_code = attr_type::NEXT_HOP;
                value.extend_from_slice(&addr.octets());
            }
            PathAttribute::Med(med) => {
                flags = attr_flags::OPTIONAL;
                type_code = attr_type::MULTI_EXIT_DISC;
                value.extend_from_slice(&med.to_be_bytes());
            }
            PathAttribute::LocalPref(lp) => {
                flags = attr_flags::TRANSITIVE;
                type_code = attr_type::LOCAL_PREF;
                value.extend_from_slice(&lp.to_be_bytes());
            }
            PathAttribute::Communities(communities) => {
                flags = attr_flags::OPTIONAL | attr_flags::TRANSITIVE;
                type_code = attr_type::COMMUNITIES;
                for &c in communities {
                    value.extend_from_slice(&c.to_be_bytes());
                }
            }
            PathAttribute::ExtendedCommunities(communities) => {
                flags = attr_flags::OPTIONAL | attr_flags::TRANSITIVE;
                type_code = attr_type::EXTENDED_COMMUNITIES;
                for &c in communities {
                    value.extend_from_slice(&c.as_u64().to_be_bytes());
                }
            }
            PathAttribute::LargeCommunities(communities) => {
                flags = attr_flags::OPTIONAL | attr_flags::TRANSITIVE;
                type_code = attr_type::LARGE_COMMUNITIES;
                for &c in communities {
                    value.extend_from_slice(&c.global_admin.to_be_bytes());
                    value.extend_from_slice(&c.local_data1.to_be_bytes());
                    value.extend_from_slice(&c.local_data2.to_be_bytes());
                }
            }
            PathAttribute::OriginatorId(addr) => {
                flags = attr_flags::OPTIONAL;
                type_code = attr_type::ORIGINATOR_ID;
                value.extend_from_slice(&addr.octets());
            }
            PathAttribute::ClusterList(ids) => {
                flags = attr_flags::OPTIONAL;
                type_code = attr_type::CLUSTER_LIST;
                for id in ids {
                    value.extend_from_slice(&id.octets());
                }
            }
            PathAttribute::MpReachNlri(mp) => {
                flags = attr_flags::OPTIONAL;
                type_code = attr_type::MP_REACH_NLRI;
                encode_mp_reach_nlri(mp, &mut value, add_path_mp);
            }
            PathAttribute::MpUnreachNlri(mp) => {
                flags = attr_flags::OPTIONAL;
                type_code = attr_type::MP_UNREACH_NLRI;
                encode_mp_unreach_nlri(mp, &mut value, add_path_mp);
            }
            PathAttribute::Unknown(raw) => {
                // RFC 4271 §5: unrecognized *optional* transitive attributes
                // must be propagated with the Partial bit set. Well-known
                // transitive attributes (OPTIONAL=0) must NOT get PARTIAL.
                let optional_transitive = attr_flags::OPTIONAL | attr_flags::TRANSITIVE;
                flags = if (raw.flags & optional_transitive) == optional_transitive {
                    raw.flags | attr_flags::PARTIAL
                } else {
                    raw.flags
                };
                type_code = raw.type_code;
                value.extend_from_slice(&raw.data);
            }
        }

        // Use extended length if value > 255 bytes
        if value.len() > 255 {
            buf.push(flags | attr_flags::EXTENDED_LENGTH);
            buf.push(type_code);
            #[expect(clippy::cast_possible_truncation)]
            let len = value.len() as u16;
            buf.extend_from_slice(&len.to_be_bytes());
        } else {
            buf.push(flags);
            buf.push(type_code);
            #[expect(clippy::cast_possible_truncation)]
            buf.push(value.len() as u8);
        }
        buf.extend_from_slice(&value);
    }
}

/// Encode `MP_REACH_NLRI` value bytes.
///
/// When `add_path` is true, each NLRI entry includes a 4-byte path ID
/// prefix per RFC 7911.
fn encode_mp_reach_nlri(mp: &MpReachNlri, buf: &mut Vec<u8>, add_path: bool) {
    buf.extend_from_slice(&(mp.afi as u16).to_be_bytes());
    buf.push(mp.safi as u8);

    // FlowSpec: NH length = 0, reserved = 0, then FlowSpec NLRI
    if mp.safi == Safi::FlowSpec {
        buf.push(0); // NH-Len = 0
        buf.push(0); // Reserved
        crate::flowspec::encode_flowspec_nlri(&mp.flowspec_announced, buf, mp.afi);
        return;
    }

    match mp.next_hop {
        IpAddr::V4(addr) => {
            buf.push(4); // NH-Len
            buf.extend_from_slice(&addr.octets());
        }
        IpAddr::V6(addr) => {
            buf.push(16); // NH-Len
            buf.extend_from_slice(&addr.octets());
        }
    }

    buf.push(0); // Reserved

    if add_path {
        crate::nlri::encode_ipv6_nlri_addpath(&mp.announced, buf);
    } else {
        for entry in &mp.announced {
            match entry.prefix {
                Prefix::V4(p) => crate::nlri::encode_nlri(&[p], buf),
                Prefix::V6(p) => crate::nlri::encode_ipv6_nlri(&[p], buf),
            }
        }
    }
}

/// Encode `MP_UNREACH_NLRI` value bytes.
///
/// When `add_path` is true, each withdrawn entry includes a 4-byte path ID.
fn encode_mp_unreach_nlri(mp: &MpUnreachNlri, buf: &mut Vec<u8>, add_path: bool) {
    buf.extend_from_slice(&(mp.afi as u16).to_be_bytes());
    buf.push(mp.safi as u8);

    // FlowSpec: encode FlowSpec NLRI rules
    if mp.safi == Safi::FlowSpec {
        crate::flowspec::encode_flowspec_nlri(&mp.flowspec_withdrawn, buf, mp.afi);
        return;
    }

    if add_path {
        crate::nlri::encode_ipv6_nlri_addpath(&mp.withdrawn, buf);
    } else {
        for entry in &mp.withdrawn {
            match entry.prefix {
                Prefix::V4(p) => crate::nlri::encode_nlri(&[p], buf),
                Prefix::V6(p) => crate::nlri::encode_ipv6_nlri(&[p], buf),
            }
        }
    }
}

/// Encode `AS_PATH` segments into value bytes.
fn encode_as_path(as_path: &AsPath, buf: &mut Vec<u8>, four_octet_as: bool) {
    for segment in &as_path.segments {
        let (seg_type, asns) = match segment {
            AsPathSegment::AsSet(asns) => (as_path_segment::AS_SET, asns),
            AsPathSegment::AsSequence(asns) => (as_path_segment::AS_SEQUENCE, asns),
        };
        buf.push(seg_type);
        #[expect(clippy::cast_possible_truncation)]
        buf.push(asns.len() as u8);
        for &asn in asns {
            if four_octet_as {
                buf.extend_from_slice(&asn.to_be_bytes());
            } else {
                // RFC 6793: ASNs > 65535 are mapped to AS_TRANS (23456)
                // in 2-octet AS_PATH encoding.
                let as2 = u16::try_from(asn).unwrap_or(crate::constants::AS_TRANS);
                buf.extend_from_slice(&as2.to_be_bytes());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_from_u8_roundtrip() {
        assert_eq!(Origin::from_u8(0), Some(Origin::Igp));
        assert_eq!(Origin::from_u8(1), Some(Origin::Egp));
        assert_eq!(Origin::from_u8(2), Some(Origin::Incomplete));
        assert_eq!(Origin::from_u8(3), None);
    }

    #[test]
    fn origin_ordering() {
        assert!(Origin::Igp < Origin::Egp);
        assert!(Origin::Egp < Origin::Incomplete);
    }

    #[test]
    fn as_path_length_calculation() {
        let path = AsPath {
            segments: vec![
                AsPathSegment::AsSequence(vec![65001, 65002, 65003]),
                AsPathSegment::AsSet(vec![65004, 65005]),
            ],
        };
        // Sequence: 3 ASNs, Set: counts as 1 → total 4
        assert_eq!(path.len(), 4);
    }

    #[test]
    fn as_path_empty() {
        let path = AsPath { segments: vec![] };
        assert!(path.is_empty());
        assert_eq!(path.len(), 0);
    }

    #[test]
    fn contains_asn_in_sequence() {
        let path = AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65001, 65002, 65003])],
        };
        assert!(path.contains_asn(65002));
        assert!(!path.contains_asn(65004));
    }

    #[test]
    fn contains_asn_in_set() {
        let path = AsPath {
            segments: vec![AsPathSegment::AsSet(vec![65004, 65005])],
        };
        assert!(path.contains_asn(65005));
        assert!(!path.contains_asn(65001));
    }

    #[test]
    fn contains_asn_multiple_segments() {
        let path = AsPath {
            segments: vec![
                AsPathSegment::AsSequence(vec![65001, 65002]),
                AsPathSegment::AsSet(vec![65003]),
            ],
        };
        assert!(path.contains_asn(65001));
        assert!(path.contains_asn(65003));
        assert!(!path.contains_asn(65004));
    }

    #[test]
    fn contains_asn_empty_path() {
        let path = AsPath { segments: vec![] };
        assert!(!path.contains_asn(65001));
    }

    #[test]
    fn decode_origin_igp() {
        // flags=0x40 (transitive), type=1, len=1, value=0 (IGP)
        let buf = [0x40, 0x01, 0x01, 0x00];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0], PathAttribute::Origin(Origin::Igp));
    }

    #[test]
    fn decode_origin_egp() {
        let buf = [0x40, 0x01, 0x01, 0x01];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs[0], PathAttribute::Origin(Origin::Egp));
    }

    #[test]
    fn decode_origin_invalid_value() {
        // ORIGIN with value 5 — not a valid Origin (only 0-2 are defined)
        let buf = [0x40, 0x01, 0x01, 0x05];
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        match &err {
            DecodeError::UpdateAttributeError { subcode, .. } => {
                assert_eq!(*subcode, update_subcode::INVALID_ORIGIN);
            }
            other => panic!("expected UpdateAttributeError, got: {other:?}"),
        }
    }

    #[test]
    fn decode_next_hop() {
        // flags=0x40, type=3, len=4, value=10.0.0.1
        let buf = [0x40, 0x03, 0x04, 10, 0, 0, 1];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs[0], PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn decode_med() {
        // flags=0x80 (optional), type=4, len=4, value=100
        let buf = [0x80, 0x04, 0x04, 0, 0, 0, 100];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs[0], PathAttribute::Med(100));
    }

    #[test]
    fn decode_local_pref() {
        // flags=0x40, type=5, len=4, value=200
        let buf = [0x40, 0x05, 0x04, 0, 0, 0, 200];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs[0], PathAttribute::LocalPref(200));
    }

    #[test]
    fn decode_as_path_4byte() {
        // flags=0x40, type=2, len=10
        // segment: type=2 (AS_SEQUENCE), count=2, ASNs: 65001, 65002 (4 bytes each)
        let buf = [
            0x40, 0x02, 0x0A, // header
            0x02, 0x02, // AS_SEQUENCE, 2 ASNs
            0x00, 0x00, 0xFD, 0xE9, // 65001
            0x00, 0x00, 0xFD, 0xEA, // 65002
        ];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(
            attrs[0],
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001, 65002])]
            })
        );
    }

    #[test]
    fn decode_as_path_2byte() {
        // flags=0x40, type=2, len=6
        // segment: type=2 (AS_SEQUENCE), count=2, ASNs: 100, 200 (2 bytes each)
        let buf = [
            0x40, 0x02, 0x06, // header
            0x02, 0x02, // AS_SEQUENCE, 2 ASNs
            0x00, 0x64, // 100
            0x00, 0xC8, // 200
        ];
        let attrs = decode_path_attributes(&buf, false, &[]).unwrap();
        assert_eq!(
            attrs[0],
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![100, 200])]
            })
        );
    }

    #[test]
    fn decode_unknown_attribute_preserved() {
        // flags=0xC0 (optional+transitive), type=99, len=3, data=[1,2,3]
        let buf = [0xC0, 99, 0x03, 1, 2, 3];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(
            attrs[0],
            PathAttribute::Unknown(RawAttribute {
                flags: 0xC0,
                type_code: 99,
                data: Bytes::from_static(&[1, 2, 3]),
            })
        );
    }

    #[test]
    fn decode_atomic_aggregate_as_unknown() {
        // ATOMIC_AGGREGATE: flags=0x40, type=6, len=0
        let buf = [0x40, 0x06, 0x00];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert!(matches!(attrs[0], PathAttribute::Unknown(_)));
    }

    #[test]
    fn decode_extended_length() {
        // flags=0x50 (transitive+extended), type=2, len=0x000A (10)
        // Same AS_PATH as the 4-byte test
        let buf = [
            0x50, 0x02, 0x00, 0x0A, // header with extended length
            0x02, 0x02, // AS_SEQUENCE, 2 ASNs
            0x00, 0x00, 0xFD, 0xE9, // 65001
            0x00, 0x00, 0xFD, 0xEA, // 65002
        ];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(
            attrs[0],
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001, 65002])]
            })
        );
    }

    #[test]
    fn decode_multiple_attributes() {
        let mut buf = Vec::new();
        // ORIGIN IGP
        buf.extend_from_slice(&[0x40, 0x01, 0x01, 0x00]);
        // NEXT_HOP 10.0.0.1
        buf.extend_from_slice(&[0x40, 0x03, 0x04, 10, 0, 0, 1]);
        // AS_PATH empty
        buf.extend_from_slice(&[0x40, 0x02, 0x00]);

        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs.len(), 3);
        assert_eq!(attrs[0], PathAttribute::Origin(Origin::Igp));
        assert_eq!(attrs[1], PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(attrs[2], PathAttribute::AsPath(AsPath { segments: vec![] }));
    }

    #[test]
    fn roundtrip_attributes_4byte() {
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001, 65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
            PathAttribute::Med(100),
            PathAttribute::LocalPref(200),
        ];

        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false);
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded, attrs);
    }

    #[test]
    fn roundtrip_attributes_2byte() {
        let attrs = vec![
            PathAttribute::Origin(Origin::Egp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![100, 200])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(172, 16, 0, 1)),
        ];

        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, false, false);
        let decoded = decode_path_attributes(&buf, false, &[]).unwrap();
        assert_eq!(decoded, attrs);
    }

    #[test]
    fn reject_truncated_attribute_header() {
        let buf = [0x40]; // only 1 byte
        assert!(decode_path_attributes(&buf, true, &[]).is_err());
    }

    #[test]
    fn reject_truncated_attribute_value() {
        // ORIGIN claims 1 byte value but nothing follows
        let buf = [0x40, 0x01, 0x01];
        assert!(decode_path_attributes(&buf, true, &[]).is_err());
    }

    #[test]
    fn reject_bad_origin_length() {
        // ORIGIN with 2-byte value
        let buf = [0x40, 0x01, 0x02, 0x00, 0x00];
        assert!(decode_path_attributes(&buf, true, &[]).is_err());
    }

    #[test]
    fn as_path_with_set_and_sequence() {
        // AS_SEQUENCE [65001], AS_SET [65002, 65003]
        let attrs = vec![PathAttribute::AsPath(AsPath {
            segments: vec![
                AsPathSegment::AsSequence(vec![65001]),
                AsPathSegment::AsSet(vec![65002, 65003]),
            ],
        })];

        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false);
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded, attrs);
    }

    #[test]
    fn decode_communities_single() {
        // flags=0xC0 (optional+transitive), type=8, len=4, community=65001:100
        // 65001 = 0xFDE9, 100 = 0x0064 → u32 = 0xFDE90064
        let community: u32 = (65001 << 16) | 100;
        let bytes = community.to_be_bytes();
        let buf = [0xC0, 0x08, 0x04, bytes[0], bytes[1], bytes[2], bytes[3]];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0], PathAttribute::Communities(vec![community]));
    }

    #[test]
    fn decode_communities_multiple() {
        let c1: u32 = (65001 << 16) | 100;
        let c2: u32 = (65002 << 16) | 200;
        let b1 = c1.to_be_bytes();
        let b2 = c2.to_be_bytes();
        let buf = [
            0xC0, 0x08, 0x08, b1[0], b1[1], b1[2], b1[3], b2[0], b2[1], b2[2], b2[3],
        ];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs[0], PathAttribute::Communities(vec![c1, c2]));
    }

    #[test]
    fn decode_communities_empty() {
        // flags=0xC0, type=8, len=0
        let buf = [0xC0, 0x08, 0x00];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs[0], PathAttribute::Communities(vec![]));
    }

    #[test]
    fn decode_communities_odd_length_rejected() {
        // flags=0xC0, type=8, len=3, only 3 bytes (not multiple of 4)
        let buf = [0xC0, 0x08, 0x03, 0x01, 0x02, 0x03];
        assert!(decode_path_attributes(&buf, true, &[]).is_err());
    }

    #[test]
    fn communities_roundtrip() {
        let c1: u32 = (65001 << 16) | 100;
        let c2: u32 = (65002 << 16) | 200;
        let attrs = vec![PathAttribute::Communities(vec![c1, c2])];

        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false);
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded, attrs);
    }

    #[test]
    fn communities_type_code_and_flags() {
        let attr = PathAttribute::Communities(vec![]);
        assert_eq!(attr.type_code(), 8);
        assert_eq!(attr.flags(), attr_flags::OPTIONAL | attr_flags::TRANSITIVE);
    }

    // --- Extended Communities (RFC 4360) tests ---

    #[test]
    fn decode_extended_communities_single() {
        // Route Target 65001:100 — type 0x00, subtype 0x02, AS 65001 (2-octet), value 100
        let ec = ExtendedCommunity::new(0x0002_FDE9_0000_0064);
        let bytes = ec.as_u64().to_be_bytes();
        let buf = [
            0xC0, 0x10, 0x08, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
            bytes[7],
        ];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0], PathAttribute::ExtendedCommunities(vec![ec]));
    }

    #[test]
    fn decode_extended_communities_multiple() {
        let ec1 = ExtendedCommunity::new(0x0002_FDE9_0000_0064);
        let ec2 = ExtendedCommunity::new(0x0003_FDEA_0000_00C8);
        let b1 = ec1.as_u64().to_be_bytes();
        let b2 = ec2.as_u64().to_be_bytes();
        let mut buf = vec![0xC0, 0x10, 16]; // flags, type=16, len=16
        buf.extend_from_slice(&b1);
        buf.extend_from_slice(&b2);
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs[0], PathAttribute::ExtendedCommunities(vec![ec1, ec2]));
    }

    #[test]
    fn decode_extended_communities_empty() {
        let buf = [0xC0, 0x10, 0x00];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs[0], PathAttribute::ExtendedCommunities(vec![]));
    }

    #[test]
    fn decode_extended_communities_bad_length() {
        // length 5 is not a multiple of 8
        let buf = [0xC0, 0x10, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(decode_path_attributes(&buf, true, &[]).is_err());
    }

    #[test]
    fn extended_communities_roundtrip() {
        let ec1 = ExtendedCommunity::new(0x0002_FDE9_0000_0064);
        let ec2 = ExtendedCommunity::new(0x0003_FDEA_0000_00C8);
        let attrs = vec![PathAttribute::ExtendedCommunities(vec![ec1, ec2])];

        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false);
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded, attrs);
    }

    #[test]
    fn extended_communities_type_code_and_flags() {
        let attr = PathAttribute::ExtendedCommunities(vec![]);
        assert_eq!(attr.type_code(), 16);
        assert_eq!(attr.flags(), attr_flags::OPTIONAL | attr_flags::TRANSITIVE);
    }

    #[test]
    fn extended_community_type_subtype() {
        // Type 0x00, Sub-type 0x02 (Route Target, 2-octet AS)
        let ec = ExtendedCommunity::new(0x0002_FDE9_0000_0064);
        assert_eq!(ec.type_byte(), 0x00);
        assert_eq!(ec.subtype(), 0x02);
        assert!(ec.is_transitive());
    }

    #[test]
    fn extended_community_route_target() {
        // 2-octet AS RT: type=0x00, subtype=0x02, AS=65001, value=100
        let ec = ExtendedCommunity::new(0x0002_FDE9_0000_0064);
        assert_eq!(ec.route_target(), Some((65001, 100)));
        assert_eq!(ec.route_origin(), None);

        // 4-octet AS RT: type=0x02, subtype=0x02, AS=65537, value=200
        let ec4 = ExtendedCommunity::new(0x0202_0001_0001_00C8);
        assert_eq!(ec4.route_target(), Some((65537, 200)));

        // IPv4-specific RT: type=0x01, subtype=0x02, IP=192.0.2.1, value=100
        // 192.0.2.1 = 0xC0000201
        let ec_ipv4 = ExtendedCommunity::new(0x0102_C000_0201_0064);
        let (g, l) = ec_ipv4.route_target().unwrap();
        assert_eq!(g, 0xC000_0201); // 192.0.2.1 as u32
        assert_eq!(l, 100);
        // Callers distinguish via type_byte()
        assert_eq!(ec_ipv4.type_byte() & 0x3F, 0x01);
    }

    #[test]
    fn extended_community_is_transitive() {
        // Type 0x00 → transitive (bit 6 = 0)
        let t = ExtendedCommunity::new(0x0002_0000_0000_0000);
        assert!(t.is_transitive());

        // Type 0x40 → non-transitive (bit 6 = 1)
        let nt = ExtendedCommunity::new(0x4002_0000_0000_0000);
        assert!(!nt.is_transitive());
    }

    #[test]
    fn extended_community_display() {
        let rt = ExtendedCommunity::new(0x0002_FDE9_0000_0064);
        assert_eq!(rt.to_string(), "RT:65001:100");

        let ro = ExtendedCommunity::new(0x0003_FDE9_0000_0064);
        assert_eq!(ro.to_string(), "RO:65001:100");

        // IPv4-specific RT: type=0x01, subtype=0x02, IP=192.0.2.1, value=100
        let target_v4 = ExtendedCommunity::new(0x0102_C000_0201_0064);
        assert_eq!(target_v4.to_string(), "RT:192.0.2.1:100");

        // IPv4-specific RO
        let origin_v4 = ExtendedCommunity::new(0x0103_C000_0201_0064);
        assert_eq!(origin_v4.to_string(), "RO:192.0.2.1:100");

        // 4-octet AS RT
        let rt_as4 = ExtendedCommunity::new(0x0202_0001_0001_00C8);
        assert_eq!(rt_as4.to_string(), "RT:65537:200");

        // Non-transitive opaque → hex fallback
        let opaque = ExtendedCommunity::new(0x4300_1234_5678_9ABC);
        assert_eq!(opaque.to_string(), "0x4300123456789abc");
    }

    #[test]
    fn unknown_attribute_roundtrip() {
        // Input has flags 0xC0 (optional+transitive). After encoding, the
        // Partial bit is OR'd in for transitive unknowns → 0xE0.
        let attrs = vec![PathAttribute::Unknown(RawAttribute {
            flags: 0xC0,
            type_code: 99,
            data: Bytes::from_static(&[1, 2, 3, 4, 5]),
        })];

        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false);
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(
            decoded,
            vec![PathAttribute::Unknown(RawAttribute {
                flags: 0xE0, // Partial bit set on re-advertisement
                type_code: 99,
                data: Bytes::from_static(&[1, 2, 3, 4, 5]),
            })]
        );
    }

    #[test]
    fn origin_with_optional_flag_rejected() {
        // ORIGIN with flags 0xC0 (Optional+Transitive) — should be 0x40 (Transitive only)
        let buf = [0xC0, 0x01, 0x01, 0x00];
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        match &err {
            DecodeError::UpdateAttributeError { subcode, .. } => {
                assert_eq!(*subcode, update_subcode::ATTRIBUTE_FLAGS_ERROR);
            }
            other => panic!("expected UpdateAttributeError, got: {other:?}"),
        }
    }

    #[test]
    fn med_with_transitive_flag_rejected() {
        // MED with flags 0xC0 (Optional+Transitive) — should be 0x80 (Optional only)
        let buf = [0xC0, 0x04, 0x04, 0, 0, 0, 100];
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        match &err {
            DecodeError::UpdateAttributeError { subcode, .. } => {
                assert_eq!(*subcode, update_subcode::ATTRIBUTE_FLAGS_ERROR);
            }
            other => panic!("expected UpdateAttributeError, got: {other:?}"),
        }
    }

    #[test]
    fn communities_without_optional_rejected() {
        // COMMUNITIES with flags 0x40 (Transitive only) — should be 0xC0 (Optional+Transitive)
        let buf = [0x40, 0x08, 0x04, 0, 0, 0, 100];
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        match &err {
            DecodeError::UpdateAttributeError { subcode, .. } => {
                assert_eq!(*subcode, update_subcode::ATTRIBUTE_FLAGS_ERROR);
            }
            other => panic!("expected UpdateAttributeError, got: {other:?}"),
        }
    }

    #[test]
    fn next_hop_length_error_subcode() {
        // NEXT_HOP with 3 bytes instead of 4
        let buf = [0x40, 0x03, 0x03, 10, 0, 0];
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        match &err {
            DecodeError::UpdateAttributeError { subcode, .. } => {
                assert_eq!(*subcode, update_subcode::ATTRIBUTE_LENGTH_ERROR);
            }
            other => panic!("expected UpdateAttributeError, got: {other:?}"),
        }
    }

    #[test]
    fn invalid_origin_value_subcode() {
        // ORIGIN with value 5 → subcode 6 (INVALID_ORIGIN)
        let buf = [0x40, 0x01, 0x01, 0x05];
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        match &err {
            DecodeError::UpdateAttributeError { subcode, .. } => {
                assert_eq!(*subcode, update_subcode::INVALID_ORIGIN);
            }
            other => panic!("expected UpdateAttributeError, got: {other:?}"),
        }
    }

    #[test]
    fn as_path_bad_segment_subcode() {
        // AS_PATH with unknown segment type 5
        let buf = [
            0x40, 0x02, 0x06, // AS_PATH header, length 6
            0x05, 0x01, // unknown segment type 5, count 1
            0x00, 0x00, 0xFD, 0xE9, // ASN 65001
        ];
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        match &err {
            DecodeError::UpdateAttributeError { subcode, .. } => {
                assert_eq!(*subcode, update_subcode::MALFORMED_AS_PATH);
            }
            other => panic!("expected UpdateAttributeError, got: {other:?}"),
        }
    }

    #[test]
    fn encode_unknown_transitive_sets_partial() {
        let attr = PathAttribute::Unknown(RawAttribute {
            flags: attr_flags::OPTIONAL | attr_flags::TRANSITIVE, // 0xC0
            type_code: 99,
            data: Bytes::from_static(&[1, 2]),
        });
        let mut buf = Vec::new();
        encode_path_attributes(&[attr], &mut buf, true, false);
        // First byte is flags — should have PARTIAL bit set
        assert_eq!(
            buf[0],
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE | attr_flags::PARTIAL
        );
    }

    #[test]
    fn encode_unknown_wellknown_transitive_no_partial() {
        // Well-known transitive (OPTIONAL=0, TRANSITIVE=1) should NOT get PARTIAL
        let attr = PathAttribute::Unknown(RawAttribute {
            flags: attr_flags::TRANSITIVE, // 0x40, well-known transitive
            type_code: 99,
            data: Bytes::from_static(&[1, 2]),
        });
        let mut buf = Vec::new();
        encode_path_attributes(&[attr], &mut buf, true, false);
        assert_eq!(buf[0], attr_flags::TRANSITIVE);
    }

    #[test]
    fn encode_unknown_nontransitive_no_partial() {
        let attr = PathAttribute::Unknown(RawAttribute {
            flags: attr_flags::OPTIONAL, // 0x80, no Transitive
            type_code: 99,
            data: Bytes::from_static(&[1, 2]),
        });
        let mut buf = Vec::new();
        encode_path_attributes(&[attr], &mut buf, true, false);
        // First byte is flags — should NOT have PARTIAL bit
        assert_eq!(buf[0], attr_flags::OPTIONAL);
    }

    // --- MP_REACH_NLRI / MP_UNREACH_NLRI tests ---

    /// Helper to create a `NlriEntry` with `path_id=0`.
    fn nlri(prefix: Prefix) -> NlriEntry {
        NlriEntry { path_id: 0, prefix }
    }

    #[test]
    fn mp_reach_nlri_ipv6_roundtrip() {
        use crate::capability::{Afi, Safi};
        use crate::nlri::{Ipv6Prefix, Prefix};

        let mp = MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
            announced: vec![
                nlri(Prefix::V6(Ipv6Prefix::new(
                    "2001:db8:1::".parse().unwrap(),
                    48,
                ))),
                nlri(Prefix::V6(Ipv6Prefix::new(
                    "2001:db8:2::".parse().unwrap(),
                    48,
                ))),
            ],
            flowspec_announced: vec![],
        };
        let attrs = vec![PathAttribute::MpReachNlri(mp.clone())];

        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false);
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], PathAttribute::MpReachNlri(mp));
    }

    #[test]
    fn mp_unreach_nlri_ipv6_roundtrip() {
        use crate::capability::{Afi, Safi};
        use crate::nlri::{Ipv6Prefix, Prefix};

        let mp = MpUnreachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            withdrawn: vec![nlri(Prefix::V6(Ipv6Prefix::new(
                "2001:db8:1::".parse().unwrap(),
                48,
            )))],
            flowspec_withdrawn: vec![],
        };
        let attrs = vec![PathAttribute::MpUnreachNlri(mp.clone())];

        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false);
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], PathAttribute::MpUnreachNlri(mp));
    }

    #[test]
    fn mp_reach_nlri_ipv4_roundtrip() {
        use crate::capability::{Afi, Safi};
        use crate::nlri::Prefix;

        let mp = MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            announced: vec![nlri(Prefix::V4(crate::nlri::Ipv4Prefix::new(
                Ipv4Addr::new(10, 1, 0, 0),
                16,
            )))],
            flowspec_announced: vec![],
        };
        let attrs = vec![PathAttribute::MpReachNlri(mp.clone())];

        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false);
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded[0], PathAttribute::MpReachNlri(mp));
    }

    #[test]
    fn mp_reach_nlri_type_code_and_flags() {
        use crate::capability::{Afi, Safi};

        let attr = PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            next_hop: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            announced: vec![],
            flowspec_announced: vec![],
        });
        assert_eq!(attr.type_code(), 14);
        // RFC 4760 §3: MP_REACH_NLRI is optional non-transitive
        assert_eq!(attr.flags(), attr_flags::OPTIONAL);
    }

    #[test]
    fn mp_unreach_nlri_type_code_and_flags() {
        use crate::capability::{Afi, Safi};

        let attr = PathAttribute::MpUnreachNlri(MpUnreachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            withdrawn: vec![],
            flowspec_withdrawn: vec![],
        });
        assert_eq!(attr.type_code(), 15);
        assert_eq!(attr.flags(), attr_flags::OPTIONAL);
    }

    #[test]
    fn mp_reach_nlri_empty_nlri() {
        use crate::capability::{Afi, Safi};

        let mp = MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            next_hop: IpAddr::V6("fe80::1".parse().unwrap()),
            announced: vec![],
            flowspec_announced: vec![],
        };
        let attrs = vec![PathAttribute::MpReachNlri(mp.clone())];

        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false);
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded[0], PathAttribute::MpReachNlri(mp));
    }

    #[test]
    fn mp_reach_nlri_bad_flags_rejected() {
        // MP_REACH_NLRI (type 14) with flags 0x40 (Transitive only)
        // — should be 0xC0 (Optional+Transitive)
        // Build minimal valid value: AFI=2, SAFI=1, NH-Len=16, NH=::1, Reserved=0
        let mut value = Vec::new();
        value.extend_from_slice(&2u16.to_be_bytes()); // AFI IPv6
        value.push(1); // SAFI Unicast
        value.push(16); // NH-Len
        value.extend_from_slice(&"::1".parse::<Ipv6Addr>().unwrap().octets()); // NH
        value.push(0); // Reserved

        let mut buf = Vec::new();
        buf.push(0x40); // flags: Transitive only (wrong)
        buf.push(14); // type: MP_REACH_NLRI
        #[expect(clippy::cast_possible_truncation)]
        buf.push(value.len() as u8);
        buf.extend_from_slice(&value);

        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UpdateAttributeError {
                subcode: 4, // ATTRIBUTE_FLAGS_ERROR
                ..
            }
        ));
    }

    // --- MP Add-Path decode tests ---

    #[test]
    #[expect(clippy::cast_possible_truncation)]
    fn mp_reach_nlri_ipv4_addpath_decode() {
        use crate::capability::{Afi, Safi};
        use crate::nlri::Prefix;

        // Build MP_REACH_NLRI with Add-Path-encoded IPv4 NLRI:
        // path_id(4) + prefix_len(1) + prefix_bytes
        let mut value = Vec::new();
        value.extend_from_slice(&1u16.to_be_bytes()); // AFI IPv4
        value.push(1); // SAFI Unicast
        value.push(4); // NH-Len
        value.extend_from_slice(&[10, 0, 0, 1]); // Next Hop
        value.push(0); // Reserved
        // Add-Path NLRI: path_id=42, 10.1.0.0/16
        value.extend_from_slice(&42u32.to_be_bytes());
        value.push(16);
        value.extend_from_slice(&[10, 1]);

        let mut buf = Vec::new();
        buf.push(0x90); // flags: Optional + Extended Length
        buf.push(14); // type: MP_REACH_NLRI
        buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
        buf.extend_from_slice(&value);

        // With Add-Path for IPv4 unicast → decode path_id
        let decoded = decode_path_attributes(&buf, true, &[(Afi::Ipv4, Safi::Unicast)]).unwrap();
        let PathAttribute::MpReachNlri(mp) = &decoded[0] else {
            panic!("expected MpReachNlri");
        };
        assert_eq!(mp.announced.len(), 1);
        assert_eq!(mp.announced[0].path_id, 42);
        assert!(matches!(mp.announced[0].prefix, Prefix::V4(p) if p.len == 16));

        // Without Add-Path → plain decoder misinterprets the path_id bytes
        // as prefix encoding and rejects the garbled data.
        assert!(decode_path_attributes(&buf, true, &[]).is_err());
    }

    #[test]
    #[expect(clippy::cast_possible_truncation)]
    fn mp_reach_nlri_ipv6_addpath_decode() {
        use crate::capability::{Afi, Safi};
        use crate::nlri::{Ipv6Prefix, Prefix};

        // Build MP_REACH_NLRI with Add-Path-encoded IPv6 NLRI
        let mut value = Vec::new();
        value.extend_from_slice(&2u16.to_be_bytes()); // AFI IPv6
        value.push(1); // SAFI Unicast
        value.push(16); // NH-Len
        value.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        value.push(0); // Reserved
        // Add-Path NLRI: path_id=99, 2001:db8:1::/48
        value.extend_from_slice(&99u32.to_be_bytes());
        value.push(48);
        value.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]);

        let mut buf = Vec::new();
        buf.push(0x90); // flags: Optional + Extended Length
        buf.push(14); // type: MP_REACH_NLRI
        buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
        buf.extend_from_slice(&value);

        let decoded = decode_path_attributes(&buf, true, &[(Afi::Ipv6, Safi::Unicast)]).unwrap();
        let PathAttribute::MpReachNlri(mp) = &decoded[0] else {
            panic!("expected MpReachNlri");
        };
        assert_eq!(mp.announced.len(), 1);
        assert_eq!(mp.announced[0].path_id, 99);
        assert_eq!(
            mp.announced[0].prefix,
            Prefix::V6(Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 48))
        );
    }

    #[test]
    #[expect(clippy::cast_possible_truncation)]
    fn mp_unreach_nlri_ipv6_addpath_decode() {
        use crate::capability::{Afi, Safi};
        use crate::nlri::{Ipv6Prefix, Prefix};

        // Build MP_UNREACH_NLRI with Add-Path-encoded IPv6 NLRI
        let mut value = Vec::new();
        value.extend_from_slice(&2u16.to_be_bytes()); // AFI IPv6
        value.push(1); // SAFI Unicast
        // Add-Path NLRI: path_id=7, 2001:db8:2::/48
        value.extend_from_slice(&7u32.to_be_bytes());
        value.push(48);
        value.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02]);

        let mut buf = Vec::new();
        buf.push(0x90); // flags: Optional + Extended Length
        buf.push(15); // type: MP_UNREACH_NLRI
        buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
        buf.extend_from_slice(&value);

        let decoded = decode_path_attributes(&buf, true, &[(Afi::Ipv6, Safi::Unicast)]).unwrap();
        let PathAttribute::MpUnreachNlri(mp) = &decoded[0] else {
            panic!("expected MpUnreachNlri");
        };
        assert_eq!(mp.withdrawn.len(), 1);
        assert_eq!(mp.withdrawn[0].path_id, 7);
        assert_eq!(
            mp.withdrawn[0].prefix,
            Prefix::V6(Ipv6Prefix::new("2001:db8:2::".parse().unwrap(), 48))
        );
    }

    #[test]
    fn mp_reach_addpath_only_applies_to_matching_family() {
        use crate::capability::{Afi, Safi};
        use crate::nlri::{Ipv6Prefix, Prefix};

        // Build plain (non-Add-Path) MP_REACH_NLRI for IPv6
        let mp = MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
            announced: vec![NlriEntry {
                path_id: 0,
                prefix: Prefix::V6(Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 48)),
            }],
            flowspec_announced: vec![],
        };
        let attrs = vec![PathAttribute::MpReachNlri(mp.clone())];

        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false);

        // Add-Path enabled for IPv4 only — IPv6 should still decode as plain
        let decoded = decode_path_attributes(&buf, true, &[(Afi::Ipv4, Safi::Unicast)]).unwrap();
        assert_eq!(decoded[0], PathAttribute::MpReachNlri(mp));
    }

    // --- ORIGINATOR_ID tests ---

    #[test]
    fn decode_originator_id() {
        // flags=0x80 (optional), type=9, len=4, value=1.2.3.4
        let buf = [0x80, 0x09, 0x04, 1, 2, 3, 4];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(
            attrs[0],
            PathAttribute::OriginatorId(Ipv4Addr::new(1, 2, 3, 4))
        );
    }

    #[test]
    fn originator_id_roundtrip() {
        let attr = PathAttribute::OriginatorId(Ipv4Addr::new(10, 0, 0, 1));
        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false);
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded, vec![attr]);
    }

    #[test]
    fn originator_id_wrong_length() {
        // 3 bytes instead of 4
        let buf = [0x80, 0x09, 0x03, 1, 2, 3];
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UpdateAttributeError {
                subcode: 5, // ATTRIBUTE_LENGTH_ERROR
                ..
            }
        ));
    }

    #[test]
    fn originator_id_wrong_flags() {
        // flags=0x40 (transitive) — should be 0x80 (optional)
        let buf = [0x40, 0x09, 0x04, 1, 2, 3, 4];
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UpdateAttributeError {
                subcode: 4, // ATTRIBUTE_FLAGS_ERROR
                ..
            }
        ));
    }

    // --- CLUSTER_LIST tests ---

    #[test]
    fn decode_cluster_list() {
        // flags=0x80 (optional), type=10, len=8, two cluster IDs
        let buf = [0x80, 0x0A, 0x08, 1, 2, 3, 4, 5, 6, 7, 8];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(
            attrs[0],
            PathAttribute::ClusterList(vec![Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8),])
        );
    }

    #[test]
    fn cluster_list_roundtrip() {
        let attr = PathAttribute::ClusterList(vec![
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
        ]);
        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false);
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded, vec![attr]);
    }

    #[test]
    fn cluster_list_wrong_length() {
        // 5 bytes — not a multiple of 4
        let buf = [0x80, 0x0A, 0x05, 1, 2, 3, 4, 5];
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UpdateAttributeError {
                subcode: 5, // ATTRIBUTE_LENGTH_ERROR
                ..
            }
        ));
    }

    // -----------------------------------------------------------------------
    // Large Communities (RFC 8092)
    // -----------------------------------------------------------------------

    #[test]
    fn large_community_display() {
        let lc = LargeCommunity::new(65001, 100, 200);
        assert_eq!(lc.to_string(), "65001:100:200");
    }

    #[test]
    fn large_community_type_code_and_flags() {
        let attr = PathAttribute::LargeCommunities(vec![LargeCommunity::new(1, 2, 3)]);
        assert_eq!(attr.type_code(), attr_type::LARGE_COMMUNITIES);
        assert_eq!(attr.flags(), attr_flags::OPTIONAL | attr_flags::TRANSITIVE);
    }

    #[test]
    fn decode_large_community_single() {
        // flags=0xC0 (Optional|Transitive), type=32, length=12
        let mut buf = vec![0xC0, 32, 12];
        buf.extend_from_slice(&65001u32.to_be_bytes());
        buf.extend_from_slice(&100u32.to_be_bytes());
        buf.extend_from_slice(&200u32.to_be_bytes());
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(
            attrs[0],
            PathAttribute::LargeCommunities(vec![LargeCommunity::new(65001, 100, 200)])
        );
    }

    #[test]
    fn decode_large_community_multiple() {
        // Two LCs: 24 bytes total
        let mut buf = vec![0xC0, 32, 24];
        for (g, l1, l2) in [(65001u32, 100u32, 200u32), (65002, 300, 400)] {
            buf.extend_from_slice(&g.to_be_bytes());
            buf.extend_from_slice(&l1.to_be_bytes());
            buf.extend_from_slice(&l2.to_be_bytes());
        }
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(
            attrs[0],
            PathAttribute::LargeCommunities(vec![
                LargeCommunity::new(65001, 100, 200),
                LargeCommunity::new(65002, 300, 400),
            ])
        );
    }

    #[test]
    fn decode_large_community_bad_length() {
        // 10 bytes — not a multiple of 12
        let buf = [0xC0, 32, 10, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0];
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UpdateAttributeError {
                subcode: 5, // ATTRIBUTE_LENGTH_ERROR
                ..
            }
        ));
    }

    #[test]
    fn decode_large_community_empty_rejected() {
        // Zero-length LARGE_COMMUNITIES is rejected (must carry at least one community).
        let buf = [0xC0, 32, 0];
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UpdateAttributeError {
                subcode: 5, // ATTRIBUTE_LENGTH_ERROR
                ..
            }
        ));
    }

    #[test]
    fn large_community_roundtrip() {
        let lcs = vec![
            LargeCommunity::new(65001, 100, 200),
            LargeCommunity::new(0, u32::MAX, 42),
        ];
        let attr = PathAttribute::LargeCommunities(lcs.clone());
        let mut buf = Vec::new();
        encode_path_attributes(&[attr], &mut buf, true, false);
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], PathAttribute::LargeCommunities(lcs));
    }

    #[test]
    fn large_community_expected_flags_validated() {
        // Wrong flags: TRANSITIVE only (0x40) instead of OPTIONAL|TRANSITIVE (0xC0)
        let mut buf = vec![0x40, 32, 12];
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&2u32.to_be_bytes());
        buf.extend_from_slice(&3u32.to_be_bytes());
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UpdateAttributeError {
                subcode: 4, // ATTRIBUTE_FLAGS_ERROR
                ..
            }
        ));
    }

    // -----------------------------------------------------------------------
    // AsPath::to_aspath_string()
    // -----------------------------------------------------------------------

    #[test]
    fn aspath_string_sequence() {
        let p = AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65001, 65002, 65003])],
        };
        assert_eq!(p.to_aspath_string(), "65001 65002 65003");
    }

    #[test]
    fn aspath_string_set() {
        let p = AsPath {
            segments: vec![AsPathSegment::AsSet(vec![65003, 65004])],
        };
        assert_eq!(p.to_aspath_string(), "{65003 65004}");
    }

    #[test]
    fn aspath_string_mixed() {
        let p = AsPath {
            segments: vec![
                AsPathSegment::AsSequence(vec![65001, 65002]),
                AsPathSegment::AsSet(vec![65003, 65004]),
            ],
        };
        assert_eq!(p.to_aspath_string(), "65001 65002 {65003 65004}");
    }

    #[test]
    fn aspath_string_empty() {
        let p = AsPath { segments: vec![] };
        assert_eq!(p.to_aspath_string(), "");
    }
}
