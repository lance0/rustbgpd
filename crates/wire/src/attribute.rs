use std::net::Ipv4Addr;

use bytes::Bytes;

use crate::constants::{as_path_segment, attr_flags, attr_type};
use crate::error::DecodeError;

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
            Self::Med(_) => attr_flags::OPTIONAL,
            Self::Communities(_) => attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
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

        let attr = decode_attribute_value(flags, type_code, value, four_octet_as)?;
        attrs.push(attr);
    }

    Ok(attrs)
}

/// Decode a single attribute value given its flags, type code, and raw bytes.
fn decode_attribute_value(
    flags: u8,
    type_code: u8,
    value: &[u8],
    four_octet_as: bool,
) -> Result<PathAttribute, DecodeError> {
    match type_code {
        attr_type::ORIGIN => {
            if value.len() != 1 {
                return Err(DecodeError::MalformedField {
                    message_type: "UPDATE",
                    detail: format!("ORIGIN length {} (expected 1)", value.len()),
                });
            }
            match Origin::from_u8(value[0]) {
                Some(origin) => Ok(PathAttribute::Origin(origin)),
                None => Err(DecodeError::MalformedField {
                    message_type: "UPDATE",
                    detail: format!("invalid ORIGIN value {}", value[0]),
                }),
            }
        }

        attr_type::AS_PATH => {
            let segments = decode_as_path(value, four_octet_as)?;
            Ok(PathAttribute::AsPath(AsPath { segments }))
        }

        attr_type::NEXT_HOP => {
            if value.len() != 4 {
                return Err(DecodeError::MalformedField {
                    message_type: "UPDATE",
                    detail: format!("NEXT_HOP length {} (expected 4)", value.len()),
                });
            }
            let addr = Ipv4Addr::new(value[0], value[1], value[2], value[3]);
            Ok(PathAttribute::NextHop(addr))
        }

        attr_type::MULTI_EXIT_DISC => {
            if value.len() != 4 {
                return Err(DecodeError::MalformedField {
                    message_type: "UPDATE",
                    detail: format!("MED length {} (expected 4)", value.len()),
                });
            }
            let med = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
            Ok(PathAttribute::Med(med))
        }

        attr_type::LOCAL_PREF => {
            if value.len() != 4 {
                return Err(DecodeError::MalformedField {
                    message_type: "UPDATE",
                    detail: format!("LOCAL_PREF length {} (expected 4)", value.len()),
                });
            }
            let lp = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
            Ok(PathAttribute::LocalPref(lp))
        }

        attr_type::COMMUNITIES => {
            if !value.len().is_multiple_of(4) {
                return Err(DecodeError::MalformedField {
                    message_type: "UPDATE",
                    detail: format!("COMMUNITIES length {} not a multiple of 4", value.len()),
                });
            }
            let communities = value
                .chunks_exact(4)
                .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                .collect();
            Ok(PathAttribute::Communities(communities))
        }

        // ATOMIC_AGGREGATE, AGGREGATOR, and any unknown type → RawAttribute
        _ => Ok(PathAttribute::Unknown(RawAttribute {
            flags,
            type_code,
            data: Bytes::copy_from_slice(value),
        })),
    }
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

/// Encode path attributes to wire bytes.
///
/// `four_octet_as` controls whether AS numbers in `AS_PATH` are 2 or 4 bytes.
pub fn encode_path_attributes(attrs: &[PathAttribute], buf: &mut Vec<u8>, four_octet_as: bool) {
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
            PathAttribute::Unknown(raw) => {
                flags = raw.flags;
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
    fn decode_origin_igp() {
        // flags=0x40 (transitive), type=1, len=1, value=0 (IGP)
        let buf = [0x40, 0x01, 0x01, 0x00];
        let attrs = decode_path_attributes(&buf, true).unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0], PathAttribute::Origin(Origin::Igp));
    }

    #[test]
    fn decode_origin_egp() {
        let buf = [0x40, 0x01, 0x01, 0x01];
        let attrs = decode_path_attributes(&buf, true).unwrap();
        assert_eq!(attrs[0], PathAttribute::Origin(Origin::Egp));
    }

    #[test]
    fn decode_origin_invalid_value() {
        // ORIGIN with value 5 — not a valid Origin (only 0-2 are defined)
        let buf = [0x40, 0x01, 0x01, 0x05];
        let err = decode_path_attributes(&buf, true).unwrap_err();
        assert!(
            matches!(err, DecodeError::MalformedField { .. }),
            "expected MalformedField, got: {err:?}"
        );
    }

    #[test]
    fn decode_next_hop() {
        // flags=0x40, type=3, len=4, value=10.0.0.1
        let buf = [0x40, 0x03, 0x04, 10, 0, 0, 1];
        let attrs = decode_path_attributes(&buf, true).unwrap();
        assert_eq!(attrs[0], PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn decode_med() {
        // flags=0x80 (optional), type=4, len=4, value=100
        let buf = [0x80, 0x04, 0x04, 0, 0, 0, 100];
        let attrs = decode_path_attributes(&buf, true).unwrap();
        assert_eq!(attrs[0], PathAttribute::Med(100));
    }

    #[test]
    fn decode_local_pref() {
        // flags=0x40, type=5, len=4, value=200
        let buf = [0x40, 0x05, 0x04, 0, 0, 0, 200];
        let attrs = decode_path_attributes(&buf, true).unwrap();
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
        let attrs = decode_path_attributes(&buf, true).unwrap();
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
        let attrs = decode_path_attributes(&buf, false).unwrap();
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
        let attrs = decode_path_attributes(&buf, true).unwrap();
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
        let attrs = decode_path_attributes(&buf, true).unwrap();
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
        let attrs = decode_path_attributes(&buf, true).unwrap();
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

        let attrs = decode_path_attributes(&buf, true).unwrap();
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
        encode_path_attributes(&attrs, &mut buf, true);
        let decoded = decode_path_attributes(&buf, true).unwrap();
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
        encode_path_attributes(&attrs, &mut buf, false);
        let decoded = decode_path_attributes(&buf, false).unwrap();
        assert_eq!(decoded, attrs);
    }

    #[test]
    fn reject_truncated_attribute_header() {
        let buf = [0x40]; // only 1 byte
        assert!(decode_path_attributes(&buf, true).is_err());
    }

    #[test]
    fn reject_truncated_attribute_value() {
        // ORIGIN claims 1 byte value but nothing follows
        let buf = [0x40, 0x01, 0x01];
        assert!(decode_path_attributes(&buf, true).is_err());
    }

    #[test]
    fn reject_bad_origin_length() {
        // ORIGIN with 2-byte value
        let buf = [0x40, 0x01, 0x02, 0x00, 0x00];
        assert!(decode_path_attributes(&buf, true).is_err());
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
        encode_path_attributes(&attrs, &mut buf, true);
        let decoded = decode_path_attributes(&buf, true).unwrap();
        assert_eq!(decoded, attrs);
    }

    #[test]
    fn decode_communities_single() {
        // flags=0xC0 (optional+transitive), type=8, len=4, community=65001:100
        // 65001 = 0xFDE9, 100 = 0x0064 → u32 = 0xFDE90064
        let community: u32 = (65001 << 16) | 100;
        let bytes = community.to_be_bytes();
        let buf = [0xC0, 0x08, 0x04, bytes[0], bytes[1], bytes[2], bytes[3]];
        let attrs = decode_path_attributes(&buf, true).unwrap();
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
        let attrs = decode_path_attributes(&buf, true).unwrap();
        assert_eq!(attrs[0], PathAttribute::Communities(vec![c1, c2]));
    }

    #[test]
    fn decode_communities_empty() {
        // flags=0xC0, type=8, len=0
        let buf = [0xC0, 0x08, 0x00];
        let attrs = decode_path_attributes(&buf, true).unwrap();
        assert_eq!(attrs[0], PathAttribute::Communities(vec![]));
    }

    #[test]
    fn decode_communities_odd_length_rejected() {
        // flags=0xC0, type=8, len=3, only 3 bytes (not multiple of 4)
        let buf = [0xC0, 0x08, 0x03, 0x01, 0x02, 0x03];
        assert!(decode_path_attributes(&buf, true).is_err());
    }

    #[test]
    fn communities_roundtrip() {
        let c1: u32 = (65001 << 16) | 100;
        let c2: u32 = (65002 << 16) | 200;
        let attrs = vec![PathAttribute::Communities(vec![c1, c2])];

        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true);
        let decoded = decode_path_attributes(&buf, true).unwrap();
        assert_eq!(decoded, attrs);
    }

    #[test]
    fn communities_type_code_and_flags() {
        let attr = PathAttribute::Communities(vec![]);
        assert_eq!(attr.type_code(), 8);
        assert_eq!(attr.flags(), attr_flags::OPTIONAL | attr_flags::TRANSITIVE);
    }

    #[test]
    fn unknown_attribute_roundtrip() {
        let attrs = vec![PathAttribute::Unknown(RawAttribute {
            flags: 0xC0,
            type_code: 99,
            data: Bytes::from_static(&[1, 2, 3, 4, 5]),
        })];

        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true);
        let decoded = decode_path_attributes(&buf, true).unwrap();
        assert_eq!(decoded, attrs);
    }
}
