use std::net::Ipv4Addr;

use bytes::{Buf, BufMut, BytesMut};

use crate::capability::{Capability, decode_optional_parameters, encode_optional_parameters};
use crate::constants::{BGP_VERSION, HEADER_LEN, MAX_MESSAGE_LEN};
use crate::error::{DecodeError, EncodeError};
use crate::header::{BgpHeader, MessageType};

/// A decoded BGP OPEN message (RFC 4271 §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenMessage {
    /// BGP version (must be 4).
    pub version: u8,
    /// 2-byte AS from the OPEN wire format. May be `AS_TRANS` (23456)
    /// if the speaker's ASN > 65535 — the true ASN is in the
    /// `FourOctetAs` capability.
    pub my_as: u16,
    /// Proposed hold time in seconds (0 = no keepalives, or >= 3).
    pub hold_time: u16,
    /// BGP Identifier (router ID).
    pub bgp_identifier: Ipv4Addr,
    /// Capabilities from optional parameters.
    pub capabilities: Vec<Capability>,
}

impl OpenMessage {
    /// Decode an OPEN message body from a buffer.
    /// The header must already be consumed; `body_len` is
    /// `header.length - HEADER_LEN`.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] if the body is too short, the version is
    /// unsupported, or optional parameters are malformed.
    pub fn decode(buf: &mut impl Buf, body_len: usize) -> Result<Self, DecodeError> {
        // OPEN body: version(1) + AS(2) + hold(2) + id(4) + opt_len(1) = 10 minimum
        if body_len < 10 {
            return Err(DecodeError::MalformedField {
                message_type: "OPEN",
                detail: format!("body too short: {body_len} bytes (need at least 10)"),
            });
        }

        if buf.remaining() < body_len {
            return Err(DecodeError::Incomplete {
                needed: body_len,
                available: buf.remaining(),
            });
        }

        let version = buf.get_u8();
        if version != BGP_VERSION {
            return Err(DecodeError::UnsupportedVersion { version });
        }

        let my_as = buf.get_u16();
        let hold_time = buf.get_u16();
        let bgp_identifier = Ipv4Addr::from(buf.get_u32());
        let opt_params_len = buf.get_u8();

        // Validate opt_params_len fits within the remaining body
        let expected_body = 10 + usize::from(opt_params_len);
        if expected_body != body_len {
            return Err(DecodeError::MalformedField {
                message_type: "OPEN",
                detail: format!(
                    "optional parameters length {opt_params_len} inconsistent \
                     with body length {body_len} (expected {expected_body})"
                ),
            });
        }

        let capabilities = decode_optional_parameters(buf, opt_params_len)?;

        Ok(Self {
            version,
            my_as,
            hold_time,
            bgp_identifier,
            capabilities,
        })
    }

    /// Encode a complete OPEN message (header + body) into a buffer.
    ///
    /// # Errors
    ///
    /// Returns an [`EncodeError`] if the optional parameters exceed 255 bytes
    /// or the total message exceeds the maximum BGP message size.
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
        // Calculate optional parameters size
        let mut opt_params = BytesMut::new();
        encode_optional_parameters(&self.capabilities, &mut opt_params)?;
        let opt_params_len = opt_params.len();

        if opt_params_len > 255 {
            return Err(EncodeError::ValueOutOfRange {
                field: "optional_parameters_length",
                value: opt_params_len.to_string(),
            });
        }

        let total_len = HEADER_LEN + 10 + opt_params_len;
        if total_len > usize::from(MAX_MESSAGE_LEN) {
            return Err(EncodeError::MessageTooLong { size: total_len });
        }

        // Header
        let header = BgpHeader {
            #[expect(clippy::cast_possible_truncation)]
            length: total_len as u16,
            message_type: MessageType::Open,
        };
        header.encode(buf);

        // Body
        buf.put_u8(self.version);
        buf.put_u16(self.my_as);
        buf.put_u16(self.hold_time);
        buf.put_u32(u32::from(self.bgp_identifier));
        #[expect(clippy::cast_possible_truncation)]
        buf.put_u8(opt_params_len as u8);
        buf.put_slice(&opt_params);

        Ok(())
    }

    /// Total encoded size in bytes.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let cap_size: usize = self.capabilities.iter().map(Capability::encoded_len).sum();
        // opt params wrapper: type(1) + len(1) per parameter block
        let opt_params_overhead = if self.capabilities.is_empty() { 0 } else { 2 };
        HEADER_LEN + 10 + opt_params_overhead + cap_size
    }

    /// Extract the 4-byte ASN from capabilities, if advertised.
    /// Falls back to `my_as` (2-byte) if no `FourOctetAs` capability.
    #[must_use]
    pub fn four_byte_as(&self) -> u32 {
        for cap in &self.capabilities {
            if let Capability::FourOctetAs { asn } = cap {
                return *asn;
            }
        }
        u32::from(self.my_as)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::Afi;
    use crate::capability::Safi;
    use crate::constants::MAX_MESSAGE_LEN;

    fn minimal_open() -> OpenMessage {
        OpenMessage {
            version: BGP_VERSION,
            my_as: 65001,
            hold_time: 90,
            bgp_identifier: Ipv4Addr::new(10, 0, 0, 1),
            capabilities: vec![],
        }
    }

    #[test]
    fn encode_decode_minimal_open() {
        let original = minimal_open();
        let mut encoded = BytesMut::with_capacity(64);
        original.encode(&mut encoded).unwrap();

        let mut bytes = encoded.freeze();
        let header = BgpHeader::decode(&mut bytes, MAX_MESSAGE_LEN).unwrap();
        assert_eq!(header.message_type, MessageType::Open);
        assert_eq!(header.length, 29); // 19 + 10, no caps

        let body_len = usize::from(header.length) - HEADER_LEN;
        let decoded = OpenMessage::decode(&mut bytes, body_len).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn encode_decode_with_capabilities() {
        let original = OpenMessage {
            version: BGP_VERSION,
            my_as: 23456, // AS_TRANS
            hold_time: 90,
            bgp_identifier: Ipv4Addr::new(10, 0, 0, 1),
            capabilities: vec![
                Capability::MultiProtocol {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                },
                Capability::FourOctetAs { asn: 4_200_000_001 },
            ],
        };

        let mut encoded = BytesMut::with_capacity(128);
        original.encode(&mut encoded).unwrap();

        let mut bytes = encoded.freeze();
        let header = BgpHeader::decode(&mut bytes, MAX_MESSAGE_LEN).unwrap();
        let body_len = usize::from(header.length) - HEADER_LEN;
        let decoded = OpenMessage::decode(&mut bytes, body_len).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn four_byte_as_extraction() {
        let open = OpenMessage {
            version: BGP_VERSION,
            my_as: 23456,
            hold_time: 90,
            bgp_identifier: Ipv4Addr::new(10, 0, 0, 1),
            capabilities: vec![Capability::FourOctetAs { asn: 4_200_000_001 }],
        };
        assert_eq!(open.four_byte_as(), 4_200_000_001);
    }

    #[test]
    fn four_byte_as_fallback_to_my_as() {
        let open = minimal_open();
        assert_eq!(open.four_byte_as(), 65001);
    }

    #[test]
    fn reject_bad_version() {
        let body: &[u8] = &[
            3, // version 3 (bad)
            0xFD, 0xE9, // AS 65001
            0, 90, // hold time
            10, 0, 0, 1, // router ID
            0, // opt params len
        ];
        let mut buf = bytes::Bytes::copy_from_slice(body);
        assert!(matches!(
            OpenMessage::decode(&mut buf, 10),
            Err(DecodeError::UnsupportedVersion { version: 3 })
        ));
    }

    #[test]
    fn reject_body_too_short() {
        let body: &[u8] = &[4, 0, 1]; // only 3 bytes
        let mut buf = bytes::Bytes::copy_from_slice(body);
        assert!(matches!(
            OpenMessage::decode(&mut buf, 3),
            Err(DecodeError::MalformedField { .. })
        ));
    }

    #[test]
    fn reject_inconsistent_opt_params_length() {
        let body: &[u8] = &[
            4, // version
            0xFD, 0xE9, // AS 65001
            0, 90, // hold time
            10, 0, 0, 1, // router ID
            5, // opt params len = 5, but body_len says 10
        ];
        let mut buf = bytes::Bytes::copy_from_slice(body);
        assert!(matches!(
            OpenMessage::decode(&mut buf, 10),
            Err(DecodeError::MalformedField { .. })
        ));
    }

    #[test]
    fn unknown_capabilities_preserved() {
        let original = OpenMessage {
            version: BGP_VERSION,
            my_as: 65001,
            hold_time: 90,
            bgp_identifier: Ipv4Addr::new(10, 0, 0, 1),
            capabilities: vec![Capability::Unknown {
                code: 128,
                data: bytes::Bytes::from_static(&[0xDE, 0xAD]),
            }],
        };

        let mut encoded = BytesMut::with_capacity(64);
        original.encode(&mut encoded).unwrap();

        let mut bytes = encoded.freeze();
        let header = BgpHeader::decode(&mut bytes, MAX_MESSAGE_LEN).unwrap();
        let body_len = usize::from(header.length) - HEADER_LEN;
        let decoded = OpenMessage::decode(&mut bytes, body_len).unwrap();
        assert_eq!(original, decoded);
    }
}
