use std::net::Ipv4Addr;

use bytes::{Buf, BufMut, BytesMut};

use crate::capability::{
    Capability, decode_extended_optional_parameters, decode_optional_parameters,
    encode_extended_optional_parameters, encode_optional_parameters,
};
use crate::constants::{BGP_VERSION, HEADER_LEN, MAX_MESSAGE_LEN, param_type};
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
        let non_extended_len = buf.get_u8();
        let mut optional_parameters = buf.copy_to_bytes(body_len - 10);

        let capabilities = if non_extended_len != 0
            && optional_parameters.first() == Some(&param_type::EXTENDED_LENGTH)
        {
            if optional_parameters.remaining() < 3 {
                return Err(DecodeError::MalformedOptionalParameter {
                    offset: 0,
                    detail: "extended optional parameters header too short".into(),
                });
            }
            optional_parameters.advance(1); // Non-Ext OP Type marker.
            let extended_len = optional_parameters.get_u16();
            if optional_parameters.remaining() != usize::from(extended_len) {
                return Err(DecodeError::MalformedField {
                    message_type: "OPEN",
                    detail: format!(
                        "extended optional parameters length {extended_len} inconsistent \
                         with body length {body_len}"
                    ),
                });
            }
            decode_extended_optional_parameters(&mut optional_parameters, extended_len)?
        } else {
            if optional_parameters.remaining() != usize::from(non_extended_len) {
                let expected_body = 10 + usize::from(non_extended_len);
                return Err(DecodeError::MalformedField {
                    message_type: "OPEN",
                    detail: format!(
                        "optional parameters length {non_extended_len} inconsistent \
                         with body length {body_len} (expected {expected_body})"
                    ),
                });
            }
            decode_optional_parameters(&mut optional_parameters, non_extended_len)?
        };

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
    /// Returns an [`EncodeError`] if an individual capability cannot be
    /// encoded or the total OPEN exceeds the 4096-byte BGP message limit.
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
        let capabilities_len: usize = self.capabilities.iter().map(Capability::encoded_len).sum();
        let use_extended = !self.capabilities.is_empty() && capabilities_len + 2 > 255;
        let mut opt_params = BytesMut::new();
        if use_extended {
            encode_extended_optional_parameters(&self.capabilities, &mut opt_params)?;
        } else {
            encode_optional_parameters(&self.capabilities, &mut opt_params)?;
        }
        let opt_params_len = opt_params.len();

        let body_prefix_len = if use_extended { 13 } else { 10 };
        let total_len = HEADER_LEN + body_prefix_len + opt_params_len;
        if total_len > usize::from(MAX_MESSAGE_LEN) {
            return Err(EncodeError::MessageTooLong { size: total_len });
        }

        // Header
        let header = BgpHeader {
            #[expect(
                clippy::cast_possible_truncation,
                reason = "codec bounds or masks the value before narrowing to the protocol field width"
            )]
            length: total_len as u16,
            message_type: MessageType::Open,
        };
        header.encode(buf);

        // Body
        buf.put_u8(self.version);
        buf.put_u16(self.my_as);
        buf.put_u16(self.hold_time);
        buf.put_u32(u32::from(self.bgp_identifier));
        if use_extended {
            buf.put_u8(param_type::EXTENDED_LENGTH);
            buf.put_u8(param_type::EXTENDED_LENGTH);
            let opt_params_len =
                u16::try_from(opt_params_len).map_err(|_| EncodeError::ValueOutOfRange {
                    field: "optional_parameters_length",
                    value: opt_params_len.to_string(),
                })?;
            buf.put_u16(opt_params_len);
        } else {
            #[expect(
                clippy::cast_possible_truncation,
                reason = "classic framing is selected only through 255 optional-parameter octets"
            )]
            buf.put_u8(opt_params_len as u8);
        }
        buf.put_slice(&opt_params);

        Ok(())
    }

    /// Total encoded size in bytes.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let cap_size: usize = self.capabilities.iter().map(Capability::encoded_len).sum();
        if self.capabilities.is_empty() {
            HEADER_LEN + 10
        } else if cap_size + 2 <= 255 {
            HEADER_LEN + 10 + 2 + cap_size
        } else {
            // Extended OPEN prefix adds marker type(1) + u16 aggregate
            // length(2); the capability parameter uses a u16 length (3).
            HEADER_LEN + 13 + 3 + cap_size
        }
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
    fn classic_encoding_carries_255_optional_parameter_octets() {
        // Capability TLV 253 + classic parameter header 2 = 255.
        let mut original = minimal_open();
        original.capabilities = vec![Capability::Unknown {
            code: 200,
            data: bytes::Bytes::from(vec![0xA5; 251]),
        }];

        let mut encoded = BytesMut::new();
        original.encode(&mut encoded).unwrap();

        // Mutation-red: selecting extended framing at >=255 changes both
        // these boundary octets and the encoded length.
        assert_eq!(encoded.len(), 284);
        assert_eq!(encoded[28], 255); // classic aggregate length
        assert_eq!(encoded[29], param_type::CAPABILITIES);
        assert_eq!(encoded[30], 253); // classic parameter length

        let mut bytes = encoded.freeze();
        let header = BgpHeader::decode(&mut bytes, MAX_MESSAGE_LEN).unwrap();
        let decoded =
            OpenMessage::decode(&mut bytes, usize::from(header.length) - HEADER_LEN).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn extended_encoding_starts_above_255_optional_parameter_octets() {
        // Capability TLV 254 cannot fit behind the classic 2-byte parameter
        // header, so RFC 9072 widens both enclosing length fields.
        let mut original = minimal_open();
        original.capabilities = vec![Capability::Unknown {
            code: 200,
            data: bytes::Bytes::from(vec![0x5A; 252]),
        }];

        let mut encoded = BytesMut::new();
        original.encode(&mut encoded).unwrap();

        // Mutation-red: restoring the old 255-byte ceiling makes encode fail;
        // keeping the classic parameter length changes these exact bytes.
        assert_eq!(encoded.len(), 289);
        assert_eq!(encoded[28], param_type::EXTENDED_LENGTH);
        assert_eq!(encoded[29], param_type::EXTENDED_LENGTH);
        assert_eq!(&encoded[30..32], &257_u16.to_be_bytes());
        assert_eq!(encoded[32], param_type::CAPABILITIES);
        assert_eq!(&encoded[33..35], &254_u16.to_be_bytes());
        assert_eq!(original.encoded_len(), encoded.len());

        let mut bytes = encoded.freeze();
        let header = BgpHeader::decode(&mut bytes, MAX_MESSAGE_LEN).unwrap();
        let decoded =
            OpenMessage::decode(&mut bytes, usize::from(header.length) - HEADER_LEN).unwrap();
        assert_eq!(decoded, original);
    }

    fn extended_open_body(non_extended_len: u8, parameters: &[u8]) -> BytesMut {
        let mut body = BytesMut::new();
        body.put_u8(BGP_VERSION);
        body.put_u16(65001);
        body.put_u16(90);
        body.put_u32(u32::from(Ipv4Addr::new(10, 0, 0, 1)));
        body.put_u8(non_extended_len);
        body.put_u8(param_type::EXTENDED_LENGTH);
        body.put_u16(u16::try_from(parameters.len()).unwrap());
        body.put_slice(parameters);
        body
    }

    #[test]
    fn decode_accepts_forced_small_extended_encoding() {
        let parameters = [
            param_type::CAPABILITIES,
            0,
            4, // extended parameter length
            200,
            2,
            0xAA,
            0xBB, // unknown capability preserved inside type 2
        ];
        // RFC 9072 says the non-extended length is ignored once marker 255 is
        // seen; use 1 to prove receivers do not require the recommended 255.
        let mut body = extended_open_body(1, &parameters).freeze();
        let body_len = body.len();
        let decoded = OpenMessage::decode(&mut body, body_len).unwrap();

        // Mutation-red: requiring the marker length to be 255 or decoding
        // parameter lengths as u8 rejects/misparses this OPEN.
        assert_eq!(
            decoded.capabilities,
            vec![Capability::Unknown {
                code: 200,
                data: bytes::Bytes::from_static(&[0xAA, 0xBB]),
            }]
        );
    }

    #[test]
    fn decode_accepts_zero_length_extended_encoding() {
        let mut body = extended_open_body(255, &[]).freeze();
        let body_len = body.len();
        let decoded = OpenMessage::decode(&mut body, body_len).unwrap();

        // Mutation-red: treating an extended length of zero as truncated or
        // falling back to classic framing makes this fail.
        assert!(decoded.capabilities.is_empty());
    }

    #[test]
    fn decode_rejects_inconsistent_extended_aggregate_length() {
        let mut body = extended_open_body(255, &[]);
        body[11] = 0;
        body[12] = 1; // claim one parameter octet, provide none
        let body_len = body.len();
        let result = OpenMessage::decode(&mut body.freeze(), body_len);

        // Mutation-red: dropping the aggregate/body consistency check accepts
        // this structurally truncated extended OPEN.
        assert!(matches!(result, Err(DecodeError::MalformedField { .. })));
    }

    #[test]
    fn decode_rejects_unknown_optional_parameter_type() {
        let body: &[u8] = &[
            4, 0xFD, 0xE9, 0, 90, 10, 0, 0, 1, 3, // fixed OPEN + opt len
            99, 1, 0xAA, // unsupported Optional Parameter
        ];
        let mut body = bytes::Bytes::copy_from_slice(body);
        let result = OpenMessage::decode(&mut body, 13);

        // Mutation-red: restoring the previous skip-unknown behavior returns
        // a successful OPEN instead of the RFC 4271 2/4 error source.
        assert_eq!(
            result,
            Err(DecodeError::UnsupportedOptionalParameter { param_type: 99 })
        );
    }

    #[test]
    fn extended_length_marker_is_unsupported_inside_parameter_list() {
        let parameters = [param_type::EXTENDED_LENGTH, 0, 0];
        let mut body = extended_open_body(255, &parameters).freeze();
        let body_len = body.len();
        let result = OpenMessage::decode(&mut body, body_len);

        // Mutation-red: treating type 255 as a normal/skippable parameter
        // outside its marker position accepts a forbidden encoding.
        assert_eq!(
            result,
            Err(DecodeError::UnsupportedOptionalParameter {
                param_type: param_type::EXTENDED_LENGTH,
            })
        );
    }

    fn unknown_capabilities_with_encoded_len(mut encoded_len: usize) -> Vec<Capability> {
        let mut capabilities = Vec::new();
        let mut code = 128_u8;
        while encoded_len > 257 {
            capabilities.push(Capability::Unknown {
                code,
                data: bytes::Bytes::from(vec![0; 255]),
            });
            code = code.wrapping_add(1);
            encoded_len -= 257;
        }
        assert!(encoded_len >= 2);
        capabilities.push(Capability::Unknown {
            code,
            data: bytes::Bytes::from(vec![0; encoded_len - 2]),
        });
        capabilities
    }

    #[test]
    fn extended_open_accepts_4096_and_rejects_4097_atomically() {
        let mut at_limit = minimal_open();
        // Extended framing is 35 bytes: header 19 + body prefix 13 +
        // capability-parameter header 3. 4061 capability bytes land at 4096.
        at_limit.capabilities = unknown_capabilities_with_encoded_len(4061);
        let mut encoded = BytesMut::new();
        at_limit.encode(&mut encoded).unwrap();

        // Mutation-red: changing the limit check from > to >= rejects this
        // exact legal boundary.
        assert_eq!(encoded.len(), 4096);
        let mut bytes = encoded.freeze();
        let header = BgpHeader::decode(&mut bytes, MAX_MESSAGE_LEN).unwrap();
        let decoded =
            OpenMessage::decode(&mut bytes, usize::from(header.length) - HEADER_LEN).unwrap();
        assert_eq!(decoded, at_limit);

        let mut over_limit = minimal_open();
        over_limit.capabilities = unknown_capabilities_with_encoded_len(4062);
        let mut encoded = BytesMut::new();
        let result = over_limit.encode(&mut encoded);

        // Mutation-red: removing the OPEN cap makes this exact 4097-byte
        // message encode successfully.
        assert_eq!(result, Err(EncodeError::MessageTooLong { size: 4097 }));
        assert!(encoded.is_empty());
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
