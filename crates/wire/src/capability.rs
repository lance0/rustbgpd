use bytes::{Buf, BufMut, Bytes};

use crate::constants::{capability_code, param_type};
use crate::error::DecodeError;

/// Address Family Identifier (IANA).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Afi {
    Ipv4 = 1,
    Ipv6 = 2,
}

impl Afi {
    #[must_use]
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Ipv4),
            2 => Some(Self::Ipv6),
            _ => None,
        }
    }
}

/// Subsequent Address Family Identifier (IANA).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Safi {
    Unicast = 1,
    Multicast = 2,
}

impl Safi {
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Unicast),
            2 => Some(Self::Multicast),
            _ => None,
        }
    }
}

/// BGP capability as negotiated in OPEN optional parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    /// RFC 4760: Multi-Protocol Extensions.
    MultiProtocol { afi: Afi, safi: Safi },
    /// RFC 6793: 4-Byte AS Number.
    FourOctetAs { asn: u32 },
    /// Unknown or unrecognized capability, preserved for re-emission.
    Unknown { code: u8, data: Bytes },
}

impl Capability {
    /// Decode a single capability TLV from a buffer.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::MalformedOptionalParameter`] if the TLV is
    /// truncated or the claimed length exceeds the remaining bytes.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, DecodeError> {
        if buf.remaining() < 2 {
            return Err(DecodeError::MalformedOptionalParameter {
                offset: 0,
                detail: "capability TLV too short".into(),
            });
        }

        let code = buf.get_u8();
        let length = buf.get_u8();

        if buf.remaining() < usize::from(length) {
            return Err(DecodeError::MalformedOptionalParameter {
                offset: 0,
                detail: format!(
                    "capability code {code} claims length {length}, \
                     but only {} bytes remain",
                    buf.remaining()
                ),
            });
        }

        match code {
            capability_code::MULTI_PROTOCOL => {
                if length != 4 {
                    // Store as unknown if length is wrong
                    let data = buf.copy_to_bytes(usize::from(length));
                    return Ok(Capability::Unknown { code, data });
                }
                let afi_raw = buf.get_u16();
                let _reserved = buf.get_u8();
                let safi_raw = buf.get_u8();

                if let (Some(afi), Some(safi)) = (Afi::from_u16(afi_raw), Safi::from_u8(safi_raw)) {
                    Ok(Capability::MultiProtocol { afi, safi })
                } else {
                    // Unrecognized AFI/SAFI — store as unknown
                    let mut data = bytes::BytesMut::with_capacity(4);
                    data.put_u16(afi_raw);
                    data.put_u8(0); // reserved
                    data.put_u8(safi_raw);
                    Ok(Capability::Unknown {
                        code,
                        data: data.freeze(),
                    })
                }
            }
            capability_code::FOUR_OCTET_AS => {
                if length != 4 {
                    let data = buf.copy_to_bytes(usize::from(length));
                    return Ok(Capability::Unknown { code, data });
                }
                let asn = buf.get_u32();
                Ok(Capability::FourOctetAs { asn })
            }
            _ => {
                let data = buf.copy_to_bytes(usize::from(length));
                Ok(Capability::Unknown { code, data })
            }
        }
    }

    /// Encode a single capability TLV into a buffer.
    pub fn encode(&self, buf: &mut impl BufMut) {
        match self {
            Capability::MultiProtocol { afi, safi } => {
                buf.put_u8(capability_code::MULTI_PROTOCOL);
                buf.put_u8(4); // length
                buf.put_u16(*afi as u16);
                buf.put_u8(0); // reserved
                buf.put_u8(*safi as u8);
            }
            Capability::FourOctetAs { asn } => {
                buf.put_u8(capability_code::FOUR_OCTET_AS);
                buf.put_u8(4); // length
                buf.put_u32(*asn);
            }
            Capability::Unknown { code, data } => {
                buf.put_u8(*code);
                // Safe: capability length field is u8, max 255. Capabilities
                // with data > 255 bytes cannot exist on the wire.
                #[expect(clippy::cast_possible_truncation)]
                buf.put_u8(data.len() as u8);
                buf.put_slice(data);
            }
        }
    }

    /// Returns the capability code byte.
    #[must_use]
    pub fn code(&self) -> u8 {
        match self {
            Self::MultiProtocol { .. } => capability_code::MULTI_PROTOCOL,
            Self::FourOctetAs { .. } => capability_code::FOUR_OCTET_AS,
            Self::Unknown { code, .. } => *code,
        }
    }

    /// Encoded size of this capability TLV (code + length + value).
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        2 + match self {
            Self::MultiProtocol { .. } | Self::FourOctetAs { .. } => 4,
            Self::Unknown { data, .. } => data.len(),
        }
    }
}

/// Decode all optional parameters from an OPEN message body.
/// Returns capabilities found in parameter type 2 TLVs.
///
/// # Errors
///
/// Returns [`DecodeError::MalformedOptionalParameter`] if any parameter TLV
/// is truncated or contains an invalid capability.
pub fn decode_optional_parameters(
    buf: &mut impl Buf,
    opt_params_len: u8,
) -> Result<Vec<Capability>, DecodeError> {
    let mut capabilities = Vec::new();
    let mut remaining = usize::from(opt_params_len);

    while remaining > 0 {
        if buf.remaining() < 2 {
            return Err(DecodeError::MalformedOptionalParameter {
                offset: usize::from(opt_params_len) - remaining,
                detail: "optional parameter TLV too short".into(),
            });
        }

        let param_type = buf.get_u8();
        let param_len = buf.get_u8();
        remaining = remaining.saturating_sub(2);

        if usize::from(param_len) > remaining || buf.remaining() < usize::from(param_len) {
            return Err(DecodeError::MalformedOptionalParameter {
                offset: usize::from(opt_params_len) - remaining,
                detail: format!(
                    "parameter type {param_type} claims length {param_len}, \
                     but only {remaining} bytes remain"
                ),
            });
        }

        if param_type == param_type::CAPABILITIES {
            let mut cap_remaining = usize::from(param_len);
            while cap_remaining > 0 {
                let before = buf.remaining();
                let cap = Capability::decode(buf)?;
                let consumed = before - buf.remaining();
                cap_remaining = cap_remaining.saturating_sub(consumed);
                capabilities.push(cap);
            }
        } else {
            // Skip unknown parameter types
            buf.advance(usize::from(param_len));
        }

        remaining = remaining.saturating_sub(usize::from(param_len));
    }

    Ok(capabilities)
}

/// Encode capabilities as OPEN optional parameters (parameter type 2).
pub fn encode_optional_parameters(capabilities: &[Capability], buf: &mut impl BufMut) {
    if capabilities.is_empty() {
        return;
    }

    // Calculate total capability TLV size
    let cap_total: usize = capabilities.iter().map(Capability::encoded_len).sum();

    // Parameter type 2 header
    buf.put_u8(param_type::CAPABILITIES);
    #[expect(clippy::cast_possible_truncation)]
    buf.put_u8(cap_total as u8);

    for cap in capabilities {
        cap.encode(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_multi_protocol_ipv4_unicast() {
        let data: &[u8] = &[1, 4, 0, 1, 0, 1]; // code=1, len=4, AFI=1, res=0, SAFI=1
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        assert_eq!(
            cap,
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast
            }
        );
    }

    #[test]
    fn decode_four_octet_as() {
        let data: &[u8] = &[65, 4, 0, 0, 0xFD, 0xE8]; // code=65, len=4, ASN=65000
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        assert_eq!(cap, Capability::FourOctetAs { asn: 65000 });
    }

    #[test]
    fn decode_unknown_capability_preserved() {
        let data: &[u8] = &[99, 3, 0xAA, 0xBB, 0xCC]; // code=99, len=3
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        match cap {
            Capability::Unknown { code, data } => {
                assert_eq!(code, 99);
                assert_eq!(data.as_ref(), &[0xAA, 0xBB, 0xCC]);
            }
            _ => panic!("expected Unknown"),
        }
    }

    #[test]
    fn unrecognized_afi_safi_stored_as_unknown() {
        let data: &[u8] = &[1, 4, 0, 99, 0, 1]; // code=1, len=4, AFI=99 (unknown)
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        assert!(matches!(cap, Capability::Unknown { code: 1, .. }));
    }

    #[test]
    fn roundtrip_multi_protocol() {
        let original = Capability::MultiProtocol {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
        };
        let mut encoded = bytes::BytesMut::with_capacity(6);
        original.encode(&mut encoded);
        let mut buf = encoded.freeze();
        let decoded = Capability::decode(&mut buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_four_octet_as() {
        let original = Capability::FourOctetAs { asn: 4_200_000_000 };
        let mut encoded = bytes::BytesMut::with_capacity(6);
        original.encode(&mut encoded);
        let mut buf = encoded.freeze();
        let decoded = Capability::decode(&mut buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_unknown() {
        let original = Capability::Unknown {
            code: 42,
            data: Bytes::from_static(&[1, 2, 3]),
        };
        let mut encoded = bytes::BytesMut::with_capacity(5);
        original.encode(&mut encoded);
        let mut buf = encoded.freeze();
        let decoded = Capability::decode(&mut buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_optional_params_multiple_caps() {
        // Parameter type=2, length=12, containing two capabilities
        let mut data = bytes::BytesMut::new();
        data.put_u8(2); // param type = capabilities
        data.put_u8(12); // param length
        // Cap 1: MultiProtocol IPv4 Unicast
        data.put_u8(1);
        data.put_u8(4);
        data.put_u16(1); // AFI IPv4
        data.put_u8(0);
        data.put_u8(1); // SAFI Unicast
        // Cap 2: FourOctetAs 65001
        data.put_u8(65);
        data.put_u8(4);
        data.put_u32(65001);

        let mut buf = data.freeze();
        let caps = decode_optional_parameters(&mut buf, 14).unwrap();
        assert_eq!(caps.len(), 2);
        assert_eq!(
            caps[0],
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast
            }
        );
        assert_eq!(caps[1], Capability::FourOctetAs { asn: 65001 });
    }

    #[test]
    fn decode_empty_optional_params() {
        let mut buf = Bytes::new();
        let caps = decode_optional_parameters(&mut buf, 0).unwrap();
        assert!(caps.is_empty());
    }

    #[test]
    fn reject_truncated_capability() {
        let data: &[u8] = &[65, 4, 0, 0]; // FourOctetAs but only 2 bytes of value
        let mut buf = Bytes::copy_from_slice(data);
        assert!(Capability::decode(&mut buf).is_err());
    }
}
