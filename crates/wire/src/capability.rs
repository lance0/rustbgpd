use bytes::{Buf, BufMut, Bytes};

use crate::constants::{capability_code, param_type};
use crate::error::{DecodeError, EncodeError};

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

/// Per-AFI/SAFI entry in the Graceful Restart capability (RFC 4724 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GracefulRestartFamily {
    pub afi: Afi,
    pub safi: Safi,
    /// Whether the peer preserved forwarding state for this family.
    pub forwarding_preserved: bool,
}

/// Add-Path send/receive mode per AFI/SAFI (RFC 7911 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AddPathMode {
    Receive = 1,
    Send = 2,
    Both = 3,
}

impl AddPathMode {
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Receive),
            2 => Some(Self::Send),
            3 => Some(Self::Both),
            _ => None,
        }
    }
}

/// Per-AFI/SAFI entry in the Add-Path capability (RFC 7911 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddPathFamily {
    pub afi: Afi,
    pub safi: Safi,
    pub send_receive: AddPathMode,
}

/// BGP capability as negotiated in OPEN optional parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    /// RFC 4760: Multi-Protocol Extensions.
    MultiProtocol { afi: Afi, safi: Safi },
    /// RFC 4724: Graceful Restart.
    GracefulRestart {
        /// R-bit: the sender has restarted and its forwarding state
        /// may have been preserved.
        restart_state: bool,
        /// Time in seconds the sender will retain stale routes (12-bit, max 4095).
        restart_time: u16,
        /// Per-AFI/SAFI forwarding state flags.
        families: Vec<GracefulRestartFamily>,
    },
    /// RFC 2918: Route Refresh.
    RouteRefresh,
    /// RFC 8654: Extended Messages (raise max message length to 65535).
    ExtendedMessage,
    /// RFC 7911: Add-Path — advertise/receive multiple paths per prefix.
    AddPath(Vec<AddPathFamily>),
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
    #[expect(clippy::too_many_lines)]
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
            capability_code::ROUTE_REFRESH => {
                if length != 0 {
                    let data = buf.copy_to_bytes(usize::from(length));
                    return Ok(Capability::Unknown { code, data });
                }
                Ok(Capability::RouteRefresh)
            }
            capability_code::EXTENDED_MESSAGE => {
                if length != 0 {
                    let data = buf.copy_to_bytes(usize::from(length));
                    return Ok(Capability::Unknown { code, data });
                }
                Ok(Capability::ExtendedMessage)
            }
            capability_code::GRACEFUL_RESTART => {
                // Minimum 2 bytes (restart flags/time). Each family is 4 bytes.
                if length < 2 || !(length - 2).is_multiple_of(4) {
                    let data = buf.copy_to_bytes(usize::from(length));
                    return Ok(Capability::Unknown { code, data });
                }
                let flags_and_time = buf.get_u16();
                let restart_state = (flags_and_time & 0x8000) != 0;
                let restart_time = flags_and_time & 0x0FFF;
                let family_count = (length - 2) / 4;
                let mut families = Vec::with_capacity(usize::from(family_count));
                for _ in 0..family_count {
                    let afi_raw = buf.get_u16();
                    let safi_raw = buf.get_u8();
                    let flags = buf.get_u8();
                    if let (Some(afi), Some(safi)) =
                        (Afi::from_u16(afi_raw), Safi::from_u8(safi_raw))
                    {
                        families.push(GracefulRestartFamily {
                            afi,
                            safi,
                            forwarding_preserved: (flags & 0x80) != 0,
                        });
                    }
                    // Skip unrecognized AFI/SAFI entries silently
                }
                Ok(Capability::GracefulRestart {
                    restart_state,
                    restart_time,
                    families,
                })
            }
            capability_code::ADD_PATH => {
                // RFC 7911 §4: value is N entries of (AFI:2 + SAFI:1 + mode:1) = 4 bytes each
                if length == 0 || !usize::from(length).is_multiple_of(4) {
                    let data = buf.copy_to_bytes(usize::from(length));
                    return Ok(Capability::Unknown { code, data });
                }
                let entry_count = usize::from(length) / 4;
                // Snapshot the raw bytes before parsing so we can fall back
                // to Unknown if any entry would be discarded (lossless roundtrip).
                let raw_data = buf.copy_to_bytes(usize::from(length));
                let mut cursor = raw_data.clone();
                let mut families = Vec::with_capacity(entry_count);
                let mut all_valid = true;
                for _ in 0..entry_count {
                    let afi_raw = cursor.get_u16();
                    let safi_raw = cursor.get_u8();
                    let mode_raw = cursor.get_u8();
                    if let (Some(afi), Some(safi), Some(mode)) = (
                        Afi::from_u16(afi_raw),
                        Safi::from_u8(safi_raw),
                        AddPathMode::from_u8(mode_raw),
                    ) {
                        families.push(AddPathFamily {
                            afi,
                            safi,
                            send_receive: mode,
                        });
                    } else {
                        all_valid = false;
                    }
                }
                // Preserve as Unknown if any entry was unrecognized, to avoid
                // silently rewriting malformed capability data on re-encode.
                if all_valid {
                    Ok(Capability::AddPath(families))
                } else {
                    Ok(Capability::Unknown { code, data: raw_data })
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
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::ValueOutOfRange`] if the capability value
    /// exceeds the 255-byte limit of the single-octet length field.
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
        match self {
            Capability::MultiProtocol { afi, safi } => {
                buf.put_u8(capability_code::MULTI_PROTOCOL);
                buf.put_u8(4); // length
                buf.put_u16(*afi as u16);
                buf.put_u8(0); // reserved
                buf.put_u8(*safi as u8);
            }
            Capability::RouteRefresh => {
                buf.put_u8(capability_code::ROUTE_REFRESH);
                buf.put_u8(0); // zero-length value
            }
            Capability::ExtendedMessage => {
                buf.put_u8(capability_code::EXTENDED_MESSAGE);
                buf.put_u8(0); // zero-length value
            }
            Capability::GracefulRestart {
                restart_state,
                restart_time,
                families,
            } => {
                let value_len = 2 + families.len() * 4;
                if value_len > 255 {
                    return Err(EncodeError::ValueOutOfRange {
                        field: "graceful_restart_capability_length",
                        value: value_len.to_string(),
                    });
                }
                if *restart_time > 4095 {
                    return Err(EncodeError::ValueOutOfRange {
                        field: "graceful_restart_time",
                        value: restart_time.to_string(),
                    });
                }
                buf.put_u8(capability_code::GRACEFUL_RESTART);
                #[expect(clippy::cast_possible_truncation)]
                buf.put_u8(value_len as u8);
                let mut flags_and_time = *restart_time;
                if *restart_state {
                    flags_and_time |= 0x8000;
                }
                buf.put_u16(flags_and_time);
                for fam in families {
                    buf.put_u16(fam.afi as u16);
                    buf.put_u8(fam.safi as u8);
                    buf.put_u8(if fam.forwarding_preserved { 0x80 } else { 0 });
                }
            }
            Capability::AddPath(families) => {
                let value_len = families.len() * 4;
                if value_len > 255 {
                    return Err(EncodeError::ValueOutOfRange {
                        field: "add_path_capability_length",
                        value: value_len.to_string(),
                    });
                }
                buf.put_u8(capability_code::ADD_PATH);
                #[expect(clippy::cast_possible_truncation)]
                buf.put_u8(value_len as u8);
                for fam in families {
                    buf.put_u16(fam.afi as u16);
                    buf.put_u8(fam.safi as u8);
                    buf.put_u8(fam.send_receive as u8);
                }
            }
            Capability::FourOctetAs { asn } => {
                buf.put_u8(capability_code::FOUR_OCTET_AS);
                buf.put_u8(4); // length
                buf.put_u32(*asn);
            }
            Capability::Unknown { code, data } => {
                if data.len() > 255 {
                    return Err(EncodeError::ValueOutOfRange {
                        field: "unknown_capability_length",
                        value: data.len().to_string(),
                    });
                }
                buf.put_u8(*code);
                #[expect(clippy::cast_possible_truncation)]
                buf.put_u8(data.len() as u8);
                buf.put_slice(data);
            }
        }
        Ok(())
    }

    /// Returns the capability code byte.
    #[must_use]
    pub fn code(&self) -> u8 {
        match self {
            Self::MultiProtocol { .. } => capability_code::MULTI_PROTOCOL,
            Self::RouteRefresh => capability_code::ROUTE_REFRESH,
            Self::ExtendedMessage => capability_code::EXTENDED_MESSAGE,
            Self::AddPath(_) => capability_code::ADD_PATH,
            Self::GracefulRestart { .. } => capability_code::GRACEFUL_RESTART,
            Self::FourOctetAs { .. } => capability_code::FOUR_OCTET_AS,
            Self::Unknown { code, .. } => *code,
        }
    }

    /// Encoded size of this capability TLV (code + length + value).
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        2 + match self {
            Self::MultiProtocol { .. } | Self::FourOctetAs { .. } => 4,
            Self::RouteRefresh | Self::ExtendedMessage => 0,
            Self::AddPath(families) => families.len() * 4,
            Self::GracefulRestart { families, .. } => 2 + families.len() * 4,
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
            // Parse capabilities from a bounded sub-buffer so a malformed
            // capability length cannot consume into the next parameter or
            // beyond the OPEN body.
            let param_bytes = buf.copy_to_bytes(usize::from(param_len));
            let mut cap_buf = param_bytes;
            while cap_buf.has_remaining() {
                let cap = Capability::decode(&mut cap_buf)?;
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
///
/// # Errors
///
/// Returns [`EncodeError::ValueOutOfRange`] if the total capabilities size
/// exceeds 255 bytes or any individual capability is too large.
///
/// # Note
///
/// On error, partial bytes may have been written to `buf`. Callers should
/// encode into a staging buffer (as `OpenMessage::encode` does) to ensure
/// atomicity.
pub fn encode_optional_parameters(
    capabilities: &[Capability],
    buf: &mut impl BufMut,
) -> Result<(), EncodeError> {
    if capabilities.is_empty() {
        return Ok(());
    }

    // Calculate total capability TLV size
    let cap_total: usize = capabilities.iter().map(Capability::encoded_len).sum();

    if cap_total > 255 {
        return Err(EncodeError::ValueOutOfRange {
            field: "capabilities_parameter_length",
            value: cap_total.to_string(),
        });
    }

    // Parameter type 2 header
    buf.put_u8(param_type::CAPABILITIES);
    #[expect(clippy::cast_possible_truncation)]
    buf.put_u8(cap_total as u8);

    for cap in capabilities {
        cap.encode(buf)?;
    }
    Ok(())
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
        original.encode(&mut encoded).unwrap();
        let mut buf = encoded.freeze();
        let decoded = Capability::decode(&mut buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_four_octet_as() {
        let original = Capability::FourOctetAs { asn: 4_200_000_000 };
        let mut encoded = bytes::BytesMut::with_capacity(6);
        original.encode(&mut encoded).unwrap();
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
        original.encode(&mut encoded).unwrap();
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

    #[test]
    fn decode_graceful_restart_with_families() {
        // code=64, len=10 (2 + 2*4), flags=0x80 (R-bit) | time=120
        // Family 1: IPv4/Unicast, forwarding preserved
        // Family 2: IPv6/Unicast, forwarding not preserved
        let mut data = bytes::BytesMut::new();
        data.put_u8(64); // code
        data.put_u8(10); // length: 2 + 2*4
        data.put_u16(0x8078); // R-bit set, restart_time=120
        data.put_u16(1); // AFI IPv4
        data.put_u8(1); // SAFI Unicast
        data.put_u8(0x80); // forwarding preserved
        data.put_u16(2); // AFI IPv6
        data.put_u8(1); // SAFI Unicast
        data.put_u8(0x00); // forwarding not preserved

        let mut buf = data.freeze();
        let cap = Capability::decode(&mut buf).unwrap();
        assert_eq!(
            cap,
            Capability::GracefulRestart {
                restart_state: true,
                restart_time: 120,
                families: vec![
                    GracefulRestartFamily {
                        afi: Afi::Ipv4,
                        safi: Safi::Unicast,
                        forwarding_preserved: true,
                    },
                    GracefulRestartFamily {
                        afi: Afi::Ipv6,
                        safi: Safi::Unicast,
                        forwarding_preserved: false,
                    },
                ],
            }
        );
    }

    #[test]
    fn decode_graceful_restart_no_r_bit() {
        let mut data = bytes::BytesMut::new();
        data.put_u8(64);
        data.put_u8(6); // 2 + 1*4
        data.put_u16(0x005A); // R-bit clear, restart_time=90
        data.put_u16(1); // AFI IPv4
        data.put_u8(1); // SAFI Unicast
        data.put_u8(0x00); // forwarding not preserved

        let mut buf = data.freeze();
        let cap = Capability::decode(&mut buf).unwrap();
        assert_eq!(
            cap,
            Capability::GracefulRestart {
                restart_state: false,
                restart_time: 90,
                families: vec![GracefulRestartFamily {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                    forwarding_preserved: false,
                }],
            }
        );
    }

    #[test]
    fn decode_graceful_restart_empty_families() {
        let mut data = bytes::BytesMut::new();
        data.put_u8(64);
        data.put_u8(2); // just the flags/time, no families
        data.put_u16(0x003C); // time=60

        let mut buf = data.freeze();
        let cap = Capability::decode(&mut buf).unwrap();
        assert_eq!(
            cap,
            Capability::GracefulRestart {
                restart_state: false,
                restart_time: 60,
                families: vec![],
            }
        );
    }

    #[test]
    fn roundtrip_graceful_restart() {
        let original = Capability::GracefulRestart {
            restart_state: true,
            restart_time: 120,
            families: vec![
                GracefulRestartFamily {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                    forwarding_preserved: true,
                },
                GracefulRestartFamily {
                    afi: Afi::Ipv6,
                    safi: Safi::Unicast,
                    forwarding_preserved: false,
                },
            ],
        };
        let mut encoded = bytes::BytesMut::with_capacity(12);
        original.encode(&mut encoded).unwrap();
        let mut buf = encoded.freeze();
        let decoded = Capability::decode(&mut buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn graceful_restart_encoded_len() {
        let cap = Capability::GracefulRestart {
            restart_state: false,
            restart_time: 120,
            families: vec![GracefulRestartFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                forwarding_preserved: true,
            }],
        };
        // code(1) + length(1) + flags_time(2) + 1 family(4) = 8
        assert_eq!(cap.encoded_len(), 8);
    }

    #[test]
    fn graceful_restart_code() {
        let cap = Capability::GracefulRestart {
            restart_state: false,
            restart_time: 0,
            families: vec![],
        };
        assert_eq!(cap.code(), 64);
    }

    #[test]
    fn graceful_restart_bad_length_stored_as_unknown() {
        // Length 3 is invalid (not 2 + N*4)
        let data: &[u8] = &[64, 3, 0x00, 0x3C, 0xFF];
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        assert!(matches!(cap, Capability::Unknown { code: 64, .. }));
    }

    #[test]
    fn encode_rejects_oversized_gr_families() {
        // 64 families → value_len = 2 + 64*4 = 258, exceeds u8
        let families: Vec<GracefulRestartFamily> = (0..64)
            .map(|_| GracefulRestartFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                forwarding_preserved: false,
            })
            .collect();
        let cap = Capability::GracefulRestart {
            restart_state: false,
            restart_time: 120,
            families,
        };
        let mut buf = bytes::BytesMut::new();
        assert!(cap.encode(&mut buf).is_err());
    }

    #[test]
    fn encode_rejects_oversized_unknown_data() {
        let cap = Capability::Unknown {
            code: 99,
            data: Bytes::from(vec![0u8; 256]),
        };
        let mut buf = bytes::BytesMut::new();
        assert!(cap.encode(&mut buf).is_err());
    }

    #[test]
    fn encode_optional_params_rejects_overflow() {
        // Total capabilities exceeding 255 bytes
        let caps: Vec<Capability> = (0..50)
            .map(|_| Capability::Unknown {
                code: 99,
                data: Bytes::from(vec![0u8; 5]),
            })
            .collect();
        // 50 caps * 7 bytes each = 350 > 255
        let mut buf = bytes::BytesMut::new();
        assert!(encode_optional_parameters(&caps, &mut buf).is_err());
    }

    #[test]
    fn encode_rejects_restart_time_over_4095() {
        let cap = Capability::GracefulRestart {
            restart_state: false,
            restart_time: 4096,
            families: vec![],
        };
        let mut buf = bytes::BytesMut::new();
        assert!(cap.encode(&mut buf).is_err());
    }

    #[test]
    fn encode_accepts_restart_time_at_4095() {
        let cap = Capability::GracefulRestart {
            restart_state: false,
            restart_time: 4095,
            families: vec![],
        };
        let mut buf = bytes::BytesMut::new();
        assert!(cap.encode(&mut buf).is_ok());
    }

    #[test]
    fn decode_capability_bounded_to_parameter_slice() {
        // Build optional parameters where the capability inside claims a
        // length that would overrun the parameter boundary.
        // Parameter: type=2, len=4 (only 4 bytes of capability data)
        // Capability inside: code=65 (FourOctetAs), len=8 (claims 8 but only 2 available)
        // Followed by: a valid second parameter that should not be consumed.
        let mut data = bytes::BytesMut::new();
        // Parameter 1: capabilities, len=4
        data.put_u8(2); // param type = capabilities
        data.put_u8(4); // param len = 4 bytes
        // Capability: code=65, len=8 (overflows the 4-byte parameter)
        data.put_u8(65);
        data.put_u8(8); // claims 8 bytes but only 2 remain in parameter
        data.put_u16(0xBEEF); // 2 bytes of data
        // Parameter 2: unknown type, should be untouched
        data.put_u8(99); // param type = unknown
        data.put_u8(2); // param len = 2
        data.put_u16(0xCAFE);

        let mut buf = data.freeze();
        // Should fail because the capability overflows the parameter slice
        // Total is 8 bytes: param1(2+4) + param2(2+2) but we pass the full
        // length so the outer parser sees both parameters.
        let result = decode_optional_parameters(&mut buf, 8);
        assert!(result.is_err());
    }

    #[test]
    fn decode_extended_message() {
        let data: &[u8] = &[6, 0]; // code=6, len=0
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        assert_eq!(cap, Capability::ExtendedMessage);
    }

    #[test]
    fn roundtrip_extended_message() {
        let original = Capability::ExtendedMessage;
        let mut encoded = bytes::BytesMut::with_capacity(2);
        original.encode(&mut encoded).unwrap();
        let mut buf = encoded.freeze();
        let decoded = Capability::decode(&mut buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn extended_message_code_and_len() {
        let cap = Capability::ExtendedMessage;
        assert_eq!(cap.code(), 6);
        assert_eq!(cap.encoded_len(), 2);
    }

    #[test]
    fn extended_message_bad_length_stored_as_unknown() {
        let data: &[u8] = &[6, 1, 0xFF]; // code=6, len=1 (should be 0)
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        assert!(matches!(cap, Capability::Unknown { code: 6, .. }));
    }

    // --- Add-Path capability tests ---

    #[test]
    fn decode_add_path_single_family() {
        // code=69, len=4, AFI=1(IPv4), SAFI=1(Unicast), mode=3(Both)
        let data: &[u8] = &[69, 4, 0, 1, 1, 3];
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        assert_eq!(
            cap,
            Capability::AddPath(vec![AddPathFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                send_receive: AddPathMode::Both,
            }])
        );
    }

    #[test]
    fn decode_add_path_multiple_families() {
        let mut data = bytes::BytesMut::new();
        data.put_u8(69); // code
        data.put_u8(8); // len = 2 * 4
        data.put_u16(1); // AFI IPv4
        data.put_u8(1); // SAFI Unicast
        data.put_u8(1); // Receive
        data.put_u16(2); // AFI IPv6
        data.put_u8(1); // SAFI Unicast
        data.put_u8(2); // Send

        let mut buf = data.freeze();
        let cap = Capability::decode(&mut buf).unwrap();
        assert_eq!(
            cap,
            Capability::AddPath(vec![
                AddPathFamily {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                    send_receive: AddPathMode::Receive,
                },
                AddPathFamily {
                    afi: Afi::Ipv6,
                    safi: Safi::Unicast,
                    send_receive: AddPathMode::Send,
                },
            ])
        );
    }

    #[test]
    fn roundtrip_add_path() {
        let original = Capability::AddPath(vec![
            AddPathFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                send_receive: AddPathMode::Both,
            },
            AddPathFamily {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                send_receive: AddPathMode::Receive,
            },
        ]);
        let mut encoded = bytes::BytesMut::with_capacity(10);
        original.encode(&mut encoded).unwrap();
        let mut buf = encoded.freeze();
        let decoded = Capability::decode(&mut buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn add_path_code_and_len() {
        let cap = Capability::AddPath(vec![AddPathFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            send_receive: AddPathMode::Receive,
        }]);
        assert_eq!(cap.code(), 69);
        // code(1) + length(1) + 1 family(4) = 6
        assert_eq!(cap.encoded_len(), 6);
    }

    #[test]
    fn add_path_bad_length_stored_as_unknown() {
        // code=69, len=3 (not multiple of 4)
        let data: &[u8] = &[69, 3, 0, 1, 1];
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        assert!(matches!(cap, Capability::Unknown { code: 69, .. }));
    }

    #[test]
    fn add_path_zero_length_stored_as_unknown() {
        // code=69, len=0
        let data: &[u8] = &[69, 0];
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        assert!(matches!(cap, Capability::Unknown { code: 69, .. }));
    }

    #[test]
    fn add_path_unknown_afi_preserved_as_unknown() {
        // code=69, len=4, AFI=99(unknown), SAFI=1, mode=3
        let data: &[u8] = &[69, 4, 0, 99, 1, 3];
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        // Unrecognized entry → preserve as Unknown for lossless roundtrip
        assert!(matches!(cap, Capability::Unknown { code: 69, .. }));
    }

    #[test]
    fn add_path_invalid_mode_preserved_as_unknown() {
        // code=69, len=4, AFI=1, SAFI=1, mode=0 (invalid)
        let data: &[u8] = &[69, 4, 0, 1, 1, 0];
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        // Invalid mode → preserve as Unknown for lossless roundtrip
        assert!(matches!(cap, Capability::Unknown { code: 69, .. }));
    }

    #[test]
    fn add_path_mixed_valid_and_invalid_preserved_as_unknown() {
        // Two entries: valid IPv4/Unicast/Both + invalid AFI=99
        let mut data = bytes::BytesMut::new();
        data.put_u8(69); // code
        data.put_u8(8); // len = 2 * 4
        data.put_u16(1); // AFI IPv4
        data.put_u8(1); // SAFI Unicast
        data.put_u8(3); // Both (valid)
        data.put_u16(99); // AFI unknown
        data.put_u8(1); // SAFI Unicast
        data.put_u8(3); // Both
        let mut buf = data.freeze();
        let cap = Capability::decode(&mut buf).unwrap();
        // One invalid entry → entire capability preserved as Unknown
        assert!(matches!(cap, Capability::Unknown { code: 69, .. }));
    }
}
