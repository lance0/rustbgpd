//! RTR protocol (RFC 8210 / draft-ietf-sidrops-8210bis) PDU codec.
//!
//! Encode/decode for the RPKI-to-Router protocol, versions 1 and 2.
//! Version 2 adds ASPA PDU (type 11) support.
//! Used by [`super::rtr_client`] to communicate with RPKI cache validators.

use std::net::{Ipv4Addr, Ipv6Addr};

/// RTR protocol version 1 (RFC 8210).
pub const RTR_VERSION: u8 = 1;

/// RTR protocol version 2 (draft-ietf-sidrops-8210bis) — adds ASPA support.
pub const RTR_VERSION_2: u8 = 2;

/// RTR PDU types (client perspective).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtrPdu {
    /// Server → Client: cache has new data (type 0).
    SerialNotify {
        /// RTR session identifier.
        session_id: u16,
        /// Current serial number.
        serial: u32,
    },
    /// Client → Server: request incremental update (type 1).
    SerialQuery {
        /// RTR session identifier.
        session_id: u16,
        /// Last known serial number.
        serial: u32,
    },
    /// Client → Server: request full table (type 2).
    ResetQuery,
    /// Server → Client: start of data payload (type 3).
    CacheResponse {
        /// RTR session identifier.
        session_id: u16,
    },
    /// Server → Client: IPv4 VRP entry (type 4).
    Ipv4Prefix {
        /// 1 = announce, 0 = withdraw.
        flags: u8,
        /// Prefix length in bits.
        prefix_len: u8,
        /// Maximum prefix length for this ROA.
        max_len: u8,
        /// IPv4 prefix address.
        prefix: Ipv4Addr,
        /// Authorized origin ASN.
        asn: u32,
    },
    /// Server → Client: IPv6 VRP entry (type 6).
    Ipv6Prefix {
        /// 1 = announce, 0 = withdraw.
        flags: u8,
        /// Prefix length in bits.
        prefix_len: u8,
        /// Maximum prefix length for this ROA.
        max_len: u8,
        /// IPv6 prefix address.
        prefix: Ipv6Addr,
        /// Authorized origin ASN.
        asn: u32,
    },
    /// Server → Client: end of payload with serial + timers (type 7).
    EndOfData {
        /// RTR session identifier.
        session_id: u16,
        /// Serial number after this data set.
        serial: u32,
        /// Recommended refresh interval (seconds).
        refresh: u32,
        /// Recommended retry interval (seconds).
        retry: u32,
        /// Cache expiration interval (seconds).
        expire: u32,
    },
    /// Server → Client: cache unavailable, do full reset (type 8).
    CacheReset,
    /// Both directions: error report (type 10).
    ErrorReport {
        /// RTR error code.
        code: u16,
        /// Encapsulated erroneous PDU (may be empty).
        pdu: Vec<u8>,
        /// Human-readable error text.
        text: String,
    },
    /// Server → Client: ASPA record (type 11, RTR v2 only).
    Aspa {
        /// 1 = announce, 0 = withdraw.
        flags: u8,
        /// Customer ASN.
        customer_asn: u32,
        /// Authorized provider ASNs (sorted ascending).
        provider_asns: Vec<u32>,
    },
}

/// RTR decode errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RtrDecodeError {
    /// Need more bytes to complete the PDU.
    #[error("incomplete: need more bytes")]
    Incomplete,
    /// Unsupported RTR protocol version.
    #[error("invalid RTR version {0}")]
    InvalidVersion(u8),
    /// Unrecognized PDU type code.
    #[error("unknown RTR PDU type {0}")]
    InvalidType(u8),
    /// PDU length field does not match the expected size.
    #[error("invalid PDU length")]
    InvalidLength,
    /// Prefix length or max-length out of range.
    #[error("invalid prefix")]
    InvalidPrefix,
    /// Error report text is not valid UTF-8.
    #[error("invalid UTF-8 in error text")]
    Utf8Error,
}

// ── PDU type codes ───────────────────────────────────────────────

const PDU_SERIAL_NOTIFY: u8 = 0;
const PDU_SERIAL_QUERY: u8 = 1;
const PDU_RESET_QUERY: u8 = 2;
const PDU_CACHE_RESPONSE: u8 = 3;
const PDU_IPV4_PREFIX: u8 = 4;
const PDU_IPV6_PREFIX: u8 = 6;
const PDU_END_OF_DATA: u8 = 7;
const PDU_CACHE_RESET: u8 = 8;
const PDU_ERROR_REPORT: u8 = 10;
const PDU_ASPA: u8 = 11;

impl RtrPdu {
    /// Peek at a buffer to determine the total PDU length.
    ///
    /// Returns `None` if fewer than 8 bytes (minimum header) are available.
    #[must_use]
    pub fn peek_length(buf: &[u8]) -> Option<u32> {
        if buf.len() < 8 {
            return None;
        }
        Some(u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]))
    }

    /// Decode a single RTR PDU from a byte buffer.
    ///
    /// Returns the parsed PDU and number of bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `Incomplete` if more bytes are needed, or a specific error
    /// for malformed PDUs.
    #[expect(clippy::too_many_lines)]
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), RtrDecodeError> {
        if buf.len() < 8 {
            return Err(RtrDecodeError::Incomplete);
        }

        let version = buf[0];
        if version != RTR_VERSION && version != RTR_VERSION_2 {
            return Err(RtrDecodeError::InvalidVersion(version));
        }

        let pdu_type = buf[1];
        let session_id = u16::from_be_bytes([buf[2], buf[3]]);
        let length = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;

        if buf.len() < length {
            return Err(RtrDecodeError::Incomplete);
        }

        let pdu = match pdu_type {
            PDU_SERIAL_NOTIFY => {
                if length != 12 {
                    return Err(RtrDecodeError::InvalidLength);
                }
                let serial = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
                RtrPdu::SerialNotify { session_id, serial }
            }
            PDU_SERIAL_QUERY => {
                if length != 12 {
                    return Err(RtrDecodeError::InvalidLength);
                }
                let serial = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
                RtrPdu::SerialQuery { session_id, serial }
            }
            PDU_RESET_QUERY => {
                if length != 8 {
                    return Err(RtrDecodeError::InvalidLength);
                }
                RtrPdu::ResetQuery
            }
            PDU_CACHE_RESPONSE => {
                if length != 8 {
                    return Err(RtrDecodeError::InvalidLength);
                }
                RtrPdu::CacheResponse { session_id }
            }
            PDU_IPV4_PREFIX => {
                if length != 20 {
                    return Err(RtrDecodeError::InvalidLength);
                }
                let flags = buf[8];
                let prefix_len = buf[9];
                let max_len = buf[10];
                // buf[11] = zero
                let prefix = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
                let asn = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
                if prefix_len > 32 || max_len > 32 || max_len < prefix_len {
                    return Err(RtrDecodeError::InvalidPrefix);
                }
                RtrPdu::Ipv4Prefix {
                    flags,
                    prefix_len,
                    max_len,
                    prefix,
                    asn,
                }
            }
            PDU_IPV6_PREFIX => {
                if length != 32 {
                    return Err(RtrDecodeError::InvalidLength);
                }
                let flags = buf[8];
                let prefix_len = buf[9];
                let max_len = buf[10];
                // buf[11] = zero
                let mut addr_bytes = [0u8; 16];
                addr_bytes.copy_from_slice(&buf[12..28]);
                let prefix = Ipv6Addr::from(addr_bytes);
                let asn = u32::from_be_bytes([buf[28], buf[29], buf[30], buf[31]]);
                if prefix_len > 128 || max_len > 128 || max_len < prefix_len {
                    return Err(RtrDecodeError::InvalidPrefix);
                }
                RtrPdu::Ipv6Prefix {
                    flags,
                    prefix_len,
                    max_len,
                    prefix,
                    asn,
                }
            }
            PDU_END_OF_DATA => {
                if length != 24 {
                    return Err(RtrDecodeError::InvalidLength);
                }
                let serial = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
                let refresh = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
                let retry = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
                let expire = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]);
                RtrPdu::EndOfData {
                    session_id,
                    serial,
                    refresh,
                    retry,
                    expire,
                }
            }
            PDU_CACHE_RESET => {
                if length != 8 {
                    return Err(RtrDecodeError::InvalidLength);
                }
                RtrPdu::CacheReset
            }
            PDU_ERROR_REPORT => {
                if length < 16 {
                    return Err(RtrDecodeError::InvalidLength);
                }
                let err_code = session_id; // In Error Report, bytes 2-3 are the error code
                let encap_len = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]) as usize;
                if 16 + encap_len > length {
                    return Err(RtrDecodeError::InvalidLength);
                }
                let encap_pdu = buf[12..12 + encap_len].to_vec();
                let text_len_offset = 12 + encap_len;
                let text_len = u32::from_be_bytes([
                    buf[text_len_offset],
                    buf[text_len_offset + 1],
                    buf[text_len_offset + 2],
                    buf[text_len_offset + 3],
                ]) as usize;
                if text_len_offset + 4 + text_len != length {
                    return Err(RtrDecodeError::InvalidLength);
                }
                let text =
                    std::str::from_utf8(&buf[text_len_offset + 4..text_len_offset + 4 + text_len])
                        .map_err(|_| RtrDecodeError::Utf8Error)?
                        .to_string();
                RtrPdu::ErrorReport {
                    code: err_code,
                    pdu: encap_pdu,
                    text,
                }
            }
            PDU_ASPA => {
                if version != RTR_VERSION_2 {
                    return Err(RtrDecodeError::InvalidType(pdu_type));
                }
                // ASPA PDU: header(8) + flags(1) + zero(1) + provider_count(2) + customer_asn(4)
                //           + provider_asns(4 * count)
                if length < 16 {
                    return Err(RtrDecodeError::InvalidLength);
                }
                let flags = buf[8];
                // buf[9] = zero (AFI flags, reserved in current spec)
                let provider_count = u16::from_be_bytes([buf[10], buf[11]]) as usize;
                let customer_asn = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
                let expected_len = 16 + provider_count * 4;
                if length != expected_len {
                    return Err(RtrDecodeError::InvalidLength);
                }
                let mut provider_asns = Vec::with_capacity(provider_count);
                for i in 0..provider_count {
                    let offset = 16 + i * 4;
                    let asn = u32::from_be_bytes([
                        buf[offset],
                        buf[offset + 1],
                        buf[offset + 2],
                        buf[offset + 3],
                    ]);
                    provider_asns.push(asn);
                }
                RtrPdu::Aspa {
                    flags,
                    customer_asn,
                    provider_asns,
                }
            }
            _ => return Err(RtrDecodeError::InvalidType(pdu_type)),
        };

        Ok((pdu, length))
    }

    /// Encode this PDU into a byte buffer.
    #[expect(clippy::too_many_lines)]
    pub fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            RtrPdu::SerialNotify { session_id, serial } => {
                buf.push(RTR_VERSION);
                buf.push(PDU_SERIAL_NOTIFY);
                buf.extend_from_slice(&session_id.to_be_bytes());
                buf.extend_from_slice(&12u32.to_be_bytes());
                buf.extend_from_slice(&serial.to_be_bytes());
            }
            RtrPdu::SerialQuery { session_id, serial } => {
                buf.push(RTR_VERSION);
                buf.push(PDU_SERIAL_QUERY);
                buf.extend_from_slice(&session_id.to_be_bytes());
                buf.extend_from_slice(&12u32.to_be_bytes());
                buf.extend_from_slice(&serial.to_be_bytes());
            }
            RtrPdu::ResetQuery => {
                buf.push(RTR_VERSION);
                buf.push(PDU_RESET_QUERY);
                buf.extend_from_slice(&0u16.to_be_bytes());
                buf.extend_from_slice(&8u32.to_be_bytes());
            }
            RtrPdu::CacheResponse { session_id } => {
                buf.push(RTR_VERSION);
                buf.push(PDU_CACHE_RESPONSE);
                buf.extend_from_slice(&session_id.to_be_bytes());
                buf.extend_from_slice(&8u32.to_be_bytes());
            }
            RtrPdu::Ipv4Prefix {
                flags,
                prefix_len,
                max_len,
                prefix,
                asn,
            } => {
                buf.push(RTR_VERSION);
                buf.push(PDU_IPV4_PREFIX);
                buf.extend_from_slice(&0u16.to_be_bytes());
                buf.extend_from_slice(&20u32.to_be_bytes());
                buf.push(*flags);
                buf.push(*prefix_len);
                buf.push(*max_len);
                buf.push(0); // zero
                buf.extend_from_slice(&prefix.octets());
                buf.extend_from_slice(&asn.to_be_bytes());
            }
            RtrPdu::Ipv6Prefix {
                flags,
                prefix_len,
                max_len,
                prefix,
                asn,
            } => {
                buf.push(RTR_VERSION);
                buf.push(PDU_IPV6_PREFIX);
                buf.extend_from_slice(&0u16.to_be_bytes());
                buf.extend_from_slice(&32u32.to_be_bytes());
                buf.push(*flags);
                buf.push(*prefix_len);
                buf.push(*max_len);
                buf.push(0); // zero
                buf.extend_from_slice(&prefix.octets());
                buf.extend_from_slice(&asn.to_be_bytes());
            }
            RtrPdu::EndOfData {
                session_id,
                serial,
                refresh,
                retry,
                expire,
            } => {
                buf.push(RTR_VERSION);
                buf.push(PDU_END_OF_DATA);
                buf.extend_from_slice(&session_id.to_be_bytes());
                buf.extend_from_slice(&24u32.to_be_bytes());
                buf.extend_from_slice(&serial.to_be_bytes());
                buf.extend_from_slice(&refresh.to_be_bytes());
                buf.extend_from_slice(&retry.to_be_bytes());
                buf.extend_from_slice(&expire.to_be_bytes());
            }
            RtrPdu::CacheReset => {
                buf.push(RTR_VERSION);
                buf.push(PDU_CACHE_RESET);
                buf.extend_from_slice(&0u16.to_be_bytes());
                buf.extend_from_slice(&8u32.to_be_bytes());
            }
            RtrPdu::Aspa {
                flags,
                customer_asn,
                provider_asns,
            } => {
                #[expect(clippy::cast_possible_truncation)]
                let total_len = (16 + provider_asns.len() * 4) as u32;
                #[expect(clippy::cast_possible_truncation)]
                let provider_count = provider_asns.len() as u16;
                buf.push(RTR_VERSION_2);
                buf.push(PDU_ASPA);
                buf.extend_from_slice(&0u16.to_be_bytes()); // session_id / zero
                buf.extend_from_slice(&total_len.to_be_bytes());
                buf.push(*flags);
                buf.push(0); // AFI flags (zero / reserved)
                buf.extend_from_slice(&provider_count.to_be_bytes());
                buf.extend_from_slice(&customer_asn.to_be_bytes());
                for asn in provider_asns {
                    buf.extend_from_slice(&asn.to_be_bytes());
                }
            }
            RtrPdu::ErrorReport { code, pdu, text } => {
                let text_bytes = text.as_bytes();
                #[expect(clippy::cast_possible_truncation)]
                let total_len = (16 + pdu.len() + text_bytes.len()) as u32;
                buf.push(RTR_VERSION);
                buf.push(PDU_ERROR_REPORT);
                buf.extend_from_slice(&code.to_be_bytes());
                buf.extend_from_slice(&total_len.to_be_bytes());
                #[expect(clippy::cast_possible_truncation)]
                let encap_len = pdu.len() as u32;
                buf.extend_from_slice(&encap_len.to_be_bytes());
                buf.extend_from_slice(pdu);
                #[expect(clippy::cast_possible_truncation)]
                let text_len = text_bytes.len() as u32;
                buf.extend_from_slice(&text_len.to_be_bytes());
                buf.extend_from_slice(text_bytes);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(pdu: &RtrPdu) -> RtrPdu {
        let mut buf = Vec::new();
        pdu.encode(&mut buf);
        let (decoded, consumed) = RtrPdu::decode(&buf).unwrap();
        assert_eq!(consumed, buf.len());
        decoded
    }

    #[test]
    fn serial_notify_roundtrip() {
        let pdu = RtrPdu::SerialNotify {
            session_id: 42,
            serial: 12345,
        };
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn serial_query_roundtrip() {
        let pdu = RtrPdu::SerialQuery {
            session_id: 1,
            serial: 99,
        };
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn reset_query_roundtrip() {
        let pdu = RtrPdu::ResetQuery;
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn cache_response_roundtrip() {
        let pdu = RtrPdu::CacheResponse { session_id: 7 };
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn ipv4_prefix_roundtrip() {
        let pdu = RtrPdu::Ipv4Prefix {
            flags: 1,
            prefix_len: 24,
            max_len: 24,
            prefix: Ipv4Addr::new(10, 0, 0, 0),
            asn: 65001,
        };
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn ipv6_prefix_roundtrip() {
        let pdu = RtrPdu::Ipv6Prefix {
            flags: 0,
            prefix_len: 48,
            max_len: 64,
            prefix: "2001:db8::".parse().unwrap(),
            asn: 65002,
        };
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn end_of_data_roundtrip() {
        let pdu = RtrPdu::EndOfData {
            session_id: 5,
            serial: 100,
            refresh: 3600,
            retry: 600,
            expire: 7200,
        };
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn cache_reset_roundtrip() {
        let pdu = RtrPdu::CacheReset;
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn error_report_roundtrip() {
        let pdu = RtrPdu::ErrorReport {
            code: 2,
            pdu: vec![1, 2, 3, 4],
            text: "test error".to_string(),
        };
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn error_report_empty_pdu_and_text() {
        let pdu = RtrPdu::ErrorReport {
            code: 0,
            pdu: vec![],
            text: String::new(),
        };
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn ipv4_prefix_withdraw_flag() {
        let pdu = RtrPdu::Ipv4Prefix {
            flags: 0, // withdraw
            prefix_len: 16,
            max_len: 24,
            prefix: Ipv4Addr::new(192, 168, 0, 0),
            asn: 65000,
        };
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn peek_length_works() {
        let mut buf = Vec::new();
        RtrPdu::ResetQuery.encode(&mut buf);
        assert_eq!(RtrPdu::peek_length(&buf), Some(8));
    }

    #[test]
    fn peek_length_too_short() {
        assert_eq!(RtrPdu::peek_length(&[1, 2, 3]), None);
    }

    #[test]
    fn decode_incomplete_header() {
        assert_eq!(
            RtrPdu::decode(&[1, 0, 0]).unwrap_err(),
            RtrDecodeError::Incomplete
        );
    }

    #[test]
    fn decode_incomplete_body() {
        // Valid header saying 12 bytes total, but only 8 bytes provided
        let mut buf = Vec::new();
        RtrPdu::SerialNotify {
            session_id: 1,
            serial: 1,
        }
        .encode(&mut buf);
        assert_eq!(
            RtrPdu::decode(&buf[..8]).unwrap_err(),
            RtrDecodeError::Incomplete
        );
    }

    #[test]
    fn decode_invalid_version() {
        let buf = [0, 0, 0, 0, 0, 0, 0, 8]; // version 0
        assert_eq!(
            RtrPdu::decode(&buf).unwrap_err(),
            RtrDecodeError::InvalidVersion(0)
        );
    }

    #[test]
    fn decode_unknown_type() {
        let buf = [RTR_VERSION, 99, 0, 0, 0, 0, 0, 8];
        assert_eq!(
            RtrPdu::decode(&buf).unwrap_err(),
            RtrDecodeError::InvalidType(99)
        );
    }

    #[test]
    fn ipv4_prefix_invalid_prefix_len() {
        let mut buf = Vec::new();
        RtrPdu::Ipv4Prefix {
            flags: 1,
            prefix_len: 24,
            max_len: 24,
            prefix: Ipv4Addr::new(10, 0, 0, 0),
            asn: 65001,
        }
        .encode(&mut buf);
        // Corrupt prefix_len to 33
        buf[9] = 33;
        assert_eq!(
            RtrPdu::decode(&buf).unwrap_err(),
            RtrDecodeError::InvalidPrefix
        );
    }

    #[test]
    fn ipv4_prefix_max_len_less_than_prefix_len() {
        let mut buf = Vec::new();
        RtrPdu::Ipv4Prefix {
            flags: 1,
            prefix_len: 24,
            max_len: 24,
            prefix: Ipv4Addr::new(10, 0, 0, 0),
            asn: 65001,
        }
        .encode(&mut buf);
        // Set max_len=16, prefix_len=24 → invalid
        buf[10] = 16;
        assert_eq!(
            RtrPdu::decode(&buf).unwrap_err(),
            RtrDecodeError::InvalidPrefix
        );
    }

    #[test]
    fn serial_notify_wrong_length() {
        let buf = [RTR_VERSION, PDU_SERIAL_NOTIFY, 0, 0, 0, 0, 0, 8];
        assert_eq!(
            RtrPdu::decode(&buf).unwrap_err(),
            RtrDecodeError::InvalidLength
        );
    }

    #[test]
    fn multiple_pdus_in_buffer() {
        let mut buf = Vec::new();
        let pdu1 = RtrPdu::ResetQuery;
        let pdu2 = RtrPdu::CacheResponse { session_id: 42 };
        pdu1.encode(&mut buf);
        pdu2.encode(&mut buf);

        let (decoded1, consumed1) = RtrPdu::decode(&buf).unwrap();
        assert_eq!(decoded1, pdu1);
        let (decoded2, consumed2) = RtrPdu::decode(&buf[consumed1..]).unwrap();
        assert_eq!(decoded2, pdu2);
        assert_eq!(consumed1 + consumed2, buf.len());
    }

    #[test]
    fn aspa_roundtrip() {
        let pdu = RtrPdu::Aspa {
            flags: 1,
            customer_asn: 65001,
            provider_asns: vec![65002, 65003, 65004],
        };
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn aspa_withdraw_roundtrip() {
        let pdu = RtrPdu::Aspa {
            flags: 0,
            customer_asn: 65001,
            provider_asns: vec![65002],
        };
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn aspa_no_providers_roundtrip() {
        let pdu = RtrPdu::Aspa {
            flags: 1,
            customer_asn: 65001,
            provider_asns: vec![],
        };
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn aspa_encoded_as_v2() {
        let mut buf = Vec::new();
        RtrPdu::Aspa {
            flags: 1,
            customer_asn: 65001,
            provider_asns: vec![65002],
        }
        .encode(&mut buf);
        assert_eq!(buf[0], RTR_VERSION_2);
        assert_eq!(buf[1], PDU_ASPA);
    }

    #[test]
    fn aspa_rejected_on_v1() {
        let mut buf = Vec::new();
        RtrPdu::Aspa {
            flags: 1,
            customer_asn: 65001,
            provider_asns: vec![65002],
        }
        .encode(&mut buf);
        // Overwrite version to 1 — should be rejected
        buf[0] = RTR_VERSION;
        assert_eq!(
            RtrPdu::decode(&buf).unwrap_err(),
            RtrDecodeError::InvalidType(PDU_ASPA)
        );
    }

    #[test]
    fn aspa_invalid_length() {
        let mut buf = Vec::new();
        RtrPdu::Aspa {
            flags: 1,
            customer_asn: 65001,
            provider_asns: vec![65002],
        }
        .encode(&mut buf);
        // Corrupt length to wrong value
        let bad_len = 14u32.to_be_bytes();
        buf[4..8].copy_from_slice(&bad_len);
        assert_eq!(
            RtrPdu::decode(&buf).unwrap_err(),
            RtrDecodeError::InvalidLength
        );
    }

    #[test]
    fn v2_accepts_v1_pdus() {
        // A v2-speaking server can still send v1-format PDUs like CacheResponse
        // with version byte = 2
        let mut buf = Vec::new();
        buf.push(RTR_VERSION_2);
        buf.push(PDU_CACHE_RESPONSE);
        buf.extend_from_slice(&42u16.to_be_bytes());
        buf.extend_from_slice(&8u32.to_be_bytes());
        let (pdu, consumed) = RtrPdu::decode(&buf).unwrap();
        assert_eq!(consumed, 8);
        assert_eq!(pdu, RtrPdu::CacheResponse { session_id: 42 });
    }
}
