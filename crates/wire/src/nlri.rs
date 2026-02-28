use std::fmt;
use std::net::Ipv4Addr;

use crate::error::DecodeError;

/// An IPv4 prefix (network address + prefix length).
///
/// Stored in canonical form: host bits are always zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv4Prefix {
    pub addr: Ipv4Addr,
    pub len: u8,
}

impl Ipv4Prefix {
    /// Create a new prefix, masking off host bits.
    #[must_use]
    pub fn new(addr: Ipv4Addr, len: u8) -> Self {
        let masked = if len == 0 {
            0
        } else if len >= 32 {
            u32::from(addr)
        } else {
            u32::from(addr) & !((1u32 << (32 - len)) - 1)
        };
        Self {
            addr: Ipv4Addr::from(masked),
            len,
        }
    }
}

impl fmt::Display for Ipv4Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

/// Decode a sequence of NLRI prefixes from wire format (RFC 4271 §4.3).
///
/// Each prefix is encoded as a length byte (0–32) followed by the minimum
/// number of address bytes (`ceil(len / 8)`).
///
/// # Errors
///
/// Returns `DecodeError` if a prefix length exceeds 32 or the buffer is
/// truncated mid-prefix.
pub fn decode_nlri(mut buf: &[u8]) -> Result<Vec<Ipv4Prefix>, DecodeError> {
    let mut prefixes = Vec::new();

    while !buf.is_empty() {
        let prefix_len = buf[0];
        buf = &buf[1..];

        if prefix_len > 32 {
            return Err(DecodeError::InvalidNetworkField {
                detail: format!("NLRI prefix length {prefix_len} exceeds 32"),
                data: buf.to_vec(),
            });
        }

        let byte_count = usize::from(prefix_len.div_ceil(8));
        if buf.len() < byte_count {
            return Err(DecodeError::Incomplete {
                needed: byte_count,
                available: buf.len(),
            });
        }

        let mut octets = [0u8; 4];
        octets[..byte_count].copy_from_slice(&buf[..byte_count]);
        buf = &buf[byte_count..];

        prefixes.push(Ipv4Prefix::new(Ipv4Addr::from(octets), prefix_len));
    }

    Ok(prefixes)
}

/// Encode a sequence of NLRI prefixes into wire format.
pub fn encode_nlri(prefixes: &[Ipv4Prefix], buf: &mut Vec<u8>) {
    for prefix in prefixes {
        buf.push(prefix.len);
        let byte_count = usize::from(prefix.len.div_ceil(8));
        let octets = prefix.addr.octets();
        buf.extend_from_slice(&octets[..byte_count]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_single_prefix() {
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        let mut buf = Vec::new();
        encode_nlri(&[prefix], &mut buf);
        let decoded = decode_nlri(&buf).unwrap();
        assert_eq!(decoded, vec![prefix]);
    }

    #[test]
    fn roundtrip_multiple_prefixes() {
        let prefixes = vec![
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8),
            Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24),
            Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 12),
        ];
        let mut buf = Vec::new();
        encode_nlri(&prefixes, &mut buf);
        let decoded = decode_nlri(&buf).unwrap();
        assert_eq!(decoded, prefixes);
    }

    #[test]
    fn prefix_len_zero() {
        let prefix = Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0);
        assert_eq!(prefix.addr, Ipv4Addr::UNSPECIFIED);
        let mut buf = Vec::new();
        encode_nlri(&[prefix], &mut buf);
        assert_eq!(buf, vec![0]); // just the length byte, no address bytes
        let decoded = decode_nlri(&buf).unwrap();
        assert_eq!(decoded, vec![prefix]);
    }

    #[test]
    fn prefix_len_32() {
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 1, 2, 3), 32);
        let mut buf = Vec::new();
        encode_nlri(&[prefix], &mut buf);
        assert_eq!(buf, vec![32, 10, 1, 2, 3]);
        let decoded = decode_nlri(&buf).unwrap();
        assert_eq!(decoded, vec![prefix]);
    }

    #[test]
    fn host_bits_masked() {
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 255), 24);
        assert_eq!(prefix.addr, Ipv4Addr::new(10, 0, 0, 0));
    }

    #[test]
    fn reject_prefix_len_exceeds_32() {
        let buf = [33, 10, 0, 0, 0];
        let err = decode_nlri(&buf).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));
        let (code, subcode, _) = err.to_notification();
        assert_eq!(code, crate::notification::NotificationCode::UpdateMessage);
        assert_eq!(subcode, 10);
    }

    #[test]
    fn reject_truncated_buffer() {
        // /24 needs 3 bytes but only 2 provided
        let buf = [24, 10, 0];
        let err = decode_nlri(&buf).unwrap_err();
        assert!(matches!(err, DecodeError::Incomplete { .. }));
    }

    #[test]
    fn empty_buffer_yields_empty_vec() {
        let decoded = decode_nlri(&[]).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn display_format() {
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        assert_eq!(format!("{prefix}"), "10.0.0.0/24");
    }

    #[test]
    fn wire_encoding_10_0_slash_24() {
        // 10.0.0.0/24 → [24, 10, 0, 0] (3 address bytes)
        let buf = [24, 10, 0, 0];
        let decoded = decode_nlri(&buf).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].addr, Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(decoded[0].len, 24);
    }

    #[test]
    fn wire_encoding_odd_prefix_len() {
        // 10.128.0.0/9 → [9, 10, 128] (2 address bytes)
        let buf = [9, 10, 128];
        let decoded = decode_nlri(&buf).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].addr, Ipv4Addr::new(10, 128, 0, 0));
        assert_eq!(decoded[0].len, 9);
    }
}
