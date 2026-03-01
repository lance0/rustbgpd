use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

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
    ///
    /// Prefix length is clamped to 32 (values above 32 are silently
    /// reduced). This is intentional: wire decoders validate prefix
    /// lengths before construction, and clamping is safer than panicking
    /// for internal callers that may compute lengths arithmetically.
    #[must_use]
    pub fn new(addr: Ipv4Addr, len: u8) -> Self {
        let len = len.min(32);
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
        let field_start = buf;
        let prefix_len = buf[0];
        buf = &buf[1..];

        if prefix_len > 32 {
            // Include the length byte + available address bytes in error data
            let addr_bytes = usize::from(prefix_len.div_ceil(8)).min(buf.len());
            return Err(DecodeError::InvalidNetworkField {
                detail: format!("NLRI prefix length {prefix_len} exceeds 32"),
                data: field_start[..=addr_bytes].to_vec(),
            });
        }

        let byte_count = usize::from(prefix_len.div_ceil(8));
        if buf.len() < byte_count {
            // Truncated NLRI is also an Invalid Network Field, not a header
            // framing error. Include the length byte + available bytes.
            return Err(DecodeError::InvalidNetworkField {
                detail: format!(
                    "NLRI truncated: prefix length {prefix_len} requires \
                     {byte_count} bytes, have {}",
                    buf.len()
                ),
                data: field_start[..=buf.len()].to_vec(),
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

/// An IPv6 prefix (network address + prefix length).
///
/// Stored in canonical form: host bits are always zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv6Prefix {
    pub addr: Ipv6Addr,
    pub len: u8,
}

impl Ipv6Prefix {
    /// Create a new prefix, masking off host bits.
    ///
    /// Prefix length is clamped to 128 (values above 128 are silently
    /// reduced). This is intentional: wire decoders validate prefix
    /// lengths before construction, and clamping is safer than panicking
    /// for internal callers that may compute lengths arithmetically.
    #[must_use]
    pub fn new(addr: Ipv6Addr, len: u8) -> Self {
        let len = len.min(128);
        let masked = if len == 0 {
            0u128
        } else if len >= 128 {
            u128::from(addr)
        } else {
            u128::from(addr) & !((1u128 << (128 - len)) - 1)
        };
        Self {
            addr: Ipv6Addr::from(masked),
            len,
        }
    }
}

impl fmt::Display for Ipv6Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

/// A prefix that can be either IPv4 or IPv6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Prefix {
    V4(Ipv4Prefix),
    V6(Ipv6Prefix),
}

impl Prefix {
    /// Return the network address as a string.
    #[must_use]
    pub fn addr_string(&self) -> String {
        match self {
            Self::V4(p) => p.addr.to_string(),
            Self::V6(p) => p.addr.to_string(),
        }
    }

    /// Return the prefix length.
    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        match self {
            Self::V4(p) => p.len,
            Self::V6(p) => p.len,
        }
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(p) => p.fmt(f),
            Self::V6(p) => p.fmt(f),
        }
    }
}

/// Decode a sequence of IPv6 NLRI prefixes from wire format.
///
/// Same encoding as IPv4 NLRI: length byte (0–128) followed by the minimum
/// number of address bytes (`ceil(len / 8)`) up to 16.
///
/// # Errors
///
/// Returns `DecodeError` if a prefix length exceeds 128 or the buffer is
/// truncated mid-prefix.
pub fn decode_ipv6_nlri(mut buf: &[u8]) -> Result<Vec<Ipv6Prefix>, DecodeError> {
    let mut prefixes = Vec::new();

    while !buf.is_empty() {
        let field_start = buf;
        let prefix_len = buf[0];
        buf = &buf[1..];

        if prefix_len > 128 {
            let addr_bytes = usize::from(prefix_len.div_ceil(8)).min(buf.len());
            return Err(DecodeError::InvalidNetworkField {
                detail: format!("NLRI prefix length {prefix_len} exceeds 128"),
                data: field_start[..=addr_bytes].to_vec(),
            });
        }

        let byte_count = usize::from(prefix_len.div_ceil(8));
        if buf.len() < byte_count {
            return Err(DecodeError::InvalidNetworkField {
                detail: format!(
                    "NLRI truncated: prefix length {prefix_len} requires \
                     {byte_count} bytes, have {}",
                    buf.len()
                ),
                data: field_start[..=buf.len()].to_vec(),
            });
        }

        let mut octets = [0u8; 16];
        octets[..byte_count].copy_from_slice(&buf[..byte_count]);
        buf = &buf[byte_count..];

        prefixes.push(Ipv6Prefix::new(Ipv6Addr::from(octets), prefix_len));
    }

    Ok(prefixes)
}

/// Encode a sequence of IPv6 NLRI prefixes into wire format.
pub fn encode_ipv6_nlri(prefixes: &[Ipv6Prefix], buf: &mut Vec<u8>) {
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
        let (code, subcode, data) = err.to_notification();
        assert_eq!(code, crate::notification::NotificationCode::UpdateMessage);
        assert_eq!(subcode, 10);
        // Error data includes the length byte + available address bytes
        assert_eq!(data.as_ref(), &[33, 10, 0, 0, 0]);
    }

    #[test]
    fn reject_truncated_buffer() {
        // /24 needs 3 bytes but only 2 provided
        let buf = [24, 10, 0];
        let err = decode_nlri(&buf).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));
        let (code, subcode, data) = err.to_notification();
        assert_eq!(code, crate::notification::NotificationCode::UpdateMessage);
        assert_eq!(subcode, 10);
        // Error data includes the length byte + available bytes
        assert_eq!(data.as_ref(), &[24, 10, 0]);
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

    // --- IPv6 prefix tests ---

    #[test]
    fn ipv6_prefix_new_masks_host_bits() {
        let prefix = Ipv6Prefix::new("2001:db8::ffff".parse().unwrap(), 32);
        assert_eq!(prefix.addr, "2001:db8::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(prefix.len, 32);
    }

    #[test]
    fn ipv6_prefix_len_zero() {
        let prefix = Ipv6Prefix::new(Ipv6Addr::UNSPECIFIED, 0);
        assert_eq!(prefix.addr, Ipv6Addr::UNSPECIFIED);
    }

    #[test]
    fn ipv6_prefix_len_128() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let prefix = Ipv6Prefix::new(addr, 128);
        assert_eq!(prefix.addr, addr);
        assert_eq!(prefix.len, 128);
    }

    #[test]
    fn ipv6_prefix_display() {
        let prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);
        assert_eq!(format!("{prefix}"), "2001:db8::/32");
    }

    #[test]
    fn ipv6_nlri_roundtrip_single() {
        let prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);
        let mut buf = Vec::new();
        encode_ipv6_nlri(&[prefix], &mut buf);
        let decoded = decode_ipv6_nlri(&buf).unwrap();
        assert_eq!(decoded, vec![prefix]);
    }

    #[test]
    fn ipv6_nlri_roundtrip_multiple() {
        let prefixes = vec![
            Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32),
            Ipv6Prefix::new("fd00::".parse().unwrap(), 64),
            Ipv6Prefix::new("::1".parse().unwrap(), 128),
        ];
        let mut buf = Vec::new();
        encode_ipv6_nlri(&prefixes, &mut buf);
        let decoded = decode_ipv6_nlri(&buf).unwrap();
        assert_eq!(decoded, prefixes);
    }

    #[test]
    fn ipv6_nlri_len_zero() {
        let prefix = Ipv6Prefix::new(Ipv6Addr::UNSPECIFIED, 0);
        let mut buf = Vec::new();
        encode_ipv6_nlri(&[prefix], &mut buf);
        assert_eq!(buf, vec![0]); // just the length byte
        let decoded = decode_ipv6_nlri(&buf).unwrap();
        assert_eq!(decoded, vec![prefix]);
    }

    #[test]
    fn ipv6_nlri_reject_exceeds_128() {
        let buf = [129, 0x20, 0x01];
        let err = decode_ipv6_nlri(&buf).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));
    }

    #[test]
    fn ipv6_nlri_reject_truncated() {
        // /64 needs 8 bytes but only 4 provided
        let buf = [64, 0x20, 0x01, 0x0d, 0xb8];
        let err = decode_ipv6_nlri(&buf).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));
    }

    #[test]
    fn ipv6_nlri_empty_buffer() {
        let decoded = decode_ipv6_nlri(&[]).unwrap();
        assert!(decoded.is_empty());
    }

    // --- Prefix enum tests ---

    #[test]
    fn prefix_display_v4() {
        let p = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
        assert_eq!(format!("{p}"), "10.0.0.0/24");
    }

    #[test]
    fn ipv4_prefix_clamps_length() {
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 33);
        assert_eq!(prefix.len, 32);
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 255);
        assert_eq!(prefix.len, 32);
    }

    #[test]
    fn ipv6_prefix_clamps_length() {
        let prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 129);
        assert_eq!(prefix.len, 128);
        let prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 200);
        assert_eq!(prefix.len, 128);
    }

    #[test]
    fn prefix_display_v6() {
        let p = Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32));
        assert_eq!(format!("{p}"), "2001:db8::/32");
    }
}
