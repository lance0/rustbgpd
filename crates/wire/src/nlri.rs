use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::DecodeError;

/// An IPv4 NLRI entry with an optional Add-Path path ID (RFC 7911).
///
/// For non-Add-Path peers, `path_id` is always 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4NlriEntry {
    /// Add-Path path identifier (0 when Add-Path is not in use).
    pub path_id: u32,
    /// The IPv4 prefix.
    pub prefix: Ipv4Prefix,
}

/// A generic NLRI entry (IPv4 or IPv6) with an optional Add-Path path ID.
///
/// For non-Add-Path peers, `path_id` is always 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NlriEntry {
    /// Add-Path path identifier (0 when Add-Path is not in use).
    pub path_id: u32,
    /// The prefix (IPv4 or IPv6).
    pub prefix: Prefix,
}

/// An IPv4 prefix (network address + prefix length).
///
/// Stored in canonical form: host bits are always zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv4Prefix {
    /// Network address (host bits zeroed).
    pub addr: Ipv4Addr,
    /// Prefix length in bits (0–32).
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
    /// Network address (host bits zeroed).
    pub addr: Ipv6Addr,
    /// Prefix length in bits (0–128).
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
    /// IPv4 prefix.
    V4(Ipv4Prefix),
    /// IPv6 prefix.
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

/// Decode a sequence of Add-Path IPv4 NLRI entries (RFC 7911 §3).
///
/// Wire format: `[4-byte path_id BE][prefix_len][prefix_bytes...]` per entry.
///
/// # Errors
///
/// Returns `DecodeError` if the buffer is truncated or a prefix length exceeds 32.
pub fn decode_nlri_addpath(mut buf: &[u8]) -> Result<Vec<Ipv4NlriEntry>, DecodeError> {
    let mut entries = Vec::new();

    while !buf.is_empty() {
        if buf.len() < 5 {
            return Err(DecodeError::InvalidNetworkField {
                detail: format!(
                    "Add-Path NLRI truncated: need at least 5 bytes (path_id + prefix_len), have {}",
                    buf.len()
                ),
                data: buf.to_vec(),
            });
        }

        let path_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        buf = &buf[4..];

        let field_start = buf;
        let prefix_len = buf[0];
        buf = &buf[1..];

        if prefix_len > 32 {
            let addr_bytes = usize::from(prefix_len.div_ceil(8)).min(buf.len());
            return Err(DecodeError::InvalidNetworkField {
                detail: format!("NLRI prefix length {prefix_len} exceeds 32"),
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

        let mut octets = [0u8; 4];
        octets[..byte_count].copy_from_slice(&buf[..byte_count]);
        buf = &buf[byte_count..];

        entries.push(Ipv4NlriEntry {
            path_id,
            prefix: Ipv4Prefix::new(Ipv4Addr::from(octets), prefix_len),
        });
    }

    Ok(entries)
}

/// Encode a sequence of Add-Path IPv4 NLRI entries into wire format.
pub fn encode_nlri_addpath(entries: &[Ipv4NlriEntry], buf: &mut Vec<u8>) {
    for entry in entries {
        buf.extend_from_slice(&entry.path_id.to_be_bytes());
        buf.push(entry.prefix.len);
        let byte_count = usize::from(entry.prefix.len.div_ceil(8));
        let octets = entry.prefix.addr.octets();
        buf.extend_from_slice(&octets[..byte_count]);
    }
}

/// Decode a sequence of Add-Path IPv6 NLRI entries (RFC 7911 §3).
///
/// Wire format: `[4-byte path_id BE][prefix_len][prefix_bytes...]` per entry.
///
/// # Errors
///
/// Returns `DecodeError` if the buffer is truncated or a prefix length exceeds 128.
pub fn decode_ipv6_nlri_addpath(mut buf: &[u8]) -> Result<Vec<NlriEntry>, DecodeError> {
    let mut entries = Vec::new();

    while !buf.is_empty() {
        if buf.len() < 5 {
            return Err(DecodeError::InvalidNetworkField {
                detail: format!(
                    "Add-Path NLRI truncated: need at least 5 bytes (path_id + prefix_len), have {}",
                    buf.len()
                ),
                data: buf.to_vec(),
            });
        }

        let path_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        buf = &buf[4..];

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

        entries.push(NlriEntry {
            path_id,
            prefix: Prefix::V6(Ipv6Prefix::new(Ipv6Addr::from(octets), prefix_len)),
        });
    }

    Ok(entries)
}

/// Encode a sequence of Add-Path IPv6 NLRI entries into wire format.
pub fn encode_ipv6_nlri_addpath(entries: &[NlriEntry], buf: &mut Vec<u8>) {
    for entry in entries {
        buf.extend_from_slice(&entry.path_id.to_be_bytes());
        match entry.prefix {
            Prefix::V6(p) => {
                buf.push(p.len);
                let byte_count = usize::from(p.len.div_ceil(8));
                let octets = p.addr.octets();
                buf.extend_from_slice(&octets[..byte_count]);
            }
            Prefix::V4(p) => {
                buf.push(p.len);
                let byte_count = usize::from(p.len.div_ceil(8));
                let octets = p.addr.octets();
                buf.extend_from_slice(&octets[..byte_count]);
            }
        }
    }
}

/// Decode Add-Path IPv4 NLRI entries into generic `NlriEntry` (for `MP_REACH`/`MP_UNREACH`).
///
/// # Errors
///
/// Returns `DecodeError` if the buffer is truncated or a prefix length exceeds 32.
pub fn decode_nlri_addpath_generic(buf: &[u8]) -> Result<Vec<NlriEntry>, DecodeError> {
    decode_nlri_addpath(buf).map(|entries| {
        entries
            .into_iter()
            .map(|e| NlriEntry {
                path_id: e.path_id,
                prefix: Prefix::V4(e.prefix),
            })
            .collect()
    })
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

    // --- Add-Path IPv4 NLRI tests ---

    #[test]
    fn addpath_ipv4_roundtrip_single() {
        let entry = Ipv4NlriEntry {
            path_id: 42,
            prefix: Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        };
        let mut buf = Vec::new();
        encode_nlri_addpath(&[entry], &mut buf);
        let decoded = decode_nlri_addpath(&buf).unwrap();
        assert_eq!(decoded, vec![entry]);
    }

    #[test]
    fn addpath_ipv4_roundtrip_multiple() {
        let entries = vec![
            Ipv4NlriEntry {
                path_id: 1,
                prefix: Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8),
            },
            Ipv4NlriEntry {
                path_id: 2,
                prefix: Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24),
            },
            Ipv4NlriEntry {
                path_id: 0xFFFF_FFFF,
                prefix: Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 12),
            },
        ];
        let mut buf = Vec::new();
        encode_nlri_addpath(&entries, &mut buf);
        let decoded = decode_nlri_addpath(&buf).unwrap();
        assert_eq!(decoded, entries);
    }

    #[test]
    fn addpath_ipv4_empty() {
        let decoded = decode_nlri_addpath(&[]).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn addpath_ipv4_truncated_path_id() {
        // Only 3 bytes — not enough for a 4-byte path ID + prefix len
        let buf = [0, 0, 0];
        assert!(decode_nlri_addpath(&buf).is_err());
    }

    #[test]
    fn addpath_ipv4_prefix_len_exceeds_32() {
        // path_id=1, prefix_len=33
        let buf = [0, 0, 0, 1, 33, 10, 0, 0, 0, 0];
        assert!(decode_nlri_addpath(&buf).is_err());
    }

    #[test]
    fn addpath_ipv4_truncated_prefix() {
        // path_id=1, prefix_len=24, but only 2 address bytes (need 3)
        let buf = [0, 0, 0, 1, 24, 10, 0];
        assert!(decode_nlri_addpath(&buf).is_err());
    }

    #[test]
    fn addpath_ipv4_wire_format() {
        let entry = Ipv4NlriEntry {
            path_id: 1,
            prefix: Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        };
        let mut buf = Vec::new();
        encode_nlri_addpath(&[entry], &mut buf);
        // 4-byte path_id (BE) + 1-byte len + 3-byte addr
        assert_eq!(buf, vec![0, 0, 0, 1, 24, 10, 0, 0]);
    }

    // --- Add-Path IPv6 NLRI tests ---

    #[test]
    fn addpath_ipv6_roundtrip_single() {
        let entry = NlriEntry {
            path_id: 7,
            prefix: Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32)),
        };
        let mut buf = Vec::new();
        encode_ipv6_nlri_addpath(&[entry], &mut buf);
        let decoded = decode_ipv6_nlri_addpath(&buf).unwrap();
        assert_eq!(decoded, vec![entry]);
    }

    #[test]
    fn addpath_ipv6_roundtrip_multiple() {
        let entries = vec![
            NlriEntry {
                path_id: 1,
                prefix: Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32)),
            },
            NlriEntry {
                path_id: 2,
                prefix: Prefix::V6(Ipv6Prefix::new("fd00::".parse().unwrap(), 64)),
            },
        ];
        let mut buf = Vec::new();
        encode_ipv6_nlri_addpath(&entries, &mut buf);
        let decoded = decode_ipv6_nlri_addpath(&buf).unwrap();
        assert_eq!(decoded, entries);
    }

    #[test]
    fn addpath_ipv6_empty() {
        let decoded = decode_ipv6_nlri_addpath(&[]).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn addpath_ipv6_truncated() {
        let buf = [0, 0, 0];
        assert!(decode_ipv6_nlri_addpath(&buf).is_err());
    }

    #[test]
    fn addpath_generic_ipv4_roundtrip() {
        let entries = vec![Ipv4NlriEntry {
            path_id: 1,
            prefix: Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        }];
        let mut buf = Vec::new();
        encode_nlri_addpath(&entries, &mut buf);
        let generic = decode_nlri_addpath_generic(&buf).unwrap();
        assert_eq!(generic.len(), 1);
        assert_eq!(generic[0].path_id, 1);
        assert_eq!(
            generic[0].prefix,
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24))
        );
    }
}
