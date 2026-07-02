//! IPv4/IPv6 labeled-unicast NLRI codec (RFC 8277, SAFI 4).
//!
//! Pure codec pieces for the labeled-unicast wire layout
//! `len | label stack | prefix` — the SAFI 128 VPN layout from
//! [`crate::vpn`] minus the 8-byte Route Distinguisher — in both
//! announce mode (BOS-terminated label stack) and RFC 8277 §2.4
//! withdraw mode (a single 3-octet compatibility field, or a GoBGP-style
//! echo of the announced label stack; ignored either way).
//!
//! MP_REACH/MP_UNREACH dispatch in [`crate::attribute`] accepts SAFI 4
//! and routes announce/withdraw NLRI (plain and RFC 7911 Add-Path forms)
//! through this codec. Route identity is the IP prefix alone (RFC 8277
//! §2.3 implicit-replace is per-prefix); the label stack is route data,
//! matching the SAFI 128 decision.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{DecodeError, EncodeError};
use crate::nlri::{Ipv4Prefix, Ipv6Prefix, Prefix};
use crate::vpn::{
    MPLS_LABEL_ENTRY_BITS, MplsLabelEntry, VPN_WITHDRAW_COMPATIBILITY, decode_label_stack,
    encode_label_stack, split_withdraw_label_field, validate_label_stack,
};

/// Address family carried by a labeled-unicast NLRI.
///
/// Display strings follow the ADR-0077 §8 / `OpenConfig` identity names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LabeledAddressFamily {
    /// IPv4 labeled-unicast, AFI 1 / SAFI 4.
    V4,
    /// IPv6 labeled-unicast, AFI 2 / SAFI 4.
    V6,
}

impl LabeledAddressFamily {
    const fn max_prefix_len(self) -> u8 {
        match self {
            Self::V4 => 32,
            Self::V6 => 128,
        }
    }
}

impl fmt::Display for LabeledAddressFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4 => write!(f, "ipv4_labeled_unicast"),
            Self::V6 => write!(f, "ipv6_labeled_unicast"),
        }
    }
}

/// One IPv4/IPv6 labeled-unicast NLRI (RFC 8277 §2).
///
/// The prefix is an ordinary unicast [`Prefix`] — this family *is* IP
/// prefixes — but labeled routes never enter the unicast RIB maps: the
/// RIB layer wraps the prefix in a labeled-specific key (ADR-0077 §2
/// scopes "do not extend `Prefix`" to route *keys*, not payloads).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LabeledNlri {
    /// MPLS label stack bound to the prefix (route data, not identity).
    pub labels: Vec<MplsLabelEntry>,
    /// The IP prefix.
    pub prefix: Prefix,
}

/// A labeled-unicast NLRI with an optional Add-Path path ID (RFC 7911).
///
/// For non-Add-Path peers, `path_id` is always 0. Mirrors the VPN
/// [`crate::vpn::VpnNlriEntry`] shape: the 4-octet Path Identifier is
/// prepended to the entire NLRI (length octet included) on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LabeledNlriEntry {
    /// Add-Path path identifier (0 when Add-Path is not in use).
    pub path_id: u32,
    /// The labeled-unicast NLRI.
    pub nlri: LabeledNlri,
}

impl LabeledNlri {
    /// Return the route-key identity for this NLRI: the prefix alone.
    /// Labels are route data (RFC 8277 §2.3 implicit-replace is
    /// per-prefix), matching the SAFI 128 VPN decision.
    #[must_use]
    pub const fn key(&self) -> Prefix {
        self.prefix
    }

    /// Return the labeled address family, derived from the prefix.
    #[must_use]
    pub const fn family(&self) -> LabeledAddressFamily {
        match self.prefix {
            Prefix::V4(_) => LabeledAddressFamily::V4,
            Prefix::V6(_) => LabeledAddressFamily::V6,
        }
    }

    fn validate_for_family(&self, family: LabeledAddressFamily) -> Result<(), EncodeError> {
        if self.family() != family {
            return Err(EncodeError::ValueOutOfRange {
                field: "labeled-unicast NLRI family",
                value: self.family().to_string(),
            });
        }
        validate_label_stack(&self.labels)?;
        let total_bits = total_labeled_nlri_bits(self.labels.len(), self.prefix.prefix_len());
        if total_bits > u16::from(u8::MAX) {
            return Err(EncodeError::ValueOutOfRange {
                field: "labeled-unicast NLRI length bits",
                value: total_bits.to_string(),
            });
        }
        Ok(())
    }
}

/// Decode announce-mode labeled-unicast NLRI bytes for the selected family
/// (`MP_REACH_NLRI`, RFC 8277 §2.2): per entry, a one-octet bit length, a
/// BOS-terminated label stack, then the prefix.
///
/// # Errors
///
/// Returns [`DecodeError`] for malformed length, label stack, or prefix
/// encodings.
pub fn decode_labeled_nlri(
    mut buf: &[u8],
    family: LabeledAddressFamily,
) -> Result<Vec<LabeledNlri>, DecodeError> {
    let mut entries = Vec::new();

    while !buf.is_empty() {
        let field_start = buf;
        let total_len_bits = buf[0];
        buf = &buf[1..];
        let value_len = usize::from(total_len_bits.div_ceil(8));

        if buf.len() < value_len {
            return invalid_labeled_nlri(
                format!(
                    "{family} NLRI truncated: length {total_len_bits} bits requires {value_len} bytes, have {}",
                    buf.len()
                ),
                field_start,
                1 + buf.len(),
            );
        }

        let value = &buf[..value_len];
        buf = &buf[value_len..];

        entries.push(decode_one_labeled_nlri(
            value,
            total_len_bits,
            family,
            field_start,
        )?);
    }

    Ok(entries)
}

/// Encode announce-mode labeled-unicast NLRI bytes for the selected family.
///
/// On error, `buf` is restored to its original length.
///
/// # Errors
///
/// Returns [`EncodeError`] if an entry belongs to the wrong family, its
/// label stack is invalid, or its encoded length cannot fit in the
/// one-octet NLRI length.
pub fn encode_labeled_nlri(
    entries: &[LabeledNlri],
    family: LabeledAddressFamily,
    buf: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let start_len = buf.len();

    for entry in entries {
        if let Err(err) = encode_one_labeled_nlri(entry, family, buf) {
            buf.truncate(start_len);
            return Err(err);
        }
    }

    Ok(())
}

/// Decode withdraw-mode labeled-unicast NLRI bytes (`MP_UNREACH_NLRI`).
///
/// Per RFC 8277 §2.4 a withdrawn labeled-unicast NLRI carries a single
/// 3-octet compatibility field in the label position — but `GoBGP` (and any
/// stack without a dedicated withdraw encoder) echoes the announced
/// BOS-terminated label stack instead, so the label position is dispatched
/// per the shared `split_withdraw_label_field` dispatch in `crate::vpn`: an exact compatibility
/// value (0x800000 or 0x000000) is one field, anything else is S-bit-walked
/// like announce mode. Labels are ignored either way; decoded entries have
/// an empty `labels` vec.
///
/// # Errors
///
/// Returns [`DecodeError`] for malformed length or prefix encodings.
pub fn decode_labeled_withdraw_nlri(
    mut buf: &[u8],
    family: LabeledAddressFamily,
) -> Result<Vec<LabeledNlri>, DecodeError> {
    let mut entries = Vec::new();

    while !buf.is_empty() {
        let field_start = buf;
        let total_len_bits = buf[0];
        buf = &buf[1..];
        let value_len = usize::from(total_len_bits.div_ceil(8));

        if buf.len() < value_len {
            return invalid_labeled_nlri(
                format!(
                    "{family} withdraw NLRI truncated: length {total_len_bits} bits requires {value_len} bytes, have {}",
                    buf.len()
                ),
                field_start,
                1 + buf.len(),
            );
        }

        let value = &buf[..value_len];
        buf = &buf[value_len..];

        entries.push(decode_one_labeled_withdraw_nlri(
            value,
            total_len_bits,
            family,
            field_start,
        )?);
    }

    Ok(entries)
}

/// Encode withdraw-mode labeled-unicast NLRI bytes (`MP_UNREACH_NLRI`).
///
/// Writes the RFC 8277 §2.4 3-octet compatibility value 0x800000 in the
/// label position and ignores each entry's `labels`. On error, `buf` is
/// restored to its original length.
///
/// # Errors
///
/// Returns [`EncodeError`] if an entry belongs to the wrong family.
pub fn encode_labeled_withdraw_nlri(
    entries: &[LabeledNlri],
    family: LabeledAddressFamily,
    buf: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let start_len = buf.len();

    for entry in entries {
        if entry.family() != family {
            buf.truncate(start_len);
            return Err(EncodeError::ValueOutOfRange {
                field: "labeled-unicast NLRI family",
                value: entry.family().to_string(),
            });
        }
        // One compatibility field + prefix always fits in u8:
        // 24 + at most 128 = 152 bits.
        let total_bits = MPLS_LABEL_ENTRY_BITS + entry.prefix.prefix_len();
        buf.push(total_bits);
        buf.extend_from_slice(&VPN_WITHDRAW_COMPATIBILITY);
        push_prefix_octets(&entry.prefix, buf);
    }

    Ok(())
}

/// Decode Add-Path labeled-unicast NLRI bytes (RFC 7911 §3).
///
/// Wire format per entry: `[4-byte path_id BE]` prepended to the ordinary
/// RFC 8277 NLRI (`len | label stack | prefix`).
///
/// # Errors
///
/// Returns [`DecodeError`] for a truncated path ID or malformed length,
/// label stack, or prefix encodings.
pub fn decode_labeled_nlri_addpath(
    mut buf: &[u8],
    family: LabeledAddressFamily,
) -> Result<Vec<LabeledNlriEntry>, DecodeError> {
    let mut entries = Vec::new();

    while !buf.is_empty() {
        let (path_id, rest) = split_labeled_path_id(buf, family)?;
        buf = rest;

        let field_start = buf;
        let (value, total_len_bits, rest) = split_labeled_nlri_value(buf, family, "NLRI")?;
        buf = rest;

        entries.push(LabeledNlriEntry {
            path_id,
            nlri: decode_one_labeled_nlri(value, total_len_bits, family, field_start)?,
        });
    }

    Ok(entries)
}

/// Decode Add-Path withdraw-mode labeled-unicast NLRI bytes
/// (`MP_UNREACH_NLRI`, RFC 7911 §3 + RFC 8277 §2.4).
///
/// The 4-octet Path Identifier is prepended to the whole withdraw-mode NLRI:
/// `path_id(4) | len | label field | prefix`. The label field is dispatched
/// (compatibility value or echoed stack) and ignored, exactly as in
/// [`decode_labeled_withdraw_nlri`]. Decoded entries have an empty `labels`
/// vec.
///
/// # Errors
///
/// Returns [`DecodeError`] for a truncated path ID or malformed length or
/// prefix encodings.
pub fn decode_labeled_withdraw_nlri_addpath(
    mut buf: &[u8],
    family: LabeledAddressFamily,
) -> Result<Vec<LabeledNlriEntry>, DecodeError> {
    let mut entries = Vec::new();

    while !buf.is_empty() {
        let (path_id, rest) = split_labeled_path_id(buf, family)?;
        buf = rest;

        let field_start = buf;
        let (value, total_len_bits, rest) = split_labeled_nlri_value(buf, family, "withdraw NLRI")?;
        buf = rest;

        entries.push(LabeledNlriEntry {
            path_id,
            nlri: decode_one_labeled_withdraw_nlri(value, total_len_bits, family, field_start)?,
        });
    }

    Ok(entries)
}

/// Split a 4-octet RFC 7911 Path Identifier off the front of `buf`.
fn split_labeled_path_id(
    buf: &[u8],
    family: LabeledAddressFamily,
) -> Result<(u32, &[u8]), DecodeError> {
    if buf.len() < 5 {
        return invalid_labeled_nlri(
            format!(
                "{family} Add-Path NLRI truncated: need at least 5 bytes (path_id + length), have {}",
                buf.len()
            ),
            buf,
            buf.len(),
        );
    }
    let path_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    Ok((path_id, &buf[4..]))
}

/// Split one length-prefixed NLRI value off the front of `buf`, returning
/// `(value, total_len_bits, rest)`.
fn split_labeled_nlri_value<'a>(
    buf: &'a [u8],
    family: LabeledAddressFamily,
    kind: &str,
) -> Result<(&'a [u8], u8, &'a [u8]), DecodeError> {
    let total_len_bits = buf[0];
    let rest = &buf[1..];
    let value_len = usize::from(total_len_bits.div_ceil(8));

    if rest.len() < value_len {
        return invalid_labeled_nlri(
            format!(
                "{family} {kind} truncated: length {total_len_bits} bits requires {value_len} bytes, have {}",
                rest.len()
            ),
            buf,
            1 + rest.len(),
        );
    }

    Ok((&rest[..value_len], total_len_bits, &rest[value_len..]))
}

/// Encode Add-Path labeled-unicast NLRI bytes (RFC 7911 §3): each entry's
/// 4-octet path ID is prepended to the ordinary RFC 8277 NLRI encoding.
///
/// On error, `buf` is restored to its original length.
///
/// # Errors
///
/// Returns [`EncodeError`] if an entry belongs to the wrong family, its label
/// stack is invalid, or its encoded length cannot fit in the one-octet NLRI
/// length.
pub fn encode_labeled_nlri_addpath(
    entries: &[LabeledNlriEntry],
    family: LabeledAddressFamily,
    buf: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let start_len = buf.len();

    for entry in entries {
        buf.extend_from_slice(&entry.path_id.to_be_bytes());
        if let Err(err) = encode_one_labeled_nlri(&entry.nlri, family, buf) {
            buf.truncate(start_len);
            return Err(err);
        }
    }

    Ok(())
}

/// Encode Add-Path withdraw-mode labeled-unicast NLRI bytes
/// (`MP_UNREACH_NLRI`, RFC 7911 §3 + RFC 8277 §2.4): each entry's 4-octet
/// path ID is prepended to the withdraw-mode NLRI (compatibility field
/// 0x800000 in the label position; each entry's `labels` are ignored).
///
/// On error, `buf` is restored to its original length.
///
/// # Errors
///
/// Returns [`EncodeError`] if an entry belongs to the wrong family.
pub fn encode_labeled_withdraw_nlri_addpath(
    entries: &[LabeledNlriEntry],
    family: LabeledAddressFamily,
    buf: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let start_len = buf.len();

    for entry in entries {
        buf.extend_from_slice(&entry.path_id.to_be_bytes());
        if let Err(err) =
            encode_labeled_withdraw_nlri(std::slice::from_ref(&entry.nlri), family, buf)
        {
            buf.truncate(start_len);
            return Err(err);
        }
    }

    Ok(())
}

fn decode_one_labeled_nlri(
    value: &[u8],
    total_len_bits: u8,
    family: LabeledAddressFamily,
    field_start: &[u8],
) -> Result<LabeledNlri, DecodeError> {
    let (labels, label_octets, label_bits) =
        decode_label_stack(value, total_len_bits, family, field_start)?;

    // The stack loop only consumes an entry when at least 24 more bits fit
    // in `total_len_bits`, so `label_bits <= total_len_bits` always holds
    // and this subtraction cannot underflow.
    let prefix_len = total_len_bits - label_bits;
    if prefix_len > family.max_prefix_len() {
        return invalid_labeled_nlri(
            format!(
                "{family} prefix length {prefix_len} exceeds {}",
                family.max_prefix_len()
            ),
            field_start,
            1 + value.len(),
        );
    }

    let prefix_octets = usize::from(prefix_len.div_ceil(8));
    let prefix_end = label_octets + prefix_octets;
    if value.len() < prefix_end {
        return invalid_labeled_nlri(
            format!("{family} NLRI truncated before prefix"),
            field_start,
            1 + value.len(),
        );
    }

    let prefix = decode_labeled_prefix(family, prefix_len, &value[label_octets..prefix_end]);
    Ok(LabeledNlri { labels, prefix })
}

fn decode_one_labeled_withdraw_nlri(
    value: &[u8],
    total_len_bits: u8,
    family: LabeledAddressFamily,
    field_start: &[u8],
) -> Result<LabeledNlri, DecodeError> {
    if total_len_bits < MPLS_LABEL_ENTRY_BITS {
        return invalid_labeled_nlri(
            format!(
                "{family} withdraw NLRI length {total_len_bits} bits is shorter than the compatibility field"
            ),
            field_start,
            1 + value.len(),
        );
    }

    let (label_octets, label_bits) =
        split_withdraw_label_field(value, total_len_bits, family, field_start)?;

    // The dispatch only consumes bits that fit in `total_len_bits`, so this
    // subtraction cannot underflow.
    let prefix_len = total_len_bits - label_bits;
    if prefix_len > family.max_prefix_len() {
        return invalid_labeled_nlri(
            format!(
                "{family} prefix length {prefix_len} exceeds {}",
                family.max_prefix_len()
            ),
            field_start,
            1 + value.len(),
        );
    }

    let prefix_octets = usize::from(prefix_len.div_ceil(8));
    let prefix_end = label_octets + prefix_octets;
    if value.len() < prefix_end {
        return invalid_labeled_nlri(
            format!("{family} withdraw NLRI truncated before prefix"),
            field_start,
            1 + value.len(),
        );
    }

    let prefix = decode_labeled_prefix(family, prefix_len, &value[label_octets..prefix_end]);
    Ok(LabeledNlri {
        labels: vec![],
        prefix,
    })
}

/// Build a canonical [`Prefix`] from wire bytes; `Ipv4Prefix::new` /
/// `Ipv6Prefix::new` mask host bits. `bytes` is exactly
/// `ceil(len / 8)` long (callers slice it that way after bounds checks).
fn decode_labeled_prefix(family: LabeledAddressFamily, len: u8, bytes: &[u8]) -> Prefix {
    match family {
        LabeledAddressFamily::V4 => {
            let mut octets = [0u8; 4];
            octets[..bytes.len()].copy_from_slice(bytes);
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(octets), len))
        }
        LabeledAddressFamily::V6 => {
            let mut octets = [0u8; 16];
            octets[..bytes.len()].copy_from_slice(bytes);
            Prefix::V6(Ipv6Prefix::new(Ipv6Addr::from(octets), len))
        }
    }
}

fn encode_one_labeled_nlri(
    entry: &LabeledNlri,
    family: LabeledAddressFamily,
    buf: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    entry.validate_for_family(family)?;
    let total_bits = total_labeled_nlri_bits(entry.labels.len(), entry.prefix.prefix_len());
    let total_bits_u8 = u8::try_from(total_bits).map_err(|_| EncodeError::ValueOutOfRange {
        field: "labeled-unicast NLRI length bits",
        value: total_bits.to_string(),
    })?;
    buf.push(total_bits_u8);
    encode_label_stack(&entry.labels, buf)?;
    push_prefix_octets(&entry.prefix, buf);
    Ok(())
}

fn push_prefix_octets(prefix: &Prefix, buf: &mut Vec<u8>) {
    let byte_count = usize::from(prefix.prefix_len().div_ceil(8));
    match prefix {
        Prefix::V4(p) => buf.extend_from_slice(&p.addr.octets()[..byte_count]),
        Prefix::V6(p) => buf.extend_from_slice(&p.addr.octets()[..byte_count]),
    }
}

fn total_labeled_nlri_bits(label_count: usize, prefix_len: u8) -> u16 {
    // Saturate like the VPN sibling: an extreme label_count saturates to
    // u16::MAX and callers reject any total > u8::MAX downstream.
    u16::try_from(label_count)
        .unwrap_or(u16::MAX)
        .saturating_mul(u16::from(MPLS_LABEL_ENTRY_BITS))
        .saturating_add(u16::from(prefix_len))
}

fn invalid_labeled_nlri<T>(detail: String, data: &[u8], len: usize) -> Result<T, DecodeError> {
    Err(DecodeError::InvalidNetworkField {
        detail,
        data: data[..len.min(data.len())].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label(value: u32, bos: bool) -> MplsLabelEntry {
        MplsLabelEntry::try_new(value, 0, bos).unwrap()
    }

    fn v4(addr: [u8; 4], len: u8) -> Prefix {
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(addr), len))
    }

    #[test]
    fn labeled_v4_single_label_roundtrip() {
        let entry = LabeledNlri {
            labels: vec![label(200, true)],
            prefix: v4([10, 0, 1, 0], 24),
        };
        let mut buf = Vec::new();
        encode_labeled_nlri(
            std::slice::from_ref(&entry),
            LabeledAddressFamily::V4,
            &mut buf,
        )
        .unwrap();
        assert_eq!(buf[0], 24 + 24);

        let decoded = decode_labeled_nlri(&buf, LabeledAddressFamily::V4).unwrap();
        assert_eq!(decoded, vec![entry]);
        assert_eq!(decoded[0].prefix.to_string(), "10.0.1.0/24");
    }

    #[test]
    fn labeled_v6_multi_label_roundtrip() {
        let prefix = Prefix::V6(Ipv6Prefix::new("2001:db8:100::".parse().unwrap(), 48));
        let entry = LabeledNlri {
            labels: vec![label(16_000, false), label(24_000, true)],
            prefix,
        };
        let mut buf = Vec::new();
        encode_labeled_nlri(
            std::slice::from_ref(&entry),
            LabeledAddressFamily::V6,
            &mut buf,
        )
        .unwrap();
        assert_eq!(buf[0], 48 + 48);

        let decoded = decode_labeled_nlri(&buf, LabeledAddressFamily::V6).unwrap();
        assert_eq!(decoded, vec![entry]);
        assert_eq!(decoded[0].prefix.to_string(), "2001:db8:100::/48");
    }

    #[test]
    fn multiple_nlri_preserve_order() {
        let a = LabeledNlri {
            labels: vec![label(100, true)],
            prefix: v4([10, 0, 0, 0], 8),
        };
        let b = LabeledNlri {
            labels: vec![label(101, true)],
            prefix: v4([192, 0, 2, 0], 24),
        };
        let mut buf = Vec::new();
        encode_labeled_nlri(&[a.clone(), b.clone()], LabeledAddressFamily::V4, &mut buf).unwrap();
        assert_eq!(
            decode_labeled_nlri(&buf, LabeledAddressFamily::V4).unwrap(),
            vec![a, b]
        );
    }

    /// GoBGP-shaped fixture, hand-derived from the RFC 8277 §2.2 wire
    /// layout (`GoBGP`'s `LabeledIPAddrPrefix` encodes `-a ipv4-labeled`
    /// NLRI the same way: Length = label-stack bits + mask length):
    /// len = 48 bits, label 100 (TC 0, S=1) = 0x000641, 10.0.1.0/24.
    #[test]
    fn labeled_v4_gobgp_shaped_fixture() {
        let buf = vec![
            0x30, // 48 bits = 24 label + 24 prefix
            0x00, 0x06, 0x41, // label 100, TC 0, S=1
            10, 0, 1, // 10.0.1.0/24
        ];
        let decoded = decode_labeled_nlri(&buf, LabeledAddressFamily::V4).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].labels, vec![label(100, true)]);
        assert_eq!(decoded[0].prefix.to_string(), "10.0.1.0/24");

        let mut reencoded = Vec::new();
        encode_labeled_nlri(&decoded, LabeledAddressFamily::V4, &mut reencoded).unwrap();
        assert_eq!(reencoded, buf);
    }

    #[test]
    fn route_key_excludes_label_stack() {
        let prefix = v4([203, 0, 113, 0], 24);
        let a = LabeledNlri {
            labels: vec![label(100, true)],
            prefix,
        };
        let b = LabeledNlri {
            labels: vec![label(200, true)],
            prefix,
        };
        assert_eq!(a.key(), b.key());
        assert_ne!(a, b);
    }

    #[test]
    fn withdraw_encode_emits_compatibility_value_and_ignores_labels() {
        let entry = LabeledNlri {
            labels: vec![label(200, true)], // ignored on withdraw encode
            prefix: v4([10, 0, 1, 0], 24),
        };
        let mut buf = Vec::new();
        encode_labeled_withdraw_nlri(
            std::slice::from_ref(&entry),
            LabeledAddressFamily::V4,
            &mut buf,
        )
        .unwrap();
        assert_eq!(buf[0], 24 + 24);
        assert_eq!(&buf[1..4], &VPN_WITHDRAW_COMPATIBILITY);

        let decoded = decode_labeled_withdraw_nlri(&buf, LabeledAddressFamily::V4).unwrap();
        assert_eq!(decoded.len(), 1);
        assert!(decoded[0].labels.is_empty());
        assert_eq!(decoded[0].prefix, entry.prefix);
    }

    #[test]
    fn withdraw_decode_accepts_zero_compatibility_value() {
        // GoBGP's ZERO_LABEL: some stacks zero the withdraw label field.
        // 0x000000 has S=0, so an S-bit walk would overrun — it must be
        // taken as a single compatibility field.
        let buf = vec![24 + 24, 0x00, 0x00, 0x00, 10, 0, 1];
        let decoded = decode_labeled_withdraw_nlri(&buf, LabeledAddressFamily::V4).unwrap();
        assert_eq!(decoded.len(), 1);
        assert!(decoded[0].labels.is_empty());
        assert_eq!(decoded[0].prefix, v4([10, 0, 1, 0], 24));
    }

    /// Exact wire bytes from the M79 lab: `GoBGP` has no withdraw-mode
    /// encoder and echoes the announced label stack (801, 802) verbatim.
    /// The old single-compatibility-field parse computed prefix length
    /// 72 − 24 = 48 > 32 → NOTIFICATION 3/10 → session reset.
    #[test]
    fn withdraw_decode_m79_gobgp_label_stack_echo() {
        let buf = vec![
            0x48, // 72 bits = 2×24 label + 24 prefix
            0x00, 0x32, 0x10, // label 801, S=0
            0x00, 0x32, 0x21, // label 802, S=1
            0xC6, 0x33, 0x65, // 198.51.101.0/24
        ];
        let decoded = decode_labeled_withdraw_nlri(&buf, LabeledAddressFamily::V4).unwrap();
        assert_eq!(decoded.len(), 1);
        assert!(decoded[0].labels.is_empty());
        assert_eq!(decoded[0].prefix.to_string(), "198.51.101.0/24");
    }

    #[test]
    fn withdraw_decode_v6_multi_label_stack_echo() {
        // A GoBGP-shaped withdraw is byte-identical to the announce
        // encoding of the same NLRI.
        let entry = LabeledNlri {
            labels: vec![label(16_000, false), label(24_000, true)],
            prefix: Prefix::V6(Ipv6Prefix::new("2001:db8:100::".parse().unwrap(), 48)),
        };
        let mut buf = Vec::new();
        encode_labeled_nlri(
            std::slice::from_ref(&entry),
            LabeledAddressFamily::V6,
            &mut buf,
        )
        .unwrap();

        let decoded = decode_labeled_withdraw_nlri(&buf, LabeledAddressFamily::V6).unwrap();
        assert_eq!(decoded.len(), 1);
        assert!(decoded[0].labels.is_empty());
        assert_eq!(decoded[0].prefix, entry.prefix);
    }

    #[test]
    fn addpath_withdraw_decode_label_stack_echo() {
        let mut buf = 9u32.to_be_bytes().to_vec();
        buf.extend_from_slice(&[
            0x48, // 72 bits = 2×24 label + 24 prefix
            0x00, 0x32, 0x10, // label 801, S=0
            0x00, 0x32, 0x21, // label 802, S=1
            0xC6, 0x33, 0x65, // 198.51.101.0/24
        ]);
        let decoded = decode_labeled_withdraw_nlri_addpath(&buf, LabeledAddressFamily::V4).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].path_id, 9);
        assert!(decoded[0].nlri.labels.is_empty());
        assert_eq!(decoded[0].nlri.prefix.to_string(), "198.51.101.0/24");
    }

    #[test]
    fn withdraw_decode_rejects_stack_without_bottom_of_stack() {
        // Not a compatibility value and no S=1 within the declared length.
        let buf = vec![24 + 24, 0x00, 0x32, 0x10, 0x00, 0x32, 0x20];
        let err = decode_labeled_withdraw_nlri(&buf, LabeledAddressFamily::V4).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));
    }

    #[test]
    fn withdraw_decode_rejects_prefix_too_long_for_family() {
        // Compatibility-field form: 57 − 24 = 33 > 32.
        let buf = vec![24 + 33, 0x80, 0x00, 0x00, 10, 0, 0, 0, 0];
        let err = decode_labeled_withdraw_nlri(&buf, LabeledAddressFamily::V4).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));

        // Stack-echo form: single BOS label, 57 − 24 = 33 > 32.
        let buf = vec![24 + 33, 0x00, 0x32, 0x11, 10, 0, 0, 0, 0];
        let err = decode_labeled_withdraw_nlri(&buf, LabeledAddressFamily::V4).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));
    }

    /// Stack-echo compatibility invariant: for every announce-encodable
    /// NLRI, the announce bytes (what `GoBGP` sends as a withdraw) decode
    /// through the withdraw decoders to the same route key.
    #[test]
    fn withdraw_stack_echo_matches_announce_key() {
        let cases = [
            (
                LabeledAddressFamily::V4,
                vec![
                    LabeledNlri {
                        labels: vec![label(3, true)],
                        prefix: v4([0, 0, 0, 0], 0),
                    },
                    LabeledNlri {
                        labels: vec![label(801, false), label(802, true)],
                        prefix: v4([198, 51, 101, 0], 24),
                    },
                    LabeledNlri {
                        labels: vec![label(100, false), label(200, false), label(300, true)],
                        prefix: v4([203, 0, 113, 7], 32),
                    },
                ],
            ),
            (
                LabeledAddressFamily::V6,
                vec![
                    LabeledNlri {
                        labels: vec![label(16_000, false), label(24_000, true)],
                        prefix: Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32)),
                    },
                    LabeledNlri {
                        labels: vec![label(42, true)],
                        prefix: Prefix::V6(Ipv6Prefix::new("2001:db8::1".parse().unwrap(), 128)),
                    },
                ],
            ),
        ];

        for (family, entries) in cases {
            let mut announce = Vec::new();
            encode_labeled_nlri(&entries, family, &mut announce).unwrap();
            let withdrawn = decode_labeled_withdraw_nlri(&announce, family).unwrap();
            assert_eq!(withdrawn.len(), entries.len());
            for (got, want) in withdrawn.iter().zip(&entries) {
                assert!(got.labels.is_empty());
                assert_eq!(got.key(), want.key(), "{family}");
            }

            let addpath: Vec<_> = entries
                .iter()
                .enumerate()
                .map(|(i, nlri)| LabeledNlriEntry {
                    path_id: u32::try_from(i).unwrap() + 1,
                    nlri: nlri.clone(),
                })
                .collect();
            let mut announce = Vec::new();
            encode_labeled_nlri_addpath(&addpath, family, &mut announce).unwrap();
            let withdrawn = decode_labeled_withdraw_nlri_addpath(&announce, family).unwrap();
            assert_eq!(withdrawn.len(), addpath.len());
            for (got, want) in withdrawn.iter().zip(&addpath) {
                assert_eq!(got.path_id, want.path_id);
                assert_eq!(got.nlri.key(), want.nlri.key(), "{family}");
            }
        }
    }

    #[test]
    fn withdraw_decode_rejects_shorter_than_compatibility_field() {
        let err =
            decode_labeled_withdraw_nlri(&[16, 0x80, 0x00], LabeledAddressFamily::V4).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));
    }

    #[test]
    fn withdraw_encode_rejects_wrong_family_and_restores_buffer() {
        let entry = LabeledNlri {
            labels: vec![],
            prefix: Prefix::V6(Ipv6Prefix::new(Ipv6Addr::LOCALHOST, 128)),
        };
        let mut buf = vec![0xAA];
        let err =
            encode_labeled_withdraw_nlri(&[entry], LabeledAddressFamily::V4, &mut buf).unwrap_err();
        assert!(matches!(err, EncodeError::ValueOutOfRange { .. }));
        assert_eq!(buf, vec![0xAA]);
    }

    #[test]
    fn decode_rejects_truncated_value() {
        let err = decode_labeled_nlri(&[48, 0x00, 0x06], LabeledAddressFamily::V4).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));
    }

    #[test]
    fn decode_rejects_missing_bottom_of_stack() {
        // Two label entries, both S=0, exhausting the 48-bit length: the
        // stack never terminates within the declared bits.
        let buf = vec![24 + 24, 0x00, 0x06, 0x40, 0x00, 0x06, 0x40];
        let err = decode_labeled_nlri(&buf, LabeledAddressFamily::V4).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));
    }

    #[test]
    fn decode_rejects_prefix_too_long_for_family() {
        let buf = vec![24 + 33, 0x00, 0x06, 0x41, 10, 0, 0, 0, 0];
        let err = decode_labeled_nlri(&buf, LabeledAddressFamily::V4).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));
    }

    #[test]
    fn encode_rejects_invalid_label_stack_and_restores_buffer() {
        // Empty stack.
        let empty = LabeledNlri {
            labels: vec![],
            prefix: v4([10, 0, 0, 0], 8),
        };
        let mut buf = vec![0xAA];
        let err = encode_labeled_nlri(
            std::slice::from_ref(&empty),
            LabeledAddressFamily::V4,
            &mut buf,
        )
        .unwrap_err();
        assert!(matches!(err, EncodeError::ValueOutOfRange { .. }));
        assert_eq!(buf, vec![0xAA]);

        // Missing bottom-of-stack.
        let no_bos = LabeledNlri {
            labels: vec![label(100, false)],
            prefix: v4([10, 0, 0, 0], 8),
        };
        assert!(matches!(
            encode_labeled_nlri(&[no_bos], LabeledAddressFamily::V4, &mut Vec::new()),
            Err(EncodeError::ValueOutOfRange { .. })
        ));

        // Bottom-of-stack before the final label.
        let early_bos = LabeledNlri {
            labels: vec![label(100, true), label(200, true)],
            prefix: v4([10, 0, 0, 0], 8),
        };
        assert!(matches!(
            encode_labeled_nlri(&[early_bos], LabeledAddressFamily::V4, &mut Vec::new()),
            Err(EncodeError::ValueOutOfRange { .. })
        ));
    }

    #[test]
    fn encode_rejects_too_long_v6_nlri() {
        // Six labels (144 bits) + /128 = 272 bits > 255-bit length octet.
        let entry = LabeledNlri {
            labels: (0..5)
                .map(|i| label(100 + i, false))
                .chain(std::iter::once(label(200, true)))
                .collect(),
            prefix: Prefix::V6(Ipv6Prefix::new(Ipv6Addr::UNSPECIFIED, 128)),
        };
        let err =
            encode_labeled_nlri(&[entry], LabeledAddressFamily::V6, &mut Vec::new()).unwrap_err();
        assert!(matches!(err, EncodeError::ValueOutOfRange { .. }));
    }

    #[test]
    fn encode_rejects_wrong_family() {
        let entry = LabeledNlri {
            labels: vec![label(100, true)],
            prefix: Prefix::V6(Ipv6Prefix::new(Ipv6Addr::LOCALHOST, 128)),
        };
        let err =
            encode_labeled_nlri(&[entry], LabeledAddressFamily::V4, &mut Vec::new()).unwrap_err();
        assert!(matches!(err, EncodeError::ValueOutOfRange { .. }));
    }

    #[test]
    fn addpath_labeled_v4_roundtrip_multiple() {
        let entries = vec![
            LabeledNlriEntry {
                path_id: 1,
                nlri: LabeledNlri {
                    labels: vec![label(100, true)],
                    prefix: v4([10, 0, 1, 0], 24),
                },
            },
            LabeledNlriEntry {
                path_id: 0xFFFF_FFFF,
                nlri: LabeledNlri {
                    labels: vec![label(200, true)],
                    prefix: v4([10, 0, 2, 0], 24),
                },
            },
        ];
        let mut buf = Vec::new();
        encode_labeled_nlri_addpath(&entries, LabeledAddressFamily::V4, &mut buf).unwrap();
        assert_eq!(
            decode_labeled_nlri_addpath(&buf, LabeledAddressFamily::V4).unwrap(),
            entries
        );
    }

    #[test]
    fn addpath_labeled_v6_withdraw_roundtrip() {
        let entry = LabeledNlriEntry {
            path_id: 7,
            nlri: LabeledNlri {
                labels: vec![],
                prefix: Prefix::V6(Ipv6Prefix::new("2001:db8:100::".parse().unwrap(), 48)),
            },
        };
        let mut buf = Vec::new();
        encode_labeled_withdraw_nlri_addpath(
            std::slice::from_ref(&entry),
            LabeledAddressFamily::V6,
            &mut buf,
        )
        .unwrap();
        assert_eq!(&buf[..4], &7u32.to_be_bytes());
        assert_eq!(&buf[5..8], &VPN_WITHDRAW_COMPATIBILITY);
        assert_eq!(
            decode_labeled_withdraw_nlri_addpath(&buf, LabeledAddressFamily::V6).unwrap(),
            vec![entry]
        );
    }

    #[test]
    fn addpath_decode_rejects_truncated_path_id() {
        let err = decode_labeled_nlri_addpath(&[0, 0, 1], LabeledAddressFamily::V4).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));
    }

    #[test]
    fn zero_length_prefix_roundtrips() {
        let entry = LabeledNlri {
            labels: vec![label(3, true)], // implicit-null-shaped label value
            prefix: v4([0, 0, 0, 0], 0),
        };
        let mut buf = Vec::new();
        encode_labeled_nlri(
            std::slice::from_ref(&entry),
            LabeledAddressFamily::V4,
            &mut buf,
        )
        .unwrap();
        assert_eq!(buf[0], 24);
        assert_eq!(
            decode_labeled_nlri(&buf, LabeledAddressFamily::V4).unwrap(),
            vec![entry]
        );
    }
}
