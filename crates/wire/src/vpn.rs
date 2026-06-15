//! VPNv4/VPNv6 labeled NLRI codec substrate.
//!
//! This module is deliberately pure and unreachable from MP_REACH/MP_UNREACH
//! dispatch today. It provides the RFC 8277 label-stack and RFC 4364 / RFC
//! 4659 RD-prefixed VPN prefix codec pieces needed for a future typed
//! VPNv4/VPNv6 route-reflector slice without treating VPN routes as unicast
//! [`crate::nlri::Prefix`] values.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{DecodeError, EncodeError};
use crate::evpn::RouteDistinguisher;

/// AFI for `VPNv4` labeled NLRI (RFC 4364 §4.3.1).
pub const VPNV4_AFI: u16 = 1;
/// AFI for `VPNv6` labeled NLRI (RFC 4659 §3.2).
pub const VPNV6_AFI: u16 = 2;
/// SAFI for labeled-unicast NLRI (RFC 8277 §2).
pub const LABELED_UNICAST_SAFI: u8 = 4;
/// SAFI for labeled VPN NLRI (RFC 8277 §2, RFC 4364, RFC 4659).
pub const MPLS_VPN_SAFI: u8 = 128;
/// Route Distinguisher length in octets.
pub const ROUTE_DISTINGUISHER_LEN: usize = 8;
/// Route Distinguisher length in bits.
pub const ROUTE_DISTINGUISHER_BITS: u8 = 64;
/// One MPLS label-stack entry is a 20-bit label, 3-bit TC, and S bit.
pub const MPLS_LABEL_ENTRY_BITS: u8 = 24;
/// One MPLS label-stack entry length in octets.
pub const MPLS_LABEL_ENTRY_LEN: usize = 3;
/// Maximum 20-bit MPLS label value.
pub const MAX_MPLS_LABEL: u32 = 0x000F_FFFF;
/// Maximum 3-bit MPLS traffic-class value.
pub const MAX_MPLS_TRAFFIC_CLASS: u8 = 0x07;

/// VPN address family carried by a VPNv4/VPNv6 NLRI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VpnAddressFamily {
    /// VPN-IPv4, AFI 1 / SAFI 128.
    V4,
    /// VPN-IPv6, AFI 2 / SAFI 128.
    V6,
}

impl VpnAddressFamily {
    /// Return the AFI value for this VPN family.
    #[must_use]
    pub const fn afi(self) -> u16 {
        match self {
            Self::V4 => VPNV4_AFI,
            Self::V6 => VPNV6_AFI,
        }
    }

    const fn max_prefix_len(self) -> u8 {
        match self {
            Self::V4 => 32,
            Self::V6 => 128,
        }
    }
}

impl fmt::Display for VpnAddressFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4 => write!(f, "vpnv4"),
            Self::V6 => write!(f, "vpnv6"),
        }
    }
}

/// One RFC 8277 MPLS label-stack entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MplsLabelEntry {
    /// The 20-bit MPLS label value.
    pub label: u32,
    /// The 3-bit traffic-class field.
    pub traffic_class: u8,
    /// Bottom-of-stack bit.
    pub bottom_of_stack: bool,
}

impl MplsLabelEntry {
    /// Construct a validated MPLS label-stack entry.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::ValueOutOfRange`] when `label` exceeds 20 bits
    /// or `traffic_class` exceeds 3 bits.
    pub fn try_new(
        label: u32,
        traffic_class: u8,
        bottom_of_stack: bool,
    ) -> Result<Self, EncodeError> {
        validate_label(label)?;
        validate_traffic_class(traffic_class)?;
        Ok(Self {
            label,
            traffic_class,
            bottom_of_stack,
        })
    }

    /// Decode a raw 24-bit label-stack entry.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "traffic-class value is masked to 3 bits before the cast"
    )]
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self {
            label: (raw >> 4) & MAX_MPLS_LABEL,
            traffic_class: ((raw >> 1) & MAX_MPLS_TRAFFIC_CLASS as u32) as u8,
            bottom_of_stack: (raw & 0x01) != 0,
        }
    }

    /// Encode this entry as a raw 24-bit wire value.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::ValueOutOfRange`] if the public fields contain
    /// out-of-range values.
    pub fn raw_value(&self) -> Result<u32, EncodeError> {
        validate_label(self.label)?;
        validate_traffic_class(self.traffic_class)?;
        Ok((self.label << 4)
            | (u32::from(self.traffic_class) << 1)
            | u32::from(self.bottom_of_stack))
    }
}

/// A `VPNv4` or `VPNv6` route prefix keyed by RD plus address prefix.
///
/// This is intentionally not [`crate::nlri::Prefix`]. VPN route identity is
/// different from ordinary IPv4/IPv6 unicast because the Route Distinguisher is
/// part of the address-family-specific route key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VpnPrefix {
    /// VPN-IPv4 prefix.
    V4 {
        /// IPv4 network address with host bits zeroed.
        addr: Ipv4Addr,
        /// Prefix length in bits.
        len: u8,
    },
    /// VPN-IPv6 prefix.
    V6 {
        /// IPv6 network address with host bits zeroed.
        addr: Ipv6Addr,
        /// Prefix length in bits.
        len: u8,
    },
}

impl VpnPrefix {
    /// Create a canonical VPN-IPv4 prefix.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::ValueOutOfRange`] if `len` exceeds 32.
    pub fn v4(addr: Ipv4Addr, len: u8) -> Result<Self, EncodeError> {
        if len > 32 {
            return Err(EncodeError::ValueOutOfRange {
                field: "VPNv4 prefix length",
                value: len.to_string(),
            });
        }
        Ok(Self::V4 {
            addr: Ipv4Addr::from(mask_v4(addr, len)),
            len,
        })
    }

    /// Create a canonical VPN-IPv6 prefix.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::ValueOutOfRange`] if `len` exceeds 128.
    pub fn v6(addr: Ipv6Addr, len: u8) -> Result<Self, EncodeError> {
        if len > 128 {
            return Err(EncodeError::ValueOutOfRange {
                field: "VPNv6 prefix length",
                value: len.to_string(),
            });
        }
        Ok(Self::V6 {
            addr: Ipv6Addr::from(mask_v6(addr, len)),
            len,
        })
    }

    /// Return the VPN address family.
    #[must_use]
    pub const fn family(&self) -> VpnAddressFamily {
        match self {
            Self::V4 { .. } => VpnAddressFamily::V4,
            Self::V6 { .. } => VpnAddressFamily::V6,
        }
    }

    /// Return the IP prefix length.
    #[must_use]
    pub const fn len(&self) -> u8 {
        match self {
            Self::V4 { len, .. } | Self::V6 { len, .. } => *len,
        }
    }

    /// Return true for a zero-length IP prefix.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn wire_octets(&self) -> [u8; 16] {
        match self {
            Self::V4 { addr, .. } => {
                let mut out = [0u8; 16];
                out[..4].copy_from_slice(&addr.octets());
                out
            }
            Self::V6 { addr, .. } => addr.octets(),
        }
    }
}

impl fmt::Display for VpnPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4 { addr, len } => write!(f, "{addr}/{len}"),
            Self::V6 { addr, len } => write!(f, "{addr}/{len}"),
        }
    }
}

/// Route-key identity for one VPNv4/VPNv6 NLRI.
///
/// The label stack is intentionally excluded: labels are route data carried by
/// the path, while the VPN route key is RD plus IP prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VpnRouteKey {
    /// Route Distinguisher.
    pub route_distinguisher: RouteDistinguisher,
    /// RD-scoped VPN IP prefix.
    pub prefix: VpnPrefix,
}

/// One VPNv4/VPNv6 labeled NLRI.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VpnNlri {
    /// MPLS label stack bound to the VPN prefix.
    pub labels: Vec<MplsLabelEntry>,
    /// Route Distinguisher.
    pub route_distinguisher: RouteDistinguisher,
    /// RD-scoped VPN IP prefix.
    pub prefix: VpnPrefix,
}

impl VpnNlri {
    /// Return the route-key identity for this NLRI.
    #[must_use]
    pub const fn key(&self) -> VpnRouteKey {
        VpnRouteKey {
            route_distinguisher: self.route_distinguisher,
            prefix: self.prefix,
        }
    }

    fn validate_for_family(&self, family: VpnAddressFamily) -> Result<(), EncodeError> {
        if self.prefix.family() != family {
            return Err(EncodeError::ValueOutOfRange {
                field: "VPN NLRI family",
                value: self.prefix.family().to_string(),
            });
        }
        validate_label_stack(&self.labels)?;
        let total_bits = total_vpn_nlri_bits(self.labels.len(), self.prefix.len());
        if total_bits > u16::from(u8::MAX) {
            return Err(EncodeError::ValueOutOfRange {
                field: "VPN NLRI length bits",
                value: total_bits.to_string(),
            });
        }
        Ok(())
    }
}

/// Decode `VPNv4` NLRI bytes.
///
/// # Errors
///
/// Returns [`DecodeError`] for malformed length, label stack, RD, or prefix
/// encodings.
pub fn decode_vpnv4_nlri(buf: &[u8]) -> Result<Vec<VpnNlri>, DecodeError> {
    decode_vpn_nlri(buf, VpnAddressFamily::V4)
}

/// Decode `VPNv6` NLRI bytes.
///
/// # Errors
///
/// Returns [`DecodeError`] for malformed length, label stack, RD, or prefix
/// encodings.
pub fn decode_vpnv6_nlri(buf: &[u8]) -> Result<Vec<VpnNlri>, DecodeError> {
    decode_vpn_nlri(buf, VpnAddressFamily::V6)
}

/// Decode `VPNv4` or `VPNv6` NLRI bytes for the selected family.
///
/// # Errors
///
/// Returns [`DecodeError`] for malformed length, label stack, RD, or prefix
/// encodings.
pub fn decode_vpn_nlri(
    mut buf: &[u8],
    family: VpnAddressFamily,
) -> Result<Vec<VpnNlri>, DecodeError> {
    let mut entries = Vec::new();

    while !buf.is_empty() {
        let field_start = buf;
        let total_len_bits = buf[0];
        buf = &buf[1..];
        let value_len = usize::from(total_len_bits.div_ceil(8));

        if buf.len() < value_len {
            return invalid_vpn_nlri(
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

        entries.push(decode_one_vpn_nlri(
            value,
            total_len_bits,
            family,
            field_start,
        )?);
    }

    Ok(entries)
}

/// Encode `VPNv4` NLRI bytes.
///
/// # Errors
///
/// Returns [`EncodeError`] if an entry is not `VPNv4`, its label stack is
/// invalid, or its encoded length cannot fit in the one-octet NLRI length.
pub fn encode_vpnv4_nlri(entries: &[VpnNlri], buf: &mut Vec<u8>) -> Result<(), EncodeError> {
    encode_vpn_nlri(entries, VpnAddressFamily::V4, buf)
}

/// Encode `VPNv6` NLRI bytes.
///
/// # Errors
///
/// Returns [`EncodeError`] if an entry is not `VPNv6`, its label stack is
/// invalid, or its encoded length cannot fit in the one-octet NLRI length.
pub fn encode_vpnv6_nlri(entries: &[VpnNlri], buf: &mut Vec<u8>) -> Result<(), EncodeError> {
    encode_vpn_nlri(entries, VpnAddressFamily::V6, buf)
}

/// Encode `VPNv4` or `VPNv6` NLRI bytes for the selected family.
///
/// On error, `buf` is restored to its original length.
///
/// # Errors
///
/// Returns [`EncodeError`] if an entry belongs to the wrong family, its label
/// stack is invalid, or its encoded length cannot fit in the one-octet NLRI
/// length.
pub fn encode_vpn_nlri(
    entries: &[VpnNlri],
    family: VpnAddressFamily,
    buf: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let start_len = buf.len();

    for entry in entries {
        if let Err(err) = encode_one_vpn_nlri(entry, family, buf) {
            buf.truncate(start_len);
            return Err(err);
        }
    }

    Ok(())
}

fn decode_one_vpn_nlri(
    value: &[u8],
    total_len_bits: u8,
    family: VpnAddressFamily,
    field_start: &[u8],
) -> Result<VpnNlri, DecodeError> {
    let min_bits = u16::from(MPLS_LABEL_ENTRY_BITS) + u16::from(ROUTE_DISTINGUISHER_BITS);
    if u16::from(total_len_bits) < min_bits {
        return invalid_vpn_nlri(
            format!("{family} NLRI length {total_len_bits} bits is shorter than label+RD"),
            field_start,
            1 + value.len(),
        );
    }

    let (labels, label_octets, label_bits) =
        decode_label_stack(value, total_len_bits, family, field_start)?;
    let rd_offset = label_octets;
    let rd_end = rd_offset + ROUTE_DISTINGUISHER_LEN;
    if value.len() < rd_end {
        return invalid_vpn_nlri(
            format!("{family} NLRI truncated before Route Distinguisher"),
            field_start,
            1 + value.len(),
        );
    }

    let mut rd = [0u8; ROUTE_DISTINGUISHER_LEN];
    rd.copy_from_slice(&value[rd_offset..rd_end]);

    // Reserve the label-stack and RD bits with checked subtraction: a
    // multi-label stack can consume enough bits that `total_len_bits` no longer
    // covers the RD, which would underflow this u8 and panic in debug builds
    // (violating the crate's no-panic-on-malformed-input invariant).
    let Some(prefix_len) = total_len_bits
        .checked_sub(label_bits)
        .and_then(|rem| rem.checked_sub(ROUTE_DISTINGUISHER_BITS))
    else {
        return invalid_vpn_nlri(
            format!(
                "{family} NLRI length {total_len_bits} bits cannot hold the {label_bits}-bit label stack plus Route Distinguisher"
            ),
            field_start,
            1 + value.len(),
        );
    };
    if prefix_len > family.max_prefix_len() {
        return invalid_vpn_nlri(
            format!(
                "{family} prefix length {prefix_len} exceeds {}",
                family.max_prefix_len()
            ),
            field_start,
            1 + value.len(),
        );
    }

    let prefix_octets = usize::from(prefix_len.div_ceil(8));
    let prefix_start = rd_end;
    let prefix_end = prefix_start + prefix_octets;
    if value.len() < prefix_end {
        return invalid_vpn_nlri(
            format!("{family} NLRI truncated before prefix"),
            field_start,
            1 + value.len(),
        );
    }

    let prefix = decode_vpn_prefix(family, prefix_len, &value[prefix_start..prefix_end])?;
    Ok(VpnNlri {
        labels,
        route_distinguisher: RouteDistinguisher(rd),
        prefix,
    })
}

fn decode_label_stack(
    value: &[u8],
    total_len_bits: u8,
    family: VpnAddressFamily,
    field_start: &[u8],
) -> Result<(Vec<MplsLabelEntry>, usize, u8), DecodeError> {
    let mut labels = Vec::new();
    let mut offset = 0usize;
    let mut label_bits = 0u8;

    loop {
        if u16::from(label_bits) + u16::from(MPLS_LABEL_ENTRY_BITS) > u16::from(total_len_bits) {
            return invalid_vpn_nlri(
                format!("{family} NLRI label stack has no bottom-of-stack marker"),
                field_start,
                1 + value.len(),
            );
        }
        if value.len() < offset + MPLS_LABEL_ENTRY_LEN {
            return invalid_vpn_nlri(
                format!("{family} NLRI truncated inside label stack"),
                field_start,
                1 + value.len(),
            );
        }

        let raw = (u32::from(value[offset]) << 16)
            | (u32::from(value[offset + 1]) << 8)
            | u32::from(value[offset + 2]);
        let label = MplsLabelEntry::from_raw(raw);
        labels.push(label);
        offset += MPLS_LABEL_ENTRY_LEN;
        label_bits += MPLS_LABEL_ENTRY_BITS;

        if label.bottom_of_stack {
            return Ok((labels, offset, label_bits));
        }
    }
}

fn decode_vpn_prefix(
    family: VpnAddressFamily,
    len: u8,
    bytes: &[u8],
) -> Result<VpnPrefix, DecodeError> {
    let expected = usize::from(len.div_ceil(8));
    if bytes.len() != expected {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: format!(
                "{family} prefix byte length {} != expected {expected}",
                bytes.len()
            ),
        });
    }

    match family {
        VpnAddressFamily::V4 => {
            let mut octets = [0u8; 4];
            octets[..bytes.len()].copy_from_slice(bytes);
            Ok(VpnPrefix::V4 {
                addr: Ipv4Addr::from(mask_v4(Ipv4Addr::from(octets), len)),
                len,
            })
        }
        VpnAddressFamily::V6 => {
            let mut octets = [0u8; 16];
            octets[..bytes.len()].copy_from_slice(bytes);
            Ok(VpnPrefix::V6 {
                addr: Ipv6Addr::from(mask_v6(Ipv6Addr::from(octets), len)),
                len,
            })
        }
    }
}

fn encode_one_vpn_nlri(
    entry: &VpnNlri,
    family: VpnAddressFamily,
    buf: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    entry.validate_for_family(family)?;
    let total_bits = total_vpn_nlri_bits(entry.labels.len(), entry.prefix.len());
    let total_bits_u8 = u8::try_from(total_bits).map_err(|_| EncodeError::ValueOutOfRange {
        field: "VPN NLRI length bits",
        value: total_bits.to_string(),
    })?;
    buf.push(total_bits_u8);

    for label in &entry.labels {
        let raw = label.raw_value()?;
        buf.push(((raw >> 16) & 0xFF) as u8);
        buf.push(((raw >> 8) & 0xFF) as u8);
        buf.push((raw & 0xFF) as u8);
    }

    buf.extend_from_slice(&entry.route_distinguisher.0);
    let prefix_octets = entry.prefix.wire_octets();
    let prefix_byte_count = usize::from(entry.prefix.len().div_ceil(8));
    buf.extend_from_slice(&prefix_octets[..prefix_byte_count]);
    Ok(())
}

fn validate_label_stack(labels: &[MplsLabelEntry]) -> Result<(), EncodeError> {
    if labels.is_empty() {
        return Err(EncodeError::ValueOutOfRange {
            field: "VPN label stack",
            value: "empty".to_string(),
        });
    }
    for (index, label) in labels.iter().enumerate() {
        validate_label(label.label)?;
        validate_traffic_class(label.traffic_class)?;
        if label.bottom_of_stack && index + 1 != labels.len() {
            return Err(EncodeError::ValueOutOfRange {
                field: "VPN label stack",
                value: "bottom-of-stack before final label".to_string(),
            });
        }
    }
    if !labels.last().is_some_and(|label| label.bottom_of_stack) {
        return Err(EncodeError::ValueOutOfRange {
            field: "VPN label stack",
            value: "missing bottom-of-stack".to_string(),
        });
    }
    Ok(())
}

fn validate_label(label: u32) -> Result<(), EncodeError> {
    if label > MAX_MPLS_LABEL {
        return Err(EncodeError::ValueOutOfRange {
            field: "MPLS label",
            value: label.to_string(),
        });
    }
    Ok(())
}

fn validate_traffic_class(traffic_class: u8) -> Result<(), EncodeError> {
    if traffic_class > MAX_MPLS_TRAFFIC_CLASS {
        return Err(EncodeError::ValueOutOfRange {
            field: "MPLS traffic class",
            value: traffic_class.to_string(),
        });
    }
    Ok(())
}

fn total_vpn_nlri_bits(label_count: usize, prefix_len: u8) -> u16 {
    let label_bits = u16::try_from(label_count)
        .unwrap_or(u16::MAX)
        .saturating_mul(u16::from(MPLS_LABEL_ENTRY_BITS));
    // Saturate the final adds too: an extreme label_count saturates label_bits
    // to u16::MAX, and a plain `+` would then overflow and panic in debug.
    // Callers reject any total > u8::MAX, so a saturated value is rejected
    // cleanly downstream.
    label_bits
        .saturating_add(u16::from(ROUTE_DISTINGUISHER_BITS))
        .saturating_add(u16::from(prefix_len))
}

fn mask_v4(addr: Ipv4Addr, len: u8) -> u32 {
    let raw = u32::from(addr);
    if len == 0 {
        0
    } else if len >= 32 {
        raw
    } else {
        raw & !((1u32 << (32 - len)) - 1)
    }
}

fn mask_v6(addr: Ipv6Addr, len: u8) -> u128 {
    let raw = u128::from(addr);
    if len == 0 {
        0
    } else if len >= 128 {
        raw
    } else {
        raw & !((1u128 << (128 - len)) - 1)
    }
}

fn invalid_vpn_nlri<T>(detail: String, data: &[u8], len: usize) -> Result<T, DecodeError> {
    Err(DecodeError::InvalidNetworkField {
        detail,
        data: data[..len.min(data.len())].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rd() -> RouteDistinguisher {
        RouteDistinguisher([0, 0, 0xFD, 0xE9, 0, 0, 0, 100])
    }

    fn label(value: u32, bos: bool) -> MplsLabelEntry {
        MplsLabelEntry::try_new(value, 0, bos).unwrap()
    }

    #[test]
    fn constants_match_standards() {
        assert_eq!(VPNV4_AFI, 1);
        assert_eq!(VPNV6_AFI, 2);
        assert_eq!(LABELED_UNICAST_SAFI, 4);
        assert_eq!(MPLS_VPN_SAFI, 128);
        assert_eq!(ROUTE_DISTINGUISHER_LEN, 8);
        assert_eq!(MPLS_LABEL_ENTRY_BITS, 24);
    }

    #[test]
    fn label_entry_roundtrip() {
        let entry = MplsLabelEntry::try_new(100_000, 5, true).unwrap();
        let raw = entry.raw_value().unwrap();
        assert_eq!(MplsLabelEntry::from_raw(raw), entry);
    }

    #[test]
    fn vpnv4_single_label_roundtrip() {
        let entry = VpnNlri {
            labels: vec![label(200, true)],
            route_distinguisher: rd(),
            prefix: VpnPrefix::v4(Ipv4Addr::new(10, 0, 1, 99), 24).unwrap(),
        };
        let mut buf = Vec::new();
        encode_vpnv4_nlri(std::slice::from_ref(&entry), &mut buf).unwrap();
        assert_eq!(buf[0], 24 + 64 + 24);

        let decoded = decode_vpnv4_nlri(&buf).unwrap();
        assert_eq!(decoded, vec![entry]);
        assert_eq!(decoded[0].prefix.to_string(), "10.0.1.0/24");
    }

    #[test]
    fn vpnv6_two_label_roundtrip() {
        let prefix = "2001:db8:100::1".parse::<Ipv6Addr>().unwrap();
        let entry = VpnNlri {
            labels: vec![label(16_000, false), label(24_000, true)],
            route_distinguisher: rd(),
            prefix: VpnPrefix::v6(prefix, 48).unwrap(),
        };
        let mut buf = Vec::new();
        encode_vpnv6_nlri(std::slice::from_ref(&entry), &mut buf).unwrap();
        assert_eq!(buf[0], 48 + 64 + 48);

        let decoded = decode_vpnv6_nlri(&buf).unwrap();
        assert_eq!(decoded, vec![entry]);
        assert_eq!(decoded[0].prefix.to_string(), "2001:db8:100::/48");
    }

    #[test]
    fn multiple_nlri_preserve_order() {
        let a = VpnNlri {
            labels: vec![label(100, true)],
            route_distinguisher: rd(),
            prefix: VpnPrefix::v4(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
        };
        let b = VpnNlri {
            labels: vec![label(101, true)],
            route_distinguisher: rd(),
            prefix: VpnPrefix::v4(Ipv4Addr::new(192, 0, 2, 0), 24).unwrap(),
        };
        let mut buf = Vec::new();
        encode_vpnv4_nlri(&[a.clone(), b.clone()], &mut buf).unwrap();

        assert_eq!(decode_vpnv4_nlri(&buf).unwrap(), vec![a, b]);
    }

    #[test]
    fn route_key_excludes_label_stack() {
        let prefix = VpnPrefix::v4(Ipv4Addr::new(203, 0, 113, 0), 24).unwrap();
        let a = VpnNlri {
            labels: vec![label(100, true)],
            route_distinguisher: rd(),
            prefix,
        };
        let b = VpnNlri {
            labels: vec![label(200, true)],
            route_distinguisher: rd(),
            prefix,
        };

        assert_eq!(a.key(), b.key());
        assert_ne!(a, b);
    }

    #[test]
    fn decode_rejects_nlri_shorter_than_label_plus_rd() {
        let err = decode_vpnv4_nlri(&[87, 0, 0, 1]).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));
    }

    #[test]
    fn decode_rejects_truncated_value() {
        let err = decode_vpnv4_nlri(&[112, 0, 0x0C, 0x81]).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));
    }

    #[test]
    fn decode_rejects_missing_bottom_of_stack() {
        let mut buf = vec![24 + 64, 0, 0x0C, 0x80];
        buf.extend_from_slice(&rd().0);
        let err = decode_vpnv4_nlri(&buf).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));
    }

    #[test]
    fn decode_rejects_label_stack_consuming_rd_bits_without_underflow() {
        // total_len_bits = 105 with a two-label stack (48 label bits) leaves
        // only 57 bits — fewer than the 64 Route Distinguisher bits — so the
        // prefix-length computation would underflow u8 and panic in debug.
        // The decoder must reject cleanly instead. Bytes: len=105, label1
        // (no BoS), label2 (BoS set), then the 8-byte RD.
        let mut buf = vec![105u8, 0, 0, 0, 0, 0, 1];
        buf.extend_from_slice(&rd().0);
        let err = decode_vpnv4_nlri(&buf).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));
    }

    #[test]
    fn decode_rejects_high_bit_length_without_bottom_of_stack() {
        let mut buf = vec![u8::MAX];
        for value in 0..10u32 {
            let raw = MplsLabelEntry::try_new(value + 100, 0, false)
                .unwrap()
                .raw_value()
                .unwrap();
            buf.push(((raw >> 16) & 0xFF) as u8);
            buf.push(((raw >> 8) & 0xFF) as u8);
            buf.push((raw & 0xFF) as u8);
        }
        buf.extend_from_slice(&[0, 0]);

        let err = decode_vpnv6_nlri(&buf).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));
    }

    #[test]
    fn decode_rejects_prefix_too_long_for_family() {
        let mut buf = vec![24 + 64 + 33, 0, 0x0C, 0x81];
        buf.extend_from_slice(&rd().0);
        buf.extend_from_slice(&[10, 0, 0, 0, 0]);
        let err = decode_vpnv4_nlri(&buf).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));
    }

    #[test]
    fn encode_rejects_empty_label_stack_and_restores_buffer() {
        let entry = VpnNlri {
            labels: vec![],
            route_distinguisher: rd(),
            prefix: VpnPrefix::v4(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
        };
        let mut buf = vec![0xAA];
        let err = encode_vpnv4_nlri(&[entry], &mut buf).unwrap_err();

        assert!(matches!(err, EncodeError::ValueOutOfRange { .. }));
        assert_eq!(buf, vec![0xAA]);
    }

    #[test]
    fn encode_rejects_missing_bottom_of_stack() {
        let entry = VpnNlri {
            labels: vec![label(100, false)],
            route_distinguisher: rd(),
            prefix: VpnPrefix::v4(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
        };

        assert!(matches!(
            encode_vpnv4_nlri(&[entry], &mut Vec::new()),
            Err(EncodeError::ValueOutOfRange { .. })
        ));
    }

    #[test]
    fn encode_rejects_early_bottom_of_stack() {
        let entry = VpnNlri {
            labels: vec![label(100, true), label(200, true)],
            route_distinguisher: rd(),
            prefix: VpnPrefix::v4(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
        };

        assert!(matches!(
            encode_vpnv4_nlri(&[entry], &mut Vec::new()),
            Err(EncodeError::ValueOutOfRange { .. })
        ));
    }

    #[test]
    fn encode_rejects_label_and_traffic_class_out_of_range() {
        assert!(MplsLabelEntry::try_new(MAX_MPLS_LABEL + 1, 0, true).is_err());
        assert!(MplsLabelEntry::try_new(100, MAX_MPLS_TRAFFIC_CLASS + 1, true).is_err());
    }

    #[test]
    fn encode_rejects_too_long_vpnv6_nlri() {
        let entry = VpnNlri {
            labels: vec![label(100, false), label(200, false), label(300, true)],
            route_distinguisher: rd(),
            prefix: VpnPrefix::v6(Ipv6Addr::UNSPECIFIED, 128).unwrap(),
        };

        let err = encode_vpnv6_nlri(&[entry], &mut Vec::new()).unwrap_err();
        assert!(matches!(err, EncodeError::ValueOutOfRange { .. }));
    }

    #[test]
    fn encode_rejects_wrong_family() {
        let entry = VpnNlri {
            labels: vec![label(100, true)],
            route_distinguisher: rd(),
            prefix: VpnPrefix::v6(Ipv6Addr::LOCALHOST, 128).unwrap(),
        };

        let err = encode_vpnv4_nlri(&[entry], &mut Vec::new()).unwrap_err();
        assert!(matches!(err, EncodeError::ValueOutOfRange { .. }));
    }
}
