//! VPNv4/VPNv6 labeled NLRI codec.
//!
//! Pure codec pieces dispatched from MP_REACH/MP_UNREACH for SAFI 128: the
//! RFC 8277 label-stack and RFC 4364 / RFC 4659 RD-prefixed VPN prefix
//! encodings (announce and withdraw-compatibility modes), plus their RFC
//! 7911 Add-Path variants with the 4-octet Path Identifier prepended to
//! each NLRI. VPN routes are deliberately not treated as unicast
//! [`crate::nlri::Prefix`] values — the Route Distinguisher is part of the
//! route key.

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

/// A VPNv4/VPNv6 NLRI with an optional Add-Path path ID (RFC 7911).
///
/// For non-Add-Path peers, `path_id` is always 0. Mirrors the unicast
/// [`crate::nlri::NlriEntry`] shape: the 4-octet Path Identifier is
/// prepended to the entire NLRI (length octet included) on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VpnNlriEntry {
    /// Add-Path path identifier (0 when Add-Path is not in use).
    pub path_id: u32,
    /// The VPN NLRI.
    pub nlri: VpnNlri,
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

/// Decode Add-Path `VPNv4`/`VPNv6` NLRI bytes (RFC 7911 §3).
///
/// Wire format per entry: `[4-byte path_id BE]` prepended to the ordinary
/// RFC 8277 NLRI (`len | label stack | RD | prefix`).
///
/// # Errors
///
/// Returns [`DecodeError`] for a truncated path ID or malformed length,
/// label stack, RD, or prefix encodings.
pub fn decode_vpn_nlri_addpath(
    mut buf: &[u8],
    family: VpnAddressFamily,
) -> Result<Vec<VpnNlriEntry>, DecodeError> {
    let mut entries = Vec::new();

    while !buf.is_empty() {
        let (path_id, rest) = split_vpn_path_id(buf, family)?;
        buf = rest;

        let field_start = buf;
        let (value, total_len_bits, rest) = split_vpn_nlri_value(buf, family, "NLRI")?;
        buf = rest;

        entries.push(VpnNlriEntry {
            path_id,
            nlri: decode_one_vpn_nlri(value, total_len_bits, family, field_start)?,
        });
    }

    Ok(entries)
}

/// Decode Add-Path withdraw-mode `VPNv4`/`VPNv6` NLRI bytes
/// (`MP_UNREACH_NLRI`, RFC 7911 §3 + RFC 8277 §2.4).
///
/// The 4-octet Path Identifier is prepended to the whole withdraw-mode NLRI:
/// `path_id(4) | len | label field | RD | prefix`. The label field is
/// dispatched (compatibility value or echoed stack) and ignored, exactly as
/// in [`decode_vpn_withdraw_nlri`]. Decoded entries have an empty `labels`
/// vec.
///
/// # Errors
///
/// Returns [`DecodeError`] for a truncated path ID or malformed length, RD,
/// or prefix encodings.
pub fn decode_vpn_withdraw_nlri_addpath(
    mut buf: &[u8],
    family: VpnAddressFamily,
) -> Result<Vec<VpnNlriEntry>, DecodeError> {
    let mut entries = Vec::new();

    while !buf.is_empty() {
        let (path_id, rest) = split_vpn_path_id(buf, family)?;
        buf = rest;

        let field_start = buf;
        let (value, total_len_bits, rest) = split_vpn_nlri_value(buf, family, "withdraw NLRI")?;
        buf = rest;

        entries.push(VpnNlriEntry {
            path_id,
            nlri: decode_one_vpn_withdraw_nlri(value, total_len_bits, family, field_start)?,
        });
    }

    Ok(entries)
}

/// Split a 4-octet RFC 7911 Path Identifier off the front of `buf`.
fn split_vpn_path_id(buf: &[u8], family: VpnAddressFamily) -> Result<(u32, &[u8]), DecodeError> {
    if buf.len() < 5 {
        return invalid_vpn_nlri(
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
fn split_vpn_nlri_value<'a>(
    buf: &'a [u8],
    family: VpnAddressFamily,
    kind: &str,
) -> Result<(&'a [u8], u8, &'a [u8]), DecodeError> {
    let total_len_bits = buf[0];
    let rest = &buf[1..];
    let value_len = usize::from(total_len_bits.div_ceil(8));

    if rest.len() < value_len {
        return invalid_vpn_nlri(
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

/// Encode Add-Path `VPNv4`/`VPNv6` NLRI bytes (RFC 7911 §3): each entry's
/// 4-octet path ID is prepended to the ordinary RFC 8277 NLRI encoding.
///
/// On error, `buf` is restored to its original length.
///
/// # Errors
///
/// Returns [`EncodeError`] if an entry belongs to the wrong family, its label
/// stack is invalid, or its encoded length cannot fit in the one-octet NLRI
/// length.
pub fn encode_vpn_nlri_addpath(
    entries: &[VpnNlriEntry],
    family: VpnAddressFamily,
    buf: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let start_len = buf.len();

    for entry in entries {
        buf.extend_from_slice(&entry.path_id.to_be_bytes());
        if let Err(err) = encode_one_vpn_nlri(&entry.nlri, family, buf) {
            buf.truncate(start_len);
            return Err(err);
        }
    }

    Ok(())
}

/// Encode Add-Path withdraw-mode `VPNv4`/`VPNv6` NLRI bytes
/// (`MP_UNREACH_NLRI`, RFC 7911 §3 + RFC 8277 §2.4): each entry's 4-octet
/// path ID is prepended to the withdraw-mode NLRI (compatibility field
/// 0x800000 in the label position; each entry's `labels` are ignored).
///
/// On error, `buf` is restored to its original length.
///
/// # Errors
///
/// Returns [`EncodeError`] if an entry belongs to the wrong family.
pub fn encode_vpn_withdraw_nlri_addpath(
    entries: &[VpnNlriEntry],
    family: VpnAddressFamily,
    buf: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let start_len = buf.len();

    for entry in entries {
        buf.extend_from_slice(&entry.path_id.to_be_bytes());
        if let Err(err) = encode_vpn_withdraw_nlri(std::slice::from_ref(&entry.nlri), family, buf) {
            buf.truncate(start_len);
            return Err(err);
        }
    }

    Ok(())
}

/// 3-octet compatibility value transmitted in the label position of a
/// withdrawn VPN NLRI (RFC 8277 §2.4): SHOULD be 0x800000 on transmission;
/// receivers MUST ignore whatever value arrives.
pub const VPN_WITHDRAW_COMPATIBILITY: [u8; MPLS_LABEL_ENTRY_LEN] = [0x80, 0x00, 0x00];

/// Decode withdraw-mode `VPNv4`/`VPNv6` NLRI bytes (`MP_UNREACH_NLRI`).
///
/// Per RFC 8277 §2.4 a withdrawn VPN NLRI carries a single 3-octet
/// compatibility field in the label position — but `GoBGP` (and any stack
/// without a dedicated withdraw encoder) echoes the announced BOS-terminated
/// label stack instead, so the label position is dispatched per
/// the shared `split_withdraw_label_field` dispatch: an exact compatibility value (0x800000 or
/// 0x000000) is one field, anything else is S-bit-walked like announce mode.
/// Labels are ignored either way; decoded entries have an empty `labels` vec.
///
/// # Errors
///
/// Returns [`DecodeError`] for malformed length, RD, or prefix encodings.
pub fn decode_vpn_withdraw_nlri(
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
                    "{family} withdraw NLRI truncated: length {total_len_bits} bits requires {value_len} bytes, have {}",
                    buf.len()
                ),
                field_start,
                1 + buf.len(),
            );
        }

        let value = &buf[..value_len];
        buf = &buf[value_len..];

        entries.push(decode_one_vpn_withdraw_nlri(
            value,
            total_len_bits,
            family,
            field_start,
        )?);
    }

    Ok(entries)
}

fn decode_one_vpn_withdraw_nlri(
    value: &[u8],
    total_len_bits: u8,
    family: VpnAddressFamily,
    field_start: &[u8],
) -> Result<VpnNlri, DecodeError> {
    let min_bits = u16::from(MPLS_LABEL_ENTRY_BITS) + u16::from(ROUTE_DISTINGUISHER_BITS);
    if u16::from(total_len_bits) < min_bits {
        return invalid_vpn_nlri(
            format!(
                "{family} withdraw NLRI length {total_len_bits} bits is shorter than compatibility field+RD"
            ),
            field_start,
            1 + value.len(),
        );
    }

    let (label_octets, label_bits) =
        split_withdraw_label_field(value, total_len_bits, family, field_start)?;
    let rd_offset = label_octets;
    let rd_end = rd_offset + ROUTE_DISTINGUISHER_LEN;
    if value.len() < rd_end {
        return invalid_vpn_nlri(
            format!("{family} withdraw NLRI truncated before Route Distinguisher"),
            field_start,
            1 + value.len(),
        );
    }
    let mut rd = [0u8; ROUTE_DISTINGUISHER_LEN];
    rd.copy_from_slice(&value[rd_offset..rd_end]);

    // Checked subtraction: an echoed multi-label stack can consume enough
    // bits that `total_len_bits` no longer covers the RD.
    let Some(prefix_len) = total_len_bits
        .checked_sub(label_bits)
        .and_then(|rem| rem.checked_sub(ROUTE_DISTINGUISHER_BITS))
    else {
        return invalid_vpn_nlri(
            format!(
                "{family} withdraw NLRI length {total_len_bits} bits cannot hold the {label_bits}-bit label field plus Route Distinguisher"
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
    let prefix_end = rd_end + prefix_octets;
    if value.len() < prefix_end {
        return invalid_vpn_nlri(
            format!("{family} withdraw NLRI truncated before prefix"),
            field_start,
            1 + value.len(),
        );
    }

    let prefix = decode_vpn_prefix(family, prefix_len, &value[rd_end..prefix_end])?;
    Ok(VpnNlri {
        labels: vec![],
        route_distinguisher: RouteDistinguisher(rd),
        prefix,
    })
}

/// Encode withdraw-mode `VPNv4`/`VPNv6` NLRI bytes (`MP_UNREACH_NLRI`).
///
/// Writes the RFC 8277 §2.4 3-octet compatibility value 0x800000 in the label
/// position and ignores each entry's `labels`. On error, `buf` is restored to
/// its original length.
///
/// # Errors
///
/// Returns [`EncodeError`] if an entry belongs to the wrong family.
pub fn encode_vpn_withdraw_nlri(
    entries: &[VpnNlri],
    family: VpnAddressFamily,
    buf: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let start_len = buf.len();

    for entry in entries {
        if entry.prefix.family() != family {
            buf.truncate(start_len);
            return Err(EncodeError::ValueOutOfRange {
                field: "VPN NLRI family",
                value: entry.prefix.family().to_string(),
            });
        }
        // One compatibility field + RD + prefix always fits in u8:
        // 24 + 64 + at most 128 = 216 bits.
        let total_bits = MPLS_LABEL_ENTRY_BITS + ROUTE_DISTINGUISHER_BITS + entry.prefix.len();
        buf.push(total_bits);
        buf.extend_from_slice(&VPN_WITHDRAW_COMPATIBILITY);
        buf.extend_from_slice(&entry.route_distinguisher.0);
        let prefix_octets = entry.prefix.wire_octets();
        let prefix_byte_count = usize::from(entry.prefix.len().div_ceil(8));
        buf.extend_from_slice(&prefix_octets[..prefix_byte_count]);
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

/// Decode a BOS-terminated RFC 8277 label stack from the front of `value`,
/// returning `(labels, consumed_octets, consumed_bits)`. Shared by the SAFI
/// 128 (VPN) and SAFI 4 (labeled-unicast) announce-mode decoders; `family`
/// is display-only, for error messages.
pub(crate) fn decode_label_stack(
    value: &[u8],
    total_len_bits: u8,
    family: impl fmt::Display + Copy,
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

/// Split the label position of a withdraw-mode NLRI off the front of
/// `value`, returning `(consumed_octets, consumed_bits)`.
///
/// RFC 8277 §2.4 senders transmit a single 3-octet compatibility field
/// (SHOULD be 0x800000; the value is ignored). `GoBGP` has no withdraw-mode
/// encoder at all — `MPLSLabelStack.Serialize` echoes the announced label
/// stack verbatim — so a withdraw of a multi-label route arrives with a
/// BOS-terminated stack in the label position, and assuming a single field
/// mis-computes the prefix length (M79: NOTIFICATION 3/10, session reset).
/// Match `GoBGP`'s own decoder (`MPLSLabelStack.DecodeFromBytes` special-cases
/// `WITHDRAW_LABEL` 0x800000 and `ZERO_LABEL` 0x000000): an exact
/// compatibility value is one 3-octet field; anything else is walked like an
/// announce-mode stack. Residual theoretical ambiguity: a lone non-compat
/// entry with S=0 is rejected as missing its bottom-of-stack marker —
/// unreachable from compliant (single compat field) or stack-echoing
/// (BOS-terminated) senders.
pub(crate) fn split_withdraw_label_field(
    value: &[u8],
    total_len_bits: u8,
    family: impl fmt::Display + Copy,
    field_start: &[u8],
) -> Result<(usize, u8), DecodeError> {
    match value.get(..MPLS_LABEL_ENTRY_LEN) {
        // 0x800000 (RFC 8277 §2.4) or 0x000000 (GoBGP's ZERO_LABEL; seen
        // from stacks that zero the withdraw label field).
        Some([0x80 | 0x00, 0x00, 0x00]) => Ok((MPLS_LABEL_ENTRY_LEN, MPLS_LABEL_ENTRY_BITS)),
        // Echoed announce-mode label stack: S-bit walk. The decoded label
        // values are discarded — withdraw identity is RD/prefix only.
        _ => decode_label_stack(value, total_len_bits, family, field_start)
            .map(|(_, octets, bits)| (octets, bits)),
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
    encode_label_stack(&entry.labels, buf)?;
    buf.extend_from_slice(&entry.route_distinguisher.0);
    let prefix_octets = entry.prefix.wire_octets();
    let prefix_byte_count = usize::from(entry.prefix.len().div_ceil(8));
    buf.extend_from_slice(&prefix_octets[..prefix_byte_count]);
    Ok(())
}

/// Encode an RFC 8277 label stack as raw 3-octet entries. Shared by the
/// SAFI 128 (VPN) and SAFI 4 (labeled-unicast) announce-mode encoders.
pub(crate) fn encode_label_stack(
    labels: &[MplsLabelEntry],
    buf: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    for label in labels {
        let raw = label.raw_value()?;
        buf.push(((raw >> 16) & 0xFF) as u8);
        buf.push(((raw >> 8) & 0xFF) as u8);
        buf.push((raw & 0xFF) as u8);
    }
    Ok(())
}

/// Validate an RFC 8277 label stack for encoding: non-empty, in-range
/// values, and exactly one bottom-of-stack marker on the final entry.
/// Shared by the SAFI 128 (VPN) and SAFI 4 (labeled-unicast) encoders.
pub(crate) fn validate_label_stack(labels: &[MplsLabelEntry]) -> Result<(), EncodeError> {
    if labels.is_empty() {
        return Err(EncodeError::ValueOutOfRange {
            field: "MPLS label stack",
            value: "empty".to_string(),
        });
    }
    for (index, label) in labels.iter().enumerate() {
        validate_label(label.label)?;
        validate_traffic_class(label.traffic_class)?;
        if label.bottom_of_stack && index + 1 != labels.len() {
            return Err(EncodeError::ValueOutOfRange {
                field: "MPLS label stack",
                value: "bottom-of-stack before final label".to_string(),
            });
        }
    }
    if !labels.last().is_some_and(|label| label.bottom_of_stack) {
        return Err(EncodeError::ValueOutOfRange {
            field: "MPLS label stack",
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
    fn withdraw_encode_emits_compatibility_value_and_ignores_labels() {
        let entry = VpnNlri {
            labels: vec![label(200, true)], // ignored on withdraw encode
            route_distinguisher: rd(),
            prefix: VpnPrefix::v4(Ipv4Addr::new(10, 0, 1, 0), 24).unwrap(),
        };
        let mut buf = Vec::new();
        encode_vpn_withdraw_nlri(std::slice::from_ref(&entry), VpnAddressFamily::V4, &mut buf)
            .unwrap();
        assert_eq!(buf[0], 24 + 64 + 24);
        assert_eq!(&buf[1..4], &VPN_WITHDRAW_COMPATIBILITY);

        let decoded = decode_vpn_withdraw_nlri(&buf, VpnAddressFamily::V4).unwrap();
        assert_eq!(decoded.len(), 1);
        assert!(decoded[0].labels.is_empty());
        assert_eq!(decoded[0].route_distinguisher, rd());
        assert_eq!(decoded[0].prefix, entry.prefix);
    }

    #[test]
    fn withdraw_decode_accepts_zero_compatibility_value() {
        // GoBGP's ZERO_LABEL: some stacks zero the withdraw label field.
        // 0x000000 has S=0, so an S-bit walk would consume the RD — it must
        // be taken as a single compatibility field.
        let mut buf = vec![24 + 64, 0x00, 0x00, 0x00];
        buf.extend_from_slice(&rd().0);
        let decoded = decode_vpn_withdraw_nlri(&buf, VpnAddressFamily::V4).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].route_distinguisher, rd());
        assert_eq!(
            decoded[0].prefix,
            VpnPrefix::v4(Ipv4Addr::UNSPECIFIED, 0).unwrap()
        );
    }

    /// GoBGP-shaped multi-label `VPNv4` withdraw: `GoBGP` has no
    /// withdraw-mode encoder and echoes the announced label stack
    /// (801, 802) verbatim. The old single-compatibility-field parse
    /// mis-read the second label as the start of the RD.
    #[test]
    fn withdraw_decode_vpnv4_multi_label_stack_echo() {
        let mut buf = vec![
            0x88, // 136 bits = 2×24 label + 64 RD + 24 prefix
            0x00, 0x32, 0x10, // label 801, S=0
            0x00, 0x32, 0x21, // label 802, S=1
        ];
        buf.extend_from_slice(&rd().0);
        buf.extend_from_slice(&[0xC6, 0x33, 0x65]); // 198.51.101.0/24

        let decoded = decode_vpn_withdraw_nlri(&buf, VpnAddressFamily::V4).unwrap();
        assert_eq!(decoded.len(), 1);
        assert!(decoded[0].labels.is_empty());
        assert_eq!(decoded[0].route_distinguisher, rd());
        assert_eq!(decoded[0].prefix.to_string(), "198.51.101.0/24");
    }

    /// GoBGP-shaped multi-label `VPNv6` stack-echo withdraw.
    #[test]
    fn withdraw_decode_vpnv6_multi_label_stack_echo() {
        let mut buf = vec![
            0xA0, // 160 bits = 2×24 label + 64 RD + 48 prefix
            0x03, 0xE8, 0x00, // label 16000, S=0
            0x05, 0xDC, 0x01, // label 24000, S=1
        ];
        buf.extend_from_slice(&rd().0);
        buf.extend_from_slice(&[0x20, 0x01, 0x0D, 0xB8, 0x01, 0x00]); // 2001:db8:100::/48

        let decoded = decode_vpn_withdraw_nlri(&buf, VpnAddressFamily::V6).unwrap();
        assert_eq!(decoded.len(), 1);
        assert!(decoded[0].labels.is_empty());
        assert_eq!(decoded[0].route_distinguisher, rd());
        assert_eq!(decoded[0].prefix.to_string(), "2001:db8:100::/48");
    }

    #[test]
    fn withdraw_decode_rejects_stack_without_bottom_of_stack() {
        // Not a compatibility value and no S=1 within the declared length.
        let buf = vec![
            0x58, // 88 bits
            0x00, 0x32, 0x10, // S=0
            0x00, 0x32, 0x20, // S=0
            0x00, 0x32, 0x30, // S=0
            0x00, 0x00, // filler to 11 bytes
        ];
        let err = decode_vpn_withdraw_nlri(&buf, VpnAddressFamily::V4).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));
    }

    #[test]
    fn withdraw_decode_rejects_stack_consuming_route_distinguisher() {
        // A 48-bit echoed stack leaves only 40 of the declared 88 bits —
        // not enough for the 64-bit RD.
        let buf = vec![
            0x58, // 88 bits
            0x00, 0x32, 0x10, // label 801, S=0
            0x00, 0x32, 0x21, // label 802, S=1
            0x00, 0x00, 0x00, 0x00, 0x00, // 40 bits of would-be RD
        ];
        let err = decode_vpn_withdraw_nlri(&buf, VpnAddressFamily::V4).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));
    }

    #[test]
    fn withdraw_encode_rejects_wrong_family_and_restores_buffer() {
        let entry = VpnNlri {
            labels: vec![],
            route_distinguisher: rd(),
            prefix: VpnPrefix::v6(Ipv6Addr::LOCALHOST, 128).unwrap(),
        };
        let mut buf = vec![0xAA];
        let err = encode_vpn_withdraw_nlri(&[entry], VpnAddressFamily::V4, &mut buf).unwrap_err();
        assert!(matches!(err, EncodeError::ValueOutOfRange { .. }));
        assert_eq!(buf, vec![0xAA]);
    }

    #[test]
    fn addpath_vpnv4_roundtrip_multiple() {
        let entries = vec![
            VpnNlriEntry {
                path_id: 1,
                nlri: VpnNlri {
                    labels: vec![label(200, true)],
                    route_distinguisher: rd(),
                    prefix: VpnPrefix::v4(Ipv4Addr::new(10, 0, 1, 0), 24).unwrap(),
                },
            },
            VpnNlriEntry {
                path_id: 0xFFFF_FFFF,
                nlri: VpnNlri {
                    labels: vec![label(16_000, false), label(24_000, true)],
                    route_distinguisher: rd(),
                    prefix: VpnPrefix::v4(Ipv4Addr::new(192, 0, 2, 0), 24).unwrap(),
                },
            },
        ];
        let mut buf = Vec::new();
        encode_vpn_nlri_addpath(&entries, VpnAddressFamily::V4, &mut buf).unwrap();
        assert_eq!(
            decode_vpn_nlri_addpath(&buf, VpnAddressFamily::V4).unwrap(),
            entries
        );
    }

    #[test]
    fn addpath_vpnv6_roundtrip() {
        let entry = VpnNlriEntry {
            path_id: 7,
            nlri: VpnNlri {
                labels: vec![label(300, true)],
                route_distinguisher: rd(),
                prefix: VpnPrefix::v6("2001:db8:100::".parse().unwrap(), 48).unwrap(),
            },
        };
        let mut buf = Vec::new();
        encode_vpn_nlri_addpath(std::slice::from_ref(&entry), VpnAddressFamily::V6, &mut buf)
            .unwrap();
        assert_eq!(
            decode_vpn_nlri_addpath(&buf, VpnAddressFamily::V6).unwrap(),
            vec![entry]
        );
    }

    /// GoBGP-shaped `VPNv4` Add-Path fixture: the 4-octet Path Identifier is
    /// prepended to the whole RFC 8277 NLRI (length octet included) —
    /// `path_id=2`, then len=112 bits, label 100 (BOS), RD 65001:100,
    /// 10.0.1.0/24.
    #[test]
    fn addpath_vpnv4_gobgp_shaped_fixture() {
        let mut buf = vec![
            0x00, 0x00, 0x00, 0x02, // path_id = 2
            0x70, // 112 bits = 24 label + 64 RD + 24 prefix
            0x00, 0x06, 0x41, // label 100, TC 0, S=1
        ];
        buf.extend_from_slice(&rd().0); // RD 65001:100
        buf.extend_from_slice(&[10, 0, 1]); // 10.0.1.0/24

        let decoded = decode_vpn_nlri_addpath(&buf, VpnAddressFamily::V4).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].path_id, 2);
        assert_eq!(decoded[0].nlri.labels, vec![label(100, true)]);
        assert_eq!(decoded[0].nlri.route_distinguisher, rd());
        assert_eq!(decoded[0].nlri.prefix.to_string(), "10.0.1.0/24");

        let mut reencoded = Vec::new();
        encode_vpn_nlri_addpath(&decoded, VpnAddressFamily::V4, &mut reencoded).unwrap();
        assert_eq!(reencoded, buf);
    }

    #[test]
    fn addpath_withdraw_roundtrip_emits_compatibility_value() {
        let entry = VpnNlriEntry {
            path_id: 3,
            nlri: VpnNlri {
                labels: vec![label(200, true)], // ignored on withdraw encode
                route_distinguisher: rd(),
                prefix: VpnPrefix::v4(Ipv4Addr::new(10, 0, 1, 0), 24).unwrap(),
            },
        };
        let mut buf = Vec::new();
        encode_vpn_withdraw_nlri_addpath(
            std::slice::from_ref(&entry),
            VpnAddressFamily::V4,
            &mut buf,
        )
        .unwrap();
        // path_id(4) | len | compat(3) | RD(8) | prefix(3)
        assert_eq!(&buf[..4], &3u32.to_be_bytes());
        assert_eq!(buf[4], 24 + 64 + 24);
        assert_eq!(&buf[5..8], &VPN_WITHDRAW_COMPATIBILITY);

        let decoded = decode_vpn_withdraw_nlri_addpath(&buf, VpnAddressFamily::V4).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].path_id, 3);
        assert!(decoded[0].nlri.labels.is_empty());
        assert_eq!(decoded[0].nlri.route_distinguisher, rd());
        assert_eq!(decoded[0].nlri.prefix, entry.nlri.prefix);
    }

    #[test]
    fn addpath_withdraw_decode_label_stack_echo() {
        // GoBGP-shaped stack-echo withdraw under Add-Path.
        let mut buf = 9u32.to_be_bytes().to_vec();
        buf.extend_from_slice(&[
            0x88, // 136 bits = 2×24 label + 64 RD + 24 prefix
            0x00, 0x32, 0x10, // label 801, S=0
            0x00, 0x32, 0x21, // label 802, S=1
        ]);
        buf.extend_from_slice(&rd().0);
        buf.extend_from_slice(&[0xC6, 0x33, 0x65]); // 198.51.101.0/24

        let decoded = decode_vpn_withdraw_nlri_addpath(&buf, VpnAddressFamily::V4).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].path_id, 9);
        assert!(decoded[0].nlri.labels.is_empty());
        assert_eq!(decoded[0].nlri.route_distinguisher, rd());
        assert_eq!(decoded[0].nlri.prefix.to_string(), "198.51.101.0/24");
    }

    /// Stack-echo compatibility invariant: for every announce-encodable
    /// NLRI, the announce bytes (what `GoBGP` sends as a withdraw) decode
    /// through the withdraw decoders to the same route key.
    #[test]
    fn withdraw_stack_echo_matches_announce_key() {
        let cases = [
            (
                VpnAddressFamily::V4,
                vec![
                    VpnNlri {
                        labels: vec![label(3, true)],
                        route_distinguisher: rd(),
                        prefix: VpnPrefix::v4(Ipv4Addr::UNSPECIFIED, 0).unwrap(),
                    },
                    VpnNlri {
                        labels: vec![label(801, false), label(802, true)],
                        route_distinguisher: rd(),
                        prefix: VpnPrefix::v4(Ipv4Addr::new(198, 51, 101, 0), 24).unwrap(),
                    },
                    VpnNlri {
                        labels: vec![label(100, false), label(200, false), label(300, true)],
                        route_distinguisher: rd(),
                        prefix: VpnPrefix::v4(Ipv4Addr::new(203, 0, 113, 7), 32).unwrap(),
                    },
                ],
            ),
            (
                VpnAddressFamily::V6,
                vec![
                    VpnNlri {
                        labels: vec![label(16_000, false), label(24_000, true)],
                        route_distinguisher: rd(),
                        prefix: VpnPrefix::v6("2001:db8:100::".parse().unwrap(), 48).unwrap(),
                    },
                    VpnNlri {
                        labels: vec![label(42, true)],
                        route_distinguisher: rd(),
                        prefix: VpnPrefix::v6("2001:db8::1".parse().unwrap(), 128).unwrap(),
                    },
                ],
            ),
        ];

        for (family, entries) in cases {
            let mut announce = Vec::new();
            encode_vpn_nlri(&entries, family, &mut announce).unwrap();
            let withdrawn = decode_vpn_withdraw_nlri(&announce, family).unwrap();
            assert_eq!(withdrawn.len(), entries.len());
            for (got, want) in withdrawn.iter().zip(&entries) {
                assert!(got.labels.is_empty());
                assert_eq!(got.key(), want.key(), "{family}");
            }

            let addpath: Vec<_> = entries
                .iter()
                .enumerate()
                .map(|(i, nlri)| VpnNlriEntry {
                    path_id: u32::try_from(i).unwrap() + 1,
                    nlri: nlri.clone(),
                })
                .collect();
            let mut announce = Vec::new();
            encode_vpn_nlri_addpath(&addpath, family, &mut announce).unwrap();
            let withdrawn = decode_vpn_withdraw_nlri_addpath(&announce, family).unwrap();
            assert_eq!(withdrawn.len(), addpath.len());
            for (got, want) in withdrawn.iter().zip(&addpath) {
                assert_eq!(got.path_id, want.path_id);
                assert_eq!(got.nlri.key(), want.nlri.key(), "{family}");
            }
        }
    }

    #[test]
    fn addpath_decode_rejects_truncated_path_id() {
        let err = decode_vpn_nlri_addpath(&[0, 0, 1], VpnAddressFamily::V4).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));
        let err = decode_vpn_withdraw_nlri_addpath(&[0, 0, 1], VpnAddressFamily::V4).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));
    }

    #[test]
    fn addpath_decode_rejects_truncated_value() {
        let mut buf = 1u32.to_be_bytes().to_vec();
        buf.extend_from_slice(&[112, 0, 0x0C, 0x81]);
        let err = decode_vpn_nlri_addpath(&buf, VpnAddressFamily::V4).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));
    }

    #[test]
    fn addpath_encode_rejects_wrong_family_and_restores_buffer() {
        let entry = VpnNlriEntry {
            path_id: 1,
            nlri: VpnNlri {
                labels: vec![label(100, true)],
                route_distinguisher: rd(),
                prefix: VpnPrefix::v6(Ipv6Addr::LOCALHOST, 128).unwrap(),
            },
        };
        let mut buf = vec![0xAA];
        let err =
            encode_vpn_nlri_addpath(std::slice::from_ref(&entry), VpnAddressFamily::V4, &mut buf)
                .unwrap_err();
        assert!(matches!(err, EncodeError::ValueOutOfRange { .. }));
        assert_eq!(buf, vec![0xAA]);

        let mut buf = vec![0xBB];
        let err =
            encode_vpn_withdraw_nlri_addpath(&[entry], VpnAddressFamily::V4, &mut buf).unwrap_err();
        assert!(matches!(err, EncodeError::ValueOutOfRange { .. }));
        assert_eq!(buf, vec![0xBB]);
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
