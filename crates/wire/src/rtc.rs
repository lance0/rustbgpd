//! RT-Constrain NLRI codec substrate (RFC 4684, AFI 1 / SAFI 132).
//!
//! This module is deliberately pure and unreachable from MP_REACH/MP_UNREACH
//! dispatch today. It provides the Route Target membership NLRI codec and
//! prefix-matching pieces needed for a future RT-Constrain route-reflector
//! slice, mirroring the VPNv4/VPNv6 substrate in [`crate::vpn`].

use std::fmt;

use crate::attribute::ExtendedCommunity;
use crate::error::{DecodeError, EncodeError};

/// SAFI for RT-Constrain NLRI (RFC 4684 §7).
pub const RTC_SAFI: u8 = 132;
/// Maximum RT-Constrain prefix length in bits: origin AS (32) + RT (64).
pub const RTC_MAX_PREFIX_BITS: u8 = 96;
/// Minimum non-default RT-Constrain prefix length in bits (RFC 4684 §4
/// requires the full origin-AS field for a non-default NLRI).
pub const RTC_MIN_NON_DEFAULT_PREFIX_BITS: u8 = 32;

/// RFC 4684 Route Target membership NLRI.
///
/// A 0–96-bit prefix over `origin_as(4 octets) + route_target(8 octets)`.
/// The zero-length prefix ([`RtcNlri::DEFAULT`]) is the default/wildcard
/// membership: interest in every Route Target. Lengths 1–31 are malformed
/// (the origin-AS field cannot be partially covered), matching `GoBGP`'s
/// decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RtcNlri {
    /// Origin AS of the advertised membership (bits 0–31 of the prefix).
    pub origin_as: u32,
    /// Route Target extended-community bytes (bits 32–95 of the prefix),
    /// stored as the raw big-endian 8-octet community value.
    pub route_target_bits: u64,
    /// Prefix length in bits: 0 (default) or 32..=96.
    pub prefix_len: u8,
}

impl RtcNlri {
    /// The default (zero-length) RT membership NLRI: matches every RT.
    pub const DEFAULT: Self = Self {
        origin_as: 0,
        route_target_bits: 0,
        prefix_len: 0,
    };

    /// Construct a canonical RT-Constrain NLRI, masking any bits set past
    /// `prefix_len` (mirrors [`crate::vpn::VpnPrefix::v4`] host-bit masking).
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::ValueOutOfRange`] when `prefix_len` is 1–31 or
    /// greater than 96.
    pub fn new(
        origin_as: u32,
        route_target_bits: u64,
        prefix_len: u8,
    ) -> Result<Self, EncodeError> {
        validate_prefix_len(prefix_len)?;
        let value = (u128::from(origin_as) << 64) | u128::from(route_target_bits);
        Ok(Self::from_masked(mask_value(value, prefix_len), prefix_len))
    }

    /// Whether this is the zero-length default membership NLRI.
    #[must_use]
    pub const fn is_default(&self) -> bool {
        self.prefix_len == 0
    }

    /// The 96-bit prefix value right-aligned in a `u128`: origin AS in bits
    /// 64–95, Route Target bytes in bits 0–63.
    #[must_use]
    pub fn value_u128(&self) -> u128 {
        (u128::from(self.origin_as) << 64) | u128::from(self.route_target_bits)
    }

    /// RFC 4684 §3 membership matching: does this NLRI cover Route Target
    /// `rt`?
    ///
    /// Only Route Target extended communities (sub-type 0x02 in a two-part
    /// encoding) can match; anything else — including Route Origin — never
    /// matches, even against the default NLRI. The 96-bit candidate is
    /// `(rt_global_admin << 64) | rt_raw`, where the global administrator is
    /// the AS number for type 0x00/0x02 encodings and the IPv4 address as a
    /// `u32` for type 0x01.
    ///
    /// `GoBGP` diverges here: it compares only the 64 RT bits and ignores the
    /// origin-AS field, so when an RT's global administrator differs from the
    /// NLRI's origin AS we under-advertise relative to `GoBGP`. That is the
    /// RFC-defensible side of the divergence (never advertises more than the
    /// peer asked for).
    #[must_use]
    pub fn matches(&self, rt: ExtendedCommunity) -> bool {
        let Some((global_admin, _local)) = rt.route_target() else {
            return false;
        };
        if self.prefix_len == 0 {
            return true;
        }
        let candidate = (u128::from(global_admin) << 64) | u128::from(rt.as_u64());
        (candidate ^ self.value_u128()) >> (96 - u32::from(self.prefix_len)) == 0
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "value is at most 96 bits, so the two halves fit u32/u64 exactly"
    )]
    const fn from_masked(value: u128, prefix_len: u8) -> Self {
        Self {
            origin_as: (value >> 64) as u32,
            route_target_bits: value as u64,
            prefix_len,
        }
    }

    fn wire_octets(&self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[..4].copy_from_slice(&self.origin_as.to_be_bytes());
        out[4..].copy_from_slice(&self.route_target_bits.to_be_bytes());
        out
    }
}

impl fmt::Display for RtcNlri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_default() {
            write!(f, "default")
        } else {
            write!(
                f,
                "{}:{}/{}",
                self.origin_as,
                ExtendedCommunity::new(self.route_target_bits),
                self.prefix_len
            )
        }
    }
}

/// Decode RT-Constrain NLRI bytes.
///
/// One codec covers both announce and withdraw: RFC 4684 has no VPN-style
/// compatibility-field split. The default NLRI is a single `0x00` length
/// byte; a non-default NLRI is `len` + `ceil(len/8)` value bytes. Rejects
/// prefix lengths 1–31 and >96, truncated values, and non-canonical
/// encodings with bits set past `prefix_len`.
///
/// # Errors
///
/// Returns [`DecodeError::InvalidNetworkField`] for any malformed entry.
pub fn decode_rtc_nlri(mut buf: &[u8]) -> Result<Vec<RtcNlri>, DecodeError> {
    let mut entries = Vec::new();

    while !buf.is_empty() {
        let field_start = buf;
        let prefix_len = buf[0];
        buf = &buf[1..];

        if prefix_len != 0
            && !(RTC_MIN_NON_DEFAULT_PREFIX_BITS..=RTC_MAX_PREFIX_BITS).contains(&prefix_len)
        {
            return invalid_rtc_nlri(
                format!("RTC NLRI prefix length {prefix_len} bits is not 0 or 32..=96"),
                field_start,
                1,
            );
        }

        let value_len = usize::from(prefix_len.div_ceil(8));
        if buf.len() < value_len {
            return invalid_rtc_nlri(
                format!(
                    "RTC NLRI truncated: length {prefix_len} bits requires {value_len} bytes, have {}",
                    buf.len()
                ),
                field_start,
                1 + buf.len(),
            );
        }

        let value = &buf[..value_len];
        buf = &buf[value_len..];

        let mut raw: u128 = 0;
        for (index, byte) in value.iter().enumerate() {
            raw |= u128::from(*byte) << (88 - 8 * index);
        }
        if mask_value(raw, prefix_len) != raw {
            return invalid_rtc_nlri(
                format!("RTC NLRI has non-zero bits past prefix length {prefix_len}"),
                field_start,
                1 + value_len,
            );
        }

        entries.push(RtcNlri::from_masked(raw, prefix_len));
    }

    Ok(entries)
}

/// Encode RT-Constrain NLRI bytes.
///
/// The default NLRI encodes as exactly one `0x00` length byte. On error,
/// `buf` is restored to its original length.
///
/// # Errors
///
/// Returns [`EncodeError::ValueOutOfRange`] if an entry has an invalid
/// prefix length or non-canonical bits set past its prefix length.
pub fn encode_rtc_nlri(entries: &[RtcNlri], buf: &mut Vec<u8>) -> Result<(), EncodeError> {
    let start_len = buf.len();

    for entry in entries {
        if let Err(err) = encode_one_rtc_nlri(entry, buf) {
            buf.truncate(start_len);
            return Err(err);
        }
    }

    Ok(())
}

fn encode_one_rtc_nlri(entry: &RtcNlri, buf: &mut Vec<u8>) -> Result<(), EncodeError> {
    validate_prefix_len(entry.prefix_len)?;
    let value = entry.value_u128();
    if mask_value(value, entry.prefix_len) != value {
        return Err(EncodeError::ValueOutOfRange {
            field: "RTC NLRI value",
            value: format!("non-zero bits past prefix length {}", entry.prefix_len),
        });
    }

    buf.push(entry.prefix_len);
    let octets = entry.wire_octets();
    buf.extend_from_slice(&octets[..usize::from(entry.prefix_len.div_ceil(8))]);
    Ok(())
}

fn validate_prefix_len(prefix_len: u8) -> Result<(), EncodeError> {
    if prefix_len == 0
        || (RTC_MIN_NON_DEFAULT_PREFIX_BITS..=RTC_MAX_PREFIX_BITS).contains(&prefix_len)
    {
        Ok(())
    } else {
        Err(EncodeError::ValueOutOfRange {
            field: "RTC NLRI prefix length",
            value: prefix_len.to_string(),
        })
    }
}

/// Keep only the top `len` bits of a right-aligned 96-bit value.
///
/// Precondition: `value < 2^96` and `len <= 96` (all internal callers
/// construct values from a `u32` + `u64` pair or at most 12 decoded bytes).
fn mask_value(value: u128, len: u8) -> u128 {
    if len == 0 {
        0
    } else {
        value & (u128::MAX << (96 - u32::from(len)))
    }
}

fn invalid_rtc_nlri<T>(detail: String, data: &[u8], len: usize) -> Result<T, DecodeError> {
    Err(DecodeError::InvalidNetworkField {
        detail,
        data: data[..len.min(data.len())].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Repo-canonical RT:65001:100 — 2-octet-AS-specific (type 0x00,
    /// sub-type 0x02): AS 65001 = 0xFDE9, local admin 100 = 0x64.
    const RT_65001_100: u64 = 0x0002_FDE9_0000_0064;

    fn nlri(origin_as: u32, rt: u64, len: u8) -> RtcNlri {
        RtcNlri::new(origin_as, rt, len).unwrap()
    }

    #[test]
    fn constants_match_rfc_4684() {
        assert_eq!(RTC_SAFI, 132);
        assert_eq!(RTC_MAX_PREFIX_BITS, 96);
        assert_eq!(RTC_MIN_NON_DEFAULT_PREFIX_BITS, 32);
    }

    #[test]
    fn default_round_trips_as_single_zero_byte() {
        let mut buf = Vec::new();
        encode_rtc_nlri(&[RtcNlri::DEFAULT], &mut buf).unwrap();
        assert_eq!(buf, vec![0x00], "default NLRI is exactly one zero byte");

        let decoded = decode_rtc_nlri(&buf).unwrap();
        assert_eq!(decoded, vec![RtcNlri::DEFAULT]);
        assert!(decoded[0].is_default());
    }

    #[test]
    fn full_96_bit_fixture_matches_gobgp_bytes() {
        // GoBGP serializes NewRouteTargetMembershipNLRI(65001, RT:65001:100)
        // as: length byte 0x60 (96 bits), origin AS 65001 big-endian, then
        // the 8-byte 2-octet-AS RT extended community.
        let entry = nlri(65001, RT_65001_100, 96);
        let mut buf = Vec::new();
        encode_rtc_nlri(std::slice::from_ref(&entry), &mut buf).unwrap();
        assert_eq!(
            buf,
            vec![
                0x60, // 96-bit prefix length
                0x00, 0x00, 0xFD, 0xE9, // origin AS 65001
                0x00, 0x02, 0xFD, 0xE9, 0x00, 0x00, 0x00, 0x64, // RT:65001:100
            ]
        );
        assert_eq!(decode_rtc_nlri(&buf).unwrap(), vec![entry]);
    }

    #[test]
    fn partial_lengths_round_trip() {
        for len in [32, 48, 96] {
            let entry = nlri(65001, RT_65001_100, len);
            let mut buf = Vec::new();
            encode_rtc_nlri(std::slice::from_ref(&entry), &mut buf).unwrap();
            assert_eq!(buf[0], len);
            assert_eq!(buf.len(), 1 + usize::from(len.div_ceil(8)));
            assert_eq!(decode_rtc_nlri(&buf).unwrap(), vec![entry], "len {len}");
        }
    }

    #[test]
    fn multiple_entries_preserve_order() {
        let a = RtcNlri::DEFAULT;
        let b = nlri(65001, RT_65001_100, 96);
        let mut buf = Vec::new();
        encode_rtc_nlri(&[a, b], &mut buf).unwrap();
        assert_eq!(decode_rtc_nlri(&buf).unwrap(), vec![a, b]);
    }

    #[test]
    fn constructor_masks_bits_past_prefix_len() {
        // /32 keeps only the origin AS; every RT bit is masked away.
        let entry = nlri(65001, RT_65001_100, 32);
        assert_eq!(entry.origin_as, 65001);
        assert_eq!(entry.route_target_bits, 0);

        // /48 keeps the origin AS plus the RT type + sub-type bytes.
        let entry = nlri(65001, RT_65001_100, 48);
        assert_eq!(entry.origin_as, 65001);
        assert_eq!(entry.route_target_bits, 0x0002_0000_0000_0000);
    }

    #[test]
    fn constructor_rejects_invalid_prefix_lengths() {
        for len in [1, 16, 31, 97, u8::MAX] {
            assert!(
                matches!(
                    RtcNlri::new(65001, RT_65001_100, len),
                    Err(EncodeError::ValueOutOfRange { .. })
                ),
                "len {len} must be rejected"
            );
        }
    }

    #[test]
    fn decode_rejects_lengths_1_to_31_and_over_96() {
        for len in [1u8, 31] {
            let mut buf = vec![len];
            buf.extend_from_slice(&[0u8; 4]);
            let err = decode_rtc_nlri(&buf).unwrap_err();
            assert!(
                matches!(err, DecodeError::InvalidNetworkField { .. }),
                "len {len}"
            );
        }
        let mut buf = vec![97u8];
        buf.extend_from_slice(&[0u8; 13]);
        assert!(matches!(
            decode_rtc_nlri(&buf).unwrap_err(),
            DecodeError::InvalidNetworkField { .. }
        ));
    }

    #[test]
    fn decode_rejects_truncated_value() {
        // /96 requires 12 value bytes; provide only 4.
        let err = decode_rtc_nlri(&[0x60, 0x00, 0x00, 0xFD, 0xE9]).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));
    }

    #[test]
    fn decode_rejects_trailing_garbage() {
        let mut buf = Vec::new();
        encode_rtc_nlri(&[nlri(65001, RT_65001_100, 96)], &mut buf).unwrap();
        buf.push(0xFF); // 255-bit length is not a valid RTC prefix length
        let err = decode_rtc_nlri(&buf).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));
    }

    #[test]
    fn decode_rejects_non_canonical_bits_past_prefix_len() {
        // len 33 needs 5 value bytes; bits 33..40 of the fifth byte must be
        // zero. 0x7F sets them all.
        let buf = [33u8, 0x00, 0x00, 0xFD, 0xE9, 0x7F];
        let err = decode_rtc_nlri(&buf).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidNetworkField { .. }));
    }

    #[test]
    fn encode_rejects_non_canonical_entry_and_restores_buffer() {
        // Bypass the masking constructor to build a non-canonical value.
        let entry = RtcNlri {
            origin_as: 65001,
            route_target_bits: RT_65001_100,
            prefix_len: 32,
        };
        let mut buf = vec![0xAA];
        let err = encode_rtc_nlri(&[entry], &mut buf).unwrap_err();
        assert!(matches!(err, EncodeError::ValueOutOfRange { .. }));
        assert_eq!(buf, vec![0xAA]);
    }

    #[test]
    fn default_matches_any_route_target() {
        // 2-octet-AS, 4-octet-AS, and IPv4-address RT encodings all match.
        for rt in [
            RT_65001_100,
            0x0202_0001_0001_00C8, // 4-octet AS 65537, local 200
            0x0102_C000_0201_0064, // IPv4 192.0.2.1, local 100
        ] {
            assert!(RtcNlri::DEFAULT.matches(ExtendedCommunity::new(rt)));
        }
    }

    #[test]
    fn full_96_exact_hit_and_miss() {
        let entry = nlri(65001, RT_65001_100, 96);
        assert!(entry.matches(ExtendedCommunity::new(RT_65001_100)));
        // Same origin AS, different local admin (101) — miss at /96.
        assert!(!entry.matches(ExtendedCommunity::new(0x0002_FDE9_0000_0065)));
    }

    #[test]
    fn prefix_48_hit_and_miss() {
        // /48 covers origin AS + RT type/sub-type: interest in every
        // 2-octet-AS RT whose global administrator is 65001.
        let entry = nlri(65001, RT_65001_100, 48);
        assert!(entry.matches(ExtendedCommunity::new(RT_65001_100)));
        assert!(entry.matches(ExtendedCommunity::new(0x0002_FDE9_0000_03E7))); // RT:65001:999
        // RT:65002:100 — global admin mismatch flips candidate bits inside /48.
        assert!(!entry.matches(ExtendedCommunity::new(0x0002_FDEA_0000_0064)));
    }

    #[test]
    fn prefix_32_matches_origin_as_only() {
        // LAN-190 §D: a /32 NLRI covers only the origin-AS field. Every RT
        // bit below it — the RT type/sub-type byte included — is outside the
        // prefix and ignored, so interest in AS 65001 matches that AS's RTs
        // regardless of RT sub-type encoding or local admin.
        let entry = nlri(65001, 0, 32);
        // 2-octet-AS RT:65001:100 (type 0x00) — global admin 65001.
        assert!(entry.matches(ExtendedCommunity::new(RT_65001_100)));
        // Same global admin 65001 but a DIFFERENT RT sub-type encoding
        // (4-octet AS, type 0x02, RT:65001:999) — still a hit; /32
        // discriminates on origin-AS alone, not the RT sub-type.
        assert!(entry.matches(ExtendedCommunity::new(0x0202_0000_FDE9_03E7)));
        // A different global admin (65002) misses.
        assert!(!entry.matches(ExtendedCommunity::new(0x0002_FDEA_0000_0064)));
        // A non-RT community (Route Origin, sub-type 0x03) never matches,
        // even when its global admin equals the origin AS.
        assert!(!entry.matches(ExtendedCommunity::new(0x0003_FDE9_0000_0064)));
    }

    #[test]
    fn origin_as_mismatch_at_96_misses() {
        // The RT bytes are identical, but the candidate's high 32 bits come
        // from the RT's global administrator (65001), not the NLRI's origin
        // AS (64999) — so this misses. GoBGP diverges: it compares only the
        // 64 RT bits and would match here. Under-advertising when RT admin ≠
        // origin AS is the RFC-defensible side of that divergence; do NOT
        // "fix" this by switching to exact 64-bit matching (that would break
        // legitimate <96-bit prefix filters).
        let entry = nlri(64999, RT_65001_100, 96);
        assert!(!entry.matches(ExtendedCommunity::new(RT_65001_100)));
    }

    #[test]
    fn non_rt_subtype_never_matches() {
        // Route Origin (sub-type 0x03) with otherwise identical bytes.
        let route_origin = ExtendedCommunity::new(0x0003_FDE9_0000_0064);
        assert!(!RtcNlri::DEFAULT.matches(route_origin));
        // Even an NLRI whose value bits would prefix-match cannot match a
        // non-RT community.
        let entry = RtcNlri::new(65001, 0x0003_FDE9_0000_0064, 96).unwrap();
        assert!(!entry.matches(route_origin));
    }

    #[test]
    fn ipv4_admin_rt_candidate_derivation() {
        // Type 0x01 RT:192.0.2.1:100 — the candidate's origin-AS field is
        // the IPv4 address as a u32 (0xC0000201).
        let rt = ExtendedCommunity::new(0x0102_C000_0201_0064);
        let hit = nlri(0xC000_0201, 0x0102_C000_0201_0064, 96);
        assert!(hit.matches(rt));
        let miss = nlri(65001, 0x0102_C000_0201_0064, 96);
        assert!(!miss.matches(rt));
    }

    #[test]
    fn display_formats() {
        assert_eq!(RtcNlri::DEFAULT.to_string(), "default");
        assert_eq!(
            nlri(65001, RT_65001_100, 96).to_string(),
            "65001:RT:65001:100/96"
        );
    }
}
