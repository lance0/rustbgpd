//! Typed Route Target (RFC 4360 §4) — the import/export communities that
//! select which EVPN instance a route belongs to.
//!
//! This module deliberately models RTs as a domain enum rather than
//! reusing the wire crate's opaque [`rustbgpd_wire::ExtendedCommunity`]
//! 8-byte container. The enum:
//!
//! - is constructible only with valid type/subtype layouts — operator
//!   input goes through [`RouteTarget::from_str`] and either parses or
//!   rejects, never returning a half-formed RT;
//! - separates the three RT encodings without touching their on-wire
//!   form, so the encode-side conversion to a wire `ExtendedCommunity`
//!   stays a one-place mapping when the origination path lands;
//! - mirrors the textual format operators already type into
//!   community-match policy (e.g. `RT:65000:100`), without the `RT:`
//!   prefix because the field's type already says it's a Route Target.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// One Route Target, matching the three RFC 4360 §4 RT subtype encodings:
///
/// - `TwoOctetAs` — 2-octet AS (subtype 0x02 of type 0x00). Textual form
///   `<asn>:<value>` with `asn ≤ u16::MAX` and a 32-bit assigned value.
/// - `Ipv4` — IPv4 (subtype 0x02 of type 0x01). Textual form
///   `<ipv4>:<value>` with a 16-bit assigned value.
/// - `FourOctetAs` — 4-octet AS (subtype 0x02 of type 0x02). Textual
///   form `<asn>:<value>` with a 32-bit ASN and a 16-bit assigned value.
///
/// Two RTs are equal iff their wire-form bytes would match — the variant
/// itself is part of identity. `RT:65000:100` (`TwoOctetAs`) and
/// `RT:65000:100` parsed as a 4-octet AS form (which never happens with
/// the `from_str` parser, but could be constructed directly) are *not*
/// the same RT, by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RouteTarget {
    /// 2-octet AS Route Target (RFC 4360 §3.1, subtype 0x02).
    TwoOctetAs {
        /// Administrator field — 2-octet AS number.
        asn: u16,
        /// Assigned-number field — 4-octet operator-chosen value.
        value: u32,
    },
    /// IPv4 Route Target (RFC 4360 §3.2, subtype 0x02).
    Ipv4 {
        /// Administrator field — IPv4 address (typically a router-id).
        ipv4: Ipv4Addr,
        /// Assigned-number field — 2-octet operator-chosen value.
        value: u16,
    },
    /// 4-octet AS Route Target (RFC 5668 §2, subtype 0x02).
    FourOctetAs {
        /// Administrator field — 4-octet AS number.
        asn: u32,
        /// Assigned-number field — 2-octet operator-chosen value.
        value: u16,
    },
}

impl fmt::Display for RouteTarget {
    /// Format an RT in the canonical operator-facing shape, without the
    /// leading `RT:` discriminator (the surrounding type tells you it's
    /// a Route Target).
    ///
    /// - `TwoOctetAs { 65000, 100 }`        → `65000:100`
    /// - `Ipv4 { 192.0.2.1, 100 }`          → `192.0.2.1:100`
    /// - `FourOctetAs { 4200000000, 100 }`  → `4200000000:100`
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TwoOctetAs { asn, value } => write!(f, "{asn}:{value}"),
            Self::Ipv4 { ipv4, value } => write!(f, "{ipv4}:{value}"),
            Self::FourOctetAs { asn, value } => write!(f, "{asn}:{value}"),
        }
    }
}

/// Errors returned by [`RouteTarget::from_str`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RouteTargetParseError {
    /// Input did not contain exactly one `:` separator.
    #[error("expected RT in form `<asn|ipv4>:<value>`, missing `:`")]
    MissingColon,
    /// The administrator field was neither a valid `u32` nor a valid IPv4 address.
    #[error("invalid RT administrator {0:?}: expected ASN (u32) or IPv4 address")]
    InvalidAdministrator(String),
    /// The assigned-number field was not a non-negative integer.
    #[error("invalid RT value {0:?}: expected non-negative integer")]
    InvalidValue(String),
    /// The assigned-number field exceeded the maximum permitted by the
    /// inferred RT subtype (`u32::MAX` for `TwoOctetAs`, `u16::MAX` for
    /// the IPv4 and `FourOctetAs` forms).
    #[error("RT value {value} exceeds maximum {max} for the inferred RT type")]
    ValueOutOfRange {
        /// The parsed value that was rejected.
        value: u64,
        /// The maximum permitted by the RT subtype that was inferred from
        /// the administrator field.
        max: u64,
    },
}

/// Errors returned by the auto-derived Route Target constructors
/// ([`RouteTarget::auto_derived_vxlan_l2_rfc8365`] and
/// [`RouteTarget::auto_derived_ip_vrf_as_vni`]).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RouteTargetAutoDeriveError {
    /// Auto-derivation packs the VNI into a 2-octet-AS Route Target, so a
    /// 4-octet AS has no room — configure `route_targets` explicitly.
    #[error(
        "auto-derived Route Targets require a 2-octet AS number; got {asn} — configure route_targets explicitly for 4-octet AS deployments"
    )]
    FourOctetAsn { asn: u32 },
    /// The service-id field is the 24-bit VNI and zero is not a valid local VNI.
    #[error("VNI {vni} is outside the auto-derived RT range 1..=16777215")]
    InvalidVni { vni: u32 },
}

impl FromStr for RouteTarget {
    type Err = RouteTargetParseError;

    /// Parse the textual `<admin>:<value>` form used by FRR / Cisco / Junos.
    ///
    /// Disambiguation rules (matching RFC 4360 §3 and the FRR/Cisco
    /// convention used elsewhere in rustbgpd):
    ///
    /// - If `admin` parses as an IPv4 address → [`RouteTarget::Ipv4`].
    /// - Else if `admin` ≤ 65535 → [`RouteTarget::TwoOctetAs`]
    ///   with a 32-bit `value`.
    /// - Else → [`RouteTarget::FourOctetAs`] with a 16-bit `value`.
    ///
    /// A leading `RT:` discriminator is accepted (and stripped) so that
    /// operator strings copied verbatim from policy `match_community`
    /// configuration parse cleanly here too.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let body = s.strip_prefix("RT:").unwrap_or(s);
        let (admin, value) = body
            .split_once(':')
            .ok_or(RouteTargetParseError::MissingColon)?;

        let parsed_value: u64 = value
            .parse()
            .map_err(|_| RouteTargetParseError::InvalidValue(value.to_string()))?;

        if let Ok(ipv4) = admin.parse::<Ipv4Addr>() {
            let value16 = u16::try_from(parsed_value).map_err(|_| {
                RouteTargetParseError::ValueOutOfRange {
                    value: parsed_value,
                    max: u64::from(u16::MAX),
                }
            })?;
            return Ok(Self::Ipv4 {
                ipv4,
                value: value16,
            });
        }

        let asn = admin
            .parse::<u32>()
            .map_err(|_| RouteTargetParseError::InvalidAdministrator(admin.to_string()))?;

        if let Ok(asn16) = u16::try_from(asn) {
            let value32 = u32::try_from(parsed_value).map_err(|_| {
                RouteTargetParseError::ValueOutOfRange {
                    value: parsed_value,
                    max: u64::from(u32::MAX),
                }
            })?;
            Ok(Self::TwoOctetAs {
                asn: asn16,
                value: value32,
            })
        } else {
            let value16 = u16::try_from(parsed_value).map_err(|_| {
                RouteTargetParseError::ValueOutOfRange {
                    value: parsed_value,
                    max: u64::from(u16::MAX),
                }
            })?;
            Ok(Self::FourOctetAs {
                asn,
                value: value16,
            })
        }
    }
}

impl RouteTarget {
    /// Build the RFC 8365 §5.1.2.1 auto-derived **L2VNI / MAC-VRF** VXLAN
    /// Route Target.
    ///
    /// The global administrator is the local 2-octet AS number. The local
    /// administrator packs `A=0` (auto-derived), `Type=1` (VXLAN),
    /// `D-ID=0`, and the 24-bit VNI service-id:
    ///
    /// ```text
    /// value = 0x10000000 | vni
    /// ```
    ///
    /// This is the form FRR emits for L2VNIs **only** when configured with
    /// `autort rfc8365-compatible`; FRR's default L2VNI autort is `AS:VNI`.
    /// For the L3VNI / IP-VRF auto-RT — which FRR derives as `AS:VNI`
    /// regardless of `autort` — use [`Self::auto_derived_ip_vrf_as_vni`].
    ///
    /// RFC 8365 requires manual RT configuration for 4-octet ASNs because
    /// the 3-octet VNI cannot fit in that RT layout.
    ///
    /// # Errors
    ///
    /// Returns [`RouteTargetAutoDeriveError::FourOctetAsn`] when `asn` is
    /// outside the 2-octet range, or
    /// [`RouteTargetAutoDeriveError::InvalidVni`] when `vni` is outside the
    /// 24-bit VXLAN VNI range.
    pub fn auto_derived_vxlan_l2_rfc8365(
        asn: u32,
        vni: u32,
    ) -> Result<Self, RouteTargetAutoDeriveError> {
        let asn =
            u16::try_from(asn).map_err(|_| RouteTargetAutoDeriveError::FourOctetAsn { asn })?;
        if !(1..=0x00ff_ffff).contains(&vni) {
            return Err(RouteTargetAutoDeriveError::InvalidVni { vni });
        }
        Ok(Self::TwoOctetAs {
            asn,
            value: 0x1000_0000 | vni,
        })
    }

    /// Build the auto-derived **L3VNI / IP-VRF** Route Target as `AS:VNI`.
    ///
    /// Unlike the L2VNI MAC-VRF auto-RT (RFC 8365 §5.1.2.1 opaque form),
    /// the de-facto vendor convention for the tenant-VRF L3VNI auto-RT is a
    /// plain `AS:VNI` 2-octet-AS Route Target — FRR derives this for the
    /// tenant VRF regardless of the `autort rfc8365-compatible` knob (which
    /// is MAC-VRF-only), and Cumulus/NVIDIA follow the same convention. We
    /// match it so `auto_derive_route_target` on `[[evpn_ip_vrfs]]`
    /// actually imports against a default FRR L3VNI peer.
    ///
    /// ```text
    /// value = vni
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`RouteTargetAutoDeriveError::FourOctetAsn`] when `asn` is
    /// outside the 2-octet range (the 24-bit VNI does not fit a 4-octet-AS
    /// RT's 2-octet local administrator), or
    /// [`RouteTargetAutoDeriveError::InvalidVni`] when `vni` is outside the
    /// 24-bit VNI range.
    pub fn auto_derived_ip_vrf_as_vni(
        asn: u32,
        vni: u32,
    ) -> Result<Self, RouteTargetAutoDeriveError> {
        let asn =
            u16::try_from(asn).map_err(|_| RouteTargetAutoDeriveError::FourOctetAsn { asn })?;
        if !(1..=0x00ff_ffff).contains(&vni) {
            return Err(RouteTargetAutoDeriveError::InvalidVni { vni });
        }
        Ok(Self::TwoOctetAs { asn, value: vni })
    }

    /// Encode into the 8-byte wire form of a Route Target Extended
    /// Community (RFC 4360 §3 / RFC 5668 §2). The first byte is the
    /// **type** (selects the administrator format), the second byte
    /// is the **subtype** (`0x02` = Route Target), and the remaining
    /// six bytes are the administrator + assigned-number value.
    ///
    /// | Variant       | Type byte (`bytes[0]`) | Subtype (`bytes[1]`) | Value layout                  |
    /// |---------------|------------------------|----------------------|-------------------------------|
    /// | `TwoOctetAs`  | `0x00`                 | `0x02`               | `[asn:u16, value:u32]`        |
    /// | `Ipv4`        | `0x01`                 | `0x02`               | `[ipv4:[u8;4], value:u16]`    |
    /// | `FourOctetAs` | `0x02`                 | `0x02`               | `[asn:u32, value:u16]`        |
    ///
    /// The type-byte's `0x40` bit is the **non-transitive** flag
    /// (RFC 4360 §3.1 — bit set means "do not propagate across
    /// AS boundaries"; bit clear, i.e. the value emitted here,
    /// means transitive). The decoder
    /// ([`Self::from_extended_community`]) clears this bit before
    /// matching so a non-transitive-flagged community still
    /// recognizes as the same Route Target subtype — relevant if a
    /// peer originates RTs with the non-transitive bit set
    /// (uncommon for RTs but RFC-permitted).
    ///
    /// Used by Type 2 / Type 3 / Type 4 / Type 5 origination on the
    /// daemon side.
    #[must_use]
    pub fn to_extended_community(self) -> rustbgpd_wire::ExtendedCommunity {
        match self {
            Self::TwoOctetAs { asn, value } => {
                let a = asn.to_be_bytes();
                let v = value.to_be_bytes();
                rustbgpd_wire::ExtendedCommunity::new(u64::from_be_bytes([
                    0x00, 0x02, a[0], a[1], v[0], v[1], v[2], v[3],
                ]))
            }
            Self::Ipv4 { ipv4, value } => {
                let a = ipv4.octets();
                let v = value.to_be_bytes();
                rustbgpd_wire::ExtendedCommunity::new(u64::from_be_bytes([
                    0x01, 0x02, a[0], a[1], a[2], a[3], v[0], v[1],
                ]))
            }
            Self::FourOctetAs { asn, value } => {
                let a = asn.to_be_bytes();
                let v = value.to_be_bytes();
                rustbgpd_wire::ExtendedCommunity::new(u64::from_be_bytes([
                    0x02, 0x02, a[0], a[1], a[2], a[3], v[0], v[1],
                ]))
            }
        }
    }

    /// Decode the inverse of [`Self::to_extended_community`]. Returns
    /// `None` for any extended community that isn't a Route Target —
    /// the subtype byte (`bytes[1]`) must be `0x02` and the type
    /// byte (`bytes[0]`, after clearing the non-transitive flag)
    /// must be one of the three RFC-defined formats (`0x00` / `0x01`
    /// / `0x02`).
    #[must_use]
    pub fn from_extended_community(c: rustbgpd_wire::ExtendedCommunity) -> Option<Self> {
        let bytes = c.as_u64().to_be_bytes();
        // Subtype must be 0x02 (Route Target).
        if bytes[1] != 0x02 {
            return None;
        }
        // Type byte selects the variant. Clear *only* the
        // non-transitive flag bit (`0x40`, RFC 4360 §3.1) so a
        // non-transitive RT decodes as the same format as a
        // transitive one. RTs are conventionally transitive (bit
        // clear), but RFC-permitted non-transitive variants must
        // round-trip cleanly too. Critically, we keep `0x80` intact
        // — that bit is reserved by IANA for the "Experimental"
        // type-byte range. A community with `0x80 | 0x02` set must
        // NOT be mistaken for a TwoOctetAs RT (which `& 0x3F` would
        // do, because 0x80 & 0x3F == 0x00).
        match bytes[0] & !0x40 {
            0x00 => Some(Self::TwoOctetAs {
                asn: u16::from_be_bytes([bytes[2], bytes[3]]),
                value: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            }),
            0x01 => Some(Self::Ipv4 {
                ipv4: Ipv4Addr::new(bytes[2], bytes[3], bytes[4], bytes[5]),
                value: u16::from_be_bytes([bytes[6], bytes[7]]),
            }),
            0x02 => Some(Self::FourOctetAs {
                asn: u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
                value: u16::from_be_bytes([bytes[6], bytes[7]]),
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_two_octet_as() {
        let rt: RouteTarget = "65000:100".parse().unwrap();
        assert_eq!(
            rt,
            RouteTarget::TwoOctetAs {
                asn: 65000,
                value: 100
            }
        );
        assert_eq!(rt.to_string(), "65000:100");
    }

    #[test]
    fn parse_two_octet_as_max_value() {
        let rt: RouteTarget = "65000:4294967295".parse().unwrap();
        assert_eq!(
            rt,
            RouteTarget::TwoOctetAs {
                asn: 65000,
                value: u32::MAX,
            }
        );
    }

    #[test]
    fn parse_ipv4_form() {
        let rt: RouteTarget = "192.0.2.1:100".parse().unwrap();
        assert_eq!(
            rt,
            RouteTarget::Ipv4 {
                ipv4: Ipv4Addr::new(192, 0, 2, 1),
                value: 100,
            }
        );
        assert_eq!(rt.to_string(), "192.0.2.1:100");
    }

    #[test]
    fn parse_four_octet_as() {
        let rt: RouteTarget = "4200000000:200".parse().unwrap();
        assert_eq!(
            rt,
            RouteTarget::FourOctetAs {
                asn: 4_200_000_000,
                value: 200,
            }
        );
        assert_eq!(rt.to_string(), "4200000000:200");
    }

    #[test]
    fn derives_l2_rfc8365_vxlan_route_target() {
        // L2VNI MAC-VRF: RFC 8365 §5.1.2.1 opaque form (0x10000000 | vni).
        // AS 65000 / VNI 100 -> 65000:268435556.
        let rt = RouteTarget::auto_derived_vxlan_l2_rfc8365(65000, 100).unwrap();
        assert_eq!(
            rt,
            RouteTarget::TwoOctetAs {
                asn: 65000,
                value: 0x1000_0000 | 0x0000_0064,
            }
        );
        assert_eq!(rt.to_string(), "65000:268435556");
    }

    #[test]
    fn derives_l2_rfc8365_route_target_for_max_vni() {
        assert_eq!(
            RouteTarget::auto_derived_vxlan_l2_rfc8365(65535, 0x00ff_ffff).unwrap(),
            RouteTarget::TwoOctetAs {
                asn: 65535,
                value: 0x10ff_ffff,
            }
        );
    }

    #[test]
    fn derives_ip_vrf_as_vni_route_target() {
        // L3VNI / IP-VRF: plain AS:VNI, matching FRR's default tenant-VRF
        // auto-RT. AS 65000 / VNI 100 -> 65000:100.
        let rt = RouteTarget::auto_derived_ip_vrf_as_vni(65000, 100).unwrap();
        assert_eq!(
            rt,
            RouteTarget::TwoOctetAs {
                asn: 65000,
                value: 100
            }
        );
        assert_eq!(rt.to_string(), "65000:100");
    }

    #[test]
    fn derives_ip_vrf_as_vni_route_target_for_max_vni() {
        assert_eq!(
            RouteTarget::auto_derived_ip_vrf_as_vni(65535, 0x00ff_ffff).unwrap(),
            RouteTarget::TwoOctetAs {
                asn: 65535,
                value: 0x00ff_ffff,
            }
        );
    }

    #[test]
    fn auto_derived_route_targets_reject_four_octet_asn() {
        assert_eq!(
            RouteTarget::auto_derived_vxlan_l2_rfc8365(65536, 100).unwrap_err(),
            RouteTargetAutoDeriveError::FourOctetAsn { asn: 65536 }
        );
        assert_eq!(
            RouteTarget::auto_derived_ip_vrf_as_vni(65536, 100).unwrap_err(),
            RouteTargetAutoDeriveError::FourOctetAsn { asn: 65536 }
        );
    }

    #[test]
    fn auto_derived_route_targets_reject_invalid_vni() {
        for ctor in [
            RouteTarget::auto_derived_vxlan_l2_rfc8365,
            RouteTarget::auto_derived_ip_vrf_as_vni,
        ] {
            assert_eq!(
                ctor(65000, 0).unwrap_err(),
                RouteTargetAutoDeriveError::InvalidVni { vni: 0 }
            );
            assert_eq!(
                ctor(65000, 0x0100_0000).unwrap_err(),
                RouteTargetAutoDeriveError::InvalidVni { vni: 0x0100_0000 }
            );
        }
    }

    #[test]
    fn accepts_leading_rt_prefix() {
        let rt: RouteTarget = "RT:65000:100".parse().unwrap();
        assert_eq!(
            rt,
            RouteTarget::TwoOctetAs {
                asn: 65000,
                value: 100
            }
        );
    }

    #[test]
    fn rejects_missing_colon() {
        let err = "65000".parse::<RouteTarget>().unwrap_err();
        assert_eq!(err, RouteTargetParseError::MissingColon);
    }

    #[test]
    fn rejects_invalid_admin() {
        let err = "not-an-asn:1".parse::<RouteTarget>().unwrap_err();
        assert!(matches!(
            err,
            RouteTargetParseError::InvalidAdministrator(_)
        ));
    }

    #[test]
    fn rejects_invalid_value() {
        let err = "65000:abc".parse::<RouteTarget>().unwrap_err();
        assert!(matches!(err, RouteTargetParseError::InvalidValue(_)));
    }

    #[test]
    fn rejects_value_overflow_for_ipv4_form() {
        let err = "192.0.2.1:65536".parse::<RouteTarget>().unwrap_err();
        assert_eq!(
            err,
            RouteTargetParseError::ValueOutOfRange {
                value: 65_536,
                max: u64::from(u16::MAX),
            }
        );
    }

    #[test]
    fn rejects_value_overflow_for_four_octet_as() {
        let err = "4200000000:65536".parse::<RouteTarget>().unwrap_err();
        assert_eq!(
            err,
            RouteTargetParseError::ValueOutOfRange {
                value: 65_536,
                max: u64::from(u16::MAX),
            }
        );
    }

    #[test]
    fn from_extended_community_round_trips_transitive_variants() {
        for rt in [
            RouteTarget::TwoOctetAs {
                asn: 65000,
                value: 100,
            },
            RouteTarget::Ipv4 {
                ipv4: std::net::Ipv4Addr::new(10, 0, 0, 1),
                value: 42,
            },
            RouteTarget::FourOctetAs {
                asn: 4_200_000_000,
                value: 7,
            },
        ] {
            let ext = rt.to_extended_community();
            assert_eq!(RouteTarget::from_extended_community(ext), Some(rt));
        }
    }

    #[test]
    fn from_extended_community_decodes_non_transitive_rt() {
        // RFC 4360 §3.1: a non-transitive RT has bit 0x40 set on
        // the type byte. We don't emit these (transitive is the
        // default), but if a peer does, the decoder should
        // recognize them as the same Route Target subtype.
        let raw_transitive: u64 = 0x0002_0000_0000_0000 | (65000_u64 << 32) | 0x0000_0064;
        let raw_non_transitive = raw_transitive | 0x4000_0000_0000_0000;
        let ext = rustbgpd_wire::ExtendedCommunity::new(raw_non_transitive);
        assert_eq!(
            RouteTarget::from_extended_community(ext),
            Some(RouteTarget::TwoOctetAs {
                asn: 65000,
                value: 100,
            })
        );
    }

    #[test]
    fn from_extended_community_rejects_experimental_range_type_byte() {
        // Regression for the `bytes[0] & 0x3F` bug — that mask
        // cleared 0x80 as well as 0x40, so an extended community
        // with type byte 0x80 (IANA Experimental range, NOT a Route
        // Target) and subtype 0x02 would decode as TwoOctetAs.
        // Under the fixed `bytes[0] & !0x40` mask, the high bit
        // is preserved and the match falls through to `None`.
        let raw: u64 = 0x8002_0000_0000_0000 | (65000_u64 << 32) | 0x0000_0064;
        let ext = rustbgpd_wire::ExtendedCommunity::new(raw);
        assert_eq!(RouteTarget::from_extended_community(ext), None);
    }

    #[test]
    fn from_extended_community_rejects_wrong_subtype() {
        // Type 0x00 + subtype 0x03 is "Route Origin", not Route
        // Target. Must not decode.
        let raw: u64 = 0x0003_0000_0000_0000 | (65000_u64 << 32) | 0x0000_0064;
        let ext = rustbgpd_wire::ExtendedCommunity::new(raw);
        assert_eq!(RouteTarget::from_extended_community(ext), None);
    }

    #[test]
    fn ord_is_total_and_stable() {
        // Used by EvpnInstance to canonicalize RT lists; smoke test the ordering.
        let mut rts = [
            RouteTarget::TwoOctetAs {
                asn: 65000,
                value: 100,
            },
            RouteTarget::TwoOctetAs {
                asn: 64000,
                value: 200,
            },
            RouteTarget::FourOctetAs {
                asn: 4_200_000_000,
                value: 1,
            },
        ];
        rts.sort();
        assert_eq!(
            rts[0],
            RouteTarget::TwoOctetAs {
                asn: 64000,
                value: 200,
            }
        );
    }
}
