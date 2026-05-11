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
    /// The transitive flag (high bit `0x40` of the type byte, RFC
    /// 4360 §3) is omitted on emit — receivers OR it in as needed.
    /// The decoder ([`Self::from_extended_community`]) clears it
    /// before matching so a transitive-flagged community still
    /// recognizes as the same Route Target subtype.
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
    /// byte (`bytes[0]`, after masking the transitive flag) must be
    /// one of the three RFC-defined formats (`0x00` / `0x01` / `0x02`).
    #[must_use]
    pub fn from_extended_community(c: rustbgpd_wire::ExtendedCommunity) -> Option<Self> {
        let bytes = c.as_u64().to_be_bytes();
        // Subtype must be 0x02 (Route Target).
        if bytes[1] != 0x02 {
            return None;
        }
        // Type byte selects the variant. Mask off the transitive bit
        // (0x40, RFC 4360 §3) so a transitive-flagged community decodes
        // as the same RT format as a non-transitive one.
        match bytes[0] & 0x3F {
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
