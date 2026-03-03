use std::collections::HashSet;
use std::net::IpAddr;

use crate::attribute::{AsPath, AsPathSegment, PathAttribute, attr_error_data};
use crate::constants::{attr_flags, attr_type};
use crate::notification::update_subcode;

/// Error produced by UPDATE attribute validation.
///
/// Contains the NOTIFICATION subcode and data bytes per RFC 4271 §6.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateError {
    pub subcode: u8,
    pub data: Vec<u8>,
}

/// Well-known attribute type codes that MUST be present when NLRI is advertised.
const MANDATORY_ATTRS: &[u8] = &[attr_type::ORIGIN, attr_type::AS_PATH];

/// Validate the semantic correctness of a set of path attributes.
///
/// This is separate from decode (which is structural — "can I read these bytes?").
/// Validation checks whether the attribute set is RFC-compliant for this UPDATE.
///
/// `has_nlri` — true if the UPDATE carries announced prefixes (body or MP).
/// `has_body_nlri` — true if the UPDATE carries IPv4 NLRI in the body fields.
/// `is_ebgp` — true if the session is external BGP.
///
/// # Errors
///
/// Returns an `UpdateError` with the appropriate subcode and data.
pub fn validate_update_attributes(
    attrs: &[PathAttribute],
    has_nlri: bool,
    has_body_nlri: bool,
    is_ebgp: bool,
) -> Result<(), UpdateError> {
    check_duplicate_types(attrs)?;
    check_unrecognized_wellknown(attrs)?;

    if has_nlri {
        check_mandatory_present(attrs, has_body_nlri, is_ebgp)?;
    }

    for attr in attrs {
        match attr {
            PathAttribute::NextHop(addr) => check_next_hop(*addr)?,
            PathAttribute::AsPath(path) => check_as_path(path)?,
            PathAttribute::MpReachNlri(mp) => check_mp_reach_next_hop(mp.next_hop)?,
            _ => {}
        }
    }

    Ok(())
}

/// (3,1) Duplicate attribute type codes.
fn check_duplicate_types(attrs: &[PathAttribute]) -> Result<(), UpdateError> {
    let mut seen = HashSet::new();
    for attr in attrs {
        let tc = attr.type_code();
        if !seen.insert(tc) {
            return Err(UpdateError {
                subcode: update_subcode::MALFORMED_ATTRIBUTE_LIST,
                data: vec![],
            });
        }
    }
    Ok(())
}

/// (3,2) Unrecognized well-known attribute: Optional=0 and type code unknown.
fn check_unrecognized_wellknown(attrs: &[PathAttribute]) -> Result<(), UpdateError> {
    for attr in attrs {
        if let PathAttribute::Unknown(raw) = attr {
            // If Optional bit is NOT set, it claims to be well-known
            if (raw.flags & attr_flags::OPTIONAL) == 0 {
                return Err(UpdateError {
                    subcode: update_subcode::UNRECOGNIZED_WELLKNOWN,
                    data: attr_error_data(raw.flags, raw.type_code, &raw.data),
                });
            }
        }
    }
    Ok(())
}

/// (3,3) Missing mandatory well-known attributes.
///
/// `has_body_nlri` — true if the UPDATE carries IPv4 NLRI in the body fields.
/// When only `MP_REACH_NLRI` is present (no body NLRI), `NEXT_HOP` is carried
/// inside the MP attribute (RFC 4760 §3) and not required as a separate attribute.
/// Mixed UPDATEs (body NLRI + `MP_REACH_NLRI`) still require body `NEXT_HOP`.
fn check_mandatory_present(
    attrs: &[PathAttribute],
    has_body_nlri: bool,
    is_ebgp: bool,
) -> Result<(), UpdateError> {
    let present: HashSet<u8> = attrs.iter().map(PathAttribute::type_code).collect();

    for &tc in MANDATORY_ATTRS {
        if !present.contains(&tc) {
            return Err(UpdateError {
                subcode: update_subcode::MISSING_WELLKNOWN,
                data: vec![tc],
            });
        }
    }

    // NEXT_HOP mandatory for eBGP when body NLRI is present. When only MP_REACH
    // carries NLRI, the next-hop is inside the MP attribute (RFC 4760 §3).
    if is_ebgp && has_body_nlri && !present.contains(&attr_type::NEXT_HOP) {
        return Err(UpdateError {
            subcode: update_subcode::MISSING_WELLKNOWN,
            data: vec![attr_type::NEXT_HOP],
        });
    }

    Ok(())
}

/// (3,8) Invalid `NEXT_HOP` address.
fn check_next_hop(addr: std::net::Ipv4Addr) -> Result<(), UpdateError> {
    let octets = addr.octets();

    // 0.0.0.0
    if addr.is_unspecified() {
        return Err(UpdateError {
            subcode: update_subcode::INVALID_NEXT_HOP,
            data: octets.to_vec(),
        });
    }

    // 127.0.0.0/8
    if addr.is_loopback() {
        return Err(UpdateError {
            subcode: update_subcode::INVALID_NEXT_HOP,
            data: octets.to_vec(),
        });
    }

    // 224.0.0.0/4 (multicast)
    if addr.is_multicast() {
        return Err(UpdateError {
            subcode: update_subcode::INVALID_NEXT_HOP,
            data: octets.to_vec(),
        });
    }

    // 255.255.255.255
    if addr.is_broadcast() {
        return Err(UpdateError {
            subcode: update_subcode::INVALID_NEXT_HOP,
            data: octets.to_vec(),
        });
    }

    Ok(())
}

/// Validate `MP_REACH_NLRI` next-hop address.
fn check_mp_reach_next_hop(addr: IpAddr) -> Result<(), UpdateError> {
    match addr {
        IpAddr::V4(v4) => check_next_hop(v4)?,
        IpAddr::V6(v6) => {
            if !is_valid_ipv6_nexthop(&v6) {
                return Err(UpdateError {
                    subcode: update_subcode::INVALID_NEXT_HOP,
                    data: v6.octets().to_vec(),
                });
            }
        }
    }
    Ok(())
}

/// Check if an IPv6 address is link-local (`fe80::/10`).
fn is_ipv6_link_local(addr: &std::net::Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

/// Returns `true` if `addr` is a valid IPv6 next-hop for BGP advertisements.
///
/// Rejects unspecified (`::`), loopback (`::1`), multicast (`ff00::/8`),
/// and link-local (`fe80::/10`) addresses.
#[must_use]
pub fn is_valid_ipv6_nexthop(addr: &std::net::Ipv6Addr) -> bool {
    !addr.is_unspecified()
        && !addr.is_loopback()
        && !addr.is_multicast()
        && !is_ipv6_link_local(addr)
}

/// (3,11) Malformed `AS_PATH`.
fn check_as_path(path: &AsPath) -> Result<(), UpdateError> {
    for segment in &path.segments {
        let asns = match segment {
            AsPathSegment::AsSet(asns) | AsPathSegment::AsSequence(asns) => asns,
        };
        if asns.is_empty() {
            return Err(UpdateError {
                subcode: update_subcode::MALFORMED_AS_PATH,
                data: vec![],
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use bytes::Bytes;

    use super::*;
    use crate::attribute::{Origin, RawAttribute};

    fn basic_attrs(next_hop: Ipv4Addr) -> Vec<PathAttribute> {
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001])],
            }),
            PathAttribute::NextHop(next_hop),
        ]
    }

    #[test]
    fn valid_ebgp_update() {
        let attrs = basic_attrs(Ipv4Addr::new(10, 0, 0, 1));
        assert!(validate_update_attributes(&attrs, true, true, true).is_ok());
    }

    #[test]
    fn valid_ibgp_update_no_next_hop() {
        // iBGP doesn't require NEXT_HOP (it's optional based on the peer)
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001])],
            }),
        ];
        assert!(validate_update_attributes(&attrs, true, true, false).is_ok());
    }

    #[test]
    fn withdrawal_only_no_attrs_ok() {
        // No NLRI → no mandatory attributes required
        assert!(validate_update_attributes(&[], false, false, true).is_ok());
    }

    #[test]
    fn reject_duplicate_type() {
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::Origin(Origin::Egp),
        ];
        let err = validate_update_attributes(&attrs, false, false, true).unwrap_err();
        assert_eq!(err.subcode, update_subcode::MALFORMED_ATTRIBUTE_LIST);
    }

    #[test]
    fn reject_missing_origin() {
        let attrs = vec![
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
        ];
        let err = validate_update_attributes(&attrs, true, true, true).unwrap_err();
        assert_eq!(err.subcode, update_subcode::MISSING_WELLKNOWN);
    }

    #[test]
    fn reject_missing_as_path() {
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
        ];
        let err = validate_update_attributes(&attrs, true, true, true).unwrap_err();
        assert_eq!(err.subcode, update_subcode::MISSING_WELLKNOWN);
    }

    #[test]
    fn reject_missing_next_hop_ebgp() {
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001])],
            }),
        ];
        let err = validate_update_attributes(&attrs, true, true, true).unwrap_err();
        assert_eq!(err.subcode, update_subcode::MISSING_WELLKNOWN);
        assert_eq!(err.data, vec![attr_type::NEXT_HOP]);
    }

    #[test]
    fn reject_next_hop_unspecified() {
        let attrs = basic_attrs(Ipv4Addr::UNSPECIFIED);
        let err = validate_update_attributes(&attrs, true, true, true).unwrap_err();
        assert_eq!(err.subcode, update_subcode::INVALID_NEXT_HOP);
    }

    #[test]
    fn reject_next_hop_loopback() {
        let attrs = basic_attrs(Ipv4Addr::LOCALHOST);
        let err = validate_update_attributes(&attrs, true, true, true).unwrap_err();
        assert_eq!(err.subcode, update_subcode::INVALID_NEXT_HOP);
    }

    #[test]
    fn reject_next_hop_multicast() {
        let attrs = basic_attrs(Ipv4Addr::new(224, 0, 0, 1));
        let err = validate_update_attributes(&attrs, true, true, true).unwrap_err();
        assert_eq!(err.subcode, update_subcode::INVALID_NEXT_HOP);
    }

    #[test]
    fn reject_next_hop_broadcast() {
        let attrs = basic_attrs(Ipv4Addr::BROADCAST);
        let err = validate_update_attributes(&attrs, true, true, true).unwrap_err();
        assert_eq!(err.subcode, update_subcode::INVALID_NEXT_HOP);
    }

    #[test]
    fn reject_empty_as_path_segment() {
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
        ];
        let err = validate_update_attributes(&attrs, true, true, true).unwrap_err();
        assert_eq!(err.subcode, update_subcode::MALFORMED_AS_PATH);
    }

    #[test]
    fn reject_unrecognized_wellknown() {
        let attrs = vec![PathAttribute::Unknown(RawAttribute {
            flags: attr_flags::TRANSITIVE, // Optional=0 → claims well-known
            type_code: 99,
            data: Bytes::from_static(&[1, 2, 3]),
        })];
        let err = validate_update_attributes(&attrs, false, false, true).unwrap_err();
        assert_eq!(err.subcode, update_subcode::UNRECOGNIZED_WELLKNOWN);
    }

    #[test]
    fn optional_unknown_attribute_ok() {
        let attrs = vec![PathAttribute::Unknown(RawAttribute {
            flags: attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            type_code: 99,
            data: Bytes::from_static(&[1, 2, 3]),
        })];
        assert!(validate_update_attributes(&attrs, false, false, true).is_ok());
    }

    // --- MP_REACH_NLRI validation tests ---

    #[test]
    fn mp_reach_nlri_no_body_next_hop_required_for_ebgp() {
        use crate::attribute::MpReachNlri;
        use crate::capability::{Afi, Safi};
        use crate::nlri::{Ipv6Prefix, NlriEntry, Prefix};

        // eBGP UPDATE with MP_REACH_NLRI only (no body NLRI): NEXT_HOP not required
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001])],
            }),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                next_hop: std::net::IpAddr::V6("2001:db8::1".parse().unwrap()),
                announced: vec![NlriEntry {
                    path_id: 0,
                    prefix: Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32)),
                }],
            }),
        ];
        // has_nlri=true, has_body_nlri=false (only MP NLRI), is_ebgp=true
        assert!(validate_update_attributes(&attrs, true, false, true).is_ok());
    }

    #[test]
    fn mixed_update_requires_body_next_hop_for_ebgp() {
        use crate::attribute::MpReachNlri;
        use crate::capability::{Afi, Safi};
        use crate::nlri::{Ipv6Prefix, NlriEntry, Prefix};

        // eBGP UPDATE with BOTH body NLRI and MP_REACH_NLRI but no NEXT_HOP attr
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001])],
            }),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                next_hop: std::net::IpAddr::V6("2001:db8::1".parse().unwrap()),
                announced: vec![NlriEntry {
                    path_id: 0,
                    prefix: Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32)),
                }],
            }),
        ];
        // has_nlri=true, has_body_nlri=true (body IPv4 NLRI present), is_ebgp=true
        // → should require NEXT_HOP for the body NLRI
        let err = validate_update_attributes(&attrs, true, true, true).unwrap_err();
        assert_eq!(err.subcode, update_subcode::MISSING_WELLKNOWN);
        assert_eq!(err.data, vec![attr_type::NEXT_HOP]);
    }

    #[test]
    fn mp_reach_nlri_reject_unspecified_v6_next_hop() {
        use crate::attribute::MpReachNlri;
        use crate::capability::{Afi, Safi};

        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001])],
            }),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                next_hop: std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                announced: vec![],
            }),
        ];
        let err = validate_update_attributes(&attrs, true, false, true).unwrap_err();
        assert_eq!(err.subcode, update_subcode::INVALID_NEXT_HOP);
    }

    #[test]
    fn mp_reach_nlri_reject_link_local_v6_next_hop() {
        use crate::attribute::MpReachNlri;
        use crate::capability::{Afi, Safi};

        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001])],
            }),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                next_hop: std::net::IpAddr::V6("fe80::1".parse().unwrap()),
                announced: vec![],
            }),
        ];
        let err = validate_update_attributes(&attrs, true, false, true).unwrap_err();
        assert_eq!(err.subcode, update_subcode::INVALID_NEXT_HOP);
    }

    #[test]
    fn mp_reach_nlri_reject_loopback_v6_next_hop() {
        use crate::attribute::MpReachNlri;
        use crate::capability::{Afi, Safi};

        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001])],
            }),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                next_hop: std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                announced: vec![],
            }),
        ];
        let err = validate_update_attributes(&attrs, true, false, true).unwrap_err();
        assert_eq!(err.subcode, update_subcode::INVALID_NEXT_HOP);
    }

    #[test]
    fn is_valid_ipv6_nexthop_accepts_global() {
        assert!(super::is_valid_ipv6_nexthop(
            &"2001:db8::1".parse().unwrap()
        ));
    }

    #[test]
    fn is_valid_ipv6_nexthop_rejects_unspecified() {
        assert!(!super::is_valid_ipv6_nexthop(
            &std::net::Ipv6Addr::UNSPECIFIED
        ));
    }

    #[test]
    fn is_valid_ipv6_nexthop_rejects_loopback() {
        assert!(!super::is_valid_ipv6_nexthop(
            &std::net::Ipv6Addr::LOCALHOST
        ));
    }

    #[test]
    fn is_valid_ipv6_nexthop_rejects_link_local() {
        assert!(!super::is_valid_ipv6_nexthop(&"fe80::1".parse().unwrap()));
    }

    #[test]
    fn is_valid_ipv6_nexthop_rejects_multicast() {
        assert!(!super::is_valid_ipv6_nexthop(&"ff02::1".parse().unwrap()));
    }

    #[test]
    fn mp_reach_nlri_reject_multicast_v6_next_hop() {
        use crate::attribute::MpReachNlri;
        use crate::capability::{Afi, Safi};

        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001])],
            }),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                // ff02::1 is multicast
                next_hop: std::net::IpAddr::V6("ff02::1".parse().unwrap()),
                announced: vec![],
            }),
        ];
        let err = validate_update_attributes(&attrs, true, false, true).unwrap_err();
        assert_eq!(err.subcode, update_subcode::INVALID_NEXT_HOP);
    }
}
