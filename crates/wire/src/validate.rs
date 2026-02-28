use std::collections::HashSet;

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
/// `has_nlri` — true if the UPDATE carries announced prefixes.
/// `is_ebgp` — true if the session is external BGP.
///
/// # Errors
///
/// Returns an `UpdateError` with the appropriate subcode and data.
pub fn validate_update_attributes(
    attrs: &[PathAttribute],
    has_nlri: bool,
    is_ebgp: bool,
) -> Result<(), UpdateError> {
    check_duplicate_types(attrs)?;
    check_unrecognized_wellknown(attrs)?;

    if has_nlri {
        check_mandatory_present(attrs, is_ebgp)?;
    }

    for attr in attrs {
        match attr {
            PathAttribute::NextHop(addr) => check_next_hop(*addr)?,
            PathAttribute::AsPath(path) => check_as_path(path)?,
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
fn check_mandatory_present(attrs: &[PathAttribute], is_ebgp: bool) -> Result<(), UpdateError> {
    let present: HashSet<u8> = attrs.iter().map(PathAttribute::type_code).collect();

    for &tc in MANDATORY_ATTRS {
        if !present.contains(&tc) {
            return Err(UpdateError {
                subcode: update_subcode::MISSING_WELLKNOWN,
                data: vec![tc],
            });
        }
    }

    // NEXT_HOP mandatory for eBGP with NLRI
    if is_ebgp && !present.contains(&attr_type::NEXT_HOP) {
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
        assert!(validate_update_attributes(&attrs, true, true).is_ok());
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
        assert!(validate_update_attributes(&attrs, true, false).is_ok());
    }

    #[test]
    fn withdrawal_only_no_attrs_ok() {
        // No NLRI → no mandatory attributes required
        assert!(validate_update_attributes(&[], false, true).is_ok());
    }

    #[test]
    fn reject_duplicate_type() {
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::Origin(Origin::Egp),
        ];
        let err = validate_update_attributes(&attrs, false, true).unwrap_err();
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
        let err = validate_update_attributes(&attrs, true, true).unwrap_err();
        assert_eq!(err.subcode, update_subcode::MISSING_WELLKNOWN);
    }

    #[test]
    fn reject_missing_as_path() {
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
        ];
        let err = validate_update_attributes(&attrs, true, true).unwrap_err();
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
        let err = validate_update_attributes(&attrs, true, true).unwrap_err();
        assert_eq!(err.subcode, update_subcode::MISSING_WELLKNOWN);
        assert_eq!(err.data, vec![attr_type::NEXT_HOP]);
    }

    #[test]
    fn reject_next_hop_unspecified() {
        let attrs = basic_attrs(Ipv4Addr::UNSPECIFIED);
        let err = validate_update_attributes(&attrs, true, true).unwrap_err();
        assert_eq!(err.subcode, update_subcode::INVALID_NEXT_HOP);
    }

    #[test]
    fn reject_next_hop_loopback() {
        let attrs = basic_attrs(Ipv4Addr::LOCALHOST);
        let err = validate_update_attributes(&attrs, true, true).unwrap_err();
        assert_eq!(err.subcode, update_subcode::INVALID_NEXT_HOP);
    }

    #[test]
    fn reject_next_hop_multicast() {
        let attrs = basic_attrs(Ipv4Addr::new(224, 0, 0, 1));
        let err = validate_update_attributes(&attrs, true, true).unwrap_err();
        assert_eq!(err.subcode, update_subcode::INVALID_NEXT_HOP);
    }

    #[test]
    fn reject_next_hop_broadcast() {
        let attrs = basic_attrs(Ipv4Addr::BROADCAST);
        let err = validate_update_attributes(&attrs, true, true).unwrap_err();
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
        let err = validate_update_attributes(&attrs, true, true).unwrap_err();
        assert_eq!(err.subcode, update_subcode::MALFORMED_AS_PATH);
    }

    #[test]
    fn reject_unrecognized_wellknown() {
        let attrs = vec![PathAttribute::Unknown(RawAttribute {
            flags: attr_flags::TRANSITIVE, // Optional=0 → claims well-known
            type_code: 99,
            data: Bytes::from_static(&[1, 2, 3]),
        })];
        let err = validate_update_attributes(&attrs, false, true).unwrap_err();
        assert_eq!(err.subcode, update_subcode::UNRECOGNIZED_WELLKNOWN);
    }

    #[test]
    fn optional_unknown_attribute_ok() {
        let attrs = vec![PathAttribute::Unknown(RawAttribute {
            flags: attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            type_code: 99,
            data: Bytes::from_static(&[1, 2, 3]),
        })];
        assert!(validate_update_attributes(&attrs, false, true).is_ok());
    }
}
