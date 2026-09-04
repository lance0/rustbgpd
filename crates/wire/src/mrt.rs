//! MRT `TABLE_DUMP_V2` RIB-entry `MP_REACH_NLRI` decoding (RFC 6396 §4.3.4).
//!
//! Inside a `TABLE_DUMP_V2` RIB entry the `MP_REACH_NLRI` attribute is reduced
//! to its next hop: RFC 6396 §4.3.4 keeps the next-hop length and next hop and
//! drops the AFI, SAFI, reserved octet, and NLRI. Several collectors write the
//! full RFC 4760 layout instead. [`decode_table_dump_v2_mp_reach_next_hop`]
//! accepts both, so an MRT reader and a converter built on this crate agree on
//! which dumps are readable.

use crate::Afi;
use crate::error::DecodeError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IANA AFI numbers accepted in a full-form `MP_REACH_NLRI` header.
const AFI_IPV4: u16 = Afi::Ipv4 as u16;
const AFI_IPV6: u16 = Afi::Ipv6 as u16;

fn malformed(detail: String) -> DecodeError {
    DecodeError::MalformedField {
        message_type: "RIB entry MP_REACH_NLRI",
        detail,
    }
}

/// Decode the `MP_REACH_NLRI` value of a `TABLE_DUMP_V2` RIB entry into its
/// next hop, plus the link-local address when the next hop is the 32-octet
/// global + link-local pair (RFC 2545 §3).
///
/// Two encodings are accepted, told apart by the first octet: a next-hop
/// length is never 0, so a leading 0 can only be the high octet of AFI 1 or 2
/// — the discriminator bgpdump, bgpkit-parser, and mrtparse also use.
///
/// - Reduced form (RFC 6396 §4.3.4): next-hop length, next hop.
/// - Full form (RFC 4760 §3): AFI, SAFI, next-hop length, next hop, and an
///   optional single reserved octet whose value is ignored.
///
/// Everything else is rejected: a next-hop length other than 4, 16, or 32; a
/// truncated next hop; a full-form AFI that disagrees with the next-hop length
/// (AFI 1 requires 4, AFI 2 requires 16 or 32); and any octets past the next
/// hop beyond that one reserved octet.
///
/// # Errors
///
/// [`DecodeError::MalformedField`] for every rejected shape.
pub fn decode_table_dump_v2_mp_reach_next_hop(
    value: &[u8],
) -> Result<(IpAddr, Option<Ipv6Addr>), DecodeError> {
    let Some(&first) = value.first() else {
        return Err(malformed("empty value".to_owned()));
    };
    let (afi, nh_len_at) = if first == 0 {
        if value.len() < 4 {
            return Err(malformed(format!(
                "truncated full-form header: {} of 4 octets",
                value.len()
            )));
        }
        (Some(u16::from_be_bytes([value[0], value[1]])), 3)
    } else {
        (None, 0)
    };
    let nh_len = usize::from(value[nh_len_at]);
    let rest = &value[nh_len_at + 1..];
    let v6 = |o: &[u8; 16]| IpAddr::V6(Ipv6Addr::from(*o));
    let decoded = match (afi, nh_len) {
        (None | Some(AFI_IPV4), 4) => rest
            .split_first_chunk::<4>()
            .map(|(o, tail)| ((IpAddr::V4(Ipv4Addr::from(*o)), None), tail)),
        (None | Some(AFI_IPV6), 16) => rest
            .split_first_chunk::<16>()
            .map(|(o, tail)| ((v6(o), None), tail)),
        (None | Some(AFI_IPV6), 32) => rest.split_first_chunk::<16>().and_then(|(g, tail)| {
            tail.split_first_chunk::<16>()
                .map(|(ll, tail)| ((v6(g), Some(Ipv6Addr::from(*ll))), tail))
        }),
        (None, _) => {
            return Err(malformed(format!("NH-Len {nh_len} is not 4, 16, or 32")));
        }
        (Some(afi), _) => {
            return Err(malformed(format!(
                "AFI {afi} does not carry a {nh_len}-octet next hop"
            )));
        }
    };
    let Some((next_hop, tail)) = decoded else {
        return Err(malformed(format!(
            "truncated next hop: NH-Len {nh_len}, {} octets present",
            rest.len()
        )));
    };
    // The full form ends with one reserved octet (RFC 4760 §3); nothing else
    // may follow the next hop in either form.
    let reserved = usize::from(afi.is_some());
    if tail.len() > reserved {
        return Err(malformed(format!(
            "{} trailing octets after the next hop",
            tail.len() - reserved
        )));
    }
    Ok(next_hop)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cat(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    #[test]
    fn accepts_reduced_and_full_forms() {
        let global = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let v4 = [192, 0, 2, 1];
        let v6 = global.octets();
        let pair = cat(&[&v6, &link_local.octets()]);
        let cases = [
            // RFC 6396 §4.3.4 reduced form: NH-Len + next hop.
            (cat(&[&[4], &v4]), (IpAddr::V4(v4.into()), None)),
            (cat(&[&[16], &v6]), (IpAddr::V6(global), None)),
            (cat(&[&[32], &pair]), (IpAddr::V6(global), Some(link_local))),
            // Full RFC 4760 form: AFI, SAFI, NH-Len, next hop, optional
            // reserved octet.
            (
                cat(&[&[0, 1, 1, 4], &v4, &[0]]),
                (IpAddr::V4(v4.into()), None),
            ),
            (cat(&[&[0, 1, 1, 4], &v4]), (IpAddr::V4(v4.into()), None)),
            (
                cat(&[&[0, 2, 1, 16], &v6, &[0]]),
                (IpAddr::V6(global), None),
            ),
            (cat(&[&[0, 2, 1, 16], &v6]), (IpAddr::V6(global), None)),
            (
                cat(&[&[0, 2, 1, 32], &pair, &[0]]),
                (IpAddr::V6(global), Some(link_local)),
            ),
        ];
        for (value, expected) in cases {
            assert_eq!(
                decode_table_dump_v2_mp_reach_next_hop(&value).unwrap(),
                expected,
                "value {value:?}"
            );
        }
    }

    #[test]
    fn rejects_malformed_shapes() {
        let v4 = [192, 0, 2, 1];
        let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets();
        let rejected = [
            (vec![], "empty value"),
            // A leading 0 is an AFI high octet, so a lone 0 (or a
            // reduced-form NH-Len 0) is a truncated full-form header.
            (vec![0], "truncated full-form header"),
            (vec![0, 0, 0, 0], "AFI 0 does not carry a 0-octet"),
            (cat(&[&[5], &[1, 2, 3, 4, 5]]), "NH-Len 5 is not"),
            (vec![16, 0, 0], "truncated next hop"),
            (cat(&[&[0, 2, 1, 16], &[0, 0]]), "truncated next hop"),
            // The reduced form has no reserved octet.
            (cat(&[&[4], &v4, &[0]]), "1 trailing octets"),
            (cat(&[&[0, 1, 1, 4], &v4, &[0, 0]]), "1 trailing octets"),
            (
                cat(&[&[0, 2, 1, 4], &v4, &[0]]),
                "AFI 2 does not carry a 4-octet",
            ),
            (
                cat(&[&[0, 1, 1, 16], &v6, &[0]]),
                "AFI 1 does not carry a 16-octet",
            ),
            (
                cat(&[&[0, 2, 1, 5], &[1, 2, 3, 4, 5]]),
                "AFI 2 does not carry a 5-octet",
            ),
        ];
        for (value, needle) in rejected {
            match decode_table_dump_v2_mp_reach_next_hop(&value) {
                Err(DecodeError::MalformedField {
                    message_type,
                    detail,
                }) => {
                    assert_eq!(message_type, "RIB entry MP_REACH_NLRI");
                    assert!(detail.contains(needle), "value {value:?}: {detail}");
                }
                other => panic!("value {value:?}: expected MalformedField, got {other:?}"),
            }
        }
    }
}
