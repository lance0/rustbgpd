//! Decode a GoBGP v3 `AddPath` request into one rustbgpd injection call.
//!
//! The accepted subset is deliberately narrow. Anything outside it is
//! rejected with a gRPC error rather than dropped, so a detector never
//! believes an attribute was announced when it was not.

use std::net::IpAddr;

use rustbgpd_wire::attribute::decode_path_attributes;
use rustbgpd_wire::nlri::{decode_ipv6_nlri, decode_nlri};
use rustbgpd_wire::{Afi, AsPathSegment, PathAttribute, Prefix, Safi};
use sha2::{Digest, Sha256};
use tonic::Status;

use crate::gobgp;
use crate::rustbgpd as rbgp;

/// The rustbgpd call a GoBGP request maps to.
#[derive(Debug, PartialEq)]
pub enum Mutation {
    /// An announcement (`is_withdraw = false`).
    Announce(rbgp::AddPathRequest),
    /// A withdrawal (`is_withdraw = true`).
    Withdraw(rbgp::DeletePathRequest),
}

/// A decoded request and the identifier returned to the client.
#[derive(Debug, PartialEq)]
pub struct Decoded {
    /// The injection call to make.
    pub mutation: Mutation,
    /// Deterministic UUID for (family, prefix, path id).
    pub uuid: [u8; 16],
}

// Path attribute type codes in the accepted subset (RFC 4271, RFC 1997, RFC 4760).
const ORIGIN: u8 = 1;
const AS_PATH: u8 = 2;
const NEXT_HOP: u8 = 3;
const MED: u8 = 4;
const LOCAL_PREF: u8 = 5;
const COMMUNITIES: u8 = 8;
const MP_REACH_NLRI: u8 = 14;

fn invalid(message: impl Into<String>) -> Status {
    Status::invalid_argument(message.into())
}

fn unsupported(message: impl Into<String>) -> Status {
    Status::unimplemented(format!(
        "{}; the bridge accepts only binary IPv4/IPv6 unicast paths in the global table",
        message.into()
    ))
}

/// Decode one GoBGP v3 `AddPath` request.
///
/// # Errors
///
/// `UNIMPLEMENTED` for a valid GoBGP request outside the supported subset,
/// `INVALID_ARGUMENT` for malformed bytes or an incomplete announcement, and
/// `FAILED_PRECONDITION` for an unspecified next hop.
pub fn decode(request: &gobgp::AddPathRequest) -> Result<Decoded, Status> {
    if request.table_type != gobgp::TableType::Global as i32 {
        return Err(unsupported(format!(
            "table_type {} is not supported",
            request.table_type
        )));
    }
    if !request.vrf_id.is_empty() {
        return Err(unsupported("vrf_id is not supported"));
    }
    let path = request
        .path
        .as_ref()
        .ok_or_else(|| invalid("AddPath request has no path"))?;
    if path.nlri.is_some() || !path.pattrs.is_empty() {
        return Err(unsupported(
            "structured nlri/pattrs are not supported; send nlri_binary and pattrs_binary",
        ));
    }
    // GoBGP keys paths by these fields as well. The injection API has a single
    // local source per (prefix, path id), so honouring a request that sets
    // them would let one source replace or remove another's route.
    if path.no_implicit_withdraw
        || path.source_asn != 0
        || !path.source_id.is_empty()
        || path.is_from_external
    {
        return Err(unsupported(
            "no_implicit_withdraw, source_asn, source_id and is_from_external are not supported",
        ));
    }
    let family = path
        .family
        .as_ref()
        .ok_or_else(|| invalid("path has no family"))?;
    if family.safi != gobgp::family::Safi::Unicast as i32 {
        return Err(unsupported(format!(
            "SAFI {} is not supported",
            family.safi
        )));
    }
    let afi = match family.afi {
        a if a == gobgp::family::Afi::Ip as i32 => Afi::Ipv4,
        a if a == gobgp::family::Afi::Ip6 as i32 => Afi::Ipv6,
        other => return Err(unsupported(format!("AFI {other} is not supported"))),
    };
    let prefix = decode_prefix(afi, &path.nlri_binary)?;
    let path_id = path.identifier;
    let attrs = decode_attributes(afi, prefix, &path.pattrs_binary)?;
    let uuid = path_uuid(prefix, path_id);
    let (addr, len) = match prefix {
        Prefix::V4(p) => (p.addr.to_string(), p.len),
        Prefix::V6(p) => (p.addr.to_string(), p.len),
    };

    if path.is_withdraw {
        // GoBGP ignores attributes on a withdrawal; they were still checked
        // above so a malformed request fails the same way in both directions.
        return Ok(Decoded {
            mutation: Mutation::Withdraw(rbgp::DeletePathRequest {
                prefix: addr,
                prefix_length: u32::from(len),
                path_id,
            }),
            uuid,
        });
    }

    let next_hop = attrs.next_hop.ok_or_else(|| {
        invalid("announcement has no next hop: send NEXT_HOP (IPv4) or MP_REACH_NLRI (IPv6)")
    })?;
    // LAN-2396: rustbgpd rejects an unspecified next hop until it gains
    // next-hop-self for injected routes; then pass 0.0.0.0 and :: through.
    if next_hop.is_unspecified() {
        return Err(Status::failed_precondition(format!(
            "next hop {next_hop} (next-hop-self) is not supported by rustbgpd yet; \
             configure an explicit next hop in the detector"
        )));
    }
    Ok(Decoded {
        mutation: Mutation::Announce(rbgp::AddPathRequest {
            prefix: addr,
            prefix_length: u32::from(len),
            next_hop: next_hop.to_string(),
            as_path: attrs.as_path,
            origin: attrs.origin,
            local_pref: attrs.local_pref,
            med: attrs.med,
            communities: attrs.communities,
            path_id,
            ..Default::default()
        }),
        uuid,
    })
}

fn decode_prefix(afi: Afi, nlri: &[u8]) -> Result<Prefix, Status> {
    if nlri.is_empty() {
        return Err(invalid("nlri_binary is empty"));
    }
    let malformed = |e: rustbgpd_wire::DecodeError| invalid(format!("malformed nlri_binary: {e}"));
    let prefixes: Vec<Prefix> = match afi {
        Afi::Ipv4 => decode_nlri(nlri)
            .map_err(malformed)?
            .into_iter()
            .map(Prefix::V4)
            .collect(),
        _ => decode_ipv6_nlri(nlri)
            .map_err(malformed)?
            .into_iter()
            .map(Prefix::V6)
            .collect(),
    };
    match prefixes.as_slice() {
        [prefix] => Ok(*prefix),
        _ => Err(invalid(format!(
            "nlri_binary must carry exactly one prefix, found {}",
            prefixes.len()
        ))),
    }
}

/// Attribute values carried into the injection request.
#[derive(Default)]
struct Attributes {
    origin: u32,
    as_path: Vec<u32>,
    next_hop: Option<IpAddr>,
    med: Option<u32>,
    local_pref: Option<u32>,
    communities: Vec<u32>,
}

fn decode_attributes(afi: Afi, prefix: Prefix, raw: &[Vec<u8>]) -> Result<Attributes, Status> {
    let mut out = Attributes::default();
    let mut seen = [false; 256];
    for bytes in raw {
        let type_code = *bytes
            .get(1)
            .ok_or_else(|| invalid("path attribute shorter than its header"))?;
        // Check the type before decoding: the wire decoder skips unknown
        // optional non-transitive attributes, which here would be a silent drop.
        let allowed = match type_code {
            ORIGIN | AS_PATH | MED | LOCAL_PREF | COMMUNITIES => true,
            NEXT_HOP => afi == Afi::Ipv4,
            MP_REACH_NLRI => afi == Afi::Ipv6,
            _ => false,
        };
        if !allowed {
            return Err(unsupported(format!(
                "path attribute type {type_code} is not supported for {afi:?} unicast"
            )));
        }
        if std::mem::replace(&mut seen[usize::from(type_code)], true) {
            return Err(invalid(format!(
                "duplicate path attribute type {type_code}"
            )));
        }
        // The entry must be one attribute, its header and value, and nothing
        // after it: the wire decoder would skip a trailing unknown optional
        // non-transitive attribute without an error.
        let framed = match bytes[0] {
            flags if flags & 0x10 != 0 => bytes
                .get(2..4)
                .map(|len| 4 + usize::from(u16::from_be_bytes([len[0], len[1]]))),
            _ => bytes.get(2).map(|len| 3 + usize::from(*len)),
        };
        if framed != Some(bytes.len()) {
            return Err(invalid(format!(
                "each pattrs_binary entry must hold exactly one attribute; \
                 the type {type_code} entry is {} bytes",
                bytes.len()
            )));
        }
        // GoBGP's binary path attributes use four-octet AS numbers.
        let decoded = decode_path_attributes(bytes, true, &[])
            .map_err(|e| invalid(format!("malformed path attribute type {type_code}: {e}")))?;
        let [attr] = decoded.as_slice() else {
            return Err(invalid(format!(
                "each pattrs_binary entry must hold one attribute; type {type_code} entry held {}",
                decoded.len()
            )));
        };
        match attr {
            PathAttribute::Origin(origin) => out.origin = *origin as u32,
            PathAttribute::AsPath(path) => {
                for segment in &path.segments {
                    let AsPathSegment::AsSequence(asns) = segment else {
                        return Err(unsupported("AS_PATH may hold only AS_SEQUENCE segments"));
                    };
                    // RFC 4271 malformed AS_PATH, as the wire crate's UPDATE
                    // validation treats it; the attribute decoder accepts it.
                    // An AS_PATH with no segments stays valid.
                    if asns.is_empty() {
                        return Err(invalid("AS_PATH has an empty AS_SEQUENCE segment"));
                    }
                    out.as_path.extend_from_slice(asns);
                }
            }
            PathAttribute::NextHop(nh) => out.next_hop = Some(IpAddr::V4(*nh)),
            PathAttribute::Med(med) => out.med = Some(*med),
            PathAttribute::LocalPref(pref) => out.local_pref = Some(*pref),
            PathAttribute::Communities(values) => out.communities.clone_from(values),
            PathAttribute::MpReachNlri(mp) => {
                if mp.afi != Afi::Ipv6 || mp.safi != Safi::Unicast {
                    return Err(unsupported(format!(
                        "MP_REACH_NLRI for {:?}/{:?} is not supported",
                        mp.afi, mp.safi
                    )));
                }
                if mp.link_local_next_hop.is_some() || !mp.next_hop.is_ipv6() {
                    return Err(unsupported(
                        "MP_REACH_NLRI must carry one 16-octet IPv6 next hop",
                    ));
                }
                // GoBGP takes the prefix from nlri_binary and only the next
                // hop from MP_REACH_NLRI; reject a body that disagrees.
                if mp.announced.iter().any(|entry| entry.prefix != prefix) {
                    return Err(invalid(
                        "MP_REACH_NLRI announces a prefix other than nlri_binary",
                    ));
                }
                out.next_hop = Some(mp.next_hop);
            }
            other => {
                return Err(unsupported(format!(
                    "path attribute {other:?} is not supported"
                )));
            }
        }
    }
    Ok(out)
}

/// A deterministic RFC 9562 version 8 UUID for (family, prefix, path id), so
/// repeating an add returns the same identifier.
#[must_use]
pub fn path_uuid(prefix: Prefix, path_id: u32) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"rustbgpd-gobgp-bridge/path/v1");
    match prefix {
        Prefix::V4(p) => {
            hash.update([1]);
            hash.update(p.addr.octets());
            hash.update([p.len]);
        }
        Prefix::V6(p) => {
            hash.update([2]);
            hash.update(p.addr.octets());
            hash.update([p.len]);
        }
    }
    hash.update(path_id.to_be_bytes());
    let digest = hash.finalize();
    let mut uuid = [0; 16];
    uuid.copy_from_slice(&digest[..16]);
    uuid[6] = (uuid[6] & 0x0f) | 0x80;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    uuid
}

#[cfg(test)]
mod tests {
    use super::*;

    // Byte layouts below match what RTBH detectors that drive GoBGP send:
    // one attribute per pattrs_binary entry, four-octet AS_PATH, and for
    // IPv6 the prefix in nlri_binary with the next hop in MP_REACH_NLRI.
    const ORIGIN_IGP: &[u8] = &[0x40, 1, 1, 0];
    const NEXT_HOP_V4: &[u8] = &[0x40, 3, 4, 192, 0, 2, 1];
    const COMMUNITY_65535_666: &[u8] = &[0xc0, 8, 4, 0xff, 0xff, 0x02, 0x9a];
    const AS_PATH_65001: &[u8] = &[0x40, 2, 6, 2, 1, 0, 0, 0xfd, 0xe9];
    const MED_10: &[u8] = &[0x80, 4, 4, 0, 0, 0, 10];
    const LOCAL_PREF_200: &[u8] = &[0x40, 5, 4, 0, 0, 0, 200];
    const NLRI_V4_HOST: &[u8] = &[32, 203, 0, 113, 7];
    const NLRI_V6_HOST: &[u8] = &[
        128, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x07,
    ];

    fn mp_reach_v6(next_hop: [u8; 16], nlri: &[u8]) -> Vec<u8> {
        let mut body = vec![0, 2, 1, 16];
        body.extend_from_slice(&next_hop);
        body.push(0);
        body.extend_from_slice(nlri);
        let mut attr = vec![0x80, 14, u8::try_from(body.len()).unwrap()];
        attr.extend_from_slice(&body);
        attr
    }

    fn v6_next_hop() -> [u8; 16] {
        "2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets()
    }

    fn request(afi: i32, nlri: &[u8], attrs: &[&[u8]], withdraw: bool) -> gobgp::AddPathRequest {
        gobgp::AddPathRequest {
            table_type: gobgp::TableType::Global as i32,
            vrf_id: String::new(),
            path: Some(gobgp::Path {
                family: Some(gobgp::Family {
                    afi,
                    safi: gobgp::family::Safi::Unicast as i32,
                }),
                nlri_binary: nlri.to_vec(),
                pattrs_binary: attrs.iter().map(|a| a.to_vec()).collect(),
                is_withdraw: withdraw,
                ..Default::default()
            }),
        }
    }

    const IP: i32 = gobgp::family::Afi::Ip as i32;
    const IP6: i32 = gobgp::family::Afi::Ip6 as i32;

    fn announce(decoded: Decoded) -> rbgp::AddPathRequest {
        match decoded.mutation {
            Mutation::Announce(req) => req,
            Mutation::Withdraw(req) => panic!("expected announce, got {req:?}"),
        }
    }

    fn code(request: &gobgp::AddPathRequest) -> tonic::Code {
        decode(request).unwrap_err().code()
    }

    #[test]
    fn ipv4_origin_next_hop_community() {
        let req = announce(
            decode(&request(
                IP,
                NLRI_V4_HOST,
                &[ORIGIN_IGP, NEXT_HOP_V4, COMMUNITY_65535_666],
                false,
            ))
            .unwrap(),
        );
        assert_eq!(req.prefix, "203.0.113.7");
        assert_eq!(req.prefix_length, 32);
        assert_eq!(req.next_hop, "192.0.2.1");
        assert_eq!(req.origin, 0);
        assert_eq!(req.communities, vec![0xffff_029a]);
        assert_eq!(req.as_path, Vec::<u32>::new());
    }

    #[test]
    fn ipv4_origin_values() {
        for (value, expected) in [(0u8, 0u32), (1, 1), (2, 2)] {
            let origin = [0x40, 1, 1, value];
            let req = announce(
                decode(&request(IP, NLRI_V4_HOST, &[&origin, NEXT_HOP_V4], false)).unwrap(),
            );
            assert_eq!(req.origin, expected);
        }
    }

    #[test]
    fn optional_as_path_med_local_pref() {
        let req = announce(
            decode(&request(
                IP,
                NLRI_V4_HOST,
                &[
                    ORIGIN_IGP,
                    AS_PATH_65001,
                    NEXT_HOP_V4,
                    MED_10,
                    LOCAL_PREF_200,
                ],
                false,
            ))
            .unwrap(),
        );
        assert_eq!(req.as_path, vec![65001]);
        assert_eq!(req.med, Some(10));
        assert_eq!(req.local_pref, Some(200));
    }

    #[test]
    fn ipv4_subnet_prefix() {
        let req =
            announce(decode(&request(IP, &[24, 198, 51, 100], &[NEXT_HOP_V4], false)).unwrap());
        assert_eq!(
            (req.prefix.as_str(), req.prefix_length),
            ("198.51.100.0", 24)
        );
    }

    #[test]
    fn ipv6_gobgp_mp_reach_shape() {
        let mp = mp_reach_v6(v6_next_hop(), NLRI_V6_HOST);
        let req = announce(
            decode(&request(
                IP6,
                NLRI_V6_HOST,
                &[&mp, ORIGIN_IGP, COMMUNITY_65535_666],
                false,
            ))
            .unwrap(),
        );
        assert_eq!(req.prefix, "2001:db8::7");
        assert_eq!(req.prefix_length, 128);
        assert_eq!(req.next_hop, "2001:db8::1");
        assert_eq!(req.communities, vec![0xffff_029a]);
    }

    #[test]
    fn ipv6_mp_reach_must_match_nlri_binary() {
        let other = [64, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1];
        let mp = mp_reach_v6(v6_next_hop(), &other);
        assert_eq!(
            code(&request(IP6, NLRI_V6_HOST, &[&mp], false)),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn withdraw_maps_to_delete_path() {
        let decoded = decode(&request(
            IP,
            NLRI_V4_HOST,
            &[ORIGIN_IGP, NEXT_HOP_V4, COMMUNITY_65535_666],
            true,
        ))
        .unwrap();
        assert_eq!(
            decoded.mutation,
            Mutation::Withdraw(rbgp::DeletePathRequest {
                prefix: "203.0.113.7".into(),
                prefix_length: 32,
                path_id: 0,
            })
        );
        let mp = mp_reach_v6([0; 16], NLRI_V6_HOST);
        let decoded = decode(&request(IP6, NLRI_V6_HOST, &[&mp, ORIGIN_IGP], true)).unwrap();
        assert!(
            matches!(decoded.mutation, Mutation::Withdraw(ref d) if d.prefix == "2001:db8::7" && d.prefix_length == 128),
            "a withdrawal needs no usable next hop"
        );
    }

    #[test]
    fn uuid_is_deterministic_per_path() {
        let add = decode(&request(IP, NLRI_V4_HOST, &[NEXT_HOP_V4], false)).unwrap();
        let again = decode(&request(IP, NLRI_V4_HOST, &[NEXT_HOP_V4, MED_10], false)).unwrap();
        let withdraw = decode(&request(IP, NLRI_V4_HOST, &[], true)).unwrap();
        assert_eq!(add.uuid, again.uuid);
        assert_eq!(add.uuid, withdraw.uuid);
        let other = decode(&request(IP, &[24, 203, 0, 113], &[NEXT_HOP_V4], false)).unwrap();
        assert_ne!(add.uuid, other.uuid);
        assert_eq!(add.uuid[6] >> 4, 8, "version 8");
        assert_eq!(add.uuid[8] >> 6, 0b10, "RFC 9562 variant");
    }

    #[test]
    fn unspecified_next_hop_is_refused() {
        let zero = [0x40, 3, 4, 0, 0, 0, 0];
        assert_eq!(
            code(&request(IP, NLRI_V4_HOST, &[&zero], false)),
            tonic::Code::FailedPrecondition
        );
        let mp = mp_reach_v6([0; 16], NLRI_V6_HOST);
        assert_eq!(
            code(&request(IP6, NLRI_V6_HOST, &[&mp], false)),
            tonic::Code::FailedPrecondition
        );
    }

    #[test]
    fn rejects_unsupported_family() {
        let mut req = request(IP, NLRI_V4_HOST, &[NEXT_HOP_V4], false);
        req.path.as_mut().unwrap().family.as_mut().unwrap().safi =
            gobgp::family::Safi::FlowSpecUnicast as i32;
        assert_eq!(code(&req), tonic::Code::Unimplemented);
        let mut req = request(IP, NLRI_V4_HOST, &[NEXT_HOP_V4], false);
        req.path.as_mut().unwrap().family.as_mut().unwrap().afi = gobgp::family::Afi::L2vpn as i32;
        assert_eq!(code(&req), tonic::Code::Unimplemented);
        let mut req = request(IP, NLRI_V4_HOST, &[NEXT_HOP_V4], false);
        req.path.as_mut().unwrap().family = None;
        assert_eq!(code(&req), tonic::Code::InvalidArgument);
    }

    #[test]
    fn rejects_non_global_table_and_vrf() {
        let mut req = request(IP, NLRI_V4_HOST, &[NEXT_HOP_V4], false);
        req.table_type = gobgp::TableType::Vrf as i32;
        assert_eq!(code(&req), tonic::Code::Unimplemented);
        let mut req = request(IP, NLRI_V4_HOST, &[NEXT_HOP_V4], false);
        req.vrf_id = "blue".into();
        assert_eq!(code(&req), tonic::Code::Unimplemented);
    }

    #[test]
    fn rejects_unknown_and_out_of_family_attributes() {
        // Extended communities (16), an unknown optional non-transitive
        // attribute (which the wire decoder would otherwise skip), NEXT_HOP on
        // IPv6 and MP_REACH_NLRI on IPv4.
        let ext = [0xc0, 16, 8, 0, 2, 0xfd, 0xe9, 0, 0, 0, 1];
        let unknown = [0x80, 200, 1, 0];
        let mp = mp_reach_v6(v6_next_hop(), NLRI_V6_HOST);
        for (afi, nlri, attr) in [
            (IP, NLRI_V4_HOST, &ext[..]),
            (IP, NLRI_V4_HOST, &unknown[..]),
            (IP, NLRI_V4_HOST, &mp[..]),
            (IP6, NLRI_V6_HOST, NEXT_HOP_V4),
        ] {
            assert_eq!(
                code(&request(afi, nlri, &[NEXT_HOP_V4, attr], false)),
                tonic::Code::Unimplemented,
                "{attr:?}"
            );
        }
        let as_set = [0x40, 2, 6, 1, 1, 0, 0, 0xfd, 0xe9];
        assert_eq!(
            code(&request(IP, NLRI_V4_HOST, &[NEXT_HOP_V4, &as_set], false)),
            tonic::Code::Unimplemented
        );
    }

    #[test]
    fn rejects_source_identity_fields() {
        let cases: [fn(&mut gobgp::Path); 4] = [
            |p| p.no_implicit_withdraw = true,
            |p| p.source_asn = 65001,
            |p| p.source_id = "192.0.2.9".into(),
            |p| p.is_from_external = true,
        ];
        for (index, set) in cases.into_iter().enumerate() {
            let mut req = request(IP, NLRI_V4_HOST, &[NEXT_HOP_V4], false);
            set(req.path.as_mut().unwrap());
            assert_eq!(code(&req), tonic::Code::Unimplemented, "case {index}");
        }
    }

    #[test]
    fn rejects_structured_any_form() {
        let mut req = request(IP, NLRI_V4_HOST, &[NEXT_HOP_V4], false);
        req.path.as_mut().unwrap().nlri = Some(prost_types::Any::default());
        assert_eq!(code(&req), tonic::Code::Unimplemented);
    }

    #[test]
    fn empty_as_path_segment_is_malformed() {
        let empty_segment = [0x40, 2, 2, 2, 0];
        for withdraw in [false, true] {
            assert_eq!(
                code(&request(
                    IP,
                    NLRI_V4_HOST,
                    &[NEXT_HOP_V4, &empty_segment],
                    withdraw
                )),
                tonic::Code::InvalidArgument,
                "withdraw={withdraw}"
            );
        }
        // An AS_PATH with no segments at all is valid and means an empty path.
        let empty_path = [0x40, 2, 0];
        let req = announce(
            decode(&request(
                IP,
                NLRI_V4_HOST,
                &[NEXT_HOP_V4, &empty_path],
                false,
            ))
            .unwrap(),
        );
        assert_eq!(req.as_path, Vec::<u32>::new());
    }

    #[test]
    fn extended_length_attribute() {
        let community = [0xd0, 8, 0, 4, 0xff, 0xff, 0x02, 0x9a];
        let req = announce(
            decode(&request(
                IP,
                NLRI_V4_HOST,
                &[NEXT_HOP_V4, &community],
                false,
            ))
            .unwrap(),
        );
        assert_eq!(req.communities, vec![0xffff_029a]);
    }

    #[test]
    fn rejects_trailing_attribute_in_one_entry() {
        // NEXT_HOP followed by an unknown optional non-transitive type 200,
        // which the wire decoder alone would drop silently.
        let hidden = [0x40, 3, 4, 192, 0, 2, 1, 0x80, 200, 1, 0];
        assert_eq!(
            code(&request(IP, NLRI_V4_HOST, &[&hidden], false)),
            tonic::Code::InvalidArgument
        );
        let hidden_ext = [0x50, 3, 0, 4, 192, 0, 2, 1, 0x80, 200, 1, 0];
        assert_eq!(
            code(&request(IP, NLRI_V4_HOST, &[&hidden_ext], false)),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn rejects_malformed_bytes() {
        let truncated_attr = [0x40, 3, 4, 192, 0];
        let two_in_one = [0x40, 1, 1, 0, 0x40, 3, 4, 192, 0, 2, 1];
        let bad_origin = [0x40, 1, 1, 7];
        for attrs in [
            &[&truncated_attr[..]][..],
            &[&two_in_one[..]],
            &[&bad_origin[..], NEXT_HOP_V4],
            &[&[0x40][..]],
            &[NEXT_HOP_V4, NEXT_HOP_V4],
        ] {
            assert_eq!(
                code(&request(IP, NLRI_V4_HOST, attrs, false)),
                tonic::Code::InvalidArgument,
                "{attrs:?}"
            );
        }
        for nlri in [
            &[][..],
            &[33, 1, 2, 3, 4],
            &[32, 203, 0],
            &[24, 1, 2, 3, 24, 4, 5, 6],
        ] {
            assert_eq!(
                code(&request(IP, nlri, &[NEXT_HOP_V4], false)),
                tonic::Code::InvalidArgument,
                "{nlri:?}"
            );
        }
        assert_eq!(
            code(&request(IP, NLRI_V4_HOST, &[ORIGIN_IGP], false)),
            tonic::Code::InvalidArgument,
            "an announcement without a next hop"
        );
    }
}
