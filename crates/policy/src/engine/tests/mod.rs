use std::net::Ipv4Addr;

use rustbgpd_wire::Ipv4Prefix;

use super::*;

mod as_path_length;
mod aspath_regex;
mod chain;
mod community;
mod large_community;
mod modifications;
mod peer_context;
mod prefix;
mod rpki;

fn v4_prefix(addr: [u8; 4], len: u8) -> Prefix {
    Prefix::V4(Ipv4Prefix::new(
        Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]),
        len,
    ))
}

fn v4_entry(addr: [u8; 4], len: u8) -> Prefix {
    v4_prefix(addr, len)
}

fn ctx<'a>(
    prefix: Prefix,
    extended_communities: &'a [ExtendedCommunity],
    communities: &'a [u32],
    large_communities: &'a [LargeCommunity],
    as_path_str: &'a str,
    as_path_len: usize,
    validation_state: RpkiValidation,
) -> RouteContext<'a> {
    RouteContext {
        prefix,
        extended_communities,
        communities,
        large_communities,
        as_path_str,
        as_path_len,
        validation_state,
        peer_address: None,
        peer_asn: None,
        peer_group: None,
        route_type: None,
        local_pref: None,
        med: None,
    }
}

#[expect(clippy::too_many_arguments)]
fn evaluate_policy(
    policy: Option<&Policy>,
    prefix: Prefix,
    extended_communities: &[ExtendedCommunity],
    communities: &[u32],
    large_communities: &[LargeCommunity],
    as_path_str: &str,
    as_path_len: usize,
    validation_state: RpkiValidation,
) -> PolicyResult {
    super::evaluate_policy(
        policy,
        &ctx(
            prefix,
            extended_communities,
            communities,
            large_communities,
            as_path_str,
            as_path_len,
            validation_state,
        ),
    )
}

#[expect(clippy::too_many_arguments)]
fn evaluate_chain(
    chain: Option<&PolicyChain>,
    prefix: Prefix,
    extended_communities: &[ExtendedCommunity],
    communities: &[u32],
    large_communities: &[LargeCommunity],
    as_path_str: &str,
    as_path_len: usize,
    validation_state: RpkiValidation,
) -> PolicyResult {
    super::evaluate_chain(
        chain,
        &ctx(
            prefix,
            extended_communities,
            communities,
            large_communities,
            as_path_str,
            as_path_len,
            validation_state,
        ),
    )
}

fn stmt(
    prefix: Option<Prefix>,
    action: PolicyAction,
    community: Vec<CommunityMatch>,
) -> PolicyStatement {
    PolicyStatement {
        prefix,
        ge: None,
        le: None,
        action,
        match_community: community,
        match_as_path: None,
        match_neighbor_set: None,
        match_route_type: None,
        match_rpki_validation: None,
        match_as_path_length_ge: None,
        match_as_path_length_le: None,
        match_local_pref_ge: None,
        match_local_pref_le: None,
        match_med_ge: None,
        match_med_le: None,
        modifications: RouteModifications::default(),
    }
}

fn make_rt(asn: u16, value: u32) -> ExtendedCommunity {
    let mut b = [0u8; 8];
    b[0] = 0x00;
    b[1] = 0x02;
    b[2..4].copy_from_slice(&asn.to_be_bytes());
    b[4..8].copy_from_slice(&value.to_be_bytes());
    ExtendedCommunity::new(u64::from_be_bytes(b))
}

fn make_ro(asn: u16, value: u32) -> ExtendedCommunity {
    let mut b = [0u8; 8];
    b[0] = 0x00;
    b[1] = 0x03;
    b[2..4].copy_from_slice(&asn.to_be_bytes());
    b[4..8].copy_from_slice(&value.to_be_bytes());
    ExtendedCommunity::new(u64::from_be_bytes(b))
}

fn make_rt_as4(asn: u32, value: u16) -> ExtendedCommunity {
    let mut b = [0u8; 8];
    b[0] = 0x02;
    b[1] = 0x02;
    b[2..6].copy_from_slice(&asn.to_be_bytes());
    b[6..8].copy_from_slice(&value.to_be_bytes());
    ExtendedCommunity::new(u64::from_be_bytes(b))
}
