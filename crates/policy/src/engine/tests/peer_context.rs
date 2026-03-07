use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;

#[test]
fn neighbor_set_matches_peer_address() {
    let mut statement = stmt(None, PolicyAction::Deny, vec![]);
    statement.match_neighbor_set = Some(NeighborSetMatch {
        addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
        remote_asns: vec![],
        peer_groups: vec![],
    });
    let policy = Policy {
        entries: vec![statement],
        default_action: PolicyAction::Permit,
    };

    let mut route_ctx = ctx(
        v4_prefix([192, 0, 2, 0], 24),
        &[],
        &[],
        &[],
        "",
        0,
        RpkiValidation::NotFound,
    );
    route_ctx.peer_address = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    assert_eq!(policy.evaluate(&route_ctx).action, PolicyAction::Deny);

    route_ctx.peer_address = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)));
    assert_eq!(policy.evaluate(&route_ctx).action, PolicyAction::Permit);
}

#[test]
fn neighbor_set_matches_peer_group_or_asn() {
    let mut statement = stmt(None, PolicyAction::Deny, vec![]);
    statement.match_neighbor_set = Some(NeighborSetMatch {
        addresses: vec![],
        remote_asns: vec![65020],
        peer_groups: vec!["ix-rs".to_string()],
    });
    let policy = Policy {
        entries: vec![statement],
        default_action: PolicyAction::Permit,
    };

    let mut route_ctx = ctx(
        v4_prefix([198, 51, 100, 0], 24),
        &[],
        &[],
        &[],
        "",
        0,
        RpkiValidation::NotFound,
    );
    route_ctx.peer_group = Some("ix-rs");
    assert_eq!(policy.evaluate(&route_ctx).action, PolicyAction::Deny);

    route_ctx.peer_group = None;
    route_ctx.peer_asn = Some(65020);
    assert_eq!(policy.evaluate(&route_ctx).action, PolicyAction::Deny);

    route_ctx.peer_asn = Some(65030);
    assert_eq!(policy.evaluate(&route_ctx).action, PolicyAction::Permit);
}

#[test]
fn route_type_match_distinguishes_local_internal_external() {
    let mut statement = stmt(None, PolicyAction::Deny, vec![]);
    statement.match_route_type = Some(RouteType::External);
    let policy = Policy {
        entries: vec![statement],
        default_action: PolicyAction::Permit,
    };

    let mut route_ctx = ctx(
        v4_prefix([203, 0, 113, 0], 24),
        &[],
        &[],
        &[],
        "",
        0,
        RpkiValidation::NotFound,
    );
    route_ctx.route_type = Some(RouteType::External);
    assert_eq!(policy.evaluate(&route_ctx).action, PolicyAction::Deny);

    route_ctx.route_type = Some(RouteType::Internal);
    assert_eq!(policy.evaluate(&route_ctx).action, PolicyAction::Permit);

    route_ctx.route_type = Some(RouteType::Local);
    assert_eq!(policy.evaluate(&route_ctx).action, PolicyAction::Permit);
}

#[test]
fn local_pref_and_med_comparisons_require_present_attributes() {
    let mut statement = stmt(None, PolicyAction::Deny, vec![]);
    statement.match_local_pref_ge = Some(200);
    statement.match_med_le = Some(50);
    let policy = Policy {
        entries: vec![statement],
        default_action: PolicyAction::Permit,
    };

    let mut route_ctx = ctx(
        v4_prefix([203, 0, 113, 0], 24),
        &[],
        &[],
        &[],
        "",
        0,
        RpkiValidation::NotFound,
    );

    assert_eq!(policy.evaluate(&route_ctx).action, PolicyAction::Permit);

    route_ctx.local_pref = Some(200);
    assert_eq!(policy.evaluate(&route_ctx).action, PolicyAction::Permit);

    route_ctx.med = Some(50);
    assert_eq!(policy.evaluate(&route_ctx).action, PolicyAction::Deny);

    route_ctx.med = Some(60);
    assert_eq!(policy.evaluate(&route_ctx).action, PolicyAction::Permit);
}

#[test]
fn next_hop_match_requires_exact_address() {
    let mut statement = stmt(None, PolicyAction::Deny, vec![]);
    statement.match_next_hop = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let policy = Policy {
        entries: vec![statement],
        default_action: PolicyAction::Permit,
    };

    let mut route_ctx = ctx(
        v4_prefix([203, 0, 113, 0], 24),
        &[],
        &[],
        &[],
        "",
        0,
        RpkiValidation::NotFound,
    );
    assert_eq!(policy.evaluate(&route_ctx).action, PolicyAction::Permit);

    route_ctx.next_hop = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(policy.evaluate(&route_ctx).action, PolicyAction::Deny);

    route_ctx.next_hop = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(policy.evaluate(&route_ctx).action, PolicyAction::Permit);
}
