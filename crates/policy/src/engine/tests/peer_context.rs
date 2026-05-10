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
fn local_pref_and_med_comparisons_use_rfc_implicit_defaults() {
    // RFC 4271: absent LOCAL_PREF defaults to 100, absent MED to 0.
    // The policy engine matches against those implicit values so an
    // operator's `match local-preference >= 100` reads identically
    // against eBGP-received routes (no LP on the wire) and iBGP
    // routes (LP attribute present).

    // ── LOCAL_PREF: implicit 100 should match `_ge >= 100`,
    //    `_le <= 100`, and `_ge >= 50`, but not `_ge >= 200`.
    let mut high_threshold = stmt(None, PolicyAction::Deny, vec![]);
    high_threshold.match_local_pref_ge = Some(200);
    let policy_above_default = Policy {
        entries: vec![high_threshold],
        default_action: PolicyAction::Permit,
    };
    let route_ctx_no_lp = ctx(
        v4_prefix([203, 0, 113, 0], 24),
        &[],
        &[],
        &[],
        "",
        0,
        RpkiValidation::NotFound,
    );
    assert_eq!(
        policy_above_default.evaluate(&route_ctx_no_lp).action,
        PolicyAction::Permit,
        "implicit LOCAL_PREF=100 must not satisfy ge=200"
    );

    let mut local_pref_ge_100 = stmt(None, PolicyAction::Deny, vec![]);
    local_pref_ge_100.match_local_pref_ge = Some(100);
    let policy_ge_100 = Policy {
        entries: vec![local_pref_ge_100],
        default_action: PolicyAction::Permit,
    };
    assert_eq!(
        policy_ge_100.evaluate(&route_ctx_no_lp).action,
        PolicyAction::Deny,
        "implicit LOCAL_PREF=100 must satisfy ge=100"
    );

    let mut local_pref_ge_50 = stmt(None, PolicyAction::Deny, vec![]);
    local_pref_ge_50.match_local_pref_ge = Some(50);
    let policy_ge_50 = Policy {
        entries: vec![local_pref_ge_50],
        default_action: PolicyAction::Permit,
    };
    assert_eq!(
        policy_ge_50.evaluate(&route_ctx_no_lp).action,
        PolicyAction::Deny,
        "implicit LOCAL_PREF=100 must satisfy ge=50"
    );

    let mut implicit_default_threshold = stmt(None, PolicyAction::Deny, vec![]);
    implicit_default_threshold.match_local_pref_le = Some(100);
    let policy_at_default = Policy {
        entries: vec![implicit_default_threshold],
        default_action: PolicyAction::Permit,
    };
    assert_eq!(
        policy_at_default.evaluate(&route_ctx_no_lp).action,
        PolicyAction::Deny,
        "implicit LOCAL_PREF=100 must satisfy le=100"
    );

    // Explicit LOCAL_PREF overrides the implicit default.
    let mut route_ctx_lp_200 = route_ctx_no_lp;
    route_ctx_lp_200.local_pref = Some(200);
    assert_eq!(
        policy_above_default.evaluate(&route_ctx_lp_200).action,
        PolicyAction::Deny,
        "explicit LOCAL_PREF=200 must satisfy ge=200"
    );

    // ── MED: implicit 0 should match `_le <= 0` and `_ge >= 0`,
    //    but not `_ge >= 50`.
    let mut med_le_0 = stmt(None, PolicyAction::Deny, vec![]);
    med_le_0.match_med_le = Some(0);
    let p_med_le_0 = Policy {
        entries: vec![med_le_0],
        default_action: PolicyAction::Permit,
    };
    assert_eq!(
        p_med_le_0.evaluate(&route_ctx_no_lp).action,
        PolicyAction::Deny,
        "implicit MED=0 must satisfy le=0"
    );

    let mut med_floor_statement = stmt(None, PolicyAction::Deny, vec![]);
    med_floor_statement.match_med_ge = Some(0);
    let policy_med_floor = Policy {
        entries: vec![med_floor_statement],
        default_action: PolicyAction::Permit,
    };
    assert_eq!(
        policy_med_floor.evaluate(&route_ctx_no_lp).action,
        PolicyAction::Deny,
        "implicit MED=0 must satisfy ge=0"
    );

    let mut med_ge_50 = stmt(None, PolicyAction::Deny, vec![]);
    med_ge_50.match_med_ge = Some(50);
    let p_med_ge_50 = Policy {
        entries: vec![med_ge_50],
        default_action: PolicyAction::Permit,
    };
    assert_eq!(
        p_med_ge_50.evaluate(&route_ctx_no_lp).action,
        PolicyAction::Permit,
        "implicit MED=0 must not satisfy ge=50"
    );

    // Explicit MED=60 overrides the implicit default.
    let mut route_ctx_med_60 = route_ctx_no_lp;
    route_ctx_med_60.med = Some(60);
    assert_eq!(
        p_med_ge_50.evaluate(&route_ctx_med_60).action,
        PolicyAction::Deny,
        "explicit MED=60 must satisfy ge=50"
    );
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
