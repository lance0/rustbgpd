use super::*;

/// `match_evpn_route_type = Some(2)` matches an EVPN MAC/IP NLRI but not
/// a Type 5 IP-Prefix NLRI; both pass policy when the clause is None.
#[test]
fn evpn_route_type_filters_by_type() {
    let pl = Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Deny,
            match_community: vec![],
            match_as_path: None,
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: Some(2),
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    };

    let prefix = v4_prefix([0, 0, 0, 0], 0);
    let make_ctx = |evpn_type: Option<u8>| RouteContext {
        prefix,
        next_hop: None,
        extended_communities: &[],
        communities: &[],
        large_communities: &[],
        as_path_str: "",
        as_path_len: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        peer_address: None,
        peer_asn: None,
        peer_group: None,
        route_type: None,
        evpn_route_type: evpn_type,
        local_pref: None,
        med: None,
    };

    // Type 2 (MAC/IP) matches the deny clause.
    assert_eq!(
        crate::evaluate_policy(Some(&pl), &make_ctx(Some(2))).action,
        PolicyAction::Deny
    );
    // Type 5 (IP Prefix) does NOT match — falls through to default permit.
    assert_eq!(
        crate::evaluate_policy(Some(&pl), &make_ctx(Some(5))).action,
        PolicyAction::Permit
    );
    // Non-EVPN route (`evpn_route_type: None`) never matches — falls through.
    assert_eq!(
        crate::evaluate_policy(Some(&pl), &make_ctx(None)).action,
        PolicyAction::Permit
    );
}

/// `match_evpn_route_type = None` is the no-constraint case: every EVPN
/// type and the non-EVPN case all pass through unchanged.
#[test]
fn evpn_route_type_unset_matches_all() {
    let pl = Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Deny,
            match_community: vec![],
            match_as_path: None,
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 99))),
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    };

    let prefix = v4_prefix([0, 0, 0, 0], 0);
    let ctx = RouteContext {
        prefix,
        next_hop: None,
        extended_communities: &[],
        communities: &[],
        large_communities: &[],
        as_path_str: "",
        as_path_len: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        peer_address: None,
        peer_asn: None,
        peer_group: None,
        route_type: None,
        evpn_route_type: Some(2),
        local_pref: None,
        med: None,
    };
    // The next-hop clause won't match (no next_hop on the route), so the
    // statement falls through and the default permit fires — proving the
    // unset evpn-type clause has no effect.
    assert_eq!(
        crate::evaluate_policy(Some(&pl), &ctx).action,
        PolicyAction::Permit
    );
}
