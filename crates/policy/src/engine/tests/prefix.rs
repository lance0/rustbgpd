use super::*;

// -----------------------------------------------------------------------
// PolicyResult helpers
// -----------------------------------------------------------------------

#[test]
fn policy_result_permit_helper() {
    let r = PolicyResult::permit();
    assert_eq!(r.action, PolicyAction::Permit);
    assert!(r.modifications.set_local_pref.is_none());
}

#[test]
fn policy_result_deny_helper() {
    let r = PolicyResult::deny();
    assert_eq!(r.action, PolicyAction::Deny);
}

#[test]
fn evaluate_policy_none_returns_permit() {
    let r = evaluate_policy(
        None,
        v4_prefix([10, 0, 0, 0], 8),
        &[],
        &[],
        &[],
        "",
        0,
        RpkiValidation::NotFound,
    );
    assert_eq!(r.action, PolicyAction::Permit);
}

// -----------------------------------------------------------------------
// Prefix matching (renamed types)
// -----------------------------------------------------------------------

#[test]
fn exact_match_permit() {
    let pl = Policy {
        entries: vec![stmt(
            Some(v4_entry([10, 0, 0, 0], 8)),
            PolicyAction::Permit,
            vec![],
        )],
        default_action: PolicyAction::Deny,
    };
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "",
            0,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Permit
    );
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 1, 0, 0], 24),
            &[],
            &[],
            &[],
            "",
            0,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Deny
    );
}

#[test]
fn ge_le_range() {
    let pl = Policy {
        entries: vec![PolicyStatement {
            prefix: Some(v4_entry([10, 0, 0, 0], 8)),
            ge: Some(16),
            le: Some(24),
            action: PolicyAction::Permit,
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
            match_next_hop: None,
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Deny,
    };
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "",
            0,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Deny
    );
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 1, 0, 0], 16),
            &[],
            &[],
            &[],
            "",
            0,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Permit
    );
}

#[test]
fn default_action_used_when_no_match() {
    let pl = Policy {
        entries: vec![stmt(
            Some(v4_entry([10, 0, 0, 0], 8)),
            PolicyAction::Deny,
            vec![],
        )],
        default_action: PolicyAction::Permit,
    };
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([192, 168, 0, 0], 16),
            &[],
            &[],
            &[],
            "",
            0,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Permit
    );
}

#[test]
fn first_match_wins() {
    let pl = Policy {
        entries: vec![
            stmt(Some(v4_entry([10, 0, 0, 0], 8)), PolicyAction::Deny, vec![]),
            stmt(
                Some(v4_entry([10, 0, 0, 0], 8)),
                PolicyAction::Permit,
                vec![],
            ),
        ],
        default_action: PolicyAction::Permit,
    };
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "",
            0,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Deny
    );
}
#[test]
fn v6_exact_match() {
    use rustbgpd_wire::Ipv6Prefix;

    let pl = Policy {
        entries: vec![PolicyStatement {
            prefix: Some(Prefix::V6(Ipv6Prefix::new(
                "2001:db8::".parse().unwrap(),
                32,
            ))),
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
            match_next_hop: None,
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    };
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32)),
            &[],
            &[],
            &[],
            "",
            0,
            RpkiValidation::NotFound,
        )
        .action,
        PolicyAction::Deny
    );
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            Prefix::V6(Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 48)),
            &[],
            &[],
            &[],
            "",
            0,
            RpkiValidation::NotFound,
        )
        .action,
        PolicyAction::Permit
    );
}

// -----------------------------------------------------------------------
// Prefix-length edge cases: the /0 mask-shift guard, /32 and /128 exact
// host masks, and ge/le bound combinations with boundaries. These pin the
// current matches_v4 / matches_v6 behavior so a future build-time prefix
// precompute cannot silently change it.
// -----------------------------------------------------------------------

fn permit_on(entry: Prefix, ge: Option<u8>, le: Option<u8>) -> Policy {
    let mut s = stmt(Some(entry), PolicyAction::Permit, vec![]);
    s.ge = ge;
    s.le = le;
    Policy {
        entries: vec![s],
        default_action: PolicyAction::Deny,
    }
}

fn v4_matches(pl: &Policy, addr: [u8; 4], len: u8) -> bool {
    evaluate_policy(
        Some(pl),
        v4_prefix(addr, len),
        &[],
        &[],
        &[],
        "",
        0,
        RpkiValidation::NotFound,
    )
    .action
        == PolicyAction::Permit
}

#[test]
fn zero_length_prefix_without_bounds_matches_only_default_route() {
    // 0.0.0.0/0 with no ge/le → (min,max)=(0,0): matches only a /0 route.
    // Exercises the `entry.len > 0` guard that avoids a `1 << 32` shift.
    let pl = permit_on(v4_entry([0, 0, 0, 0], 0), None, None);
    assert!(v4_matches(&pl, [0, 0, 0, 0], 0));
    assert!(!v4_matches(&pl, [10, 0, 0, 0], 24));
}

#[test]
fn zero_length_prefix_with_full_bounds_matches_everything() {
    // 0.0.0.0/0 ge 0 le 32 → (0,32): the canonical "match all" entry.
    let pl = permit_on(v4_entry([0, 0, 0, 0], 0), Some(0), Some(32));
    assert!(v4_matches(&pl, [0, 0, 0, 0], 0));
    assert!(v4_matches(&pl, [10, 20, 30, 0], 24));
    assert!(v4_matches(&pl, [192, 168, 1, 1], 32));
}

#[test]
fn host_route_v4_full_mask_matches_exact_address_only() {
    // /32 with no ge/le → (32,32) and a full mask: exact host only.
    let pl = permit_on(v4_entry([10, 0, 0, 1], 32), None, None);
    assert!(v4_matches(&pl, [10, 0, 0, 1], 32));
    assert!(!v4_matches(&pl, [10, 0, 0, 2], 32)); // mask distinguishes the host
    assert!(!v4_matches(&pl, [10, 0, 0, 1], 31)); // length differs
}

#[test]
fn host_route_v6_full_mask_matches_exact_address_only() {
    use rustbgpd_wire::Ipv6Prefix;

    let mut s = stmt(
        Some(Prefix::V6(Ipv6Prefix::new(
            "2001:db8::1".parse().unwrap(),
            128,
        ))),
        PolicyAction::Permit,
        vec![],
    );
    s.ge = None;
    s.le = None;
    let pl = Policy {
        entries: vec![s],
        default_action: PolicyAction::Deny,
    };
    let hit = |addr: &str, len: u8| {
        evaluate_policy(
            Some(&pl),
            Prefix::V6(Ipv6Prefix::new(addr.parse().unwrap(), len)),
            &[],
            &[],
            &[],
            "",
            0,
            RpkiValidation::NotFound,
        )
        .action
            == PolicyAction::Permit
    };
    assert!(hit("2001:db8::1", 128));
    assert!(!hit("2001:db8::2", 128)); // mask distinguishes the host
    assert!(!hit("2001:db8::1", 127)); // length differs
}

#[test]
fn ge_only_bounds_match_more_specifics_up_to_max() {
    // 10.0.0.0/8 ge 16 → (16,32): more-specifics of 10/8 from /16 to /32.
    let pl = permit_on(v4_entry([10, 0, 0, 0], 8), Some(16), None);
    assert!(!v4_matches(&pl, [10, 0, 0, 0], 8)); // /8 is below ge 16
    assert!(!v4_matches(&pl, [10, 1, 0, 0], 15)); // below ge
    assert!(v4_matches(&pl, [10, 1, 0, 0], 16)); // ge boundary
    assert!(v4_matches(&pl, [10, 1, 2, 3], 32)); // up to /32
    assert!(!v4_matches(&pl, [192, 0, 0, 0], 16)); // outside 10/8 network
}

#[test]
fn le_only_bounds_match_from_entry_length_to_le() {
    // 10.0.0.0/8 le 24 → (8,24).
    let pl = permit_on(v4_entry([10, 0, 0, 0], 8), None, Some(24));
    assert!(v4_matches(&pl, [10, 0, 0, 0], 8)); // entry-length boundary
    assert!(v4_matches(&pl, [10, 1, 2, 0], 24)); // le boundary
    assert!(!v4_matches(&pl, [10, 1, 2, 3], 25)); // above le
}

#[test]
fn ge_le_bounds_match_within_range_inclusive() {
    // 10.0.0.0/8 ge 16 le 24 → (16,24), boundaries inclusive.
    let pl = permit_on(v4_entry([10, 0, 0, 0], 8), Some(16), Some(24));
    assert!(!v4_matches(&pl, [10, 0, 0, 0], 8)); // below ge
    assert!(!v4_matches(&pl, [10, 1, 0, 0], 15)); // below ge
    assert!(v4_matches(&pl, [10, 1, 0, 0], 16)); // ge boundary
    assert!(v4_matches(&pl, [10, 1, 2, 0], 24)); // le boundary
    assert!(!v4_matches(&pl, [10, 1, 2, 3], 25)); // above le
}
