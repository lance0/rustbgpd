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
            match_rpki_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
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
            match_rpki_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
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
