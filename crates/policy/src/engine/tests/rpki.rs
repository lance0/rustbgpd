use super::*;

// --- RPKI validation matching ---

#[test]
fn chain_reports_validation_state_dependencies() {
    let policy = |entries| Policy {
        entries,
        default_action: PolicyAction::Deny,
    };

    assert!(
        !PolicyChain::new(vec![policy(vec![stmt(None, PolicyAction::Permit, vec![])])])
            .requires_validation_state(),
        "ordinary policy predicates do not depend on external validation caches"
    );

    let mut as_path_len_only = stmt(None, PolicyAction::Permit, vec![]);
    as_path_len_only.match_as_path_length_ge = Some(2);
    assert!(
        !PolicyChain::new(vec![policy(vec![as_path_len_only])]).requires_validation_state(),
        "AS_PATH length matching is unrelated to RPKI/ASPA cache state"
    );

    let mut rpki = stmt(None, PolicyAction::Permit, vec![]);
    rpki.match_rpki_validation = Some(RpkiValidation::Invalid);
    let rpki_chain = PolicyChain::new(vec![policy(vec![rpki])]);
    assert!(rpki_chain.requires_rpki_validation());
    assert!(!rpki_chain.requires_aspa_validation());
    assert!(rpki_chain.requires_validation_state());

    let mut aspa = stmt(None, PolicyAction::Permit, vec![]);
    aspa.match_aspa_validation = Some(AspaValidation::Invalid);
    let aspa_chain = PolicyChain::new(vec![policy(vec![aspa])]);
    assert!(!aspa_chain.requires_rpki_validation());
    assert!(aspa_chain.requires_aspa_validation());
    assert!(aspa_chain.requires_validation_state());

    let mut second_policy_rpki = stmt(None, PolicyAction::Permit, vec![]);
    second_policy_rpki.match_rpki_validation = Some(RpkiValidation::Valid);
    assert!(
        PolicyChain::new(vec![
            policy(vec![stmt(None, PolicyAction::Permit, vec![])]),
            policy(vec![second_policy_rpki]),
        ])
        .requires_rpki_validation(),
        "dependency detection must scan every policy in the chain"
    );
}

#[test]
fn rpki_match_invalid_deny() {
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
            match_rpki_validation: Some(RpkiValidation::Invalid),
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
    // Invalid route → matches deny rule
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "",
            0,
            RpkiValidation::Invalid,
        )
        .action,
        PolicyAction::Deny
    );
    // Valid route → doesn't match, falls through to permit
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "",
            0,
            RpkiValidation::Valid,
        )
        .action,
        PolicyAction::Permit
    );
    // NotFound route → doesn't match
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
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

#[test]
fn rpki_match_valid_accept() {
    let pl = Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Permit,
            match_community: vec![],
            match_as_path: None,
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_rpki_validation: Some(RpkiValidation::Valid),
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: RouteModifications {
                set_local_pref: Some(200),
                ..RouteModifications::default()
            },
        }],
        default_action: PolicyAction::Permit,
    };
    // Valid route → matches, gets local_pref modification
    let r = evaluate_policy(
        Some(&pl),
        v4_prefix([10, 0, 0, 0], 8),
        &[],
        &[],
        &[],
        "",
        0,
        RpkiValidation::Valid,
    );
    assert_eq!(r.action, PolicyAction::Permit);
    assert_eq!(r.modifications.set_local_pref, Some(200));

    // NotFound route → doesn't match, gets default (no mods)
    let r = evaluate_policy(
        Some(&pl),
        v4_prefix([10, 0, 0, 0], 8),
        &[],
        &[],
        &[],
        "",
        0,
        RpkiValidation::NotFound,
    );
    assert_eq!(r.modifications.set_local_pref, None);
}

#[test]
fn rpki_match_not_found() {
    let pl = Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Permit,
            match_community: vec![],
            match_as_path: None,
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_rpki_validation: Some(RpkiValidation::NotFound),
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: RouteModifications {
                set_local_pref: Some(100),
                ..RouteModifications::default()
            },
        }],
        default_action: PolicyAction::Permit,
    };
    // NotFound → matches
    let r = evaluate_policy(
        Some(&pl),
        v4_prefix([10, 0, 0, 0], 8),
        &[],
        &[],
        &[],
        "",
        0,
        RpkiValidation::NotFound,
    );
    assert_eq!(r.modifications.set_local_pref, Some(100));
}

#[test]
fn rpki_match_none_matches_all() {
    // No RPKI match criterion → matches any validation state
    let pl = Policy {
        entries: vec![PolicyStatement {
            prefix: Some(v4_entry([10, 0, 0, 0], 8)),
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
    for state in [
        RpkiValidation::Valid,
        RpkiValidation::Invalid,
        RpkiValidation::NotFound,
    ] {
        assert_eq!(
            evaluate_policy(
                Some(&pl),
                v4_prefix([10, 0, 0, 0], 8),
                &[],
                &[],
                &[],
                "",
                0,
                state
            )
            .action,
            PolicyAction::Deny,
            "state={state:?} should still match"
        );
    }
}

#[test]
fn rpki_combined_with_prefix() {
    // Match: prefix 10.0.0.0/8 AND rpki=invalid → deny
    let pl = Policy {
        entries: vec![PolicyStatement {
            prefix: Some(v4_entry([10, 0, 0, 0], 8)),
            ge: None,
            le: None,
            action: PolicyAction::Deny,
            match_community: vec![],
            match_as_path: None,
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_rpki_validation: Some(RpkiValidation::Invalid),
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
    // Both match → deny
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "",
            0,
            RpkiValidation::Invalid,
        )
        .action,
        PolicyAction::Deny
    );
    // Prefix matches, RPKI doesn't → permit
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "",
            0,
            RpkiValidation::Valid,
        )
        .action,
        PolicyAction::Permit
    );
    // RPKI matches, prefix doesn't → permit
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([192, 168, 0, 0], 16),
            &[],
            &[],
            &[],
            "",
            0,
            RpkiValidation::Invalid,
        )
        .action,
        PolicyAction::Permit
    );
}
