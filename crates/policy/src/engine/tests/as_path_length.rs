use super::*;

use rustbgpd_wire::{AsPath, AsPathSegment};

// -----------------------------------------------------------------------
// AS_PATH length matching
// -----------------------------------------------------------------------

#[test]
fn aspath_length_ge_matches() {
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
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: Some(3),
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
    // length 3 → matches ge=3
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "",
            3,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Deny
    );
    // length 5 → matches ge=3
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "",
            5,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Deny
    );
    // length 2 → doesn't match ge=3
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "",
            2,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Permit
    );
}

#[test]
fn aspath_length_le_matches() {
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
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: Some(3),
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    };
    // length 1 → matches le=3
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "",
            1,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Deny
    );
    // length 3 → matches le=3
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "",
            3,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Deny
    );
    // length 4 → doesn't match le=3
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "",
            4,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Permit
    );
}

#[test]
fn aspath_length_range_matches() {
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
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: Some(2),
            match_as_path_length_le: Some(4),
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    };
    // length 1 → below range
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "",
            1,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Permit
    );
    // length 2,3,4 → in range
    for len in [2, 3, 4] {
        assert_eq!(
            evaluate_policy(
                Some(&pl),
                v4_prefix([10, 0, 0, 0], 8),
                &[],
                &[],
                &[],
                "",
                len,
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Deny,
            "length {len} should match range [2,4]"
        );
    }
    // length 5 → above range
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "",
            5,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Permit
    );
}

#[test]
fn aspath_length_combined_with_regex() {
    // Both regex and length must match (AND logic)
    let pl = Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Deny,
            match_community: vec![],
            match_as_path: Some(AsPathRegex::new("^65100").unwrap()),
            match_neighbor_set: None,
            match_route_type: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: Some(2),
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
    // regex matches, length matches → deny
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "65100 65200",
            2,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Deny
    );
    // regex matches, length doesn't → permit
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "65100",
            1,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Permit
    );
    // regex doesn't match, length matches → permit
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "65200 65300",
            2,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Permit
    );
}

#[test]
fn aspath_length_as_set_counts_as_one() {
    // AS_SET {65001 65002} counts as 1 toward length per RFC 4271
    let path = AsPath {
        segments: vec![
            AsPathSegment::AsSequence(vec![65100]),
            AsPathSegment::AsSet(vec![65001, 65002]),
        ],
    };
    // AS_SEQUENCE(1) + AS_SET(1) = 2
    assert_eq!(path.len(), 2);

    // With ge=3, length 2 should not match
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
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: Some(3),
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
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            &path.to_aspath_string(),
            path.len(),
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Permit
    );
}

#[test]
fn aspath_length_standalone_match() {
    // Length match without prefix — valid standalone like regex
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
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: Some(3),
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
        default_action: PolicyAction::Deny,
    };
    let r = evaluate_policy(
        Some(&pl),
        v4_prefix([10, 0, 0, 0], 8),
        &[],
        &[],
        &[],
        "",
        2,
        RpkiValidation::NotFound,
    );
    assert_eq!(r.action, PolicyAction::Permit);
    assert_eq!(r.modifications.set_local_pref, Some(200));
}
