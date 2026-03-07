use super::*;

// -----------------------------------------------------------------------
// AsPathRegex
// -----------------------------------------------------------------------

#[test]
fn aspath_regex_starts_with() {
    let r = AsPathRegex::new("^65100").unwrap();
    assert!(r.is_match("65100 65200"));
    assert!(!r.is_match("65200 65100"));
}

#[test]
fn aspath_regex_ends_with() {
    let r = AsPathRegex::new("65200$").unwrap();
    assert!(r.is_match("65100 65200"));
    assert!(!r.is_match("65200 65100"));
}

#[test]
fn aspath_regex_contains() {
    let r = AsPathRegex::new("65200").unwrap();
    assert!(r.is_match("65100 65200 65300"));
    assert!(!r.is_match("65100 65300"));
}

#[test]
fn aspath_regex_exact() {
    let r = AsPathRegex::new("^65100$").unwrap();
    assert!(r.is_match("65100"));
    assert!(!r.is_match("65100 65200"));
}

#[test]
fn aspath_regex_underscore_boundary() {
    // _65200_ should match 65200 as a separate AS number
    let r = AsPathRegex::new("_65200_").unwrap();
    assert!(r.is_match("65100 65200 65300"));
    assert!(r.is_match("65200"));
    assert!(!r.is_match("165200"));
}

#[test]
fn aspath_regex_underscore_matches_as_set_braces() {
    // _ should match { and } delimiters in AS_SET representation
    let r = AsPathRegex::new("_65003_").unwrap();
    assert!(r.is_match("65001 {65003 65004}"));
    assert!(r.is_match("{65003}"));
    assert!(!r.is_match("65001 {650030 65004}"));
}

#[test]
fn aspath_regex_raw_pattern() {
    let r = AsPathRegex::new("651[0-9]{2}").unwrap();
    assert!(r.is_match("65100"));
    assert!(r.is_match("65199"));
    assert!(!r.is_match("65200"));
}

#[test]
fn aspath_regex_invalid_rejected() {
    assert!(AsPathRegex::new("[invalid").is_err());
}

// -----------------------------------------------------------------------
// AS_PATH regex in policy evaluation
// -----------------------------------------------------------------------

#[test]
fn aspath_match_in_policy() {
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
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "65100 65200",
            0,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Deny
    );
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "65200 65100",
            0,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Permit
    );
}

#[test]
fn aspath_combined_with_prefix() {
    let pl = Policy {
        entries: vec![PolicyStatement {
            prefix: Some(v4_entry([10, 0, 0, 0], 8)),
            ge: None,
            le: None,
            action: PolicyAction::Deny,
            match_community: vec![],
            match_as_path: Some(AsPathRegex::new("_65200_").unwrap()),
            match_neighbor_set: None,
            match_route_type: None,
            match_rpki_validation: None,
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
            "65100 65200",
            0,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Deny
    );
    // Prefix matches, aspath doesn't → permit
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "65100 65300",
            0,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Permit
    );
    // Aspath matches, prefix doesn't → permit
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([192, 168, 0, 0], 16),
            &[],
            &[],
            &[],
            "65100 65200",
            0,
            RpkiValidation::NotFound,
        )
        .action,
        PolicyAction::Permit
    );
}

#[test]
fn aspath_combined_with_community() {
    let pl = Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Deny,
            match_community: vec![CommunityMatch::Standard {
                value: (65001 << 16) | 0x0064,
            }],
            match_as_path: Some(AsPathRegex::new("_65200_").unwrap()),
            match_neighbor_set: None,
            match_route_type: None,
            match_rpki_validation: None,
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
    let std_c = (65001u32 << 16) | 0x0064;
    // Both match → deny
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[std_c],
            &[],
            "65200",
            0,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Deny
    );
    // Community matches, aspath doesn't → permit
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[std_c],
            &[],
            "65300",
            0,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Permit
    );
}
