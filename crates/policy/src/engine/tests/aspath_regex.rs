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

/// The pre-scan matcher every `_<digits>_` pattern compiled to.
fn boundary_regex(pattern: &str) -> Regex {
    Regex::new(&pattern.replace('_', "(?:^| |$|[{}])")).unwrap()
}

/// The token scan agrees with the boundary regex on rendered paths of each
/// segment shape: `AS_SEQUENCE`, `AS_SET`, mixed, sets at either end, and
/// 2- vs 4-octet ASNs whose digits embed one another.
#[test]
fn aspath_asn_token_matches_boundary_regex_per_segment_type() {
    use rustbgpd_wire::{AsPath, AsPathSegment::AsSequence, AsPathSegment::AsSet};

    let paths = [
        AsPath { segments: vec![] },
        AsPath {
            segments: vec![AsSequence(vec![65001, 65100, 4_200_000_000])],
        },
        AsPath {
            segments: vec![AsSet(vec![65003, 650_030, 1])],
        },
        AsPath {
            segments: vec![AsSequence(vec![174, 65003]), AsSet(vec![65004, 17])],
        },
        AsPath {
            segments: vec![
                AsSet(vec![65100]),
                AsSequence(vec![1, 65100]),
                AsSet(vec![]),
            ],
        },
        AsPath {
            segments: vec![AsSequence(vec![4_294_967_295, 42_949_672, 65535])],
        },
    ];
    let asns = [
        1u32,
        17,
        174,
        1740,
        65003,
        650_030,
        65004,
        65100,
        65535,
        42_949_672,
        4_200_000_000,
        4_294_967_295,
        0,
    ];
    let mut checked = 0;
    for path in &paths {
        let rendered = path.to_aspath_string();
        for asn in asns {
            let pattern = format!("_{asn}_");
            let scan = AsPathRegex::new(&pattern).unwrap();
            assert!(scan.regex.is_none(), "{pattern} compiled an automaton");
            assert_eq!(
                scan.is_match(&rendered),
                boundary_regex(&pattern).is_match(&rendered),
                "{pattern} on {rendered:?}"
            );
            checked += usize::from(scan.is_match(&rendered));
        }
    }
    // Both outcomes occur: the comparison is not vacuous.
    assert!(checked > 10, "{checked}");
}

/// Seeded differential check over arbitrary strings (including non-ASCII
/// bytes and adjacent braces), since `AsPathRegex` is a public type that
/// TOML policy and API callers also feed directly.
#[test]
fn aspath_asn_token_matches_boundary_regex_on_random_strings() {
    const ALPHABET: [char; 8] = ['1', '2', '0', ' ', '{', '}', 'é', 'x'];
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = |bound: usize| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        usize::try_from(state % bound as u64).unwrap()
    };
    let (mut hits, mut misses) = (0, 0);
    for _ in 0..20_000 {
        let digits: String = (0..=next(3)).map(|_| ['1', '2', '0'][next(3)]).collect();
        let pattern = format!("_{digits}_");
        let path: String = (0..next(12))
            .map(|_| ALPHABET[next(ALPHABET.len())])
            .collect();
        let scan = AsPathRegex::new(&pattern).unwrap();
        let expected = boundary_regex(&pattern).is_match(&path);
        assert_eq!(scan.is_match(&path), expected, "{pattern} on {path:?}");
        if expected {
            hits += 1;
        } else {
            misses += 1;
        }
    }
    assert!(hits > 1_000 && misses > 1_000, "{hits} / {misses}");
}

/// Only exact `_<digits>_` patterns take the token scan; anything else is
/// still a regex.
#[test]
fn aspath_asn_token_only_for_single_asn_boundary_patterns() {
    for pattern in ["_65001_", "_0_", "_00123_"] {
        assert!(
            AsPathRegex::new(pattern).unwrap().regex.is_none(),
            "{pattern}"
        );
    }
    for pattern in [
        "__",
        "_65001",
        "65001_",
        "_6500a_",
        "_65001_65002_",
        "^_65001_$",
        "_[0-9]_",
    ] {
        assert!(
            AsPathRegex::new(pattern).unwrap().regex.is_some(),
            "{pattern}"
        );
    }
}

/// `route.as-path contains N` with many distinct values interns no regex
/// automaton: each costs its pattern string, so a chain's resident size
/// follows the node budget instead of carrying one compiled regex per ASN.
#[test]
fn rpol_distinct_as_path_contains_compile_no_automata() {
    use std::fmt::Write as _;

    const CALLS: u32 = 100_000;
    let mut source = String::from("policy big {\n");
    for asn in 1..=CALLS {
        let _ = writeln!(
            source,
            "term t{asn} {{ if route.as-path contains {asn} {{ reject }} }}"
        );
    }
    source.push('}');
    let chain =
        crate::rpol::compile_rpol(&source, &mut crate::sets::SetStore::new()).expect("compiles");
    assert_eq!(chain.as_path_regexes.len(), CALLS as usize);
    let automata = chain
        .as_path_regexes
        .iter()
        .filter(|regex| regex.regex.is_some())
        .count();
    assert_eq!(automata, 0);
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

#[test]
fn chain_requires_as_path_string_only_for_regex() {
    let regex_stmt = |pat: &str| {
        let mut s = stmt(None, PolicyAction::Permit, vec![]);
        s.match_as_path = Some(AsPathRegex::new(pat).unwrap());
        s
    };
    let policy = |entries| Policy {
        entries,
        default_action: PolicyAction::Deny,
    };

    // No AS_PATH criteria -> the rendered string is never read.
    assert!(
        !PolicyChain::new(vec![policy(vec![stmt(None, PolicyAction::Permit, vec![])])])
            .requires_as_path_string()
    );

    // AS_PATH *length* matching uses the cheap count, not the string.
    let mut len_only = stmt(None, PolicyAction::Permit, vec![]);
    len_only.match_as_path_length_ge = Some(2);
    assert!(!PolicyChain::new(vec![policy(vec![len_only])]).requires_as_path_string());

    // An AS_PATH *regex* anywhere in the chain requires the string.
    assert!(PolicyChain::new(vec![policy(vec![regex_stmt("_65000_")])]).requires_as_path_string());
    assert!(
        PolicyChain::new(vec![
            policy(vec![stmt(None, PolicyAction::Permit, vec![])]),
            policy(vec![regex_stmt("^65100")]),
        ])
        .requires_as_path_string()
    );
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
