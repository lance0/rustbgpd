use super::*;

// -----------------------------------------------------------------------
// Large community matching
// -----------------------------------------------------------------------

#[test]
fn parse_large_community_match() {
    let cm = parse_community_match("LC:65001:100:200").unwrap();
    assert_eq!(
        cm,
        CommunityMatch::LargeCommunity {
            global_admin: 65001,
            local_data1: 100,
            local_data2: 200,
        }
    );
}

#[test]
fn parse_large_community_match_invalid() {
    assert!(parse_community_match("LC:65001:100").is_err());
    assert!(parse_community_match("LC:abc:100:200").is_err());
}

#[test]
fn large_community_match_hit() {
    let pl = Policy {
        entries: vec![stmt(
            None,
            PolicyAction::Deny,
            vec![CommunityMatch::LargeCommunity {
                global_admin: 65001,
                local_data1: 100,
                local_data2: 200,
            }],
        )],
        default_action: PolicyAction::Permit,
    };
    let lcs = [LargeCommunity::new(65001, 100, 200)];
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &lcs,
            "",
            0,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Deny
    );
}

#[test]
fn large_community_match_miss() {
    let pl = Policy {
        entries: vec![stmt(
            None,
            PolicyAction::Deny,
            vec![CommunityMatch::LargeCommunity {
                global_admin: 65001,
                local_data1: 100,
                local_data2: 200,
            }],
        )],
        default_action: PolicyAction::Permit,
    };
    let lcs = [LargeCommunity::new(65001, 999, 200)];
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &lcs,
            "",
            0,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Permit
    );
}

#[test]
fn large_community_does_not_match_standard_or_ec() {
    let cm = CommunityMatch::LargeCommunity {
        global_admin: 65001,
        local_data1: 100,
        local_data2: 200,
    };
    assert!(!cm.matches_ec(&make_rt(65001, 100)));
    assert!(!cm.matches_standard((65001 << 16) | 0x0064));
}

#[test]
fn or_across_all_community_types() {
    let pl = Policy {
        entries: vec![stmt(
            None,
            PolicyAction::Deny,
            vec![
                CommunityMatch::Standard {
                    value: (65001 << 16) | 0x0064,
                },
                CommunityMatch::RouteTarget {
                    global: 65002,
                    local: 200,
                },
                CommunityMatch::LargeCommunity {
                    global_admin: 65003,
                    local_data1: 300,
                    local_data2: 400,
                },
            ],
        )],
        default_action: PolicyAction::Permit,
    };
    // LC match
    let lcs = [LargeCommunity::new(65003, 300, 400)];
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &lcs,
            "",
            0,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Deny
    );
    // EC match
    let ecs = [make_rt(65002, 200)];
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &ecs,
            &[],
            &[],
            "",
            0,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Deny
    );
    // Standard match
    let std_c = (65001u32 << 16) | 0x0064;
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[std_c],
            &[],
            "",
            0,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Deny
    );
    // No match
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
}
