use std::net::Ipv4Addr;

use super::*;

// -----------------------------------------------------------------------
// Community match parse tests
// -----------------------------------------------------------------------

#[test]
fn parse_community_match_rt_asn() {
    let cm = parse_community_match("RT:65001:100").unwrap();
    assert_eq!(
        cm,
        CommunityMatch::RouteTarget {
            global: 65001,
            local: 100
        }
    );
}

#[test]
fn parse_community_match_ro_asn() {
    let cm = parse_community_match("RO:65002:200").unwrap();
    assert_eq!(
        cm,
        CommunityMatch::RouteOrigin {
            global: 65002,
            local: 200
        }
    );
}

#[test]
fn parse_community_match_rt_ipv4() {
    let cm = parse_community_match("RT:192.0.2.1:100").unwrap();
    assert_eq!(
        cm,
        CommunityMatch::RouteTarget {
            global: u32::from(Ipv4Addr::new(192, 0, 2, 1)),
            local: 100
        }
    );
}

#[test]
fn parse_community_match_invalid_type() {
    assert!(parse_community_match("XX:1:2").is_err());
}

#[test]
fn parse_community_match_rejects_impossible_ipv4_local() {
    assert!(parse_community_match("RT:192.0.2.1:70000").is_err());
}

#[test]
fn parse_community_match_rejects_impossible_as4_local() {
    assert!(parse_community_match("RT:65551:70000").is_err());
}

#[test]
fn parse_community_match_standard() {
    let cm = parse_community_match("65001:100").unwrap();
    assert_eq!(
        cm,
        CommunityMatch::Standard {
            value: (65001 << 16) | 0x0064
        }
    );
}

#[test]
fn parse_community_match_well_known() {
    assert_eq!(
        parse_community_match("NO_EXPORT").unwrap(),
        CommunityMatch::Standard { value: 0xFFFF_FF01 }
    );
}

// -----------------------------------------------------------------------
// Community matching evaluation
// -----------------------------------------------------------------------

#[test]
fn community_only_entry_matches() {
    let pl = Policy {
        entries: vec![stmt(
            None,
            PolicyAction::Deny,
            vec![CommunityMatch::RouteTarget {
                global: 65001,
                local: 100,
            }],
        )],
        default_action: PolicyAction::Permit,
    };
    let ecs = [make_rt(65001, 100)];
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
}

#[test]
fn community_only_entry_no_match() {
    let pl = Policy {
        entries: vec![stmt(
            None,
            PolicyAction::Deny,
            vec![CommunityMatch::RouteTarget {
                global: 65001,
                local: 100,
            }],
        )],
        default_action: PolicyAction::Permit,
    };
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
        PolicyAction::Permit
    );
}

#[test]
fn prefix_and_community_both_required() {
    let pl = Policy {
        entries: vec![stmt(
            Some(v4_entry([10, 0, 0, 0], 8)),
            PolicyAction::Deny,
            vec![CommunityMatch::RouteTarget {
                global: 65001,
                local: 100,
            }],
        )],
        default_action: PolicyAction::Permit,
    };
    let ecs = [make_rt(65001, 100)];
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
    // Prefix mismatch
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([192, 168, 0, 0], 16),
            &ecs,
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
fn standard_community_match_hit() {
    let val = (65001u32 << 16) | 0x0064;
    let pl = Policy {
        entries: vec![stmt(
            None,
            PolicyAction::Deny,
            vec![CommunityMatch::Standard { value: val }],
        )],
        default_action: PolicyAction::Permit,
    };
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[val],
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
fn mixed_standard_and_ec_or_semantics() {
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
            ],
        )],
        default_action: PolicyAction::Permit,
    };
    let std_community = (65001u32 << 16) | 0x0064;
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[std_community],
            &[],
            "",
            0,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Deny
    );
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

#[test]
fn community_match_route_origin() {
    let pl = Policy {
        entries: vec![stmt(
            None,
            PolicyAction::Deny,
            vec![CommunityMatch::RouteOrigin {
                global: 65001,
                local: 100,
            }],
        )],
        default_action: PolicyAction::Permit,
    };
    let target_ecs = [make_rt(65001, 100)];
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &target_ecs,
            &[],
            &[],
            "",
            0,
            RpkiValidation::NotFound
        )
        .action,
        PolicyAction::Permit
    );
    let origin_ecs = [make_ro(65001, 100)];
    assert_eq!(
        evaluate_policy(
            Some(&pl),
            v4_prefix([10, 0, 0, 0], 8),
            &origin_ecs,
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
