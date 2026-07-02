//! Golden decision-compatibility corpus (ADR-0096 PR-1).
//!
//! Pins the IR path — `PolicyChain::evaluate_with_attribution`, which
//! compiles through `crate::compile` and evaluates through the
//! `CompiledChain` evaluator — decision-identical to the legacy
//! statement walker (`evaluate_with_attribution_legacy`) across a broad
//! (chain-shape × route-context) matrix:
//!
//! - every match field kind, including the indexed community-set path
//!   (multi-criterion OR-lists) and the inline single-criterion path;
//! - prefix ge/le boundaries, len-0 entries, and the mask-only corner
//!   where the member is longer than the candidate;
//! - the RFC 4271 implicit `LOCAL_PREF` 100 / `MED` 0 defaults at
//!   their exact boundaries, against both explicit and absent
//!   attributes;
//! - first-match-wins within a policy, chain accumulation and
//!   deny-termination across policies, modification merge conflicts,
//!   deny statements carrying (dropped) modifications;
//! - attribution names for named / unnamed / empty / `None` chains;
//! - `requires_*` introspection parity (legacy field scan vs IR walk).
//!
//! Both `PolicyResult` and `PolicyEvaluation` must be equal on every
//! case. The legacy walker stays in-tree solely as this oracle until a
//! later ADR-0096 slice deletes it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rustbgpd_wire::{
    AspaValidation, ExtendedCommunity, Ipv6Prefix, LargeCommunity, Prefix, RpkiValidation,
};

use super::*;

fn v6_prefix(len: u8) -> Prefix {
    Prefix::V6(Ipv6Prefix::new(
        Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0),
        len,
    ))
}

fn base(action: PolicyAction) -> PolicyStatement {
    stmt(None, action, vec![])
}

fn full_mods() -> RouteModifications {
    RouteModifications {
        set_local_pref: Some(200),
        set_med: Some(10),
        set_next_hop: Some(NextHopAction::Self_),
        communities_add: vec![(65001 << 16) | 0x2A],
        communities_remove: vec![(65001 << 16) | 0x64],
        extended_communities_add: vec![make_rt(65010, 1)],
        extended_communities_remove: vec![make_ro(65002, 9)],
        large_communities_add: vec![LargeCommunity {
            global_admin: 65009,
            local_data1: 1,
            local_data2: 1,
        }],
        large_communities_remove: vec![LargeCommunity {
            global_admin: 65001,
            local_data1: 1,
            local_data2: 2,
        }],
        as_path_prepend: Some((65001, 2)),
    }
}

/// One statement shape per match-field kind (plus combinations), all
/// built with `Permit`; the harness derives the Deny / with-mods /
/// default-action versions.
#[expect(clippy::too_many_lines, reason = "the corpus is the point")]
fn statement_variants() -> Vec<(&'static str, PolicyStatement)> {
    let mut variants: Vec<(&'static str, PolicyStatement)> = Vec::new();

    variants.push(("unconditional", base(PolicyAction::Permit)));

    let mut s = base(PolicyAction::Permit);
    s.prefix = Some(v4_prefix([10, 20, 30, 0], 24));
    variants.push(("prefix_exact_24", s));

    let mut s = base(PolicyAction::Permit);
    s.prefix = Some(v4_prefix([10, 20, 0, 0], 16));
    s.ge = Some(24);
    variants.push(("prefix_16_ge24", s));

    let mut s = base(PolicyAction::Permit);
    s.prefix = Some(v4_prefix([10, 20, 0, 0], 16));
    s.le = Some(28);
    variants.push(("prefix_16_le28", s));

    let mut s = base(PolicyAction::Permit);
    s.prefix = Some(v4_prefix([10, 20, 0, 0], 16));
    s.ge = Some(24);
    s.le = Some(28);
    variants.push(("prefix_16_ge24_le28", s));

    let mut s = base(PolicyAction::Permit);
    s.prefix = Some(v4_prefix([0, 0, 0, 0], 0));
    variants.push(("prefix_default_only", s));

    let mut s = base(PolicyAction::Permit);
    s.prefix = Some(v4_prefix([0, 0, 0, 0], 0));
    s.ge = Some(0);
    s.le = Some(32);
    variants.push(("prefix_any_v4", s));

    let mut s = base(PolicyAction::Permit);
    s.prefix = Some(v4_prefix([10, 20, 30, 40], 32));
    variants.push(("prefix_host_32", s));

    // Mask-only corner: member longer than candidate, ge below member.
    let mut s = base(PolicyAction::Permit);
    s.prefix = Some(v4_prefix([10, 20, 0, 0], 16));
    s.ge = Some(8);
    variants.push(("prefix_16_ge8_below_len", s));

    let mut s = base(PolicyAction::Permit);
    s.prefix = Some(v6_prefix(32));
    s.ge = Some(48);
    s.le = Some(64);
    variants.push(("prefix_v6_32_ge48_le64", s));

    let mut s = base(PolicyAction::Permit);
    s.prefix = Some(v6_prefix(48));
    variants.push(("prefix_v6_exact_48", s));

    // Single community criterion → inline CommunityContains.
    let mut s = base(PolicyAction::Permit);
    s.match_community = vec![CommunityMatch::Standard {
        value: (65001 << 16) | 0x64,
    }];
    variants.push(("community_std_single", s));

    // Multi-criterion OR-list → indexed CommunityInSet.
    let mut s = base(PolicyAction::Permit);
    s.match_community = vec![
        CommunityMatch::Standard {
            value: (65001 << 16) | 0x64,
        },
        CommunityMatch::Standard {
            value: (65001 << 16) | 0xC8,
        },
        CommunityMatch::Standard {
            value: (65500 << 16) | 0x01,
        },
    ];
    variants.push(("community_std_set", s));

    let mut s = base(PolicyAction::Permit);
    s.match_community = vec![CommunityMatch::RouteTarget {
        global: 65001,
        local: 7,
    }];
    variants.push(("community_rt", s));

    let mut s = base(PolicyAction::Permit);
    s.match_community = vec![CommunityMatch::RouteOrigin {
        global: 65002,
        local: 9,
    }];
    variants.push(("community_ro", s));

    let mut s = base(PolicyAction::Permit);
    s.match_community = vec![CommunityMatch::LargeCommunity {
        global_admin: 65001,
        local_data1: 1,
        local_data2: 2,
    }];
    variants.push(("community_lc", s));

    let mut s = base(PolicyAction::Permit);
    s.match_community = vec![
        CommunityMatch::Standard {
            value: (65001 << 16) | 0xC8,
        },
        CommunityMatch::RouteTarget {
            global: 65001,
            local: 7,
        },
        CommunityMatch::LargeCommunity {
            global_admin: 65001,
            local_data1: 1,
            local_data2: 2,
        },
        CommunityMatch::RouteOrigin {
            global: 65002,
            local: 9,
        },
    ];
    variants.push(("community_mixed_set", s));

    let mut s = base(PolicyAction::Permit);
    s.match_as_path = Some(AsPathRegex::new("_65100_").unwrap());
    variants.push(("as_path_regex_mid", s));

    let mut s = base(PolicyAction::Permit);
    s.match_as_path = Some(AsPathRegex::new("^65001").unwrap());
    variants.push(("as_path_regex_anchor", s));

    let mut s = base(PolicyAction::Permit);
    s.prefix = Some(v4_prefix([10, 20, 0, 0], 16));
    s.ge = Some(16);
    s.le = Some(24);
    s.match_community = vec![CommunityMatch::Standard {
        value: (65001 << 16) | 0x64,
    }];
    s.match_as_path = Some(AsPathRegex::new("_65100_").unwrap());
    variants.push(("prefix_community_regex", s));

    let mut s = base(PolicyAction::Permit);
    s.match_neighbor_set = Some(NeighborSetMatch {
        addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
        remote_asns: vec![],
        peer_groups: vec![],
    });
    variants.push(("neighbor_addr", s));

    let mut s = base(PolicyAction::Permit);
    s.match_neighbor_set = Some(NeighborSetMatch {
        addresses: vec![],
        remote_asns: vec![65001],
        peer_groups: vec![],
    });
    variants.push(("neighbor_asn", s));

    let mut s = base(PolicyAction::Permit);
    s.match_neighbor_set = Some(NeighborSetMatch {
        addresses: vec![],
        remote_asns: vec![],
        peer_groups: vec!["leaf".to_string()],
    });
    variants.push(("neighbor_group", s));

    let mut s = base(PolicyAction::Permit);
    s.match_neighbor_set = Some(NeighborSetMatch {
        addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99))],
        remote_asns: vec![65001],
        peer_groups: vec!["spine".to_string()],
    });
    variants.push(("neighbor_mixed", s));

    let mut s = base(PolicyAction::Permit);
    s.match_route_type = Some(RouteType::Internal);
    variants.push(("route_type_internal", s));

    let mut s = base(PolicyAction::Permit);
    s.match_route_type = Some(RouteType::External);
    variants.push(("route_type_external", s));

    let mut s = base(PolicyAction::Permit);
    s.match_evpn_route_type = Some(2);
    variants.push(("evpn_type_2", s));

    let mut s = base(PolicyAction::Permit);
    s.match_rpki_validation = Some(RpkiValidation::Invalid);
    variants.push(("rpki_invalid", s));

    let mut s = base(PolicyAction::Permit);
    s.match_rpki_validation = Some(RpkiValidation::Valid);
    variants.push(("rpki_valid", s));

    let mut s = base(PolicyAction::Permit);
    s.match_aspa_validation = Some(AspaValidation::Invalid);
    variants.push(("aspa_invalid", s));

    let mut s = base(PolicyAction::Permit);
    s.match_as_path_length_ge = Some(3);
    variants.push(("as_path_len_ge3", s));

    let mut s = base(PolicyAction::Permit);
    s.match_as_path_length_le = Some(2);
    variants.push(("as_path_len_le2", s));

    let mut s = base(PolicyAction::Permit);
    s.match_as_path_length_ge = Some(1);
    s.match_as_path_length_le = Some(3);
    variants.push(("as_path_len_ge1_le3", s));

    // Implicit LOCAL_PREF (100) boundaries.
    let mut s = base(PolicyAction::Permit);
    s.match_local_pref_ge = Some(100);
    variants.push(("lp_ge100", s));

    let mut s = base(PolicyAction::Permit);
    s.match_local_pref_ge = Some(101);
    variants.push(("lp_ge101", s));

    let mut s = base(PolicyAction::Permit);
    s.match_local_pref_le = Some(99);
    variants.push(("lp_le99", s));

    let mut s = base(PolicyAction::Permit);
    s.match_local_pref_le = Some(100);
    variants.push(("lp_le100", s));

    // Implicit MED (0) boundaries.
    let mut s = base(PolicyAction::Permit);
    s.match_med_ge = Some(1);
    variants.push(("med_ge1", s));

    let mut s = base(PolicyAction::Permit);
    s.match_med_le = Some(0);
    variants.push(("med_le0", s));

    let mut s = base(PolicyAction::Permit);
    s.match_med_ge = Some(0);
    s.match_med_le = Some(50);
    variants.push(("med_ge0_le50", s));

    let mut s = base(PolicyAction::Permit);
    s.match_next_hop = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)));
    variants.push(("next_hop_eq", s));

    // Every field at once — the widest And guard.
    let mut s = base(PolicyAction::Permit);
    s.prefix = Some(v4_prefix([10, 20, 0, 0], 16));
    s.ge = Some(16);
    s.le = Some(32);
    s.match_community = vec![
        CommunityMatch::Standard {
            value: (65001 << 16) | 0x64,
        },
        CommunityMatch::RouteTarget {
            global: 65001,
            local: 7,
        },
    ];
    s.match_as_path = Some(AsPathRegex::new("_65100_").unwrap());
    s.match_neighbor_set = Some(NeighborSetMatch {
        addresses: vec![],
        remote_asns: vec![65001],
        peer_groups: vec![],
    });
    s.match_route_type = Some(RouteType::External);
    s.match_rpki_validation = Some(RpkiValidation::NotFound);
    s.match_aspa_validation = Some(AspaValidation::Unknown);
    s.match_as_path_length_ge = Some(1);
    s.match_as_path_length_le = Some(5);
    s.match_local_pref_ge = Some(50);
    s.match_local_pref_le = Some(150);
    s.match_med_ge = Some(0);
    s.match_med_le = Some(100);
    s.match_next_hop = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)));
    variants.push(("kitchen_sink", s));

    variants
}

/// Backing storage for the borrowed `RouteContext` fields.
struct Backing {
    comm_hit: Vec<u32>,
    comm_alt: Vec<u32>,
    ext: Vec<ExtendedCommunity>,
    large: Vec<LargeCommunity>,
    path_a: String,
    path_b: String,
}

impl Backing {
    fn new() -> Self {
        Self {
            comm_hit: vec![(65001 << 16) | 0x64, (65500 << 16) | 0x01],
            comm_alt: vec![(65001 << 16) | 0xC8],
            ext: vec![make_rt(65001, 7), make_ro(65002, 9)],
            large: vec![LargeCommunity {
                global_admin: 65001,
                local_data1: 1,
                local_data2: 2,
            }],
            path_a: "65001 65100 65200".to_string(),
            path_b: "65010".to_string(),
        }
    }
}

fn blank_ctx() -> RouteContext<'static> {
    RouteContext {
        prefix: None,
        next_hop: None,
        extended_communities: &[],
        communities: &[],
        large_communities: &[],
        as_path_str: "",
        as_path_len: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: AspaValidation::Unknown,
        peer_address: None,
        peer_asn: None,
        peer_group: None,
        route_type: None,
        evpn_route_type: None,
        local_pref: None,
        med: None,
    }
}

#[expect(clippy::too_many_lines, reason = "the corpus is the point")]
fn contexts(b: &Backing) -> Vec<(&'static str, RouteContext<'_>)> {
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let next_hop = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));

    vec![
        (
            "full_v4_hit",
            RouteContext {
                prefix: Some(v4_prefix([10, 20, 30, 0], 24)),
                next_hop: Some(next_hop),
                extended_communities: &b.ext,
                communities: &b.comm_hit,
                large_communities: &b.large,
                as_path_str: &b.path_a,
                as_path_len: 3,
                peer_address: Some(peer),
                peer_asn: Some(65001),
                peer_group: Some("leaf"),
                route_type: Some(RouteType::External),
                local_pref: Some(100),
                med: Some(50),
                ..blank_ctx()
            },
        ),
        (
            "implicit_attrs_alt_comm",
            RouteContext {
                prefix: Some(v4_prefix([10, 20, 30, 0], 24)),
                next_hop: Some(next_hop),
                communities: &b.comm_alt,
                as_path_str: &b.path_b,
                as_path_len: 1,
                validation_state: RpkiValidation::Valid,
                peer_asn: Some(65002),
                route_type: Some(RouteType::Internal),
                local_pref: None,
                med: None,
                ..blank_ctx()
            },
        ),
        (
            "lp99_med0_explicit",
            RouteContext {
                prefix: Some(v4_prefix([10, 20, 30, 0], 24)),
                as_path_str: &b.path_a,
                as_path_len: 3,
                local_pref: Some(99),
                med: Some(0),
                ..blank_ctx()
            },
        ),
        (
            "lp101_med1",
            RouteContext {
                prefix: Some(v4_prefix([10, 20, 30, 0], 24)),
                local_pref: Some(101),
                med: Some(1),
                ..blank_ctx()
            },
        ),
        ("prefixless_bgp_ls", blank_ctx()),
        (
            "v6_route",
            RouteContext {
                prefix: Some(v6_prefix(48)),
                next_hop: Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
                as_path_str: &b.path_a,
                as_path_len: 3,
                ..blank_ctx()
            },
        ),
        (
            "v4_default_route",
            RouteContext {
                prefix: Some(v4_prefix([0, 0, 0, 0], 0)),
                ..blank_ctx()
            },
        ),
        (
            "v4_host_route",
            RouteContext {
                prefix: Some(v4_prefix([10, 20, 30, 40], 32)),
                communities: &b.comm_hit,
                ..blank_ctx()
            },
        ),
        (
            "unrelated_invalid",
            RouteContext {
                prefix: Some(v4_prefix([192, 0, 2, 0], 24)),
                validation_state: RpkiValidation::Invalid,
                aspa_state: AspaValidation::Invalid,
                ..blank_ctx()
            },
        ),
        (
            "evpn_mac_ip",
            RouteContext {
                prefix: Some(v4_prefix([10, 20, 30, 0], 24)),
                route_type: Some(RouteType::Local),
                evpn_route_type: Some(2),
                ..blank_ctx()
            },
        ),
        (
            "evpn_ip_prefix",
            RouteContext {
                evpn_route_type: Some(5),
                ..blank_ctx()
            },
        ),
        (
            "v4_short_8",
            RouteContext {
                prefix: Some(v4_prefix([10, 20, 0, 0], 8)),
                ..blank_ctx()
            },
        ),
        (
            "group_only_peer",
            RouteContext {
                prefix: Some(v4_prefix([10, 20, 30, 0], 24)),
                peer_group: Some("leaf"),
                ..blank_ctx()
            },
        ),
    ]
}

/// A leading statement no corpus context matches, so single-statement
/// chains still exercise the first-match-wins walk.
fn never_matches() -> PolicyStatement {
    stmt(
        Some(v4_prefix([203, 0, 113, 0], 24)),
        PolicyAction::Deny,
        vec![],
    )
}

fn named(name: &str, policy: Policy) -> NamedPolicy {
    NamedPolicy {
        name: Some(name.to_string()),
        policy,
        rpol: None,
    }
}

/// Generated single-statement chains: every variant × action ×
/// default-action × with/without modifications.
fn generated_chains() -> Vec<(String, PolicyChain)> {
    let mut chains = Vec::new();
    for (variant_name, statement) in statement_variants() {
        for action in [PolicyAction::Permit, PolicyAction::Deny] {
            for default_action in [PolicyAction::Permit, PolicyAction::Deny] {
                for with_mods in [false, true] {
                    let mut s = statement.clone();
                    s.action = action;
                    if with_mods {
                        // Also attached to Deny statements: the legacy
                        // path drops their modifications, the compiler
                        // must too.
                        s.modifications = full_mods();
                    }
                    let chain = PolicyChain::from_named(vec![named(
                        "p0",
                        Policy {
                            entries: vec![never_matches(), s],
                            default_action,
                        },
                    )]);
                    chains.push((
                        format!(
                            "{variant_name}/{action:?}/default_{default_action:?}/mods_{with_mods}"
                        ),
                        chain,
                    ));
                }
            }
        }
    }
    chains
}

/// Hand-built multi-policy chains covering chain-level semantics.
#[expect(clippy::too_many_lines, reason = "the corpus is the point")]
fn composed_chains() -> Vec<(String, PolicyChain)> {
    let permit_all = |mods: RouteModifications| {
        let mut s = base(PolicyAction::Permit);
        s.modifications = mods;
        s
    };
    let deny_on_prefix =
        |addr: [u8; 4], len: u8| stmt(Some(v4_prefix(addr, len)), PolicyAction::Deny, vec![]);

    let mut chains: Vec<(String, PolicyChain)> = Vec::new();

    chains.push(("empty_chain".to_string(), PolicyChain::default()));

    for default_action in [PolicyAction::Permit, PolicyAction::Deny] {
        chains.push((
            format!("entryless_policy_default_{default_action:?}"),
            PolicyChain::from_named(vec![named(
                "fallthrough",
                Policy {
                    entries: vec![],
                    default_action,
                },
            )]),
        ));
    }

    // Merge conflicts: later policy wins scalars; a later remove
    // cancels an earlier add (exact and RT-equivalence lists).
    let mods_a = RouteModifications {
        set_local_pref: Some(200),
        communities_add: vec![(65001 << 16) | 0x2A],
        extended_communities_add: vec![make_rt(65010, 1)],
        ..RouteModifications::default()
    };
    let mods_b = RouteModifications {
        set_local_pref: Some(300),
        communities_remove: vec![(65001 << 16) | 0x2A],
        extended_communities_remove: vec![make_rt_as4(65010, 1)],
        ..RouteModifications::default()
    };
    chains.push((
        "merge_conflicts".to_string(),
        PolicyChain::from_named(vec![
            named(
                "first",
                Policy {
                    entries: vec![permit_all(mods_a.clone())],
                    default_action: PolicyAction::Deny,
                },
            ),
            named(
                "second",
                Policy {
                    entries: vec![permit_all(mods_b)],
                    default_action: PolicyAction::Deny,
                },
            ),
        ]),
    ));

    // Permit then deny-on-hit: attribution goes to the denying policy.
    chains.push((
        "permit_then_deny_on_hit".to_string(),
        PolicyChain::from_named(vec![
            named(
                "open",
                Policy {
                    entries: vec![permit_all(mods_a.clone())],
                    default_action: PolicyAction::Permit,
                },
            ),
            named(
                "guard",
                Policy {
                    entries: vec![deny_on_prefix([10, 20, 30, 0], 24)],
                    default_action: PolicyAction::Permit,
                },
            ),
        ]),
    ));

    // Unconditional deny first: the second policy (with mods) is never
    // consulted.
    chains.push((
        "deny_terminates_chain".to_string(),
        PolicyChain::from_named(vec![
            named(
                "wall",
                Policy {
                    entries: vec![base(PolicyAction::Deny)],
                    default_action: PolicyAction::Permit,
                },
            ),
            named(
                "unreached",
                Policy {
                    entries: vec![permit_all(full_mods())],
                    default_action: PolicyAction::Deny,
                },
            ),
        ]),
    ));

    // Unnamed terminal policy: attribution must be None.
    chains.push((
        "unnamed_terminal".to_string(),
        PolicyChain::new(vec![Policy {
            entries: vec![permit_all(mods_a)],
            default_action: PolicyAction::Deny,
        }]),
    ));

    // First-match-wins: the guarded statement shadows the
    // unconditional one when it matches.
    let mut guarded = base(PolicyAction::Permit);
    guarded.match_local_pref_ge = Some(100);
    guarded.modifications = RouteModifications {
        set_med: Some(1),
        ..RouteModifications::default()
    };
    let mut fallback = base(PolicyAction::Permit);
    fallback.modifications = RouteModifications {
        set_med: Some(2),
        ..RouteModifications::default()
    };
    chains.push((
        "first_match_wins".to_string(),
        PolicyChain::from_named(vec![named(
            "ordered",
            Policy {
                entries: vec![guarded, fallback],
                default_action: PolicyAction::Deny,
            },
        )]),
    ));

    // Mixed set/regex chain: community-set policy then regex policy.
    let mut set_stmt = base(PolicyAction::Permit);
    set_stmt.match_community = vec![
        CommunityMatch::Standard {
            value: (65001 << 16) | 0x64,
        },
        CommunityMatch::Standard {
            value: (65001 << 16) | 0xC8,
        },
    ];
    let mut regex_stmt = base(PolicyAction::Permit);
    regex_stmt.match_as_path = Some(AsPathRegex::new("_65100_").unwrap());
    chains.push((
        "set_then_regex".to_string(),
        PolicyChain::from_named(vec![
            named(
                "sets",
                Policy {
                    entries: vec![set_stmt],
                    default_action: PolicyAction::Deny,
                },
            ),
            named(
                "paths",
                Policy {
                    entries: vec![regex_stmt],
                    default_action: PolicyAction::Deny,
                },
            ),
        ]),
    ));

    chains
}

#[test]
fn golden_corpus_ir_matches_legacy() {
    let backing = Backing::new();
    let contexts = contexts(&backing);

    let mut chains = generated_chains();
    chains.extend(composed_chains());

    let mut cases = 0usize;
    for (chain_name, chain) in &chains {
        // requires_* parity: legacy field scan vs IR analysis.
        let legacy_regex = chain
            .policies
            .iter()
            .any(|np| np.entries.iter().any(|e| e.match_as_path.is_some()));
        let legacy_rpki = chain
            .policies
            .iter()
            .any(|np| np.entries.iter().any(|e| e.match_rpki_validation.is_some()));
        let legacy_aspa = chain
            .policies
            .iter()
            .any(|np| np.entries.iter().any(|e| e.match_aspa_validation.is_some()));
        assert_eq!(
            chain.requires_as_path_string(),
            legacy_regex,
            "requires_as_path_string diverges on {chain_name}"
        );
        assert_eq!(
            chain.requires_rpki_validation(),
            legacy_rpki,
            "requires_rpki_validation diverges on {chain_name}"
        );
        assert_eq!(
            chain.requires_aspa_validation(),
            legacy_aspa,
            "requires_aspa_validation diverges on {chain_name}"
        );
        assert_eq!(
            chain.requires_validation_state(),
            legacy_rpki || legacy_aspa,
            "requires_validation_state diverges on {chain_name}"
        );

        for (ctx_name, route) in &contexts {
            let legacy = chain.evaluate_with_attribution_legacy(route);
            let ir = chain.evaluate_with_attribution(route);
            assert_eq!(
                legacy, ir,
                "IR/legacy divergence: chain={chain_name} ctx={ctx_name}"
            );
            cases += 1;
        }
    }

    // 42 variants × 2 actions × 2 defaults × 2 mods + composed, × 13
    // contexts. Guard against the corpus silently shrinking.
    assert!(cases >= 4000, "corpus shrank to {cases} cases");
}

/// `None`-chain contract: implicit permit with no attribution, on both
/// free functions.
#[test]
fn none_chain_is_implicit_permit() {
    let route = blank_ctx();
    let (result, eval) = evaluate_chain_with_attribution(None, &route);
    assert_eq!(result, PolicyResult::permit());
    assert_eq!(eval.action, PolicyAction::Permit);
    assert_eq!(eval.matched_policy, None);
    assert_eq!(
        super::super::evaluate_chain(None, &route),
        PolicyResult::permit()
    );
}
