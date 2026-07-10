//! Statement-level chain attribution (`engine::explain`).
//!
//! Two layers of coverage:
//! 1. Per-statement-kind rendering: each match-condition kind and each
//!    modification kind produces its stable `"<label> <detail>"` form.
//! 2. Agreement: over a matrix of chains × route contexts the
//!    explain-only walk must reach the same terminal action and the
//!    same terminal policy as `evaluate_chain_with_attribution` — the
//!    same discipline that pins the RIB-side tiebreaker-explain ladder
//!    to the live comparator.

use std::net::{IpAddr, Ipv4Addr};

use super::super::explain::explain_chain_statements;
use super::*;

fn named(name: &str, policy: Policy) -> NamedPolicy {
    NamedPolicy {
        name: Some(name.to_string()),
        policy,
        rpol: None,
    }
}

fn policy(entries: Vec<PolicyStatement>, default_action: PolicyAction) -> Policy {
    Policy {
        entries,
        default_action,
    }
}

#[test]
fn no_chain_is_permit_with_no_steps() {
    let trace = explain_chain_statements(None, &plain_ctx(v4_prefix([10, 0, 0, 0], 24)));
    assert_eq!(trace.action, PolicyAction::Permit);
    assert!(trace.steps.is_empty());
}

#[test]
fn empty_chain_is_permit_with_no_steps() {
    let chain = PolicyChain::default();
    let trace = explain_chain_statements(Some(&chain), &plain_ctx(v4_prefix([10, 0, 0, 0], 24)));
    assert_eq!(trace.action, PolicyAction::Permit);
    assert!(trace.steps.is_empty());
}

fn plain_ctx(prefix: Prefix) -> RouteContext<'static> {
    RouteContext {
        prefix: Some(prefix),
        next_hop: None,
        extended_communities: &[],
        communities: &[],
        large_communities: &[],
        as_path_str: "",
        as_path_len: 0,
        origin_asn: None,
        validation_state: RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        peer_address: None,
        peer_asn: None,
        peer_group: None,
        route_type: None,
        evpn_route_type: None,
        local_pref: None,
        med: None,
    }
}

#[test]
fn prefix_match_attributes_statement_and_renders_bounds() {
    let mut wide = stmt(
        Some(v4_entry([10, 0, 0, 0], 8)),
        PolicyAction::Permit,
        vec![],
    );
    wide.ge = Some(16);
    wide.le = Some(24);
    // A non-matching statement first, so the index is meaningful.
    let miss = stmt(
        Some(v4_entry([192, 0, 2, 0], 24)),
        PolicyAction::Deny,
        vec![],
    );
    let chain = PolicyChain::from_named(vec![named(
        "pfx",
        policy(vec![miss, wide], PolicyAction::Deny),
    )]);
    let trace = explain_chain_statements(Some(&chain), &plain_ctx(v4_prefix([10, 1, 0, 0], 16)));
    assert_eq!(trace.action, PolicyAction::Permit);
    assert_eq!(trace.steps.len(), 1);
    let step = &trace.steps[0];
    assert_eq!(step.policy_index, 0);
    assert_eq!(step.policy_name.as_deref(), Some("pfx"));
    assert_eq!(step.statement_index, Some(1));
    assert_eq!(step.action, PolicyAction::Permit);
    assert_eq!(
        step.matched_conditions,
        vec!["prefix 10.0.0.0/8 ge 16 le 24".to_string()]
    );
    assert!(step.modifications.is_empty());
}

#[test]
fn community_match_reports_the_matched_criterion() {
    // OR-list of two criteria; the route carries only the second.
    let statement = stmt(
        None,
        PolicyAction::Permit,
        vec![
            CommunityMatch::Standard {
                value: (65001 << 16) | 0x0064,
            },
            CommunityMatch::Standard {
                value: (65001 << 16) | 0x00c8,
            },
        ],
    );
    let chain = PolicyChain::from_named(vec![named(
        "comm",
        policy(vec![statement], PolicyAction::Deny),
    )]);
    let communities = [(65001 << 16) | 0x00c8_u32];
    let mut ctx = plain_ctx(v4_prefix([10, 0, 0, 0], 24));
    ctx.communities = &communities;
    let trace = explain_chain_statements(Some(&chain), &ctx);
    assert_eq!(
        trace.steps[0].matched_conditions,
        vec!["community 65001:200"]
    );
}

#[test]
fn as_path_regex_match_renders_the_configured_pattern() {
    let mut statement = stmt(None, PolicyAction::Deny, vec![]);
    statement.match_as_path = Some(AsPathRegex::new("_65010_").unwrap());
    let chain = PolicyChain::from_named(vec![named(
        "rgx",
        policy(vec![statement], PolicyAction::Permit),
    )]);
    let mut ctx = plain_ctx(v4_prefix([10, 0, 0, 0], 24));
    ctx.as_path_str = "65001 65010 65002";
    ctx.as_path_len = 3;
    let trace = explain_chain_statements(Some(&chain), &ctx);
    assert_eq!(trace.action, PolicyAction::Deny);
    let step = &trace.steps[0];
    assert_eq!(step.statement_index, Some(0));
    assert_eq!(step.action, PolicyAction::Deny);
    assert_eq!(step.matched_conditions, vec!["as_path ~ \"_65010_\""]);
}

#[test]
fn scalar_and_validation_conditions_render_stable_labels() {
    let mut statement = stmt(None, PolicyAction::Permit, vec![]);
    statement.match_route_type = Some(RouteType::External);
    statement.match_rpki_validation = Some(RpkiValidation::Valid);
    statement.match_as_path_length_ge = Some(2);
    statement.match_local_pref_le = Some(300);
    statement.match_med_ge = Some(0);
    statement.match_next_hop = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    let chain = PolicyChain::from_named(vec![named(
        "scalars",
        policy(vec![statement], PolicyAction::Deny),
    )]);
    let mut ctx = plain_ctx(v4_prefix([10, 0, 0, 0], 24));
    ctx.route_type = Some(RouteType::External);
    ctx.validation_state = RpkiValidation::Valid;
    ctx.as_path_len = 3;
    ctx.local_pref = Some(250);
    ctx.med = Some(10);
    ctx.next_hop = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    let trace = explain_chain_statements(Some(&chain), &ctx);
    assert_eq!(
        trace.steps[0].matched_conditions,
        vec![
            "route_type external",
            "rpki valid",
            "as_path_len >= 2",
            "local_pref <= 300",
            "med >= 0",
            "next_hop 192.0.2.1",
        ]
    );
}

#[test]
fn neighbor_set_condition_reports_the_admitting_member_kind() {
    let mut statement = stmt(None, PolicyAction::Permit, vec![]);
    statement.match_neighbor_set = Some(NeighborSetMatch {
        addresses: vec![],
        remote_asns: vec![65002],
        peer_groups: vec!["spines".to_string()],
    });
    let chain = PolicyChain::from_named(vec![named(
        "nbr",
        policy(vec![statement], PolicyAction::Deny),
    )]);
    let mut ctx = plain_ctx(v4_prefix([10, 0, 0, 0], 24));
    ctx.peer_asn = Some(65002);
    ctx.peer_group = Some("spines");
    let trace = explain_chain_statements(Some(&chain), &ctx);
    // ASN is checked before group, mirroring NeighborSetMatch::matches.
    assert_eq!(
        trace.steps[0].matched_conditions,
        vec!["neighbor_set asn 65002"]
    );
}

#[test]
fn unconditional_statement_renders_any() {
    let chain = PolicyChain::from_named(vec![named(
        "open",
        policy(
            vec![stmt(None, PolicyAction::Permit, vec![])],
            PolicyAction::Deny,
        ),
    )]);
    let trace = explain_chain_statements(Some(&chain), &plain_ctx(v4_prefix([10, 0, 0, 0], 24)));
    assert_eq!(trace.steps[0].matched_conditions, vec!["any"]);
}

#[test]
fn default_action_fallthrough_names_the_policy_with_no_statement() {
    let chain = PolicyChain::from_named(vec![named(
        "guard",
        policy(
            vec![stmt(
                Some(v4_entry([192, 0, 2, 0], 24)),
                PolicyAction::Permit,
                vec![],
            )],
            PolicyAction::Deny,
        ),
    )]);
    let trace = explain_chain_statements(Some(&chain), &plain_ctx(v4_prefix([10, 0, 0, 0], 24)));
    assert_eq!(trace.action, PolicyAction::Deny);
    let step = &trace.steps[0];
    assert_eq!(step.policy_name.as_deref(), Some("guard"));
    assert_eq!(step.statement_index, None, "fallthrough has no statement");
    assert_eq!(step.action, PolicyAction::Deny);
    assert!(step.matched_conditions.is_empty());
    assert!(step.modifications.is_empty());
}

#[test]
fn deny_stops_the_walk_and_later_policies_get_no_step() {
    let permit_all = policy(
        vec![stmt(None, PolicyAction::Permit, vec![])],
        PolicyAction::Deny,
    );
    let deny_all = policy(
        vec![stmt(None, PolicyAction::Deny, vec![])],
        PolicyAction::Permit,
    );
    let never_reached = policy(
        vec![stmt(None, PolicyAction::Permit, vec![])],
        PolicyAction::Permit,
    );
    let chain = PolicyChain::from_named(vec![
        named("first", permit_all),
        named("blocker", deny_all),
        named("after", never_reached),
    ]);
    let trace = explain_chain_statements(Some(&chain), &plain_ctx(v4_prefix([10, 0, 0, 0], 24)));
    assert_eq!(trace.action, PolicyAction::Deny);
    assert_eq!(trace.steps.len(), 2, "walk stops at the denying policy");
    assert_eq!(trace.steps[0].policy_name.as_deref(), Some("first"));
    assert_eq!(trace.steps[1].policy_name.as_deref(), Some("blocker"));
    assert_eq!(trace.steps[1].policy_index, 1);
    assert_eq!(trace.steps[1].statement_index, Some(0));
}

#[test]
fn deny_statement_never_claims_modifications() {
    // Live-path parity: a Deny terminator drops its set clauses
    // (`PolicyResult::deny()`), so the trace must not render them.
    let mut denying = stmt(None, PolicyAction::Deny, vec![]);
    denying.modifications = RouteModifications {
        set_local_pref: Some(200),
        ..Default::default()
    };
    let chain = PolicyChain::from_named(vec![named(
        "blocker",
        policy(vec![denying], PolicyAction::Permit),
    )]);
    let trace = explain_chain_statements(Some(&chain), &plain_ctx(v4_prefix([10, 0, 0, 0], 24)));
    assert_eq!(trace.action, PolicyAction::Deny);
    assert_eq!(trace.steps.len(), 1);
    assert_eq!(trace.steps[0].statement_index, Some(0));
    assert!(
        trace.steps[0].modifications.is_empty(),
        "denying statement must not claim attribute edits: {:?}",
        trace.steps[0].modifications
    );
}

#[test]
fn modifications_render_before_and_after_from_pre_policy_values() {
    let mut statement = stmt(None, PolicyAction::Permit, vec![]);
    statement.modifications = RouteModifications {
        set_local_pref: Some(200),
        set_med: Some(50),
        set_next_hop: Some(NextHopAction::Specific(IpAddr::V4(Ipv4Addr::new(
            203, 0, 113, 9,
        )))),
        communities_add: vec![(65001 << 16) | 0x029a],
        communities_remove: vec![(65001 << 16) | 0x0064],
        as_path_prepend: Some((65001, 3)),
        ..RouteModifications::default()
    };
    let chain = PolicyChain::from_named(vec![named(
        "mods",
        policy(vec![statement], PolicyAction::Deny),
    )]);
    let mut ctx = plain_ctx(v4_prefix([10, 0, 0, 0], 24));
    ctx.next_hop = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)));
    ctx.med = Some(10);
    // local_pref is absent on the wire: the rendered "before" is the
    // RFC 4271 implicit 100, matching the engine's match semantics.
    let trace = explain_chain_statements(Some(&chain), &ctx);
    assert_eq!(
        trace.steps[0].modifications,
        vec![
            "local_pref 100 -> 200",
            "med 10 -> 50",
            "next_hop 192.0.2.7 -> 203.0.113.9",
            "community + 65001:666",
            "community - 65001:100",
            "as_path prepend 65001 x3",
        ]
    );
}

#[test]
fn next_hop_self_renders_self_keyword() {
    let mut statement = stmt(None, PolicyAction::Permit, vec![]);
    statement.modifications = RouteModifications {
        set_next_hop: Some(NextHopAction::Self_),
        ..RouteModifications::default()
    };
    let chain = PolicyChain::from_named(vec![named(
        "nhs",
        policy(vec![statement], PolicyAction::Deny),
    )]);
    let trace = explain_chain_statements(Some(&chain), &plain_ctx(v4_prefix([10, 0, 0, 0], 24)));
    assert_eq!(trace.steps[0].modifications, vec!["next_hop none -> self"]);
}

#[test]
fn multi_policy_permit_attributes_each_policy_step() {
    let lp = {
        let mut s = stmt(None, PolicyAction::Permit, vec![]);
        s.modifications = RouteModifications {
            set_local_pref: Some(200),
            ..RouteModifications::default()
        };
        policy(vec![s], PolicyAction::Deny)
    };
    let med = {
        let mut s = stmt(None, PolicyAction::Permit, vec![]);
        s.modifications = RouteModifications {
            set_med: Some(5),
            ..RouteModifications::default()
        };
        policy(vec![s], PolicyAction::Deny)
    };
    let chain = PolicyChain::from_named(vec![named("lp-bump", lp), named("med-set", med)]);
    let trace = explain_chain_statements(Some(&chain), &plain_ctx(v4_prefix([10, 0, 0, 0], 24)));
    assert_eq!(trace.action, PolicyAction::Permit);
    assert_eq!(trace.steps.len(), 2);
    assert_eq!(trace.steps[0].policy_name.as_deref(), Some("lp-bump"));
    assert_eq!(trace.steps[0].modifications, vec!["local_pref 100 -> 200"]);
    assert_eq!(trace.steps[1].policy_name.as_deref(), Some("med-set"));
    assert_eq!(trace.steps[1].modifications, vec!["med 0 -> 5"]);
}

// ---------------------------------------------------------------------
// Agreement: the explain-only walk vs the live evaluator.
// ---------------------------------------------------------------------

/// Build the matrix of chains the agreement test sweeps. Names double
/// as documentation of the case.
fn agreement_chains() -> Vec<(&'static str, PolicyChain)> {
    let prefix_permit = || {
        policy(
            vec![stmt(
                Some(v4_entry([10, 0, 0, 0], 8)),
                PolicyAction::Permit,
                vec![],
            )],
            PolicyAction::Deny,
        )
    };
    let prefix_deny = || {
        policy(
            vec![stmt(
                Some(v4_entry([10, 0, 0, 0], 8)),
                PolicyAction::Deny,
                vec![],
            )],
            PolicyAction::Permit,
        )
    };
    let community_gate = || {
        policy(
            vec![stmt(
                None,
                PolicyAction::Permit,
                vec![CommunityMatch::Standard {
                    value: (65001 << 16) | 0x0064,
                }],
            )],
            PolicyAction::Deny,
        )
    };
    let regex_block = || {
        let mut s = stmt(None, PolicyAction::Deny, vec![]);
        s.match_as_path = Some(AsPathRegex::new("_65010_").unwrap());
        policy(vec![s], PolicyAction::Permit)
    };
    let lp_mod = || {
        let mut s = stmt(None, PolicyAction::Permit, vec![]);
        s.modifications = RouteModifications {
            set_local_pref: Some(200),
            communities_add: vec![(65001 << 16) | 0x029a],
            ..RouteModifications::default()
        };
        policy(vec![s], PolicyAction::Deny)
    };

    vec![
        ("empty", PolicyChain::default()),
        (
            "single_prefix_permit",
            PolicyChain::from_named(vec![named("p", prefix_permit())]),
        ),
        (
            "single_prefix_deny",
            PolicyChain::from_named(vec![named("d", prefix_deny())]),
        ),
        (
            "community_gate",
            PolicyChain::from_named(vec![named("c", community_gate())]),
        ),
        (
            "regex_block_then_mods",
            PolicyChain::from_named(vec![named("rgx", regex_block()), named("lp", lp_mod())]),
        ),
        (
            "mods_then_prefix_deny",
            PolicyChain::from_named(vec![named("lp", lp_mod()), named("d", prefix_deny())]),
        ),
        (
            "anonymous_terminal",
            PolicyChain::from_named(vec![named("lp", lp_mod()), prefix_permit().into()]),
        ),
    ]
}

/// Route contexts the agreement matrix sweeps the chains against.
fn agreement_contexts() -> Vec<(&'static str, RouteContext<'static>)> {
    const COMMUNITIES: &[u32] = &[(65001 << 16) | 0x0064];

    let inside = plain_ctx(v4_prefix([10, 2, 3, 0], 24));
    let outside = plain_ctx(v4_prefix([192, 0, 2, 0], 24));
    let mut tagged = plain_ctx(v4_prefix([10, 9, 0, 0], 16));
    tagged.communities = COMMUNITIES;
    let mut bad_path = plain_ctx(v4_prefix([10, 5, 0, 0], 16));
    bad_path.as_path_str = "65001 65010";
    bad_path.as_path_len = 2;

    vec![
        ("inside_prefix", inside),
        ("outside_prefix", outside),
        ("community_tagged", tagged),
        ("as65010_path", bad_path),
    ]
}

/// The load-bearing pin: over the full chain × context matrix the
/// explain-only statement walk must reach the same terminal action as
/// `evaluate_chain_with_attribution`, and its last step must name the
/// same terminal policy `PolicyEvaluation.matched_policy` reports.
#[test]
fn statement_trace_agrees_with_live_evaluation_across_matrix() {
    for (chain_name, chain) in agreement_chains() {
        for (ctx_name, ctx) in agreement_contexts() {
            let (live, evaluation) =
                super::super::evaluate_chain_with_attribution(Some(&chain), &ctx);
            let trace = explain_chain_statements(Some(&chain), &ctx);
            assert_eq!(
                trace.action, live.action,
                "action diverged for chain={chain_name} ctx={ctx_name}"
            );
            assert_eq!(
                trace.action, evaluation.action,
                "attribution action diverged for chain={chain_name} ctx={ctx_name}"
            );
            // Terminal-policy agreement. For an empty chain both sides
            // report nothing; otherwise the last step is the policy the
            // live evaluator attributes the decision to.
            match trace.steps.last() {
                Some(last) => assert_eq!(
                    last.policy_name, evaluation.matched_policy,
                    "terminal policy diverged for chain={chain_name} ctx={ctx_name}"
                ),
                None => assert_eq!(
                    evaluation.matched_policy, None,
                    "live evaluator attributed an empty trace for chain={chain_name} ctx={ctx_name}"
                ),
            }
            // Every step before the terminal one must be a Permit —
            // the walk only continues past a permitting policy.
            for step in &trace.steps[..trace.steps.len().saturating_sub(1)] {
                assert_eq!(
                    step.action,
                    PolicyAction::Permit,
                    "non-terminal step was not a permit for chain={chain_name} ctx={ctx_name}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------
// `.rpol` members (ADR-0096): per-term traces + agreement.
// ---------------------------------------------------------------------

const RPOL: &str = r"
prefix-set customers { 10.10.0.0/16 ge 24 le 28 }

policy customer-in(peer_lp: u32) {
    term rpki-guard {
        if route.rpki == invalid { reject }
    }
    term tag {
        set med 5;
    }
    term customer-routes {
        if route.prefix in customers { set local-pref peer_lp; accept }
    }
}
";

fn rpol_member(lp: u32) -> NamedPolicy {
    let file = crate::rpol::RpolFile::parse(RPOL).expect("clean rpol");
    let mut store = crate::sets::SetStore::new();
    let compiled = file
        .compile_policy("customer-in", &[lp], &mut store)
        .expect("policy exists");
    NamedPolicy::from_rpol(format!("customer-in({lp})"), std::sync::Arc::new(compiled))
}

#[test]
fn rpol_member_traces_terms_with_matched_status_and_merged_mods() {
    let chain = PolicyChain::from_named(vec![rpol_member(200)]);
    // A customer route: rpki-guard misses, tag continues, customer-routes decides.
    let trace = explain_chain_statements(Some(&chain), &plain_ctx(v4_prefix([10, 10, 3, 0], 24)));
    assert_eq!(trace.action, PolicyAction::Permit);
    assert_eq!(trace.steps.len(), 1);
    let step = &trace.steps[0];
    assert_eq!(step.policy_name.as_deref(), Some("customer-in(200)"));
    assert_eq!(step.statement_index, Some(2));
    assert_eq!(step.term_name.as_deref(), Some("customer-routes"));
    assert_eq!(step.action, PolicyAction::Permit);
    assert_eq!(
        step.matched_conditions,
        vec!["guard route.prefix in customers".to_string()]
    );
    // Continue mods merge under the deciding permit, rendered
    // before -> after against the pre-policy route.
    assert_eq!(
        step.modifications,
        vec![
            "local_pref 100 -> 200".to_string(),
            "med 0 -> 5".to_string()
        ]
    );
    assert_eq!(
        step.term_traces,
        vec![
            "term rpki-guard: route.rpki == invalid => reject [not matched]".to_string(),
            "term tag: true => set med 5; continue [matched]".to_string(),
            "term customer-routes: route.prefix in customers => set local-pref 200; accept [matched]"
                .to_string(),
        ]
    );
}

#[test]
fn rpol_deny_term_stops_the_walk_and_claims_no_modifications() {
    let chain = PolicyChain::from_named(vec![rpol_member(200)]);
    let mut invalid = plain_ctx(v4_prefix([10, 10, 3, 0], 24));
    invalid.validation_state = RpkiValidation::Invalid;
    let trace = explain_chain_statements(Some(&chain), &invalid);
    assert_eq!(trace.action, PolicyAction::Deny);
    let step = &trace.steps[0];
    assert_eq!(step.statement_index, Some(0));
    assert_eq!(step.term_name.as_deref(), Some("rpki-guard"));
    assert_eq!(step.action, PolicyAction::Deny);
    assert!(step.modifications.is_empty(), "a deny contributes nothing");
    // Terms after the decider were never evaluated: one trace line.
    assert_eq!(
        step.term_traces,
        vec!["term rpki-guard: route.rpki == invalid => reject [matched]".to_string()]
    );
}

#[test]
fn rpol_fallthrough_keeps_continue_mods_under_the_permit_default() {
    let chain = PolicyChain::from_named(vec![rpol_member(200)]);
    // Not a customer prefix: rpki-guard and customer-routes miss, tag
    // continues, the policy's implicit permit default decides.
    let trace = explain_chain_statements(Some(&chain), &plain_ctx(v4_prefix([192, 0, 2, 0], 24)));
    assert_eq!(trace.action, PolicyAction::Permit);
    let step = &trace.steps[0];
    assert_eq!(step.statement_index, None, "fallthrough has no term");
    assert_eq!(step.term_name, None);
    assert_eq!(step.action, PolicyAction::Permit);
    assert!(step.matched_conditions.is_empty());
    assert_eq!(step.modifications, vec!["med 0 -> 5".to_string()]);
    assert_eq!(step.term_traces.len(), 3, "every term was evaluated");
    assert!(step.term_traces[2].ends_with("[not matched]"));
}

/// The rpol agreement matrix: mixed TOML + rpol chains, contexts that
/// exercise deny terms, Continue accumulation, and fallthrough.
fn rpol_agreement_chains() -> Vec<(&'static str, PolicyChain)> {
    let toml_deny = || {
        named(
            "toml-deny",
            policy(
                vec![stmt(
                    Some(v4_entry([192, 0, 2, 0], 24)),
                    PolicyAction::Deny,
                    vec![],
                )],
                PolicyAction::Permit,
            ),
        )
    };
    vec![
        ("rpol_only", PolicyChain::from_named(vec![rpol_member(200)])),
        (
            "toml_then_rpol",
            PolicyChain::from_named(vec![toml_deny(), rpol_member(300)]),
        ),
        (
            "rpol_then_toml",
            PolicyChain::from_named(vec![rpol_member(200), toml_deny()]),
        ),
    ]
}

fn rpol_agreement_contexts() -> Vec<(&'static str, RouteContext<'static>)> {
    let customer = plain_ctx(v4_prefix([10, 10, 3, 0], 24));
    let mut invalid = plain_ctx(v4_prefix([10, 10, 4, 0], 24));
    invalid.validation_state = RpkiValidation::Invalid;
    let toml_blocked = plain_ctx(v4_prefix([192, 0, 2, 0], 24));
    let fallthrough = plain_ctx(v4_prefix([203, 0, 113, 0], 24));
    vec![
        ("customer", customer),
        ("rpki_invalid", invalid),
        ("toml_blocked", toml_blocked),
        ("fallthrough", fallthrough),
    ]
}

/// The rpol extension of the agreement pin: over the rpol chain ×
/// context matrix the trace must reach the live evaluator's terminal
/// action / policy, its per-policy modifications must reproduce the
/// live result's accumulated modifications (Continue-merge parity),
/// and its matched-term view must equal `evaluate_recording_hits`'
/// counted guards term by term.
#[test]
fn rpol_statement_trace_agrees_with_live_evaluation_and_recorded_hits() {
    for (chain_name, chain) in rpol_agreement_chains() {
        for (ctx_name, ctx) in rpol_agreement_contexts() {
            let (live, evaluation) =
                super::super::evaluate_chain_with_attribution(Some(&chain), &ctx);
            let trace = explain_chain_statements(Some(&chain), &ctx);
            assert_eq!(
                trace.action, live.action,
                "action diverged for chain={chain_name} ctx={ctx_name}"
            );
            let last = trace.steps.last().expect("non-empty chains");
            assert_eq!(
                last.policy_name, evaluation.matched_policy,
                "terminal policy diverged for chain={chain_name} ctx={ctx_name}"
            );

            // Matched-term parity with the counting evaluator: a term
            // counted a hit iff its trace line says [matched], and
            // terms past the trace were never evaluated.
            let compiled = chain.compiled();
            let mut hits = compiled.zero_term_hits();
            let recorded = compiled.evaluate_recording_hits(&ctx, &mut hits);
            assert_eq!(recorded, live, "recording eval diverged");
            for step in &trace.steps {
                if step.term_traces.is_empty() {
                    continue; // TOML member: no per-term trace.
                }
                let policy_hits = &hits[step.policy_index];
                for (index, line) in step.term_traces.iter().enumerate() {
                    let expected = u64::from(line.ends_with("[matched]"));
                    assert_eq!(
                        policy_hits[index], expected,
                        "term hit diverged for chain={chain_name} ctx={ctx_name} \
                         policy={:?} line={line:?}",
                        step.policy_name
                    );
                }
                for (index, hit) in policy_hits.iter().enumerate().skip(step.term_traces.len()) {
                    assert_eq!(
                        *hit, 0,
                        "unevaluated term counted a hit for chain={chain_name} \
                         ctx={ctx_name} term_index={index}"
                    );
                }
                // The deciding term (when there is one) is the last
                // matched line — the matched-term invariant.
                if let Some(decider) = step.statement_index {
                    assert!(
                        step.term_traces[decider].ends_with("[matched]"),
                        "decider not matched for chain={chain_name} ctx={ctx_name}"
                    );
                    assert_eq!(
                        decider + 1,
                        step.term_traces.len(),
                        "walk continued past the decider for chain={chain_name} ctx={ctx_name}"
                    );
                }
            }
        }
    }
}
