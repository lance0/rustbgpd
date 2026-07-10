//! End-to-end `.rpol` frontend tests: compile → IR shape goldens,
//! evaluation through the real IR evaluator, every diagnostic path
//! (with rendering assertions), and the in-language test runner.

use std::net::Ipv4Addr;

use rustbgpd_wire::{Ipv4Prefix, Prefix, RpkiValidation};

use crate::engine::{PolicyAction, RouteContext, RouteModifications};
use crate::ir::{Cmp, MatchExpr, PolicySource, SetId, TermAction};
use crate::sets::SetStore;

use super::{TestReport, check_rpol, compile_rpol, run_rpol_tests};

const ADR_EXAMPLE: &str = r"
prefix-set customers { 10.10.0.0/16 ge 24 le 28, 192.0.2.0/24 }
community-set tagged { 65000:100, 65000:200 }

policy bogon-filter {
    term bogons {
        if route.prefix == 0.0.0.0/8 || route.prefix == 127.0.0.0/8 { accept }
    }
    term everything-else { reject }
}

policy customer-in(peer_lp: u32) {
    term rpki-guard {
        if route.rpki == invalid { reject }
    }
    term customer-routes {
        if route.prefix in customers && route.communities has 65000:100 {
            set local-pref peer_lp;
            add community 65001:999;
            accept
        }
    }
    term bogon-guard { if apply(bogon-filter) { reject } }
}

test customer-in-accepts-tagged {
    route { prefix 10.10.1.0/24; communities [65000:100]; rpki valid }
    expect customer-in(200) == accept with local-pref 200, community 65001:999
}

test customer-in-rejects-rpki-invalid {
    route { prefix 10.10.1.0/24; communities [65000:100]; rpki invalid }
    expect customer-in(200) == reject
}

test bogons-rejected {
    route { prefix 127.0.0.0/8 }
    expect customer-in(200) == reject
}
";

fn route_ctx(prefix: Prefix, communities: &[u32], rpki: RpkiValidation) -> RouteContext<'static> {
    RouteContext {
        prefix: Some(prefix),
        next_hop: None,
        extended_communities: &[],
        communities: Box::leak(communities.to_vec().into_boxed_slice()),
        large_communities: &[],
        as_path_str: "",
        as_path: None,
        as_path_len: 0,
        origin_asn: None,
        validation_state: rpki,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        peer_address: None,
        peer_asn: None,
        peer_group: None,
        route_type: None,
        family: None,
        evpn_route_type: None,
        local_pref: None,
        med: None,
    }
}

fn v4(a: u8, b: u8, c: u8, d: u8, len: u8) -> Prefix {
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(a, b, c, d), len))
}

fn compile_ok(source: &str) -> crate::ir::CompiledChain {
    let mut store = SetStore::new();
    match compile_rpol(source, &mut store) {
        Ok(chain) => chain,
        Err(diags) => panic!("{}", diags.render("test.rpol", source, false)),
    }
}

fn diagnostics_of(source: &str) -> (super::Diagnostics, String) {
    let mut store = SetStore::new();
    let diags = compile_rpol(source, &mut store).expect_err("expected diagnostics");
    let rendered = diags.render("test.rpol", source, false);
    (diags, rendered)
}

// ── compile + IR shape goldens ─────────────────────────────────────

#[test]
fn adr_example_compiles_zero_param_policies_only() {
    let chain = compile_ok(ADR_EXAMPLE);
    // `customer-in` takes a parameter → template only; `bogon-filter`
    // is the sole zero-param policy in the chain.
    assert_eq!(chain.policies.len(), 1);
    let bogon = &chain.policies[0];
    assert_eq!(bogon.name.as_deref(), Some("bogon-filter"));
    assert_eq!(bogon.source, PolicySource::Rpol);
    assert_eq!(bogon.default_action, PolicyAction::Permit);
    assert_eq!(bogon.terms.len(), 2);
    assert_eq!(bogon.terms[0].name.as_deref(), Some("bogons"));
    assert!(matches!(bogon.terms[0].guard, MatchExpr::Or(_)));
    assert!(matches!(bogon.terms[0].action, TermAction::Permit(_)));
    assert_eq!(bogon.terms[1].name.as_deref(), Some("everything-else"));
    assert_eq!(bogon.terms[1].guard, MatchExpr::True);
    assert_eq!(bogon.terms[1].action, TermAction::Deny);
    // Set tables carry both defined sets even though only `customers`
    // is referenced by a zero-param policy.
    assert_eq!(chain.prefix_sets.len(), 1);
    assert_eq!(chain.community_sets.len(), 1);
}

#[test]
fn set_membership_lowers_to_indexed_sets() {
    let chain = compile_ok(
        "prefix-set customers { 10.10.0.0/16 ge 24 le 28 }
         policy p {
             term t { if route.prefix in customers { accept } }
         }",
    );
    let term = &chain.policies[0].terms[0];
    assert_eq!(term.guard, MatchExpr::PrefixInSet(SetId(0)));
    assert!(chain.prefix_sets[0].matches(v4(10, 10, 3, 0, 24)));
    assert!(!chain.prefix_sets[0].matches(v4(10, 10, 3, 0, 30)));
}

#[test]
fn u32_equality_lowers_to_ge_and_le() {
    let chain = compile_ok("policy p { term t { if route.med == 50 { reject } } }");
    assert_eq!(
        chain.policies[0].terms[0].guard,
        MatchExpr::And(vec![
            MatchExpr::Med(Cmp::Ge(50)),
            MatchExpr::Med(Cmp::Le(50))
        ])
    );
}

#[test]
fn term_fallthrough_encoding() {
    // A bare modification run + an if with a verdictless body + a
    // final verdict term: exercises Continue flushing and `<term>.<n>`
    // naming.
    let chain = compile_ok(
        "policy p {
             term shape {
                 set med 10;
                 if route.local-pref >= 500 { add community 65000:1 }
             }
             term decide { accept }
         }",
    );
    let terms = &chain.policies[0].terms;
    assert_eq!(terms.len(), 3);
    assert_eq!(terms[0].name.as_deref(), Some("shape.1"));
    assert_eq!(terms[0].guard, MatchExpr::True);
    let TermAction::Continue(mods) = &terms[0].action else {
        panic!("bare mods flush as Continue, got {:?}", terms[0].action)
    };
    assert_eq!(mods.set_med, Some(10));
    assert_eq!(terms[1].name.as_deref(), Some("shape.2"));
    let TermAction::Continue(mods) = &terms[1].action else {
        panic!("verdictless if body is Continue, got {:?}", terms[1].action)
    };
    assert_eq!(mods.communities_add, vec![(65000 << 16) | 1]);
    assert_eq!(terms[2].name.as_deref(), Some("decide"));
    assert_eq!(
        terms[2].action,
        TermAction::Permit(RouteModifications::default())
    );

    // And the evaluator honors it: both Continue mods survive into the
    // accept.
    let ctx = RouteContext {
        local_pref: Some(600),
        ..route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound)
    };
    let result = chain.evaluate(&ctx);
    assert_eq!(result.action, PolicyAction::Permit);
    assert_eq!(result.modifications.set_med, Some(10));
    assert_eq!(
        result.modifications.communities_add,
        vec![(65000 << 16) | 1]
    );

    // Below the local-pref threshold only the unconditional mod applies.
    let ctx = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
    let result = chain.evaluate(&ctx);
    assert_eq!(result.modifications.set_med, Some(10));
    assert!(result.modifications.communities_add.is_empty());
}

#[test]
fn else_lowers_to_negated_guard() {
    let chain = compile_ok(
        "policy p {
             term t {
                 if route.rpki == valid { accept } else { reject }
             }
         }",
    );
    let terms = &chain.policies[0].terms;
    assert_eq!(terms.len(), 2);
    assert_eq!(terms[0].guard, MatchExpr::RpkiIs(RpkiValidation::Valid));
    assert!(matches!(terms[0].action, TermAction::Permit(_)));
    assert_eq!(
        terms[1].guard,
        MatchExpr::Not(Box::new(MatchExpr::RpkiIs(RpkiValidation::Valid)))
    );
    assert_eq!(terms[1].action, TermAction::Deny);
}

#[test]
fn apply_inlines_the_target_decision() {
    let chain = compile_ok(
        "policy inner {
             term a { if route.med <= 5 { accept } }
             term b { reject }
         }
         policy outer {
             term guard { if apply(inner) { reject } }
         }",
    );
    let outer = chain
        .policies
        .iter()
        .find(|p| p.name.as_deref() == Some("outer"))
        .expect("outer compiled");
    // inner accepts iff med <= 5 (default-permit arm is unreachable
    // behind the unconditional reject), so outer rejects exactly then.
    let low_med = RouteContext {
        med: Some(3),
        ..route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound)
    };
    let high_med = RouteContext {
        med: Some(50),
        ..route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound)
    };
    let single = crate::ir::CompiledChain {
        policies: vec![outer.clone()],
        ..chain.clone()
    };
    assert_eq!(single.evaluate(&low_med).action, PolicyAction::Deny);
    assert_eq!(single.evaluate(&high_med).action, PolicyAction::Permit);
}

#[test]
fn end_to_end_adr_example_evaluation() {
    let chain = compile_ok(ADR_EXAMPLE);
    // Evaluate `customer-in(200)` by instantiating through a test-run
    // equivalent: reuse run_rpol_tests which does exactly that.
    let report = run_rpol_tests(ADR_EXAMPLE).expect("compiles");
    assert_eq!(report.total, 3);
    assert!(
        report.all_passed(),
        "in-language tests failed: {:?}",
        report.failures
    );
    // The zero-param bogon-filter is directly evaluable too.
    let bogon_route = route_ctx(v4(127, 0, 0, 0, 8), &[], RpkiValidation::NotFound);
    assert_eq!(chain.evaluate(&bogon_route).action, PolicyAction::Permit);
    let normal = route_ctx(v4(8, 8, 8, 0, 24), &[], RpkiValidation::NotFound);
    assert_eq!(chain.evaluate(&normal).action, PolicyAction::Deny);
}

#[test]
fn as_path_and_peer_predicates_lower_and_evaluate() {
    let chain = compile_ok(
        r#"policy p {
             term long-paths { if route.as-path.len >= 3 && route.as-path contains 65001 { reject } }
             term from-leaf { if peer.group == "leaf" && route.as-path matches "^65010" { reject } }
             term rest { accept }
         }"#,
    );
    let base = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
    let long = RouteContext {
        as_path_str: "65005 65001 65002",
        as_path: None,
        as_path_len: 3,
        origin_asn: None,
        ..base
    };
    assert_eq!(chain.evaluate(&long).action, PolicyAction::Deny);
    let leaf = RouteContext {
        as_path_str: "65010 65011",
        as_path: None,
        as_path_len: 2,
        origin_asn: None,
        peer_group: Some("leaf"),
        ..base
    };
    assert_eq!(chain.evaluate(&leaf).action, PolicyAction::Deny);
    assert_eq!(chain.evaluate(&base).action, PolicyAction::Permit);
}

#[test]
fn modification_actions_lower_to_route_modifications() {
    let chain = compile_ok(
        "policy p {
             term t {
                 set next-hop self;
                 remove community NO_EXPORT;
                 add large-community 65000:1:2;
                 add ext-community RT:65001:100;
                 prepend as 65001 3;
                 accept
             }
         }",
    );
    let TermAction::Permit(mods) = &chain.policies[0].terms[0].action else {
        panic!("expected permit")
    };
    assert_eq!(mods.set_next_hop, Some(crate::engine::NextHopAction::Self_));
    assert_eq!(
        mods.communities_remove,
        vec![rustbgpd_wire::COMMUNITY_NO_EXPORT]
    );
    assert_eq!(mods.large_communities_add.len(), 1);
    assert_eq!(mods.as_path_prepend, Some((65001, 3)));
    // RT:65001:100 with a 2-octet ASN admin → type 0x00, subtype 0x02.
    let ec = mods.extended_communities_add[0];
    assert_eq!(ec.type_byte(), 0x00);
    assert_eq!(ec.route_target(), Some((65001, 100)));
}

// ── diagnostics (every error path asserts its rendering) ──────────

#[test]
fn unknown_set_suggests_and_renders() {
    let (diags, rendered) = diagnostics_of(
        "prefix-set customers { 10.0.0.0/8 }
         policy p { term t { if route.prefix in custmers { accept } } }",
    );
    assert_eq!(diags.len(), 1);
    assert!(
        rendered.contains("unknown prefix-set `custmers`"),
        "{rendered}"
    );
    assert!(
        rendered.contains("no prefix-set with this name"),
        "{rendered}"
    );
    assert!(rendered.contains("did you mean `customers`?"), "{rendered}");
}

#[test]
fn unknown_policy_in_apply_suggests() {
    let (_, rendered) = diagnostics_of(
        "policy bogon-filter { term t { reject } }
         policy p { term t { if apply(bogon-fitler) { reject } } }",
    );
    assert!(
        rendered.contains("unknown policy `bogon-fitler`"),
        "{rendered}"
    );
    assert!(
        rendered.contains("did you mean `bogon-filter`?"),
        "{rendered}"
    );
}

#[test]
fn suggestions_label_the_definition_site() {
    // LAN-328: the did-you-mean note carries a label at the
    // candidate's definition, so the rendering names its file:line.
    let (_, rendered) = diagnostics_of(
        "prefix-set customers { 10.0.0.0/8 }
         policy p { term t { if route.prefix in custmers { accept } } }",
    );
    assert!(rendered.contains("did you mean `customers`?"), "{rendered}");
    assert!(
        rendered.contains("`customers` is defined here"),
        "{rendered}"
    );

    let (_, rendered) = diagnostics_of(
        "policy bogon-filter { term t { reject } }
         policy p { term t { if apply(bogon-fitler) { reject } } }",
    );
    assert!(
        rendered.contains("`bogon-filter` is defined here"),
        "{rendered}"
    );
}

#[test]
fn unknown_community_set_suggests() {
    let (_, rendered) = diagnostics_of(
        "community-set scrub-tags { 65000:1 }
         policy p { term t { if route.communities in scrub-tagz { reject } } }",
    );
    assert!(
        rendered.contains("unknown community-set `scrub-tagz`"),
        "{rendered}"
    );
    assert!(
        rendered.contains("did you mean `scrub-tags`?"),
        "{rendered}"
    );
    assert!(
        rendered.contains("`scrub-tags` is defined here"),
        "{rendered}"
    );
}

#[test]
fn unknown_asn_set_suggests() {
    let (_, rendered) = diagnostics_of(
        "asn-set peers { 64500 }
         policy p { term t { if route.origin-as in peerz { accept } } }",
    );
    assert!(rendered.contains("unknown asn-set `peerz`"), "{rendered}");
    assert!(rendered.contains("did you mean `peers`?"), "{rendered}");
    assert!(rendered.contains("`peers` is defined here"), "{rendered}");
}

#[test]
fn unknown_fn_suggestion_labels_the_definition() {
    let (_, rendered) = diagnostics_of(
        "fn shift(a: u32) -> u32 { a + 1 }
         policy p { term t { if shitf(1) >= 2 { reject } } }",
    );
    assert!(rendered.contains("did you mean `shift`?"), "{rendered}");
    assert!(rendered.contains("`shift` is defined here"), "{rendered}");
}

#[test]
fn unknown_dataset_reference_suggests() {
    // A typo'd `in` probe near a declared dataset suggests the
    // dataset (LAN-328) — right-kind datasets are valid probe targets.
    let (_, rendered) = diagnostics_of(
        "dataset prefix-set bogons
         policy p { term t { if route.prefix in bogonz { reject } } }",
    );
    assert!(
        rendered.contains("unknown prefix-set `bogonz`"),
        "{rendered}"
    );
    assert!(rendered.contains("did you mean `bogons`?"), "{rendered}");
    assert!(rendered.contains("`bogons` is defined here"), "{rendered}");

    // Same for a test block's dataset override.
    let (_, rendered) = diagnostics_of(
        "dataset asn-set flappers
         policy p { term t { if route.origin-as in flappers { accept } } }
         test t { dataset flapperz { 64500 } route { prefix 10.0.0.0/8 } expect p == accept }",
    );
    assert!(
        rendered.contains("unknown dataset `flapperz`"),
        "{rendered}"
    );
    assert!(rendered.contains("did you mean `flappers`?"), "{rendered}");
    assert!(
        rendered.contains("`flappers` is defined here"),
        "{rendered}"
    );
}

#[test]
fn unknown_expect_policy_suggests() {
    let (_, rendered) = diagnostics_of(
        "policy guard { term t { reject } }
         test t { route { prefix 10.0.0.0/8 } expect gaurd == reject }",
    );
    assert!(rendered.contains("unknown policy `gaurd`"), "{rendered}");
    assert!(rendered.contains("did you mean `guard`?"), "{rendered}");
    assert!(rendered.contains("`guard` is defined here"), "{rendered}");
}

#[test]
fn no_suggestion_when_nothing_is_close() {
    let (_, rendered) = diagnostics_of(
        "prefix-set customers { 10.0.0.0/8 }
         policy p { term t { if route.prefix in zzz { accept } } }",
    );
    assert!(rendered.contains("unknown prefix-set `zzz`"), "{rendered}");
    assert!(!rendered.contains("did you mean"), "{rendered}");

    let (_, rendered) = diagnostics_of(
        "policy bogon-filter { term t { reject } }
         policy p { term t { if apply(zzz) { reject } } }",
    );
    assert!(rendered.contains("unknown policy `zzz`"), "{rendered}");
    assert!(!rendered.contains("did you mean"), "{rendered}");
}

#[test]
fn exact_match_of_another_kind_names_it() {
    // An exact name match in a different kind is a wrong reference,
    // not a typo (LAN-328): say what the name is instead of
    // suggesting a spelling fix.
    let (_, rendered) = diagnostics_of(
        "asn-set bogons { 64500 }
         policy p { term t { if route.prefix in bogons { reject } } }",
    );
    assert!(
        rendered.contains("`bogons` is an asn-set; `route.prefix in` needs a prefix-set"),
        "{rendered}"
    );
    assert!(rendered.contains("`bogons` is defined here"), "{rendered}");
    assert!(!rendered.contains("did you mean"), "{rendered}");

    let (_, rendered) = diagnostics_of(
        "asn-set bogons { 64500 }
         policy p { term t { if apply(bogons) { reject } } }",
    );
    assert!(
        rendered.contains("`bogons` is an asn-set, not a policy"),
        "{rendered}"
    );
    assert!(rendered.contains("`bogons` is defined here"), "{rendered}");

    let (_, rendered) = diagnostics_of(
        "asn-set bogons { 64500 }
         policy p { term t { if bogons(1) >= 2 { reject } } }",
    );
    assert!(
        rendered.contains("`bogons` is an asn-set, not a function"),
        "{rendered}"
    );
}

#[test]
fn unknown_field_suggests() {
    let (_, rendered) =
        diagnostics_of("policy p { term t { if route.local-perf >= 100 { accept } } }");
    assert!(
        rendered.contains("unknown field `route.local-perf`"),
        "{rendered}"
    );
    assert!(
        rendered.contains("did you mean `route.local-pref`?"),
        "{rendered}"
    );
}

#[test]
fn type_mismatches_render() {
    let (_, rendered) = diagnostics_of("policy p { term t { if route.next-hop == 5 { accept } } }");
    assert!(rendered.contains("type mismatch"), "{rendered}");
    assert!(rendered.contains("expected an IP address"), "{rendered}");

    let (_, rendered) = diagnostics_of("policy p { term t { if route.rpki >= valid { accept } } }");
    assert!(
        rendered.contains("supports only `==` and `!=`"),
        "{rendered}"
    );

    let (_, rendered) = diagnostics_of("policy p { term t { if route.rpki == vaild { accept } } }");
    assert!(
        rendered.contains("not a valid `route.rpki` value"),
        "{rendered}"
    );
    assert!(rendered.contains("did you mean `valid`?"), "{rendered}");

    let (_, rendered) =
        diagnostics_of("policy p { term t { if route.communities == 65000:1 { accept } } }");
    assert!(
        rendered.contains("cannot be compared directly"),
        "{rendered}"
    );
    assert!(rendered.contains("use `has <community>`"), "{rendered}");
}

#[test]
fn community_kind_mismatches_render() {
    let (_, rendered) =
        diagnostics_of("policy p { term t { if route.communities has 65000:1:2 { accept } } }");
    assert!(rendered.contains("community kind mismatch"), "{rendered}");
    assert!(rendered.contains("large-community literal"), "{rendered}");

    let (_, rendered) = diagnostics_of("policy p { term t { add community RT:65001:1; accept } }");
    assert!(rendered.contains("community kind mismatch"), "{rendered}");
    assert!(
        rendered.contains("use `add/remove ext-community`"),
        "{rendered}"
    );
}

#[test]
fn apply_recursion_is_rejected() {
    let (_, rendered) = diagnostics_of(
        "policy a { term t { if apply(b) { reject } } }
         policy b { term t { if apply(a) { reject } } }",
    );
    assert!(
        rendered.contains("`apply` cycle: a -> b -> a"),
        "{rendered}"
    );
    assert!(rendered.contains("must form a DAG"), "{rendered}");

    let (_, rendered) = diagnostics_of("policy a { term t { if apply(a) { reject } } }");
    assert!(rendered.contains("`apply` cycle: a -> a"), "{rendered}");
}

#[test]
fn arity_mismatch_is_rejected() {
    let (_, rendered) = diagnostics_of(
        "policy takes-one(lp: u32) { term t { accept } }
         policy p { term t { if apply(takes-one) { reject } } }",
    );
    assert!(
        rendered.contains("takes 1 argument but 0 were supplied"),
        "{rendered}"
    );
    assert!(rendered.contains("policy defined here"), "{rendered}");
}

#[test]
fn duplicate_names_are_rejected() {
    let (_, rendered) = diagnostics_of(
        "policy p { term t { accept } }
         policy p { term t { reject } }",
    );
    assert!(rendered.contains("duplicate policy `p`"), "{rendered}");
    assert!(rendered.contains("first definition is here"), "{rendered}");

    let (_, rendered) = diagnostics_of("policy q { term t { accept } term t { reject } }");
    assert!(rendered.contains("duplicate term `t`"), "{rendered}");
}

#[test]
fn unknown_parameter_suggests() {
    let (_, rendered) =
        diagnostics_of("policy p(peer_lp: u32) { term t { set local-pref peer_pl; accept } }");
    assert!(
        rendered.contains("unknown parameter or binding `peer_pl`"),
        "{rendered}"
    );
    assert!(rendered.contains("did you mean `peer_lp`?"), "{rendered}");
}

#[test]
fn unreachable_statements_are_rejected() {
    let (_, rendered) = diagnostics_of("policy p { term t { accept set med 5 } }");
    assert!(rendered.contains("unreachable statement"), "{rendered}");
    assert!(rendered.contains("already decided here"), "{rendered}");
}

#[test]
fn bad_regex_is_rejected_at_compile_time() {
    let (_, rendered) =
        diagnostics_of(r#"policy p { term t { if route.as-path matches "[65001" { reject } } }"#);
    assert!(rendered.contains("regex does not compile"), "{rendered}");
}

#[test]
fn parse_errors_render_with_expected_token() {
    let (_, rendered) = diagnostics_of("policy p { term t { if route.rpki == { accept } } }");
    assert!(
        rendered.contains("expected a comparison operand"),
        "{rendered}"
    );

    let (_, rendered) = diagnostics_of("policy p { accept }");
    assert!(rendered.contains("expected `term`"), "{rendered}");
}

#[test]
fn multiple_errors_reported_together() {
    let (diags, rendered) = diagnostics_of(
        "policy p { term t { if route.rpki == vaild { accept } } }
         policy q { term t { if route.prefix in nowhere { reject } } }",
    );
    assert!(diags.len() >= 2, "{rendered}");
    assert!(rendered.contains("vaild"), "{rendered}");
    assert!(rendered.contains("nowhere"), "{rendered}");
}

// ── in-language test runner ────────────────────────────────────────

#[test]
fn failing_tests_are_reported_with_reasons() {
    let source = r"
policy p {
    term t { if route.med <= 5 { set local-pref 300; accept } }
    term rest { reject }
}

test wrong-verdict {
    route { prefix 10.0.0.0/24; med 100 }
    expect p == accept
}

test wrong-attribute {
    route { prefix 10.0.0.0/24; med 3 }
    expect p == accept with local-pref 999
}

test passing {
    route { prefix 10.0.0.0/24; med 3 }
    expect p == accept with local-pref 300
}
";
    let report = run_rpol_tests(source).expect("compiles");
    assert_eq!(report.total, 3);
    assert_eq!(report.passed(), 1);
    assert_eq!(report.failures.len(), 2);
    let by_name: std::collections::HashMap<&str, &str> = report
        .failures
        .iter()
        .map(|f| (f.name.as_str(), f.message.as_str()))
        .collect();
    assert!(by_name["wrong-verdict"].contains("expected accept, got reject"));
    assert!(by_name["wrong-attribute"].contains("expected local-pref 999, got 300"));
}

#[test]
fn tests_use_peer_fixture_and_parameters() {
    let source = r#"
policy per-peer(lp: u32) {
    term from-leaf {
        if peer.group == "leaf" && peer.asn == 65010 {
            set local-pref lp;
            accept
        }
    }
    term rest { reject }
}

test leaf-peer-matches {
    route { prefix 10.0.0.0/24 }
    peer { address 192.0.2.1; asn 65010; group "leaf" }
    expect per-peer(500) == accept with local-pref 500
}

test other-peer-rejected {
    route { prefix 10.0.0.0/24 }
    peer { asn 65099 }
    expect per-peer(500) == reject
}
"#;
    let report = run_rpol_tests(source).expect("compiles");
    assert!(report.all_passed(), "{:?}", report.failures);
}

#[test]
fn check_rpol_shapes() {
    // Clean file, passing tests.
    let report = check_rpol(ADR_EXAMPLE);
    assert!(report.is_ok());
    assert!(report.diagnostics.is_empty());
    assert_eq!(report.tests.as_ref().map(TestReport::passed), Some(3));

    // Diagnostics: no tests run.
    let report = check_rpol("policy p { term t { if route.zzz == 1 { accept } } }");
    assert!(!report.is_ok());
    assert!(!report.diagnostics.is_empty());
    assert!(report.tests.is_none());

    // Clean compile, failing test.
    let report = check_rpol(
        "policy p { term t { reject } }
         test should-fail {
             route { prefix 10.0.0.0/24 }
             expect p == accept
         }",
    );
    assert!(!report.is_ok());
    assert!(report.diagnostics.is_empty());
    assert_eq!(report.tests.as_ref().map(|t| t.failures.len()), Some(1));
}

// ── LAN-184: recursion-depth guard ──────────────────────────────────

/// The deterministic stack bound the depth-guard tests enforce: the
/// tokio worker-thread default (2 MiB) — the smallest stack the daemon
/// compiles policies on (SIGHUP reload, gRPC policy check). Explicit
/// `stack_size` so the bound never depends on `RUST_MIN_STACK` or
/// scheduler/layout luck. The measured worst case (128-level
/// expression nesting, debug build) is ~7.4 KiB per level across the
/// `expr → and_expr → unary_expr` parse cycle ≈ 946 KiB — under half
/// this budget; keep non-recursive parse branches hoisted out of that
/// cycle (see `Parser::ident_condition`) so it stays there.
const SMALL_STACK: usize = 2 * 1024 * 1024;

/// Run `check_rpol` on `src` in a small-stack thread so an unguarded
/// (or frame-bloated) recursive front overflows fast and
/// deterministically instead of depending on the host's default stack
/// size.
fn check_on_small_stack(src: String) -> super::CheckReport {
    std::thread::Builder::new()
        .stack_size(SMALL_STACK)
        .spawn(move || check_rpol(&src))
        .expect("spawn")
        .join()
        .expect("policy compilation must never crash the thread")
}

/// LAN-303 regression guard for the boundary the depth-*error* tests
/// above cannot reach: **legal** maximum-depth shapes must compile AND
/// evaluate inside [`SMALL_STACK`] — every recursive pass runs (parse,
/// typecheck, constant folding, lowering, evaluation, and the drop
/// glue of both the AST and the compiled IR), where the diagnostic
/// tests stop at the parser. A compile-legal configuration must never
/// be able to overflow a daemon worker thread.
#[test]
fn legal_max_depth_shapes_compile_and_evaluate_on_small_stack() {
    // Depth 120 of the 128 allowed, one source per recursion shape:
    // `!` chains (deep unary AST), `&&` chains (deep binary AST),
    // parenthesized nesting (deep parse recursion, flat AST), a deep
    // arithmetic chain (value-expression recursion + folding), and a
    // maximally nested loop (LAN-303) around all of it.
    let bangs = format!(
        "policy p {{ term t {{ if {}route.med == 0 {{ reject }} accept }} }}",
        "!".repeat(120),
    );
    let ands = format!(
        "policy p {{ term t {{ if route.med == 0{} {{ reject }} accept }} }}",
        " && route.med == 0".repeat(120),
    );
    let parens = format!(
        "policy p {{ term t {{ if {}route.med == 0{} {{ reject }} accept }} }}",
        "(".repeat(120),
        ")".repeat(120),
    );
    let arith = format!(
        "policy p {{ term t {{ if route.med == 0{} {{ reject }} accept }} }}",
        " + 1 - 1".repeat(60),
    );
    let loops = "
        asn-set s { 1, 2 }
        policy p { term t {
            for a in s { for b in s { for c in s { for d in s {
                if a + b + c + d >= 8 { add community 65009:9 }
            } } } }
            accept
        } }"
    .to_string();
    for (name, src) in [
        ("bangs", bangs),
        ("ands", ands),
        ("parens", parens),
        ("arith", arith),
        ("loops", loops),
    ] {
        let verdict = std::thread::Builder::new()
            .stack_size(SMALL_STACK)
            .spawn(move || {
                let chain = compile_ok(&src);
                let ctx = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
                let action = chain.evaluate(&ctx).action;
                drop(chain); // deep IR drop glue, still on this stack
                action
            })
            .expect("spawn")
            .join()
            .unwrap_or_else(|_| panic!("legal-depth `{name}` shape crashed the small stack"));
        // med defaults to 0: `route.med == 0` matches, so every shape
        // but the loop one rejects (bangs: 120 negations = even).
        let expect = if name == "loops" {
            PolicyAction::Permit
        } else {
            PolicyAction::Deny
        };
        assert_eq!(verdict, expect, "{name}");
    }
}

#[test]
fn deep_paren_nesting_is_a_diagnostic_not_a_stack_overflow() {
    // 100k nested parens: config-triggered daemon crash before the
    // parser depth guard (rpol files arrive via SIGHUP overlay).
    let src = format!(
        "policy p {{ term t {{ if {}route.med == 0{} {{ accept }} }} }}",
        "(".repeat(100_000),
        ")".repeat(100_000),
    );
    let report = check_on_small_stack(src);
    let rendered = format!("{:?}", report.diagnostics);
    assert!(
        rendered.contains("nesting exceeds"),
        "want a depth diagnostic, got: {rendered:.300}"
    );
}

#[test]
fn deep_bang_and_operator_chains_are_diagnostics_too() {
    // `!` recursion in the parser.
    let src = format!(
        "policy p {{ term t {{ if {}route.med == 0 {{ accept }} }} }}",
        "!".repeat(100_000),
    );
    let report = check_on_small_stack(src);
    let rendered = format!("{:?}", report.diagnostics);
    assert!(
        rendered.contains("nesting exceeds"),
        "want a depth diagnostic, got: {rendered:.300}"
    );

    // Chained binary ops build a left-leaning AST whose depth the
    // downstream recursive passes (typeck, lower, Drop) consume.
    let src = format!(
        "policy p {{ term t {{ if route.med == 0{} {{ accept }} }} }}",
        " && route.med == 0".repeat(100_000),
    );
    let report = check_on_small_stack(src);
    let rendered = format!("{:?}", report.diagnostics);
    assert!(
        rendered.contains("nesting exceeds"),
        "want a depth diagnostic, got: {rendered:.300}"
    );
}

#[test]
fn reasonable_nesting_stays_clean() {
    // 64 levels of parens + a 100-term `&&` chain: well within the cap.
    let src = format!(
        "policy p {{ term t {{ if {}route.med == 0{}{} {{ accept }} }} }}",
        "(".repeat(64),
        ")".repeat(64),
        " && route.local-pref >= 1".repeat(100),
    );
    let report = check_on_small_stack(src);
    assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
}

// ── LAN-290: apply-DAG expansion/depth bounds ───────────────────────

/// `p0` plus `levels` policies each guarding on `apply` of the
/// previous one, `applies_per_level` times (`||`-joined).
fn apply_chain(levels: u32, applies_per_level: u32) -> String {
    use std::fmt::Write;

    let mut src = String::from("policy p0 { term t { if route.med == 0 { accept } } }\n");
    for i in 1..=levels {
        let guard = (0..applies_per_level)
            .map(|_| format!("apply(p{})", i - 1))
            .collect::<Vec<_>>()
            .join(" || ");
        writeln!(
            src,
            "policy p{i} {{ term t {{ if {guard} {{ accept }} }} }}"
        )
        .expect("string io");
    }
    src
}

#[test]
fn exponential_apply_dag_is_a_diagnostic_not_an_explosion() {
    // p_{i+1} applies p_i four times: unbounded lowering would
    // multiply the inlined predicate ~8× per level (each apply inlines
    // the target's predicate, which itself embeds each guard twice).
    let report = check_on_small_stack(apply_chain(40, 4));
    let rendered = format!("{:?}", report.diagnostics);
    assert!(
        rendered.contains("expands past"),
        "want an expansion diagnostic, got: {rendered:.300}"
    );
    // Poisoning: one root-cause diagnostic, not one per dependent.
    assert_eq!(report.diagnostics.0.len(), 1, "{rendered:.500}");
}

#[test]
fn deep_apply_chain_is_a_depth_diagnostic() {
    // A linear apply chain past MAX_APPLY_DEPTH: a legal DAG, but the
    // lowering recursion (and the inlined guard tree) would nest one
    // more level per policy.
    let report = check_on_small_stack(apply_chain(10, 1));
    let rendered = format!("{:?}", report.diagnostics);
    assert!(
        rendered.contains("nests policies more than"),
        "want a depth diagnostic, got: {rendered:.300}"
    );
    assert_eq!(report.diagnostics.0.len(), 1, "{rendered:.500}");
}

#[test]
fn reasonable_apply_composition_stays_clean_and_evaluates_flat() {
    // A max-depth-legal linear chain compiles and evaluates on a small
    // stack: `apply` is inlined at lower time (no runtime recursion
    // into applied policies), so evaluation walks a statically bounded
    // guard tree.
    let src = apply_chain(8, 1);
    let report = check_on_small_stack(src.clone());
    assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
    std::thread::Builder::new()
        .stack_size(1024 * 1024)
        .spawn(move || {
            let mut store = SetStore::new();
            let chain = compile_rpol(&src, &mut store).expect("within bounds");
            assert_eq!(chain.evaluate(&absent_ctx()).action, PolicyAction::Permit);
        })
        .expect("spawn")
        .join()
        .expect("bounded compile + flat evaluation must not overflow");
}

// ── RFC 8097 origin-validation-state well-known names (OV_*) ──────

#[test]
fn ov_names_match_add_remove_and_evaluate() {
    use rustbgpd_wire::ExtendedCommunity;

    let chain = compile_ok(
        r"policy ov {
             term drop-invalid { if route.ext-communities has OV_INVALID { reject } }
             term tag {
                 add ext-community OV_VALID;
                 remove ext-community OV_NOT_FOUND;
                 accept
             }
         }",
    );
    let TermAction::Permit(mods) = &chain.policies[0].terms[1].action else {
        panic!("expected permit")
    };
    assert_eq!(
        mods.extended_communities_add,
        vec![ExtendedCommunity::ORIGIN_VALIDATION_VALID]
    );
    assert_eq!(
        mods.extended_communities_remove,
        vec![ExtendedCommunity::ORIGIN_VALIDATION_NOT_FOUND]
    );

    let base = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
    let invalid_ecs = [ExtendedCommunity::ORIGIN_VALIDATION_INVALID];
    assert_eq!(
        chain
            .evaluate(&RouteContext {
                extended_communities: &invalid_ecs,
                ..base
            })
            .action,
        PolicyAction::Deny
    );
    // Exact raw-value match: a different OV state does not trip it.
    let valid_ecs = [ExtendedCommunity::ORIGIN_VALIDATION_VALID];
    assert_eq!(
        chain
            .evaluate(&RouteContext {
                extended_communities: &valid_ecs,
                ..base
            })
            .action,
        PolicyAction::Permit
    );
}

#[test]
fn ov_names_in_test_fixtures_and_with_assertions() {
    // End-to-end tag-on-import + match through the in-language runner:
    // one policy tags, a second matches what the first added.
    let source = r"
policy tag-ov { term tag { add ext-community OV_INVALID; accept } }
policy drop-ov-invalid {
    term drop { if route.ext-communities has OV_INVALID { reject } }
    term rest { accept }
}

test tagging-asserts-the-added-ov-state {
    route { prefix 10.0.0.0/24 }
    expect tag-ov == accept with ext-community OV_INVALID
}

test tagged-route-is-dropped-on-rematch {
    route { prefix 10.0.0.0/24; ext-communities [OV_INVALID] }
    expect drop-ov-invalid == reject
}

test untagged-route-passes {
    route { prefix 10.0.0.0/24; ext-communities [OV_VALID, RT:65001:100] }
    expect drop-ov-invalid == accept
}
";
    let report = run_rpol_tests(source).expect("compiles");
    assert!(report.all_passed(), "{:?}", report.failures);
}

// ── strict next-hop (`route.next-hop == peer.address`) ────────────

#[test]
fn strict_next_hop_lowers_and_evaluates_both_ways() {
    let chain = compile_ok(
        "policy strict-nh {
             term ok { if route.next-hop == peer.address { accept } }
             term rest { reject }
         }",
    );
    assert_eq!(chain.policies[0].terms[0].guard, MatchExpr::NextHopEqPeer);
    assert!(
        chain.requires_peer_context(),
        "strict next-hop reads peer identity — must disqualify grouping"
    );

    let peer = std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let base = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
    let matching = RouteContext {
        next_hop: Some(peer),
        peer_address: Some(peer),
        ..base
    };
    assert_eq!(chain.evaluate(&matching).action, PolicyAction::Permit);
    let mismatched = RouteContext {
        next_hop: Some(std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))),
        peer_address: Some(peer),
        ..base
    };
    assert_eq!(chain.evaluate(&mismatched).action, PolicyAction::Deny);
    // Unknown next-hop never matches (both sides must be known).
    let unknown = RouteContext {
        next_hop: None,
        peer_address: Some(peer),
        ..base
    };
    assert_eq!(chain.evaluate(&unknown).action, PolicyAction::Deny);
}

#[test]
fn strict_next_hop_negated_form() {
    let chain = compile_ok(
        "policy not-self {
             term reroute { if route.next-hop != peer.address { reject } }
             term rest { accept }
         }",
    );
    // `!=` lowers to a dedicated Ne node (not `Not(NextHopEqPeer)`) so
    // that an absent next-hop matches neither `==` nor `!=` (LAN-209).
    assert_eq!(chain.policies[0].terms[0].guard, MatchExpr::NextHopNePeer);
    assert!(
        chain.requires_peer_context(),
        "strict next-hop `!=` still reads peer identity"
    );
    let peer = std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let base = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
    let matching = RouteContext {
        next_hop: Some(peer),
        peer_address: Some(peer),
        ..base
    };
    assert_eq!(chain.evaluate(&matching).action, PolicyAction::Permit);
    let mismatched = RouteContext {
        next_hop: Some(std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))),
        peer_address: Some(peer),
        ..base
    };
    assert_eq!(chain.evaluate(&mismatched).action, PolicyAction::Deny);
    // LAN-209: an absent next-hop must NOT match `!=` — the `reroute`
    // term must not fire, so the route falls through to `accept`.
    let absent = RouteContext {
        next_hop: None,
        peer_address: Some(peer),
        ..base
    };
    assert_eq!(
        chain.evaluate(&absent).action,
        PolicyAction::Permit,
        "absent next-hop must not match `route.next-hop != peer.address`"
    );
}

#[test]
fn next_hop_ne_literal_absent_does_not_match() {
    // LAN-209: `route.next-hop != <ip>` must never match when the
    // next-hop attribute is absent (mirroring `==`), rather than
    // matching via `Not(NextHopEq)`.
    let chain = compile_ok(
        "policy drop-non-blackhole {
             term reject-others { if route.next-hop != 192.0.2.1 { reject } }
             term rest { accept }
         }",
    );
    assert_eq!(
        chain.policies[0].terms[0].guard,
        MatchExpr::NextHopNe(std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
    );
    let base = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
    // Present and differing → matches → reject.
    let differing = RouteContext {
        next_hop: Some(std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))),
        ..base
    };
    assert_eq!(chain.evaluate(&differing).action, PolicyAction::Deny);
    // Present and equal → no match → accept.
    let equal = RouteContext {
        next_hop: Some(std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        ..base
    };
    assert_eq!(chain.evaluate(&equal).action, PolicyAction::Permit);
    // Absent → must NOT match → accept (this was the bug).
    let absent = RouteContext {
        next_hop: None,
        ..base
    };
    assert_eq!(
        chain.evaluate(&absent).action,
        PolicyAction::Permit,
        "absent next-hop must not match `route.next-hop != <ip>`"
    );
}

#[test]
fn strict_next_hop_rejects_other_field_comparisons() {
    // The one legal field-vs-field pair is next-hop vs peer.address.
    let (_, rendered) =
        diagnostics_of("policy p { term t { if route.next-hop == peer.asn { accept } } }");
    assert!(
        rendered.contains("only `peer.address` is allowed here"),
        "{rendered}"
    );
    // Field references are not valid operands for other fields.
    let (_, rendered) =
        diagnostics_of("policy p { term t { if route.local-pref == peer.address { accept } } }");
    assert!(rendered.contains("field reference"), "{rendered}");
    // And peer.address still only compares against an IP literal.
    let (_, rendered) =
        diagnostics_of("policy p { term t { if peer.address == route.next-hop { accept } } }");
    assert!(rendered.contains("field reference"), "{rendered}");
}

#[test]
fn evpn_route_type_enforces_rfc7432_range() {
    // LAN-192: rustbgpd only emits EVPN route types 1-5 (RFC 7432 §7),
    // so those compile…
    for t in 1..=5 {
        compile_ok(&format!(
            "policy p {{ term t {{ if route.evpn-route-type == {t} {{ accept }} }} }}"
        ));
    }
    // …while 0 and 6-255 can never match a real route and are rejected
    // as dead policies rather than silently never firing.
    for t in [0u32, 6, 255, 256] {
        let (_, rendered) = diagnostics_of(&format!(
            "policy p {{ term t {{ if route.evpn-route-type == {t} {{ accept }} }} }}"
        ));
        assert!(
            rendered.contains("out of range"),
            "evpn-route-type {t} must be rejected, got: {rendered}"
        );
    }
}

/// A route context with every optional attribute absent — the shape a
/// BGP-LS / RTC / non-EVPN NLRI presents to a policy.
fn absent_ctx() -> RouteContext<'static> {
    RouteContext {
        prefix: None,
        next_hop: None,
        extended_communities: &[],
        communities: &[],
        large_communities: &[],
        as_path_str: "",
        as_path: None,
        as_path_len: 0,
        origin_asn: None,
        validation_state: RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        peer_address: None,
        peer_asn: None,
        peer_group: None,
        route_type: None,
        family: None,
        evpn_route_type: None,
        local_pref: None,
        med: None,
    }
}

/// Compile `if route.<expr> { reject }` guarded by `everything-else:
/// accept`, so a matching guard yields `Deny` and a non-matching one
/// falls through to `Permit`.
fn reject_if(guard: &str) -> crate::ir::CompiledChain {
    compile_ok(&format!(
        "policy guard {{ term t {{ if {guard} {{ reject }} }} term rest {{ accept }} }}"
    ))
}

/// LAN-209 class guard: for EVERY structurally-absent route attribute
/// that supports `==`/`!=`, an absent attribute must match **neither**
/// operator (mirroring the next-hop fix). This fails loudly if any
/// field's `!=` ever lowers back to `Not(<X>Eq)` (which matches on
/// absent) — a future comparable field cannot silently reintroduce the
/// bug without tripping this table.
///
/// `local-pref`/`med` are deliberately excluded: they carry RFC 4271
/// implicit defaults (100/0), so their "absent" is a real value that
/// legitimately compares — they are not part of the absent-`!=` class.
#[test]
fn absent_route_attribute_matches_neither_eq_nor_ne() {
    // (field expression, a literal it compares against)
    let fields = [
        ("route.next-hop", "192.0.2.1"),
        ("route.prefix", "10.0.0.0/24"),
        ("route.route-type", "external"),
        ("route.evpn-route-type", "3"),
        ("route.family", "evpn"),
    ];
    let absent = absent_ctx();
    for (field, literal) in fields {
        for op in ["==", "!="] {
            let chain = reject_if(&format!("{field} {op} {literal}"));
            assert_eq!(
                chain.evaluate(&absent).action,
                PolicyAction::Permit,
                "absent `{field}` must not match `{field} {op} {literal}`"
            );
        }
    }
}

#[test]
fn evpn_route_type_ne_absent_does_not_match() {
    // A non-EVPN route (absent evpn-route-type) must match neither `==`
    // nor `!=` — `Not(EvpnRouteTypeIs)` used to match every such route.
    let chain = reject_if("route.evpn-route-type != 3");
    assert_eq!(
        chain.policies[0].terms[0].guard,
        MatchExpr::EvpnRouteTypeNe(3)
    );
    let base = absent_ctx();
    // Present and differing → matches → reject.
    let differing = RouteContext {
        evpn_route_type: Some(2),
        ..base
    };
    assert_eq!(chain.evaluate(&differing).action, PolicyAction::Deny);
    // Present and equal → no match → accept.
    let equal = RouteContext {
        evpn_route_type: Some(3),
        ..base
    };
    assert_eq!(chain.evaluate(&equal).action, PolicyAction::Permit);
    // Absent → must NOT match → accept (this was the bug).
    assert_eq!(
        chain.evaluate(&base).action,
        PolicyAction::Permit,
        "absent evpn-route-type must not match `!= 3`"
    );
}

#[test]
fn prefix_ne_absent_does_not_match() {
    // A prefixless route (BGP-LS / RTC NLRIs) must match neither `==`
    // nor `!=` — `Not(PrefixEq)` used to match every prefixless route.
    let chain = reject_if("route.prefix != 10.0.0.0/24");
    assert_eq!(
        chain.policies[0].terms[0].guard,
        MatchExpr::PrefixNe {
            prefix: v4(10, 0, 0, 0, 24),
            ge: None,
            le: None,
        }
    );
    let base = absent_ctx();
    // Present and differing → matches → reject.
    let differing = RouteContext {
        prefix: Some(v4(198, 51, 100, 0, 24)),
        ..base
    };
    assert_eq!(chain.evaluate(&differing).action, PolicyAction::Deny);
    // Present and equal → no match → accept.
    let equal = RouteContext {
        prefix: Some(v4(10, 0, 0, 0, 24)),
        ..base
    };
    assert_eq!(chain.evaluate(&equal).action, PolicyAction::Permit);
    // Absent → must NOT match → accept (this was the bug).
    assert_eq!(
        chain.evaluate(&base).action,
        PolicyAction::Permit,
        "absent prefix must not match `!= 10.0.0.0/24`"
    );
}

#[test]
fn route_type_ne_absent_does_not_match() {
    // A route with no source class must match neither `==` nor `!=` —
    // `Not(RouteTypeIs)` used to match when the route-type was absent.
    let chain = reject_if("route.route-type != external");
    assert_eq!(
        chain.policies[0].terms[0].guard,
        MatchExpr::RouteTypeNe(crate::engine::RouteType::External)
    );
    let base = absent_ctx();
    // Present and differing → matches → reject.
    let differing = RouteContext {
        route_type: Some(crate::engine::RouteType::Local),
        ..base
    };
    assert_eq!(chain.evaluate(&differing).action, PolicyAction::Deny);
    // Present and equal → no match → accept.
    let equal = RouteContext {
        route_type: Some(crate::engine::RouteType::External),
        ..base
    };
    assert_eq!(chain.evaluate(&equal).action, PolicyAction::Permit);
    // Absent → must NOT match → accept (this was the bug).
    assert_eq!(
        chain.evaluate(&base).action,
        PolicyAction::Permit,
        "absent route-type must not match `!= external`"
    );
}

// ── asn-sets and origin-as predicates (LAN-249) ────────────────────

const ASN_SET_EXAMPLE: &str = r"
asn-set customers { 64500, 64501, 64502, 64500 }

policy origin-filter {
    term customer-origins {
        if route.origin-as in customers { accept }
    }
    term rest { reject }
}

policy peer-filter {
    term customer-peers {
        if peer.asn in customers { accept }
    }
    term rest { reject }
}

policy exact-origin {
    term hit { if route.origin-as == 64500 { accept } }
    term not-hit { if route.origin-as != 64500 { reject } }
}
";

#[test]
fn asn_set_lowers_to_indexed_set() {
    let chain = compile_ok(ASN_SET_EXAMPLE);
    assert_eq!(chain.asn_sets.len(), 1);
    // Duplicates canonicalized away; members sorted.
    assert_eq!(chain.asn_sets[0].asns(), &[64500, 64501, 64502]);
    assert_eq!(chain.asn_set_names, vec![Some("customers".to_string())]);
    let origin_filter = &chain.policies[0];
    assert_eq!(
        origin_filter.terms[0].guard,
        MatchExpr::OriginAsInSet(SetId(0))
    );
    let peer_filter = &chain.policies[1];
    assert_eq!(peer_filter.terms[0].guard, MatchExpr::PeerAsInSet(SetId(0)));
    let exact = &chain.policies[2];
    assert_eq!(exact.terms[0].guard, MatchExpr::OriginAsEq(64500));
    assert_eq!(exact.terms[1].guard, MatchExpr::OriginAsNe(64500));
    // peer.asn membership reads peer identity; origin-as does not.
    assert!(chain.requires_peer_context());
}

/// Absent origin (empty or AS_SET-only path) matches neither `in` nor
/// `==` nor `!=` — three-valued, mirroring the other absent-attribute
/// predicates.
#[test]
fn origin_as_predicates_evaluate_three_valued() {
    let chain = compile_ok(ASN_SET_EXAMPLE);
    let base = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
    let eval = |policy: usize, ctx: &RouteContext<'_>| {
        let single = crate::ir::CompiledChain {
            policies: vec![chain.policies[policy].clone()],
            ..chain.clone()
        };
        single.evaluate(ctx).action
    };

    // origin-filter: member accepts, non-member rejects, absent rejects.
    let member = RouteContext {
        origin_asn: Some(64501),
        ..base
    };
    let non_member = RouteContext {
        origin_asn: Some(65000),
        ..base
    };
    assert_eq!(eval(0, &member), PolicyAction::Permit);
    assert_eq!(eval(0, &non_member), PolicyAction::Deny);
    assert_eq!(
        eval(0, &base),
        PolicyAction::Deny,
        "absent origin: no match"
    );

    // peer-filter: same probe against peer.asn.
    let peer_member = RouteContext {
        peer_asn: Some(64502),
        ..base
    };
    let peer_non_member = RouteContext {
        peer_asn: Some(65000),
        ..base
    };
    assert_eq!(eval(1, &peer_member), PolicyAction::Permit);
    assert_eq!(eval(1, &peer_non_member), PolicyAction::Deny);
    assert_eq!(eval(1, &base), PolicyAction::Deny, "unknown peer ASN");

    // exact-origin: == hits only 64500; != hits any other present
    // origin; an absent origin matches neither and falls through to
    // the default permit.
    let exact_hit = RouteContext {
        origin_asn: Some(64500),
        ..base
    };
    let exact_other = RouteContext {
        origin_asn: Some(64501),
        ..base
    };
    assert_eq!(eval(2, &exact_hit), PolicyAction::Permit);
    assert_eq!(eval(2, &exact_other), PolicyAction::Deny, "`!=` rejects");
    assert_eq!(
        eval(2, &base),
        PolicyAction::Permit,
        "absent origin matches neither == nor != and falls through"
    );
}

#[test]
fn asn_set_diagnostics() {
    // Unknown set name suggests the near-miss.
    let (_, rendered) = diagnostics_of(
        "asn-set customers { 64500 }
         policy p { term t { if route.origin-as in customer { accept } } }",
    );
    assert!(rendered.contains("unknown asn-set"), "{rendered}");
    assert!(rendered.contains("did you mean `customers`?"), "{rendered}");

    // Wrong set kind gets a targeted note.
    let (_, rendered) = diagnostics_of(
        "prefix-set nets { 10.0.0.0/8 }
         policy p { term t { if peer.asn in nets { accept } } }",
    );
    assert!(
        rendered.contains("`nets` is a prefix-set; ASN membership needs an asn-set"),
        "{rendered}"
    );

    // Ordering comparisons are rejected on origin-as.
    let (_, rendered) =
        diagnostics_of("policy p { term t { if route.origin-as >= 64500 { accept } } }");
    assert!(
        rendered.contains("supports only `==` and `!=`"),
        "{rendered}"
    );

    // Out-of-range ASN literals are rejected at parse.
    let (_, rendered) = diagnostics_of("asn-set wide { 5000000000 }");
    assert!(rendered.contains("does not fit in u32"), "{rendered}");

    // Duplicate set names are rejected.
    let (_, rendered) = diagnostics_of("asn-set a { 1 }\nasn-set a { 2 }");
    assert!(rendered.contains("duplicate asn-set `a`"), "{rendered}");

    // `in` on a field with no set kind names all three.
    let (_, rendered) =
        diagnostics_of("policy p { term t { if route.med in something { accept } } }");
    assert!(rendered.contains("asn-sets"), "{rendered}");
}

// ── route.family (LAN-295) ──────────────────────────────────────────

/// Every supported family spelling lowers to its typed IR value and
/// evaluates strictly: `==` matches exactly its own family and nothing
/// else (families are typed knowledge — never classified from the
/// context's prefix).
#[test]
fn family_eq_pins_every_supported_family() {
    use crate::engine::RouteFamily;

    let families = [
        ("ipv4-unicast", RouteFamily::Ipv4Unicast),
        ("ipv6-unicast", RouteFamily::Ipv6Unicast),
        ("ipv4-labeled-unicast", RouteFamily::Ipv4LabeledUnicast),
        ("ipv6-labeled-unicast", RouteFamily::Ipv6LabeledUnicast),
        ("vpnv4", RouteFamily::Vpnv4),
        ("vpnv6", RouteFamily::Vpnv6),
        ("ipv4-flowspec", RouteFamily::Ipv4Flowspec),
        ("ipv6-flowspec", RouteFamily::Ipv6Flowspec),
        ("evpn", RouteFamily::Evpn),
        ("rtc", RouteFamily::RtConstrain),
        ("bgp-ls", RouteFamily::BgpLs),
        ("bgp-ls-vpn", RouteFamily::BgpLsVpn),
    ];
    let base = absent_ctx();
    for (spelling, family) in families {
        let chain = reject_if(&format!("route.family == {spelling}"));
        assert_eq!(
            chain.policies[0].terms[0].guard,
            MatchExpr::FamilyIs(family),
            "`{spelling}` lowers to its typed value"
        );
        for (other_spelling, other) in families {
            let ctx = RouteContext {
                family: Some(other),
                ..base
            };
            let expect = if other == family {
                PolicyAction::Deny
            } else {
                PolicyAction::Permit
            };
            assert_eq!(
                chain.evaluate(&ctx).action,
                expect,
                "family {other_spelling} vs `route.family == {spelling}`"
            );
        }
    }
}

#[test]
fn family_ne_absent_does_not_match() {
    // A context without typed family knowledge must match neither `==`
    // nor `!=` (the LAN-209 absent class).
    let chain = reject_if("route.family != evpn");
    assert_eq!(
        chain.policies[0].terms[0].guard,
        MatchExpr::FamilyNe(crate::engine::RouteFamily::Evpn)
    );
    let base = absent_ctx();
    let differing = RouteContext {
        family: Some(crate::engine::RouteFamily::Ipv4Unicast),
        ..base
    };
    assert_eq!(chain.evaluate(&differing).action, PolicyAction::Deny);
    let equal = RouteContext {
        family: Some(crate::engine::RouteFamily::Evpn),
        ..base
    };
    assert_eq!(chain.evaluate(&equal).action, PolicyAction::Permit);
    assert_eq!(
        chain.evaluate(&base).action,
        PolicyAction::Permit,
        "absent family must not match `!= evpn`"
    );
}

/// The honest-context rule (ADR-0077): the family is typed knowledge,
/// never inferred from prefix shape. A context carrying an IPv4 prefix
/// but no typed family matches no family predicate; one carrying an
/// IPv4 prefix with typed FlowSpec-v6 knowledge matches `ipv6-flowspec`
/// (families whose policy prefix is a v4 destination component still
/// classify by their typed family, not the prefix).
#[test]
fn family_is_never_classified_from_prefix_shape() {
    use crate::engine::RouteFamily;

    let v4_prefix_no_family = RouteContext {
        prefix: Some(v4(10, 0, 0, 0, 24)),
        ..absent_ctx()
    };
    for guard in ["route.family == ipv4-unicast", "route.family != evpn"] {
        let chain = reject_if(guard);
        assert_eq!(
            chain.evaluate(&v4_prefix_no_family).action,
            PolicyAction::Permit,
            "a v4 prefix without typed family knowledge must not match `{guard}`"
        );
    }

    let v4_prefix_v6_flowspec = RouteContext {
        prefix: Some(v4(10, 0, 0, 0, 24)),
        family: Some(RouteFamily::Ipv6Flowspec),
        ..absent_ctx()
    };
    let chain = reject_if("route.family == ipv6-flowspec");
    assert_eq!(
        chain.evaluate(&v4_prefix_v6_flowspec).action,
        PolicyAction::Deny,
        "typed family wins regardless of the policy prefix's shape"
    );
    let chain = reject_if("route.family == ipv4-unicast");
    assert_eq!(
        chain.evaluate(&v4_prefix_v6_flowspec).action,
        PolicyAction::Permit,
        "the v4 prefix must not classify the route as ipv4-unicast"
    );
}

/// Family predicates are route-context-only: they never disqualify a
/// peer from update-group sharing the way peer-dependent predicates do
/// (`requires_peer_context` drives the update-group fingerprint).
#[test]
fn family_predicates_do_not_require_peer_context() {
    let family_chain = compile_ok(
        "policy fam {
            term v4-only { if route.family != ipv4-unicast { reject } }
            term rest { accept }
        }",
    );
    assert!(!family_chain.requires_peer_context());

    // Control: a genuinely peer-dependent chain still trips the flag.
    let peer_chain = compile_ok(
        "policy peered {
            term nh { if route.next-hop == peer.address { reject } }
            term rest { accept }
        }",
    );
    assert!(peer_chain.requires_peer_context());
}

#[test]
fn family_rejects_ordering_unknown_member_and_wrong_type() {
    let (diags, rendered) =
        diagnostics_of("policy p { term t { if route.family >= ipv4-unicast { accept } } }");
    assert_eq!(diags.len(), 1, "{rendered}");
    assert!(
        rendered.contains("supports only `==` and `!=`"),
        "{rendered}"
    );

    // ASN literals are u32 — no 16-bit truncation, out-of-range rejected.
    let (_, rendered) = diagnostics_of("asn-set wide { 5000000000 }");
    assert!(rendered.contains("does not fit in u32"), "{rendered}");

    // Duplicate set names are rejected.
    let (_, rendered) = diagnostics_of("asn-set a { 1 }\nasn-set a { 2 }");
    assert!(rendered.contains("duplicate asn-set `a`"), "{rendered}");

    // `in` on a field with no set kind names all three.
    let (_, rendered) =
        diagnostics_of("policy p { term t { if route.med in something { accept } } }");
    assert!(rendered.contains("asn-sets"), "{rendered}");
}

/// 4-byte ASNs are first-class set members and comparison operands.
#[test]
fn four_byte_asns_compile_and_match() {
    let chain = compile_ok(
        "asn-set wide { 4200000001, 64500 }
         policy p {
             term hit { if route.origin-as in wide { accept } }
             term rest { reject }
         }",
    );
    let base = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
    let wide = RouteContext {
        origin_asn: Some(4_200_000_001),
        ..base
    };
    assert_eq!(chain.evaluate(&wide).action, PolicyAction::Permit);
    assert_eq!(chain.evaluate(&base).action, PolicyAction::Deny);
}

/// The in-language test runner derives the fixture origin from the
/// `as-path` string exactly like `AsPath::origin_asn` on the typed
/// path: last ASN of the rightmost non-empty `AS_SEQUENCE`; `AS_SET`
/// members (`{...}`) never contribute; empty/AS_SET-only paths have
/// no origin and match nothing.
#[test]
fn fixture_origin_derives_from_as_path_string() {
    let source = r#"
asn-set customers { 64500, 64501 }

policy origin-filter {
    term customer-origins {
        if route.origin-as in customers { accept }
    }
    term rest { reject }
}

test sequence-origin-matches {
    route { prefix 10.0.0.0/24; as-path "65010 64500" }
    expect origin-filter == accept
}

test aggregated-path-uses-sequence-tail {
    route { prefix 10.0.0.0/24; as-path "64501 {64999 65000}" }
    expect origin-filter == accept
}

test as-set-only-path-has-no-origin {
    route { prefix 10.0.0.0/24; as-path "{64500 64501}" }
    expect origin-filter == reject
}

test empty-path-has-no-origin {
    route { prefix 10.0.0.0/24 }
    expect origin-filter == reject
}

test non-member-origin-rejected {
    route { prefix 10.0.0.0/24; as-path "64500 65010" }
    expect origin-filter == reject
}
"#;
    let report = run_rpol_tests(source).expect("compiles");
    assert_eq!(report.total, 5);
    assert!(
        report.failures.is_empty(),
        "unexpected failures: {:?}",
        report.failures
    );
    let (diags, rendered) =
        diagnostics_of("policy p { term t { if route.family == ipv4-unicats { accept } } }");
    assert_eq!(diags.len(), 1, "{rendered}");
    assert!(
        rendered.contains("did you mean `ipv4-unicast`?"),
        "{rendered}"
    );

    let (diags, rendered) =
        diagnostics_of("policy p { term t { if route.family == 42 { accept } } }");
    assert_eq!(diags.len(), 1, "{rendered}");
    assert!(rendered.contains("type mismatch"), "{rendered}");
}

/// The in-language test runner: `family` is an explicit fixture field;
/// an omitted fixture family is absent (matches neither `==` nor `!=`)
/// even when the fixture carries a prefix.
#[test]
fn family_in_test_fixtures() {
    let source = r"
policy evpn-only {
    term fam { if route.family != evpn { reject } }
    term rest { accept }
}

test evpn-family-accepted {
    route { family evpn }
    expect evpn-only == accept
}

test other-family-rejected {
    route { family vpnv4 }
    expect evpn-only == reject
}

test no-family-is-absent-not-prefix-classified {
    route { prefix 10.0.0.0/24 }
    expect evpn-only == accept
}
";
    let report = run_rpol_tests(source).expect("compiles");
    assert_eq!(report.total, 3);
    assert!(report.all_passed(), "failures: {:?}", report.failures);
}

#[test]
fn family_fixture_rejects_unknown_member() {
    let (diags, rendered) = diagnostics_of(
        "policy p { term t { accept } }
         test t { route { family evnp } expect p == accept }",
    );
    assert_eq!(diags.len(), 1, "{rendered}");
    assert!(rendered.contains("did you mean `evpn`?"), "{rendered}");
}

// ── computed prepend operands (LAN-296) ────────────────────────────

/// A context with just the fields the prepend operands read.
fn prepend_ctx(peer_asn: Option<u32>, origin_asn: Option<u32>) -> RouteContext<'static> {
    RouteContext {
        origin_asn,
        peer_asn,
        ..route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound)
    }
}

/// The mods a single-policy chain's first term action carries.
fn first_term_mods(chain: &crate::ir::CompiledChain) -> &RouteModifications {
    match &chain.policies[0].terms[0].action {
        TermAction::Permit(mods) | TermAction::Continue(mods) => mods,
        _ => panic!("expected a modifying term"),
    }
}

#[test]
fn computed_prepend_operands_lower_to_computed_slot() {
    use crate::engine::PrependAs;
    for (source_operand, expected) in [
        ("self", PrependAs::LocalAs),
        ("peer", PrependAs::PeerAs),
        ("origin", PrependAs::OriginAs),
    ] {
        let chain = compile_ok(&format!(
            "policy p {{ term t {{ prepend as {source_operand} 3; accept }} }}"
        ));
        let mods = first_term_mods(&chain);
        assert_eq!(
            mods.as_path_prepend_computed,
            Some((expected, 3)),
            "operand {source_operand}"
        );
        assert_eq!(mods.as_path_prepend, None, "operand {source_operand}");
    }
}

/// Zero source-compatibility break: the literal and parameter forms
/// still lower to the literal slot, and a policy parameter named
/// `origin` keeps its parameter meaning (grammar-evolution rule).
#[test]
fn fixed_prepend_forms_unchanged() {
    let chain = compile_ok("policy p { term t { prepend as 65001 3; accept } }");
    let mods = first_term_mods(&chain);
    assert_eq!(mods.as_path_prepend, Some((65001, 3)));
    assert_eq!(mods.as_path_prepend_computed, None);

    let mut store = SetStore::new();
    let set =
        super::RpolFile::parse("policy p(origin: u32) { term t { prepend as origin 2; accept } }")
            .expect("compiles");
    let chain = set
        .compile_policy("p", &[64999], &mut store)
        .expect("policy exists");
    let mods = first_term_mods(&chain);
    assert_eq!(
        mods.as_path_prepend,
        Some((64999, 2)),
        "a parameter named `origin` must stay a parameter"
    );
    assert_eq!(mods.as_path_prepend_computed, None);
}

#[test]
fn prepend_peer_resolves_to_peer_asn_on_import_eval() {
    let chain = compile_ok("policy p { term t { prepend as peer 3; accept } }");
    let result = chain.evaluate(&prepend_ctx(Some(65010), None));
    assert_eq!(result.action, PolicyAction::Permit);
    assert_eq!(result.modifications.as_path_prepend, Some((65010, 3)));
    assert_eq!(result.modifications.as_path_prepend_computed, None);
}

#[test]
fn prepend_origin_resolves_to_origin_asn() {
    let chain = compile_ok("policy p { term t { prepend as origin 2; accept } }");
    let result = chain.evaluate(&prepend_ctx(None, Some(64500)));
    assert_eq!(result.action, PolicyAction::Permit);
    assert_eq!(result.modifications.as_path_prepend, Some((64500, 2)));
    assert_eq!(result.modifications.as_path_prepend_computed, None);
}

#[test]
fn prepend_self_resolves_from_chain_local_asn() {
    let mut chain = compile_ok("policy p { term t { prepend as self 4; accept } }");
    chain.local_asn = Some(64512);
    let result = chain.evaluate(&prepend_ctx(None, None));
    assert_eq!(result.action, PolicyAction::Permit);
    assert_eq!(result.modifications.as_path_prepend, Some((64512, 4)));
    assert_eq!(result.modifications.as_path_prepend_computed, None);
}

/// Missing context fails the route CLOSED (uniform Deny) — and never
/// prepends ASN 0. Covers all three operands, plus a zero context
/// value (RFC 7607: AS 0 must never reach the wire).
#[test]
fn computed_prepend_missing_context_fails_closed() {
    let cases: [(&str, RouteContext<'static>); 4] = [
        ("peer", prepend_ctx(None, Some(64500))),
        ("origin", prepend_ctx(Some(65010), None)),
        ("self", prepend_ctx(Some(65010), Some(64500))),
        // Zero peer ASN counts as unknown.
        ("peer", prepend_ctx(Some(0), Some(64500))),
    ];
    for (operand, ctx) in cases {
        let chain = compile_ok(&format!(
            "policy p {{ term t {{ prepend as {operand} 3; accept }} }}"
        ));
        // No local_asn stamped: the `self` case is the missing case.
        let result = chain.evaluate(&ctx);
        assert_eq!(result.action, PolicyAction::Deny, "operand {operand}");
        assert!(
            result.modifications.is_empty(),
            "fail closed discards staged modifications ({operand})"
        );
    }
}

/// A Continue term's failing computed operand also denies (the action
/// executes when the term matches, even without a verdict).
#[test]
fn computed_prepend_failure_in_continue_term_denies() {
    let chain = compile_ok(
        "policy p {
            term tag { prepend as origin 1 }
            term rest { accept }
        }",
    );
    let result = chain.evaluate(&prepend_ctx(None, None));
    assert_eq!(result.action, PolicyAction::Deny);
    // With an origin present the same chain permits.
    let result = chain.evaluate(&prepend_ctx(None, Some(64500)));
    assert_eq!(result.action, PolicyAction::Permit);
    assert_eq!(result.modifications.as_path_prepend, Some((64500, 1)));
}

/// `prepend as peer` is peer-dependent for update-group
/// fingerprinting; `self` and `origin` are not (they must never
/// disqualify grouping).
#[test]
fn computed_prepend_peer_context_flags() {
    let peer_chain = compile_ok("policy p { term t { prepend as peer 3; accept } }");
    assert!(peer_chain.requires_peer_context());
    assert!(peer_chain.peer_prepend_action().is_some());

    for operand in ["self", "origin"] {
        let chain = compile_ok(&format!(
            "policy p {{ term t {{ prepend as {operand} 3; accept }} }}"
        ));
        assert!(!chain.requires_peer_context(), "operand {operand}");
        assert!(chain.peer_prepend_action().is_none(), "operand {operand}");
    }
    // Literal prepends never flag either.
    let literal = compile_ok("policy p { term t { prepend as 65001 3; accept } }");
    assert!(!literal.requires_peer_context());
}

/// Literal and computed prepends share one merge slot: the later term
/// wins regardless of form.
#[test]
fn computed_and_literal_prepends_share_the_merge_slot() {
    let chain = compile_ok(
        "policy p {
            term tag { prepend as origin 2 }
            term decide { prepend as 65001 1; accept }
        }",
    );
    let result = chain.evaluate(&prepend_ctx(None, Some(64500)));
    assert_eq!(result.action, PolicyAction::Permit);
    assert_eq!(result.modifications.as_path_prepend, Some((65001, 1)));

    let chain = compile_ok(
        "policy p {
            term tag { prepend as 65001 1 }
            term decide { prepend as origin 2; accept }
        }",
    );
    let result = chain.evaluate(&prepend_ctx(None, Some(64500)));
    assert_eq!(result.modifications.as_path_prepend, Some((64500, 2)));
}

/// `evaluate_recording_hits` (the `rbgp policy test` backend) applies
/// the same resolution and fail-closed rules as the live walk.
#[test]
fn recording_hits_resolves_and_fails_closed_like_live_eval() {
    let chain = compile_ok("policy p { term t { prepend as peer 3; accept } }");
    for ctx in [prepend_ctx(Some(65010), None), prepend_ctx(None, None)] {
        let mut hits = chain.zero_term_hits();
        let recorded = chain.evaluate_recording_hits(&ctx, &mut hits);
        let live = chain.evaluate(&ctx);
        assert_eq!(recorded, live);
        assert_eq!(hits, vec![vec![1]], "matched term still counts");
    }
}

/// Explain traces render the source-level operand — and agree with
/// the live verdict, including the fail-closed case.
#[test]
fn computed_prepend_explain_renders_operand_and_agrees() {
    use crate::engine::PolicyChain;
    use crate::engine::explain::explain_chain_statements;

    let mut compiled = compile_ok("policy p { term t { prepend as peer 3; accept } }");
    compiled.local_asn = Some(64512);
    let chain = PolicyChain::from_named(vec![crate::NamedPolicy::from_rpol(
        "p".to_string(),
        std::sync::Arc::new(compiled),
    )]);

    // Resolvable: permit, with the operand rendered in both the static
    // term line and the resolved before→after modification line.
    let ctx = prepend_ctx(Some(65010), None);
    let trace = explain_chain_statements(Some(&chain), &ctx);
    assert_eq!(trace.action, chain.evaluate(&ctx).action);
    assert_eq!(trace.action, PolicyAction::Permit);
    let step = &trace.steps[0];
    assert!(
        step.term_traces
            .iter()
            .any(|line| line.contains("prepend as peer 3")),
        "term trace renders the source operand: {:?}",
        step.term_traces
    );
    assert!(
        step.modifications
            .iter()
            .any(|line| line.contains("as_path prepend peer=65010 x3")),
        "modifications render operand + resolved value: {:?}",
        step.modifications
    );

    // Unresolvable: fail-closed deny, rendered in the trace and in
    // agreement with the live walk.
    let ctx = prepend_ctx(None, None);
    let trace = explain_chain_statements(Some(&chain), &ctx);
    assert_eq!(trace.action, chain.evaluate(&ctx).action);
    assert_eq!(trace.action, PolicyAction::Deny);
    let step = &trace.steps[0];
    assert!(
        step.term_traces
            .iter()
            .any(|line| line.contains("prepend as peer unresolvable")
                && line.contains("fail closed")),
        "failure is explainable: {:?}",
        step.term_traces
    );
    assert!(step.modifications.is_empty(), "a deny contributes no mods");
}

/// In-language `test` fixtures cover all three operands: `peer { asn }`
/// backs `peer`, the as-path fixture backs `origin`, and the new
/// `peer { local-as }` field backs `self`.
#[test]
fn in_language_tests_cover_computed_operands() {
    let source = r#"
policy peer-pad { term t { prepend as peer 3; accept } }
policy origin-pad { term t { prepend as origin 2; accept } }
policy self-pad { term t { prepend as self 4; accept } }

test peer-operand {
    route { prefix 10.0.0.0/24 }
    peer { asn 65010 }
    expect peer-pad == accept with prepend as 65010 3
}

test origin-operand {
    route { prefix 10.0.0.0/24; as-path "65010 64500" }
    expect origin-pad == accept with prepend as 64500 2
}

test self-operand {
    route { prefix 10.0.0.0/24 }
    peer { asn 65010; local-as 64512 }
    expect self-pad == accept with prepend as 64512 4
}

test missing-origin-fails-closed {
    route { prefix 10.0.0.0/24; as-path "{64500 64501}" }
    expect origin-pad == error absent-prepend-operand
}

test missing-peer-fails-closed {
    route { prefix 10.0.0.0/24 }
    expect peer-pad == error absent-prepend-operand
}

test missing-local-as-fails-closed {
    route { prefix 10.0.0.0/24 }
    peer { asn 65010 }
    expect self-pad == error absent-prepend-operand
}
"#;
    let report = run_rpol_tests(source).expect("compiles");
    assert_eq!(report.total, 6);
    assert!(report.all_passed(), "failures: {:?}", report.failures);
}

// ── LAN-299: typed arithmetic, value comparisons, eval-error rails ──

/// `set med 25 + 25` must compile to *exactly* what `set med 50`
/// compiles to (constant folding at lower time, checked ops), so the
/// evaluator, memoization, diffing, and every downstream consumer see
/// identical `RouteModifications`.
#[test]
fn constant_arithmetic_actions_fold_to_literals() {
    let folded =
        compile_ok("policy p { term t { set med 25 + 25; set local-pref 2 * 100; accept } }");
    let literal = compile_ok("policy p { term t { set med 50; set local-pref 200; accept } }");
    assert_eq!(
        folded, literal,
        "constant arithmetic folds to the literal form"
    );
    let mods = first_term_mods(&folded);
    assert_eq!(mods.set_med, Some(50));
    assert_eq!(mods.set_local_pref, Some(200));
    assert!(mods.set_med_computed.is_none() && mods.set_local_pref_computed.is_none());

    // Builtins fold too, including through parameter substitution.
    let chain = compile_ok(
        "policy q(n: u32) { term t { set med min(n * 2, 400); accept } }
         policy p { term t { if apply(q(50)) { accept } } }",
    );
    // q(50) is instantiated inside apply as a predicate — instantiate
    // it directly to observe the folded mods.
    let mut store = SetStore::new();
    let file =
        super::RpolFile::parse("policy q(n: u32) { term t { set med min(n * 2, 400); accept } }")
            .expect("clean");
    let inst = file
        .compile_policy("q", &[300], &mut store)
        .expect("exists");
    assert_eq!(
        first_term_mods(&inst).set_med,
        Some(400),
        "min(600, 400) folds"
    );
    drop(chain);
}

/// Kebab-case maximal munch is permanent (ADR-0103 Decision 2.1):
/// `route.med - 1` is subtraction, `route.med-1` is one identifier and
/// therefore an unknown-field error suggesting `med`.
#[test]
fn subtraction_requires_whitespace_around_minus() {
    let chain = reject_if("route.med - 1 >= 9");
    let med10 = RouteContext {
        med: Some(10),
        ..absent_ctx()
    };
    assert_eq!(chain.evaluate(&med10).action, PolicyAction::Deny, "9 >= 9");
    let med5 = RouteContext {
        med: Some(5),
        ..absent_ctx()
    };
    assert_eq!(chain.evaluate(&med5).action, PolicyAction::Permit, "4 < 9");

    let (_, rendered) = diagnostics_of("policy p { term t { if route.med-1 >= 9 { reject } } }");
    assert!(
        rendered.contains("unknown field `route.med-1`"),
        "maximal munch keeps `med-1` one identifier: {rendered}"
    );
    assert!(rendered.contains("did you mean `route.med`?"), "{rendered}");
}

/// The ADR guard example: arithmetic on both sides of a comparison,
/// with fields as operands (`route.as-path.len * 10 >= route.med`).
#[test]
fn value_comparisons_evaluate_both_sides() {
    let chain = reject_if("route.as-path.len * 10 >= route.med");
    let mut ctx = absent_ctx();
    ctx.as_path_len = 3;
    ctx.med = Some(30);
    assert_eq!(chain.evaluate(&ctx).action, PolicyAction::Deny, "30 >= 30");
    ctx.med = Some(31);
    assert_eq!(chain.evaluate(&ctx).action, PolicyAction::Permit, "30 < 31");

    // Precedence: `*` binds tighter than `+`, both tighter than the
    // comparison; parentheses group within value positions (a guard
    // may not *start* with a value parenthesis — `(` at guard start
    // opens a boolean group).
    let chain = reject_if("route.med + 2 * 3 == 16");
    let mut ctx = absent_ctx();
    ctx.med = Some(10);
    assert_eq!(
        chain.evaluate(&ctx).action,
        PolicyAction::Deny,
        "10 + 6 == 16"
    );
    let chain = reject_if("route.med == (2 + 4) * 2");
    ctx.med = Some(12);
    assert_eq!(
        chain.evaluate(&ctx).action,
        PolicyAction::Deny,
        "12 == 6 * 2"
    );
    let chain = reject_if("route.med * (route.med - 2) == 8");
    ctx.med = Some(4);
    assert_eq!(
        chain.evaluate(&ctx).action,
        PolicyAction::Deny,
        "4 * 2 == 8"
    );
}

/// Computed `set` values resolve per route at action execution; the
/// evaluation result carries only the literal field (the LAN-296
/// prepend discipline).
#[test]
fn computed_set_values_resolve_per_route() {
    let chain = compile_ok(
        "policy p { term t { set med route.med + 50; set local-pref min(route.local-pref * 2, 250); accept } }",
    );
    let mods = first_term_mods(&chain);
    assert!(mods.set_med.is_none() && mods.set_med_computed.is_some());
    let mut ctx = absent_ctx();
    ctx.med = Some(7);
    ctx.local_pref = Some(100);
    let result = chain.evaluate(&ctx);
    assert_eq!(result.action, PolicyAction::Permit);
    assert_eq!(result.modifications.set_med, Some(57));
    assert_eq!(result.modifications.set_local_pref, Some(200));
    assert!(
        result.modifications.set_med_computed.is_none()
            && result.modifications.set_local_pref_computed.is_none(),
        "downstream consumers only ever see literal values"
    );
    // Absent med/local-pref use the documented implicit defaults
    // (0 / 100), consistent with comparisons.
    let result = chain.evaluate(&absent_ctx());
    assert_eq!(result.modifications.set_med, Some(50));
    assert_eq!(result.modifications.set_local_pref, Some(200));
}

/// The eval-error rail end to end on the counting path: uniform Deny,
/// staged modifications (an earlier Continue term's) discarded, the
/// per-chain error counter incremented, hit counters untouched by the
/// error itself.
#[test]
fn eval_error_denies_discards_mods_and_counts() {
    use crate::eval::PolicyHitCounters;

    let chain = compile_ok(
        "policy p {
            term tag { set local-pref 200 }
            term guard { if route.med + 1 >= 1 { accept } }
            term rest { accept }
         }",
    );
    let counters = PolicyHitCounters::for_chain(&chain);

    // Normal route: Continue mods merge under the eventual accept.
    let mut ctx = absent_ctx();
    ctx.med = Some(5);
    let result = chain.evaluate_counting(&ctx, &counters);
    assert_eq!(result.action, PolicyAction::Permit);
    assert_eq!(result.modifications.set_local_pref, Some(200));
    assert_eq!(counters.eval_errors(), 0);

    // Overflowing route: `u32::MAX + 1` is an evaluation error →
    // uniform Deny, staged Continue mods discarded, counter bumped.
    ctx.med = Some(u32::MAX);
    let result = chain.evaluate_counting(&ctx, &counters);
    assert_eq!(result.action, PolicyAction::Deny);
    assert!(result.modifications.is_empty(), "staged mods discarded");
    assert_eq!(counters.eval_errors(), 1);
    assert_eq!(counters.evals(), 2);
    // LAN-301: the counters retain the last error with blame context
    // for the stats surface.
    let last = counters.last_error().expect("last error retained");
    assert_eq!(last.kind, crate::eval::EvalErrorKind::Overflow);
    assert_eq!(last.policy.as_deref(), Some("p"));
    assert_eq!(last.term.as_deref(), Some("guard"));
    assert_eq!(last.to_string(), "overflow in policy p term guard");

    // The recording walk (dry runs) agrees on the verdict.
    let mut hits = chain.zero_term_hits();
    let recorded = chain.evaluate_recording_hits(&ctx, &mut hits);
    assert_eq!(recorded.action, PolicyAction::Deny);
    assert!(recorded.modifications.is_empty());
    // Dry runs never move the live error counter.
    assert_eq!(counters.eval_errors(), 1);
}

/// An absent operand without a documented default (origin-as on an
/// AS_SET-only path, unknown peer.asn) is unresolvable → the same
/// eval-error rail. Plain (arithmetic-free) comparisons keep their
/// legacy never-match semantics — the two deliberately diverge.
#[test]
fn absent_operand_is_an_eval_error_not_a_non_match() {
    // Arithmetic form: absent origin denies the route.
    let arith = reject_if("route.origin-as * 1 == 64500");
    assert_eq!(
        arith.evaluate(&absent_ctx()).action,
        PolicyAction::Deny,
        "absent origin in arithmetic fails closed"
    );
    // Plain form: absent origin matches neither == nor != and the
    // route falls through to the accepting term.
    let plain = reject_if("route.origin-as == 64500");
    assert_eq!(
        plain.evaluate(&absent_ctx()).action,
        PolicyAction::Permit,
        "plain comparison keeps never-match-on-absent semantics"
    );
    // peer.asn as an operand behaves the same.
    let peer = reject_if("peer.asn + 0 == 65010");
    assert_eq!(peer.evaluate(&absent_ctx()).action, PolicyAction::Deny);
    let mut ctx = absent_ctx();
    ctx.peer_asn = Some(65010);
    assert_eq!(
        peer.evaluate(&ctx).action,
        PolicyAction::Deny,
        "matches → reject term fires"
    );
}

/// min/max/clamp evaluate per route with checked operand evaluation;
/// a data-dependent inverted clamp is an eval error.
#[test]
fn builtin_edges_evaluate_and_inverted_clamp_fails_closed() {
    let chain = compile_ok("policy p { term t { set med clamp(route.med, 10, 20); accept } }");
    for (med, expected) in [(5u32, 10u32), (15, 15), (25, 20), (10, 10), (20, 20)] {
        let mut ctx = absent_ctx();
        ctx.med = Some(med);
        assert_eq!(
            chain.evaluate(&ctx).modifications.set_med,
            Some(expected),
            "clamp({med}, 10, 20)"
        );
    }
    // Parameter-dependent inversion is invisible to the typechecker
    // (it only folds literals) and fails per route, closed.
    let mut store = SetStore::new();
    let file = super::RpolFile::parse(
        "policy q(lo: u32, hi: u32) { term t { set med clamp(route.med, lo, hi); accept } }",
    )
    .expect("clean");
    let inverted = file
        .compile_policy("q", &[20, 10], &mut store)
        .expect("exists");
    assert_eq!(inverted.evaluate(&absent_ctx()).action, PolicyAction::Deny);
}

/// Statically invalid constant expressions are compile errors at the
/// failing subexpression's span, not per-route runtime errors.
#[test]
fn constant_folding_diagnostics_carry_spans() {
    let src = "policy p { term t { set med 4294967295 + 1; accept } }";
    let (diags, rendered) = diagnostics_of(src);
    assert!(
        rendered.contains("this expression always fails: arithmetic overflow"),
        "{rendered}"
    );
    let (span, _) = diags.0[0].labels[0];
    assert_eq!(
        &src[span.range()],
        "4294967295 + 1",
        "span pins the expression"
    );

    let (_, rendered) = diagnostics_of("policy p { term t { set med 1 / 0; accept } }");
    assert!(rendered.contains("division by zero"), "{rendered}");

    let (_, rendered) = diagnostics_of("policy p { term t { set med clamp(5, 10, 2); accept } }");
    assert!(
        rendered.contains("clamp bounds are inverted: lo (10) > hi (2)"),
        "{rendered}"
    );

    // The error reports at the smallest failing subexpression, once.
    let src = "policy p { term t { if route.med >= (4294967295 + 1) * 2 { reject } } }";
    let (diags, rendered) = diagnostics_of(src);
    assert_eq!(
        diags.len(),
        1,
        "one diagnostic, at the inner overflow: {rendered}"
    );
    let (span, _) = diags.0[0].labels[0];
    assert_eq!(&src[span.range()], "4294967295 + 1");
}

/// Builtin misuse diagnostics: unknown names get did-you-mean, wrong
/// arity says what was expected, non-u32 fields are rejected as
/// operands.
#[test]
fn value_expression_type_diagnostics() {
    let (_, rendered) = diagnostics_of("policy p { term t { set med mim(1, 2); accept } }");
    assert!(
        rendered.contains("unknown function or builtin `mim`"),
        "{rendered}"
    );
    assert!(rendered.contains("did you mean `min`?"), "{rendered}");

    let (_, rendered) = diagnostics_of("policy p { term t { set med min(1); accept } }");
    assert!(
        rendered.contains("`min` takes 2 arguments but 1 was supplied"),
        "{rendered}"
    );

    let (_, rendered) = diagnostics_of("policy p { term t { if route.rpki + 1 >= 2 { reject } } }");
    assert!(
        rendered.contains("`route.rpki` is not a u32 field"),
        "{rendered}"
    );

    let (_, rendered) =
        diagnostics_of("policy p { term t { set med route.med + peer_lp; accept } }");
    assert!(
        rendered.contains("unknown parameter or binding `peer_lp`"),
        "{rendered}"
    );
}

/// Arithmetic chains count toward the expression-depth budget like
/// `&&`/`||` chains: a pathological operator run is a diagnostic, not
/// a lowering/evaluation hazard.
#[test]
fn deep_arithmetic_chains_are_depth_diagnostics() {
    let ones = " + 1".repeat(200);
    let report = check_on_small_stack(format!(
        "policy p {{ term t {{ set med 1{ones}; accept }} }}"
    ));
    let rendered = format!("{:?}", report.diagnostics);
    assert!(
        rendered.contains("expression nesting exceeds"),
        "want the depth diagnostic, got: {rendered:.300}"
    );
}

/// `peer.asn` as a value-expression operand reads peer identity and
/// must disqualify update-group sharing; route-field arithmetic must
/// not (grouping stays unaffected).
#[test]
fn peer_asn_operand_registers_peer_context() {
    let peer_guard = reject_if("route.med + peer.asn >= 100");
    assert!(peer_guard.requires_peer_context());

    let route_only = reject_if("route.med * 2 >= route.as-path.len + 10");
    assert!(!route_only.requires_peer_context());

    let peer_action = compile_ok("policy p { term t { set med peer.asn + 1; accept } }");
    assert!(
        peer_action.requires_peer_context(),
        "computed set value reading peer.asn"
    );

    let route_action = compile_ok("policy p { term t { set med route.med + 1; accept } }");
    assert!(!route_action.requires_peer_context());
}

/// Guard evaluation errors render in explain traces in place of a
/// verdict, in agreement with the live walk (ADR-0103 Decision 6.4).
#[test]
fn eval_error_explain_renders_and_agrees() {
    use crate::engine::PolicyChain;
    use crate::engine::explain::explain_chain_statements;

    let compiled = compile_ok(
        "policy p { term big-med { if route.med + 1 >= 1 { reject } } term rest { accept } }",
    );
    let chain = PolicyChain::from_named(vec![crate::NamedPolicy::from_rpol(
        "p".to_string(),
        std::sync::Arc::new(compiled),
    )]);

    let mut ctx = absent_ctx();
    ctx.med = Some(u32::MAX);
    let trace = explain_chain_statements(Some(&chain), &ctx);
    assert_eq!(trace.action, chain.evaluate(&ctx).action);
    assert_eq!(trace.action, PolicyAction::Deny);
    let step = &trace.steps[0];
    assert_eq!(step.term_name.as_deref(), Some("big-med"));
    assert!(
        step.term_traces.iter().any(|line| line
            .contains("route.med + 1 >= 1 => evaluation error: arithmetic overflow")
            && line.contains("fail closed")),
        "error renders in place of a verdict: {:?}",
        step.term_traces
    );
    assert!(step.modifications.is_empty());

    // Computed set values render in source form in the action lines.
    let compiled = compile_ok("policy p { term t { set med route.med + 50; accept } }");
    let chain = PolicyChain::from_named(vec![crate::NamedPolicy::from_rpol(
        "p".to_string(),
        std::sync::Arc::new(compiled),
    )]);
    let mut ctx = absent_ctx();
    ctx.med = Some(7);
    let trace = explain_chain_statements(Some(&chain), &ctx);
    let step = &trace.steps[0];
    assert!(
        step.term_traces
            .iter()
            .any(|line| line.contains("set med route.med + 50")),
        "{:?}",
        step.term_traces
    );
    assert!(
        step.modifications
            .iter()
            .any(|line| line.contains("med 7 -> route.med + 50 = 57")),
        "{:?}",
        step.modifications
    );
}

/// In-language `test` fixtures exercise the boundary arithmetic and
/// the deny-on-error contract end to end through `rbgp policy check`.
#[test]
fn in_language_tests_cover_arithmetic_boundaries() {
    let source = r#"
policy overflow-guard { term t { if route.med + 1 >= 1 { accept } } term rest { reject } }
policy div-zero { term t { if route.med / 0 >= 0 { accept } } term rest { reject } }
policy mod-zero { term t { if route.med % route.med >= 0 { accept } } term rest { reject } }
policy absent-origin { term t { if route.origin-as * 1 >= 0 { accept } } term rest { reject } }
policy folded-parity(bump: u32) { term t { set med 25 + 25; set local-pref bump * 2; accept } }
policy builtin-edges {
    term t { set med max(min(route.med, 400), 100); accept }
}

test overflow-denies {
    route { med 4294967295 }
    expect overflow-guard == error overflow
}

test no-overflow-accepts {
    route { med 5 }
    expect overflow-guard == accept
}

test divide-by-zero-denies {
    route { med 5 }
    expect div-zero == error divide-by-zero
}

test modulo-zero-denies {
    route { }
    expect mod-zero == error remainder-by-zero
}

test absent-origin-denies {
    route { as-path "{64500 64501}" }
    expect absent-origin == error absent-operand
}

test present-origin-accepts {
    route { as-path "65010 64500" }
    expect absent-origin == accept
}

test folded-constants-match-literals {
    route { }
    expect folded-parity(100) == accept with med 50, local-pref 200
}

test builtin-clamps-low {
    route { med 5 }
    expect builtin-edges == accept with med 100
}

test builtin-clamps-high {
    route { med 900 }
    expect builtin-edges == accept with med 400
}

test builtin-passes-middle {
    route { med 250 }
    expect builtin-edges == accept with med 250
}
"#;
    let report = run_rpol_tests(source).expect("compiles cleanly");
    assert_eq!(report.total, 10);
    assert!(report.all_passed(), "failures: {:?}", report.failures);
}

// ── LAN-301: `expect ... == error [KIND]` and eval-error observability ──

/// The bare and kind-pinned `error` expectation forms pass on the
/// rails they pin, and the kind mismatch renders both kinds.
#[test]
fn error_expectation_pins_the_fail_closed_rail() {
    let source = r"
policy overflowing { term t { if route.med + 1 >= 1 { accept } } term rest { reject } }

test any-error-passes {
    route { med 4294967295 }
    expect overflowing == error
}

test kind-pinned-passes {
    route { med 4294967295 }
    expect overflowing == error overflow
}
";
    let report = run_rpol_tests(source).expect("compiles cleanly");
    assert!(report.all_passed(), "failures: {:?}", report.failures);
}

/// A clean verdict is not an error (and vice versa): `== error` fails
/// on a clean reject, `== reject` fails on an erroring evaluation with
/// the error (kind, policy, term) rendered, and a kind-pinned `error`
/// fails on a different kind.
#[test]
fn error_expectation_mismatches_render_the_divergence() {
    let source = r"
policy clean-reject { term t { reject } }
policy overflowing { term t { if route.med + 1 >= 1 { accept } } term rest { reject } }

test clean-reject-is-not-an-error {
    route { }
    expect clean-reject == error
}

test error-is-not-a-clean-reject {
    route { med 4294967295 }
    expect overflowing == reject
}

test wrong-kind-fails {
    route { med 4294967295 }
    expect overflowing == error divide-by-zero
}
";
    let report = run_rpol_tests(source).expect("compiles cleanly");
    assert_eq!(report.total, 3);
    assert_eq!(report.failures.len(), 3, "{:?}", report.failures);
    let by_name = |name: &str| {
        report
            .failures
            .iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("{name} should fail"))
            .message
            .clone()
    };
    assert!(
        by_name("clean-reject-is-not-an-error")
            .contains("expected an evaluation error, got reject"),
        "{:?}",
        report.failures
    );
    let msg = by_name("error-is-not-a-clean-reject");
    assert!(
        msg.contains(
            "expected reject, got evaluation error: overflow in policy overflowing term t"
        ),
        "{msg}"
    );
    assert!(
        msg.contains("use `== error overflow`"),
        "steers to the pinning form: {msg}"
    );
    let msg = by_name("wrong-kind-fails");
    assert!(
        msg.contains("expected error divide-by-zero, got error overflow"),
        "{msg}"
    );
}

/// An unknown error kind after `== error` is a compile diagnostic with
/// a closest-label suggestion, and `with` assertions cannot follow
/// `== error` (an error discards all modifications).
#[test]
fn error_expectation_grammar_diagnostics() {
    let (_, rendered) = diagnostics_of(
        "policy p { term t { reject } }
         test t { route { } expect p == error divide-by-zeroo }",
    );
    assert!(
        rendered.contains("`divide-by-zeroo` is not an evaluation-error kind"),
        "{rendered}"
    );
    assert!(
        rendered.contains("did you mean `divide-by-zero`?"),
        "{rendered}"
    );

    let (_, rendered) = diagnostics_of(
        "policy p { term t { reject } }
         test t { route { } expect p == error with med 5 }",
    );
    assert!(
        rendered.contains("`with` assertions cannot follow `== error`"),
        "{rendered}"
    );
}

/// `error` stays contextual: a policy (or set) named `error` keeps
/// compiling and keeps being referencable from expects.
#[test]
fn policy_named_error_still_works() {
    let source = r"
policy error { term t { accept } }

test error-policy-accepts {
    route { }
    expect error == accept
}
";
    let report = run_rpol_tests(source).expect("compiles cleanly");
    assert!(report.all_passed(), "failures: {:?}", report.failures);
}

/// The attribution surface carries the evaluation error (LAN-301):
/// `eval_error` is `Some` with kind/policy/term on the error rail and
/// `None` on a clean deny — the discriminator the test runner and the
/// metrics sites read.
#[test]
fn evaluation_carries_eval_error_on_the_error_rail_only() {
    let chain = compile_ok(
        "policy p {
            term guard { if route.med + 1 >= 1 { accept } }
            term rest { reject }
         }",
    );
    let mut ctx = absent_ctx();
    ctx.med = Some(u32::MAX);
    let (result, evaluation) = chain.evaluate_with_attribution(&ctx);
    assert_eq!(result.action, PolicyAction::Deny);
    let error = evaluation.eval_error.expect("error rail carries blame");
    assert_eq!(error.kind, crate::eval::EvalErrorKind::Overflow);
    assert_eq!(error.policy.as_deref(), Some("p"));
    assert_eq!(error.term.as_deref(), Some("guard"));

    ctx.med = Some(1);
    let (result, evaluation) = chain.evaluate_with_attribution(&ctx);
    assert_eq!(result.action, PolicyAction::Permit);
    assert_eq!(evaluation.eval_error, None);

    // Clean deny (guard non-match falls to the reject term): no error.
    let clean = compile_ok("policy p { term t { reject } }");
    let (result, evaluation) = clean.evaluate_with_attribution(&absent_ctx());
    assert_eq!(result.action, PolicyAction::Deny);
    assert_eq!(evaluation.eval_error, None);
}

// ── `let` bindings (LAN-302) ───────────────────────────────────────

/// The issue's surface example: term-body `let`s lower to Bind terms
/// with sequential slots, are readable in guards (including as the
/// LEFT side of a comparison) and in `set` value expressions, and the
/// policy evaluates them per route.
#[test]
fn let_bindings_lower_to_bind_terms_and_evaluate() {
    let chain = compile_ok(
        "policy p {
            term score {
                let origin = route.origin-as
                let penalty = route.as-path.len * 10
                if penalty >= route.med { reject }
                if origin == 64500 { set med penalty; accept }
            }
            term rest { accept }
         }",
    );

    // IR shape: two Bind terms, slots 0 and 1, guarded by True.
    let terms = &chain.policies[0].terms;
    let binds: Vec<(u8, &str)> = terms
        .iter()
        .filter_map(|term| match &term.action {
            TermAction::Bind { slot, name, .. } => Some((*slot, &**name)),
            _ => None,
        })
        .collect();
    assert_eq!(binds, vec![(0, "origin"), (1, "penalty")]);

    // Route: origin 64500, path len 2 → penalty 20, med 100 → accept
    // with med 20 (a binding read inside a body's set expression).
    let mut ctx = absent_ctx();
    ctx.as_path_len = 2;
    ctx.origin_asn = Some(64500);
    ctx.med = Some(100);
    let result = chain.evaluate(&ctx);
    assert_eq!(result.action, PolicyAction::Permit);
    assert_eq!(result.modifications.set_med, Some(20));

    // Route: med 5 → penalty 20 >= 5 → reject.
    ctx.med = Some(5);
    assert_eq!(chain.evaluate(&ctx).action, PolicyAction::Deny);
}

/// Deterministic shadowing: a `let` may shadow a parameter and an
/// outer binding; the innermost declaration wins in value positions,
/// and initializers read the scope *before* their own declaration.
#[test]
fn let_shadows_parameters_and_outer_bindings() {
    let mut store = SetStore::new();
    let file = super::RpolFile::parse(
        "policy p(x: u32) {
            term t {
                let x = x + 1
                let x = x * 2
                if route.med >= 1 { let x = x + 100; set med x; set local-pref x }
                accept
            }
         }",
    )
    .expect("compiles");
    let chain = file.compile_policy("p", &[10], &mut store).expect("policy");
    let mut ctx = absent_ctx();
    ctx.med = Some(1);
    let result = chain.evaluate(&ctx);
    assert_eq!(result.action, PolicyAction::Permit);
    // param 10 → +1 = 11 → *2 = 22 → body +100 = 122.
    assert_eq!(result.modifications.set_med, Some(122));
    assert_eq!(result.modifications.set_local_pref, Some(122));
}

/// Shadowing a contextual identifier is position-typed (the #764
/// `origin` precedent): `let origin` wins in value positions while
/// `prepend as origin` keeps its computed-operand meaning.
#[test]
fn let_origin_shadows_only_value_positions() {
    let chain = compile_ok(
        "policy p {
            term t {
                let origin = 7
                set med origin
                prepend as origin 2
                accept
            }
         }",
    );
    let mut ctx = absent_ctx();
    ctx.origin_asn = Some(64496);
    let result = chain.evaluate(&ctx);
    assert_eq!(result.action, PolicyAction::Permit);
    assert_eq!(
        result.modifications.set_med,
        Some(7),
        "value position: the binding"
    );
    assert_eq!(
        result.modifications.as_path_prepend,
        Some((64496, 2)),
        "operand position: the route's origin AS"
    );
}

/// Branch visibility: a `let` inside an `if` (or `else`) body is not
/// visible outside it — afterwards in the term, or in the other branch.
#[test]
fn branch_locals_are_scoped_to_their_body() {
    let (_, rendered) = diagnostics_of(
        "policy p { term t { if route.med >= 10 { let x = 1; set med x } set local-pref x; accept } }",
    );
    assert!(
        rendered.contains("unknown parameter or binding `x`"),
        "{rendered}"
    );

    let (_, rendered) = diagnostics_of(
        "policy p { term t { if route.med >= 10 { let x = 1 } else { set med x } accept } }",
    );
    assert!(
        rendered.contains("unknown parameter or binding `x`"),
        "{rendered}"
    );

    // And bindings never cross terms.
    let (_, rendered) =
        diagnostics_of("policy p { term a { let x = 1 } term b { set med x; accept } }");
    assert!(
        rendered.contains("unknown parameter or binding `x`"),
        "{rendered}"
    );
}

/// Definite assignment: use before definition is a compile error at
/// the use's span, not a runtime zero.
#[test]
fn use_before_definition_is_a_compile_error() {
    let (diags, rendered) = diagnostics_of("policy p { term t { set med y; let y = 5; accept } }");
    assert!(
        rendered.contains("unknown parameter or binding `y`"),
        "{rendered}"
    );
    assert!(!diags.0.is_empty());
}

/// The `MAX_LOCALS` boundary: 64 bindings in one scope compile; the
/// 65th is rejected with a span. A term scope plus a full body scope
/// (64 + 64 = the whole frame) still compiles and evaluates.
#[test]
fn slot_exhaustion_at_the_limit_boundary() {
    let lets = |n: usize| -> String {
        (0..n).fold(String::new(), |mut src, i| {
            use std::fmt::Write as _;
            let _ = write!(src, "let v{i} = {i}; ");
            src
        })
    };

    let ok = format!(
        "policy p {{ term t {{ {} set med v63; accept }} }}",
        lets(64)
    );
    let chain = compile_ok(&ok);
    let result = chain.evaluate(&absent_ctx());
    assert_eq!(result.action, PolicyAction::Permit);
    assert_eq!(result.modifications.set_med, Some(63));

    let over = format!("policy p {{ term t {{ {} accept }} }}", lets(65));
    let mut store = SetStore::new();
    let diags = compile_rpol(&over, &mut store).expect_err("65th binding rejected");
    let rendered = diags.render("test.rpol", &over, false);
    assert!(
        rendered.contains("more than 64 `let` bindings in one scope"),
        "{rendered}"
    );
    // Exactly one diagnostic: the cap fires once, at the 65th.
    assert_eq!(diags.0.len(), 1, "{rendered}");

    // Both nesting levels full: 64 term-scope + 64 body-scope bindings
    // fit the 128-slot frame exactly.
    let full = format!(
        "policy p {{ term t {{ {} if route.med >= 0 {{ {} set med b63 }} set local-pref v63; accept }} }}",
        lets(64),
        (0..64).fold(String::new(), |mut src, i| {
            use std::fmt::Write as _;
            let _ = write!(src, "let b{i} = v63 + {i}; ");
            src
        }),
    );
    let chain = compile_ok(&full);
    let result = chain.evaluate(&absent_ctx());
    assert_eq!(result.action, PolicyAction::Permit);
    assert_eq!(result.modifications.set_med, Some(63 + 63));
    assert_eq!(result.modifications.set_local_pref, Some(63));
}

/// Initializers ride the LAN-299 eval-error rails: a checked-arithmetic
/// failure (or absent operand) in a `let` initializer is the same
/// uniform Deny — staged modifications discarded, error counter
/// bumped — whether or not the binding is ever read.
#[test]
fn initializer_errors_deny_and_discard_staged_mods() {
    use crate::eval::PolicyHitCounters;

    let chain = compile_ok(
        "policy p {
            term t {
                set local-pref 500
                let x = route.med - 100
                set med x
                accept
            }
         }",
    );
    let counters = PolicyHitCounters::for_chain(&chain);

    // med 200: x = 100, everything applies.
    let mut ctx = absent_ctx();
    ctx.med = Some(200);
    let result = chain.evaluate_counting(&ctx, &counters);
    assert_eq!(result.action, PolicyAction::Permit);
    assert_eq!(result.modifications.set_local_pref, Some(500));
    assert_eq!(result.modifications.set_med, Some(100));
    assert_eq!(counters.eval_errors(), 0);

    // med 5: `5 - 100` underflows in the initializer → uniform Deny,
    // the staged local-pref discarded, counter bumped.
    ctx.med = Some(5);
    let result = chain.evaluate_counting(&ctx, &counters);
    assert_eq!(result.action, PolicyAction::Deny);
    assert!(result.modifications.is_empty(), "staged mods discarded");
    assert_eq!(counters.eval_errors(), 1);

    // The recording walk (dry runs) agrees.
    let mut hits = chain.zero_term_hits();
    let recorded = chain.evaluate_recording_hits(&ctx, &mut hits);
    assert_eq!(recorded.action, PolicyAction::Deny);
    assert!(recorded.modifications.is_empty());

    // An initializer that never reads its binding still errors: eager,
    // not lazy (an unused erroring binding denies).
    let chain = compile_ok(
        "policy p { term t { let unused = route.origin-as; accept } term rest { accept } }",
    );
    let ctx = absent_ctx(); // no origin → absent operand
    assert_eq!(chain.evaluate(&ctx).action, PolicyAction::Deny);
}

/// A `let` executes at its statement position: a decision *before* it
/// short-circuits the walk and the initializer never runs.
#[test]
fn let_after_a_decision_never_evaluates() {
    let chain = compile_ok(
        "policy p {
            term t {
                if route.med >= 100 { accept }
                let x = route.origin-as
                if x == 1 { reject }
                accept
            }
         }",
    );
    // med 200, absent origin: decided before the let → no error.
    let mut ctx = absent_ctx();
    ctx.med = Some(200);
    assert_eq!(chain.evaluate(&ctx).action, PolicyAction::Permit);
    // med 5, absent origin: the let runs and errors → Deny.
    ctx.med = Some(5);
    assert_eq!(chain.evaluate(&ctx).action, PolicyAction::Deny);
    // Same rule inside a branch: an untaken branch's binding never
    // evaluates; a taken branch's binding evaluates even if unused.
    let chain =
        compile_ok("policy p { term t { if route.med >= 10 { let x = route.origin-as } accept } }");
    let mut ctx = absent_ctx();
    ctx.med = Some(5);
    assert_eq!(chain.evaluate(&ctx).action, PolicyAction::Permit);
    ctx.med = Some(20);
    assert_eq!(chain.evaluate(&ctx).action, PolicyAction::Deny);
}

/// The staged-mutation pin from the issue: reads always observe the
/// ORIGINAL route — `set med 500` stages, and a following
/// `let x = route.med` still sees the pre-staging MED. Read-back is
/// out of scope (it breaks memoization; needs its own ADR).
#[test]
fn reads_see_the_original_route_never_staged_writes() {
    let chain = compile_ok(
        "policy p {
            term t {
                set med 500
                let x = route.med
                if x >= 500 { reject }
                set local-pref x
                accept
            }
         }",
    );
    let mut ctx = absent_ctx();
    ctx.med = Some(7);
    let result = chain.evaluate(&ctx);
    // If reads observed staged writes, x would be 500 and the route
    // would have been rejected.
    assert_eq!(result.action, PolicyAction::Permit);
    assert_eq!(result.modifications.set_med, Some(500));
    assert_eq!(
        result.modifications.set_local_pref,
        Some(7),
        "x = original med"
    );
}

/// Reload determinism (ADR-0103 Decision 5): compiling the same source
/// twice yields structurally identical chains — term split, slot
/// assignment, everything the live-impact planner diffs.
#[test]
fn identical_source_compiles_to_identical_ir() {
    let source = "policy p {
        term t {
            let a = route.med + 1
            if route.as-path.len >= 2 { let b = a * 2; set med b }
            if route.as-path.len <= 1 { let c = a + 3; set med c }
            set local-pref a
            accept
        }
     }";
    assert_eq!(compile_ok(source), compile_ok(source));
}

/// Parity: factoring a repeated subexpression through a `let`
/// evaluates identically to the fully inlined form, across verdicts
/// and modifications.
#[test]
fn let_parity_with_inlined_form() {
    let with_let = compile_ok(
        "policy p {
            term t {
                let penalty = route.as-path.len * 10
                if penalty >= route.med { reject }
                if penalty <= 20 { set med penalty; accept }
            }
            term rest { accept }
         }",
    );
    let inlined = compile_ok(
        "policy p {
            term t {
                if route.as-path.len * 10 >= route.med { reject }
                if route.as-path.len * 10 <= 20 { set med route.as-path.len * 10; accept }
            }
            term rest { accept }
         }",
    );
    for len in [0usize, 1, 2, 3, 9] {
        for med in [0u32, 5, 20, 21, 100] {
            let mut ctx = absent_ctx();
            ctx.as_path_len = len;
            ctx.med = Some(med);
            assert_eq!(
                with_let.evaluate(&ctx),
                inlined.evaluate(&ctx),
                "len {len} med {med}"
            );
        }
    }
}

/// `apply` targets may not declare bindings this slice: the target
/// inlines as a pure predicate with no term walk to execute Bind
/// terms in (LAN-304 `fn` is the composition vehicle).
#[test]
fn apply_of_a_let_policy_is_rejected() {
    let (_, rendered) = diagnostics_of(
        "policy uses-let { term t { let x = 1; if route.med >= x { accept } } term rest { reject } }
         policy outer { term t { if apply(uses-let) { accept } } }",
    );
    assert!(
        rendered.contains("cannot `apply` policy `uses-let`: it declares `let` bindings"),
        "{rendered}"
    );
    assert!(rendered.contains("first `let` is here"), "{rendered}");
}

/// Bindings are runtime values: compile-time-constant positions
/// (prepend arguments, `apply` args, `contains`) reject them with a
/// dedicated diagnostic, not "unknown parameter".
#[test]
fn let_in_const_position_is_rejected() {
    let (_, rendered) =
        diagnostics_of("policy p { term t { let x = 3; prepend as 65001 x; accept } }");
    assert!(
        rendered.contains("prepend count must be a literal"),
        "{rendered}"
    );

    let (_, rendered) = diagnostics_of("policy p { term t { let x = 3; prepend as x 2; accept } }");
    assert!(rendered.contains("`x` is a `let` binding"), "{rendered}");
    assert!(rendered.contains("literal or parameter"), "{rendered}");

    // Enum positions are position-typed: the member spelling wins and
    // a non-member binding name is a type error, never a u32 read.
    let (_, rendered) =
        diagnostics_of("policy p { term t { let x = 1; if route.rpki == x { reject } accept } }");
    assert!(
        rendered.contains("`x` is a u32 `let` binding; `route.rpki` is an enum field"),
        "{rendered}"
    );
}

/// A binding read on the RIGHT of a plain u32-field comparison lowers
/// to the checked value-comparison node — fail-closed absent-operand
/// semantics, like every computed form.
#[test]
fn cmp_against_a_binding_lowers_to_value_cmp() {
    let chain = compile_ok(
        "policy p { term t { let x = 64500; if route.origin-as == x { reject } } term rest { accept } }",
    );
    // The guard is a ValueCmp, not an OriginAsEq scalar node.
    assert!(
        chain.policies[0].terms.iter().any(|term| matches!(
            &term.guard,
            crate::ir::MatchExpr::ValueCmp(node)
                if matches!(node.rhs, crate::ir::ValueExpr::Local { slot: 0, .. })
        )),
        "expected a ValueCmp guard reading slot 0"
    );
    // Present origin: matches → reject.
    let mut ctx = absent_ctx();
    ctx.origin_asn = Some(64500);
    assert_eq!(chain.evaluate(&ctx).action, PolicyAction::Deny);
    // Absent origin: computed form denies (eval error), unlike the
    // never-match scalar node.
    assert_eq!(chain.evaluate(&absent_ctx()).action, PolicyAction::Deny);
}

/// `peer.asn` in a `let` initializer reads peer identity — the chain
/// must disqualify update-group sharing even if the value is unused.
/// Bindings over route fields alone never do.
#[test]
fn peer_asn_initializer_registers_peer_context() {
    let peer = compile_ok("policy p { term t { let a = peer.asn; accept } }");
    assert!(peer.requires_peer_context());

    let route_only = compile_ok("policy p { term t { let a = route.med + 1; set med a; accept } }");
    assert!(!route_only.requires_peer_context());
}

/// Explain traces render Bind terms in source form, resolve binding
/// reads in modification lines, and agree with the live verdict —
/// including on initializer errors.
#[test]
fn let_explain_renders_and_agrees() {
    use crate::engine::PolicyChain;
    use crate::engine::explain::explain_chain_statements;

    let compiled = compile_ok(
        "policy p {
            term t {
                let x = route.med + 1
                set med x
                accept
            }
         }",
    );
    let chain = PolicyChain::from_named(vec![crate::NamedPolicy::from_rpol(
        "p".to_string(),
        std::sync::Arc::new(compiled),
    )]);
    let mut ctx = absent_ctx();
    ctx.med = Some(7);
    let trace = explain_chain_statements(Some(&chain), &ctx);
    assert_eq!(trace.action, chain.evaluate(&ctx).action);
    assert_eq!(trace.action, PolicyAction::Permit);
    let step = &trace.steps[0];
    assert!(
        step.term_traces
            .iter()
            .any(|line| line.contains("let x = route.med + 1")),
        "{:?}",
        step.term_traces
    );
    assert!(
        step.modifications
            .iter()
            .any(|line| line.contains("med 7 -> x = 8")),
        "{:?}",
        step.modifications
    );

    // An erroring initializer renders the error in place of a verdict
    // and the trace verdict agrees with the live Deny.
    let compiled =
        compile_ok("policy p { term t { let x = route.med - 100; accept } term rest { accept } }");
    let chain = PolicyChain::from_named(vec![crate::NamedPolicy::from_rpol(
        "p".to_string(),
        std::sync::Arc::new(compiled),
    )]);
    let mut ctx = absent_ctx();
    ctx.med = Some(5);
    let trace = explain_chain_statements(Some(&chain), &ctx);
    assert_eq!(trace.action, chain.evaluate(&ctx).action);
    assert_eq!(trace.action, PolicyAction::Deny);
    assert!(
        trace.steps[0].term_traces.iter().any(|line| line
            .contains("evaluation error: arithmetic underflow")
            && line.contains("fail closed")),
        "{:?}",
        trace.steps[0].term_traces
    );
}

/// `let` is contextual, not reserved (ADR-0103 Decision 2.2): sets and
/// parameters named `let` keep working.
#[test]
fn let_is_not_a_reserved_word() {
    let chain = compile_ok(
        "asn-set let { 64500 }
         policy p(let: u32) {
            term t { if route.med >= let { reject } }
            term o { if route.origin-as in let { reject } }
            term rest { accept }
         }",
    );
    // Zero-parameter chain skips the parameterized policy; the file
    // still typechecks and the set named `let` interned.
    assert_eq!(chain.asn_set_names[0].as_deref(), Some("let"));
}

/// In-language `test` fixtures exercise let-heavy policies end to end
/// through `rbgp policy check`.
#[test]
fn in_language_tests_cover_let_bindings() {
    let source = r#"
policy dampen {
    term score {
        let penalty = route.as-path.len * 10
        if penalty >= route.med { reject }
        set med penalty
        accept
    }
}
policy shadow(base: u32) {
    term t {
        let base = base + 1
        if route.med >= 1 { let base = base * 2; set local-pref base; accept }
        set local-pref base
        accept
    }
}
policy eager-error {
    term t { let x = route.origin-as; accept }
    term rest { accept }
}

test dampen-rejects-long-paths {
    route { as-path "65001 65002 65003"; med 25 }
    expect dampen == reject
}

test dampen-scores-short-paths {
    route { as-path "65001 65002"; med 100 }
    expect dampen == accept with med 20
}

test shadow-inner-binding-wins {
    route { med 5 }
    expect shadow(10) == accept with local-pref 22
}

test shadow-outer-binding-on-fallthrough {
    route { }
    expect shadow(10) == accept with local-pref 11
}

test absent-origin-initializer-denies {
    route { as-path "{64500 64501}" }
    expect eager-error == error absent-operand
}
"#;
    let report = run_rpol_tests(source).expect("compiles cleanly");
    assert_eq!(report.total, 5);
    assert!(report.all_passed(), "failures: {:?}", report.failures);
}

// ── bounded loops (LAN-303) ────────────────────────────────────────

/// A context with a typed `AS_PATH`: one `AS_SEQUENCE` plus an
/// optional trailing `AS_SET`, leaked like the other test contexts.
fn as_path_ctx(seq: &[u32], set: &[u32], communities: &[u32]) -> RouteContext<'static> {
    use rustbgpd_wire::{AsPath, AsPathSegment};
    let mut segments = Vec::new();
    if !seq.is_empty() {
        segments.push(AsPathSegment::AsSequence(seq.to_vec()));
    }
    if !set.is_empty() {
        segments.push(AsPathSegment::AsSet(set.to_vec()));
    }
    let path: &'static AsPath = Box::leak(Box::new(AsPath { segments }));
    RouteContext {
        as_path: Some(path),
        ..route_ctx(v4(10, 0, 0, 0, 24), communities, RpkiValidation::NotFound)
    }
}

const STD_65000_100: u32 = (65000 << 16) | 0x64;
const STD_65000_200: u32 = (65000 << 16) | 0xC8;
const STD_65001_1: u32 = (65001 << 16) | 0x1;

#[test]
fn loop_over_communities_guards_membership() {
    // Route-server shape: reject any route carrying a scrub-set
    // community, via per-element membership.
    let chain = compile_ok(
        "community-set scrub { 65000:100, 65000:200 }
         policy p { term t { for c in route.communities { if c in scrub { reject } } accept } }",
    );
    let tagged = route_ctx(
        v4(10, 0, 0, 0, 24),
        &[STD_65001_1, STD_65000_200],
        RpkiValidation::NotFound,
    );
    assert_eq!(chain.evaluate(&tagged).action, PolicyAction::Deny);
    let clean = route_ctx(
        v4(10, 0, 0, 0, 24),
        &[STD_65001_1],
        RpkiValidation::NotFound,
    );
    assert_eq!(chain.evaluate(&clean).action, PolicyAction::Permit);
}

#[test]
fn loop_scrub_removes_each_matching_community() {
    // The scrub loop proper: `remove community <loop-var>` stages the
    // matched value per iteration.
    let chain = compile_ok(
        "community-set scrub { 65000:100, 65000:200 }
         policy p { term t { for c in route.communities { if c in scrub { remove community c } } accept } }",
    );
    let ctx = route_ctx(
        v4(10, 0, 0, 0, 24),
        &[STD_65000_100, STD_65001_1, STD_65000_200],
        RpkiValidation::NotFound,
    );
    let result = chain.evaluate(&ctx);
    assert_eq!(result.action, PolicyAction::Permit);
    assert_eq!(
        result.modifications.communities_remove,
        vec![STD_65000_100, STD_65000_200],
        "each matched community staged, in iteration order"
    );
}

#[test]
fn loop_var_compares_against_community_literal() {
    // A standard community literal is a u32 in value position.
    let chain = compile_ok(
        "policy p { term t { for c in route.communities { if c == 65000:100 { reject } } accept } }",
    );
    let hit = route_ctx(
        v4(10, 0, 0, 0, 24),
        &[STD_65000_100],
        RpkiValidation::NotFound,
    );
    assert_eq!(chain.evaluate(&hit).action, PolicyAction::Deny);
    let miss = route_ctx(
        v4(10, 0, 0, 0, 24),
        &[STD_65000_200],
        RpkiValidation::NotFound,
    );
    assert_eq!(chain.evaluate(&miss).action, PolicyAction::Permit);
}

#[test]
fn as_path_iteration_wire_order_with_duplicates_and_sets() {
    // Every ASN in wire order: prepend duplicates preserved, AS_SET
    // members yielded individually. Observed via a per-iteration
    // community add (list adds accumulate per execution).
    let chain = compile_ok(
        "policy p { term t { for asn in route.as-path { add community 65009:9 } accept } }",
    );
    let ctx = as_path_ctx(&[65001, 65001, 65002], &[64500, 64501], &[]);
    let result = chain.evaluate(&ctx);
    assert_eq!(result.action, PolicyAction::Permit);
    assert_eq!(
        result.modifications.communities_add.len(),
        5,
        "3 sequence ASNs (duplicate prepend kept) + 2 AS_SET members"
    );
    // An absent typed path iterates zero times.
    let no_path = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
    assert!(
        chain
            .evaluate(&no_path)
            .modifications
            .communities_add
            .is_empty()
    );
}

#[test]
fn as_path_loop_asn_set_guard() {
    let chain = compile_ok(
        "asn-set bogons { 64512, 65535 }
         policy p { term t { for asn in route.as-path { if asn in bogons { reject } } accept } }",
    );
    assert_eq!(
        chain
            .evaluate(&as_path_ctx(&[65001, 64512], &[], &[]))
            .action,
        PolicyAction::Deny
    );
    assert_eq!(
        chain
            .evaluate(&as_path_ctx(&[65001, 65002], &[], &[]))
            .action,
        PolicyAction::Permit
    );
}

#[test]
fn set_iteration_is_canonical_order_and_deterministic() {
    // Reversed insertion order interns to the same canonical set, so
    // the compiled chains are equal and iteration order (observed via
    // per-iteration adds) is the sorted member order.
    let a = compile_ok(
        "asn-set s { 65003, 65001, 65002 }
         policy p { term t { for asn in s { add community 65009:9 } accept } }",
    );
    let b = compile_ok(
        "asn-set s { 65002, 65001, 65003, 65001 }
         policy p { term t { for asn in s { add community 65009:9 } accept } }",
    );
    assert_eq!(a, b, "reversed/duplicated insertion compiles identically");
    let ctx = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
    assert_eq!(a.evaluate(&ctx).modifications.communities_add.len(), 3);
    // Iteration order: prove via a value comparison that fires only on
    // the *first* element being the smallest member.
    let first_probe = compile_ok(
        "asn-set s { 65003, 65001, 65002 }
         policy p { term t { for asn in s { if asn == 65001 { reject } break } accept } }",
    );
    assert_eq!(
        first_probe.evaluate(&ctx).action,
        PolicyAction::Deny,
        "canonical (sorted) order iterates 65001 first"
    );
}

#[test]
fn break_exits_innermost_loop_only() {
    // Inner loop breaks on its first iteration; the outer loop still
    // runs every iteration. 3 outer × (1 inner add) + 3 outer adds.
    let chain = compile_ok(
        "asn-set outer { 1, 2, 3 }
         asn-set inner { 10, 20 }
         policy p { term t {
             for a in outer {
                 for b in inner { add community 65009:1; break }
                 add community 65009:2
             }
             accept
         } }",
    );
    let ctx = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
    let result = chain.evaluate(&ctx);
    assert_eq!(result.action, PolicyAction::Permit);
    assert_eq!(
        result.modifications.communities_add.len(),
        6,
        "3 inner first-iteration adds + 3 outer adds — break is loop-local"
    );
}

#[test]
fn continue_skips_to_next_iteration() {
    let chain = compile_ok(
        "asn-set s { 1, 2, 3, 4 }
         policy p { term t {
             for a in s {
                 if a <= 2 { continue }
                 add community 65009:9
             }
             accept
         } }",
    );
    let ctx = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
    let result = chain.evaluate(&ctx);
    assert_eq!(
        result.modifications.communities_add.len(),
        2,
        "elements 1 and 2 skipped by continue"
    );
}

#[test]
fn loop_var_scoping_and_shadowing() {
    // The loop var shadows an outer `let`; a body `let` shadows the
    // loop var; the outer binding is intact after the loop.
    let chain = compile_ok(
        "asn-set s { 7 }
         policy p { term t {
             let x = 100;
             for x in s {
                 let x = x + 1;
                 if x == 8 { add community 65009:8 }
             }
             set med x;
             accept
         } }",
    );
    let ctx = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
    let result = chain.evaluate(&ctx);
    assert_eq!(result.action, PolicyAction::Permit);
    assert_eq!(
        result.modifications.communities_add.len(),
        1,
        "body let read the loop var (7) and shadowed it with 8"
    );
    assert_eq!(
        result.modifications.set_med,
        Some(100),
        "outer binding unshadowed after the loop"
    );
}

#[test]
fn staged_add_never_extends_its_own_iteration() {
    // Reads see the arrived route (staged mods are not read back), so
    // a loop adding communities while iterating them runs exactly once
    // per *arrived* community — pinned against self-extension.
    let chain = compile_ok(
        "policy p { term t { for c in route.communities { add community 65009:9 } accept } }",
    );
    let ctx = route_ctx(
        v4(10, 0, 0, 0, 24),
        &[STD_65000_100, STD_65000_200],
        RpkiValidation::NotFound,
    );
    let result = chain.evaluate(&ctx);
    assert_eq!(result.action, PolicyAction::Permit);
    assert_eq!(
        result.modifications.communities_add.len(),
        2,
        "exactly one add per arrived community — no self-extension"
    );
}

#[test]
fn verdict_mid_loop_terminates_policy_with_staged_mods() {
    // `accept` inside the loop decides the policy at that iteration;
    // earlier iterations' staged modifications merge under it, and
    // later terms never run.
    let chain = compile_ok(
        "asn-set s { 1, 2, 3 }
         policy p {
             term t {
                 for a in s {
                     add community 65009:9;
                     if a == 2 { set med 42; accept }
                 }
             }
             term never { set local-pref 999; accept }
         }",
    );
    let ctx = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
    let result = chain.evaluate(&ctx);
    assert_eq!(result.action, PolicyAction::Permit);
    assert_eq!(result.modifications.set_med, Some(42));
    assert_eq!(
        result.modifications.communities_add.len(),
        2,
        "iterations 1 and 2 staged adds; iteration 3 never ran"
    );
    assert_eq!(
        result.modifications.set_local_pref, None,
        "later term never ran"
    );
}

#[test]
fn fuel_accounting_is_exact() {
    // Consumed fuel == loop iterations, nothing else: straight-line
    // code pays zero; nested loops pay per entered iteration.
    let flat = compile_ok(
        "asn-set s { 1, 2, 3, 4, 5 }
         policy p { term t { for a in s { if a == 0 { break } } accept } }",
    );
    let ctx = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
    let (result, consumed) = flat.evaluate_measuring_fuel(&ctx);
    assert_eq!(result.action, PolicyAction::Permit);
    assert_eq!(consumed, 5, "one fuel step per iteration, exactly");

    let nested = compile_ok(
        "asn-set outer { 1, 2, 3 }
         asn-set inner { 10, 20 }
         policy p { term t { for a in outer { for b in inner { if b == 0 { break } } } accept } }",
    );
    let (_, consumed) = nested.evaluate_measuring_fuel(&ctx);
    assert_eq!(
        consumed,
        3 + 3 * 2,
        "outer iterations + entered inner iterations"
    );

    let loop_free = compile_ok("policy p { term t { if route.med <= 100 { set med 5 } accept } }");
    let (_, consumed) = loop_free.evaluate_measuring_fuel(&ctx);
    assert_eq!(consumed, 0, "loop-free walks never touch fuel");
}

#[test]
fn oversized_community_list_caps_then_errors_closed() {
    use crate::eval::PolicyHitCounters;
    // A peer-supplied route with more communities than the per-loop
    // cap (possible with RFC 8654 extended messages): the 4097th
    // element is an evaluation error — uniform Deny + counter, never
    // silent truncation.
    let chain = compile_ok(
        "policy p { term t { for c in route.communities { if c == 1:1 { reject } } accept } }",
    );
    let many: Vec<u32> = (0..5000u32).collect();
    let ctx = route_ctx(v4(10, 0, 0, 0, 24), &many, RpkiValidation::NotFound);
    let counters = PolicyHitCounters::for_chain(&chain);
    let result = chain.evaluate_counting(&ctx, &counters);
    assert_eq!(
        result.action,
        PolicyAction::Deny,
        "cap-then-error fails closed"
    );
    assert_eq!(counters.eval_errors(), 1);

    // Exactly at the cap: completes cleanly (no elements remain).
    let exact: Vec<u32> = (0..4096u32).collect();
    let ctx = route_ctx(v4(10, 0, 0, 0, 24), &exact, RpkiValidation::NotFound);
    assert_eq!(chain.evaluate(&ctx).action, PolicyAction::Permit);
}

#[test]
fn oversized_as_path_caps_then_errors_closed() {
    let chain = compile_ok(
        "policy p { term t { for asn in route.as-path { if asn == 0 { reject } } accept } }",
    );
    let long: Vec<u32> = (1..=5000u32).collect();
    let ctx = as_path_ctx(&long, &[], &[]);
    assert_eq!(chain.evaluate(&ctx).action, PolicyAction::Deny);
    let realistic: Vec<u32> = (1..=500u32).collect();
    assert_eq!(
        chain.evaluate(&as_path_ctx(&realistic, &[], &[])).action,
        PolicyAction::Permit
    );
}

#[test]
fn fuel_exhausts_across_a_chain_of_loops() {
    use crate::eval::PolicyHitCounters;
    // Each policy's loop fits its own compile-time budget, but the
    // chain compounds at runtime: 300 policies × 4096 iterations >
    // MAX_EVAL_COST — the fuel rail denies with a counter.
    use std::fmt::Write as _;
    let mut source = String::new();
    for i in 0..300 {
        let _ = writeln!(
            source,
            "policy p{i} {{ term t {{ for c in route.communities {{ if c == 1:1 {{ reject }} }} accept }} }}"
        );
    }
    let chain = compile_ok(&source);
    let exact: Vec<u32> = (0..4096u32).collect();
    let ctx = route_ctx(v4(10, 0, 0, 0, 24), &exact, RpkiValidation::NotFound);
    let counters = PolicyHitCounters::for_chain(&chain);
    let result = chain.evaluate_counting(&ctx, &counters);
    assert_eq!(
        result.action,
        PolicyAction::Deny,
        "fuel exhaustion fails closed"
    );
    assert_eq!(counters.eval_errors(), 1);
    let (_, consumed) = chain.evaluate_measuring_fuel(&ctx);
    assert_eq!(
        consumed,
        crate::eval::MAX_EVAL_COST,
        "every fuel step spent"
    );
}

#[test]
fn nested_loops_at_the_cap_compile_and_run_deeper_is_rejected() {
    let four = "
        asn-set s { 1, 2 }
        policy p { term t {
            for a in s { for b in s { for c in s { for d in s {
                add community 65009:9
            } } } }
            accept
        } }";
    let chain = compile_ok(four);
    let ctx = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
    let result = chain.evaluate(&ctx);
    assert_eq!(
        result.modifications.communities_add.len(),
        16,
        "2^4 innermost executions at the nesting cap"
    );

    let five = "
        asn-set s { 1, 2 }
        policy p { term t {
            for a in s { for b in s { for c in s { for d in s { for e in s {
                add community 65009:9
            } } } } }
            accept
        } }";
    let (_, rendered) = diagnostics_of(five);
    assert!(
        rendered.contains("loops nest more than 4 deep"),
        "{rendered}"
    );
}

#[test]
fn nested_attribute_loops_exceed_the_evaluation_budget() {
    // 4096 × 4096 body steps: rejected at compile time by the cost DP,
    // not metered per route.
    let (_, rendered) = diagnostics_of(
        "policy p { term t {
            for a in route.as-path { for c in route.communities { if c == 1:1 { reject } } }
            accept
        } }",
    );
    assert!(
        rendered.contains("exceeds the worst-case evaluation budget"),
        "{rendered}"
    );
}

#[test]
fn only_finite_u32_sources_iterate() {
    for (source, expect) in [
        ("route.large-communities", "not iterable"),
        ("route.ext-communities", "not iterable"),
        ("route.local-pref", "not iterable"),
        ("peer.asn", "not iterable"),
        ("route.as-path.len", "not iterable"),
    ] {
        let (_, rendered) = diagnostics_of(&format!(
            "policy p {{ term t {{ for x in {source} {{ if x == 1 {{ reject }} }} accept }} }}"
        ));
        assert!(rendered.contains(expect), "{source}: {rendered}");
    }
    // Set kinds that are not u32-valued.
    let (_, rendered) = diagnostics_of(
        "prefix-set nets { 10.0.0.0/8 }
         policy p { term t { for x in nets { if x == 1 { reject } } accept } }",
    );
    assert!(rendered.contains("not an iterable set"), "{rendered}");
    let (_, rendered) = diagnostics_of(
        "community-set cs { 65000:100 }
         policy p { term t { for x in cs { if x == 1 { reject } } accept } }",
    );
    assert!(rendered.contains("iterate route.communities"), "{rendered}");
    let (_, rendered) = diagnostics_of(
        "policy p { term t { for x in no-such-set { if x == 1 { reject } } accept } }",
    );
    assert!(rendered.contains("not an iterable set"), "{rendered}");
}

#[test]
fn oversized_asn_set_source_is_rejected_at_compile_time() {
    let members: Vec<String> = (1..=4097u32).map(|n| n.to_string()).collect();
    let source = format!(
        "asn-set big {{ {} }}
         policy p {{ term t {{ for a in big {{ if a == 1 {{ reject }} }} accept }} }}",
        members.join(", ")
    );
    let (_, rendered) = diagnostics_of(&source);
    assert!(rendered.contains("set too large to iterate"), "{rendered}");
}

#[test]
fn break_and_continue_outside_a_loop_are_rejected() {
    let (_, rendered) = diagnostics_of("policy p { term t { break; accept } }");
    assert!(rendered.contains("`break` outside a loop"), "{rendered}");
    let (_, rendered) =
        diagnostics_of("policy p { term t { if route.med <= 5 { continue } accept } }");
    assert!(rendered.contains("`continue` outside a loop"), "{rendered}");
}

#[test]
fn apply_target_with_loop_is_rejected() {
    let (_, rendered) = diagnostics_of(
        "policy looper { term t { for c in route.communities { if c == 1:1 { reject } } } }
         policy p { term t { if apply(looper) { reject } accept } }",
    );
    assert!(
        rendered.contains("cannot `apply` policy `looper`"),
        "{rendered}"
    );
    assert!(
        rendered.contains("`apply` targets cannot use `for`"),
        "{rendered}"
    );
}

#[test]
fn parameter_membership_folds_at_compile_time() {
    // `p in <asn-set>` with a parameter folds to a constant truth
    // value at instantiation.
    let source = "
        asn-set bogons { 64512 }
        policy guard(asn: u32) { term t { if asn in bogons { reject } accept } }
        test bogon-param { route { } expect guard(64512) == reject }
        test clean-param { route { } expect guard(65001) == accept }";
    let report = run_rpol_tests(source).expect("compiles cleanly");
    assert!(report.all_passed(), "failures: {:?}", report.failures);
}

#[test]
fn in_language_tests_exercise_loops() {
    let source = r#"
community-set scrub { 65000:100 }
asn-set bogons { 64512 }

policy strip-scrub {
    term walk {
        for c in route.communities {
            if c in scrub { remove community c }
        }
        accept
    }
}

policy bogon-path-guard {
    term walk {
        for asn in route.as-path {
            if asn in bogons { reject }
        }
        accept
    }
}

test scrub-removes-tagged {
    route { communities [65000:100, 65001:1] }
    expect strip-scrub == accept
}

test bogon-as-anywhere-rejects {
    route { as-path "65001 64512 65002" }
    expect bogon-path-guard == reject
}

test bogon-in-as-set-rejects {
    route { as-path "65001 {64512 64513}" }
    expect bogon-path-guard == reject
}

test clean-path-accepts {
    route { as-path "65001 65002" }
    expect bogon-path-guard == accept
}
"#;
    let report = run_rpol_tests(source).expect("compiles cleanly");
    assert_eq!(report.total, 4);
    assert!(report.all_passed(), "failures: {:?}", report.failures);
}

#[test]
fn explain_renders_loop_summary_not_iterations() {
    use crate::engine::PolicyChain;
    use crate::engine::explain::explain_chain_statements;
    use std::sync::Arc;

    let chain_ir = compile_ok(
        "asn-set bogons { 64512 }
         policy p { term guard { for asn in route.as-path { if asn in bogons { reject } } accept } }",
    );
    let chain = PolicyChain::from_named(vec![crate::NamedPolicy::from_rpol(
        "p".to_string(),
        Arc::new(chain_ir),
    )]);
    let ctx = as_path_ctx(&[65001, 65002, 64512], &[], &[]);
    let trace = explain_chain_statements(Some(&chain), &ctx);
    assert_eq!(
        trace.action,
        PolicyAction::Deny,
        "trace agrees with the live verdict"
    );
    let step = &trace.steps[0];
    let loop_line = step
        .term_traces
        .iter()
        .find(|line| line.contains("loop"))
        .expect("loop summary line present");
    assert!(
        loop_line.contains("reject at iteration 3 of 3"),
        "summary names the deciding iteration: {loop_line}"
    );
    assert!(
        step.term_traces.len() <= 3,
        "bounded output — a summary, not per-iteration lines: {:?}",
        step.term_traces
    );

    // No verdict: the loop completes and the trace says so.
    let clean = as_path_ctx(&[65001, 65002], &[], &[]);
    let trace = explain_chain_statements(Some(&chain), &clean);
    assert_eq!(trace.action, PolicyAction::Permit);
    let loop_line = trace.steps[0]
        .term_traces
        .iter()
        .find(|line| line.contains("loop"))
        .expect("loop summary line present");
    assert!(
        loop_line.contains("completed after 2 iteration(s), no verdict"),
        "{loop_line}"
    );
}

#[test]
fn loop_requires_flags_reach_through_bodies() {
    // as-path iteration sets requires_as_path_asns; a peer read inside
    // a loop body still disqualifies update-group sharing.
    let chain = compile_ok(
        "policy p { term t { for asn in route.as-path { if asn == 1 { reject } } accept } }",
    );
    assert!(chain.requires_as_path_asns());
    assert!(!chain.requires_peer_context());
    let peer_in_body = compile_ok(
        "asn-set s { 1 }
         policy p { term t { for a in s { if peer.asn == 64512 { reject } } accept } }",
    );
    assert!(peer_in_body.requires_peer_context());
    assert!(!peer_in_body.requires_as_path_asns());
    let loop_free = compile_ok("policy p { term t { if route.med <= 5 { reject } accept } }");
    assert!(!loop_free.requires_as_path_asns());
}

#[test]
fn dry_run_recording_hits_agrees_with_live_loop_walk() {
    let chain = compile_ok(
        "community-set scrub { 65000:100 }
         policy p { term walk { for c in route.communities { if c in scrub { reject } } accept } }",
    );
    for communities in [vec![STD_65000_100], vec![STD_65001_1], vec![]] {
        let ctx = route_ctx(v4(10, 0, 0, 0, 24), &communities, RpkiValidation::NotFound);
        let mut hits = chain.zero_term_hits();
        let recorded = chain.evaluate_recording_hits(&ctx, &mut hits);
        let live = chain.evaluate(&ctx);
        assert_eq!(recorded, live, "communities {communities:?}");
    }
}

// ── LAN-304: pure user-defined functions ────────────────────────────

/// The headline shape: a factored penalty computation, called with
/// route fields as arguments.
const FN_EXAMPLE: &str = "
fn penalty(len: u32, weight: u32) -> u32 {
    let base = len * weight
    min(base, 1000)
}

policy p {
    term t { if penalty(route.as-path.len, 10) >= route.med { reject } }
    term rest { accept }
}
";

/// The same policy with the function body written inline — the parity
/// oracle.
const FN_EXAMPLE_INLINE: &str = "
policy p {
    term t { if min(route.as-path.len * 10, 1000) >= route.med { reject } }
    term rest { accept }
}
";

fn ctx_with_path_and_med(as_path_len: usize, med: Option<u32>) -> RouteContext<'static> {
    let mut ctx = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
    ctx.as_path_len = as_path_len;
    ctx.med = med;
    ctx
}

#[test]
fn fn_calls_compile_and_evaluate() {
    let chain = compile_ok(FN_EXAMPLE);
    // penalty(3, 10) = 30 >= med 20 -> reject.
    assert_eq!(
        chain.evaluate(&ctx_with_path_and_med(3, Some(20))).action,
        PolicyAction::Deny
    );
    // penalty(3, 10) = 30 < med 50 -> falls through to accept.
    assert_eq!(
        chain.evaluate(&ctx_with_path_and_med(3, Some(50))).action,
        PolicyAction::Permit
    );
    // The min clamp: penalty(200, 10) = min(2000, 1000) = 1000 < 2000.
    assert_eq!(
        chain
            .evaluate(&ctx_with_path_and_med(200, Some(2000)))
            .action,
        PolicyAction::Permit
    );
}

/// Calling `penalty(a, b)` behaves — verdicts, modifications, and
/// runtime fuel — exactly like writing the body inline (the call is
/// sugar for a scope of lets; both shapes are loop-free, so both
/// consume zero fuel).
#[test]
fn fn_inlined_parity_with_manual_body() {
    let called = compile_ok(FN_EXAMPLE);
    let inline = compile_ok(FN_EXAMPLE_INLINE);
    for (len, med) in [(0, None), (3, Some(20)), (3, Some(50)), (200, Some(2000))] {
        let ctx = ctx_with_path_and_med(len, med);
        let (lhs, lhs_fuel) = called.evaluate_measuring_fuel(&ctx);
        let (rhs, rhs_fuel) = inline.evaluate_measuring_fuel(&ctx);
        assert_eq!(lhs.action, rhs.action, "len={len} med={med:?}");
        assert_eq!(
            lhs.modifications, rhs.modifications,
            "len={len} med={med:?}"
        );
        assert_eq!(lhs_fuel, 0, "loop-free walks pay zero fuel");
        assert_eq!(rhs_fuel, 0);
    }
}

/// Functions work in every value position: `set` values, `let`
/// initializers, and nested calls as arguments.
#[test]
fn fn_calls_in_set_values_and_nested_calls() {
    let chain = compile_ok(
        "
        fn double(x: u32) -> u32 { x * 2 }
        fn pad(x: u32, amount: u32) -> u32 { x + amount }
        policy p {
            term t {
                let bumped = pad(double(route.med), 7)
                set med bumped;
                set local-pref double(double(5));
                accept
            }
        }
        ",
    );
    let result = chain.evaluate(&ctx_with_path_and_med(0, Some(10)));
    assert_eq!(result.action, PolicyAction::Permit);
    assert_eq!(result.modifications.set_med, Some(27), "pad(double(10), 7)");
    // Constant arguments fold through the inlined body's checked
    // arithmetic at compile time or evaluate identically at runtime.
    assert_eq!(result.modifications.set_local_pref, Some(20));
}

#[test]
fn fn_declaration_diagnostics() {
    // Arity mismatch, with the definition labelled.
    let (_, rendered) = diagnostics_of(
        "fn f(a: u32, b: u32) -> u32 { a + b }
         policy p { term t { if f(1) >= 2 { reject } } }",
    );
    assert!(
        rendered.contains("takes 2 arguments but 1 was supplied"),
        "{rendered}"
    );

    // Unknown function, suggesting across builtins and fns.
    let (_, rendered) = diagnostics_of(
        "fn shift(a: u32) -> u32 { a + 1 }
         policy p { term t { if shitf(1) >= 2 { reject } } }",
    );
    assert!(
        rendered.contains("unknown function or builtin"),
        "{rendered}"
    );
    assert!(rendered.contains("did you mean `shift`?"), "{rendered}");

    // Duplicate function names.
    let (_, rendered) = diagnostics_of(
        "fn f(a: u32) -> u32 { a }
         fn f(b: u32) -> u32 { b }
         policy p { term t { accept } }",
    );
    assert!(rendered.contains("duplicate fn `f`"), "{rendered}");

    // Builtin shadowing is rejected.
    let (_, rendered) = diagnostics_of(
        "fn min(a: u32) -> u32 { a }
         policy p { term t { accept } }",
    );
    assert!(rendered.contains("shadows the builtin"), "{rendered}");

    // Calling a policy for a value points at apply().
    let (_, rendered) = diagnostics_of(
        "policy helper { term t { reject } }
         policy p { term t { if helper(1) >= 2 { reject } } }",
    );
    assert!(rendered.contains("is a policy"), "{rendered}");
    assert!(rendered.contains("apply"), "{rendered}");
}

/// Functions get their own namespace: a set and a policy may share a
/// function's name — every reference position is disjoint.
#[test]
fn fn_namespace_coexists_with_sets_and_policies() {
    let chain = compile_ok(
        "
        asn-set scale { 64512 }
        policy scale(threshold: u32) { term t { reject } }
        fn scale(x: u32) -> u32 { x * 100 }
        policy p {
            term t {
                if scale(route.med) >= 1000 && route.origin-as in scale { reject }
                accept
            }
        }
        ",
    );
    let mut ctx = ctx_with_path_and_med(0, Some(50));
    ctx.origin_asn = Some(64512);
    assert_eq!(chain.evaluate(&ctx).action, PolicyAction::Deny);
    ctx.med = Some(5);
    assert_eq!(chain.evaluate(&ctx).action, PolicyAction::Permit);
}

/// Purity by construction: bodies read no context fields — inputs
/// arrive as parameters.
#[test]
fn fn_purity_rejects_field_reads() {
    let (_, rendered) = diagnostics_of(
        "fn f(a: u32) -> u32 { a + route.med }
         policy p { term t { if f(1) >= 2 { reject } } }",
    );
    assert!(rendered.contains("closed over nothing"), "{rendered}");
    assert!(
        rendered.contains("pass the field as an argument"),
        "{rendered}"
    );
}

/// Bodies are expression-shaped: verdicts/actions/loops get a typed
/// diagnostic, not a generic parse error.
#[test]
fn fn_body_rejects_statements() {
    for body in ["accept", "reject", "set med 5", "for a in s { break }"] {
        let src = format!(
            "asn-set s {{ 1 }} fn f(a: u32) -> u32 {{ {body} }} policy p {{ term t {{ accept }} }}"
        );
        let (_, rendered) = diagnostics_of(&src);
        assert!(
            rendered.contains("cannot execute statements"),
            "body {body:?}: {rendered}"
        );
    }
}

#[test]
fn fn_recursion_cycle_named() {
    // Direct recursion.
    let (_, rendered) = diagnostics_of(
        "fn f(a: u32) -> u32 { f(a) }
         policy p { term t { accept } }",
    );
    assert!(
        rendered.contains("function call cycle: f -> f"),
        "{rendered}"
    );

    // Mutual recursion names the full cycle.
    let (_, rendered) = diagnostics_of(
        "fn f(a: u32) -> u32 { g(a) }
         fn g(a: u32) -> u32 { f(a) }
         policy p { term t { accept } }",
    );
    assert!(rendered.contains("function call cycle"), "{rendered}");
    assert!(
        rendered.contains('f') && rendered.contains('g'),
        "{rendered}"
    );
}

/// A linear chain of `levels` functions, `f1` calling `f2` … calling
/// `f<levels>`, with a policy calling `f1`.
fn fn_chain(levels: u32) -> String {
    use std::fmt::Write;

    let mut src = String::new();
    for i in 1..levels {
        writeln!(src, "fn f{i}(x: u32) -> u32 {{ f{}(x) + 1 }}", i + 1).expect("string io");
    }
    writeln!(src, "fn f{levels}(x: u32) -> u32 {{ x + 1 }}").expect("string io");
    writeln!(
        src,
        "policy p {{ term t {{ if f1(route.med) >= 1000 {{ reject }} accept }} }}"
    )
    .expect("string io");
    src
}

#[test]
fn fn_call_depth_8_ok_9_rejected() {
    let chain = compile_ok(&fn_chain(8));
    // med 0 (default): f1(0) = 8 < 1000 -> accept.
    assert_eq!(
        chain.evaluate(&ctx_with_path_and_med(0, None)).action,
        PolicyAction::Permit
    );
    assert_eq!(
        chain.evaluate(&ctx_with_path_and_med(0, Some(995))).action,
        PolicyAction::Deny,
        "995 + 8 >= 1000"
    );

    let (diags, rendered) = diagnostics_of(&fn_chain(9));
    assert!(
        rendered.contains("function call chain nests more than 8 deep"),
        "{rendered}"
    );
    // Poisoning: one root cause, one diagnostic.
    assert_eq!(diags.0.len(), 1, "{rendered}");
}

/// A function whose inlined body consumes `62` frame slots per call
/// site (1 parameter + 60 body lets + 1 result), for the frame-budget
/// tests: 4 statement-level calls fit the 256-slot frame exactly; one
/// more binding tips it over.
fn wide_fn() -> String {
    use std::fmt::Write;

    let mut src = String::from("fn wide(x: u32) -> u32 {\n");
    writeln!(src, "    let l1 = x + 1").expect("string io");
    for i in 2..=60 {
        writeln!(src, "    let l{i} = l{} + 1", i - 1).expect("string io");
    }
    src.push_str("    l60\n}\n");
    src
}

#[test]
fn fn_slot_exhaustion_via_call_chain() {
    // 4 × 62 = 248 slots, plus 8 explicit lets = 256: exactly the
    // frame. Compiles AND evaluates — pinning that the typecheck
    // accounting and the lowerer's allocator agree at the boundary
    // (the lowerer asserts on overflow; the DP must reject first).
    let boundary = format!(
        "{}policy p {{ term t {{
            if wide(1) >= 0 {{ set med 1 }}
            if wide(2) >= 0 {{ set med 2 }}
            if wide(3) >= 0 {{ set med 3 }}
            if wide(4) >= 0 {{ set med 4 }}
            let a1 = 1
            let a2 = 1
            let a3 = 1
            let a4 = 1
            let a5 = 1
            let a6 = 1
            let a7 = 1
            let a8 = 1
            if a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8 >= 8 {{ reject }}
            accept
        }} }}",
        wide_fn()
    );
    let chain = compile_ok(&boundary);
    assert_eq!(
        chain.evaluate(&ctx_with_path_and_med(0, None)).action,
        PolicyAction::Deny
    );

    // One more binding: 257 slots -> compile error with the term span.
    let over = boundary.replace("let a8 = 1", "let a8 = 1\n            let a9 = 1");
    let (_, rendered) = diagnostics_of(&over);
    assert!(
        rendered.contains("binding slots after function inlining"),
        "{rendered}"
    );
}

/// The expansion bomb: a moderately sized body multiplied through a
/// legal-depth call tree exceeds the inlined-node budget and is
/// rejected at compile time — never lowered.
#[test]
fn fn_expansion_bomb_rejected() {
    use std::fmt::Write;

    // f1: ~100 arithmetic steps. f2..f8 each call the previous level
    // three times: 3^7 ≈ 2187 × the base body ≫ 100k nodes, at legal
    // call depth 8.
    let mut src = String::from("fn f1(x: u32) -> u32 { x");
    for _ in 0..100 {
        src.push_str(" + 1");
    }
    src.push_str(" }\n");
    for i in 2..=8 {
        writeln!(
            src,
            "fn f{i}(x: u32) -> u32 {{ f{p}(x) + f{p}(x) + f{p}(x) }}",
            p = i - 1
        )
        .expect("string io");
    }
    src.push_str("policy p { term t { if f8(route.med) >= 1 { reject } accept } }\n");
    let report = check_on_small_stack(src);
    let rendered = format!("{:?}", report.diagnostics);
    assert!(
        rendered.contains("expands past"),
        "want an expansion diagnostic, got: {rendered:.300}"
    );
}

/// An evaluation error inside an inlined body denies the route on the
/// uniform rail and counts, exactly like any checked-arithmetic error.
#[test]
fn fn_eval_error_inside_body_denies_and_counts() {
    let chain = compile_ok(
        "
        fn share(total: u32, parts: u32) -> u32 { total / parts }
        policy p {
            term t { if share(100, route.med) >= 1 { reject } accept }
        }
        ",
    );
    let hits = crate::eval::PolicyHitCounters::for_chain(&chain);
    // med absent -> implicit 0 -> divide-by-zero inside the body ->
    // Deny, error counted.
    let denied = chain.evaluate_counting(&ctx_with_path_and_med(0, None), &hits);
    assert_eq!(denied.action, PolicyAction::Deny);
    assert_eq!(hits.eval_errors(), 1);
    // A resolvable call decides normally.
    // 100 / 200 = 0; `0 >= 1` is false -> falls through to accept.
    let permitted = chain.evaluate_counting(&ctx_with_path_and_med(0, Some(200)), &hits);
    assert_eq!(permitted.action, PolicyAction::Permit);
    assert_eq!(hits.eval_errors(), 1, "no new error");
}

/// `requires_peer_context` is a property of the CALL SITE's arguments —
/// functions are closed over nothing, so a route-only call never
/// disqualifies update-group sharing and a `peer.asn` argument counts
/// exactly like a bare `peer.asn` operand.
#[test]
fn fn_peer_argument_sets_requires_peer_context() {
    let route_only = compile_ok(
        "fn f(a: u32) -> u32 { a + 1 }
         policy p { term t { if f(route.med) >= 10 { reject } accept } }",
    );
    assert!(!route_only.requires_peer_context());

    let peer_arg = compile_ok(
        "fn f(a: u32) -> u32 { a + 1 }
         policy p { term t { if f(peer.asn) >= 64512 { reject } accept } }",
    );
    assert!(peer_arg.requires_peer_context());
}

/// Explain renders the call site source-level: the result slot is
/// named by the rendered call expression.
#[test]
fn fn_explain_renders_call_source_level() {
    let chain = compile_ok(FN_EXAMPLE);
    let terms = &chain.policies[0].terms;
    // The source term `t` lowers to bind terms + the guard term, all
    // named `t.<n>` — term identity stays a function of the source.
    let guard_term = terms
        .iter()
        .find(|term| matches!(term.guard, MatchExpr::ValueCmp(_)))
        .expect("the comparison term");
    assert!(
        guard_term.name.as_deref().unwrap_or("").starts_with("t."),
        "{:?}",
        guard_term.name
    );
    let rendered = crate::engine::explain::render_expr(&guard_term.guard, &chain);
    assert_eq!(rendered, "penalty(route.as-path.len, 10) >= route.med");
    // The hoisted binds carry qualified fn.binding names.
    let bind_names: Vec<&str> = terms
        .iter()
        .filter_map(|term| match &term.action {
            TermAction::Bind { name, .. } => Some(&**name),
            _ => None,
        })
        .collect();
    assert_eq!(
        bind_names,
        [
            "penalty.len",
            "penalty.weight",
            "penalty.base",
            "penalty(route.as-path.len, 10)"
        ]
    );
}

/// Per-term hit counters survive inlining: the body dissolves into
/// `t.<n>` terms of the calling source term, so the counter grid stays
/// a function of the source and every walk counts the term once per
/// evaluated guard.
#[test]
fn fn_counters_stay_term_shaped() {
    let chain = compile_ok(FN_EXAMPLE);
    let hits = crate::eval::PolicyHitCounters::for_chain(&chain);
    let _ = chain.evaluate_counting(&ctx_with_path_and_med(3, Some(50)), &hits);
    let snapshot = hits.snapshot();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(
        snapshot[0].len(),
        chain.policies[0].terms.len(),
        "one counter row per IR term"
    );
    // The unconditional binds and the fallthrough term all matched.
    assert_eq!(hits.evals(), 1);
    assert!(snapshot[0].iter().sum::<u64>() >= 4, "{snapshot:?}");
}

/// Calls in loop-body guards re-bind their slots per iteration; fuel
/// is charged per iteration only (calls are straight-line code).
#[test]
fn fn_calls_inside_loop_bodies() {
    let chain = compile_ok(
        "
        asn-set candidates { 64512, 64513, 64514 }
        fn shifted(asn: u32, bump: u32) -> u32 { asn + bump }
        policy p {
            term t {
                for a in candidates {
                    if shifted(a, 1) >= 64515 { reject }
                }
                accept
            }
        }
        ",
    );
    let ctx = ctx_with_path_and_med(0, None);
    let (result, fuel) = chain.evaluate_measuring_fuel(&ctx);
    // 64514 + 1 >= 64515 on the third member.
    assert_eq!(result.action, PolicyAction::Deny);
    assert_eq!(fuel, 3, "one fuel step per iteration, none for the calls");
}

/// In-language tests exercise fn-using policies through the same
/// compile + evaluate pipeline.
#[test]
fn fn_in_language_test_fixture() {
    let report = check_rpol(
        "
        fn penalty(len: u32, weight: u32) -> u32 {
            let base = len * weight
            min(base, 1000)
        }
        policy p {
            term t { if penalty(route.as-path.len, 10) >= route.med { reject } }
            term rest { accept }
        }
        test penalty-rejects-long-paths {
            route { prefix 10.0.0.0/24; as-path \"65001 65002 65003\"; med 20 }
            expect p == reject
        }
        test penalty-passes-short-paths {
            route { prefix 10.0.0.0/24; as-path \"65001\"; med 20 }
            expect p == accept
        }
        ",
    );
    assert!(report.is_ok(), "{report:?}");
}

/// `apply` targets cannot call functions — a call is sugar for `let`
/// binds, which a pure inlined predicate cannot execute (the LAN-302
/// rule extended).
#[test]
fn fn_apply_target_with_calls_rejected() {
    let (_, rendered) = diagnostics_of(
        "fn f(a: u32) -> u32 { a + 1 }
         policy helper { term t { if f(route.med) >= 10 { reject } } term rest { accept } }
         policy p { term t { if apply(helper) { accept } } }",
    );
    assert!(rendered.contains("it calls functions"), "{rendered}");
    assert!(rendered.contains("first call is here"), "{rendered}");
}

/// Legal-depth stack shape for functions (the #777 discipline): a
/// max-depth call chain wrapped in deep expressions compiles AND
/// evaluates on the small stack — every recursive pass runs.
#[test]
fn fn_legal_call_depth_on_small_stack() {
    // Depth-8 call chain where every body carries a deep-ish
    // arithmetic chain, called from a 60-deep expression.
    let mut src = String::new();
    {
        use std::fmt::Write;
        writeln!(src, "fn f8(x: u32) -> u32 {{ x{} }}", " + 1".repeat(60)).expect("string io");
        for i in (1..8).rev() {
            writeln!(src, "fn f{i}(x: u32) -> u32 {{ f{}(x) + 1 }}", i + 1).expect("string io");
        }
        writeln!(
            src,
            "policy p {{ term t {{ if f1(route.med){} >= 100000 {{ reject }} accept }} }}",
            " + 1".repeat(60),
        )
        .expect("string io");
    }
    let verdict = std::thread::Builder::new()
        .stack_size(SMALL_STACK)
        .spawn(move || {
            let chain = compile_ok(&src);
            let ctx = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
            let action = chain.evaluate(&ctx).action;
            drop(chain);
            action
        })
        .expect("spawn")
        .join()
        .expect("legal-depth fn chain crashed the small stack");
    // med 0: f1(0) = 60 + 7 = 67; 67 + 60 = 127 < 100000 -> accept.
    assert_eq!(verdict, PolicyAction::Permit);
}

// ─────────────────────────────────────────────────────────────────────
// External datasets (LAN-305, ADR-0103 Decisions 8.5 / 9)
// ─────────────────────────────────────────────────────────────────────

mod datasets {
    use std::sync::Arc;

    use rustbgpd_wire::RpkiValidation;

    use crate::datasets::{
        DatasetBindings, DatasetData, DatasetHandle, DatasetKind, MAX_UNIT_DATASETS,
    };
    use crate::engine::{CommunityMatch, PolicyAction};
    use crate::sets::{AsnSet, CommunitySet, PrefixSet, PrefixSetEntry, SetStore};

    use super::super::{RpolFile, compile_rpol, parse_dataset_text, run_rpol_tests};
    use super::{route_ctx, v4};

    const DATASET_POLICY: &str = r"
dataset asn-set customers
dataset prefix-set bogons
dataset community-set scrub-tags

policy origin-guard {
    term customers { if route.origin-as in customers { accept } }
    term rest { reject }
}

policy bogon-guard {
    term bogons { if route.prefix in bogons { reject } }
}

policy tag-guard {
    term tagged { if route.communities in scrub-tags { reject } }
}

policy peer-guard {
    term peers { if peer.asn in customers { accept } }
    term rest { reject }
}
";

    fn asn_handle(name: &str, asns: &[u32]) -> Arc<DatasetHandle> {
        Arc::new(DatasetHandle::new(
            name,
            DatasetKind::Asn,
            DatasetData::Asn(AsnSet::new(asns.iter().copied())),
        ))
    }

    fn bindings_for(handles: &[Arc<DatasetHandle>]) -> DatasetBindings {
        let mut bindings = DatasetBindings::new();
        for handle in handles {
            bindings.insert(Arc::clone(handle));
        }
        bindings
    }

    fn full_bindings() -> (Arc<DatasetHandle>, DatasetBindings) {
        let customers = asn_handle("customers", &[64500]);
        let bogons = Arc::new(DatasetHandle::new(
            "bogons",
            DatasetKind::Prefix,
            DatasetData::Prefix(PrefixSet::new([PrefixSetEntry {
                prefix: v4(127, 0, 0, 0, 8),
                ge: Some(8),
                le: Some(32),
            }])),
        ));
        let tags = Arc::new(DatasetHandle::new(
            "scrub-tags",
            DatasetKind::Community,
            DatasetData::Community(CommunitySet::new([CommunityMatch::Standard {
                value: (65000 << 16) | 0x29A,
            }])),
        ));
        let bindings = bindings_for(&[Arc::clone(&customers), bogons, tags]);
        (customers, bindings)
    }

    #[test]
    fn dataset_probes_evaluate_like_sets() {
        let file = RpolFile::parse(DATASET_POLICY).expect("clean rpol");
        let (_, bindings) = full_bindings();
        let mut store = SetStore::new();

        // ASN probe.
        let chain = file
            .compile_policy_bound("origin-guard", &[], &mut store, &bindings)
            .expect("policy exists")
            .expect("bindings complete");
        let mut hit = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
        hit.origin_asn = Some(64500);
        assert_eq!(chain.evaluate(&hit).action, PolicyAction::Permit);
        let mut miss = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
        miss.origin_asn = Some(64999);
        assert_eq!(chain.evaluate(&miss).action, PolicyAction::Deny);

        // Prefix probe.
        let chain = file
            .compile_policy_bound("bogon-guard", &[], &mut store, &bindings)
            .expect("policy exists")
            .expect("bindings complete");
        let bogon = route_ctx(v4(127, 1, 0, 0, 16), &[], RpkiValidation::NotFound);
        assert_eq!(chain.evaluate(&bogon).action, PolicyAction::Deny);
        let clean = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
        assert_eq!(chain.evaluate(&clean).action, PolicyAction::Permit);

        // Community probe.
        let chain = file
            .compile_policy_bound("tag-guard", &[], &mut store, &bindings)
            .expect("policy exists")
            .expect("bindings complete");
        let tagged = route_ctx(
            v4(10, 0, 0, 0, 24),
            &[(65000 << 16) | 0x29A],
            RpkiValidation::NotFound,
        );
        assert_eq!(chain.evaluate(&tagged).action, PolicyAction::Deny);

        // Peer-ASN probe counts toward peer context (update-group
        // disqualification), route-only probes do not.
        let peer_chain = file
            .compile_policy_bound("peer-guard", &[], &mut store, &bindings)
            .expect("policy exists")
            .expect("bindings complete");
        assert!(peer_chain.requires_peer_context());
        assert!(!chain.requires_peer_context());
    }

    /// The Decision 8.5 core: a content swap is visible to the
    /// installed chain at its next walk WITHOUT recompiling or
    /// replacing it, and chain identity (the #775 skip / live-impact
    /// diff input) is untouched by the swap.
    #[test]
    fn content_swap_reaches_installed_chains_without_recompile() {
        let file = RpolFile::parse(DATASET_POLICY).expect("clean rpol");
        let (customers, bindings) = full_bindings();
        let mut store = SetStore::new();
        let chain = file
            .compile_policy_bound("origin-guard", &[], &mut store, &bindings)
            .expect("policy exists")
            .expect("bindings complete");

        let mut ctx = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
        ctx.origin_asn = Some(64999);
        assert_eq!(chain.evaluate(&ctx).action, PolicyAction::Deny);

        let before_swap = chain.clone();
        customers
            .refresh(DatasetData::Asn(AsnSet::new([64500, 64999])))
            .expect("content changed");
        // Same chain instance, new verdict: the swap reached it.
        assert_eq!(chain.evaluate(&ctx).action, PolicyAction::Permit);
        // …and identity is stable: content is data, not program
        // (ADR-0103 Decision 5.3).
        assert_eq!(chain, before_swap);
        assert!(chain.references_dataset("customers"));
        assert!(!chain.references_dataset("bogons"));
    }

    /// Torn-generation proof at the walk level: one evaluation pins
    /// each dataset once, so a guard set of `in D` / `!(in D)` terms
    /// resolves consistently even while another thread swaps the
    /// snapshot in a tight loop. A torn read would deny (both terms
    /// miss); a pinned walk always permits through exactly one term.
    #[test]
    fn walk_pins_one_generation_under_concurrent_swaps() {
        let file = RpolFile::parse(
            r"
dataset asn-set flappers

policy pinned {
    term member { if route.origin-as in flappers { accept } }
    term nonmember { if !(route.origin-as in flappers) { accept } }
    term unreachable { reject }
}
",
        )
        .expect("clean rpol");
        let handle = asn_handle("flappers", &[64500]);
        let bindings = bindings_for(&[Arc::clone(&handle)]);
        let mut store = SetStore::new();
        let chain = file
            .compile_policy_bound("pinned", &[], &mut store, &bindings)
            .expect("policy exists")
            .expect("bindings complete");

        let stop = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let mut member = false;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    member = !member;
                    let asns: &[u32] = if member { &[64500] } else { &[] };
                    handle.refresh(DatasetData::Asn(AsnSet::new(asns.iter().copied())));
                }
            });
            let mut ctx = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
            ctx.origin_asn = Some(64500);
            for _ in 0..50_000 {
                assert_eq!(
                    chain.evaluate(&ctx).action,
                    PolicyAction::Permit,
                    "a walk observed two generations of one dataset"
                );
            }
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
        });
    }

    #[test]
    fn missing_or_wrong_kind_binding_is_a_compile_error() {
        let file = RpolFile::parse(DATASET_POLICY).expect("clean rpol");
        let mut store = SetStore::new();
        // No bindings at all.
        let missing = file
            .compile_policy_bound("origin-guard", &[], &mut store, &DatasetBindings::new())
            .expect("policy exists")
            .expect_err("unbound dataset");
        assert_eq!(missing.0, vec!["customers".to_string()]);
        // A binding of the wrong kind is as good as missing.
        let wrong = Arc::new(DatasetHandle::new(
            "customers",
            DatasetKind::Prefix,
            DatasetData::Prefix(PrefixSet::new([])),
        ));
        let missing = file
            .compile_policy_bound("origin-guard", &[], &mut store, &bindings_for(&[wrong]))
            .expect("policy exists")
            .expect_err("kind mismatch");
        assert_eq!(missing.0, vec!["customers".to_string()]);
        // Inline compilation cannot bind datasets: zero-param policies
        // probing one are a diagnostic.
        let err = compile_rpol(DATASET_POLICY, &mut SetStore::new())
            .expect_err("inline compile has no bindings");
        assert!(
            err.0[0].message.contains("cannot bind dataset"),
            "{}",
            err.0[0].message
        );
    }

    #[test]
    fn diagnostics_cover_dataset_misuse() {
        let cases: &[(&str, &str)] = &[
            // Wrong kind in a probe position.
            (
                "dataset prefix-set nets\npolicy p { term t { if route.origin-as in nets { accept } } }",
                "prefix-set dataset but this probe needs a asn-set",
            ),
            // Namespace collision with a source-defined set.
            (
                "asn-set customers { 64500 }\ndataset asn-set customers\npolicy p { term t { reject } }",
                "collides with the asn-set of the same name",
            ),
            // Duplicate declaration.
            (
                "dataset asn-set d\ndataset asn-set d\npolicy p { term t { reject } }",
                "duplicate dataset `d`",
            ),
            // Datasets are probe-only.
            (
                "dataset asn-set d\npolicy p { term t { for asn in d { reject } } }",
                "datasets are probe-only",
            ),
            // Bindings cannot probe prefix datasets.
            (
                "dataset prefix-set nets\npolicy p { term t { for c in route.communities { if c in nets { reject } } } }",
                "cannot probe prefixes",
            ),
            // Test override must name a declared dataset.
            (
                "dataset asn-set d\npolicy p { term t { reject } }\ntest t { dataset nope { 1 } route { prefix 10.0.0.0/8 } expect p == reject }",
                "unknown dataset `nope`",
            ),
            // Test override member kind must match.
            (
                "dataset asn-set d\npolicy p { term t { reject } }\ntest t { dataset d { 10.0.0.0/8 } route { prefix 10.0.0.0/8 } expect p == reject }",
                "member kind mismatch",
            ),
        ];
        for (source, needle) in cases {
            let err = RpolFile::parse(source).expect_err("should not typecheck");
            let rendered = format!("{err:?}");
            assert!(rendered.contains(needle), "{needle:?} not in {rendered}");
        }
    }

    #[test]
    fn unit_dataset_budget_is_enforced() {
        use std::fmt::Write as _;
        let mut source = String::new();
        for index in 0..=MAX_UNIT_DATASETS {
            let _ = writeln!(source, "dataset asn-set d{index}");
        }
        source.push_str("policy p { term t { reject } }\n");
        let err = RpolFile::parse(&source).expect_err("over budget");
        assert!(format!("{err:?}").contains("dataset budget exceeded"));
    }

    /// In-language tests provide dataset content with per-test
    /// `dataset` overrides; a test probing an un-overridden dataset
    /// fails with a message naming it.
    #[test]
    fn test_blocks_override_dataset_content() {
        let report = run_rpol_tests(
            r#"
dataset asn-set customers

policy origin-guard {
    term customers { if route.origin-as in customers { accept } }
    term rest { reject }
}

test member-accepted {
    dataset customers { 64500, 64501 }
    route { prefix 10.0.0.0/24; as-path "64777 64500" }
    expect origin-guard == accept
}

test nonmember-rejected {
    dataset customers { 64501 }
    route { prefix 10.0.0.0/24; as-path "64777 64500" }
    expect origin-guard == reject
}

test missing-override-fails {
    route { prefix 10.0.0.0/24; as-path "64777 64500" }
    expect origin-guard == accept
}
"#,
        )
        .expect("compiles");
        assert_eq!(report.total, 3);
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].name, "missing-override-fails");
        assert!(
            report.failures[0]
                .message
                .contains("no `dataset { ... }` override"),
            "{}",
            report.failures[0].message
        );
    }

    /// The file format: one entry per line, `#` comments, whitespace
    /// tolerant, same literal grammar as source sets, errors carry
    /// line numbers.
    #[test]
    fn dataset_file_format_parses_and_reports_lines() {
        let asn = parse_dataset_text(
            "# customer ASNs\n 64500 \n64501 # trailing comment\n\n64502\n",
            DatasetKind::Asn,
        )
        .expect("clean asn file");
        assert_eq!(asn.records(), 3);

        let prefixes = parse_dataset_text(
            "10.0.0.0/8 ge 24 le 28\n192.0.2.0/24\n2001:db8::/32 ge 48\n",
            DatasetKind::Prefix,
        )
        .expect("clean prefix file");
        assert_eq!(prefixes.records(), 3);

        let communities = parse_dataset_text(
            "65000:100\n65000:1:2\nRT:65001:7\nNO_EXPORT\n",
            DatasetKind::Community,
        )
        .expect("clean community file");
        assert_eq!(communities.records(), 4);

        // Errors carry 1-based line numbers.
        let err = parse_dataset_text("64500\nnot-an-asn\n", DatasetKind::Asn).expect_err("bad");
        assert!(err.starts_with("line 2:"), "{err}");
        // One entry per line — a second entry is an error, not a
        // silent merge.
        let err = parse_dataset_text("64500 64501\n", DatasetKind::Asn).expect_err("two");
        assert!(err.contains("one entry per line"), "{err}");
        // Wrong-kind content fails parse (this is what keeps a
        // mis-pointed path from silently probing garbage).
        assert!(parse_dataset_text("10.0.0.0/8\n", DatasetKind::Asn).is_err());
    }

    /// Explain names the dataset and the pinned generation without
    /// dumping content.
    #[test]
    fn explain_names_dataset_and_generation() {
        use crate::engine::{NamedPolicy, PolicyChain};

        let file = RpolFile::parse(DATASET_POLICY).expect("clean rpol");
        let (customers, bindings) = full_bindings();
        let mut store = SetStore::new();
        let compiled = file
            .compile_policy_bound("origin-guard", &[], &mut store, &bindings)
            .expect("policy exists")
            .expect("bindings complete");
        let chain = PolicyChain::from_named(vec![NamedPolicy::from_rpol(
            "origin-guard".to_string(),
            Arc::new(compiled),
        )]);
        // Move to generation 7 to pin the rendered number.
        for extra in 0..6u32 {
            customers
                .refresh(DatasetData::Asn(AsnSet::new([64500, 64600 + extra])))
                .expect("content changed");
        }
        let mut ctx = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
        ctx.origin_asn = Some(64500);
        let trace = crate::explain_chain_statements(Some(&chain), &ctx);
        let lines = trace.steps[0].term_traces.join("\n");
        assert!(
            lines.contains("route.origin-as in customers [dataset asn-set customers, gen 7]"),
            "{lines}"
        );
        assert!(!lines.contains("64500"), "content leaked: {lines}");
    }

    /// Datasets declared in imported modules are usable by importers
    /// (declarations merge like set definitions).
    #[test]
    fn imported_module_datasets_merge() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("lib.rpol"), "dataset asn-set customers\n")
            .expect("write lib");
        std::fs::write(
            dir.path().join("main.rpol"),
            "import \"lib.rpol\"\npolicy p { term t { if route.origin-as in customers { accept } } term r { reject } }\n",
        )
        .expect("write main");
        let file = RpolFile::load(&dir.path().join("main.rpol"), &[]).expect("loads");
        assert_eq!(
            file.dataset_decls().collect::<Vec<_>>(),
            vec![("customers", DatasetKind::Asn)]
        );
        let handle = asn_handle("customers", &[64500]);
        let mut store = SetStore::new();
        let chain = file
            .compile_policy_bound("p", &[], &mut store, &bindings_for(&[handle]))
            .expect("policy exists")
            .expect("bindings complete");
        let mut ctx = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
        ctx.origin_asn = Some(64500);
        assert_eq!(chain.evaluate(&ctx).action, PolicyAction::Permit);
    }

    /// Binding and parameter probes stay runtime probes (content is
    /// external — a parameter probe must see swaps too).
    #[test]
    fn binding_and_parameter_probes_track_swaps() {
        let file = RpolFile::parse(
            r"
dataset asn-set customers

policy scrub(target: u32) {
    term param-probe { if target in customers { accept } }
    term binding-probe {
        for asn in route.as-path {
            if asn in customers { accept }
        }
    }
    term rest { reject }
}
",
        )
        .expect("clean rpol");
        let handle = asn_handle("customers", &[]);
        let bindings = bindings_for(&[Arc::clone(&handle)]);
        let mut store = SetStore::new();
        let chain = file
            .compile_policy_bound("scrub", &[64500], &mut store, &bindings)
            .expect("policy exists")
            .expect("bindings complete");
        let ctx = route_ctx(v4(10, 0, 0, 0, 24), &[], RpkiValidation::NotFound);
        assert_eq!(chain.evaluate(&ctx).action, PolicyAction::Deny);
        handle
            .refresh(DatasetData::Asn(AsnSet::new([64500])))
            .expect("content changed");
        // The parameter probe fires post-swap without any recompile.
        assert_eq!(chain.evaluate(&ctx).action, PolicyAction::Permit);
    }
}

// ─────────────────────────────────────────────────────────────────────
// Test coverage + static lints (LAN-323)
// ─────────────────────────────────────────────────────────────────────

mod coverage {
    use super::super::{CoverageReport, LintKind, PolicyTestStatus, RpolFile, TermCoverage};

    fn coverage_of(source: &str) -> CoverageReport {
        let file = RpolFile::parse(source).expect("clean rpol");
        let (tests, cov) = file.run_tests_with_coverage();
        assert!(
            tests.all_passed(),
            "fixture tests must pass: {:?}",
            tests.failures
        );
        cov
    }

    fn term<'a>(cov: &'a CoverageReport, policy: &str, name: &str) -> &'a TermCoverage {
        cov.policies
            .iter()
            .find(|p| p.name == policy)
            .expect("policy present")
            .terms
            .iter()
            .find(|t| t.name == name)
            .expect("term present")
    }

    /// The three per-term facts: matched, evaluated-but-never-matched,
    /// and never-evaluated (earlier terms always decided) — plus the
    /// headline exercised count and the unconditional-term rule
    /// (matched whenever reached).
    #[test]
    fn attributes_evaluated_and_matched_per_term() {
        let cov = coverage_of(
            "
policy p {
    term a { if route.local-pref >= 500 { reject } }
    term b { if route.med <= 10 { accept } }
    term c { reject }
}

test hits-b {
    route { prefix 10.0.0.0/24; med 5 }
    expect p == accept
}

test falls-to-c {
    route { prefix 10.0.0.0/24; med 50 }
    expect p == reject
}
",
        );
        // Walk 1 decides at b; walk 2 falls through to c.
        assert_eq!(
            term(&cov, "p", "a"),
            &TermCoverage {
                name: "a".into(),
                evaluated: 2,
                matched: 0
            }
        );
        assert_eq!(
            term(&cov, "p", "b"),
            &TermCoverage {
                name: "b".into(),
                evaluated: 2,
                matched: 1
            }
        );
        // Unconditional c matches whenever reached.
        assert_eq!(
            term(&cov, "p", "c"),
            &TermCoverage {
                name: "c".into(),
                evaluated: 1,
                matched: 1
            }
        );
        assert_eq!(cov.terms_total(), 3);
        assert_eq!(cov.terms_exercised(), 3);
    }

    /// A term earlier walks always decide past is never evaluated, and
    /// parameterized instantiations aggregate into one policy entry.
    #[test]
    fn never_evaluated_terms_and_instantiations_aggregate() {
        let cov = coverage_of(
            "
policy pin(lp: u32) {
    term probe { if route.med == lp { accept } }
    term fallthrough { accept }
    term never { reject }
}

test med-200 {
    route { prefix 10.0.0.0/24; med 200 }
    expect pin(200) == accept
    expect pin(300) == accept
}
",
        );
        // pin(200): probe matches and decides. pin(300): probe misses,
        // fallthrough decides. `never` sits behind an unconditional
        // accept in both instantiations.
        assert_eq!(term(&cov, "pin", "probe").evaluated, 2);
        assert_eq!(term(&cov, "pin", "probe").matched, 1);
        assert_eq!(term(&cov, "pin", "fallthrough").evaluated, 1);
        assert_eq!(term(&cov, "pin", "fallthrough").matched, 1);
        assert_eq!(term(&cov, "pin", "never").evaluated, 0);
        assert_eq!(cov.terms_exercised(), 2);
        // ... and the unreachable-term lint agrees about `never`.
        assert!(
            cov.lints
                .iter()
                .any(|l| l.kind == LintKind::UnreachableTerm && l.message.contains("term never")),
            "{:?}",
            cov.lints
        );
    }

    /// `apply` targets are exercised as inlined predicates — reported
    /// as apply-only (no term attribution), never as untested; a policy
    /// nothing references is untested and lint-flagged.
    #[test]
    fn apply_only_and_untested_statuses() {
        let cov = coverage_of(
            "
policy helper {
    term inner { if route.med == 1 { accept } }
    term rest { reject }
}

policy outer {
    term probe { if apply(helper) { accept } }
}

policy orphan {
    term x { reject }
}

test t {
    route { prefix 10.0.0.0/24; med 1 }
    expect outer == accept
}
",
        );
        let status = |name: &str| {
            cov.policies
                .iter()
                .find(|p| p.name == name)
                .expect("policy present")
                .status
        };
        assert_eq!(status("outer"), PolicyTestStatus::Tested);
        assert_eq!(status("helper"), PolicyTestStatus::ApplyOnly);
        assert_eq!(status("orphan"), PolicyTestStatus::Untested);
        // Term-level facts through apply are not attributable: helper's
        // terms stay unexercised in the headline count.
        assert_eq!(term(&cov, "helper", "inner").evaluated, 0);
        // Unreferenced-policy flags only the orphan — helper is
        // applied, outer is tested.
        let unreferenced: Vec<&str> = cov
            .lints
            .iter()
            .filter(|l| l.kind == LintKind::UnreferencedPolicy)
            .map(|l| l.message.as_str())
            .collect();
        assert_eq!(unreferenced.len(), 1, "{unreferenced:?}");
        assert!(unreferenced[0].contains("policy orphan"));
    }

    /// Unused sets, datasets, and fns are flagged; referenced ones are
    /// not (including fn-to-fn calls).
    #[test]
    fn unused_definition_lints() {
        let cov = coverage_of(
            "
prefix-set used-set { 10.0.0.0/8 le 32 }
prefix-set dead-set { 192.0.2.0/24 }
asn-set loop-set { 64512 }
dataset asn-set dead-data

fn helper(x: u32) -> u32 { x + 1 }
fn wrapper(x: u32) -> u32 { helper(x) * 2 }
fn dead-fn(x: u32) -> u32 { x }

policy p {
    term t {
        if route.prefix in used-set {
            set med wrapper(1);
            accept
        }
    }
    term l {
        for asn in loop-set {
            if asn in loop-set { reject }
        }
    }
}
",
        );
        let lints: Vec<(LintKind, &str)> = cov
            .lints
            .iter()
            .map(|l| (l.kind, l.message.as_str()))
            .collect();
        assert!(
            lints
                .iter()
                .any(|(k, m)| *k == LintKind::UnusedSet && m.contains("dead-set")),
            "{lints:?}"
        );
        assert!(
            lints
                .iter()
                .any(|(k, m)| *k == LintKind::UnusedDataset && m.contains("dead-data")),
            "{lints:?}"
        );
        assert!(
            lints
                .iter()
                .any(|(k, m)| *k == LintKind::UnusedFn && m.contains("dead-fn")),
            "{lints:?}"
        );
        // Everything referenced stays off the list: used-set (guard),
        // loop-set (for-source + binding probe), wrapper (action
        // value), helper (called by wrapper).
        assert!(
            !lints.iter().any(|(_, m)| m.contains("used-set")),
            "{lints:?}"
        );
        assert!(
            !lints.iter().any(|(_, m)| m.contains("loop-set")),
            "{lints:?}"
        );
        assert!(
            !lints.iter().any(|(_, m)| m.contains("fn wrapper")),
            "{lints:?}"
        );
        assert!(
            !lints.iter().any(|(_, m)| m.contains("fn helper")),
            "{lints:?}"
        );
    }

    /// The unreachable-term lint covers exactly the static cases: a
    /// bare terminal action, an `if`/`else` with both branches
    /// terminal, and a constant guard that folds true (#768 folding).
    /// Runtime guards stay conservatively reachable.
    #[test]
    fn unreachable_term_lint_constant_cases() {
        let unreachable = |source: &str| -> Vec<String> {
            coverage_of(source)
                .lints
                .iter()
                .filter(|l| l.kind == LintKind::UnreachableTerm)
                .map(|l| l.message.clone())
                .collect()
        };
        // Bare terminal action.
        let found = unreachable("policy p { term all { accept } term dead { reject } }");
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("term dead") && found[0].contains("term all"));
        // Both branches terminal — decides regardless of the guard.
        let found = unreachable(
            "policy p {
                term split { if route.med == 1 { accept } else { reject } }
                term dead { reject }
            }",
        );
        assert_eq!(found.len(), 1, "{found:?}");
        // Constant guard folding true with a terminal branch.
        let found = unreachable(
            "policy p {
                term folded { if min(4, 2) >= 1 { accept } }
                term dead { reject }
            }",
        );
        assert_eq!(found.len(), 1, "{found:?}");
        // A runtime guard without an else decides nothing statically.
        let found = unreachable(
            "policy p {
                term maybe { if route.med == 1 { accept } }
                term reachable { reject }
            }",
        );
        assert!(found.is_empty(), "{found:?}");
    }

    /// Coverage never changes test outcomes: the report from
    /// `run_tests_with_coverage` equals `run_tests`' — including for a
    /// failing suite (which still gets attributed).
    #[test]
    fn coverage_run_preserves_test_outcomes() {
        let source = "
policy p {
    term a { if route.med <= 10 { accept } }
    term b { reject }
}

test passes {
    route { prefix 10.0.0.0/24; med 5 }
    expect p == accept
}

test fails {
    route { prefix 10.0.0.0/24; med 50 }
    expect p == accept
}
";
        let file = RpolFile::parse(source).expect("clean rpol");
        let plain = file.run_tests();
        let (with_cov, cov) = file.run_tests_with_coverage();
        assert_eq!(plain, with_cov);
        assert_eq!(with_cov.failures.len(), 1);
        // The failing walk still counted: both walks evaluated `a`.
        assert_eq!(
            cov.policies
                .iter()
                .find(|p| p.name == "p")
                .expect("policy present")
                .terms[0]
                .evaluated,
            2
        );
    }
}
