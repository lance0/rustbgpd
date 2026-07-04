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
        as_path_len: 0,
        validation_state: rpki,
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
        as_path_len: 3,
        ..base
    };
    assert_eq!(chain.evaluate(&long).action, PolicyAction::Deny);
    let leaf = RouteContext {
        as_path_str: "65010 65011",
        as_path_len: 2,
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
        rendered.contains("unknown parameter `peer_pl`"),
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

/// Run `check_rpol` on `src` in a small-stack thread so an unguarded
/// recursive front overflows fast and deterministically instead of
/// depending on the host's default stack size.
fn check_on_small_stack(src: String) -> super::CheckReport {
    std::thread::Builder::new()
        .stack_size(1024 * 1024)
        .spawn(move || check_rpol(&src))
        .expect("spawn")
        .join()
        .expect("policy compilation must never crash the thread")
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
        as_path_len: 0,
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
