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
        as_path_len: 3,
        origin_asn: None,
        ..base
    };
    assert_eq!(chain.evaluate(&long).action, PolicyAction::Deny);
    let leaf = RouteContext {
        as_path_str: "65010 65011",
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
        TermAction::Deny => panic!("expected a modifying term"),
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
    expect origin-pad == reject
}

test missing-peer-fails-closed {
    route { prefix 10.0.0.0/24 }
    expect peer-pad == reject
}

test missing-local-as-fails-closed {
    route { prefix 10.0.0.0/24 }
    peer { asn 65010 }
    expect self-pad == reject
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
    assert!(rendered.contains("unknown builtin `mim`"), "{rendered}");
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
        rendered.contains("unknown parameter `peer_lp`"),
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
    expect overflow-guard == reject
}

test no-overflow-accepts {
    route { med 5 }
    expect overflow-guard == accept
}

test divide-by-zero-denies {
    route { med 5 }
    expect div-zero == reject
}

test modulo-zero-denies {
    route { }
    expect mod-zero == reject
}

test absent-origin-denies {
    route { as-path "{64500 64501}" }
    expect absent-origin == reject
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
