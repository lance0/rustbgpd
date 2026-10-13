//! The `set next-hop` reach analysis that config validation uses to refuse a
//! labeled/VPN export binding, checked branch by branch against the
//! evaluator: a guard the analysis calls exclusive must never match a route
//! of that family, and every other guard here does match one.

use std::sync::Arc;

use crate::ir::{Cmp, CompiledChain, CompiledPolicy, MatchExpr, PolicySource, Term, TermAction};

use super::*;

const LABELED: [RouteFamily; 4] = [
    RouteFamily::Ipv4LabeledUnicast,
    RouteFamily::Ipv6LabeledUnicast,
    RouteFamily::Vpnv4,
    RouteFamily::Vpnv6,
];

/// One term: `guard` sets the next hop and, as an evaluator-visible marker
/// (no next-hop action applies to these families), the MED.
fn chain(guard: MatchExpr) -> CompiledChain {
    let mut chain = CompiledChain::empty();
    chain.policies.push(CompiledPolicy {
        name: Some(Arc::from("p")),
        terms: vec![Term {
            name: Some("t".to_string()),
            guard,
            action: TermAction::Permit(RouteModifications {
                set_next_hop: Some(NextHopAction::Self_),
                set_med: Some(7),
                ..RouteModifications::default()
            }),
        }],
        default_action: PolicyAction::Permit,
        source: PolicySource::Rpol,
    });
    chain
}

/// Does the evaluator match `guard` for some route of `family`? A non-EVPN
/// route carries no EVPN route type; MED takes each value the guards test.
fn evaluator_matches(compiled: &CompiledChain, family: RouteFamily) -> bool {
    let chain = PolicyChain::from_named(vec![NamedPolicy::from_rpol(
        "p".to_string(),
        Arc::new(compiled.clone()),
    )]);
    [None, Some(0), Some(5)].into_iter().any(|med| {
        let ctx = RouteContext {
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
            family: Some(family),
            evpn_route_type: None,
            local_pref: None,
            med,
        };
        chain.evaluate(&ctx).modifications.set_med == Some(7)
    })
}

#[test]
fn reach_analysis_agrees_with_the_evaluator_per_branch() {
    use MatchExpr::{And, EvpnRouteTypeIs, EvpnRouteTypeNe, FamilyIs, FamilyNe, Not, Or, True};
    let not = |inner: MatchExpr| Not(Box::new(inner));
    let med5 = || MatchExpr::Med(Cmp::Ge(5));
    let vpnv4 = RouteFamily::Vpnv4;
    let v4u = RouteFamily::Ipv4Unicast;
    // (guard, family it is checked for, analysis must call it exclusive)
    let cases: Vec<(&str, MatchExpr, RouteFamily, bool)> = vec![
        ("true", True, vpnv4, false),
        ("not true", not(True), vpnv4, true),
        ("family == ipv4-unicast", FamilyIs(v4u), vpnv4, true),
        ("family == vpnv4", FamilyIs(vpnv4), vpnv4, false),
        ("family != vpnv4", FamilyNe(vpnv4), vpnv4, true),
        ("family != ipv4-unicast", FamilyNe(v4u), vpnv4, false),
        ("evpn-route-type == 2", EvpnRouteTypeIs(2), vpnv4, true),
        ("evpn-route-type != 2", EvpnRouteTypeNe(2), vpnv4, true),
        (
            "!(evpn-route-type == 2)",
            not(EvpnRouteTypeIs(2)),
            vpnv4,
            false,
        ),
        (
            "!(evpn-route-type != 2)",
            not(EvpnRouteTypeNe(2)),
            vpnv4,
            false,
        ),
        (
            "evpn-route-type == 2 || family == ipv4-unicast",
            Or(vec![EvpnRouteTypeIs(2), FamilyIs(v4u)]),
            vpnv4,
            true,
        ),
        (
            "family == ipv4-unicast && med",
            And(vec![FamilyIs(v4u), med5()]),
            vpnv4,
            true,
        ),
        (
            "med && family == vpnv4",
            And(vec![med5(), FamilyIs(vpnv4)]),
            vpnv4,
            false,
        ),
        (
            "family == ipv4-unicast || med",
            Or(vec![FamilyIs(v4u), med5()]),
            vpnv4,
            false,
        ),
        ("!(family == vpnv4)", not(FamilyIs(vpnv4)), vpnv4, true),
        (
            "!(family == ipv4-unicast)",
            not(FamilyIs(v4u)),
            vpnv4,
            false,
        ),
        ("!(family != ipv4-unicast)", not(FamilyNe(v4u)), vpnv4, true),
        ("!(family != vpnv4)", not(FamilyNe(vpnv4)), vpnv4, false),
        (
            "!(family == vpnv4 && med)",
            not(And(vec![FamilyIs(vpnv4), med5()])),
            vpnv4,
            false,
        ),
        (
            "!(family == vpnv4 || med)",
            not(Or(vec![FamilyIs(vpnv4), med5()])),
            vpnv4,
            true,
        ),
        (
            "!!(family == ipv4-unicast)",
            not(not(FamilyIs(v4u))),
            vpnv4,
            true,
        ),
        (
            "!!(family == vpnv4)",
            not(not(FamilyIs(vpnv4))),
            vpnv4,
            false,
        ),
        ("med alone", med5(), vpnv4, false),
    ];
    for (label, guard, family, exclusive) in cases {
        let compiled = chain(guard);
        assert_eq!(
            compiled.set_next_hop_reaching(family).is_none(),
            exclusive,
            "analysis: {label} for {family:?}"
        );
        assert_eq!(
            evaluator_matches(&compiled, family),
            !exclusive,
            "evaluator: {label} for {family:?}"
        );
    }
}

/// The EVPN route-type guards exclude every labeled and VPN family alike.
#[test]
fn evpn_route_type_guards_exclude_every_labeled_family() {
    for family in LABELED {
        for guard in [MatchExpr::EvpnRouteTypeIs(2), MatchExpr::EvpnRouteTypeNe(2)] {
            let compiled = chain(guard.clone());
            assert!(
                compiled.set_next_hop_reaching(family).is_none(),
                "{guard:?} {family:?}"
            );
            assert!(
                !evaluator_matches(&compiled, family),
                "{guard:?} {family:?}"
            );
        }
    }
}
