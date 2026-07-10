//! Golden renderings for the explain guard pretty-printer
//! (`engine::explain::render_expr`): every `MatchExpr` node type has a
//! pinned `.rpol`-surface form, sets render by their source name where
//! the chain tables carry one, and `&&` / `||` / `!` parenthesize by
//! binding strength.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use super::super::explain::render_expr;
use super::*;
use crate::ir::{Cmp, CompiledChain, MatchExpr, SetId};
use crate::sets::{AsnSet, CommunitySet, PrefixSet, PrefixSetEntry};

/// A chain whose tables carry one named prefix set, one named
/// community set (standard criteria), and one regex — enough for every
/// table-referencing node.
fn tables() -> CompiledChain {
    CompiledChain {
        prefix_sets: vec![Arc::new(PrefixSet::new([PrefixSetEntry {
            prefix: v4_prefix([10, 10, 0, 0], 16),
            ge: Some(24),
            le: Some(28),
        }]))],
        community_sets: vec![Arc::new(CommunitySet::new([CommunityMatch::Standard {
            value: (65000 << 16) | 0x0064,
        }]))],
        asn_sets: vec![Arc::new(AsnSet::new([64500, 64501]))],
        as_path_regexes: vec![Arc::new(AsPathRegex::new("_65010_").unwrap())],
        prefix_set_names: vec![Some("customers".to_string())],
        community_set_names: vec![Some("cust-tags".to_string())],
        asn_set_names: vec![Some("cust-asns".to_string())],
        ..CompiledChain::empty()
    }
}

fn atom() -> MatchExpr {
    MatchExpr::RpkiIs(RpkiValidation::Invalid)
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one golden case per MatchExpr node type"
)]
fn every_node_type_renders_its_golden_form() {
    let tables = tables();
    let cases: Vec<(MatchExpr, &str)> = vec![
        (MatchExpr::True, "true"),
        (
            MatchExpr::PrefixInSet(SetId(0)),
            "route.prefix in customers",
        ),
        (
            MatchExpr::PrefixEq {
                prefix: v4_prefix([10, 0, 0, 0], 8),
                ge: Some(16),
                le: Some(24),
            },
            "route.prefix == 10.0.0.0/8 ge 16 le 24",
        ),
        (
            MatchExpr::PrefixEq {
                prefix: v4_prefix([192, 0, 2, 0], 24),
                ge: None,
                le: None,
            },
            "route.prefix == 192.0.2.0/24",
        ),
        (
            MatchExpr::CommunityContains(CommunityMatch::Standard {
                value: (65001 << 16) | 0x0064,
            }),
            "route.communities has 65001:100",
        ),
        (
            MatchExpr::CommunityContains(CommunityMatch::LargeCommunity {
                global_admin: 65000,
                local_data1: 1,
                local_data2: 2,
            }),
            "route.large-communities has LC:65000:1:2",
        ),
        (
            MatchExpr::CommunityContains(CommunityMatch::RouteTarget {
                global: 65001,
                local: 100,
            }),
            "route.ext-communities has RT:65001:100",
        ),
        (
            MatchExpr::CommunityInSet(SetId(0)),
            "route.communities in cust-tags",
        ),
        (
            MatchExpr::AsPathMatches(crate::ir::RegexId(0)),
            "route.as-path matches \"_65010_\"",
        ),
        (MatchExpr::AsPathLen(Cmp::Ge(3)), "route.as-path.len >= 3"),
        (MatchExpr::OriginAsEq(64500), "route.origin-as == 64500"),
        (MatchExpr::OriginAsNe(64500), "route.origin-as != 64500"),
        (
            MatchExpr::OriginAsInSet(SetId(0)),
            "route.origin-as in cust-asns",
        ),
        (MatchExpr::PeerAsInSet(SetId(0)), "peer.asn in cust-asns"),
        (MatchExpr::LocalPref(Cmp::Le(50)), "route.local-pref <= 50"),
        (MatchExpr::Med(Cmp::Ge(10)), "route.med >= 10"),
        (
            MatchExpr::NextHopEq(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            "route.next-hop == 10.0.0.1",
        ),
        (
            MatchExpr::NeighborIn(Box::new(NeighborSetMatch {
                addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
                ..NeighborSetMatch::default()
            })),
            "peer.address == 10.0.0.2",
        ),
        (
            MatchExpr::NeighborIn(Box::new(NeighborSetMatch {
                remote_asns: vec![65001],
                ..NeighborSetMatch::default()
            })),
            "peer.asn == 65001",
        ),
        (
            MatchExpr::NeighborIn(Box::new(NeighborSetMatch {
                peer_groups: vec!["edge".to_string()],
                ..NeighborSetMatch::default()
            })),
            "peer.group == \"edge\"",
        ),
        (
            MatchExpr::RouteTypeIs(RouteType::Internal),
            "route.route-type == internal",
        ),
        (MatchExpr::EvpnRouteTypeIs(2), "route.evpn-route-type == 2"),
        (
            MatchExpr::RpkiIs(RpkiValidation::NotFound),
            "route.rpki == not-found",
        ),
        (
            MatchExpr::AspaIs(rustbgpd_wire::AspaValidation::Unknown),
            "route.aspa == unknown",
        ),
        (MatchExpr::Not(Box::new(atom())), "!(route.rpki == invalid)"),
        // Empty compounds render their identity truth value.
        (MatchExpr::And(vec![]), "true"),
        (MatchExpr::Or(vec![]), "false"),
        // An empty neighbor set never matches.
        (MatchExpr::NeighborIn(Box::default()), "false"),
    ];
    for (expr, expected) in cases {
        assert_eq!(render_expr(&expr, &tables), expected, "node {expr:?}");
    }
}

#[test]
fn unnamed_sets_fall_back_to_indexed_placeholders() {
    let mut tables = tables();
    tables.prefix_set_names = vec![None];
    tables.community_set_names = Vec::new(); // shorter than the table
    assert_eq!(
        render_expr(&MatchExpr::PrefixInSet(SetId(0)), &tables),
        "route.prefix in prefix-set#0"
    );
    assert_eq!(
        render_expr(&MatchExpr::CommunityInSet(SetId(0)), &tables),
        "route.communities in community-set#0"
    );
    tables.asn_set_names = vec![None];
    assert_eq!(
        render_expr(&MatchExpr::OriginAsInSet(SetId(0)), &tables),
        "route.origin-as in asn-set#0"
    );
}

#[test]
fn compound_precedence_parenthesizes_or_under_and_and_multi_member_sets() {
    let tables = tables();
    let a = MatchExpr::LocalPref(Cmp::Ge(100));
    let b = MatchExpr::Med(Cmp::Le(5));
    let c = atom();

    // Or under And needs parens; And under Or does not.
    assert_eq!(
        render_expr(
            &MatchExpr::And(vec![a.clone(), MatchExpr::Or(vec![b.clone(), c.clone()])]),
            &tables
        ),
        "route.local-pref >= 100 && (route.med <= 5 || route.rpki == invalid)"
    );
    assert_eq!(
        render_expr(
            &MatchExpr::Or(vec![MatchExpr::And(vec![a.clone(), b.clone()]), c.clone()]),
            &tables
        ),
        "route.local-pref >= 100 && route.med <= 5 || route.rpki == invalid"
    );
    // A multi-member neighbor set is an internal `||`: parenthesized
    // when embedded in an And.
    let multi = MatchExpr::NeighborIn(Box::new(NeighborSetMatch {
        addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
        remote_asns: vec![65001],
        ..NeighborSetMatch::default()
    }));
    assert_eq!(
        render_expr(&multi, &tables),
        "peer.address == 10.0.0.2 || peer.asn == 65001"
    );
    assert_eq!(
        render_expr(&MatchExpr::And(vec![a, multi]), &tables),
        "route.local-pref >= 100 && (peer.address == 10.0.0.2 || peer.asn == 65001)"
    );
}
