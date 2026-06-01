use std::net::{IpAddr, Ipv4Addr};

use rustbgpd_wire::AspaValidation;

use super::*;

// `matches` was rewritten from an eager "evaluate every predicate, then AND"
// into a cost-ordered short-circuit chain. These tests pin the *combined*
// control flow (not just per-field behavior): a statement with every match
// predicate set must still match when all of them match (reaching the `true`
// tail), and a cheap predicate failure must decide the result even when the
// expensive community / AS_PATH-regex predicates would have matched.

/// A statement exercising every match predicate at once.
fn all_predicates_statement() -> PolicyStatement {
    let mut s = stmt(
        Some(v4_entry([10, 20, 30, 0], 24)),
        PolicyAction::Deny,
        vec![CommunityMatch::Standard {
            value: (65001u32 << 16) | 0x0064,
        }],
    );
    s.ge = Some(24);
    s.le = Some(32);
    s.match_as_path = Some(AsPathRegex::new("_65100_").unwrap());
    s.match_neighbor_set = Some(NeighborSetMatch {
        addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
        remote_asns: vec![],
        peer_groups: vec![],
    });
    s.match_route_type = Some(RouteType::External);
    s.match_evpn_route_type = Some(2);
    s.match_rpki_validation = Some(RpkiValidation::Valid);
    s.match_aspa_validation = Some(AspaValidation::Valid);
    s.match_as_path_length_ge = Some(1);
    s.match_as_path_length_le = Some(8);
    s.match_local_pref_ge = Some(100);
    s.match_local_pref_le = Some(300);
    s.match_med_ge = Some(0);
    s.match_med_le = Some(100);
    s.match_next_hop = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    s
}

/// A route context that satisfies every predicate in `all_predicates_statement`.
fn matching_ctx(communities: &[u32]) -> RouteContext<'_> {
    let mut c = ctx(
        v4_prefix([10, 20, 30, 0], 24),
        &[],
        communities,
        &[],
        "65001 65100 65200",
        3,
        RpkiValidation::Valid,
    );
    c.aspa_state = AspaValidation::Valid;
    c.peer_address = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    c.route_type = Some(RouteType::External);
    c.evpn_route_type = Some(2);
    c.local_pref = Some(150);
    c.med = Some(50);
    c.next_hop = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    c
}

#[test]
fn all_predicates_set_and_matching_still_matches() {
    let pl = Policy {
        entries: vec![all_predicates_statement()],
        default_action: PolicyAction::Permit,
    };
    let communities = vec![(65001u32 << 16) | 0x0064];
    let route_ctx = matching_ctx(&communities);
    // Every configured predicate matches → the statement's Deny action wins
    // over the default Permit.
    assert_eq!(pl.evaluate(&route_ctx).action, PolicyAction::Deny);
}

#[test]
fn cheap_predicate_miss_short_circuits_before_expensive_match() {
    let pl = Policy {
        entries: vec![all_predicates_statement()],
        default_action: PolicyAction::Permit,
    };
    let communities = vec![(65001u32 << 16) | 0x0064];
    let mut route_ctx = matching_ctx(&communities);
    // Flip a cheap scalar predicate so it fails. The community filter and the
    // AS_PATH regex would both still match this route, but the cheap route_type
    // miss decides the outcome first — the statement must not match, so the
    // chain's default Permit applies.
    route_ctx.route_type = Some(RouteType::Internal);
    assert_eq!(pl.evaluate(&route_ctx).action, PolicyAction::Permit);
}
