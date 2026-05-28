//! Criterion benchmark for the import/export policy evaluation hot path.
//!
//! `evaluate_chain_with_attribution` runs once per NLRI on every inbound
//! UPDATE (and per route on export distribution), so its cost scales the
//! whole control plane under churn. This bench measures the dominant
//! shape — a community-filter chain walked statement-by-statement — at a
//! few chain lengths, plus the early-terminate (first-statement deny)
//! contrast that bounds the best case.
//!
//! Run: `cargo bench -p rustbgpd-policy --bench policy_eval`
//! Compare across refs: `bench/compare-criterion.sh --package
//! rustbgpd-policy --bench policy_eval`.

use std::net::{IpAddr, Ipv4Addr};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use rustbgpd_policy::{
    CommunityMatch, Policy, PolicyAction, PolicyChain, PolicyStatement, RouteContext,
    RouteModifications, evaluate_chain_with_attribution,
};
use rustbgpd_wire::{AspaValidation, Ipv4Prefix, Prefix, RpkiValidation};

/// A statement that matches any prefix but requires a standard community
/// the benchmarked route does not carry — so evaluation checks prefix
/// (match) then community (miss) and walks on to the next statement.
/// This is the realistic "filter chain" cost: every statement is
/// examined because none short-circuits to a terminal action.
fn non_matching_community_stmt(idx: u32) -> PolicyStatement {
    PolicyStatement {
        prefix: Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0))),
        ge: Some(0),
        le: Some(32),
        action: PolicyAction::Permit,
        // Require a community the route lacks (route carries 65001:100).
        match_community: vec![CommunityMatch::Standard {
            value: (65500u32 << 16) | idx,
        }],
        match_as_path: None,
        match_neighbor_set: None,
        match_route_type: None,
        match_evpn_route_type: None,
        match_rpki_validation: None,
        match_aspa_validation: None,
        match_as_path_length_ge: None,
        match_as_path_length_le: None,
        match_local_pref_ge: None,
        match_local_pref_le: None,
        match_med_ge: None,
        match_med_le: None,
        match_next_hop: None,
        modifications: RouteModifications::default(),
    }
}

/// Build a chain of `len` non-matching community statements, terminating
/// in the chain's implicit default permit.
fn walk_chain(len: u32) -> PolicyChain {
    PolicyChain::new(vec![Policy {
        entries: (0..len).map(non_matching_community_stmt).collect(),
        default_action: PolicyAction::Permit,
    }])
}

/// A 32-statement chain whose **first** statement matches the route's
/// prefix and denies, followed by 31 non-matching statements that are
/// never reached. This guards short-circuit behaviour: contrasted with
/// `policy_chain_eval/32` (which walks all 32), a working early-out
/// terminates at statement 1 and costs ~the 1-statement walk, not the
/// 32-statement walk — so the trailing tail must be present for the
/// "regardless of chain length behind it" claim to mean anything.
fn early_deny_chain() -> PolicyChain {
    let mut deny = non_matching_community_stmt(0);
    deny.match_community.clear(); // match on prefix alone → Deny terminates
    deny.action = PolicyAction::Deny;
    let mut entries = vec![deny];
    entries.extend((1..32).map(non_matching_community_stmt));
    PolicyChain::new(vec![Policy {
        entries,
        default_action: PolicyAction::Permit,
    }])
}

fn bench_policy_eval(c: &mut Criterion) {
    // Backing data for the borrowed RouteContext fields. Built once;
    // the timed closure only re-runs evaluation.
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 20, 30, 0), 24));
    let communities: Vec<u32> = vec![(65001u32 << 16) | 100];
    let as_path_str = "65001 65100 65200".to_string();
    let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let ctx = RouteContext {
        prefix,
        next_hop: Some(peer_ip),
        extended_communities: &[],
        communities: &communities,
        large_communities: &[],
        as_path_str: &as_path_str,
        as_path_len: 3,
        validation_state: RpkiValidation::NotFound,
        aspa_state: AspaValidation::Unknown,
        peer_address: Some(peer_ip),
        peer_asn: Some(65001),
        peer_group: None,
        route_type: None,
        evpn_route_type: None,
        local_pref: Some(100),
        med: Some(50),
    };

    let mut group = c.benchmark_group("policy_chain_eval");
    for len in [1u32, 8, 32] {
        let chain = walk_chain(len);
        group.bench_with_input(BenchmarkId::from_parameter(len), &chain, |b, chain| {
            b.iter(|| {
                let (result, eval) =
                    evaluate_chain_with_attribution(Some(std::hint::black_box(chain)), &ctx);
                std::hint::black_box((result, eval));
            });
        });
    }
    group.finish();

    let early = early_deny_chain();
    c.bench_function("policy_chain_eval/early_deny", |b| {
        b.iter(|| {
            let (result, eval) =
                evaluate_chain_with_attribution(Some(std::hint::black_box(&early)), &ctx);
            std::hint::black_box((result, eval));
        });
    });
}

criterion_group!(benches, bench_policy_eval);
criterion_main!(benches);
