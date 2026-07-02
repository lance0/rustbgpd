//! Criterion benchmark for the import/export policy evaluation hot path.
//!
//! `evaluate_chain_with_attribution` runs once per NLRI on every inbound
//! UPDATE (and per route on export distribution), so its cost scales the
//! whole control plane under churn.
//!
//! Three benchmark groups:
//!
//! - `policy_chain_eval` — the dominant shape, a community-filter chain
//!   walked statement-by-statement at a few chain lengths, plus the
//!   early-terminate (first-statement deny) contrast that bounds the best
//!   case. This is the cross-ref regression baseline. Known step (ADR-0096):
//!   the IR tree-walk costs ~7.2 ns/statement on this walk-everything shape
//!   vs ~5.2 for the old flat-struct matcher (the And-children `Vec` is one
//!   dependent load per statement) while every other shape below improved
//!   20-50%; the ADR's deferred linearized-bytecode pass is the recovery
//!   path if a fully-walked long chain ever dominates a profile.
//! - `policy_predicate_eval` — characterizes the cost-ordered short-circuit
//!   matcher. The `regex_heavy` and `community_heavy` arms each pair an
//!   `evaluated` case (the expensive predicate runs) against a `skipped`
//!   case (a cheap predicate fails first, so the short-circuit skips it);
//!   the delta is the expensive work the short-circuit avoids, and the
//!   relative sizes tell us whether "regex last" is the right order.
//!   `prefix_miss` is the skipped case for a prefix that does not contain
//!   the route while carrying a community + AS_PATH regex that *would* match.
//!   `prefix_heavy` walks a chain whose statements all run a full prefix
//!   evaluation (mask + ge/le bounds) — its absolute cost gates whether a
//!   build-time prefix-mask precompute is worth pursuing.
//! - `set_heavy` — the ADR-0096 set-index claim measured in-repo: a
//!   1,000-prefix list as a statement chain (legacy walker and IR term
//!   walk) vs one indexed `PrefixInSet` IR term. See `bench_set_heavy`.
//!
//! Run: `cargo bench -p rustbgpd-policy --bench policy_eval`
//! Compare across refs: `bench/compare-criterion.sh --package
//! rustbgpd-policy --bench policy_eval`.

use std::net::{IpAddr, Ipv4Addr};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use rustbgpd_policy::ir::{
    CompiledChain, CompiledPolicy, MatchExpr, PolicySource, SetId, Term, TermAction,
};
use rustbgpd_policy::sets::{PrefixSetEntry, SetStore};
use rustbgpd_policy::{
    AsPathRegex, CommunityMatch, Policy, PolicyAction, PolicyChain, PolicyStatement, RouteContext,
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
    let communities: Vec<u32> = vec![(65001u32 << 16) | 0x0064];
    let as_path_str = "65001 65100 65200".to_string();
    let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let ctx = RouteContext {
        prefix: Some(prefix),
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

/// A statement with every match field unset (matches any route, Permit).
fn blank_permit() -> PolicyStatement {
    PolicyStatement {
        prefix: None,
        ge: None,
        le: None,
        action: PolicyAction::Permit,
        match_community: vec![],
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

/// Wrap a single statement in a chain that otherwise defaults to Permit.
fn single(statement: PolicyStatement) -> PolicyChain {
    PolicyChain::new(vec![Policy {
        entries: vec![statement],
        default_action: PolicyAction::Permit,
    }])
}

fn matching_prefix() -> Prefix {
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 20, 30, 0), 24))
}

/// A statement that matches the route's prefix and carries an AS_PATH regex
/// that matches the route's AS_PATH. When `cheap_fail`, a Tier-1 scalar the
/// route fails is added so the short-circuit returns before the regex.
fn regex_stmt(cheap_fail: bool) -> PolicyStatement {
    let mut s = blank_permit();
    s.prefix = Some(matching_prefix());
    s.ge = Some(24);
    s.le = Some(32);
    s.match_as_path = Some(AsPathRegex::new("_65100_").unwrap());
    if cheap_fail {
        s.match_local_pref_ge = Some(999); // route LOCAL_PREF is 100
    }
    s
}

/// A statement whose community criterion is present at the end of the route's
/// (large) community set, so the scan does real work. `cheap_fail` adds a
/// Tier-1 scalar miss so the short-circuit returns before the scan.
fn community_stmt(cheap_fail: bool) -> PolicyStatement {
    let mut s = blank_permit();
    s.prefix = Some(matching_prefix());
    s.ge = Some(24);
    s.le = Some(32);
    s.match_community = vec![CommunityMatch::Standard {
        value: (65001u32 << 16) | 0x0040,
    }];
    if cheap_fail {
        s.match_local_pref_ge = Some(999);
    }
    s
}

/// A statement on a network the route is not part of (prefix miss at Tier 2),
/// carrying a community filter and an AS_PATH regex that *would* match if
/// reached — so the measured cost is purely the skipped expensive work.
fn prefix_miss_stmt() -> PolicyStatement {
    let mut s = blank_permit();
    s.prefix = Some(Prefix::V4(Ipv4Prefix::new(
        Ipv4Addr::new(192, 168, 0, 0),
        16,
    )));
    s.ge = Some(16);
    s.le = Some(32);
    s.match_community = vec![CommunityMatch::Standard {
        value: (65001u32 << 16) | 0x0040,
    }];
    s.match_as_path = Some(AsPathRegex::new("_65100_").unwrap());
    s
}

/// A chain whose statements match the route's network but exclude its length
/// via ge/le, so the prefix matcher runs in full (mask + bounds) and returns
/// false — the chain walks every statement doing prefix work only.
fn prefix_heavy_chain(len: u32) -> PolicyChain {
    let entries = (0..len)
        .map(|_| {
            let mut s = blank_permit();
            s.prefix = Some(matching_prefix());
            s.ge = Some(32);
            s.le = Some(32);
            s
        })
        .collect();
    PolicyChain::new(vec![Policy {
        entries,
        default_action: PolicyAction::Permit,
    }])
}

fn predicate_ctx<'a>(
    prefix: Prefix,
    communities: &'a [u32],
    as_path_str: &'a str,
    peer_ip: IpAddr,
) -> RouteContext<'a> {
    RouteContext {
        prefix: Some(prefix),
        next_hop: Some(peer_ip),
        extended_communities: &[],
        communities,
        large_communities: &[],
        as_path_str,
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
    }
}

fn bench_policy_predicate_eval(c: &mut Criterion) {
    let prefix = matching_prefix();
    let one_community: Vec<u32> = vec![(65001u32 << 16) | 0x0064];
    let many_communities: Vec<u32> = (1..=64u32).map(|i| (65001u32 << 16) | i).collect();
    let as_path_str = "65001 65100 65200".to_string();
    let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let ctx_one = predicate_ctx(prefix, &one_community, &as_path_str, peer_ip);
    let ctx_many = predicate_ctx(prefix, &many_communities, &as_path_str, peer_ip);

    let regex_eval = single(regex_stmt(false));
    let regex_skip = single(regex_stmt(true));
    let community_eval = single(community_stmt(false));
    let community_skip = single(community_stmt(true));
    let prefix_miss = single(prefix_miss_stmt());
    let prefix_heavy = prefix_heavy_chain(32);

    let mut group = c.benchmark_group("policy_predicate_eval");

    // regex_heavy: the AS_PATH regex runs vs. a cheap miss skipping it.
    group.bench_function("regex_heavy/evaluated", |b| {
        b.iter(|| {
            let r =
                evaluate_chain_with_attribution(Some(std::hint::black_box(&regex_eval)), &ctx_one);
            std::hint::black_box(r);
        });
    });
    group.bench_function("regex_heavy/skipped", |b| {
        b.iter(|| {
            let r =
                evaluate_chain_with_attribution(Some(std::hint::black_box(&regex_skip)), &ctx_one);
            std::hint::black_box(r);
        });
    });

    // community_heavy: a full community scan runs vs. a cheap miss skipping it.
    group.bench_function("community_heavy/evaluated", |b| {
        b.iter(|| {
            let r = evaluate_chain_with_attribution(
                Some(std::hint::black_box(&community_eval)),
                &ctx_many,
            );
            std::hint::black_box(r);
        });
    });
    group.bench_function("community_heavy/skipped", |b| {
        b.iter(|| {
            let r = evaluate_chain_with_attribution(
                Some(std::hint::black_box(&community_skip)),
                &ctx_many,
            );
            std::hint::black_box(r);
        });
    });

    // prefix_miss: prefix miss at Tier 2 skips a would-match community + regex.
    group.bench_function("prefix_miss", |b| {
        b.iter(|| {
            let r = evaluate_chain_with_attribution(
                Some(std::hint::black_box(&prefix_miss)),
                &ctx_many,
            );
            std::hint::black_box(r);
        });
    });

    // prefix_heavy: walk a chain doing full prefix evaluation per statement
    // (gates whether a build-time prefix-mask precompute is worth pursuing).
    group.bench_function("prefix_heavy/32", |b| {
        b.iter(|| {
            let r = evaluate_chain_with_attribution(
                Some(std::hint::black_box(&prefix_heavy)),
                &ctx_one,
            );
            std::hint::black_box(r);
        });
    });

    group.finish();
}

/// The ADR-0096 headline measurement: a 1,000-prefix customer list
/// expressed the only way TOML chains allow (1,000 statements) versus
/// a single indexed set-match IR term. Three arms over the same
/// non-member route — the worst case, where every statement (or the
/// one set probe) runs to completion:
///
/// - `legacy_1000_stmts` — the pre-IR statement walker (the corpus
///   oracle), i.e. what this cost *was*.
/// - `ir_1000_terms` — the same 1,000-statement chain through the IR
///   term walk: what existing TOML configs get automatically.
/// - `ir_prefix_set` — one `PrefixInSet` term over the interned set:
///   what the `.rpol` frontend (and any set-aware frontend) emits.
fn bench_set_heavy(c: &mut Criterion) {
    let prefixes: Vec<Prefix> = (0..1000u32)
        .map(|i| {
            Prefix::V4(Ipv4Prefix::new(
                Ipv4Addr::new(10, u8::try_from(i / 256).unwrap(), (i % 256) as u8, 0),
                24,
            ))
        })
        .collect();

    let statements: Vec<PolicyStatement> = prefixes
        .iter()
        .map(|p| {
            let mut s = blank_permit();
            s.prefix = Some(*p);
            s
        })
        .collect();
    let stmt_chain = PolicyChain::new(vec![Policy {
        entries: statements,
        default_action: PolicyAction::Deny,
    }]);

    let entries: Vec<PrefixSetEntry> = prefixes
        .iter()
        .map(|p| PrefixSetEntry {
            prefix: *p,
            ge: None,
            le: None,
        })
        .collect();
    let mut store = SetStore::new();
    let set = store.prefix_set(&entries);
    let set_chain = CompiledChain {
        policies: vec![CompiledPolicy {
            name: None,
            terms: vec![Term {
                name: None,
                guard: MatchExpr::PrefixInSet(SetId(0)),
                action: TermAction::Permit(RouteModifications::default()),
            }],
            default_action: PolicyAction::Deny,
            source: PolicySource::Toml,
        }],
        prefix_sets: vec![set],
        ..CompiledChain::empty()
    };

    // 172.16.0.0/24 is in no member's 10.x.y.0/24 — full walk / probe miss.
    let miss = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 24));
    let communities: Vec<u32> = Vec::new();
    let as_path_str = String::new();
    let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let ctx = predicate_ctx(miss, &communities, &as_path_str, peer_ip);

    let mut group = c.benchmark_group("set_heavy");
    group.bench_function("legacy_1000_stmts", |b| {
        b.iter(|| {
            let r = std::hint::black_box(&stmt_chain).evaluate_with_attribution_legacy(&ctx);
            std::hint::black_box(r);
        });
    });
    group.bench_function("ir_1000_terms", |b| {
        b.iter(|| {
            let r = evaluate_chain_with_attribution(Some(std::hint::black_box(&stmt_chain)), &ctx);
            std::hint::black_box(r);
        });
    });
    group.bench_function("ir_prefix_set", |b| {
        b.iter(|| {
            let r = std::hint::black_box(&set_chain).evaluate_with_attribution(&ctx);
            std::hint::black_box(r);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_policy_eval,
    bench_policy_predicate_eval,
    bench_set_heavy
);
criterion_main!(benches);
