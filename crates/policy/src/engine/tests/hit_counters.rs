//! Live per-term hit counters (ADR-0096 Decision 3.3): counts
//! accumulate across evaluations on the standard
//! `evaluate_with_attribution` path, reset when a chain instance is
//! replaced (clone or reinstall), and are safe to read concurrently
//! with evaluation.

use std::sync::Arc;

use super::*;
use crate::rpol::RpolFile;
use crate::sets::SetStore;

const RPOL: &str = r"
policy tagger {
    term rpki-guard {
        if route.rpki == invalid { reject }
    }
    term tag {
        set med 5;
    }
    term wide-open {
        if route.local-pref >= 0 { accept }
    }
}
";

fn rpol_chain() -> PolicyChain {
    let file = RpolFile::parse(RPOL).expect("clean rpol");
    let mut store = SetStore::new();
    let compiled = file
        .compile_policy("tagger", &[], &mut store)
        .expect("policy exists");
    PolicyChain::from_named(vec![NamedPolicy::from_rpol(
        "tagger".to_string(),
        Arc::new(compiled),
    )])
}

fn route(prefix: Prefix, rpki: RpkiValidation) -> RouteContext<'static> {
    RouteContext {
        prefix: Some(prefix),
        next_hop: None,
        extended_communities: &[],
        communities: &[],
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

#[test]
fn counts_accumulate_across_evaluations() {
    let chain = rpol_chain();
    let clean = route(v4_prefix([10, 0, 0, 0], 24), RpkiValidation::NotFound);
    let invalid = route(v4_prefix([10, 0, 1, 0], 24), RpkiValidation::Invalid);

    // Two clean routes walk tag + wide-open; one invalid route stops
    // at rpki-guard.
    for _ in 0..2 {
        let _ = chain.evaluate_with_attribution(&clean);
    }
    let _ = chain.evaluate_with_attribution(&invalid);

    assert_eq!(chain.hit_counters().evals(), 3);
    let rows = chain.term_hit_rows();
    assert_eq!(rows.len(), 3);
    for row in &rows {
        assert_eq!(row.policy.as_deref(), Some("tagger"));
        assert_eq!(row.policy_index, 0);
    }
    assert_eq!(rows[0].term.as_deref(), Some("rpki-guard"));
    assert_eq!(rows[0].hits, 1);
    assert_eq!(rows[1].term.as_deref(), Some("tag"));
    assert_eq!(rows[1].hits, 2);
    assert_eq!(rows[2].term.as_deref(), Some("wide-open"));
    assert_eq!(rows[2].hits, 2);
}

#[test]
fn toml_terms_have_no_name_and_still_count() {
    let chain = PolicyChain::from_named(vec![NamedPolicy {
        name: Some("toml".to_string()),
        policy: Policy {
            entries: vec![stmt(
                Some(v4_prefix([10, 0, 0, 0], 8)),
                PolicyAction::Permit,
                vec![],
            )],
            default_action: PolicyAction::Deny,
        },
        rpol: None,
    }]);
    // No ge/le on the statement = exact-length prefix match.
    let _ = chain.evaluate_with_attribution(&route(
        v4_prefix([10, 0, 0, 0], 8),
        RpkiValidation::NotFound,
    ));
    let rows = chain.term_hit_rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].term, None, "TOML statements are unnamed");
    assert_eq!(rows[0].term_index, 0);
    assert_eq!(rows[0].hits, 1);
}

/// Replacing a chain means installing a new instance (config apply
/// clones / rebuilds); the counters live on the instance, so the new
/// chain starts from zero — the "since chain install" contract.
#[test]
fn replaced_chain_instance_starts_from_zero() {
    let chain = rpol_chain();
    let clean = route(v4_prefix([10, 0, 0, 0], 24), RpkiValidation::NotFound);
    let _ = chain.evaluate_with_attribution(&clean);
    assert_eq!(chain.hit_counters().evals(), 1);

    let replacement = chain.clone();
    assert_eq!(replacement.hit_counters().evals(), 0);
    assert!(replacement.term_hit_rows().iter().all(|row| row.hits == 0));
    // The original keeps counting independently.
    let _ = chain.evaluate_with_attribution(&clean);
    assert_eq!(chain.hit_counters().evals(), 2);
    assert_eq!(replacement.hit_counters().evals(), 0);
}

#[test]
fn concurrent_evaluation_and_reads_agree_on_totals() {
    let chain = Arc::new(rpol_chain());
    let threads = 4;
    let per_thread = 1000;
    std::thread::scope(|scope| {
        for _ in 0..threads {
            let chain = Arc::clone(&chain);
            scope.spawn(move || {
                let clean = route(v4_prefix([10, 0, 0, 0], 24), RpkiValidation::NotFound);
                for _ in 0..per_thread {
                    let _ = chain.evaluate_with_attribution(&clean);
                    // Concurrent snapshot reads must never tear or panic.
                    let _ = chain.hit_counters().snapshot();
                }
            });
        }
    });
    let total = u64::try_from(threads * per_thread).unwrap();
    assert_eq!(chain.hit_counters().evals(), total);
    let rows = chain.term_hit_rows();
    assert_eq!(rows[1].hits, total, "tag matched every route");
    assert_eq!(rows[2].hits, total, "wide-open matched every route");
    assert_eq!(rows[0].hits, 0, "rpki-guard never matched");
}
