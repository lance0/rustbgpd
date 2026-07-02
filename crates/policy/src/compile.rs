//! TOML-chain → IR compiler (ADR-0096 Decision 5).
//!
//! Every `PolicyStatement` compiles to one [`Term`] whose guard is the
//! And of its configured predicates — exactly mirroring the legacy
//! matcher's semantics, including the RFC 4271 implicit `LOCAL_PREF`
//! 100 / `MED` 0 defaults (those live in the evaluator's `Cmp`
//! handling), first-match-wins within a policy, and `GoBGP` chain
//! semantics across policies. Decision compatibility with the legacy
//! evaluator is pinned by the golden corpus in
//! `engine/tests/ir_parity.rs`.
//!
//! Match data with more than one member (a statement's
//! `match_community` OR-list) is interned through the [`SetStore`]
//! into indexed, content-deduplicated sets; single-criterion matches
//! stay inline (no set indirection for the trivial case). TOML
//! statements carry at most one prefix, so this frontend never emits
//! [`MatchExpr::PrefixInSet`] — prefix sets arrive with the `.rpol`
//! frontend (and are already evaluable for hand-built IR).

use std::sync::Arc;

use crate::engine::{AsPathRegex, PolicyAction, PolicyChain, PolicyStatement};
use crate::ir::{
    Cmp, CompiledChain, CompiledPolicy, MatchExpr, PolicySource, RegexId, SetId, Term, TermAction,
};
use crate::sets::{CommunitySet, SetStore};

/// Compile a TOML policy chain into the IR, interning match sets and
/// regexes through `store` (identical set data across policies — or
/// across chains compiled through the same store — shares one `Arc`'d
/// structure).
#[must_use]
pub fn compile_chain(chain: &PolicyChain, store: &mut SetStore) -> CompiledChain {
    let mut sets = ChainSets::default();
    let policies = chain
        .policies
        .iter()
        .map(|named| CompiledPolicy {
            name: named.name.clone(),
            terms: named
                .policy
                .entries
                .iter()
                .map(|statement| compile_statement(statement, store, &mut sets))
                .collect(),
            default_action: named.policy.default_action,
            source: PolicySource::Toml,
        })
        .collect();
    CompiledChain {
        policies,
        prefix_sets: Vec::new(),
        community_sets: sets.community_sets,
        as_path_regexes: sets.as_path_regexes,
    }
}

fn compile_statement(
    statement: &PolicyStatement,
    store: &mut SetStore,
    sets: &mut ChainSets,
) -> Term {
    let mut children = Vec::new();

    // Emit in the legacy matcher's tier order (scalars → prefix →
    // neighbor-set → community → regex); the cost-class sort below is
    // then a stable no-op for TOML input but keeps the invariant
    // explicit for any future frontend that emits out of order.
    if let Some(route_type) = statement.match_route_type {
        children.push(MatchExpr::RouteTypeIs(route_type));
    }
    if let Some(evpn_type) = statement.match_evpn_route_type {
        children.push(MatchExpr::EvpnRouteTypeIs(evpn_type));
    }
    if let Some(state) = statement.match_rpki_validation {
        children.push(MatchExpr::RpkiIs(state));
    }
    if let Some(state) = statement.match_aspa_validation {
        children.push(MatchExpr::AspaIs(state));
    }
    if let Some(v) = statement.match_as_path_length_ge {
        children.push(MatchExpr::AsPathLen(Cmp::Ge(v)));
    }
    if let Some(v) = statement.match_as_path_length_le {
        children.push(MatchExpr::AsPathLen(Cmp::Le(v)));
    }
    if let Some(v) = statement.match_local_pref_ge {
        children.push(MatchExpr::LocalPref(Cmp::Ge(v)));
    }
    if let Some(v) = statement.match_local_pref_le {
        children.push(MatchExpr::LocalPref(Cmp::Le(v)));
    }
    if let Some(v) = statement.match_med_ge {
        children.push(MatchExpr::Med(Cmp::Ge(v)));
    }
    if let Some(v) = statement.match_med_le {
        children.push(MatchExpr::Med(Cmp::Le(v)));
    }
    if let Some(next_hop) = statement.match_next_hop {
        children.push(MatchExpr::NextHopEq(next_hop));
    }
    if let Some(prefix) = statement.prefix {
        children.push(MatchExpr::PrefixEq {
            prefix,
            ge: statement.ge,
            le: statement.le,
        });
    }
    if let Some(set) = statement.match_neighbor_set.as_ref() {
        children.push(MatchExpr::NeighborIn(Box::new(set.clone())));
    }
    match statement.match_community.as_slice() {
        [] => {}
        [single] => children.push(MatchExpr::CommunityContains(*single)),
        criteria => {
            let set = store.community_set(criteria);
            children.push(MatchExpr::CommunityInSet(sets.community_set_id(set)));
        }
    }
    if let Some(regex) = statement.match_as_path.as_ref() {
        let interned = store.as_path_regex(regex);
        children.push(MatchExpr::AsPathMatches(sets.regex_id(interned)));
    }

    // And is commutative and side-effect-free; order cheapest-first so
    // a cheap miss skips the expensive community/regex work.
    children.sort_by_key(MatchExpr::cost_class);

    let guard = match children.len() {
        0 => MatchExpr::True,
        1 => children.pop().expect("len checked"),
        _ => MatchExpr::And(children),
    };

    Term {
        name: None,
        guard,
        // A Deny statement's configured modifications are dropped at
        // compile time — the legacy evaluator returns
        // `PolicyResult::deny()` and never applies them.
        action: match statement.action {
            PolicyAction::Permit => TermAction::Permit(statement.modifications.clone()),
            PolicyAction::Deny => TermAction::Deny,
        },
    }
}

/// Chain-local set tables under construction: maps store-interned
/// `Arc`s to chain-local [`SetId`] / [`RegexId`] indexes, deduplicating
/// by `Arc` identity (chains are small; a linear scan beats a side
/// table).
#[derive(Default)]
struct ChainSets {
    community_sets: Vec<Arc<CommunitySet>>,
    as_path_regexes: Vec<Arc<AsPathRegex>>,
}

impl ChainSets {
    fn community_set_id(&mut self, set: Arc<CommunitySet>) -> SetId {
        let index = self
            .community_sets
            .iter()
            .position(|existing| Arc::ptr_eq(existing, &set))
            .unwrap_or_else(|| {
                self.community_sets.push(set);
                self.community_sets.len() - 1
            });
        SetId(u32::try_from(index).expect("set table fits u32"))
    }

    fn regex_id(&mut self, regex: Arc<AsPathRegex>) -> RegexId {
        let index = self
            .as_path_regexes
            .iter()
            .position(|existing| Arc::ptr_eq(existing, &regex))
            .unwrap_or_else(|| {
                self.as_path_regexes.push(regex);
                self.as_path_regexes.len() - 1
            });
        RegexId(u32::try_from(index).expect("regex table fits u32"))
    }
}
