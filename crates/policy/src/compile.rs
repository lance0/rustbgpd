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
    Cmp, CompiledChain, CompiledPolicy, DatasetId, DatasetSlot, MatchExpr, PolicySource, RegexId,
    SetId, Term, TermAction,
};
use crate::sets::{AsnSet, CommunitySet, PrefixSet, SetStore};

/// Compile a TOML policy chain into the IR, interning match sets and
/// regexes through `store` (identical set data across policies — or
/// across chains compiled through the same store — shares one `Arc`'d
/// structure).
///
/// `.rpol`-backed chain members (`NamedPolicy.rpol`) arrive
/// pre-compiled from the config resolver; they are spliced into the
/// combined chain with their set/regex ids remapped into the chain's
/// merged tables (`Arc` identity dedupes tables shared across
/// members compiled from the same file).
#[must_use]
pub fn compile_chain(chain: &PolicyChain, store: &mut SetStore) -> CompiledChain {
    let mut sets = ChainSets::default();
    let mut policies = Vec::with_capacity(chain.policies.len());
    // `prepend as self` operand value (LAN-296): every rpol member of
    // one chain is stamped by the same config resolve with the same
    // `[global] asn`, so propagating the first `Some` into the spliced
    // chain is exact.
    let mut local_asn = None;
    for named in &chain.policies {
        if let Some(rpol) = named.rpol.as_deref() {
            local_asn = local_asn.or(rpol.local_asn);
            for policy in &rpol.policies {
                let mut spliced = splice_policy(policy, rpol, &mut sets);
                // Attribute to the configured chain-reference name
                // (e.g. `"customer-in(200)"`), matching how TOML
                // members are labeled for metrics / explain.
                spliced.name = named.name.clone().map(Arc::from);
                policies.push(spliced);
            }
            continue;
        }
        policies.push(CompiledPolicy {
            name: named.name.clone().map(Arc::from),
            terms: named
                .policy
                .entries
                .iter()
                .map(|statement| compile_statement(statement, store, &mut sets))
                .collect(),
            default_action: named.policy.default_action,
            source: PolicySource::Toml,
        });
    }
    CompiledChain {
        policies,
        prefix_sets: sets.prefix_sets,
        community_sets: sets.community_sets,
        asn_sets: sets.asn_sets,
        as_path_regexes: sets.as_path_regexes,
        prefix_set_names: sets.prefix_set_names,
        community_set_names: sets.community_set_names,
        asn_set_names: sets.asn_set_names,
        datasets: sets.datasets,
        local_asn,
    }
}

/// Copy one pre-compiled `.rpol` policy into the combined chain,
/// rewriting every `SetId` / `RegexId` from the donor chain's tables
/// into the merged chain tables.
fn splice_policy(
    policy: &CompiledPolicy,
    donor: &CompiledChain,
    sets: &mut ChainSets,
) -> CompiledPolicy {
    let terms = policy
        .terms
        .iter()
        .map(|term| Term {
            name: term.name.clone(),
            guard: remap_expr(&term.guard, donor, sets),
            action: term.action.clone(),
        })
        .collect();
    CompiledPolicy {
        name: policy.name.clone(),
        terms,
        default_action: policy.default_action,
        source: policy.source,
    }
}

/// Rewrite set/regex table ids from `donor`'s tables into `sets`.
/// Structure and semantics are otherwise preserved verbatim.
fn remap_expr(expr: &MatchExpr, donor: &CompiledChain, sets: &mut ChainSets) -> MatchExpr {
    match expr {
        MatchExpr::PrefixInSet(id) => {
            let index = id.0 as usize;
            MatchExpr::PrefixInSet(sets.prefix_set_id(
                donor.prefix_sets[index].clone(),
                donor.prefix_set_names.get(index).cloned().flatten(),
            ))
        }
        MatchExpr::CommunityInSet(id) => {
            let index = id.0 as usize;
            MatchExpr::CommunityInSet(sets.community_set_id(
                donor.community_sets[index].clone(),
                donor.community_set_names.get(index).cloned().flatten(),
            ))
        }
        MatchExpr::OriginAsInSet(id) => {
            let index = id.0 as usize;
            MatchExpr::OriginAsInSet(sets.asn_set_id(
                donor.asn_sets[index].clone(),
                donor.asn_set_names.get(index).cloned().flatten(),
            ))
        }
        MatchExpr::PeerAsInSet(id) => {
            let index = id.0 as usize;
            MatchExpr::PeerAsInSet(sets.asn_set_id(
                donor.asn_sets[index].clone(),
                donor.asn_set_names.get(index).cloned().flatten(),
            ))
        }
        MatchExpr::AsPathMatches(id) => {
            MatchExpr::AsPathMatches(sets.regex_id(donor.as_path_regexes[id.0 as usize].clone()))
        }
        // LAN-305: dataset probes remap into the merged dataset table.
        // Dataset names are daemon-global (one handle per name), so
        // deduping by name is exact across donors.
        MatchExpr::InDataset { probe, id } => MatchExpr::InDataset {
            probe: probe.clone(),
            id: sets.dataset_id(&donor.datasets[id.0 as usize]),
        },
        MatchExpr::And(children) => MatchExpr::And(
            children
                .iter()
                .map(|child| remap_expr(child, donor, sets))
                .collect(),
        ),
        MatchExpr::Or(children) => MatchExpr::Or(
            children
                .iter()
                .map(|child| remap_expr(child, donor, sets))
                .collect(),
        ),
        MatchExpr::Not(inner) => MatchExpr::Not(Box::new(remap_expr(inner, donor, sets))),
        other => other.clone(),
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
            children.push(MatchExpr::CommunityInSet(sets.community_set_id(set, None)));
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
    prefix_sets: Vec<Arc<PrefixSet>>,
    community_sets: Vec<Arc<CommunitySet>>,
    asn_sets: Vec<Arc<AsnSet>>,
    as_path_regexes: Vec<Arc<AsPathRegex>>,
    prefix_set_names: Vec<Option<String>>,
    community_set_names: Vec<Option<String>>,
    asn_set_names: Vec<Option<String>>,
    datasets: Vec<DatasetSlot>,
}

impl ChainSets {
    fn prefix_set_id(&mut self, set: Arc<PrefixSet>, name: Option<String>) -> SetId {
        let index = self
            .prefix_sets
            .iter()
            .position(|existing| Arc::ptr_eq(existing, &set))
            .unwrap_or_else(|| {
                self.prefix_sets.push(set);
                self.prefix_set_names.push(name);
                self.prefix_sets.len() - 1
            });
        SetId(u32::try_from(index).expect("set table fits u32"))
    }

    fn community_set_id(&mut self, set: Arc<CommunitySet>, name: Option<String>) -> SetId {
        let index = self
            .community_sets
            .iter()
            .position(|existing| Arc::ptr_eq(existing, &set))
            .unwrap_or_else(|| {
                self.community_sets.push(set);
                self.community_set_names.push(name);
                self.community_sets.len() - 1
            });
        SetId(u32::try_from(index).expect("set table fits u32"))
    }

    fn asn_set_id(&mut self, set: Arc<AsnSet>, name: Option<String>) -> SetId {
        let index = self
            .asn_sets
            .iter()
            .position(|existing| Arc::ptr_eq(existing, &set))
            .unwrap_or_else(|| {
                self.asn_sets.push(set);
                self.asn_set_names.push(name);
                self.asn_sets.len() - 1
            });
        SetId(u32::try_from(index).expect("set table fits u32"))
    }

    fn dataset_id(&mut self, slot: &DatasetSlot) -> DatasetId {
        let index = self
            .datasets
            .iter()
            .position(|existing| existing.name == slot.name)
            .unwrap_or_else(|| {
                self.datasets.push(slot.clone());
                self.datasets.len() - 1
            });
        DatasetId(u32::try_from(index).expect("dataset table fits u32"))
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use rustbgpd_wire::{Ipv4Prefix, Prefix};

    use crate::engine::{
        NamedPolicy, Policy, PolicyAction, PolicyChain, PolicyStatement, RouteContext,
        RouteModifications,
    };
    use crate::ir::{MatchExpr, PolicySource};
    use crate::rpol::RpolFile;
    use crate::sets::SetStore;

    const RPOL: &str = r#"
prefix-set customers { 10.10.0.0/16 ge 24 le 28 }

policy customer-in(peer_lp: u32) {
    term customer-routes {
        if route.prefix in customers { set local-pref peer_lp; accept }
    }
    term transit-guard {
        if route.as-path matches "_65010_" { reject }
    }
}

policy bogon-filter {
    term bogons { if route.prefix == 127.0.0.0/8 { reject } }
}
"#;

    fn ctx(prefix: Prefix, as_path_str: &str) -> RouteContext<'_> {
        RouteContext {
            prefix: Some(prefix),
            next_hop: None,
            extended_communities: &[],
            communities: &[],
            large_communities: &[],
            as_path_str,
            as_path: None,
            as_path_len: 1,
            origin_asn: None,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
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

    /// A TOML deny statement for 192.0.2.0/24, to mix into the chain.
    fn toml_deny_policy() -> NamedPolicy {
        NamedPolicy {
            name: Some("toml-deny".to_string()),
            policy: Policy {
                entries: vec![PolicyStatement {
                    prefix: Some(v4(192, 0, 2, 0, 24)),
                    ge: None,
                    le: None,
                    action: PolicyAction::Deny,
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
                }],
                default_action: PolicyAction::Permit,
            },
            rpol: None,
        }
    }

    /// Mixed TOML + monomorphized-rpol chain: the rpol member splices
    /// pre-compiled with its set/regex ids remapped into the merged
    /// chain tables, and evaluates with its instantiation argument.
    #[test]
    fn chain_splices_rpol_members_with_id_remap() {
        let file = RpolFile::parse(RPOL).expect("clean rpol");
        let mut store = SetStore::new();
        let customer = file
            .compile_policy("customer-in", &[200], &mut store)
            .expect("policy exists");
        let bogon = file
            .compile_policy("bogon-filter", &[], &mut store)
            .expect("policy exists");

        let chain = PolicyChain::from_named(vec![
            toml_deny_policy(),
            NamedPolicy::from_rpol("customer-in(200)".to_string(), Arc::new(customer)),
            NamedPolicy::from_rpol("bogon-filter".to_string(), Arc::new(bogon)),
        ]);
        let compiled = chain.compiled();
        assert_eq!(compiled.policies.len(), 3);
        assert_eq!(compiled.policies[0].source, PolicySource::Toml);
        assert_eq!(compiled.policies[1].source, PolicySource::Rpol);
        // Attribution uses the configured chain-reference name.
        assert_eq!(
            compiled.policies[1].name.as_deref(),
            Some("customer-in(200)")
        );
        // Both rpol members came from one file compiled through one
        // store: the (single) prefix set dedupes by Arc identity.
        assert_eq!(compiled.prefix_sets.len(), 1);
        assert_eq!(compiled.as_path_regexes.len(), 1);
        // The remapped PrefixInSet id must index the merged table.
        assert!(
            compiled.policies[1].terms[0]
                .guard
                .any_node(&|expr| matches!(expr, MatchExpr::PrefixInSet(id) if id.0 == 0))
        );

        // Evaluation end-to-end through the merged chain:
        // customer prefix → permit with the monomorphized local-pref.
        let (result, eval) = chain.evaluate_with_attribution(&ctx(v4(10, 10, 3, 0, 24), ""));
        assert_eq!(result.action, PolicyAction::Permit);
        assert_eq!(result.modifications.set_local_pref, Some(200));
        assert_eq!(eval.matched_policy.as_deref(), Some("bogon-filter"));
        // Transit AS in the path → the rpol regex guard denies.
        let (result, eval) =
            chain.evaluate_with_attribution(&ctx(v4(203, 0, 113, 0, 24), "65010 65020"));
        assert_eq!(result.action, PolicyAction::Deny);
        assert_eq!(eval.matched_policy.as_deref(), Some("customer-in(200)"));
        // TOML member still denies its prefix first.
        let (result, eval) = chain.evaluate_with_attribution(&ctx(v4(192, 0, 2, 0, 24), ""));
        assert_eq!(result.action, PolicyAction::Deny);
        assert_eq!(eval.matched_policy.as_deref(), Some("toml-deny"));
    }

    /// Chain identity (the ADR-0076 planner diff) is compiled content:
    /// same source twice → equal; different instantiation or edited
    /// source → unequal.
    #[test]
    fn rpol_member_partial_eq_is_compiled_content() {
        let member = |source: &str, lp: u32| {
            let file = RpolFile::parse(source).expect("clean rpol");
            let mut store = SetStore::new();
            NamedPolicy::from_rpol(
                format!("customer-in({lp})"),
                Arc::new(
                    file.compile_policy("customer-in", &[lp], &mut store)
                        .expect("policy exists"),
                ),
            )
        };
        assert_eq!(member(RPOL, 200), member(RPOL, 200));
        assert_ne!(member(RPOL, 200), member(RPOL, 300));
        let edited = RPOL.replace("ge 24 le 28", "ge 24 le 32");
        assert_ne!(member(RPOL, 200), member(&edited, 200));
    }

    /// `requires_*` analyses see spliced rpol guards.
    #[test]
    fn requires_analyses_cover_rpol_members() {
        let file = RpolFile::parse(RPOL).expect("clean rpol");
        let mut store = SetStore::new();
        let customer = file
            .compile_policy("customer-in", &[200], &mut store)
            .expect("policy exists");
        let chain = PolicyChain::from_named(vec![NamedPolicy::from_rpol(
            "customer-in(200)".to_string(),
            Arc::new(customer),
        )]);
        assert!(chain.requires_as_path_string());
        assert!(!chain.requires_rpki_validation());
    }

    /// An rpol member's placeholder `policy` never reaches evaluation:
    /// a Deny-defaulted placeholder must not leak a deny.
    #[test]
    fn rpol_member_placeholder_policy_is_ignored() {
        let file = RpolFile::parse(RPOL).expect("clean rpol");
        let mut store = SetStore::new();
        let bogon = file
            .compile_policy("bogon-filter", &[], &mut store)
            .expect("policy exists");
        let mut member = NamedPolicy::from_rpol("bogon-filter".to_string(), Arc::new(bogon));
        member.policy = Policy {
            entries: Vec::new(),
            default_action: PolicyAction::Deny,
        };
        let chain = PolicyChain::from_named(vec![member]);
        let (result, _) = chain.evaluate_with_attribution(&ctx(v4(10, 0, 0, 0, 24), ""));
        assert_eq!(result.action, PolicyAction::Permit);
    }
}
