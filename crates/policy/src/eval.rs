//! The IR evaluator (ADR-0096) — the single evaluation engine behind
//! `evaluate_chain_with_attribution`.
//!
//! Semantics are decision-identical to the legacy statement walker
//! (pinned by the golden corpus in `engine/tests/ir_parity.rs`):
//! first-match-wins within a policy, `GoBGP` chain semantics across
//! policies (permits accumulate modifications and continue, a deny
//! terminates), RFC 4271 implicit `LOCAL_PREF`/`MED` defaults in
//! comparisons, and the same attribution rules.
//!
//! The no-match / no-modification path allocates nothing: guard
//! evaluation is all borrows, modifications are cloned only when a
//! matched permit term actually carries some, and the attribution name
//! is cloned only for a named terminal policy (exactly as before).

use crate::engine::{
    IMPLICIT_LOCAL_PREF, IMPLICIT_MED, PolicyAction, PolicyEvaluation, PolicyResult, RouteContext,
    RouteModifications,
};
use crate::ir::{Cmp, CompiledChain, CompiledPolicy, MatchExpr, TermAction};
use crate::sets::prefix_entry_matches;

/// A policy's disposition of the route, borrowing the matched term's
/// modifications (cloned only if merged).
enum PolicyDecision<'a> {
    Permit(Option<&'a RouteModifications>),
    Deny,
}

impl CompiledChain {
    /// Evaluate a route against this chain. Identical to
    /// [`evaluate_with_attribution`](Self::evaluate_with_attribution)
    /// without the attribution.
    #[must_use]
    pub fn evaluate(&self, ctx: &RouteContext<'_>) -> PolicyResult {
        self.evaluate_with_attribution(ctx).0
    }

    /// Evaluate a route against this chain with attribution to the
    /// terminal-decision policy — the IR backend of
    /// `PolicyChain::evaluate_with_attribution`, with identical
    /// semantics and results.
    #[must_use]
    pub fn evaluate_with_attribution(
        &self,
        ctx: &RouteContext<'_>,
    ) -> (PolicyResult, PolicyEvaluation) {
        let mut accumulated = RouteModifications::default();
        for policy in &self.policies {
            match self.evaluate_policy(policy, ctx) {
                PolicyDecision::Deny => {
                    return (
                        PolicyResult::deny(),
                        PolicyEvaluation {
                            action: PolicyAction::Deny,
                            matched_policy: policy.name.clone(),
                        },
                    );
                }
                PolicyDecision::Permit(Some(mods)) if !mods.is_empty() => {
                    accumulated.merge_from(mods.clone());
                }
                PolicyDecision::Permit(_) => {}
            }
        }
        // All policies permitted (including an empty chain). Attribute
        // to the last policy in the chain since chain evaluation
        // completes only after every policy permits.
        let matched_policy = self.policies.last().and_then(|p| p.name.clone());
        (
            PolicyResult {
                action: PolicyAction::Permit,
                modifications: accumulated,
            },
            PolicyEvaluation {
                action: PolicyAction::Permit,
                matched_policy,
            },
        )
    }

    /// First-match-wins term walk; the policy's default action decides
    /// on fallthrough.
    fn evaluate_policy<'a>(
        &self,
        policy: &'a CompiledPolicy,
        ctx: &RouteContext<'_>,
    ) -> PolicyDecision<'a> {
        for term in &policy.terms {
            if self.eval_expr(&term.guard, ctx) {
                return match &term.action {
                    TermAction::Permit(mods) => PolicyDecision::Permit(Some(mods)),
                    TermAction::Deny => PolicyDecision::Deny,
                };
            }
        }
        match policy.default_action {
            PolicyAction::Permit => PolicyDecision::Permit(None),
            PolicyAction::Deny => PolicyDecision::Deny,
        }
    }

    /// Evaluate one guard node. Pure and allocation-free; set/regex
    /// ids index this chain's tables directly (out-of-range ids are a
    /// compiler bug, not reachable from operator input).
    fn eval_expr(&self, expr: &MatchExpr, ctx: &RouteContext<'_>) -> bool {
        match expr {
            MatchExpr::True => true,
            MatchExpr::And(children) => children.iter().all(|child| self.eval_expr(child, ctx)),
            MatchExpr::Or(children) => children.iter().any(|child| self.eval_expr(child, ctx)),
            MatchExpr::Not(inner) => !self.eval_expr(inner, ctx),
            MatchExpr::PrefixEq { prefix, ge, le } => ctx
                .prefix
                .is_some_and(|candidate| prefix_entry_matches(*prefix, *ge, *le, candidate)),
            MatchExpr::PrefixInSet(id) => ctx
                .prefix
                .is_some_and(|candidate| self.prefix_sets[id.0 as usize].matches(candidate)),
            MatchExpr::CommunityContains(cm) => cm.matches_route_communities(ctx),
            MatchExpr::CommunityInSet(id) => self.community_sets[id.0 as usize].matches(ctx),
            MatchExpr::AsPathMatches(id) => {
                self.as_path_regexes[id.0 as usize].is_match(ctx.as_path_str)
            }
            MatchExpr::AsPathLen(cmp) => cmp_len(*cmp, ctx.as_path_len),
            MatchExpr::LocalPref(cmp) => {
                cmp_value(*cmp, ctx.local_pref.unwrap_or(IMPLICIT_LOCAL_PREF))
            }
            MatchExpr::Med(cmp) => cmp_value(*cmp, ctx.med.unwrap_or(IMPLICIT_MED)),
            MatchExpr::NextHopEq(next_hop) => ctx.next_hop == Some(*next_hop),
            MatchExpr::NeighborIn(set) => {
                set.matches(ctx.peer_address, ctx.peer_asn, ctx.peer_group)
            }
            MatchExpr::RouteTypeIs(route_type) => ctx.route_type == Some(*route_type),
            MatchExpr::EvpnRouteTypeIs(evpn_type) => ctx.evpn_route_type == Some(*evpn_type),
            MatchExpr::RpkiIs(state) => ctx.validation_state == *state,
            MatchExpr::AspaIs(state) => ctx.aspa_state == *state,
        }
    }
}

#[inline]
fn cmp_value(cmp: Cmp, value: u32) -> bool {
    match cmp {
        Cmp::Ge(bound) => value >= bound,
        Cmp::Le(bound) => value <= bound,
    }
}

/// `AS_PATH` length comparison — mirrors the legacy `v as usize`
/// widening against the context's `usize` count.
#[inline]
fn cmp_len(cmp: Cmp, len: usize) -> bool {
    match cmp {
        Cmp::Ge(bound) => len >= bound as usize,
        Cmp::Le(bound) => len <= bound as usize,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use rustbgpd_wire::{AspaValidation, Ipv4Prefix, Prefix, RpkiValidation};

    use crate::engine::{PolicyAction, RouteContext, RouteModifications};
    use crate::ir::{
        CompiledChain, CompiledPolicy, MatchExpr, PolicySource, SetId, Term, TermAction,
    };
    use crate::sets::{PrefixSet, PrefixSetEntry};

    fn ctx(prefix: Option<Prefix>) -> RouteContext<'static> {
        RouteContext {
            prefix,
            next_hop: None,
            extended_communities: &[],
            communities: &[],
            large_communities: &[],
            as_path_str: "",
            as_path_len: 0,
            validation_state: RpkiValidation::NotFound,
            aspa_state: AspaValidation::Unknown,
            peer_address: None,
            peer_asn: None,
            peer_group: None,
            route_type: None,
            evpn_route_type: None,
            local_pref: None,
            med: None,
        }
    }

    fn single_term_chain(guard: MatchExpr, prefix_sets: Vec<Arc<PrefixSet>>) -> CompiledChain {
        CompiledChain {
            policies: vec![CompiledPolicy {
                name: None,
                terms: vec![Term {
                    name: None,
                    guard,
                    action: TermAction::Permit(RouteModifications::default()),
                }],
                default_action: PolicyAction::Deny,
                source: PolicySource::Toml,
            }],
            prefix_sets,
            community_sets: Vec::new(),
            as_path_regexes: Vec::new(),
        }
    }

    fn v4(addr: [u8; 4], len: u8) -> Prefix {
        Prefix::V4(Ipv4Prefix::new(
            Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]),
            len,
        ))
    }

    /// Or / Not / True have no TOML frontend yet, so the golden corpus
    /// cannot reach them — pin their truth tables directly.
    #[test]
    fn or_not_true_semantics() {
        let route = ctx(Some(v4([10, 0, 0, 0], 24)));
        let hit = MatchExpr::PrefixEq {
            prefix: v4([10, 0, 0, 0], 24),
            ge: None,
            le: None,
        };
        let miss = MatchExpr::PrefixEq {
            prefix: v4([192, 0, 2, 0], 24),
            ge: None,
            le: None,
        };

        for (guard, expect) in [
            (MatchExpr::True, true),
            (MatchExpr::Or(vec![miss.clone(), hit.clone()]), true),
            (MatchExpr::Or(vec![miss.clone(), miss.clone()]), false),
            (MatchExpr::Or(vec![]), false),
            (MatchExpr::And(vec![]), true),
            (MatchExpr::Not(Box::new(miss.clone())), true),
            (MatchExpr::Not(Box::new(hit.clone())), false),
        ] {
            let chain = single_term_chain(guard.clone(), Vec::new());
            let (result, _) = chain.evaluate_with_attribution(&route);
            assert_eq!(
                result.action,
                if expect {
                    PolicyAction::Permit
                } else {
                    PolicyAction::Deny
                },
                "guard {guard:?}"
            );
        }
    }

    #[test]
    fn prefix_in_set_respects_prefixless_routes() {
        let set = Arc::new(PrefixSet::new([PrefixSetEntry {
            prefix: v4([10, 0, 0, 0], 8),
            ge: Some(8),
            le: Some(32),
        }]));
        let chain = single_term_chain(MatchExpr::PrefixInSet(SetId(0)), vec![set]);

        let (result, _) = chain.evaluate_with_attribution(&ctx(Some(v4([10, 1, 2, 0], 24))));
        assert_eq!(result.action, PolicyAction::Permit);

        // A prefixless route (e.g. BGP-LS) never matches prefix nodes.
        let (result, _) = chain.evaluate_with_attribution(&ctx(None));
        assert_eq!(result.action, PolicyAction::Deny);
    }
}
