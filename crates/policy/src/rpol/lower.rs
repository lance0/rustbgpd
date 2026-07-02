//! AST → IR lowering for `.rpol` (runs only on a typechecked AST).
//!
//! ## Term-fallthrough encoding
//!
//! `.rpol` terms are statement sequences; the IR's `Term` is a single
//! `(guard, action)` pair with first-match-wins policy semantics. Each
//! `.rpol` term therefore lowers to **one or more IR terms**:
//!
//! - Every `if` becomes its own IR term (guard = condition); an `else`
//!   becomes a following IR term guarded by the negated condition.
//! - A run of bare modification actions flushes as an unconditional
//!   [`TermAction::Continue`] term before the next `if` (and at term
//!   end), preserving execution order.
//! - A body that ends in `accept` lowers to `TermAction::Permit` with
//!   the body's modifications; `reject` lowers to `Deny` (its body
//!   modifications are dropped — a denied route has no attributes to
//!   modify); a body with no verdict lowers to `Continue` — matched
//!   modifications apply and evaluation falls through to the next term.
//! - When a `.rpol` term produces multiple IR terms they are named
//!   `<term>.<n>` (1-based); a single IR term keeps the plain term
//!   name. Explain surfaces (PR-4) render these names.
//!
//! End of policy without a verdict is `default_action: Permit` — the
//! policy raises no objection and chain evaluation continues, matching
//! `GoBGP` chain semantics (an empty chain permits).
//!
//! ## Parameters
//!
//! Parameterized policies are templates; every use site
//! (`apply(p(42))`, `expect p(42)`, a PR-3 chain reference) is
//! **monomorphized**: the template is lowered with a
//! parameter→constant substitution. Policies are small, so
//! clone-with-substitution costs microseconds at compile time and the
//! evaluator stays constant-only.
//!
//! ## `apply` as a predicate
//!
//! `apply(p)` inlines the *decision* of `p` as a pure boolean guard:
//! "would `p` permit this route?". Actions of the applied policy do
//! NOT execute (unlike a Junos subroutine call) — it is a predicate,
//! not a call. The inlining is first-match-faithful:
//! `Or(over permit-terms i: guard_i && !guard_1..i-1) || (default
//! Permit && no guard matched)`; `Continue` terms don't decide and are
//! skipped. Quadratic in the applied policy's term count — fine for
//! human-written policies, and the DAG check bounds the depth.

use std::collections::HashMap;
use std::sync::Arc;

use rustbgpd_wire::ExtendedCommunity;

use crate::engine::{
    AsPathRegex, CommunityMatch, NeighborSetMatch, NextHopAction, PolicyAction, RouteModifications,
};
use crate::ir::{
    Cmp, CompiledChain, CompiledPolicy, MatchExpr, PolicySource, RegexId, SetId, Term, TermAction,
};
use crate::sets::{CommunitySet, PrefixSet, PrefixSetEntry, SetStore};

use super::ast::{
    ActionStmt, CmpOp, CommunityLit, Expr, NextHopArg, PolicyDef, Rhs, SourceFile, Stmt, U32Arg,
};
use super::typeck::{Field, resolve_field};

/// Encode a community literal's concrete wire value (for
/// `add`/`remove` actions and test assertions). RT/RO literals pick
/// the RFC 4360 type from the global admin's shape, matching the
/// daemon's other frontends: dotted-quad admin → type 0x01
/// (IPv4-address specific), ASN > 65535 → type 0x02 (4-octet AS),
/// otherwise type 0x00 (2-octet AS).
pub(super) fn ext_community_value(
    route_target: bool,
    global: u32,
    local: u32,
    ipv4_admin: bool,
) -> ExtendedCommunity {
    let subtype: u8 = if route_target { 0x02 } else { 0x03 };
    let raw = if ipv4_admin || global > u32::from(u16::MAX) {
        let type_byte: u8 = if ipv4_admin { 0x01 } else { 0x02 };
        let g = global.to_be_bytes();
        let l = u16::try_from(local)
            .expect("checked at parse time")
            .to_be_bytes();
        u64::from_be_bytes([type_byte, subtype, g[0], g[1], g[2], g[3], l[0], l[1]])
    } else {
        let g = u16::try_from(global)
            .expect("2-octet form checked above")
            .to_be_bytes();
        let l = local.to_be_bytes();
        u64::from_be_bytes([0x00, subtype, g[0], g[1], l[0], l[1], l[2], l[3]])
    };
    ExtendedCommunity::new(raw)
}

/// The lowering context: interned set tables shared by every policy
/// (and test instantiation) compiled from one source file.
pub(super) struct Lowerer<'a> {
    file: &'a SourceFile,
    prefix_sets: Vec<Arc<PrefixSet>>,
    community_sets: Vec<Arc<CommunitySet>>,
    as_path_regexes: Vec<Arc<AsPathRegex>>,
    prefix_set_names: Vec<Option<String>>,
    community_set_names: Vec<Option<String>>,
    prefix_set_ids: HashMap<String, SetId>,
    community_set_ids: HashMap<String, SetId>,
    regex_ids: HashMap<String, RegexId>,
}

impl<'a> Lowerer<'a> {
    /// Intern every defined set through `store` and build the chain
    /// tables. Must only be called on a typechecked AST.
    pub(super) fn new(file: &'a SourceFile, store: &mut SetStore) -> Self {
        let mut lowerer = Self {
            file,
            prefix_sets: Vec::new(),
            community_sets: Vec::new(),
            as_path_regexes: Vec::new(),
            prefix_set_names: Vec::new(),
            community_set_names: Vec::new(),
            prefix_set_ids: HashMap::new(),
            community_set_ids: HashMap::new(),
            regex_ids: HashMap::new(),
        };
        for def in &file.prefix_sets {
            let entries: Vec<PrefixSetEntry> = def
                .entries
                .iter()
                .map(|entry| PrefixSetEntry {
                    prefix: entry.prefix,
                    ge: entry.ge,
                    le: entry.le,
                })
                .collect();
            let set = store.prefix_set(&entries);
            let id = SetId(u32::try_from(lowerer.prefix_sets.len()).expect("fits u32"));
            lowerer.prefix_sets.push(set);
            lowerer.prefix_set_names.push(Some(def.name.node.clone()));
            lowerer.prefix_set_ids.insert(def.name.node.clone(), id);
        }
        for def in &file.community_sets {
            let criteria: Vec<CommunityMatch> =
                def.entries.iter().map(|lit| lit.node.to_match()).collect();
            let set = store.community_set(&criteria);
            let id = SetId(u32::try_from(lowerer.community_sets.len()).expect("fits u32"));
            lowerer.community_sets.push(set);
            lowerer
                .community_set_names
                .push(Some(def.name.node.clone()));
            lowerer.community_set_ids.insert(def.name.node.clone(), id);
        }
        // Regexes are interned lazily at each use site (they can be
        // parameter-dependent via `contains <param>`); `store` is
        // borrowed per call instead of held in `self` because test-run
        // instantiation happens after the main chain is built.
        lowerer
    }

    /// A chain of every zero-parameter policy, in source order, with
    /// the current set tables. Parameterized policies are templates —
    /// they compile where instantiated (`apply`, tests, PR-3 chains).
    pub(super) fn zero_param_chain(&mut self, store: &mut SetStore) -> CompiledChain {
        let policies: Vec<CompiledPolicy> = self
            .file
            .policies
            .iter()
            .filter(|def| def.params.is_empty())
            .map(|def| self.lower_policy(def, &[], store))
            .collect();
        CompiledChain {
            policies,
            prefix_sets: self.prefix_sets.clone(),
            community_sets: self.community_sets.clone(),
            as_path_regexes: self.as_path_regexes.clone(),
            prefix_set_names: self.prefix_set_names.clone(),
            community_set_names: self.community_set_names.clone(),
        }
    }

    /// Monomorphize one policy with concrete arguments into a chain of
    /// its own (used by the in-language test runner).
    pub(super) fn instantiate_chain(
        &mut self,
        name: &str,
        args: &[u32],
        store: &mut SetStore,
    ) -> CompiledChain {
        let def = self
            .file
            .policies
            .iter()
            .find(|p| p.name.node == name)
            .expect("typechecked: policy exists");
        let policy = self.lower_policy(def, args, store);
        CompiledChain {
            policies: vec![policy],
            prefix_sets: self.prefix_sets.clone(),
            community_sets: self.community_sets.clone(),
            as_path_regexes: self.as_path_regexes.clone(),
            prefix_set_names: self.prefix_set_names.clone(),
            community_set_names: self.community_set_names.clone(),
        }
    }

    fn lower_policy(
        &mut self,
        def: &PolicyDef,
        args: &[u32],
        store: &mut SetStore,
    ) -> CompiledPolicy {
        debug_assert_eq!(def.params.len(), args.len(), "typechecked arity");
        let env: HashMap<&str, u32> = def
            .params
            .iter()
            .map(|p| p.node.as_str())
            .zip(args.iter().copied())
            .collect();
        let mut terms = Vec::new();
        for term_def in &def.terms {
            let lowered = self.lower_term(term_def, &env, store);
            let multi = lowered.len() > 1;
            for (index, (guard, action)) in lowered.into_iter().enumerate() {
                let name = if multi {
                    format!("{}.{}", term_def.name.node, index + 1)
                } else {
                    term_def.name.node.clone()
                };
                terms.push(Term {
                    name: Some(name),
                    guard,
                    action,
                });
            }
        }
        CompiledPolicy {
            name: Some(def.name.node.clone()),
            terms,
            default_action: PolicyAction::Permit,
            source: PolicySource::Rpol,
        }
    }

    /// Lower one `.rpol` term to its IR terms (see module docs for the
    /// fallthrough encoding).
    fn lower_term(
        &mut self,
        term: &super::ast::TermDef,
        env: &HashMap<&str, u32>,
        store: &mut SetStore,
    ) -> Vec<(MatchExpr, TermAction)> {
        let mut out: Vec<(MatchExpr, TermAction)> = Vec::new();
        let mut pending = RouteModifications::default();
        for stmt in &term.stmts {
            match stmt {
                Stmt::Action(ActionStmt::Accept(_)) => {
                    out.push((
                        MatchExpr::True,
                        TermAction::Permit(std::mem::take(&mut pending)),
                    ));
                    return out;
                }
                Stmt::Action(ActionStmt::Reject(_)) => {
                    out.push((MatchExpr::True, TermAction::Deny));
                    return out;
                }
                Stmt::Action(action) => {
                    apply_action(&mut pending, action, env);
                }
                Stmt::If(if_stmt) => {
                    if !pending.is_empty() {
                        out.push((
                            MatchExpr::True,
                            TermAction::Continue(std::mem::take(&mut pending)),
                        ));
                    }
                    let guard = self.lower_expr(&if_stmt.cond, env, store);
                    let then_arm = lower_body(&if_stmt.then_actions, env);
                    let needs_else_guard = if_stmt.else_actions.is_some();
                    if let Some(action) = then_arm {
                        out.push((guard.clone(), action));
                    } else if needs_else_guard {
                        // An empty/no-op then-branch still gates the else.
                        out.push((
                            guard.clone(),
                            TermAction::Continue(RouteModifications::default()),
                        ));
                    }
                    if let Some(action) = if_stmt
                        .else_actions
                        .as_ref()
                        .and_then(|actions| lower_body(actions, env))
                    {
                        out.push((MatchExpr::Not(Box::new(guard)), action));
                    }
                }
            }
        }
        if !pending.is_empty() {
            out.push((MatchExpr::True, TermAction::Continue(pending)));
        }
        out
    }

    fn lower_expr(
        &mut self,
        expr: &Expr,
        env: &HashMap<&str, u32>,
        store: &mut SetStore,
    ) -> MatchExpr {
        match expr {
            Expr::And(lhs, rhs) => {
                let mut children = vec![
                    self.lower_expr(lhs, env, store),
                    self.lower_expr(rhs, env, store),
                ];
                // Guards are pure; order And-children cheapest-first
                // (the IR invariant shared with the TOML compiler).
                children.sort_by_key(MatchExpr::cost_class);
                MatchExpr::And(children)
            }
            Expr::Or(lhs, rhs) => MatchExpr::Or(vec![
                self.lower_expr(lhs, env, store),
                self.lower_expr(rhs, env, store),
            ]),
            Expr::Not(inner, _) => MatchExpr::Not(Box::new(self.lower_expr(inner, env, store))),
            Expr::Cmp { field, op, rhs, .. } => lower_cmp(field, *op, rhs, env),
            Expr::In { field, set } => match resolve_field(field).expect("typechecked") {
                Field::Prefix => MatchExpr::PrefixInSet(self.prefix_set_ids[&set.node]),
                _ => MatchExpr::CommunityInSet(self.community_set_ids[&set.node]),
            },
            Expr::Has { lit, .. } => MatchExpr::CommunityContains(lit.node.to_match()),
            Expr::Matches { pattern, .. } => {
                MatchExpr::AsPathMatches(self.intern_regex(&pattern.node, store))
            }
            Expr::Contains { asn, .. } => {
                let asn = resolve_u32(asn, env);
                MatchExpr::AsPathMatches(self.intern_regex(&format!("_{asn}_"), store))
            }
            Expr::Apply { policy, args, .. } => {
                let args: Vec<u32> = args.iter().map(|arg| resolve_u32(arg, env)).collect();
                let def = self
                    .file
                    .policies
                    .iter()
                    .find(|p| p.name.node == policy.node)
                    .expect("typechecked: apply target exists");
                let inlined = self.lower_policy(def, &args, store);
                accept_predicate(&inlined)
            }
        }
    }

    fn intern_regex(&mut self, pattern: &str, store: &mut SetStore) -> RegexId {
        if let Some(&id) = self.regex_ids.get(pattern) {
            return id;
        }
        let regex = AsPathRegex::new(pattern).expect("typechecked: regex compiles");
        let interned = store.as_path_regex(&regex);
        let id = RegexId(u32::try_from(self.as_path_regexes.len()).expect("fits u32"));
        self.as_path_regexes.push(interned);
        self.regex_ids.insert(pattern.to_string(), id);
        id
    }
}

fn lower_cmp(
    field: &super::ast::FieldPath,
    op: CmpOp,
    rhs: &Rhs,
    env: &HashMap<&str, u32>,
) -> MatchExpr {
    let resolved = resolve_field(field).expect("typechecked");
    match resolved {
        Field::LocalPref => u32_cmp(op, rhs_u32(rhs, env), MatchExpr::LocalPref),
        Field::Med => u32_cmp(op, rhs_u32(rhs, env), MatchExpr::Med),
        Field::AsPathLen => u32_cmp(op, rhs_u32(rhs, env), MatchExpr::AsPathLen),
        Field::EvpnRouteType => {
            let Rhs::Int(value, _) = rhs else {
                unreachable!("typechecked: evpn-route-type takes an integer literal")
            };
            let node = MatchExpr::EvpnRouteTypeIs(u8::try_from(*value).expect("typechecked range"));
            negate_if(op == CmpOp::Ne, node)
        }
        Field::Rpki => {
            let node = MatchExpr::RpkiIs(match rhs_ident(rhs) {
                "valid" => rustbgpd_wire::RpkiValidation::Valid,
                "invalid" => rustbgpd_wire::RpkiValidation::Invalid,
                _ => rustbgpd_wire::RpkiValidation::NotFound,
            });
            negate_if(op == CmpOp::Ne, node)
        }
        Field::Aspa => {
            let node = MatchExpr::AspaIs(match rhs_ident(rhs) {
                "valid" => rustbgpd_wire::AspaValidation::Valid,
                "invalid" => rustbgpd_wire::AspaValidation::Invalid,
                _ => rustbgpd_wire::AspaValidation::Unknown,
            });
            negate_if(op == CmpOp::Ne, node)
        }
        Field::RouteType => {
            let node = MatchExpr::RouteTypeIs(match rhs_ident(rhs) {
                "local" => crate::engine::RouteType::Local,
                "internal" => crate::engine::RouteType::Internal,
                _ => crate::engine::RouteType::External,
            });
            negate_if(op == CmpOp::Ne, node)
        }
        Field::NextHop => {
            let Rhs::Ip(addr, _) = rhs else {
                unreachable!("typechecked: next-hop compares an IP")
            };
            negate_if(op == CmpOp::Ne, MatchExpr::NextHopEq(*addr))
        }
        Field::PeerAddress => {
            let Rhs::Ip(addr, _) = rhs else {
                unreachable!("typechecked: peer.address compares an IP")
            };
            let node = MatchExpr::NeighborIn(Box::new(NeighborSetMatch {
                addresses: vec![*addr],
                ..NeighborSetMatch::default()
            }));
            negate_if(op == CmpOp::Ne, node)
        }
        Field::PeerAsn => {
            let node = MatchExpr::NeighborIn(Box::new(NeighborSetMatch {
                remote_asns: vec![rhs_u32(rhs, env)],
                ..NeighborSetMatch::default()
            }));
            negate_if(op == CmpOp::Ne, node)
        }
        Field::PeerGroup => {
            let Rhs::Str(group) = rhs else {
                unreachable!("typechecked: peer.group compares a string")
            };
            let node = MatchExpr::NeighborIn(Box::new(NeighborSetMatch {
                peer_groups: vec![group.node.clone()],
                ..NeighborSetMatch::default()
            }));
            negate_if(op == CmpOp::Ne, node)
        }
        Field::Prefix => {
            let Rhs::Prefix(prefix, _) = rhs else {
                unreachable!("typechecked: prefix compares a prefix")
            };
            let node = MatchExpr::PrefixEq {
                prefix: *prefix,
                ge: None,
                le: None,
            };
            negate_if(op == CmpOp::Ne, node)
        }
        Field::Communities | Field::LargeCommunities | Field::ExtCommunities | Field::AsPath => {
            unreachable!("typechecked: no direct comparison on lists")
        }
    }
}

/// Lower an `if` body (a flat action list) to its term action:
/// `Some(Permit)` on `accept`, `Some(Deny)` on `reject`,
/// `Some(Continue)` when it only modifies, `None` when it does nothing.
fn lower_body(actions: &[ActionStmt], env: &HashMap<&str, u32>) -> Option<TermAction> {
    let mut mods = RouteModifications::default();
    for action in actions {
        match action {
            ActionStmt::Accept(_) => return Some(TermAction::Permit(mods)),
            ActionStmt::Reject(_) => return Some(TermAction::Deny),
            other => apply_action(&mut mods, other, env),
        }
    }
    if mods.is_empty() {
        None
    } else {
        Some(TermAction::Continue(mods))
    }
}

fn apply_action(mods: &mut RouteModifications, action: &ActionStmt, env: &HashMap<&str, u32>) {
    match action {
        ActionStmt::Accept(_) | ActionStmt::Reject(_) => {
            unreachable!("verdicts handled by callers")
        }
        ActionStmt::SetLocalPref(arg, _) => mods.set_local_pref = Some(resolve_u32(arg, env)),
        ActionStmt::SetMed(arg, _) => mods.set_med = Some(resolve_u32(arg, env)),
        ActionStmt::SetNextHop(arg, _) => {
            mods.set_next_hop = Some(match arg {
                NextHopArg::Self_(_) => NextHopAction::Self_,
                NextHopArg::Addr(addr, _) => NextHopAction::Specific(*addr),
            });
        }
        ActionStmt::Community { add, lit, .. } => match lit.node {
            CommunityLit::Standard(value) => {
                if *add {
                    mods.communities_add.push(value);
                } else {
                    mods.communities_remove.push(value);
                }
            }
            CommunityLit::Large(lc) => {
                if *add {
                    mods.large_communities_add.push(lc);
                } else {
                    mods.large_communities_remove.push(lc);
                }
            }
            CommunityLit::Ext {
                route_target,
                global,
                local,
                ipv4_admin,
            } => {
                let value = ext_community_value(route_target, global, local, ipv4_admin);
                if *add {
                    mods.extended_communities_add.push(value);
                } else {
                    mods.extended_communities_remove.push(value);
                }
            }
        },
        ActionStmt::Prepend { asn, count, .. } => {
            let count = resolve_u32(count, env);
            mods.as_path_prepend = Some((
                resolve_u32(asn, env),
                u8::try_from(count).expect("typechecked: count is a 1-255 literal"),
            ));
        }
    }
}

fn resolve_u32(arg: &U32Arg, env: &HashMap<&str, u32>) -> u32 {
    match arg {
        U32Arg::Lit(value, _) => *value,
        U32Arg::Param(name) => *env
            .get(name.node.as_str())
            .expect("typechecked: parameter in scope"),
    }
}

fn rhs_u32(rhs: &Rhs, env: &HashMap<&str, u32>) -> u32 {
    match rhs {
        Rhs::Int(value, _) => *value,
        Rhs::Ident(name) => *env
            .get(name.node.as_str())
            .expect("typechecked: parameter in scope"),
        _ => unreachable!("typechecked: u32 operand"),
    }
}

fn rhs_ident(rhs: &Rhs) -> &str {
    match rhs {
        Rhs::Ident(name) => &name.node,
        _ => unreachable!("typechecked: enum operand"),
    }
}

fn u32_cmp(op: CmpOp, value: u32, make: impl Fn(Cmp) -> MatchExpr) -> MatchExpr {
    match op {
        CmpOp::Ge => make(Cmp::Ge(value)),
        CmpOp::Le => make(Cmp::Le(value)),
        CmpOp::Eq => MatchExpr::And(vec![make(Cmp::Ge(value)), make(Cmp::Le(value))]),
        CmpOp::Ne => MatchExpr::Not(Box::new(MatchExpr::And(vec![
            make(Cmp::Ge(value)),
            make(Cmp::Le(value)),
        ]))),
    }
}

fn negate_if(negate: bool, node: MatchExpr) -> MatchExpr {
    if negate {
        MatchExpr::Not(Box::new(node))
    } else {
        node
    }
}

/// The pure boolean "would this policy permit the route?" — the
/// `apply` predicate. First-match-faithful over decision-bearing terms
/// (`Continue` terms don't decide and are skipped).
fn accept_predicate(policy: &CompiledPolicy) -> MatchExpr {
    let mut not_prior: Vec<MatchExpr> = Vec::new();
    let mut arms: Vec<MatchExpr> = Vec::new();
    for term in &policy.terms {
        match term.action {
            TermAction::Continue(_) => {}
            TermAction::Permit(_) => {
                let mut children = not_prior.clone();
                children.push(term.guard.clone());
                arms.push(and_of(children));
                not_prior.push(MatchExpr::Not(Box::new(term.guard.clone())));
            }
            TermAction::Deny => {
                not_prior.push(MatchExpr::Not(Box::new(term.guard.clone())));
            }
        }
    }
    if policy.default_action == PolicyAction::Permit {
        arms.push(and_of(not_prior));
    }
    or_of(arms)
}

fn and_of(mut children: Vec<MatchExpr>) -> MatchExpr {
    children.retain(|child| *child != MatchExpr::True);
    match children.len() {
        0 => MatchExpr::True,
        1 => children.pop().expect("len checked"),
        _ => MatchExpr::And(children),
    }
}

fn or_of(mut children: Vec<MatchExpr>) -> MatchExpr {
    if children.contains(&MatchExpr::True) {
        return MatchExpr::True;
    }
    match children.len() {
        0 => MatchExpr::Or(Vec::new()), // never matches
        1 => children.pop().expect("len checked"),
        _ => MatchExpr::Or(children),
    }
}
