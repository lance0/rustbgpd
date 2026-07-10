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
//! human-written policies; the typechecker bounds the composition
//! (apply DAG plus `MAX_APPLY_DEPTH` / `MAX_APPLY_EXPANSION`,
//! LAN-290), so the recursive inlining below is statically bounded in
//! both stack depth and total nodes before lowering ever runs.

use std::collections::HashMap;
use std::sync::Arc;

use rustbgpd_wire::ExtendedCommunity;

use crate::engine::{
    AsPathRegex, CommunityMatch, NeighborSetMatch, NextHopAction, PolicyAction, RouteModifications,
};
use crate::eval::checked_arith;
use crate::ir::{
    Cmp, CompiledChain, CompiledPolicy, MatchExpr, PolicySource, RegexId, SetId, Term, TermAction,
    ValueCmpNode, ValueCmpOp, ValueExpr,
};
use crate::sets::{AsnSet, CommunitySet, PrefixSet, PrefixSetEntry, SetStore};

use super::ast::{
    ActionStmt, CmpOp, CommunityLit, Expr, NextHopArg, PolicyDef, PrependAsArg, Rhs, SourceFile,
    Stmt, U32Arg, ValueExprAst,
};
use super::typeck::{Field, resolve_field, value_field_of};

/// Static slot allocation for `let` bindings (LAN-302): one register
/// file per **source term** (bindings never cross terms), slots handed
/// out in declaration order. Entering an `if`/`else` body saves a
/// [`mark`](Self::mark) and leaving [`reset`](Self::reset)s to it, so
/// sibling scopes reuse slots — they are never live simultaneously —
/// and the frame stays within `2 × MAX_LOCALS` slots
/// (`crate::eval::LOCAL_FRAME_SLOTS`) forever. Lookup scans innermost
/// last (reverse), giving deterministic shadowing of outer bindings
/// and parameters. Purely a function of the source, so identical
/// source always compiles to identical slot assignments (ADR-0103
/// Decision 5 determinism).
#[derive(Default)]
struct LetEnv {
    lets: Vec<(String, u8)>,
    next_slot: u8,
}

impl LetEnv {
    /// The slot of the innermost visible binding named `name`.
    fn lookup(&self, name: &str) -> Option<u8> {
        self.lets
            .iter()
            .rev()
            .find(|(local, _)| local == name)
            .map(|&(_, slot)| slot)
    }

    /// Declare a binding, allocating the next slot. The typechecker's
    /// per-scope `MAX_LOCALS` cap bounds `next_slot` below the frame
    /// size (two nesting levels × 64).
    fn declare(&mut self, name: &str) -> u8 {
        let slot = self.next_slot;
        assert!(
            usize::from(slot) < crate::eval::LOCAL_FRAME_SLOTS,
            "typechecked: per-scope caps bound the frame"
        );
        self.next_slot += 1;
        self.lets.push((name.to_string(), slot));
        slot
    }

    /// Snapshot the scope for a nested `if`/`else` body.
    fn mark(&self) -> (usize, u8) {
        (self.lets.len(), self.next_slot)
    }

    /// Leave a nested scope: its names go out of scope and its slots
    /// become reusable by sibling scopes.
    fn reset(&mut self, (len, next_slot): (usize, u8)) {
        self.lets.truncate(len);
        self.next_slot = next_slot;
    }
}

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
    asn_sets: Vec<Arc<AsnSet>>,
    as_path_regexes: Vec<Arc<AsPathRegex>>,
    prefix_set_names: Vec<Option<String>>,
    community_set_names: Vec<Option<String>>,
    asn_set_names: Vec<Option<String>>,
    prefix_set_ids: HashMap<String, SetId>,
    community_set_ids: HashMap<String, SetId>,
    asn_set_ids: HashMap<String, SetId>,
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
            asn_sets: Vec::new(),
            as_path_regexes: Vec::new(),
            prefix_set_names: Vec::new(),
            community_set_names: Vec::new(),
            asn_set_names: Vec::new(),
            prefix_set_ids: HashMap::new(),
            community_set_ids: HashMap::new(),
            asn_set_ids: HashMap::new(),
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
        for def in &file.asn_sets {
            let asns: Vec<u32> = def.entries.iter().map(|asn| asn.node).collect();
            let set = store.asn_set(&asns);
            let id = SetId(u32::try_from(lowerer.asn_sets.len()).expect("fits u32"));
            lowerer.asn_sets.push(set);
            lowerer.asn_set_names.push(Some(def.name.node.clone()));
            lowerer.asn_set_ids.insert(def.name.node.clone(), id);
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
            asn_sets: self.asn_sets.clone(),
            as_path_regexes: self.as_path_regexes.clone(),
            prefix_set_names: self.prefix_set_names.clone(),
            community_set_names: self.community_set_names.clone(),
            asn_set_names: self.asn_set_names.clone(),
            local_asn: None,
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
            asn_sets: self.asn_sets.clone(),
            as_path_regexes: self.as_path_regexes.clone(),
            prefix_set_names: self.prefix_set_names.clone(),
            community_set_names: self.community_set_names.clone(),
            asn_set_names: self.asn_set_names.clone(),
            local_asn: None,
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
    ///
    /// `let` statements (LAN-302) lower to [`TermAction::Bind`] terms
    /// guarded by their enclosing branch condition — `True` in term-body
    /// position, the `if` guard (or its negation for `else`) inside a
    /// body — so the initializer evaluates exactly when the statement
    /// would execute (eager, fail-closed) and the slot is written
    /// before any IR term that reads it. Pending modification staging
    /// does not need flushing around a Bind: definite assignment means
    /// staged computed expressions only ever read slots whose Bind
    /// terms were emitted earlier.
    fn lower_term(
        &mut self,
        term: &super::ast::TermDef,
        env: &HashMap<&str, u32>,
        store: &mut SetStore,
    ) -> Vec<(MatchExpr, TermAction)> {
        let mut out: Vec<(MatchExpr, TermAction)> = Vec::new();
        let mut pending = RouteModifications::default();
        // Slots reset per source term: bindings never cross terms.
        let mut lets = LetEnv::default();
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
                // Term-body `let`: lower the initializer against the
                // scope *before* declaring, so `let x = x + 1` reads
                // the prior `x` (shadowing, not self-reference).
                Stmt::Action(ActionStmt::Let { name, init, .. }) => {
                    let expr = lower_value(init, env, &lets);
                    let slot = lets.declare(&name.node);
                    out.push((
                        MatchExpr::True,
                        TermAction::Bind {
                            slot,
                            name: name.node.clone().into_boxed_str(),
                            expr,
                        },
                    ));
                }
                Stmt::Action(action) => {
                    apply_action(&mut pending, action, env, &lets);
                }
                Stmt::If(if_stmt) => {
                    if !pending.is_empty() {
                        out.push((
                            MatchExpr::True,
                            TermAction::Continue(std::mem::take(&mut pending)),
                        ));
                    }
                    let guard = self.lower_expr(&if_stmt.cond, env, &lets, store);
                    let scope = lets.mark();
                    let (then_binds, then_arm) = lower_body(&if_stmt.then_actions, env, &mut lets);
                    lets.reset(scope);
                    let needs_else_guard = if_stmt.else_actions.is_some();
                    // Body `let`s become Bind terms guarded by the
                    // branch condition, ahead of the body's action
                    // term (guards are pure, so re-evaluating the
                    // condition per term cannot diverge).
                    for bind in then_binds {
                        out.push((guard.clone(), bind));
                    }
                    if let Some(action) = then_arm {
                        out.push((guard.clone(), action));
                    } else if needs_else_guard {
                        // An empty/no-op then-branch still gates the else.
                        out.push((
                            guard.clone(),
                            TermAction::Continue(RouteModifications::default()),
                        ));
                    }
                    if let Some(else_actions) = &if_stmt.else_actions {
                        let scope = lets.mark();
                        let (else_binds, else_arm) = lower_body(else_actions, env, &mut lets);
                        lets.reset(scope);
                        let negated = MatchExpr::Not(Box::new(guard));
                        for bind in else_binds {
                            out.push((negated.clone(), bind));
                        }
                        if let Some(action) = else_arm {
                            out.push((negated, action));
                        }
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
        lets: &LetEnv,
        store: &mut SetStore,
    ) -> MatchExpr {
        match expr {
            Expr::And(lhs, rhs) => {
                let mut children = vec![
                    self.lower_expr(lhs, env, lets, store),
                    self.lower_expr(rhs, env, lets, store),
                ];
                // Guards are pure; order And-children cheapest-first
                // (the IR invariant shared with the TOML compiler).
                children.sort_by_key(MatchExpr::cost_class);
                MatchExpr::And(children)
            }
            Expr::Or(lhs, rhs) => MatchExpr::Or(vec![
                self.lower_expr(lhs, env, lets, store),
                self.lower_expr(rhs, env, lets, store),
            ]),
            Expr::Not(inner, _) => {
                MatchExpr::Not(Box::new(self.lower_expr(inner, env, lets, store)))
            }
            Expr::Cmp { field, op, rhs, .. } => lower_cmp(field, *op, rhs, env, lets),
            // LAN-299: value comparisons keep their shape (constant
            // subtrees folded) — deliberately NOT rewritten to the
            // legacy scalar nodes even when one side folds to a
            // constant, because the two have different absent-operand
            // semantics (never-match vs. fail-closed eval error).
            Expr::ValueCmp { lhs, op, rhs, .. } => MatchExpr::ValueCmp(Box::new(ValueCmpNode {
                op: match op {
                    CmpOp::Eq => ValueCmpOp::Eq,
                    CmpOp::Ne => ValueCmpOp::Ne,
                    CmpOp::Ge => ValueCmpOp::Ge,
                    CmpOp::Le => ValueCmpOp::Le,
                },
                lhs: lower_value(lhs, env, lets),
                rhs: lower_value(rhs, env, lets),
            })),
            Expr::In { field, set } => match resolve_field(field).expect("typechecked") {
                Field::Prefix => MatchExpr::PrefixInSet(self.prefix_set_ids[&set.node]),
                Field::OriginAs => MatchExpr::OriginAsInSet(self.asn_set_ids[&set.node]),
                Field::PeerAsn => MatchExpr::PeerAsInSet(self.asn_set_ids[&set.node]),
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
                // Recursion bounded at typecheck (LAN-290): the apply
                // graph is a DAG no deeper than MAX_APPLY_DEPTH and the
                // inlined predicate no larger than MAX_APPLY_EXPANSION
                // nodes, so this cannot overflow or explode (lowering
                // only ever sees typechecked ASTs).
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

#[expect(clippy::too_many_lines, reason = "one arm per comparable policy field")]
fn lower_cmp(
    field: &super::ast::FieldPath,
    op: CmpOp,
    rhs: &Rhs,
    env: &HashMap<&str, u32>,
    lets: &LetEnv,
) -> MatchExpr {
    let resolved = resolve_field(field).expect("typechecked");
    // LAN-302: a `let` binding on the right of a u32-field comparison
    // is a runtime value, so the comparison lowers to the checked
    // value-comparison node (fail-closed absent-operand semantics,
    // like every computed form) rather than a constant-bound scalar
    // node. Gated on u32 fields: on enum-typed fields the member
    // spelling wins (position-typed resolution — bindings are read
    // only in value positions), mirroring the typechecker.
    if let Rhs::Ident(name) = rhs
        && let Some(field) = value_field_of(resolved)
        && let Some(slot) = lets.lookup(&name.node)
    {
        return MatchExpr::ValueCmp(Box::new(ValueCmpNode {
            op: match op {
                CmpOp::Eq => ValueCmpOp::Eq,
                CmpOp::Ne => ValueCmpOp::Ne,
                CmpOp::Ge => ValueCmpOp::Ge,
                CmpOp::Le => ValueCmpOp::Le,
            },
            lhs: ValueExpr::Field(field),
            rhs: ValueExpr::Local {
                slot,
                name: name.node.clone().into_boxed_str(),
            },
        }));
    }
    match resolved {
        Field::LocalPref => u32_cmp(op, rhs_u32(rhs, env), MatchExpr::LocalPref),
        Field::Med => u32_cmp(op, rhs_u32(rhs, env), MatchExpr::Med),
        Field::AsPathLen => u32_cmp(op, rhs_u32(rhs, env), MatchExpr::AsPathLen),
        // `!=` gets a dedicated Ne node rather than `Not(Eq)`: an absent
        // origin (empty or AS_SET-only path) must match neither `==` nor
        // `!=` (LAN-209 class), and `Not(OriginAsEq)` would wrongly
        // match every origin-less route.
        Field::OriginAs => {
            let asn = rhs_u32(rhs, env);
            if op == CmpOp::Ne {
                MatchExpr::OriginAsNe(asn)
            } else {
                MatchExpr::OriginAsEq(asn)
            }
        }
        // `!=` gets a dedicated Ne node rather than `Not(Eq)`: a
        // non-EVPN route (absent evpn-route-type) must match neither `==`
        // nor `!=` (LAN-209 class), and `Not(EvpnRouteTypeIs)` would
        // wrongly match every non-EVPN route.
        Field::EvpnRouteType => {
            let Rhs::Int(value, _) = rhs else {
                unreachable!("typechecked: evpn-route-type takes an integer literal")
            };
            let evpn_type = u8::try_from(*value).expect("typechecked range");
            if op == CmpOp::Ne {
                MatchExpr::EvpnRouteTypeNe(evpn_type)
            } else {
                MatchExpr::EvpnRouteTypeIs(evpn_type)
            }
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
        // `!=` gets a dedicated Ne node rather than `Not(Eq)`: an absent
        // route-type must match neither `==` nor `!=` (LAN-209 class),
        // and `Not(RouteTypeIs)` would wrongly match when it is absent.
        Field::RouteType => {
            let route_type = match rhs_ident(rhs) {
                "local" => crate::engine::RouteType::Local,
                "internal" => crate::engine::RouteType::Internal,
                _ => crate::engine::RouteType::External,
            };
            if op == CmpOp::Ne {
                MatchExpr::RouteTypeNe(route_type)
            } else {
                MatchExpr::RouteTypeIs(route_type)
            }
        }
        // `!=` gets a dedicated Ne node rather than `Not(Eq)`: a context
        // without typed family knowledge must match neither `==` nor
        // `!=` (LAN-209 class), and `Not(FamilyIs)` would wrongly match
        // it.
        Field::Family => {
            let family = family_value(rhs_ident(rhs));
            if op == CmpOp::Ne {
                MatchExpr::FamilyNe(family)
            } else {
                MatchExpr::FamilyIs(family)
            }
        }
        // `!=` gets a dedicated Ne node rather than `Not(Eq)`: an absent
        // next-hop must match neither `==` nor `!=` (LAN-209), and
        // `Not(NextHopEq)` would wrongly match when the attribute is
        // absent.
        Field::NextHop => match rhs {
            Rhs::Ip(addr, _) => {
                if op == CmpOp::Ne {
                    MatchExpr::NextHopNe(*addr)
                } else {
                    MatchExpr::NextHopEq(*addr)
                }
            }
            // Strict next-hop (`route.next-hop == peer.address`); the
            // typechecker only lets `peer.address` through here.
            Rhs::Field(_) => {
                if op == CmpOp::Ne {
                    MatchExpr::NextHopNePeer
                } else {
                    MatchExpr::NextHopEqPeer
                }
            }
            _ => unreachable!("typechecked: next-hop compares an IP or peer.address"),
        },
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
        // `!=` gets a dedicated Ne node rather than `Not(Eq)`: a
        // prefixless route (BGP-LS / RTC NLRIs) must match neither `==`
        // nor `!=` (LAN-209 class), and `Not(PrefixEq)` would wrongly
        // match when the prefix is absent.
        Field::Prefix => {
            let Rhs::Prefix(prefix, _) = rhs else {
                unreachable!("typechecked: prefix compares a prefix")
            };
            if op == CmpOp::Ne {
                MatchExpr::PrefixNe {
                    prefix: *prefix,
                    ge: None,
                    le: None,
                }
            } else {
                MatchExpr::PrefixEq {
                    prefix: *prefix,
                    ge: None,
                    le: None,
                }
            }
        }
        Field::Communities | Field::LargeCommunities | Field::ExtCommunities | Field::AsPath => {
            unreachable!("typechecked: no direct comparison on lists")
        }
    }
}

/// Lower an `if` body (a flat action list) to its `let` bindings
/// (LAN-302 — [`TermAction::Bind`]s the caller emits ahead of the
/// action term, guarded by the branch condition) and its term action:
/// `Some(Permit)` on `accept`, `Some(Deny)` on `reject`,
/// `Some(Continue)` when it only modifies, `None` when it does nothing.
/// The caller wraps this in a `lets` scope mark/reset — body bindings
/// are not visible outside the body.
fn lower_body(
    actions: &[ActionStmt],
    env: &HashMap<&str, u32>,
    lets: &mut LetEnv,
) -> (Vec<TermAction>, Option<TermAction>) {
    let mut binds = Vec::new();
    let mut mods = RouteModifications::default();
    for action in actions {
        match action {
            ActionStmt::Accept(_) => return (binds, Some(TermAction::Permit(mods))),
            ActionStmt::Reject(_) => return (binds, Some(TermAction::Deny)),
            ActionStmt::Let { name, init, .. } => {
                let expr = lower_value(init, env, lets);
                let slot = lets.declare(&name.node);
                binds.push(TermAction::Bind {
                    slot,
                    name: name.node.clone().into_boxed_str(),
                    expr,
                });
            }
            other => apply_action(&mut mods, other, env, lets),
        }
    }
    let action = if mods.is_empty() {
        None
    } else {
        Some(TermAction::Continue(mods))
    };
    (binds, action)
}

fn apply_action(
    mods: &mut RouteModifications,
    action: &ActionStmt,
    env: &HashMap<&str, u32>,
    lets: &LetEnv,
) {
    match action {
        ActionStmt::Accept(_) | ActionStmt::Reject(_) | ActionStmt::Let { .. } => {
            unreachable!("verdicts and `let` handled by callers")
        }
        // LAN-299: a computed set value that folds to a constant
        // (literal, parameter, or constant arithmetic) lowers to the
        // literal field — `set med 25 + 25` compiles to exactly what
        // `set med 50` does. Only expressions that read route/peer
        // fields stay computed (resolved per route by the evaluator).
        ActionStmt::SetLocalPref(expr, _) => match lower_value(expr, env, lets) {
            ValueExpr::Const(value) => mods.set_local_pref = Some(value),
            computed => mods.set_local_pref_computed = Some(std::sync::Arc::new(computed)),
        },
        ActionStmt::SetMed(expr, _) => match lower_value(expr, env, lets) {
            ValueExpr::Const(value) => mods.set_med = Some(value),
            computed => mods.set_med_computed = Some(std::sync::Arc::new(computed)),
        },
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
            // Well-known extended communities (RFC 8097 OV_* states):
            // add/remove by exact raw wire value.
            CommunityLit::ExtRaw(raw) => {
                let value = ExtendedCommunity::new(raw);
                if *add {
                    mods.extended_communities_add.push(value);
                } else {
                    mods.extended_communities_remove.push(value);
                }
            }
        },
        ActionStmt::Prepend { asn, count, .. } => {
            let count = u8::try_from(resolve_u32(count, env))
                .expect("typechecked: count is a 1-255 literal");
            // LAN-296: computed operands lower to the staged
            // `as_path_prepend_computed` slot (resolved per route by
            // the evaluator); the literal/parameter form keeps its
            // existing lowering. The operand decision is shared with
            // the typechecker (`PrependAsArg::operand`).
            if let Some(operand) = asn.operand(|name| env.contains_key(name)) {
                mods.as_path_prepend_computed = Some((operand, count));
            } else {
                let PrependAsArg::Value(arg) = asn else {
                    unreachable!("non-Value prepend args always denote an operand")
                };
                mods.as_path_prepend = Some((resolve_u32(arg, env), count));
            }
        }
    }
}

/// Lower a value expression to IR with parameters substituted and
/// `let` bindings resolved to frame slots (innermost first — LAN-302
/// shadowing), folding constant subtrees bottom-up with checked
/// arithmetic (LAN-299). A constant step that fails its check (e.g.
/// `4294967295 + p` with `p = 1` at instantiation — invisible to the
/// typechecker, which only sees literals) is left unfolded and fails
/// per route on the eval-error rail: fail closed, never wrap.
fn lower_value(expr: &ValueExprAst, env: &HashMap<&str, u32>, lets: &LetEnv) -> ValueExpr {
    match expr {
        ValueExprAst::Lit(value, _) => ValueExpr::Const(*value),
        ValueExprAst::Ident(name) => {
            // Innermost binding shadows parameters (and outer
            // bindings) in value positions — the typechecker resolves
            // by the same rule.
            if let Some(slot) = lets.lookup(&name.node) {
                return ValueExpr::Local {
                    slot,
                    name: name.node.clone().into_boxed_str(),
                };
            }
            ValueExpr::Const(
                *env.get(name.node.as_str())
                    .expect("typechecked: parameter in scope"),
            )
        }
        ValueExprAst::Field(path) => {
            let field = value_field_of(resolve_field(path).expect("typechecked"))
                .expect("typechecked: u32 field operand");
            ValueExpr::Field(field)
        }
        ValueExprAst::Binary { op, lhs, rhs, .. } => {
            let lhs = lower_value(lhs, env, lets);
            let rhs = lower_value(rhs, env, lets);
            if let (ValueExpr::Const(l), ValueExpr::Const(r)) = (&lhs, &rhs)
                && let Ok(folded) = checked_arith(*op, *l, *r)
            {
                return ValueExpr::Const(folded);
            }
            ValueExpr::Binary {
                op: *op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            }
        }
        ValueExprAst::Call { name, args, .. } => {
            let mut args: Vec<ValueExpr> =
                args.iter().map(|arg| lower_value(arg, env, lets)).collect();
            let consts: Vec<Option<u32>> = args
                .iter()
                .map(|arg| match arg {
                    ValueExpr::Const(value) => Some(*value),
                    _ => None,
                })
                .collect();
            match (name.node.as_str(), consts.as_slice()) {
                ("min", [Some(a), Some(b)]) => ValueExpr::Const((*a).min(*b)),
                ("max", [Some(a), Some(b)]) => ValueExpr::Const((*a).max(*b)),
                ("clamp", [Some(x), Some(lo), Some(hi)]) if lo <= hi => {
                    ValueExpr::Const((*x).clamp(*lo, *hi))
                }
                ("min", _) => {
                    let b = Box::new(args.pop().expect("typechecked arity"));
                    let a = Box::new(args.pop().expect("typechecked arity"));
                    ValueExpr::Min(a, b)
                }
                ("max", _) => {
                    let b = Box::new(args.pop().expect("typechecked arity"));
                    let a = Box::new(args.pop().expect("typechecked arity"));
                    ValueExpr::Max(a, b)
                }
                // Statically inverted constant clamps are typecheck
                // errors; a parameter-dependent inversion stays a
                // Clamp node and fails per route.
                _ => {
                    let hi = Box::new(args.pop().expect("typechecked arity"));
                    let lo = Box::new(args.pop().expect("typechecked arity"));
                    let x = Box::new(args.pop().expect("typechecked arity"));
                    ValueExpr::Clamp(x, lo, hi)
                }
            }
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

/// Language spelling → [`RouteFamily`] (the inverse of
/// `RouteFamily::as_str`; members pinned by `FAMILY_MEMBERS`).
pub(super) fn family_value(name: &str) -> crate::engine::RouteFamily {
    use crate::engine::RouteFamily;
    match name {
        "ipv4-unicast" => RouteFamily::Ipv4Unicast,
        "ipv6-unicast" => RouteFamily::Ipv6Unicast,
        "ipv4-labeled-unicast" => RouteFamily::Ipv4LabeledUnicast,
        "ipv6-labeled-unicast" => RouteFamily::Ipv6LabeledUnicast,
        "vpnv4" => RouteFamily::Vpnv4,
        "vpnv6" => RouteFamily::Vpnv6,
        "ipv4-flowspec" => RouteFamily::Ipv4Flowspec,
        "ipv6-flowspec" => RouteFamily::Ipv6Flowspec,
        "evpn" => RouteFamily::Evpn,
        "rtc" => RouteFamily::RtConstrain,
        "bgp-ls" => RouteFamily::BgpLs,
        _ => RouteFamily::BgpLsVpn,
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
            // LAN-302: the typechecker rejects `apply` of a policy
            // that declares bindings, so an inlined predicate never
            // contains Bind terms.
            TermAction::Bind { .. } => {
                unreachable!("typechecked: apply targets declare no `let` bindings")
            }
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
