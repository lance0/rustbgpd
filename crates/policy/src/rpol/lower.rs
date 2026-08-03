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
use std::net::Ipv4Addr;
use std::sync::Arc;

use rustbgpd_wire::ExtendedCommunity;

use crate::datasets::DatasetBindings;
use crate::engine::{
    AsPathRegex, CommunityMatch, NeighborSetMatch, NextHopAction, PolicyAction,
    RouteExtendedCommunityAdmin, RouteExtendedCommunityKind, RouteModifications,
    encode_route_extended_community,
};
use crate::eval::checked_arith;
use crate::ir::{
    Cmp, CompiledChain, CompiledPolicy, DatasetId, DatasetProbe, DatasetSlot, ForEachNode,
    LoopSource, MatchExpr, PolicySource, RegexId, SetId, Term, TermAction, ValueCmpNode,
    ValueCmpOp, ValueExpr,
};
use crate::sets::{AsnSet, CommunitySet, PrefixSet, PrefixSetEntry, SetStore};

use super::ast::{
    ActionStmt, CmpOp, CommunityArg, CommunityLit, Expr, FnDef, ForSource, NextHopArg, PolicyDef,
    PrependAsArg, Rhs, SourceFile, Stmt, U32Arg, ValueExprAst,
};
use super::typeck::{Field, resolve_field, value_field_of};

/// Static slot allocation for `let` bindings (LAN-302/LAN-303): one
/// register file per **source term** (bindings never cross terms),
/// slots handed out in declaration order. Entering an `if`/`else` or
/// loop body saves a [`mark`](Self::mark) and leaving
/// [`reset`](Self::reset)s to it, so sibling scopes reuse slots — they
/// are never live simultaneously — and the typechecker's per-scope and
/// whole-frame caps keep every allocation inside the
/// `crate::eval::LOCAL_FRAME_SLOTS` register file. Lookup scans
/// innermost last (reverse), giving deterministic shadowing of outer
/// bindings and parameters. Purely a function of the source, so
/// identical source always compiles to identical slot assignments
/// (ADR-0103 Decision 5 determinism).
#[derive(Default)]
struct LetEnv {
    lets: Vec<(String, u8)>,
    // u16, not u8: a full frame's last declare leaves next_slot ==
    // LOCAL_FRAME_SLOTS (256), which the slot type cannot hold — the
    // typecheck frame budget admits exactly-full frames (LAN-304
    // boundary test).
    next_slot: u16,
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
        assert!(
            usize::from(self.next_slot) < crate::eval::LOCAL_FRAME_SLOTS,
            "typechecked: per-scope and frame budgets bound the allocation"
        );
        let slot = u8::try_from(self.next_slot).expect("bounded by the frame assert");
        self.next_slot += 1;
        self.lets.push((name.to_string(), slot));
        slot
    }

    /// Snapshot the scope for a nested `if`/`else` body.
    fn mark(&self) -> (usize, u16) {
        (self.lets.len(), self.next_slot)
    }

    /// Leave a nested scope: its names go out of scope and its slots
    /// become reusable by sibling scopes.
    fn reset(&mut self, (len, next_slot): (usize, u16)) {
        self.lets.truncate(len);
        self.next_slot = next_slot;
    }
}

/// How bare identifiers resolve while lowering a value expression:
/// the policy scope (visible `let` bindings shadowing policy
/// parameters — the LAN-302 rule), or an inlined function body
/// (LAN-304), which is closed over nothing — its parameters and body
/// lets are already slot-allocated, and nothing else is visible.
enum Names<'a> {
    /// Policy context: `env` maps parameters to their instantiation
    /// constants; the `LetEnv` resolves visible bindings.
    Policy(&'a HashMap<&'a str, u32>),
    /// Inlined function body: `(source name, qualified render name,
    /// slot)` for the parameters and body lets bound so far, innermost
    /// last (reverse scan gives shadowing).
    FnBody(&'a [(&'a str, Box<str>, u8)]),
}

/// Render a value expression back to `.rpol` source form — the name a
/// call's result slot carries, so guards containing an inlined call
/// render source-level in explain (`penalty(route.as-path.len, 10) >=
/// route.med`). Deterministic from the AST (Decision 5: names
/// participate in chain equality). Minimal parentheses, mirroring
/// [`crate::ir::ValueExpr`]'s Display precedence.
fn render_value_ast(expr: &ValueExprAst) -> String {
    fn binding(expr: &ValueExprAst) -> u8 {
        match expr {
            ValueExprAst::Binary {
                op: crate::ir::ArithOp::Add | crate::ir::ArithOp::Sub,
                ..
            } => 0,
            ValueExprAst::Binary { .. } => 1,
            _ => 2,
        }
    }
    fn render(expr: &ValueExprAst, out: &mut String, min_binding: u8) {
        let paren = binding(expr) < min_binding;
        if paren {
            out.push('(');
        }
        match expr {
            ValueExprAst::Lit(value, _) => {
                let _ = std::fmt::Write::write_fmt(out, format_args!("{value}"));
            }
            ValueExprAst::Ident(name) => out.push_str(&name.node),
            ValueExprAst::Field(path) => out.push_str(&path.render()),
            ValueExprAst::Binary { op, lhs, rhs, .. } => {
                let this = binding(expr);
                render(lhs, out, this);
                let _ = std::fmt::Write::write_fmt(out, format_args!(" {} ", op.symbol()));
                render(rhs, out, this + 1);
            }
            ValueExprAst::Call { name, args, .. } => {
                out.push_str(&name.node);
                out.push('(');
                for (index, arg) in args.iter().enumerate() {
                    if index > 0 {
                        out.push_str(", ");
                    }
                    render(arg, out, 0);
                }
                out.push(')');
            }
        }
        if paren {
            out.push(')');
        }
    }
    let mut out = String::new();
    render(expr, &mut out, 0);
    out
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
    let kind = if route_target {
        RouteExtendedCommunityKind::Target
    } else {
        RouteExtendedCommunityKind::Origin
    };
    let admin = if ipv4_admin {
        RouteExtendedCommunityAdmin::Ipv4(Ipv4Addr::from(global))
    } else {
        RouteExtendedCommunityAdmin::Asn(global)
    };
    encode_route_extended_community(kind, admin, local).expect("checked at parse time")
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
    // ── per-chain-build dataset state (LAN-305), reset by
    // `begin_chain`: unlike the set tables above — which carry every
    // definition — only datasets the chain's guards actually reference
    // get a slot, so the table is the chain's dependency list for
    // swap-time refresh scoping. ──
    datasets: Vec<DatasetSlot>,
    dataset_ids: HashMap<String, DatasetId>,
    bindings: DatasetBindings,
    missing_datasets: Vec<String>,
}

/// The interned set data of one source file: every defined
/// prefix/community/asn set, indexed in definition order. Building
/// this is the expensive part of lowering — at IRR scale a file
/// carries millions of prefix-set entries — so `RpolFile` builds it
/// once and every chain instantiation reuses the `Arc`s instead of
/// re-interning through a fresh store (LAN-788: per-neighbor chain
/// resolution re-interned the full file, turning a ~1 s compile into
/// minutes and one shared set copy into one copy per neighbor).
#[derive(Debug)]
pub(super) struct SetTables {
    prefix: Vec<Arc<PrefixSet>>,
    community: Vec<Arc<CommunitySet>>,
    asn: Vec<Arc<AsnSet>>,
}

impl SetTables {
    /// Intern every set defined in `file`. A local store preserves
    /// intra-file deduplication (two identically-valued sets share one
    /// `Arc`). Must only be called on a typechecked AST.
    pub(super) fn build(file: &SourceFile) -> Self {
        let mut store = SetStore::new();
        Self::build_with_store(file, &mut store)
    }

    /// Intern every set defined in `file` through the caller's store.
    /// This preserves content sharing across one-shot compilations.
    pub(super) fn build_with_store(file: &SourceFile, store: &mut SetStore) -> Self {
        let prefix_sets = file
            .prefix_sets
            .iter()
            .map(|def| {
                let entries: Vec<PrefixSetEntry> = def
                    .entries
                    .iter()
                    .map(|entry| PrefixSetEntry {
                        prefix: entry.prefix,
                        ge: entry.ge,
                        le: entry.le,
                    })
                    .collect();
                store.prefix_set(&entries)
            })
            .collect();
        let community_sets = file
            .community_sets
            .iter()
            .map(|def| {
                let criteria: Vec<CommunityMatch> =
                    def.entries.iter().map(|lit| lit.node.to_match()).collect();
                store.community_set(&criteria)
            })
            .collect();
        let asn_sets = file
            .asn_sets
            .iter()
            .map(|def| {
                let asns: Vec<u32> = def.entries.iter().map(|asn| asn.node).collect();
                store.asn_set(&asns)
            })
            .collect();
        Self {
            prefix: prefix_sets,
            community: community_sets,
            asn: asn_sets,
        }
    }
}

impl<'a> Lowerer<'a> {
    /// Build the chain tables over `file`, interning its sets through
    /// the caller-owned store.
    /// One-shot compiles and the general [`RpolFile`](super::RpolFile)
    /// API use this path so separately parsed sources can share content
    /// through the same store. High-fanout callers deliberately use
    /// [`Self::from_tables`] and the file-owned cache instead.
    pub(super) fn new(file: &'a SourceFile, store: &mut SetStore) -> Self {
        Self::from_tables(file, &SetTables::build_with_store(file, store))
    }

    /// Build the chain tables over `file` from pre-interned set
    /// tables: the set `Arc`s are cloned, so every chain built from
    /// the same tables shares one copy of each set's data. Must only
    /// be called with tables built from this same `file`.
    pub(super) fn from_tables(file: &'a SourceFile, tables: &SetTables) -> Self {
        let mut lowerer = Self {
            file,
            prefix_sets: tables.prefix.clone(),
            community_sets: tables.community.clone(),
            asn_sets: tables.asn.clone(),
            as_path_regexes: Vec::new(),
            prefix_set_names: Vec::new(),
            community_set_names: Vec::new(),
            asn_set_names: Vec::new(),
            prefix_set_ids: HashMap::new(),
            community_set_ids: HashMap::new(),
            asn_set_ids: HashMap::new(),
            regex_ids: HashMap::new(),
            datasets: Vec::new(),
            dataset_ids: HashMap::new(),
            bindings: DatasetBindings::new(),
            missing_datasets: Vec::new(),
        };
        for (index, def) in file.prefix_sets.iter().enumerate() {
            let id = SetId(u32::try_from(index).expect("fits u32"));
            lowerer.prefix_set_names.push(Some(def.name.node.clone()));
            lowerer.prefix_set_ids.insert(def.name.node.clone(), id);
        }
        for (index, def) in file.community_sets.iter().enumerate() {
            let id = SetId(u32::try_from(index).expect("fits u32"));
            lowerer
                .community_set_names
                .push(Some(def.name.node.clone()));
            lowerer.community_set_ids.insert(def.name.node.clone(), id);
        }
        for (index, def) in file.asn_sets.iter().enumerate() {
            let id = SetId(u32::try_from(index).expect("fits u32"));
            lowerer.asn_set_names.push(Some(def.name.node.clone()));
            lowerer.asn_set_ids.insert(def.name.node.clone(), id);
        }
        // Regexes are interned lazily at each use site (they can be
        // parameter-dependent via `contains <param>`); the store is
        // borrowed per call instead of held in `self` because test-run
        // instantiation happens after the main chain is built.
        lowerer
    }

    /// Reset per-chain dataset state and adopt `bindings` for the
    /// coming build (LAN-305). Every chain builder calls this first;
    /// bindings differ per build in the test runner (per-test
    /// overrides), and dataset slots must not leak between chains —
    /// the slot table is the chain's refresh-scoping dependency list.
    fn begin_chain(&mut self, bindings: &DatasetBindings) {
        self.datasets.clear();
        self.dataset_ids.clear();
        self.bindings = bindings.clone();
        self.missing_datasets.clear();
    }

    /// The declared kind of a dataset, for the test runner's override
    /// construction (LAN-305).
    pub(super) fn dataset_kind(&self, name: &str) -> Option<crate::datasets::DatasetKind> {
        self.file
            .datasets
            .iter()
            .find(|d| d.name.node == name)
            .map(|d| d.kind)
    }

    /// Dataset names referenced during the current build that had no
    /// (kind-matching) binding. Non-empty ⇒ the built chain is invalid
    /// and must be discarded by the caller — its dataset guards are
    /// never-match placeholders.
    pub(super) fn take_missing_datasets(&mut self) -> Vec<String> {
        std::mem::take(&mut self.missing_datasets)
    }

    /// The chain-local [`DatasetId`] for a declared dataset, binding
    /// its slot on first reference. `None` (and a recorded missing
    /// name) when no kind-matching binding exists — the caller
    /// discards the chain via [`take_missing_datasets`](Self::take_missing_datasets).
    fn dataset_ref(&mut self, name: &str) -> Option<DatasetId> {
        if let Some(&id) = self.dataset_ids.get(name) {
            return Some(id);
        }
        let decl = self
            .file
            .datasets
            .iter()
            .find(|d| d.name.node == name)
            .expect("callers check the declaration exists");
        match self.bindings.get(name) {
            Some(handle) if handle.kind() == decl.kind => {
                let id = DatasetId(u32::try_from(self.datasets.len()).expect("fits u32"));
                self.datasets.push(DatasetSlot {
                    name: handle.name().clone(),
                    kind: decl.kind,
                    handle: Arc::clone(handle),
                });
                self.dataset_ids.insert(name.to_string(), id);
                Some(id)
            }
            _ => {
                if !self.missing_datasets.iter().any(|m| m == name) {
                    self.missing_datasets.push(name.to_string());
                }
                None
            }
        }
    }

    /// A chain of every zero-parameter policy, in source order, with
    /// the current set tables. Parameterized policies are templates —
    /// they compile where instantiated (`apply`, tests, PR-3 chains).
    pub(super) fn zero_param_chain(
        &mut self,
        store: &mut SetStore,
        bindings: &DatasetBindings,
    ) -> CompiledChain {
        self.begin_chain(bindings);
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
            datasets: std::mem::take(&mut self.datasets),
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
        bindings: &DatasetBindings,
    ) -> CompiledChain {
        self.begin_chain(bindings);
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
            datasets: std::mem::take(&mut self.datasets),
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
            name: Some(Arc::from(def.name.node.clone())),
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
        // Slots reset per source term: bindings never cross terms.
        let mut lets = LetEnv::default();
        self.lower_stmts(&term.stmts, env, &mut lets, store)
    }

    /// Lower one statement sequence — a term body or (recursively) a
    /// `for` body — to guarded IR actions (see module docs for the
    /// fallthrough encoding). `break`/`continue` lower to their
    /// loop-control terms (typechecked: they only occur in loop
    /// bodies); a `for` lowers to a single [`TermAction::ForEach`]
    /// term whose body re-enters this function in a nested `lets`
    /// scope.
    #[expect(
        clippy::too_many_lines,
        reason = "one arm per statement kind; splitting would scatter the fallthrough encoding"
    )]
    fn lower_stmts(
        &mut self,
        stmts: &[Stmt],
        env: &HashMap<&str, u32>,
        lets: &mut LetEnv,
        store: &mut SetStore,
    ) -> Vec<(MatchExpr, TermAction)> {
        let mut out: Vec<(MatchExpr, TermAction)> = Vec::new();
        let mut pending = RouteModifications::default();
        for stmt in stmts {
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
                // Loop control (LAN-303): staged modifications so far
                // still apply — `break`/`continue` are control, not
                // verdicts — then the statement is terminal for this
                // body (later statements are typecheck-unreachable).
                Stmt::Action(ActionStmt::Break(_)) => {
                    flush_pending(&mut out, &mut pending);
                    out.push((MatchExpr::True, TermAction::Break));
                    return out;
                }
                Stmt::Action(ActionStmt::Continue(_)) => {
                    flush_pending(&mut out, &mut pending);
                    out.push((MatchExpr::True, TermAction::ContinueLoop));
                    return out;
                }
                // Body `let`: lower the initializer against the scope
                // *before* declaring, so `let x = x + 1` reads the
                // prior `x` (shadowing, not self-reference). Function
                // calls in the initializer hoist their binds ahead of
                // the binding's own (LAN-304).
                Stmt::Action(ActionStmt::Let { name, init, .. }) => {
                    let mut call_binds = Vec::new();
                    let expr = self.lower_value(init, &Names::Policy(env), lets, &mut call_binds);
                    for bind in call_binds {
                        out.push((MatchExpr::True, bind));
                    }
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
                // LAN-303: a binding-valued community action resolves
                // per execution, so it needs its own term (flushing
                // staged modifications first preserves execution
                // order). Parameter references are compile-time
                // constants and stage as literals in `apply_action`.
                Stmt::Action(
                    action @ ActionStmt::Community {
                        add,
                        arg: CommunityArg::Var(name),
                        ..
                    },
                ) => {
                    if let Some(slot) = lets.lookup(&name.node) {
                        flush_pending(&mut out, &mut pending);
                        out.push((
                            MatchExpr::True,
                            TermAction::CommunityVar {
                                add: *add,
                                slot,
                                name: name.node.clone().into_boxed_str(),
                            },
                        ));
                    } else {
                        let mut call_binds = Vec::new();
                        self.apply_action(&mut pending, action, env, lets, &mut call_binds);
                        for bind in call_binds {
                            out.push((MatchExpr::True, bind));
                        }
                    }
                }
                Stmt::Action(action) => {
                    let mut call_binds = Vec::new();
                    self.apply_action(&mut pending, action, env, lets, &mut call_binds);
                    for bind in call_binds {
                        out.push((MatchExpr::True, bind));
                    }
                }
                Stmt::If(if_stmt) => {
                    flush_pending(&mut out, &mut pending);
                    // Function calls in the guard hoist their binds as
                    // unconditional terms ahead of the guard's own
                    // (LAN-304): they evaluate when the walk reaches
                    // this statement — eager like `let`, so both the
                    // positive and negated guard read written slots.
                    let mut guard_binds = Vec::new();
                    let guard = self.lower_expr(&if_stmt.cond, env, lets, store, &mut guard_binds);
                    for bind in guard_binds {
                        out.push((MatchExpr::True, bind));
                    }
                    let scope = lets.mark();
                    let (then_binds, then_tail) = self.lower_body(&if_stmt.then_actions, env, lets);
                    lets.reset(scope);
                    let needs_else_guard = if_stmt.else_actions.is_some();
                    // Body `let`s become Bind terms guarded by the
                    // branch condition, ahead of the body's action
                    // terms (guards are pure, so re-evaluating the
                    // condition per term cannot diverge).
                    for bind in then_binds {
                        out.push((guard.clone(), bind));
                    }
                    if then_tail.is_empty() && needs_else_guard {
                        // An empty/no-op then-branch still gates the else.
                        out.push((
                            guard.clone(),
                            TermAction::Continue(RouteModifications::default()),
                        ));
                    }
                    for action in then_tail {
                        out.push((guard.clone(), action));
                    }
                    if let Some(else_actions) = &if_stmt.else_actions {
                        let scope = lets.mark();
                        let (else_binds, else_tail) = self.lower_body(else_actions, env, lets);
                        lets.reset(scope);
                        let negated = MatchExpr::Not(Box::new(guard));
                        for bind in else_binds {
                            out.push((negated.clone(), bind));
                        }
                        for action in else_tail {
                            out.push((negated.clone(), action));
                        }
                    }
                }
                // LAN-303: the loop variable is a binding in a fresh
                // body scope (fresh value per iteration at runtime);
                // sibling scopes reuse its slots, keeping allocation a
                // pure function of the source (Decision 5 determinism).
                Stmt::For(for_stmt) => {
                    flush_pending(&mut out, &mut pending);
                    let source = self.lower_for_source(&for_stmt.source);
                    let scope = lets.mark();
                    let slot = lets.declare(&for_stmt.var.node);
                    let body = self
                        .lower_stmts(&for_stmt.body, env, lets, store)
                        .into_iter()
                        .map(|(guard, action)| Term {
                            name: None,
                            guard,
                            action,
                        })
                        .collect();
                    lets.reset(scope);
                    out.push((
                        MatchExpr::True,
                        TermAction::ForEach(Box::new(ForEachNode {
                            source,
                            slot,
                            var: for_stmt.var.node.clone().into_boxed_str(),
                            body,
                        })),
                    ));
                }
            }
        }
        if !pending.is_empty() {
            out.push((MatchExpr::True, TermAction::Continue(pending)));
        }
        out
    }

    /// Resolve a loop's iteration source (LAN-303; runs on typechecked
    /// ASTs only).
    fn lower_for_source(&self, source: &ForSource) -> LoopSource {
        match source {
            ForSource::Field(path) => match resolve_field(path).expect("typechecked") {
                Field::Communities => LoopSource::Communities,
                Field::AsPath => LoopSource::AsPath,
                _ => unreachable!("typechecked: iterable fields are communities/as-path"),
            },
            ForSource::Set(name) => LoopSource::AsnSet(self.asn_set_ids[&name.node]),
        }
    }

    /// `binds` receives the hoisted `Bind` terms of any user-function
    /// calls inside the guard's value expressions (LAN-304); the
    /// caller emits them ahead of the guard's terms.
    #[expect(
        clippy::too_many_lines,
        reason = "one arm per expression form; splitting would scatter the lowering table"
    )]
    fn lower_expr(
        &mut self,
        expr: &Expr,
        env: &HashMap<&str, u32>,
        lets: &mut LetEnv,
        store: &mut SetStore,
        binds: &mut Vec<TermAction>,
    ) -> MatchExpr {
        match expr {
            Expr::And(lhs, rhs) => {
                let mut children = vec![
                    self.lower_expr(lhs, env, lets, store, binds),
                    self.lower_expr(rhs, env, lets, store, binds),
                ];
                // Guards are pure; order And-children cheapest-first
                // (the IR invariant shared with the TOML compiler).
                // Call binds hoisted above already wrote their slots,
                // so reordering the reads cannot diverge.
                children.sort_by_key(MatchExpr::cost_class);
                MatchExpr::And(children)
            }
            Expr::Or(lhs, rhs) => MatchExpr::Or(vec![
                self.lower_expr(lhs, env, lets, store, binds),
                self.lower_expr(rhs, env, lets, store, binds),
            ]),
            Expr::Not(inner, _) => {
                MatchExpr::Not(Box::new(self.lower_expr(inner, env, lets, store, binds)))
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
                lhs: self.lower_value(lhs, &Names::Policy(env), lets, binds),
                rhs: self.lower_value(rhs, &Names::Policy(env), lets, binds),
            })),
            Expr::In { field, set } => {
                // LAN-305: a dataset reference lowers to a pinned
                // runtime probe — content is external and never folds.
                if self.file.datasets.iter().any(|d| d.name.node == set.node) {
                    let probe = match resolve_field(field).expect("typechecked") {
                        Field::Prefix => DatasetProbe::Prefix,
                        Field::OriginAs => DatasetProbe::OriginAs,
                        Field::PeerAsn => DatasetProbe::PeerAs,
                        _ => DatasetProbe::Community,
                    };
                    return match self.dataset_ref(&set.node) {
                        Some(id) => MatchExpr::InDataset { probe, id },
                        // Missing binding: never-match placeholder in a
                        // chain the caller discards (take_missing_datasets).
                        None => MatchExpr::Or(Vec::new()),
                    };
                }
                match resolve_field(field).expect("typechecked") {
                    Field::Prefix => MatchExpr::PrefixInSet(self.prefix_set_ids[&set.node]),
                    Field::OriginAs => MatchExpr::OriginAsInSet(self.asn_set_ids[&set.node]),
                    Field::PeerAsn => MatchExpr::PeerAsInSet(self.asn_set_ids[&set.node]),
                    _ => MatchExpr::CommunityInSet(self.community_set_ids[&set.node]),
                }
            }
            // LAN-303: `<binding> in <set>` — a binding probes at
            // runtime; a parameter is a compile-time constant and the
            // probe folds to its truth value here (True / empty-Or =
            // never matches).
            Expr::IdentIn { ident, set } => {
                // LAN-305: `<binding|param> in <dataset>` stays a
                // runtime probe either way — dataset content swaps at
                // runtime, so even a parameter probe cannot fold.
                if let Some(decl) = self.file.datasets.iter().find(|d| d.name.node == set.node) {
                    let asn_kind = decl.kind == crate::datasets::DatasetKind::Asn;
                    let probe = if let Some(slot) = lets.lookup(&ident.node) {
                        let name = ident.node.clone().into_boxed_str();
                        if asn_kind {
                            DatasetProbe::LocalAsn { slot, name }
                        } else {
                            DatasetProbe::LocalCommunity { slot, name }
                        }
                    } else {
                        let value = *env
                            .get(ident.node.as_str())
                            .expect("typechecked: parameter in scope");
                        if asn_kind {
                            DatasetProbe::ConstAsn(value)
                        } else {
                            DatasetProbe::ConstCommunity(value)
                        }
                    };
                    return match self.dataset_ref(&set.node) {
                        Some(id) => MatchExpr::InDataset { probe, id },
                        None => MatchExpr::Or(Vec::new()),
                    };
                }
                if let Some(slot) = lets.lookup(&ident.node) {
                    if let Some(&id) = self.asn_set_ids.get(&set.node) {
                        MatchExpr::LocalInAsnSet {
                            slot,
                            name: ident.node.clone().into_boxed_str(),
                            set: id,
                        }
                    } else {
                        MatchExpr::LocalInCommunitySet {
                            slot,
                            name: ident.node.clone().into_boxed_str(),
                            set: self.community_set_ids[&set.node],
                        }
                    }
                } else {
                    let value = *env
                        .get(ident.node.as_str())
                        .expect("typechecked: parameter in scope");
                    let matched = if let Some(&id) = self.asn_set_ids.get(&set.node) {
                        self.asn_sets[id.0 as usize].contains(value)
                    } else {
                        let id = self.community_set_ids[&set.node];
                        self.community_sets[id.0 as usize].contains_standard(value)
                    };
                    if matched {
                        MatchExpr::True
                    } else {
                        MatchExpr::Or(Vec::new())
                    }
                }
            }
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

/// Flush staged modifications as an unconditional
/// [`TermAction::Continue`] term, preserving execution order around
/// terms that must stand alone (`if` blocks, loops, loop control,
/// binding-valued community actions).
fn flush_pending(out: &mut Vec<(MatchExpr, TermAction)>, pending: &mut RouteModifications) {
    if !pending.is_empty() {
        out.push((
            MatchExpr::True,
            TermAction::Continue(std::mem::take(pending)),
        ));
    }
}

/// Lower an `if` body (a flat action list) to its `let` bindings
/// (LAN-302 — [`TermAction::Bind`]s the caller emits ahead of the
/// action terms, guarded by the branch condition; function-call binds
/// hoist here too, LAN-304) and its ordered action tail: staged
/// modifications as `Continue` terms interleaved (in execution order)
/// with binding-valued community actions (LAN-303), ending with the
/// body's terminal — `Permit` on `accept`, `Deny` on `reject`,
/// `Break`/`ContinueLoop` on loop control — or nothing when the body
/// only modifies/does nothing. The caller wraps this in a `lets` scope
/// mark/reset — body bindings are not visible outside the body.
impl Lowerer<'_> {
    fn lower_body(
        &self,
        actions: &[ActionStmt],
        env: &HashMap<&str, u32>,
        lets: &mut LetEnv,
    ) -> (Vec<TermAction>, Vec<TermAction>) {
        let mut binds = Vec::new();
        let mut tail: Vec<TermAction> = Vec::new();
        let mut mods = RouteModifications::default();
        let flush = |tail: &mut Vec<TermAction>, mods: &mut RouteModifications| {
            if !mods.is_empty() {
                tail.push(TermAction::Continue(std::mem::take(mods)));
            }
        };
        for action in actions {
            match action {
                ActionStmt::Accept(_) => {
                    tail.push(TermAction::Permit(mods));
                    return (binds, tail);
                }
                ActionStmt::Reject(_) => {
                    tail.push(TermAction::Deny);
                    return (binds, tail);
                }
                // Loop control (LAN-303): staged modifications still
                // apply, then the branch is terminal.
                ActionStmt::Break(_) => {
                    flush(&mut tail, &mut mods);
                    tail.push(TermAction::Break);
                    return (binds, tail);
                }
                ActionStmt::Continue(_) => {
                    flush(&mut tail, &mut mods);
                    tail.push(TermAction::ContinueLoop);
                    return (binds, tail);
                }
                ActionStmt::Let { name, init, .. } => {
                    let expr = self.lower_value(init, &Names::Policy(env), lets, &mut binds);
                    let slot = lets.declare(&name.node);
                    binds.push(TermAction::Bind {
                        slot,
                        name: name.node.clone().into_boxed_str(),
                        expr,
                    });
                }
                // LAN-303: binding-valued community action — its own
                // term, in execution order relative to staged
                // modifications.
                ActionStmt::Community {
                    add,
                    arg: CommunityArg::Var(name),
                    ..
                } if lets.lookup(&name.node).is_some() => {
                    flush(&mut tail, &mut mods);
                    tail.push(TermAction::CommunityVar {
                        add: *add,
                        slot: lets.lookup(&name.node).expect("checked above"),
                        name: name.node.clone().into_boxed_str(),
                    });
                }
                other => self.apply_action(&mut mods, other, env, lets, &mut binds),
            }
        }
        flush(&mut tail, &mut mods);
        (binds, tail)
    }

    /// Stage one modification action into `mods`. Function calls in
    /// computed `set` values hoist their `Bind` terms into `binds`
    /// (LAN-304); the caller emits them ahead of the term that carries
    /// the staged modifications, so the computed expression's `Local`
    /// reads always follow their writes in walk order.
    fn apply_action(
        &self,
        mods: &mut RouteModifications,
        action: &ActionStmt,
        env: &HashMap<&str, u32>,
        lets: &mut LetEnv,
        binds: &mut Vec<TermAction>,
    ) {
        match action {
            ActionStmt::Accept(_)
            | ActionStmt::Reject(_)
            | ActionStmt::Let { .. }
            | ActionStmt::Break(_)
            | ActionStmt::Continue(_) => {
                unreachable!("verdicts, `let`, and loop control handled by callers")
            }
            // LAN-299: a computed set value that folds to a constant
            // (literal, parameter, or constant arithmetic) lowers to
            // the literal field — `set med 25 + 25` compiles to
            // exactly what `set med 50` does. Only expressions that
            // read route/peer fields (or an inlined call's result,
            // LAN-304) stay computed (resolved per route by the
            // evaluator).
            ActionStmt::SetLocalPref(expr, _) => {
                match self.lower_value(expr, &Names::Policy(env), lets, binds) {
                    ValueExpr::Const(value) => mods.set_local_pref = Some(value),
                    computed => {
                        mods.set_local_pref_computed = Some(std::sync::Arc::new(computed));
                    }
                }
            }
            ActionStmt::SetMed(expr, _) => {
                match self.lower_value(expr, &Names::Policy(env), lets, binds) {
                    ValueExpr::Const(value) => mods.set_med = Some(value),
                    computed => mods.set_med_computed = Some(std::sync::Arc::new(computed)),
                }
            }
            ActionStmt::SetNextHop(arg, _) => {
                mods.set_next_hop = Some(match arg {
                    NextHopArg::Self_(_) => NextHopAction::Self_,
                    NextHopArg::Addr(addr, _) => NextHopAction::Specific(*addr),
                });
            }
            // LAN-303: a parameter-valued community reference is a
            // compile-time constant — it stages as a literal, exactly like
            // writing the value. (Binding-valued references are emitted as
            // their own CommunityVar terms by the statement/body lowerers
            // and never reach here.)
            ActionStmt::Community {
                add,
                arg: CommunityArg::Var(name),
                ..
            } => {
                let value = *env
                    .get(name.node.as_str())
                    .expect("typechecked: non-binding community var is a parameter");
                if *add {
                    mods.communities_add.push(value);
                } else {
                    mods.communities_remove.push(value);
                }
            }
            ActionStmt::Community {
                add,
                arg: CommunityArg::Lit(lit),
                ..
            } => match lit.node {
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
}

impl<'a> Lowerer<'a> {
    /// Lower a value expression to IR: parameters substituted, `let`
    /// bindings resolved to frame slots (innermost first — LAN-302
    /// shadowing), constant subtrees folded bottom-up with checked
    /// arithmetic (LAN-299), and user-function calls fully inlined
    /// (LAN-304) — each call hoists `Bind` terms into `binds` (the
    /// caller emits them ahead of the reading term) and reads its
    /// result slot. A constant step that fails its check (e.g.
    /// `4294967295 + p` with `p = 1` at instantiation — invisible to
    /// the typechecker, which only sees literals) is left unfolded and
    /// fails per route on the eval-error rail: fail closed, never
    /// wrap.
    fn lower_value(
        &self,
        expr: &ValueExprAst,
        names: &Names<'_>,
        lets: &mut LetEnv,
        binds: &mut Vec<TermAction>,
    ) -> ValueExpr {
        match expr {
            ValueExprAst::Lit(value, _) => ValueExpr::Const(*value),
            ValueExprAst::Ident(name) => match names {
                // Innermost binding shadows parameters (and outer
                // bindings) in value positions — the typechecker
                // resolves by the same rule.
                Names::Policy(env) => {
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
                // Function bodies see their parameters and earlier
                // body lets, nothing else (closed over nothing). The
                // read renders by its qualified `fn.binding` name so
                // explain and eval-error surfaces name the function.
                Names::FnBody(bound) => {
                    let (_, qualified, slot) = bound
                        .iter()
                        .rev()
                        .find(|(source, _, _)| *source == name.node)
                        .expect("typechecked: fn-body names resolve");
                    ValueExpr::Local {
                        slot: *slot,
                        name: qualified.clone(),
                    }
                }
            },
            ValueExprAst::Field(path) => {
                debug_assert!(
                    matches!(names, Names::Policy(_)),
                    "typechecked: function bodies read no context fields"
                );
                let field = value_field_of(resolve_field(path).expect("typechecked"))
                    .expect("typechecked: u32 field operand");
                ValueExpr::Field(field)
            }
            ValueExprAst::Binary { op, lhs, rhs, .. } => {
                let lhs = self.lower_value(lhs, names, lets, binds);
                let rhs = self.lower_value(rhs, names, lets, binds);
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
                // A user-defined function inlines (LAN-304); the
                // builtins keep their dedicated IR nodes below.
                if let Some(def) = self.file.fns.iter().find(|f| f.name.node == name.node) {
                    return self.inline_call(def, args, names, lets, binds);
                }
                let mut args: Vec<ValueExpr> = args
                    .iter()
                    .map(|arg| self.lower_value(arg, names, lets, binds))
                    .collect();
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

    /// Inline one user-function call (LAN-304, ADR-0103 Decision 2): a
    /// call is sugar for a scope of lets — each argument binds to a
    /// caller-frame slot named `fn.param`, each body `let` to
    /// `fn.binding`, and the result expression to a slot named by the
    /// rendered call itself, which the call site reads. Slots allocate
    /// monotonically (never reused within a statement — later terms
    /// may read them when computed modifications resolve), a pure
    /// function of the source (Decision 5 determinism); the frame,
    /// depth, and expansion budgets are typecheck-enforced through the
    /// same Kahn DP as `apply` before lowering runs, so this recursion
    /// (bounded by `MAX_CALL_DEPTH`) cannot overflow or explode.
    fn inline_call(
        &self,
        def: &'a FnDef,
        args: &[ValueExprAst],
        names: &Names<'_>,
        lets: &mut LetEnv,
        binds: &mut Vec<TermAction>,
    ) -> ValueExpr {
        debug_assert_eq!(def.params.len(), args.len(), "typechecked arity");
        let mut bound: Vec<(&str, Box<str>, u8)> = Vec::new();
        for (param, arg) in def.params.iter().zip(args) {
            // Arguments evaluate in the CALLER's name context.
            let expr = self.lower_value(arg, names, lets, binds);
            let qualified: Box<str> = format!("{}.{}", def.name.node, param.node).into();
            let slot = lets.declare(&qualified);
            binds.push(TermAction::Bind {
                slot,
                name: qualified.clone(),
                expr,
            });
            bound.push((param.node.as_str(), qualified, slot));
        }
        for l in &def.lets {
            // Initializers resolve before their own name is bound —
            // shadowing, never self-reference (the LAN-302 rule).
            let expr = self.lower_value(&l.init, &Names::FnBody(&bound), lets, binds);
            let qualified: Box<str> = format!("{}.{}", def.name.node, l.name.node).into();
            let slot = lets.declare(&qualified);
            binds.push(TermAction::Bind {
                slot,
                name: qualified.clone(),
                expr,
            });
            bound.push((l.name.node.as_str(), qualified, slot));
        }
        let result = self.lower_value(&def.result, &Names::FnBody(&bound), lets, binds);
        // The result slot is named by the rendered call, so guards
        // reading it render source-level in explain.
        let rendered_args: Vec<String> = args.iter().map(render_value_ast).collect();
        let call_name: Box<str> = format!("{}({})", def.name.node, rendered_args.join(", ")).into();
        let slot = lets.declare(&call_name);
        binds.push(TermAction::Bind {
            slot,
            name: call_name.clone(),
            expr: result,
        });
        ValueExpr::Local {
            slot,
            name: call_name,
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
            // LAN-302/LAN-303: the typechecker rejects `apply` of a
            // policy that declares bindings or contains loops, so an
            // inlined predicate never contains these terms.
            TermAction::Bind { .. }
            | TermAction::ForEach(_)
            | TermAction::Break
            | TermAction::ContinueLoop
            | TermAction::CommunityVar { .. } => {
                unreachable!("typechecked: apply targets declare no bindings or loops")
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
