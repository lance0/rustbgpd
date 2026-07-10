//! `rbgp policy check --coverage` (LAN-323): test-coverage attribution
//! over the in-language test runner's walks, plus static policy lints.
//!
//! Coverage is pure attribution — no new evaluation machinery. Every
//! `expect` in a `test` block already walks its instantiated policy
//! through the IR evaluator; the coverage pass re-runs each walk
//! through [`CompiledChain::evaluate_recording_coverage`] and
//! aggregates, per source term, two distinct facts:
//!
//! - **evaluated** — the walk reached the term's guard at all. A term
//!   that was never evaluated means earlier terms always decided.
//! - **matched** — the term's guard matched. Evaluated-but-never-
//!   matched means no test fixture satisfies the guard.
//!
//! IR terms are grouped back to their defining source term (a source
//! term may lower to several IR terms — fallthrough encoding, `let`
//! binds, `if`/`else` splits): a source term counts as *evaluated* in
//! a walk when its first IR term was, and as *matched* when any of its
//! conditional (non-constant-`True`) IR guards matched — an
//! unconditional term matches whenever it is reached.
//!
//! **`apply` boundary.** `apply(p)` inlines `p`'s *decision* as a
//! boolean guard ([`super::lower`]) — `p`'s terms never appear in the
//! walked chain, so term-level facts through `apply` are not derivable
//! from the existing walks and are out of scope. Policies reached only
//! via `apply` from tested policies are reported as such
//! ([`PolicyTestStatus::ApplyOnly`]), with no term attribution.
//! `fn`s inline fully at lowering and have no terms to attribute.
//!
//! The static lints ride the same pass but need no fixtures: unused
//! sets/datasets/fns, unreachable terms (constant-guard case only —
//! deliberately not a reachability prover), and policies unreferenced
//! within the compilation unit (daemon config chains are not visible
//! to a standalone check, so that lint is phrased accordingly).

use std::collections::{HashMap, HashSet};

use crate::ir::{CompiledPolicy, MatchExpr};

use super::ast::{
    ActionStmt, CmpOp, Expr, ForSource, IfStmt, SourceFile, Stmt, TermDef, ValueExprAst,
};
use super::typeck::fold_const;

/// Coverage of one source term, aggregated over every test walk that
/// ran its policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TermCoverage {
    /// The term name as written.
    pub name: String,
    /// Walks whose evaluation reached this term's guard.
    pub evaluated: u64,
    /// Walks in which the term's guard matched (for a term with
    /// multiple conditional branches: any branch matched; for an
    /// unconditional term: equal to `evaluated`).
    pub matched: u64,
}

/// How the test suite relates to a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyTestStatus {
    /// At least one `expect` instantiated the policy directly.
    Tested,
    /// Never expected directly, but reachable through `apply` from a
    /// tested policy — exercised as an inlined predicate, so term-level
    /// attribution is not available (see the module docs).
    ApplyOnly,
    /// No test reaches it, directly or via `apply`.
    Untested,
}

impl PolicyTestStatus {
    /// Stable machine-readable label (the `-j` value).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            PolicyTestStatus::Tested => "tested",
            PolicyTestStatus::ApplyOnly => "apply-only",
            PolicyTestStatus::Untested => "untested",
        }
    }
}

/// Coverage of one policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyCoverage {
    /// The policy name.
    pub name: String,
    /// Defining module index ([`super::Span::file`]); resolve against
    /// [`super::RpolFile::modules`] for the display path.
    pub file: u32,
    /// Whether tests reach this policy.
    pub status: PolicyTestStatus,
    /// Per-source-term coverage, in source order.
    pub terms: Vec<TermCoverage>,
}

/// A static lint's category — stable machine-readable labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LintKind {
    /// A `prefix-set`/`community-set`/`asn-set` no policy references.
    UnusedSet,
    /// A `dataset` declaration no policy probes.
    UnusedDataset,
    /// An `fn` nothing calls.
    UnusedFn,
    /// A term that can never be evaluated: an earlier term in the same
    /// policy always decides (unconditional or constant-true guard with
    /// a terminal action).
    UnreachableTerm,
    /// A policy referenced by no test and no `apply` in the compilation
    /// unit. Daemon config chains are not visible here, so this is a
    /// "within these files" fact, not proof of dead code.
    UnreferencedPolicy,
}

impl LintKind {
    /// Stable machine-readable label (the `-j` value).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            LintKind::UnusedSet => "unused-set",
            LintKind::UnusedDataset => "unused-dataset",
            LintKind::UnusedFn => "unused-fn",
            LintKind::UnreachableTerm => "unreachable-term",
            LintKind::UnreferencedPolicy => "unreferenced-policy",
        }
    }
}

/// One static lint finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lint {
    /// The category.
    pub kind: LintKind,
    /// Module index of the flagged definition.
    pub file: u32,
    /// Human-readable one-liner.
    pub message: String,
}

/// The `--coverage` result: per-policy term coverage plus static
/// lints. Reporting only — it never fails a check by itself; the CLI's
/// `--coverage-min` threshold is the one exit-code consumer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoverageReport {
    /// Every policy of the compilation unit, in source order.
    pub policies: Vec<PolicyCoverage>,
    /// Static lint findings, in source order per category.
    pub lints: Vec<Lint>,
}

impl CoverageReport {
    /// Total source terms across every policy (the coverage
    /// denominator — terms of untested and apply-only policies count).
    #[must_use]
    pub fn terms_total(&self) -> usize {
        self.policies.iter().map(|p| p.terms.len()).sum()
    }

    /// Terms some test walk evaluated.
    #[must_use]
    pub fn terms_exercised(&self) -> usize {
        self.policies
            .iter()
            .flat_map(|p| &p.terms)
            .filter(|t| t.evaluated > 0)
            .count()
    }

    /// Exercised percentage; 100 for a unit with no terms.
    #[must_use]
    #[expect(clippy::cast_precision_loss, reason = "term counts are tiny")]
    pub fn percent(&self) -> f64 {
        let total = self.terms_total();
        if total == 0 {
            100.0
        } else {
            self.terms_exercised() as f64 / total as f64 * 100.0
        }
    }
}

/// The accumulator the test runner feeds: one
/// [`record_walk`](Self::record_walk) per `expect` evaluation.
#[derive(Debug)]
pub(super) struct CoverageAccum {
    /// Policy name → `policies` index.
    index: HashMap<String, usize>,
    policies: Vec<PolicyCoverage>,
}

impl CoverageAccum {
    /// A zeroed skeleton mirroring the unit's policies and terms.
    pub(super) fn new(file: &SourceFile) -> Self {
        let policies: Vec<PolicyCoverage> = file
            .policies
            .iter()
            .map(|def| PolicyCoverage {
                name: def.name.node.clone(),
                file: def.name.span.file,
                status: PolicyTestStatus::Untested,
                terms: def
                    .terms
                    .iter()
                    .map(|term| TermCoverage {
                        name: term.name.node.clone(),
                        evaluated: 0,
                        matched: 0,
                    })
                    .collect(),
            })
            .collect();
        let index = policies
            .iter()
            .enumerate()
            .map(|(i, p)| (p.name.clone(), i))
            .collect();
        Self { index, policies }
    }

    /// Fold one test walk's grids (both `0`/`1`-valued: the term list
    /// is straight-line, so a guard evaluates at most once per walk)
    /// into the per-source-term counters. `policy` is the instantiated
    /// single policy the walk ran; the grids are its rows.
    pub(super) fn record_walk(
        &mut self,
        policy: &CompiledPolicy,
        evaluated: &[u64],
        matched: &[u64],
    ) {
        let Some(&slot) = policy.name.as_deref().and_then(|name| self.index.get(name)) else {
            return;
        };
        let entry = &mut self.policies[slot];
        entry.status = PolicyTestStatus::Tested;
        let src_count = entry.terms.len();
        // Per-source-term walk facts, then fold into the totals.
        let mut reached = vec![false; src_count];
        let mut hit = vec![false; src_count];
        let mut conditional = vec![false; src_count];
        // IR terms are emitted per source term, in order, named either
        // exactly like the source term or `<term>.<n>` when one source
        // term lowers to several — group greedily by that contract
        // (term names are identifiers and cannot contain `.`).
        let mut src = 0usize;
        for (i, term) in policy.terms.iter().enumerate() {
            let Some(ir_name) = term.name.as_deref() else {
                continue;
            };
            while src < src_count && !belongs(ir_name, &entry.terms[src].name) {
                src += 1;
            }
            if src >= src_count {
                // Shape drift between AST and IR would be a compiler
                // bug; degrade to dropped attribution, never a panic.
                break;
            }
            if evaluated.get(i).copied().unwrap_or(0) > 0 {
                reached[src] = true;
            }
            if !matches!(term.guard, MatchExpr::True) {
                conditional[src] = true;
                if matched.get(i).copied().unwrap_or(0) > 0 {
                    hit[src] = true;
                }
            }
        }
        for (term, ((reached, hit), conditional)) in entry
            .terms
            .iter_mut()
            .zip(reached.into_iter().zip(hit).zip(conditional))
        {
            if reached {
                term.evaluated += 1;
                // An unconditional term "matches" whenever reached.
                if hit || !conditional {
                    term.matched += 1;
                }
            }
        }
    }

    /// Finalize: mark apply-only policies and attach the static lints.
    pub(super) fn finish(mut self, file: &SourceFile) -> CoverageReport {
        // `apply` edges: policy → targets (a static reference walk —
        // whether the guard containing the apply ever evaluates is
        // exactly the fact we cannot attribute; see module docs).
        let mut edges: HashMap<&str, Vec<&str>> = HashMap::new();
        for def in &file.policies {
            let mut targets = Vec::new();
            for term in &def.terms {
                collect_stmt_applies(&term.stmts, &mut targets);
            }
            edges.insert(def.name.node.as_str(), targets);
        }
        // BFS from directly-tested policies over apply edges.
        let mut queue: Vec<String> = self
            .policies
            .iter()
            .filter(|p| p.status == PolicyTestStatus::Tested)
            .map(|p| p.name.clone())
            .collect();
        let mut seen: HashSet<String> = queue.iter().cloned().collect();
        while let Some(name) = queue.pop() {
            for &target in edges.get(name.as_str()).into_iter().flatten() {
                if seen.insert(target.to_string()) {
                    if let Some(&slot) = self.index.get(target)
                        && self.policies[slot].status == PolicyTestStatus::Untested
                    {
                        self.policies[slot].status = PolicyTestStatus::ApplyOnly;
                    }
                    queue.push(target.to_string());
                }
            }
        }
        CoverageReport {
            policies: self.policies,
            lints: lints(file),
        }
    }
}

/// `apply` targets referenced by a statement list's guards.
fn collect_stmt_applies<'a>(stmts: &'a [Stmt], out: &mut Vec<&'a str>) {
    for stmt in stmts {
        match stmt {
            Stmt::If(if_stmt) => collect_expr_applies(&if_stmt.cond, out),
            Stmt::For(for_stmt) => collect_stmt_applies(&for_stmt.body, out),
            Stmt::Action(_) => {}
        }
    }
}

fn collect_expr_applies<'a>(expr: &'a Expr, out: &mut Vec<&'a str>) {
    match expr {
        Expr::Or(lhs, rhs) | Expr::And(lhs, rhs) => {
            collect_expr_applies(lhs, out);
            collect_expr_applies(rhs, out);
        }
        Expr::Not(inner, _) => collect_expr_applies(inner, out),
        Expr::Apply { policy, .. } => out.push(&policy.node),
        _ => {}
    }
}

/// Does IR term name `ir` belong to source term `src`? Either the name
/// itself or the `<src>.<n>` multi-lowered form.
fn belongs(ir: &str, src: &str) -> bool {
    ir == src || (ir.len() > src.len() && ir.starts_with(src) && ir.as_bytes()[src.len()] == b'.')
}

/// The static lints (see module docs for scope).
fn lints(file: &SourceFile) -> Vec<Lint> {
    let refs = Refs::collect(file);
    let mut out = Vec::new();
    for (name, span) in file
        .prefix_sets
        .iter()
        .map(|d| (&d.name.node, d.name.span))
        .chain(
            file.community_sets
                .iter()
                .map(|d| (&d.name.node, d.name.span)),
        )
        .chain(file.asn_sets.iter().map(|d| (&d.name.node, d.name.span)))
    {
        if !refs.sets.contains(name.as_str()) {
            out.push(Lint {
                kind: LintKind::UnusedSet,
                file: span.file,
                message: format!("set {name} is never referenced by any policy"),
            });
        }
    }
    for decl in &file.datasets {
        if !refs.sets.contains(decl.name.node.as_str()) {
            out.push(Lint {
                kind: LintKind::UnusedDataset,
                file: decl.name.span.file,
                message: format!("dataset {} is never probed by any policy", decl.name.node),
            });
        }
    }
    for def in &file.fns {
        // Calls from other `fn` bodies count as uses, so an unused
        // helper keeps its callees off this list — flagged one layer
        // at a time, not transitively.
        if !refs.fns.contains(def.name.node.as_str()) {
            out.push(Lint {
                kind: LintKind::UnusedFn,
                file: def.name.span.file,
                message: format!("fn {} is never called", def.name.node),
            });
        }
    }
    for def in &file.policies {
        if let Some(decider) = def.terms.iter().position(term_always_decides)
            && decider + 1 < def.terms.len()
        {
            for term in &def.terms[decider + 1..] {
                out.push(Lint {
                    kind: LintKind::UnreachableTerm,
                    file: term.name.span.file,
                    message: format!(
                        "term {} in policy {} is unreachable (term {} always decides)",
                        term.name.node, def.name.node, def.terms[decider].name.node
                    ),
                });
            }
        }
        if !refs.policies.contains(def.name.node.as_str()) {
            out.push(Lint {
                kind: LintKind::UnreferencedPolicy,
                file: def.name.span.file,
                message: format!(
                    "policy {} is not referenced by any test or apply in these files \
                     (daemon config chain references are not visible to this check)",
                    def.name.node
                ),
            });
        }
    }
    out
}

/// Does this term decide every route that reaches it? Only the
/// statically-certain cases: a bare `accept`/`reject`, an `if` whose
/// guard folds to a constant (the #768 folding — parameters and fields
/// never fold) with a terminal branch taken, or an `if`/`else` whose
/// branches are both terminal. Loops and runtime guards are
/// conservatively non-deciding.
fn term_always_decides(term: &TermDef) -> bool {
    for stmt in &term.stmts {
        match stmt {
            Stmt::Action(ActionStmt::Accept(_) | ActionStmt::Reject(_)) => return true,
            Stmt::Action(_) | Stmt::For(_) => {}
            Stmt::If(if_stmt) => {
                if if_decides(if_stmt) {
                    return true;
                }
            }
        }
    }
    false
}

fn if_decides(if_stmt: &IfStmt) -> bool {
    let then_terminal = has_terminal(&if_stmt.then_actions);
    let else_terminal = if_stmt.else_actions.as_deref().is_some_and(has_terminal);
    match const_truth(&if_stmt.cond) {
        Some(true) => then_terminal,
        Some(false) => else_terminal,
        None => then_terminal && else_terminal,
    }
}

fn has_terminal(actions: &[ActionStmt]) -> bool {
    actions
        .iter()
        .any(|a| matches!(a, ActionStmt::Accept(_) | ActionStmt::Reject(_)))
}

/// A guard's compile-time truth value, when every leaf folds — the
/// constant-guard case only. Comparisons involving fields, parameters,
/// bindings, sets, or `apply` never fold here.
fn const_truth(expr: &Expr) -> Option<bool> {
    match expr {
        Expr::Or(lhs, rhs) => match (const_truth(lhs), const_truth(rhs)) {
            (Some(true), _) | (_, Some(true)) => Some(true),
            (Some(false), Some(false)) => Some(false),
            _ => None,
        },
        Expr::And(lhs, rhs) => match (const_truth(lhs), const_truth(rhs)) {
            (Some(false), _) | (_, Some(false)) => Some(false),
            (Some(true), Some(true)) => Some(true),
            _ => None,
        },
        Expr::Not(inner, _) => const_truth(inner).map(|b| !b),
        Expr::ValueCmp { lhs, op, rhs, .. } => {
            let (l, r) = (fold_const(lhs)?, fold_const(rhs)?);
            Some(match op {
                CmpOp::Eq => l == r,
                CmpOp::Ne => l != r,
                CmpOp::Ge => l >= r,
                CmpOp::Le => l <= r,
            })
        }
        _ => None,
    }
}

/// Names the compilation unit references, by namespace.
#[derive(Default)]
struct Refs<'a> {
    /// Set and dataset references (one flat namespace).
    sets: HashSet<&'a str>,
    /// `fn` call references (builtin names may appear; harmless — the
    /// lint only asks membership for declared fns).
    fns: HashSet<&'a str>,
    /// Policy references: `apply` targets and test expectations.
    policies: HashSet<&'a str>,
}

impl<'a> Refs<'a> {
    fn collect(file: &'a SourceFile) -> Self {
        let mut refs = Refs::default();
        for def in &file.policies {
            for term in &def.terms {
                refs.stmts(&term.stmts);
            }
        }
        for def in &file.fns {
            for binding in &def.lets {
                refs.value(&binding.init);
            }
            refs.value(&def.result);
        }
        for test in &file.tests {
            for expect in &test.expects {
                refs.policies.insert(&expect.policy.node);
            }
        }
        refs
    }

    fn stmts(&mut self, stmts: &'a [Stmt]) {
        for stmt in stmts {
            match stmt {
                Stmt::If(if_stmt) => {
                    self.expr(&if_stmt.cond);
                    self.actions(&if_stmt.then_actions);
                    if let Some(else_actions) = &if_stmt.else_actions {
                        self.actions(else_actions);
                    }
                }
                Stmt::Action(action) => self.action(action),
                Stmt::For(for_stmt) => {
                    if let ForSource::Set(name) = &for_stmt.source {
                        self.sets.insert(&name.node);
                    }
                    self.stmts(&for_stmt.body);
                }
            }
        }
    }

    fn actions(&mut self, actions: &'a [ActionStmt]) {
        for action in actions {
            self.action(action);
        }
    }

    fn action(&mut self, action: &'a ActionStmt) {
        match action {
            ActionStmt::SetLocalPref(value, _)
            | ActionStmt::SetMed(value, _)
            | ActionStmt::Let { init: value, .. } => self.value(value),
            ActionStmt::Accept(_)
            | ActionStmt::Reject(_)
            | ActionStmt::SetNextHop(..)
            | ActionStmt::Community { .. }
            | ActionStmt::Prepend { .. }
            | ActionStmt::Break(_)
            | ActionStmt::Continue(_) => {}
        }
    }

    fn expr(&mut self, expr: &'a Expr) {
        match expr {
            Expr::Or(lhs, rhs) | Expr::And(lhs, rhs) => {
                self.expr(lhs);
                self.expr(rhs);
            }
            Expr::Not(inner, _) => self.expr(inner),
            Expr::In { set, .. } | Expr::IdentIn { set, .. } => {
                self.sets.insert(&set.node);
            }
            Expr::ValueCmp { lhs, rhs, .. } => {
                self.value(lhs);
                self.value(rhs);
            }
            Expr::Apply { policy, .. } => {
                self.policies.insert(&policy.node);
            }
            Expr::Cmp { .. } | Expr::Has { .. } | Expr::Matches { .. } | Expr::Contains { .. } => {}
        }
    }

    fn value(&mut self, value: &'a ValueExprAst) {
        match value {
            ValueExprAst::Call { name, args, .. } => {
                self.fns.insert(&name.node);
                for arg in args {
                    self.value(arg);
                }
            }
            ValueExprAst::Binary { lhs, rhs, .. } => {
                self.value(lhs);
                self.value(rhs);
            }
            ValueExprAst::Lit(..) | ValueExprAst::Ident(_) | ValueExprAst::Field(_) => {}
        }
    }
}
